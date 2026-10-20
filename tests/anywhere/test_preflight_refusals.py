#!/usr/bin/env python3
"""e2e_reproos_anywhere_preflight_on_linux_fixtures -- the refusal half.

"Supported distro fixtures produce complete plans and risky or
unsupported disk, boot, and network layouts fail before mutation."
(The supported half is e2e_convert.py.) Each refused shape is built FOR
REAL on a Debian source VM -- not by editing an inventory -- and preflight
must block the report on exactly the predicate that guards it:

  lvm     the target carries an LVM physical volume with an active LV
  luks    the target carries an open LUKS2 mapping
  raid    the target is a member of an active md RAID1
  static  the management interface is statically addressed
  bios    the machine boots with legacy BIOS (SeaBIOS)

Preflight runs in --inspection mode here: the report is blocked
regardless, and the source keeps writing these disks itself (an md RAID1
resyncs), so zero writes cannot be claimed here; the strict read-only
planning path is what e2e_reproos_anywhere_converts_linux_vm measures.

    test_preflight_refusals.py --artifacts DIR [case ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
from reproos_anywhere import controller as c  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"
APT = "export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get install -y -q {} >/dev/null"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def with_target(vm: Path, serial: str) -> Path:
    """The supervisor's enrollment, with ``serial`` as the one target."""
    text = (vm / "enrollment.toml").read_text()
    blocks = text.split("[[disks]]")
    out = [blocks[0]]
    for block in blocks[1:]:
        role = "target" if f'serial = "{serial}"' in block else "keep"
        out.append(re.sub(r'role = "\w+"', f'role = "{role}"', block))
    path = vm / f"enrollment-{serial}.toml"
    path.write_text("[[disks]]".join(out))
    return path


def preflight(a: Path, enrollment: Path) -> dict:
    art = c.Artifacts(a / "out-payload", a / "out-installer", a / "out-kexec" / "bin" / "kexec")
    return c.preflight(enrollment_path=enrollment, config_path=CONFIG, artifacts=art,
                       layout_tool=a / "bin" / "anywhere_layout", state_root=a / "state", inspection=True)


def expect(report: dict, check: str, needle: str) -> dict:
    verdicts = {x["id"]: x for x in report["checks"]}
    got = verdicts.get(check)
    assert report["blocked"] and "target" not in report, report
    assert got and got["verdict"] == "fail" and needle in got["detail"], (check, got)
    print(f"    blocked by {check}: {got['detail'][:150]}", flush=True)
    return {"check": check, "detail": got["detail"]}


def stacked(a: Path) -> dict:
    vm = a / "run" / f"refusals-stacked-{int(time.time())}"
    setup = (
        APT.format("lvm2 cryptsetup-bin mdadm"),
        "pvcreate -q /dev/vdb && vgcreate -q awvg /dev/vdb && lvcreate -q -y -l 100%FREE -n data awvg",
        "printf awpass | cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vdc - "
        "&& printf awpass | cryptsetup open /dev/vdc awcrypt -",
        "mdadm --create /dev/md0 --run --level=1 --raid-devices=2 --metadata=1.2 /dev/vdd /dev/vde",
    )
    sup.create("debian", vm, None, extra_disks=(4, 4, 4, 4), runcmd=setup)
    try:
        m = json.loads((vm / "machine.json").read_text())
        ssh = sup.ssh_argv(vm)
        import subprocess
        for _ in range(60):          # runcmd finishes after sshd is up
            out = subprocess.run(ssh + ["lsblk -no NAME,TYPE"], capture_output=True, text=True).stdout
            if "lvm" in out and "crypt" in out and "raid1" in out:
                break
            time.sleep(5)
        else:
            raise AssertionError(f"fixture stacking never appeared:\n{out}")
        serials = [d["serial"] for d in m["extra_disks"]]
        results = {
            "lvm": expect(preflight(a, with_target(vm, serials[0])), "target-stacking", "lvm"),
            "luks": expect(preflight(a, with_target(vm, serials[1])), "target-stacking", "luks"),
            "raid": expect(preflight(a, with_target(vm, serials[2])), "target-stacking", "md-raid1"),
        }
        return results
    finally:
        sup.destroy(vm)


def static(a: Path) -> dict:
    vm = a / "run" / f"refusals-static-{int(time.time())}"
    mac = "52:54:00:%02x:%02x:%02x" % tuple(os.urandom(3))
    net = f"""version: 2
ethernets:
  mgmt:
    match: {{macaddress: "{mac}"}}
    addresses: [10.0.2.15/24]
    routes: [{{to: default, via: 10.0.2.2}}]
    nameservers: {{addresses: [10.0.2.3]}}
"""
    sup.create("debian", vm, None, network_config=net, mac=mac)
    try:
        return {"static": expect(preflight(a, vm / "enrollment.toml"), "network-persistence", "static")}
    finally:
        sup.destroy(vm)


def bios(a: Path) -> dict:
    vm = a / "run" / f"refusals-bios-{int(time.time())}"
    sup.create("debian", vm, None, firmware="bios")
    try:
        return {"bios": expect(preflight(a, vm / "enrollment.toml"), "firmware", "bios")}
    finally:
        sup.destroy(vm)


CASES = {"stacked": stacked, "static": static, "bios": bios}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    p.add_argument("cases", nargs="*", default=list(CASES))
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(a / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    results = {}
    for name in args.cases:
        print(f"== {name}", flush=True)
        results.update(CASES[name](a))
    out = a / "evidence" / f"refusals-{int(time.time())}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"preflight refusals: PASS ({', '.join(results)}) -> {out}")
    shutil.rmtree(a / "state" / "_none_", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
