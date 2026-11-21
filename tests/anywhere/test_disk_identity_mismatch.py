#!/usr/bin/env python3
"""test_reproos_anywhere_disk_identity_mismatch.

"Reordering device names or replacing a disk after planning invalidates
apply before partition changes." -- with the guard shown to be what does
it, by removing it.

Fixture: a Debian source VM (supervisor-created, digest-pinned image)
with its target disk and one KEEP disk that carries a marker the test
wrote. A plan is made against the original topology. Then:

  reorder   the KEEP disk is moved to a PCI slot ahead of the target, so
            /dev/vda is now the KEEP disk and the target is /dev/vdb.
            Apply must refuse before any stage starts.
            Layer controls (the controller is run in-process and the
            named guard is patched out):
              - without the pre-write inventory recheck, the takeover
                happens and the installer-side PCI-path check refuses
                before destroy;
              - without that too, the broker's serial resolution refuses;
              - MUTATION: with every guard removed and the broker driven
                by device path (what a path-bound implementation would
                do), destroy erases /dev/vda -- the KEEP disk -- and the
                marker is gone. The test asserts that this mutation is
                detected (KEEP disk destroyed), proving the assertions
                can fail.

  replace   after a fresh plan and a completed takeover, the target drive
            is hot-replaced by a blank disk of the same capacity with a
            new serial. Destroy must refuse before it writes (the management
            plane no longer shows the planned drive); the replacement must
            carry no partition table afterwards.

  clone-<controller>   (virtio-blk, virtio-scsi, ahci) the safety
            contract's per-controller identity. After planning, the target
            is swapped for a copy that reports the SAME serial and the SAME
            capacity. On SCSI and SATA the copy has its own WWN; apply must
            refuse at the
            pre-write recheck, and, with that recheck patched out, the
            broker's --wwid binding must refuse in the installer before
            destroy. MUTATION: with the planned wwid dropped as well,
            destroy erases the copy, so the wwid is what stood in the way.
            virtio-blk has no stable identifier: a second disk with the
            target's serial and capacity is attached beside it, and both
            layers refuse the ambiguous serial. (A same-slot clone of a
            virtio-blk disk is indistinguishable; the contract accepts
            that.) NVMe is not here: Linux ignores the namespace
            identifiers of QEMU's emulated NVMe controller, so such a target
            is refused at preflight (test_preflight_refusals.py nvme).

Every VM is destroyed at the end. Nothing touches the host's disks.

    test_disk_identity_mismatch.py --artifacts DIR [reorder replace clone-ahci ...]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
from e2e_convert import DEVICE_CONFIGS, payload_for  # noqa: E402
from reproos_anywhere import controller as c  # noqa: E402
from reproos_anywhere.journal import Journal  # noqa: E402

MARKER_LABEL = "AWKEEPDISK"


class Fixture:
    def __init__(self, artifacts: Path, label: str, controller: str = "virtio-blk"):
        self.a = artifacts
        self.vm = artifacts / "run" / f"diskid-{label}-{int(time.time())}"
        self.state = artifacts / "state"
        # The configuration (and the payload baked from it) names the
        # target's kernel device, which differs per controller.
        device = sup.CONTROLLERS[controller][0]
        self.config = DEVICE_CONFIGS[device]
        payload = artifacts / "out-payload" if device == "vda" else payload_for(self.config)
        self.art = c.Artifacts(payload, artifacts / "out-installer", artifacts / "out-kexec" / "bin" / "kexec")
        self.layout = artifacts / "bin" / "anywhere_layout"

    def ssh(self, cmd: str, check: bool = True) -> str:
        p = subprocess.run(sup.ssh_argv(self.vm) + [cmd], capture_output=True, text=True)
        if check and p.returncode != 0:
            raise AssertionError(f"source ssh failed: {cmd}: {p.stderr}")
        return p.stdout

    def create(self, keep_disk: bool, controller: str = "virtio-blk") -> None:
        sup.create("debian", self.vm, None, controller=controller)
        if keep_disk:
            sup.stop(self.vm)
            sup.add_disk(self.vm, "after", 2)
            sup.start(self.vm, False)
            sup.wait_ssh(self.vm, 240)
            sup.write_enrollment(self.vm, False)
            # A real filesystem signature, so "destroyed" means what destroy
            # does (wipefs erases signatures; raw bytes would survive it).
            self.ssh(f"mkfs.ext4 -q -F -L {MARKER_LABEL} /dev/vdb && sync")
        self.name = next(line.split('"')[1] for line in (self.vm / "enrollment.toml").read_text().splitlines()
                         if line.startswith("name"))

    def plan(self) -> str:
        sup.stop(self.vm)
        sup.start(self.vm, True)
        sup.wait_ssh(self.vm, 240)
        sup.write_enrollment(self.vm, True)
        report = c.preflight(enrollment_path=self.vm / "enrollment-readonly.toml", config_path=self.config,
                             artifacts=self.art, layout_tool=self.layout, state_root=self.state,
                             inspection=False)
        assert not report["blocked"], report
        sup.stop(self.vm)
        sup.start(self.vm, False)
        sup.wait_ssh(self.vm, 240)
        return c.make_plan(state_root=self.state, name=self.name, config_path=self.config, artifacts=self.art)

    def apply(self, plan_id: str) -> c.Apply:
        return c.Apply(state_root=self.state, name=self.name, acknowledge=plan_id, artifacts=self.art,
                       log=lambda m: print("   ", m, flush=True))

    def journal(self, plan_id: str) -> Journal:
        return Journal(self.state / self.name / "journal.jsonl", plan_id)

    def keep_marker(self) -> bool:
        """Read the KEEP disk image from the host side (no guest trust)."""
        img = self.vm / "extra-0.qcow2"
        # -U: read while the guest holds the image; -r: never write it.
        out = subprocess.run(["qemu-io", "-U", "-r", "-f", "qcow2", "-c", "read -v 1024 256", str(img)],
                             capture_output=True, text=True).stdout
        # "00000400:  41 41 ... 41  AAAA..." -> the hex column only
        dump = "".join(line.split(":", 1)[1].strip().split("  ")[0] for line in out.splitlines()
                       if line[:8].isalnum() and ":" in line)
        sb = bytes.fromhex(dump.replace(" ", ""))
        # ext4 superblock: magic 0xEF53 at 0x38, volume label at 0x78.
        return sb[0x38:0x3A] == b"\x53\xef" and sb[0x78:0x88].rstrip(b"\0") == MARKER_LABEL.encode()

    def reset_journal(self) -> None:
        (self.state / self.name / "journal.jsonl").unlink(missing_ok=True)

    def destroy(self) -> None:
        sup.destroy(self.vm)
        shutil.rmtree(self.state / getattr(self, "name", "_none_"), ignore_errors=True)


def expect_refused(run: c.Apply, where: str) -> str:
    try:
        run.run()
    except c.Refused as error:
        print(f"    refused at {where}: {error}")
        return str(error)
    raise AssertionError(f"apply was NOT refused ({where})")


def reorder(artifacts: Path) -> dict:
    f = Fixture(artifacts, "reorder")
    try:
        f.create(keep_disk=True)
        assert f.keep_marker(), "fixture marker missing"
        plan_id = f.plan()
        print("  plan made; moving the KEEP disk ahead of the target")
        sup.stop(f.vm)
        m = json.loads((f.vm / "machine.json").read_text())
        m["extra_disks"][0]["slot"] = "before"
        (f.vm / "machine.json").write_text(json.dumps(m, indent=2))
        sup.start(f.vm, False)
        sup.wait_ssh(f.vm, 240)
        assert "vda" in f.ssh("lsblk -dno NAME,SERIAL | grep " + m["extra_disks"][0]["serial"]), \
            "reorder did not take effect"

        print("  [guarded] apply with the stale plan")
        reason = expect_refused(f.apply(plan_id), "pre-write inventory recheck")
        assert not (f.state / f.name / "journal.jsonl").exists() or not f.journal(plan_id).records, \
            "a stage started before the refusal"
        assert f.keep_marker(), "KEEP disk changed"

        print("  [layer 2] without the source recheck")
        run = f.apply(plan_id)
        run.recheck_source = lambda: setattr(run, "source_boot_id",
                                             run.source().run("cat /proc/sys/kernel/random/boot_id").stdout.decode().strip())
        expect_refused(run, "installer PCI-path check")
        assert "destroy" not in [r["stage"] for r in f.journal(plan_id).records if r["event"] == "complete"]
        assert f.keep_marker(), "KEEP disk changed"

        print("  [layer 3] without the PCI-path check (resume in the running installer)")
        run = c.Apply(state_root=f.state, name=f.name, acknowledge=plan_id, artifacts=f.art,
                      log=lambda m: print("   ", m), resume=True)
        run.check_target_path = lambda: None
        expect_refused(run, "broker serial resolution")
        assert f.keep_marker(), "KEEP disk changed"

        print("  [MUTATION] every guard removed, broker driven by device path")
        run = c.Apply(state_root=f.state, name=f.name, acknowledge=plan_id, artifacts=f.art,
                      log=lambda m: print("   ", m), resume=True)
        run.check_target_path = lambda: None
        live_serial, live_size = run.gate("serial", "vda").split()[:2]
        original = run.target_flags
        run.target_flags = lambda: original().replace(f"--serial {run.target['serial']}", f"--serial {live_serial}") \
            .replace(f"--size-sectors {run.target['size_sectors']}", f"--size-sectors {live_size}")
        run.verify_erased = lambda: {"erased": "mutation"}
        mutated_destroyed = False
        try:
            run.stage_destroy()
            mutated_destroyed = True
        except c.AnywhereError as error:
            print(f"    mutation run stopped: {error}")
        marker_after_mutation = f.keep_marker()
        if mutated_destroyed and not marker_after_mutation:
            print("    mutation detected: the KEEP disk was erased once the guards were removed")
        else:
            raise AssertionError("the mutation did not destroy the KEEP disk; the assertions above "
                                 "would not have caught a missing guard")
        return {"case": "reorder", "plan": plan_id, "guarded": "refused before any stage",
                "layer2": "installer PCI-path check refused", "layer3": "broker serial resolution refused",
                "mutation": "KEEP disk erased when all guards were removed (detected)",
                "refusal": reason}
    finally:
        f.destroy()


def replace(artifacts: Path) -> dict:
    f = Fixture(artifacts, "replace")
    try:
        f.create(keep_disk=False)
        plan_id = f.plan()
        run = f.apply(plan_id)
        swapped = {}
        real_destroy = run.stage_destroy

        def destroy_after_swap():
            swapped.update(sup.hot_replace_target(f.vm))
            print(f"    hot-replaced the target {swapped['old_serial']} -> {swapped['new_serial']}")
            return real_destroy()
        run.stage_destroy = destroy_after_swap
        reason = expect_refused(run, "installer, before destroy")
        recs = f.journal(plan_id).records
        assert [r["stage"] for r in recs if r["event"] == "complete"] == ["stage-payload", "takeover"], recs
        probe_run = c.Apply(state_root=f.state, name=f.name, acknowledge=plan_id, artifacts=f.art,
                            log=lambda m: None, resume=True)
        node = next((n for n in ("vda", "vdb", "vdc")
                     if probe_run.gate("serial", n, check=False).split()[:1] == [swapped["new_serial"]]), "")
        assert node, "the replacement disk is not visible in the installer"
        table = probe_run.gate("probe", node)
        assert "rc=2" in table, f"replacement disk was written: {table}"
        return {"case": "replace", "plan": plan_id, "swap": swapped,
                "refusal": reason, "replacement_untouched": True}
    finally:
        f.destroy()


def has_gpt(img: Path) -> bool:
    """Is there a GPT header at LBA 1 of ``img``? Read from the host side."""
    out = subprocess.run(["qemu-io", "-U", "-r", "-f", "qcow2", "-c", "read -v 512 8", str(img)],
                         capture_output=True, text=True).stdout
    return "45 46 49 20 50 41 52 54" in out          # "EFI PART" (qemu-io prints the space as '.')


def clone(artifacts: Path, controller: str) -> dict:
    f = Fixture(artifacts, f"clone-{controller}", controller)
    try:
        f.create(keep_disk=False, controller=controller)
        m = json.loads((f.vm / "machine.json").read_text())
        kname = sup.CONTROLLERS[controller][0]
        seen = f.ssh(f"cat /sys/block/{kname}/wwid 2>/dev/null || cat /sys/block/{kname}/device/wwid 2>/dev/null",
                     check=False).strip()
        assert seen == m["wwid"], f"the guest sees wwid {seen!r}, the fixture pinned {m['wwid']!r}"
        plan_id = f.plan()
        planned = f.apply(plan_id).target
        assert planned["wwid"] == m["wwid"], planned
        print(f"  plan made on {kname} ({m['wwid'] or 'no wwid'}); cloning the target")
        sup.stop(f.vm)
        swap = sup.clone_target(f.vm)
        sup.start(f.vm, False)
        sup.wait_ssh(f.vm, 240)
        clone_img = f.vm / "clone.qcow2"
        multipath = controller == "virtio-blk"
        assert has_gpt(clone_img) != multipath, "fixture: the clone is not what clone_target promised"

        print("  [guarded] apply with the stale plan")
        reason = expect_refused(f.apply(plan_id), "pre-write inventory recheck")
        assert not (f.state / f.name / "journal.jsonl").exists() or not f.journal(plan_id).records, \
            "a stage started before the refusal"

        print("  [layer 2] without the source recheck")
        run = f.apply(plan_id)
        run.recheck_source = lambda: setattr(run, "source_boot_id",
                                             run.source().run("cat /proc/sys/kernel/random/boot_id").stdout.decode().strip())
        layer2 = expect_refused(run, "installer identity binding")
        assert ("reported by 2 disks" if multipath else "reports wwid") in layer2, layer2
        assert "destroy" not in [r["stage"] for r in f.journal(plan_id).records if r["event"] == "complete"]
        result = {"case": f"clone-{controller}", "plan": plan_id, "swap": swap, "refusal": reason,
                  "layer2": layer2}
        if multipath:
            return result
        assert has_gpt(clone_img), "the clone was written although apply was refused"

        print("  [MUTATION] the planned wwid dropped (a serial-only implementation)")
        run = c.Apply(state_root=f.state, name=f.name, acknowledge=plan_id, artifacts=f.art,
                      log=lambda m: print("   ", m), resume=True)
        run.target = {**run.target, "wwid": ""}
        run.verify_erased = lambda: {"erased": "mutation"}
        try:
            run.stage_destroy()
        except c.AnywhereError as error:
            print(f"    mutation run stopped: {error}")
        if has_gpt(clone_img):
            raise AssertionError("the mutation did not erase the clone; the assertions above "
                                 "would not have caught a missing wwid binding")
        print("    mutation detected: the clone was erased once the wwid binding was removed")
        return {**result, "mutation": "clone erased when the wwid binding was removed (detected)"}
    finally:
        f.destroy()


CASES = {"reorder": reorder, "replace": replace,
         **{f"clone-{ctl}": (lambda a, ctl=ctl: clone(a, ctl)) for ctl in ("virtio-blk", "virtio-scsi", "ahci")}}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    p.add_argument("cases", nargs="*", default=list(CASES), choices=list(CASES))
    args = p.parse_args()
    artifacts = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(artifacts / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    results = []
    for case in args.cases:
        print(f"== {case}")
        results.append(CASES[case](artifacts))
    out = artifacts / "evidence" / f"diskid-{int(time.time())}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"test_reproos_anywhere_disk_identity_mismatch: PASS ({len(results)} cases) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
