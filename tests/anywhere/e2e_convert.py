#!/usr/bin/env python3
"""e2e_reproos_anywhere_converts_linux_vm (and its preflight leg).

For each requested distribution, end to end, unattended:

  1. the supervisor creates a source VM from a fresh digest-pinned image;
  2. it is cleanly stopped and booted with its disk attached read-only by
     QEMU (the independently enforced planning environment);
  3. strict preflight must return a compatible report, and the disk image
     must be byte-identical afterwards (zero remote writes, measured);
  4. the VM is booted writable, a plan is made and applied with its
     identity; every stage must complete;
  5. the installed system must pass the installed-only proof;
  6. the VM and its controller state are destroyed.

    e2e_convert.py --artifacts DIR [--keep] [--convert] debian [ubuntu ...]

--convert drives steps 3-4 through the short form an operator types,
`reproos-anywhere convert root@HOST:PORT MACHINE` and then the same with
`--acknowledge`, against a directory of enrollments and one of machine
configurations, instead of preflight, plan and apply.

DIR holds out-payload/, out-installer/, out-kexec/ and bin/anywhere_layout
(see tests/anywhere/run-fixture-build.sh). Exit 0 only if every distro
passed. Evidence (journal, reports, console log) is copied to
DIR/evidence/<distro>-<time>/ before the VM is destroyed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CLI = REPO / "tools" / "anywhere" / "reproos-anywhere"
SUPERVISOR = HERE / "supervisor.py"
sys.path.insert(0, str(HERE))
import supervisor as sup  # noqa: E402
CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"
DEVICE_CONFIGS = {"vda": CONFIG,
                  "sda": HERE / "fixtures" / "auto-config-sda.toml",
                  "nvme0n1": HERE / "fixtures" / "auto-config-nvme0n1.toml"}


def canon_read(path: Path) -> dict:
    """A canonical controller record, with its identity (the digest of its bytes)."""
    data = path.read_bytes()
    return {**json.loads(data), "id": hashlib.sha256(data).hexdigest()}


def payload_for(config: Path) -> Path:
    """The fixture payload built for ``config`` (its target device differs)."""
    reprobuild = Path(os.environ.get("REPROBUILD_SOURCE_ROOT", REPO.parent / "reprobuild")).resolve()
    out = subprocess.run(["nix-build", "--no-out-link", str(HERE / "fixture"), "-A", "payload",
                          "--arg", "reproosSrc", str(REPO), "--arg", "reprobuildSrc", str(reprobuild),
                          "--arg", "autoConfig", str(config)],
                         check=True, capture_output=True, text=True).stdout.strip().splitlines()[-1]
    return Path(out)


def sh(*argv, check=True, **kw) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in argv], check=check, text=True, **kw)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Run:
    def __init__(self, artifacts: Path, distro: str, controller: str = "virtio-blk", convert: bool = False):
        self.a = artifacts
        self.convert = convert
        self.distro = distro
        self.controller = controller
        device = sup.CONTROLLERS[controller][0]
        self.config = DEVICE_CONFIGS[device]
        self.payload = artifacts / "out-payload" if device == "vda" else payload_for(self.config)
        self.vm = artifacts / "run" / f"{distro}-{controller}-{int(time.time())}"
        self.state = artifacts / "state"
        self.evidence = artifacts / "evidence" / self.vm.name

    def cli(self, *args, check=True) -> subprocess.CompletedProcess:
        return sh(sys.executable, CLI, "--state", self.state, "--payload", self.payload,
                  "--installer", self.a / "out-installer", "--kexec", self.a / "out-kexec" / "bin" / "kexec",
                  "--layout-tool", self.a / "bin" / "anywhere_layout", *args,
                  check=check, capture_output=True)

    def sup(self, *args) -> subprocess.CompletedProcess:
        p = sh(sys.executable, SUPERVISOR, *args, capture_output=True, check=False)
        if p.returncode != 0:
            raise RuntimeError(f"supervisor {args[0]} failed ({p.returncode}): {p.stderr.strip()[-2000:]}")
        return p

    def name(self) -> str:
        for line in (self.vm / "enrollment.toml").read_text().splitlines():
            if line.startswith("name"):
                return line.split('"')[1]
        raise RuntimeError("enrollment has no name")

    def step(self, what: str) -> None:
        print(f"[{self.distro}] {what}", flush=True)

    def run(self) -> dict:
        self.step(f"create source VM from the pinned image ({self.controller})")
        self.sup("create", self.distro, self.vm, "--controller", self.controller)
        name = self.name()
        self.sup("stop", self.vm)

        self.step("strict preflight in the read-only planning environment")
        before = sha(self.vm / "disk.qcow2")
        self.sup("start", self.vm, "--readonly")
        if self.convert:
            pf, destination, short = self.convert_plan(name)
        else:
            pf = self.cli("--json", "preflight", "--enrollment", self.vm / "enrollment-readonly.toml",
                          "--config", self.config, check=False)
        self.sup("stop", self.vm)
        after = sha(self.vm / "disk.qcow2")
        if pf.returncode != 0:
            raise AssertionError(f"strict preflight did not pass ({pf.returncode}):\n{pf.stdout}\n{pf.stderr}")
        report = canon_read(self.state / name / "compatibility.json")
        if before != after:
            raise AssertionError(f"planning changed the source disk: {before} -> {after}")

        self.step("plan")
        self.sup("start", self.vm)
        if self.convert:
            ack = pf.stdout.strip().splitlines()[-1].split()[-1]
        else:
            pl = self.cli("plan", "--name", name, "--config", self.config)
            ack = pl.stdout.strip().splitlines()[-1].split()[-1]

        self.step(f"apply {ack[:16]}...")
        started = time.monotonic()
        events = self.vm / "events.jsonl"
        if self.convert:
            ap = self.cli("convert", destination, *short, "--acknowledge", ack, "--events", events, check=False)
        else:
            ap = self.cli("apply", "--name", name, "--acknowledge", ack, "--events", events, check=False)
        elapsed = time.monotonic() - started
        if ap.returncode != 0:
            raise AssertionError(f"apply failed ({ap.returncode}):\n{ap.stdout}\n{ap.stderr}")
        proof = json.loads(ap.stdout[ap.stdout.index("{"):])
        stream = [json.loads(line) for line in events.read_text().splitlines()]
        stages = [e["stage"] for e in stream if e.get("event") == "complete"]
        if stream[-1].get("verdict") != "installed" or "final-verification" not in stages \
                or not Path(stream[-1]["evidence"]["journal"]).exists():
            raise AssertionError(f"progress events do not end in an installed verdict: {stream[-3:]}")
        if proof.get("verdict") != "installed":
            raise AssertionError(f"no installed verdict: {proof}")
        self.step(f"installed in {elapsed:.0f}s: {proof['root']} on {proof['root_disk_serial']}, "
                  f"generation {proof['generation'][:12]}, host key {proof['host_key_fingerprint']}")
        plan = json.loads((self.state / name / "plan" / "plan.json").read_text())
        machine = json.loads((self.vm / "machine.json").read_text())
        return {"distro": self.distro, "controller": self.controller, "plan": ack,
                "invocation": "convert" if self.convert else "preflight/plan/apply",
                "takeover": plan["takeover"], "firmware": machine.get("firmware", "uefi"),
                "architecture": "x86_64", "network": "dhcp",
                "planning_environment": (report.get("planning_environment") or {}).get("kind"),
                "image": sup.DISTROS[self.distro].get("file"), "planning_disk_sha256": before,
                "planning_disk_unchanged": True, "report": report.get("id"),
                "apply_seconds": int(elapsed), "proof": proof}

    def convert_plan(self, name: str) -> tuple[subprocess.CompletedProcess, str, list]:
        """Lay out what an operator has (one enrollment per machine, one
        configuration per machine) and run the short form's first step."""
        enrollments, machines = self.vm / "enrollments", self.vm / "machines"
        enrollments.mkdir()
        machines.mkdir()
        text = (self.vm / "enrollment-readonly.toml").read_text()
        for rel in ("console.log", "keys/operator_ed25519"):
            text = text.replace(f'"{rel}"', f'"{self.vm / rel}"')
        (enrollments / f"{name}.toml").write_text(text)
        shutil.copy(self.config, machines / "rehearsal.toml")
        port = json.loads((self.vm / "machine.json").read_text())["port"]
        destination = f"root@127.0.0.1:{port}"
        short = ["rehearsal", "--machines", machines, "--enrollments", enrollments]
        pf = self.cli("convert", destination, *short, check=False)
        print(pf.stdout, end="", flush=True)
        if pf.returncode == 0 and "--acknowledge" not in pf.stdout:
            raise AssertionError(f"convert printed no plan identity:\n{pf.stdout}")
        if pf.returncode == 0:
            # Acknowledging before the machine has left its planning
            # environment must be refused by the management plane's view of
            # the disk, before anything is written.
            ack = pf.stdout.strip().splitlines()[-1].split()[-1]
            early = self.cli("convert", destination, *short, "--acknowledge", ack, check=False)
            if early.returncode != 2 or "planning environment" not in early.stderr:
                raise AssertionError(f"apply in the planning environment was not refused "
                                     f"({early.returncode}):\n{early.stdout}\n{early.stderr}")
            self.step(f"apply in the planning environment refused: {early.stderr.strip()[:110]}")
        return pf, destination, short

    def collect(self) -> None:
        self.evidence.mkdir(parents=True, exist_ok=True)
        for f in ("console.log", "machine.json", "enrollment.toml", "events.jsonl"):
            if (self.vm / f).exists():
                shutil.copy(self.vm / f, self.evidence / f)
        try:
            sdir = self.state / self.name()
            for f in ("journal.jsonl", "compatibility.json", "inventory.json", "probe.out"):
                if (sdir / f).exists():
                    shutil.copy(sdir / f, self.evidence / f)
            if (sdir / "plan").exists():
                shutil.copytree(sdir / "plan", self.evidence / "plan", dirs_exist_ok=True)
        except (RuntimeError, FileNotFoundError):
            pass

    def destroy(self) -> None:
        sh(sys.executable, SUPERVISOR, "destroy", self.vm, check=False, capture_output=True)
        try:
            shutil.rmtree(self.state / self.name(), ignore_errors=True)
        except (RuntimeError, FileNotFoundError):
            pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    p.add_argument("--keep", action="store_true", help="keep the VM after the test")
    p.add_argument("--controller", default="virtio-blk", choices=sorted(sup.CONTROLLERS))
    p.add_argument("--convert", action="store_true", help="drive the conversion through `convert`")
    p.add_argument("distros", nargs="+")
    args = p.parse_args()
    artifacts = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(artifacts / "images"))
    results, failed = [], []
    for distro in args.distros:
        r = Run(artifacts, distro, args.controller, args.convert)
        try:
            results.append(r.run())
        except Exception as error:  # noqa: BLE001 -- report every distro
            failed.append(distro)
            print(f"[{distro}] FAILED: {error}", flush=True)
        finally:
            r.collect()
            if not args.keep:
                r.destroy()
    summary = artifacts / "evidence" / f"e2e-{int(time.time())}.json"
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps({"passed": results, "failed": failed}, indent=2, sort_keys=True))
    print(f"summary: {summary}")
    print(f"e2e_reproos_anywhere_converts_linux_vm: {len(results)} passed, {len(failed)} failed"
          + (f" ({', '.join(failed)})" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
