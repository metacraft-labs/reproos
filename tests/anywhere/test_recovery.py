#!/usr/bin/env python3
"""e2e_reproos_anywhere_failure_recovery_matrix (M5).

"Injected failures either recover the previous route or halt in an
accessible installer with an actionable journal."

Each case converts a fresh Debian source VM and injects ONE failure:

  rollback          the apply stops after takeover, before destroy;
                    `abort` power-cycles back to the untouched source
                    (automatic rollback), which answers on its enrolled
                    host key; the plan can no longer be applied.
  corrupt-transfer  payload bytes are corrupted in flight; materialize
                    rejects the digest and discards the file; `resume`
                    transfers again and the conversion completes.
  full-disk         the target root is filled before unpacking; the apply
                    halts in the installer; `resume --reformat`
                    (operator-confirmed, epoch 1) formats the failed install
                    again and completes.
  bootloader        the ESP is made read-only before install-root; the
                    bootloader stage fails; once the fault is cleared,
                    `resume` relaunches the failed operation and completes.
  network           the installed root's DHCP client is broken before the
                    reboot; the installed proof cannot reach the machine;
                    `recover --rematerialize` re-enters it through the rescue
                    plane, restores the root and proves it.
  first-boot        the installed system's enrollment keys are corrupted;
                    first-boot enrollment fails, so sshd never starts;
                    `recover` re-injects them and the proof passes.

Every failed case also writes a failure bundle that must contain the
journal, plan and console and must not contain a private key.

Fault injection needs a shell in the takeover environment, so this gate
runs the build WITHOUT the installer gate (confinement has its own gate).

    test_recovery.py --artifacts DIR [case ...]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
import variants  # noqa: E402
from reproos_anywhere import canon, controller as c, recovery, transport  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"


class Case:
    def __init__(self, artifacts: Path, installer: Path, label: str):
        self.a = artifacts
        self.vm = artifacts / "run" / f"recovery-{label}-{int(time.time())}"
        self.state = artifacts / "state"
        self.art = c.Artifacts(artifacts / "out-payload", installer, artifacts / "out-kexec" / "bin" / "kexec")
        self.layout = artifacts / "bin" / "anywhere_layout"
        sup.create("debian", self.vm, None)
        self.name = next(line.split('"')[1] for line in (self.vm / "enrollment.toml").read_text().splitlines()
                         if line.startswith("name"))
        sup.stop(self.vm)
        sup.start(self.vm, True)
        sup.wait_ssh(self.vm, 240)
        sup.write_enrollment(self.vm, True)
        report = c.preflight(enrollment_path=self.vm / "enrollment-readonly.toml", config_path=CONFIG,
                             artifacts=self.art, layout_tool=self.layout, state_root=self.state, inspection=False)
        assert not report["blocked"], report["checks"]
        sup.stop(self.vm)
        sup.start(self.vm, False)
        sup.wait_ssh(self.vm, 240)
        self.plan_id = c.make_plan(state_root=self.state, name=self.name, config_path=CONFIG, artifacts=self.art)

    def apply(self, **kw) -> c.Apply:
        return c.Apply(state_root=self.state, name=self.name, acknowledge=self.plan_id, artifacts=self.art,
                       log=lambda m: print("   ", m, flush=True), **kw)

    def shell(self, run: c.Apply, command: str) -> str:
        """Fault injection (the installer gate is absent in this build)."""
        return run.installer().run(command).stdout.decode()

    def before(self, run: c.Apply, stage: str, command: str) -> None:
        attr = "stage_" + stage.replace("-", "_")
        real = getattr(run, attr)

        def wrapped():
            self.shell(run, command)
            return real()
        setattr(run, attr, wrapped)

    def after(self, run: c.Apply, stage: str, command: str) -> None:
        attr = "stage_" + stage.replace("-", "_")
        real = getattr(run, attr)

        def wrapped():
            out = real()
            self.shell(run, command)
            return out
        setattr(run, attr, wrapped)

    def must_fail(self, run: c.Apply) -> str:
        try:
            run.run()
        except (c.AnywhereError, transport.TransportError) as error:
            print(f"    failed as injected: {str(error).splitlines()[0][:160]}", flush=True)
            return str(error)
        raise AssertionError("the injected failure did not stop the apply")

    def bundle_check(self) -> dict:
        out = self.a / "evidence" / f"bundle-{self.vm.name}.tar.gz"
        manifest = recovery.bundle(self.state / self.name, out)
        with tarfile.open(out) as tar:
            names = tar.getnames()
            for member in tar.getmembers():
                data = tar.extractfile(member).read()
                assert b"PRIVATE KEY" not in data, f"{member.name} carries a private key"
        for needed in ("journal.jsonl", "plan/plan.json", "rescue-console.log", "MANIFEST.json"):
            assert needed in names, (needed, names)
        return {"bundle": str(out), "files": len(manifest["files"]), "open": manifest["open"]}

    def destroy(self) -> None:
        sup.destroy(self.vm)
        shutil.rmtree(self.state / self.name, ignore_errors=True)


def proof_ok(proof: dict) -> None:
    assert proof["verdict"] == "installed", proof


def rollback(case: Case) -> dict:
    run = case.apply()
    real_start = run.journal.start

    def crash_before_destroy(stage, intent):
        # The controller dies after the takeover completed and before the
        # destroy start record exists: nothing on the target was written.
        if stage == "destroy":
            raise c.AnywhereError("injected stop before destroy")
        return real_start(stage, intent)
    run.journal.start = crash_before_destroy
    case.must_fail(run)
    bundle = case.bundle_check()
    enr = canon.read(case.state / case.name / "enrollment.json")
    evidence = recovery.abort(case.state / case.name,
                              lambda: c.source_session(enr, c.State(case.state, case.name)), log=print)
    assert evidence["rolled_back_to"] == "debian", evidence
    try:
        case.apply(resume=True)
        raise AssertionError("an aborted plan was accepted again")
    except c.Refused:
        pass
    return {"rolled_back_to": evidence["rolled_back_to"], "steps": evidence["steps"], **bundle}


def corrupt_transfer(case: Case) -> dict:
    run = case.apply()
    real_stream = transport.Session.stream

    def corrupted(self, local, offset, remote, **kw):
        bad = case.a / "corrupt.part"
        data = bytearray(Path(local).read_bytes()[offset:])
        data[len(data) // 2] ^= 0xFF
        bad.write_bytes(bytes(data))
        try:
            return real_stream(self, bad, 0, remote, **kw)
        finally:
            bad.unlink()
    transport.Session.stream = corrupted
    try:
        error = case.must_fail(run)
    finally:
        transport.Session.stream = real_stream
    assert "sha256" in error, error
    bundle = case.bundle_check()
    proof = case.apply(resume=True).run()
    proof_ok(proof)
    return {"detected": error.splitlines()[0][:200], **bundle}


def full_disk(case: Case) -> dict:
    run = case.apply()
    # Every free block, the root-reserved ones included (the installer writes as root).
    case.before(run, "materialize", "fallocate -l $(( $(stat -f -c '%f * %S' /mnt) - 65536 )) /mnt/fill")
    error = case.must_fail(run)
    bundle = case.bundle_check()
    try:
        case.apply(resume=True).run()
        raise AssertionError("resume without --reformat should still fail on the full disk")
    except (c.AnywhereError, transport.TransportError):
        pass
    proof = case.apply(resume=True, reformat=True).run()
    proof_ok(proof)
    j = case.apply(resume=True).journal
    formats = sum(1 for r in j.records if r["stage"] == "format" and r["event"] == "start")
    assert formats >= 2, formats
    return {"halted": error.splitlines()[0][:200], "format_starts": formats, **bundle}


def bootloader(case: Case) -> dict:
    run = case.apply()
    case.before(run, "bootloader", "mount -o remount,ro /mnt/boot")
    error = case.must_fail(run)
    bundle = case.bundle_check()
    clear = case.apply(resume=True)
    case.shell(clear, "mount -o remount,rw /mnt/boot")
    proof = clear.run()
    proof_ok(proof)
    return {"failed": error.splitlines()[0][:200], **bundle}


def network(case: Case) -> dict:
    run = case.apply()
    case.after(run, "bootloader",
               "printf '#!/bin/sh\\nexit 1\\n' > /mnt/usr/local/sbin/reproos-network")
    error = case.must_fail(run)
    bundle = case.bundle_check()
    proof = case.apply(resume=True).recover(rematerialize=True)
    proof_ok(proof)
    return {"failed": error.splitlines()[0][:200], **bundle}


def first_boot(case: Case) -> dict:
    run = case.apply()
    case.after(run, "inject-secrets",
               "echo not-a-key > /mnt/var/lib/reproos/anywhere-enrollment/authorized_keys")
    error = case.must_fail(run)
    bundle = case.bundle_check()
    proof = case.apply(resume=True).recover()
    proof_ok(proof)
    return {"failed": error.splitlines()[0][:200], **bundle}


CASES = {"rollback": rollback, "corrupt-transfer": corrupt_transfer, "full-disk": full_disk,
         "bootloader": bootloader, "network": network, "first-boot": first_boot}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    p.add_argument("cases", nargs="*", default=list(CASES))
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(a / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    installer = variants.build_installer([x for x in variants.ALL_CONTROLS if x != "gate"])
    results, failed = {}, []
    for name in args.cases:
        print(f"== {name}", flush=True)
        case = Case(a, installer, name)
        try:
            results[name] = CASES[name](case)
            print(f"    {name}: recovered", flush=True)
        except Exception as error:  # noqa: BLE001 -- report every case
            failed.append(name)
            results[name] = {"error": str(error)[:2000]}
            print(f"    {name}: FAILED: {error}", flush=True)
        finally:
            shutil.copy(case.vm / "console.log", a / "evidence" / f"recovery-{name}.console.log") \
                if (case.vm / "console.log").exists() else None
            case.destroy()
    out = a / "evidence" / f"recovery-{int(time.time())}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"e2e_reproos_anywhere_failure_recovery_matrix: {len(results) - len(failed)} recovered, "
          f"{len(failed)} failed{' (' + ', '.join(failed) + ')' if failed else ''} -> {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
