#!/usr/bin/env python3
"""ReproOS Anywhere negative gates on a real source VM.

test_reproos_anywhere_tampered_takeover_payload_rejected (M2):
  staged-image   the staged takeover initrd is modified on the source after
                 it was verified; takeover refuses before kexec.
  wrong-nonce    a forged console announcement (another nonce) appears on
                 the rescue plane before the real one; takeover refuses.
  wrong-hostkey  a forged announcement with the right session and nonce but
                 another host key; the real installer cannot authenticate
                 as it, so takeover fails without trusting the forger.
  source-key     the enrollment names another source host key; preflight
                 fails at the SSH host-key check, before any command runs.

test_reproos_anywhere_old_system_false_positive_rejected (M4):
  old-system     the installed-system proof run against the UNCONVERTED
                 source fails (host key), and with the key check removed
                 still fails on identity facts;
  installer      run while the takeover environment is still answering
                 (bootloader done, no reboot) fails the same way.

After every refused takeover the VM is power-cycled through the rescue
plane and must boot its untouched source system again: that is the
contract's takeover recovery route ("console boots source; no disk writes
authorised yet"), exercised rather than assumed.

    test_negatives.py --artifacts DIR [case ...]
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
from reproos_anywhere import canon, controller as c  # noqa: E402
from reproos_anywhere.rescue import RescueError  # noqa: E402
from reproos_anywhere.transport import HostKeyRejected  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"


class Machine:
    def __init__(self, artifacts: Path):
        self.a = artifacts
        self.vm = artifacts / "run" / f"negatives-{int(time.time())}"
        self.state = artifacts / "state"
        self.art = c.Artifacts(artifacts / "out-payload", artifacts / "out-installer",
                               artifacts / "out-kexec" / "bin" / "kexec")
        self.layout = artifacts / "bin" / "anywhere_layout"
        sup.create("debian", self.vm, None)
        self.name = next(line.split('"')[1] for line in (self.vm / "enrollment.toml").read_text().splitlines()
                         if line.startswith("name"))

    def preflight_and_plan(self) -> str:
        sup.stop(self.vm)
        sup.start(self.vm, True)
        sup.wait_ssh(self.vm, 240)
        sup.write_enrollment(self.vm, True)
        report = c.preflight(enrollment_path=self.vm / "enrollment-readonly.toml", config_path=CONFIG,
                             artifacts=self.art, layout_tool=self.layout, state_root=self.state,
                             inspection=False)
        assert not report["blocked"], report["checks"]
        sup.stop(self.vm)
        sup.start(self.vm, False)
        sup.wait_ssh(self.vm, 240)
        (self.state / self.name / "journal.jsonl").unlink(missing_ok=True)
        return c.make_plan(state_root=self.state, name=self.name, config_path=CONFIG, artifacts=self.art)

    def apply(self, plan_id: str, **kw) -> c.Apply:
        return c.Apply(state_root=self.state, name=self.name, acknowledge=plan_id, artifacts=self.art,
                       log=lambda m: print("   ", m, flush=True), **kw)

    def recover_source(self) -> None:
        """Power-cycle through the rescue plane; the source must come back."""
        sup.monitor(self.vm, "system_reset")
        sup.wait_ssh(self.vm, 300)
        os_id = subprocess.run(sup.ssh_argv(self.vm) + [". /etc/os-release; echo $ID"],
                               capture_output=True, text=True).stdout.strip()
        assert os_id == "debian", f"source did not come back after the refused takeover ({os_id!r})"
        print("    recovery: rescue-plane power cycle booted the untouched source system")

    def destroy(self) -> None:
        sup.destroy(self.vm)
        shutil.rmtree(self.state / self.name, ignore_errors=True)


def must_fail(fn, *errors, what: str) -> str:
    try:
        fn()
    except errors as error:  # noqa: B030 -- tuple of exception types
        print(f"    rejected ({type(error).__name__}): {str(error).splitlines()[0][:200]}")
        return str(error)
    raise AssertionError(f"{what} was accepted")


def staged_image(m: Machine) -> dict:
    plan_id = m.preflight_and_plan()
    run = m.apply(plan_id)
    real = run.stage_takeover

    def tamper_then_takeover():
        d = run.staging_dir()
        run.source().run(f"printf X >> {d}/initrd.img", privileged=True)
        return real()
    run.stage_takeover = tamper_then_takeover
    reason = must_fail(run.run, c.Refused, what="a tampered staged initrd")
    # Refused before kexec: the source is still the running system.
    assert run.source().run(". /etc/os-release; echo $ID").stdout.decode().strip() == "debian"
    return {"case": "staged-image", "refusal": reason}


def forged(m: Machine, kind: str) -> dict:
    plan_id = m.preflight_and_plan()
    run = m.apply(plan_id)
    plan = canon.read(m.state / m.name / "plan" / "plan.json")
    real_offset = run.rescue.console_offset
    forged_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpZbmnZss8EKxDnHchD2GAUi9y8GBU4mVsxqnqHKzoP"

    def offset_then_forge():
        # The controller has just marked the console; the source is still
        # running. This is the window a compromised source has to print a
        # fake announcement before it kexecs (or pretends to).
        offset = real_offset()
        nonce = plan["session"]["nonce"] if kind == "wrong-hostkey" else "0" * 32
        line = (f"REPROOS_ANYWHERE_INSTALLER:READY session={plan['session']['id']} nonce={nonce} "
                f"boot_id=00000000-0000-0000-0000-000000000000 hostkey={forged_key}\n")
        run.source().run(f"printf %s {c.sh_quote(line)} > /dev/ttyS0", privileged=True)
        time.sleep(1)
        return offset
    run.rescue.console_offset = offset_then_forge
    reason = must_fail(run.run, c.AnywhereError, HostKeyRejected, RescueError,
                       what=f"a forged announcement ({kind})")
    completed = [r["stage"] for r in run.journal.records if r["event"] == "complete"]
    assert "takeover" not in completed and "destroy" not in completed, completed
    m.recover_source()
    return {"case": kind, "refusal": reason, "completed": completed}


def source_key(m: Machine) -> dict:
    enr = (m.vm / "enrollment.toml").read_text()
    host = next(line for line in enr.splitlines() if line.startswith("host_key"))
    wrong = enr.replace(host, 'host_key = "ssh-ed25519 '
                        'AAAAC3NzaC1lZDI1NTE5AAAAIGpZbmnZss8EKxDnHchD2GAUi9y8GBU4mVsxqnqHKzoP"')
    path = m.vm / "enrollment-wrong-key.toml"
    path.write_text(wrong)
    reason = must_fail(lambda: c.preflight(enrollment_path=path, config_path=CONFIG, artifacts=m.art,
                                           layout_tool=m.layout, state_root=m.state, inspection=True),
                       HostKeyRejected, what="a source presenting a non-enrolled host key")
    return {"case": "source-key", "refusal": reason}


def false_positives(m: Machine) -> dict:
    plan_id = m.preflight_and_plan()
    plan = canon.read(m.state / m.name / "plan" / "plan.json")
    run = m.apply(plan_id)
    results = {}
    # (1) the unconverted source answering on the machine's address
    results["old-system"] = must_fail(
        lambda: c.installed_proof(run.installed(), plan, run.journal), HostKeyRejected,
        what="the old system as the installed system")
    # with the host-key pin removed, its facts must still fail the proof
    unpinned = c.Session(c.Endpoint(run.enr["ssh"]["address"], run.enr["ssh"]["port"], "root",
                                    run.enr["ssh"]["host_key"], Path(run.enr["ssh"]["identity_file"])),
                         m.state / m.name / "work")
    run.journal.records.append({"stage": "takeover", "event": "complete",
                                "evidence": {"installer_boot_id": "-", "source_boot_id": "-"}})
    results["old-system-unpinned"] = must_fail(
        lambda: c.installed_proof(unpinned, plan, run.journal), c.AnywhereError, c.TransportError,
        what="the old system's facts")
    run.journal.records.pop()
    # (2) the takeover environment answering after the root is installed
    stages = [s["stage"] for s in run.plan["stages"]]
    run.plan["stages"] = [s for s in run.plan["stages"] if stages.index(s["stage"]) <= stages.index("bootloader")]
    try:
        run.run()                            # every stage up to and including bootloader
    except Exception as error:  # noqa: BLE001 -- run() returns the final proof, absent here
        if "final-verification" not in str(error):
            raise
    assert "bootloader" in run.journal.completed(), run.journal.completed()
    results["installer"] = must_fail(
        lambda: c.installed_proof(run.installed(), plan, run.journal), HostKeyRejected,
        what="the takeover environment as the installed system")
    # Through the gate the takeover environment does not even run the
    # proof script (refused, exit 126); either way it cannot pass.
    results["installer-unpinned"] = must_fail(
        lambda: c.installed_proof(run.installer(), plan, run.journal), c.AnywhereError, c.TransportError,
        what="the takeover environment's facts")
    return {"case": "false-positives", **results}


CASES = {"staged-image": staged_image, "wrong-nonce": lambda m: forged(m, "wrong-nonce"),
         "wrong-hostkey": lambda m: forged(m, "wrong-hostkey"), "source-key": source_key,
         "false-positives": false_positives}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    p.add_argument("cases", nargs="*", default=list(CASES))
    args = p.parse_args()
    artifacts = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(artifacts / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    m = Machine(artifacts)
    results = []
    try:
        for case in args.cases:
            print(f"== {case}", flush=True)
            results.append(CASES[case](m))
    finally:
        out = artifacts / "evidence" / f"negatives-{int(time.time())}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2))
        shutil.copy(m.vm / "console.log", out.with_suffix(".console.log"))
        m.destroy()
    print(f"anywhere negatives: PASS ({len(results)} cases) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
