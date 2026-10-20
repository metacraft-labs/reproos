#!/usr/bin/env python3
"""test_reproos_anywhere_detection_and_append_only_capture (M3, MS-1 DET/EVID).

"Unexpected execution, writes, identity drift and lost heartbeat produce
attributed alerts and retained evidence; sink read/list/delete fail while
append succeeds."

A real evidence sink process (reproos-anywhere-sink serve) and one Debian
source VM, converted with the sink attached:

  exec       mid-materialize, a binary copied OUTSIDE the installer's
             verified closure is executed in the installer. The detector
             must halt the apply and the sink must hold an
             `unexpected-execution` alert naming that binary. A resume
             without --clear-detection must be refused.
  write      after clearing, a disk device is opened for writing during
             materialize (not a disk-writing stage): `unexpected-write`.
  heartbeat  a resumed apply is SIGKILLed mid-transfer; with no further
             appends or heartbeats the sink raises `heartbeat-lost`.
  drift      the installer's SSH host key is replaced; the next apply
             fails on the pinned key and reports `identity-drift`.
  sink       read, list and delete are refused and alerted while appends
             still succeed; the auditor finds the local journal consistent
             with the sink, then DIVERGENT once its newest record is edited.

    test_detection.py --artifacts DIR
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CLI = REPO / "tools" / "anywhere" / "reproos-anywhere"
SINK = REPO / "tools" / "anywhere" / "reproos-anywhere-sink"
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
import variants  # noqa: E402
from reproos_anywhere import canon, controller as c  # noqa: E402
from reproos_anywhere.evidence import Client  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"
WINDOW = 10


def alerts(sink_dir: Path) -> list[dict]:
    path = sink_dir / "alerts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def wait_alert(sink_dir: Path, kind: str, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [a for a in alerts(sink_dir) if a["kind"] == kind]
        if found:
            return found[-1]
        time.sleep(1)
    raise AssertionError(f"no {kind} alert; alerts: {[a['kind'] for a in alerts(sink_dir)]}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(a / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    stamp = int(time.time())
    vm, state = a / "run" / f"detect-{stamp}", a / "state"
    sink_dir = a / "evidence" / f"sink-{stamp}"
    sock = str(Path(tempfile.mkdtemp(prefix="aw-sink-", dir=os.environ.get("XDG_RUNTIME_DIR", "/tmp")))
               / "sink.sock")
    sink = subprocess.Popen([sys.executable, str(SINK), "serve", "--dir", str(sink_dir), "--socket", sock,
                             "--heartbeat-window", str(WINDOW)])
    # Detection is the defence for when confinement already failed: the
    # injections below need a shell in the installer, so this gate runs a
    # build WITHOUT the installer gate (the other controls stay).
    installer = variants.build_installer([c_ for c_ in variants.ALL_CONTROLS if c_ != "gate"])
    art = c.Artifacts(a / "out-payload", installer, a / "out-kexec" / "bin" / "kexec")
    common = [sys.executable, str(CLI), "--state", str(state), "--payload", str(a / "out-payload"),
              "--installer", str(installer), "--kexec", str(a / "out-kexec" / "bin" / "kexec"),
              "--layout-tool", str(a / "bin" / "anywhere_layout")]
    results = {}
    name = ""
    try:
        sup.create("debian", vm, None)
        name = next(line.split('"')[1] for line in (vm / "enrollment.toml").read_text().splitlines()
                    if line.startswith("name"))
        sup.stop(vm)
        sup.start(vm, True)
        sup.wait_ssh(vm, 240)
        sup.write_enrollment(vm, True)
        subprocess.run(common + ["preflight", "--enrollment", str(vm / "enrollment-readonly.toml"),
                                 "--config", str(CONFIG)], check=True, capture_output=True)
        sup.stop(vm)
        sup.start(vm, False)
        sup.wait_ssh(vm, 240)
        out = subprocess.run(common + ["plan", "--name", name, "--config", str(CONFIG)],
                             check=True, capture_output=True, text=True).stdout
        plan_id = out.strip().splitlines()[-1].split()[-1]

        def apply(**kw) -> c.Apply:
            return c.Apply(state_root=state, name=name, acknowledge=plan_id, artifacts=art,
                           evidence_sink=sock, log=lambda m: print("   ", m, flush=True), **kw)

        def inject(run: c.Apply, command: str, stage: str) -> None:
            attr = "stage_" + stage.replace("-", "_")
            real = getattr(run, attr)

            def wrapped():
                run.installer().run(command)
                return real()
            setattr(run, attr, wrapped)

        # -- exec -------------------------------------------------------------
        print("== exec", flush=True)
        run = apply()
        # busybox picks its applet from its own name, so the copy is named one.
        inject(run, "cp $(readlink -f $(command -v busybox)) /run/true && /run/true",
               "materialize")
        try:
            run.run()
            raise AssertionError("an unexpected execution did not halt the apply")
        except c.AnywhereError as error:
            print(f"    halted: {str(error)[:160]}", flush=True)
        alert = wait_alert(sink_dir, "unexpected-execution")
        assert "/run/true" in alert["detail"], alert
        try:
            apply(resume=True)
            raise AssertionError("resume after a detection halt was not refused")
        except c.Refused as error:
            print(f"    resume refused until cleared: {str(error)[:120]}", flush=True)
        results["exec"] = alert

        # -- write ------------------------------------------------------------
        print("== write", flush=True)
        run = apply(resume=True, clear_detection=True)
        device = run.plan["storage"]["device"]
        # inject-secrets runs on resume (materialize is reconciled) and is not
        # a stage allowed to open a disk for writing.
        inject(run, f"dd if={device} of={device} bs=512 count=1 seek=2047 skip=2047 conv=notrunc "
               "status=none", "inject-secrets")
        try:
            run.run()
            raise AssertionError("an unexpected disk write did not halt the apply")
        except c.AnywhereError as error:
            print(f"    halted: {str(error)[:160]}", flush=True)
        alert = wait_alert(sink_dir, "unexpected-write")
        assert device in alert["detail"], alert
        results["write"] = alert

        # -- heartbeat --------------------------------------------------------
        print("== heartbeat", flush=True)
        journal_path = state / name / "journal.jsonl"
        before = len(journal_path.read_bytes().splitlines())
        lost_before = len([x for x in alerts(sink_dir) if x["kind"] == "heartbeat-lost"])
        proc = subprocess.Popen(common + ["resume", "--name", name, "--acknowledge", plan_id,
                                          "--evidence-sink", sock, "--clear-detection",
                                          "--max-rate", str(1024 * 1024)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + 300
        while len(journal_path.read_bytes().splitlines()) <= before and time.monotonic() < deadline:
            time.sleep(0.1)
        proc.send_signal(signal.SIGKILL)          # dies mid-apply: no close, no more heartbeats
        proc.wait()
        deadline = time.monotonic() + WINDOW * 4
        while time.monotonic() < deadline:
            lost = [x for x in alerts(sink_dir) if x["kind"] == "heartbeat-lost"]
            if len(lost) > lost_before:
                break
            time.sleep(1)
        else:
            raise AssertionError("killing the controller raised no heartbeat-lost alert")
        results["heartbeat"] = lost[-1]

        # -- drift ------------------------------------------------------------
        print("== drift", flush=True)
        run = apply(resume=True, clear_detection=True)
        inst = run.installer()
        inst.run("rm -f /etc/ssh/ssh_host_ed25519_key* && ssh-keygen -q -t ed25519 -N '' "
                 "-f /etc/ssh/ssh_host_ed25519_key && kill -HUP $(cat /run/sshd.pid)")
        time.sleep(2)
        try:
            run.run()
            raise AssertionError("a changed installer key was accepted")
        except (c.HostKeyRejected, c.AnywhereError) as error:
            print(f"    refused: {str(error)[:160]}", flush=True)
        results["drift"] = wait_alert(sink_dir, "identity-drift")

        # -- sink boundary ----------------------------------------------------
        print("== sink", flush=True)
        client = Client(sock, plan_id)
        for op in ("read", "list", "delete", "truncate"):
            reply = client.request({"op": op, "stream": plan_id})
            assert not reply["ok"], (op, reply)
        denied = [x for x in alerts(sink_dir) if x["kind"] == "denied-operation"]
        assert len(denied) >= 4, denied
        from reproos_anywhere.journal import Journal
        j = Journal(journal_path, plan_id, sinks=[client.append])
        j.note("sink-check", {"append": "still accepted"})                  # append still works
        audit = subprocess.run([sys.executable, str(SINK), "audit", "--dir", str(sink_dir),
                                "--journal", str(journal_path), "--plan", plan_id], capture_output=True, text=True)
        assert audit.returncode == 0, audit.stdout
        lines = journal_path.read_bytes().splitlines()
        lines[-1] = lines[-1].replace(b"still accepted", b"forged history")
        journal_path.write_bytes(b"\n".join(lines) + b"\n")
        audit = subprocess.run([sys.executable, str(SINK), "audit", "--dir", str(sink_dir),
                                "--journal", str(journal_path), "--plan", plan_id], capture_output=True, text=True)
        assert audit.returncode == 1 and "DIVERGENT" in audit.stdout, audit.stdout
        results["sink"] = {"denied": len(denied), "audit": audit.stdout.strip().splitlines()[-1]}
        print(f"test_reproos_anywhere_detection_and_append_only_capture: PASS -> {sink_dir}")
        return 0
    finally:
        (sink_dir / "result.json").write_text(json.dumps(results, indent=2, default=str))
        sink.terminate()
        if (vm / "console.log").exists():
            shutil.copy(vm / "console.log", sink_dir / "console.log")
        sup.destroy(vm)
        if name:
            shutil.rmtree(state / name, ignore_errors=True)
        shutil.rmtree(Path(sock).parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
