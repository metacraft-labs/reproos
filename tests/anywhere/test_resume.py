#!/usr/bin/env python3
"""e2e_reproos_anywhere_apply_resumes_after_disconnect (M3).

"Interruptions during transfer and installation resume from verified
checkpoints without replaying completed destructive actions."

One Debian source VM is converted with two real interruptions:

  controller-crash  the controller process is SIGKILLed while the `format`
                    stage is open (journal start durable, completion not).
                    `resume` must reconcile it from the disk's actual state
                    and must NOT format again: the root filesystem UUID read
                    before the crash is the one after resume.
  link-cut          during `materialize` the payload is streamed at a
                    bounded rate and the machine's network link is cut
                    through the QEMU monitor (the supervisor's management
                    plane) halfway through. The apply fails; the link comes
                    back; `resume` continues the transfer from the bytes
                    already on the target, verifies the digest, and the
                    conversion completes and passes the installed proof.

Journal assertions: destroy and format each have exactly one `start`;
format and materialize carry `reconcile` records; nothing destructive
started twice.

    test_resume.py --artifacts DIR
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CLI = REPO / "tools" / "anywhere" / "reproos-anywhere"
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
from reproos_anywhere import canon, controller as c  # noqa: E402
from reproos_anywhere.journal import Journal  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"
RATE = 4 * 1024 * 1024            # ~25 s for the fixture payload: room to cut mid-stream


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(a / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    vm = a / "run" / f"resume-{int(time.time())}"
    state = a / "state"
    art = c.Artifacts(a / "out-payload", a / "out-installer", a / "out-kexec" / "bin" / "kexec")
    common = [sys.executable, str(CLI), "--state", str(state), "--payload", str(a / "out-payload"),
              "--installer", str(a / "out-installer"), "--kexec", str(a / "out-kexec" / "bin" / "kexec"),
              "--layout-tool", str(a / "bin" / "anywhere_layout")]
    sup.create("debian", vm, None)
    name = next(line.split('"')[1] for line in (vm / "enrollment.toml").read_text().splitlines()
                if line.startswith("name"))
    journal_path = state / name / "journal.jsonl"
    result = {}
    try:
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
        plan = canon.read(state / name / "plan" / "plan.json")

        def journal() -> Journal:
            return Journal(journal_path, plan_id)

        # -- interruption 1: kill the controller with `format` open ----------
        print("== controller-crash", flush=True)
        proc = subprocess.Popen(common + ["apply", "--name", name, "--acknowledge", plan_id,
                                          "--max-rate", str(RATE)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if journal_path.exists() and journal().open_stage() == "format":
                break
            if proc.poll() is not None:
                raise AssertionError(f"apply ended before format started:\n{proc.stdout.read()}")
            time.sleep(0.05)
        else:
            raise AssertionError("format never started")
        # Let the broker get going, then kill the controller hard.
        time.sleep(2)
        proc.send_signal(signal.SIGKILL)
        proc.wait()
        print("    controller killed with format open", flush=True)
        run = c.Apply(state_root=state, name=name, acknowledge=plan_id, artifacts=art, resume=True,
                      log=lambda m: print("   ", m, flush=True), max_rate=RATE)
        inst = run.installer()
        # The broker may still be finishing the format it was asked for.
        for _ in range(60):
            if run.layout_state() == "formatted":
                break
            time.sleep(2)
        uuid_before = inst.run(f"blkid -s UUID -o value {plan['storage']['device']}2").stdout.decode().strip()
        assert uuid_before, "no root filesystem after the interrupted format"

        # -- interruption 2: cut the link halfway through the payload --------
        print("== link-cut", flush=True)
        size = (a / "out-payload" / "rootfs.tar.zst").stat().st_size
        remote = f"{c.TARGET_ROOT}/.anywhere/rootfs.tar.zst"
        cut = {}

        def cutter():
            while True:
                try:
                    have = int(inst.run(f"stat -c %s {remote} 2>/dev/null || echo 0",
                                        timeout=10).stdout.decode().strip() or 0)
                except c.TransportError:
                    have = 0
                if have > size // 2:
                    sup.monitor(vm, "set_link n0 off")
                    cut["at"] = have
                    return
                time.sleep(0.5)
        watcher = threading.Thread(target=cutter, daemon=True)
        watcher.start()
        try:
            run.run()
            raise AssertionError("apply survived a cut link")
        except (c.AnywhereError, c.TransportError) as error:
            print(f"    apply failed as expected: {str(error).splitlines()[0][:160]}", flush=True)
        watcher.join(timeout=5)
        assert "at" in cut, "the link was never cut"
        time.sleep(3)
        sup.monitor(vm, "set_link n0 on")
        print(f"    link cut at {cut['at']} of {size} bytes, restored", flush=True)

        resumed = []
        run = c.Apply(state_root=state, name=name, acknowledge=plan_id, artifacts=art, resume=True,
                      log=lambda m: (resumed.append(m), print("   ", m, flush=True)), max_rate=0)
        proof = run.run()
        sends = [m for m in resumed if "sending rootfs.tar.zst from byte" in m]
        assert sends, f"materialize did not resend anything: {resumed}"
        resumed_from = int(sends[0].split("from byte ")[1].split()[0])
        assert resumed_from > 0, f"transfer restarted from 0 instead of resuming ({sends[0]})"
        uuid_after = run.installed().run("findmnt -n -o UUID /").stdout.decode().strip()
        assert uuid_after == uuid_before, f"root filesystem was re-created ({uuid_before} -> {uuid_after})"

        records = journal().records
        starts = {}
        for r in records:
            if r["event"] == "start":
                starts[r["stage"]] = starts.get(r["stage"], 0) + 1
        for stage in ("destroy", "format"):
            assert starts.get(stage) == 1, f"{stage} started {starts.get(stage)} times"
        reconciled = sorted({r["stage"] for r in records if r["event"] == "reconcile"})
        assert "format" in reconciled and "materialize" in reconciled, reconciled
        assert proof["verdict"] == "installed"
        result = {"plan": plan_id, "format_uuid": uuid_before, "link_cut_at": cut["at"],
                  "payload_bytes": size, "resumed_from": resumed_from, "starts": starts,
                  "reconciled": reconciled, "proof": proof}
        print(f"e2e_reproos_anywhere_apply_resumes_after_disconnect: PASS "
              f"(format UUID kept {uuid_before}; transfer resumed from byte {resumed_from})")
        return 0
    finally:
        out = a / "evidence" / f"resume-{int(time.time())}"
        out.mkdir(parents=True, exist_ok=True)
        (out / "result.json").write_text(json.dumps(result, indent=2))
        for f in (vm / "console.log", journal_path):
            if f.exists():
                shutil.copy(f, out / f.name)
        sup.destroy(vm)
        shutil.rmtree(state / name, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
