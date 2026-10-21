#!/usr/bin/env python3
"""e2e_reproos_anywhere_compromise_drill (M5, MS-1 drill).

"Compromise triggers detection, capture, read-only investigation,
quarantine, revocation and independent rescue; restored host identity is
verified."

One Debian source VM is converted with an evidence sink attached; after
destroy, an intruder binary runs in the takeover environment. Then:

  detect       the apply halts and the sink holds an attributed
               unexpected-execution alert;
  capture      a failure bundle is written and the sink's copy of the
               journal audits consistent with the controller's;
  investigate  the read-only report names the intruder and records that
               storage was destroyed (nothing is sent to the machine);
  contain      the machine is frozen, its memory captured, powered off; the
               plan and every credential it issued are revoked; resuming the
               plan is refused;
  rescue       `replan` issues a new plan (rescue-media, fresh session, host
               and access keys) and applying it converts the machine again;
  identity     the installed proof passes with the NEW host key, and the
               revoked one is refused by the restored machine.

The intruder needs a shell in the takeover environment, so the build
without the installer gate is used (confinement has its own gate).

    test_compromise_drill.py --artifacts DIR
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SINK = REPO / "tools" / "anywhere" / "reproos-anywhere-sink"
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import supervisor as sup  # noqa: E402
import variants  # noqa: E402
from reproos_anywhere import canon, controller as c, recovery  # noqa: E402
from reproos_anywhere.transport import HostKeyRejected  # noqa: E402

CONFIG = REPO / "tests" / "fixtures" / "auto-config-minimal.toml"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    os.environ.setdefault("ANYWHERE_IMAGE_CACHE", str(a / "images"))
    sup.IMAGE_CACHE = Path(os.environ["ANYWHERE_IMAGE_CACHE"])
    stamp = int(time.time())
    vm, state = a / "run" / f"drill-{stamp}", a / "state"
    evidence = a / "evidence" / f"drill-{stamp}"
    evidence.mkdir(parents=True)
    sock = str(Path(tempfile.mkdtemp(prefix="aw-drill-", dir=os.environ.get("XDG_RUNTIME_DIR", "/tmp")))
               / "sink.sock")
    sink = subprocess.Popen([sys.executable, str(SINK), "serve", "--dir", str(evidence / "sink"),
                             "--socket", sock, "--heartbeat-window", "120"])
    installer = variants.build_installer([x for x in variants.ALL_CONTROLS if x != "gate"])
    art = c.Artifacts(a / "out-payload", installer, a / "out-kexec" / "bin" / "kexec")
    result, name = {}, ""
    log = lambda m: print("   ", m, flush=True)  # noqa: E731
    try:
        sup.create("debian", vm, None)
        name = next(line.split('"')[1] for line in (vm / "enrollment.toml").read_text().splitlines()
                    if line.startswith("name"))
        sdir = state / name
        sup.stop(vm)
        sup.start(vm, True)
        sup.wait_ssh(vm, 240)
        sup.write_enrollment(vm, True)
        c.preflight(enrollment_path=vm / "enrollment-readonly.toml", config_path=CONFIG, artifacts=art,
                    layout_tool=a / "bin" / "anywhere_layout", state_root=state, inspection=False)
        sup.stop(vm)
        sup.start(vm, False)
        sup.wait_ssh(vm, 240)
        plan_id = c.make_plan(state_root=state, name=name, config_path=CONFIG, artifacts=art)
        old_plan = canon.read(sdir / "plan" / "plan.json")

        print("== detect", flush=True)
        run = c.Apply(state_root=state, name=name, acknowledge=plan_id, artifacts=art, evidence_sink=sock, log=log)
        real = run.stage_materialize

        def intrude():
            run.installer().run("cp $(readlink -f $(command -v busybox)) /run/true && /run/true")
            return real()
        run.stage_materialize = intrude
        try:
            run.run()
            raise AssertionError("the intrusion did not halt the apply")
        except c.AnywhereError as error:
            print(f"    halted: {str(error)[:140]}", flush=True)
        alerts = [json.loads(x) for x in (evidence / "sink" / "alerts.jsonl").read_text().splitlines()]
        intrusion = [x for x in alerts if x["kind"] == "unexpected-execution"]
        assert intrusion and "/run/true" in intrusion[0]["detail"], alerts
        result["detect"] = intrusion[0]["detail"]

        print("== capture", flush=True)
        manifest = recovery.bundle(sdir, evidence / "bundle.tar.gz")
        audit = subprocess.run([sys.executable, str(SINK), "audit", "--dir", str(evidence / "sink"),
                                "--journal", str(sdir / "journal.jsonl"), "--plan", plan_id],
                               capture_output=True, text=True)
        assert audit.returncode == 0, audit.stdout
        result["capture"] = {"bundle_files": len(manifest["files"]), "sink_audit": audit.stdout.strip()}

        print("== investigate", flush=True)
        report = recovery.investigate(sdir)
        assert any("/run/true" in e for e in report["detections"]), report
        assert report["storage_destroyed"], report
        result["investigate"] = report

        print("== contain", flush=True)
        contained = recovery.contain(sdir, evidence, log=log)
        assert Path(contained["memory_capture"]).stat().st_size > 0
        assert not any(k.name.startswith("session_") for k in (sdir / "keys").glob("*"))
        try:
            c.Apply(state_root=state, name=name, acknowledge=plan_id, artifacts=art, resume=True)
            raise AssertionError("a revoked plan was accepted")
        except c.Refused as error:
            print(f"    revoked plan refused: {str(error)[:100]}", flush=True)
        result["contain"] = {k: contained[k] for k in ("memory_sha256", "revoked_credentials")}

        print("== rescue", flush=True)
        st = c.State(state, name)
        new_id = recovery.replan(sdir, st.controller_key, st.controller_pub, log=log)
        proof = c.Apply(state_root=state, name=name, acknowledge=new_id, artifacts=art, evidence_sink=sock,
                        log=log).run()
        assert proof["verdict"] == "installed", proof
        new_plan = canon.read(sdir / "plan" / "plan.json")

        print("== identity", flush=True)
        assert new_plan["identities"]["installed_host_key"] != old_plan["identities"]["installed_host_key"]
        stale = c.Session(c.Endpoint(run.enr["ssh"]["address"], run.enr["ssh"]["port"],
                                     new_plan["configuration"]["user"], old_plan["identities"]["installed_host_key"],
                                     sdir / "keys" / "access_ed25519"), sdir / "work")
        try:
            stale.run("true", timeout=30)
            raise AssertionError("the restored machine answered on the REVOKED host key")
        except HostKeyRejected:
            pass
        result["identity"] = {"new_plan": new_id, "recovery_of": new_plan["recovery_of"],
                              "host_key_fingerprint": proof["host_key_fingerprint"],
                              "revoked_key_refused": True}
        print(f"e2e_reproos_anywhere_compromise_drill: PASS -> {evidence}")
        return 0
    finally:
        (evidence / "result.json").write_text(json.dumps(result, indent=2, default=str))
        for f in evidence.glob("memory-*.elf"):
            f.unlink()                          # large; its digest is in the journal and result
        sink.terminate()
        if (vm / "console.log").exists():
            shutil.copy(vm / "console.log", evidence / "console.log")
        sup.destroy(vm)
        if name:
            shutil.rmtree(state / name, ignore_errors=True)
        shutil.rmtree(Path(sock).parent, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
