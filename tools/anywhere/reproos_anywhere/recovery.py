"""Recovery, rollback and failure bundles (M5).

When rollback is possible, and how (the M0 contract's rollback table):

  before `destroy` starts   AUTOMATIC rollback: nothing on the target has
                            been written. `abort` returns the machine to its
                            source system -- removes the RAM staging, or
                            power-cycles out of a kexec takeover, or leaves
                            rescue mode -- and proves the source answers on
                            its enrolled host key again.
  after `destroy` started   rollback is IMPOSSIBLE: the source system's
                            storage is gone. Recovery is forward only:
                            `resume` (reconciling, never replaying),
                            `resume --reformat` (operator-confirmed: format
                            the failed install again), or `recover` after a
                            reboot that did not produce the installed proof.

`bundle` writes everything an investigator needs about one conversion --
plan, signature, journal, reports, inventory, detector state, the rescue
console -- and nothing that authenticates anyone: no private key, no
session key, no known_hosts.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
from pathlib import Path

from . import canon
from .journal import Journal
from .rescue import adapter as rescue_adapter
from .transport import HostKeyRejected, TransportError

SECRET_MARKERS = (b"PRIVATE KEY", b"BEGIN OPENSSH")


class RecoveryError(RuntimeError):
    pass


def _load(state_dir: Path) -> tuple[dict, str, Journal, dict]:
    plan = canon.read(state_dir / "plan" / "plan.json")
    plan_id = canon.digest(plan)
    journal = Journal(state_dir / "journal.jsonl", plan_id)
    enr = canon.read(state_dir / "enrollment.json")
    return plan, plan_id, journal, enr


def started(journal: Journal) -> set[str]:
    return {r["stage"] for r in journal.records if r["event"] == "start"}


def aborted(journal: Journal) -> bool:
    return any(r["stage"] == "plan" and r["event"] == "note" and r["evidence"].get("aborted")
               for r in journal.records)


def abort(state_dir: Path, source_session_factory, log=print) -> dict:
    """Roll back to the source system; refuse once storage was touched."""
    plan, plan_id, journal, enr = _load(state_dir)
    if aborted(journal):
        raise RecoveryError("this plan was already aborted")
    begun = started(journal)
    if "destroy" in begun:
        raise RecoveryError("destroy has started: the source system's storage may be gone and rollback "
                            "is impossible; recover forward with `resume` or `recover`")
    rescue = rescue_adapter(enr["rescue"])
    steps = []
    if "takeover" in begun:
        if plan["takeover"] == "rescue-media":
            rescue.restore_disk_boot()
            steps.append("left rescue mode; booting the source from its own disk")
        else:
            rescue.power_cycle()
            steps.append("power-cycled out of the takeover environment")
    session = source_session_factory()
    deadline = time.monotonic() + 300
    while True:
        try:
            if session.reachable(timeout=10):
                break
        except HostKeyRejected as error:
            raise RecoveryError(f"something else answers on the source's address: {error}") from error
        if time.monotonic() > deadline:
            raise RecoveryError("the source system did not come back; use the rescue route "
                                f"{enr['rescue']['console_log']}")
        time.sleep(5)
    if "stage-payload" in begun and plan["takeover"] == "kexec":
        session.run(f"rm -rf /dev/shm/reproos-anywhere-{plan['session']['id']}", privileged=True, check=False)
        steps.append("removed the RAM staging directory")
    os_id = session.run("(. /etc/os-release && echo $ID)", check=False).stdout.decode().strip()
    if os_id == "reproos":
        raise RecoveryError("the machine answering is a ReproOS system, not the source")
    evidence = {"rolled_back_to": os_id, "steps": steps, "source_key": enr["ssh"]["host_key"]}
    if journal.open_stage():
        journal.abort(journal.open_stage(), "rolled back to the source system")
    journal.note("plan", {"aborted": True, **evidence})
    log(f"rolled back: {'; '.join(steps) or 'nothing had reached the machine'}; the source ({os_id}) answers "
        "on its enrolled host key")
    return evidence


def bundle(state_dir: Path, out: Path) -> dict:
    """A failure bundle: everything to investigate, nothing that authenticates."""
    plan, plan_id, journal, enr = _load(state_dir)
    files: dict[str, bytes] = {}
    for rel in ("plan/plan.json", "plan/plan.sig", "journal.jsonl", "compatibility.json", "inventory.json",
                "probe.out", "enrollment.json", "detect.json", "auto-config.toml"):
        p = state_dir / rel
        if p.exists():
            files[rel] = p.read_bytes()
    console = Path(enr["rescue"]["console_log"])
    if console.exists():
        files["rescue-console.log"] = console.read_bytes()[-32 * 1024 * 1024:]
    for name, data in files.items():
        for marker in SECRET_MARKERS:
            if marker in data:
                raise RecoveryError(f"{name} contains {marker.decode()!r}; refusing to bundle a credential")
    manifest = {
        "schema": "reproos-anywhere-failure-bundle/1", "plan": plan_id, "machine": plan["machine"]["name"],
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "completed": journal.completed(), "open": journal.open_stage(),
        "files": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(files.items())},
        "excluded": ["keys/ (private keys and the per-plan session key)", "work/ (known_hosts, staging)"],
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return manifest
