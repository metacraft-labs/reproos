"""The apply journal: hash-chained, durable, causally ordered.

Ordering rule from the accepted M0 contract (corrected journal
definition): a stage's START is durably acknowledged BEFORE the stage
executes; its COMPLETION is durably acknowledged AFTER its postcondition
was verified and BEFORE the next stage starts. ``Journal`` enforces that
rule itself -- recording a completion for a stage that was not started,
starting a stage while another is open, or completing out of order
raises -- so a caller bug cannot produce an impossible history.

Each record carries the SHA-256 of the previous record's canonical bytes;
the first carries the plan identity. Records are appended to a JSON-lines
file with fsync of the file and its directory, then mirrored to every
configured sink (see ``evidence.py``). A sink that refuses the append
stops the apply: unrecorded progress is not allowed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
from pathlib import Path
from typing import Any, Callable, Iterable

from . import canon

EVENTS = {"start", "complete", "abort", "reconcile", "note"}


class JournalError(RuntimeError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Journal:
    def __init__(self, path: Path, plan_id: str,
                 sinks: Iterable[Callable[[bytes], None]] = ()):
        self.path = path
        self.plan_id = plan_id
        self.sinks = list(sinks)
        # Best-effort copies on the machine itself. The contract makes the
        # host journal "only a mirror": a mirror failure is reported to the
        # callback's owner and never stops or rewrites the authoritative copy.
        self.mirrors: list[Callable[[bytes], None]] = []
        self.records: list[dict[str, Any]] = []
        if path.exists():
            self._load()

    # -- reading ---------------------------------------------------------
    def _load(self) -> None:
        prev = self.plan_id
        with open(self.path, "rb") as handle:
            for number, line in enumerate(handle, 1):
                line = line.rstrip(b"\n")
                record = canon.decode(line)
                if record.get("prev") != prev:
                    raise JournalError(f"{self.path}:{number}: hash chain broken")
                if record.get("seq") != number:
                    raise JournalError(f"{self.path}:{number}: sequence gap")
                if record.get("plan") != self.plan_id:
                    raise JournalError(f"{self.path}:{number}: record of another plan")
                prev = hashlib.sha256(line).hexdigest()
                self.records.append(record)
        self._replay_check()

    def _replay_check(self) -> None:
        open_stage = None
        done = set()
        for r in self.records:
            stage, event = r["stage"], r["event"]
            if event == "start":
                if open_stage is not None and open_stage != stage:
                    raise JournalError(f"{stage} started while {open_stage} was open")
                open_stage = stage
            elif event == "complete":
                if open_stage != stage:
                    raise JournalError(f"{stage} completed without being started")
                done.add(stage)
                open_stage = None
            elif event == "abort":
                if open_stage == stage:
                    open_stage = None

    @property
    def head(self) -> str:
        if not self.records:
            return self.plan_id
        return hashlib.sha256(canon.encode(self.records[-1])).hexdigest()

    def completed(self) -> list[str]:
        return [r["stage"] for r in self.records if r["event"] == "complete"]

    def open_stage(self) -> str | None:
        state = None
        for r in self.records:
            if r["event"] == "start":
                state = r["stage"]
            elif r["event"] in ("complete", "abort") and r["stage"] == state:
                state = None
        return state

    def evidence(self, stage: str) -> dict[str, Any]:
        for r in reversed(self.records):
            if r["stage"] == stage and r["event"] == "complete":
                return r["evidence"]
        raise JournalError(f"{stage} has no completion record")

    # -- writing ---------------------------------------------------------
    def _append(self, stage: str, event: str, evidence: dict[str, Any]) -> dict[str, Any]:
        if event not in EVENTS:
            raise JournalError(f"unknown event {event}")
        open_stage = self.open_stage()
        if event == "start" and open_stage not in (None,):
            raise JournalError(f"cannot start {stage}: {open_stage} is still open")
        if event == "complete" and open_stage != stage:
            raise JournalError(f"cannot complete {stage}: it is not the open stage ({open_stage})")
        record = {
            "seq": len(self.records) + 1,
            "prev": self.head,
            "plan": self.plan_id,
            "time": _now(),
            "stage": stage,
            "event": event,
            "evidence": evidence,
        }
        data = canon.encode(record)
        # Sinks first: a refused off-host append must stop the stage
        # before the local journal claims anything happened.
        for sink in self.sinks:
            sink(data)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, data + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        self.records.append(record)
        for mirror in self.mirrors:
            try:
                mirror(data)
            except Exception:  # noqa: BLE001 -- a mirror is never authoritative
                pass
        return record

    def start(self, stage: str, intent: dict[str, Any]) -> None:
        self._append(stage, "start", intent)

    def complete(self, stage: str, evidence: dict[str, Any]) -> None:
        self._append(stage, "complete", evidence)

    def abort(self, stage: str, reason: str, evidence: dict[str, Any] | None = None) -> None:
        self._append(stage, "abort", {"reason": reason, **(evidence or {})})

    def reconcile(self, stage: str, finding: dict[str, Any]) -> None:
        self._append(stage, "reconcile", finding)

    def note(self, stage: str, what: dict[str, Any]) -> None:
        self._append(stage, "note", what)
