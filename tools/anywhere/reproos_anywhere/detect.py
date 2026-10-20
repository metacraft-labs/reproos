"""Detection in the takeover environment (M3, MS-1 DET).

The installer's kernel audits every execve and every write-open of a disk
device node and -- with no audit daemon -- prints the records to its
console. The console is the rescue plane: the controller reads it from
the management side, and nothing running in the installer can retract a
line once printed. The audit rules are locked immutable at boot.

The detector reads those records in order and attributes them to the
window they fell in -- a stage, or the gap between two stages -- and
raises on:

  unexpected-execution  an exec whose binary is not part of the installer
                        closure verified at takeover (anything under
                        /tmp, /run, /dev/shm, the target root, ...);
  unexpected-write      a write-open of a disk device outside the stages
                        that are allowed to write one;
  audit-loss            the kernel reporting lost audit records, or the
                        audit configuration changing after takeover --
                        detection that may be blind fails closed.

Identity drift (the installer stops presenting its pinned key) is raised
by the transport and reported through the same alert path by the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Stages whose job includes opening a disk device for writing: the broker
# wipes, partitions and formats, and mount(8) opens the filesystems it
# mounts read-write.
DISK_WRITE_STAGES = {"destroy", "format", "mount", "bootloader"}

RECORD = re.compile(r"audit: type=(\d+) audit\(([0-9.]+):(\d+)\): (.*)")
FIELD = re.compile(r'(\w+)=("[^"]*"|\S+)')


@dataclass
class Event:
    kind: str
    window: str
    serial: int
    detail: dict

    def describe(self) -> str:
        d = self.detail
        return (f"{self.kind} during {self.window}: exe={d.get('exe')} comm={d.get('comm')} "
                f"pid={d.get('pid')} ppid={d.get('ppid')} uid={d.get('uid')}"
                + (f" path={d['path']}" if d.get("path") else ""))


def _fields(text: str) -> dict:
    return {k: v.strip('"') for k, v in FIELD.findall(text)}


class Detector:
    def __init__(self, allowed_store_paths: set[str]):
        self.allowed = allowed_store_paths
        self.records: dict[int, dict] = {}
        self.seen_serials: set[int] = set()

    def _allowed_exe(self, exe: str) -> bool:
        if not exe.startswith("/nix/store/"):
            return False
        return "/".join(exe.split("/")[:4]) in self.allowed

    def scan(self, console_text: str, window: str) -> list[Event]:
        """Classify every audit record in ``console_text`` not seen before,
        attributing it to ``window``. Records of one event share a serial."""
        by_serial: dict[int, list[tuple[int, dict]]] = {}
        for line in console_text.splitlines():
            m = RECORD.search(line)
            if not m:
                if "audit_lost" in line or "audit: backlog limit exceeded" in line:
                    by_serial.setdefault(-1, []).append((0, {"lost": line.strip()}))
                continue
            rtype, serial, rest = int(m.group(1)), int(m.group(3)), m.group(4)
            by_serial.setdefault(serial, []).append((rtype, _fields(rest)))
        events: list[Event] = []
        for serial, recs in sorted(by_serial.items()):
            if serial in self.seen_serials:
                continue
            if serial == -1:
                events.append(Event("audit-loss", window, -1, {"exe": None, **recs[0][1]}))
                continue
            syscall = next((f for t, f in recs if t == 1300), None)
            config = next((f for t, f in recs if t == 1305), None)   # AUDIT_CONFIG_CHANGE
            if syscall is None and config is None:
                continue        # the SYSCALL record has not been printed yet; next scan
            self.seen_serials.add(serial)
            if config is not None:
                events.append(Event("audit-loss", window, serial, {"exe": None, "config_change": config}))
                continue
            key = syscall.get("key", "")
            paths = [f.get("name", "") for t, f in recs if t == 1302]
            detail = {k: syscall.get(k) for k in ("exe", "comm", "pid", "ppid", "uid")}
            if key == "anywhere-exec" and not self._allowed_exe(syscall.get("exe", "")):
                events.append(Event("unexpected-execution", window, serial, detail))
            elif key == "anywhere-disk-write" and window not in DISK_WRITE_STAGES:
                devices = [p for p in paths if p.startswith("/dev/")]
                events.append(Event("unexpected-write", window, serial,
                                    {**detail, "path": ",".join(devices)}))
        return events
