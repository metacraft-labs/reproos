"""The rescue plane: a management channel independent of the machine's SSH.

The safety contract requires an independent route to every machine
before anything destructive happens -- provider serial console, rescue
boot, or a physical console. The controller uses it for two things:

  * reading identity announcements (the takeover environment's freshly
    generated host key and the session nonce) from a channel the
    machine's SSH endpoint cannot write to; and
  * recovery: power-cycling or reattaching rescue media when SSH is gone.

Only the QEMU adapter exists: a serial console captured to a file by the
supervisor and the QEMU human monitor on a UNIX socket. Provider adapters
(Hetzner, AWS serial console, IPMI) are M6 work; an enrollment naming one
fails at load time rather than silently degrading.
"""

from __future__ import annotations

import re
import socket
import subprocess
import time
from pathlib import Path

ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\r")


class RescueError(RuntimeError):
    pass


class QemuRescue:
    def __init__(self, console_log: str, monitor: str, boot_command: list[str] | None = None,
                 restore_command: list[str] | None = None):
        self.console_log = Path(console_log)
        self.monitor = monitor
        self.boot_command = boot_command
        self.restore_command = restore_command

    # -- rescue-media boot ------------------------------------------------
    @property
    def can_boot_media(self) -> bool:
        return bool(self.boot_command and self.restore_command)

    def boot_media(self, kernel: str, initrd: str, cmdline: str) -> None:
        """Power the machine off and boot it from the given kernel/initrd
        through the management plane; its own disk is not involved."""
        if not self.can_boot_media:
            raise RescueError("this rescue route cannot boot media")
        proc = subprocess.run([*self.boot_command, kernel, initrd, cmdline], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RescueError(f"rescue boot failed: {proc.stderr.strip()[-1000:]}")

    def restore_disk_boot(self) -> None:
        proc = subprocess.run(self.restore_command, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RescueError(f"restoring disk boot failed: {proc.stderr.strip()[-1000:]}")

    # -- console ---------------------------------------------------------
    def console_offset(self) -> int:
        try:
            return self.console_log.stat().st_size
        except FileNotFoundError:
            return 0

    def console_since(self, offset: int) -> str:
        try:
            with open(self.console_log, "rb") as handle:
                handle.seek(offset)
                data = handle.read(16 * 1024 * 1024)
        except FileNotFoundError:
            return ""
        return ANSI.sub(b"", data).decode("utf-8", "replace")

    def wait_for_line(self, offset: int, pattern: re.Pattern, timeout: float,
                      fail: re.Pattern | None = None) -> re.Match:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.console_since(offset)
            for line in text.splitlines():
                m = pattern.search(line)
                if m:
                    return m
                if fail is not None and fail.search(line):
                    raise RescueError(f"console reported failure: {line.strip()}")
            time.sleep(1)
        raise RescueError(f"no console line matching {pattern.pattern!r} within {timeout}s")

    # -- monitor ---------------------------------------------------------
    def hmp(self, command: str, timeout: float = 10) -> str:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(self.monitor)
            buf = b""
            while b"(qemu)" not in buf:
                buf += sock.recv(4096)
            sock.sendall(command.encode() + b"\n")
            buf = b""
            while buf.count(b"(qemu)") < 1:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return ANSI.sub(b"", buf).decode("utf-8", "replace")
        except OSError as error:
            raise RescueError(f"monitor {self.monitor}: {error}") from error
        finally:
            sock.close()

    def reachable(self) -> bool:
        try:
            return "QEMU" in self.hmp("info version") or "(qemu)" in self.hmp("info status")
        except RescueError:
            return False

    def target_mode(self, serial: str) -> str:
        """How the management plane has the disk with ``serial`` attached:
        "writable", "read-only", or "snapshot" (writes land in an overlay
        QEMU discards when it exits). The machine cannot influence this
        answer, which is the point: a conversion applied while the machine
        is still in its planning environment would report success and then
        vanish at the next power cycle."""
        qtree = self.hmp("info qtree", timeout=30)
        drive = None
        for block in qtree.split("dev: "):
            if f'serial = "{serial}"' in block:
                m = re.search(r'drive = "([^"]+)"', block)
                drive = m.group(1) if m else None
        if not drive:
            raise RescueError(f"the management plane shows no drive with serial {serial}")
        info = self.hmp(f"info block {drive}")
        header = next((line for line in info.splitlines() if line.startswith(f"{drive} ")), "")
        if not header:
            raise RescueError(f"the management plane does not describe drive {drive}: {info.strip()[:300]}")
        if "read-only" in header:
            return "read-only"
        if re.search(r'/vl\.\w+"', header) or "ignore flushes" in info:
            return "snapshot"
        return "writable"

    def power_cycle(self) -> None:
        self.hmp("system_reset")

    def set_link(self, netdev: str, up: bool) -> None:
        self.hmp(f"set_link {netdev} {'on' if up else 'off'}")


def adapter(rescue: dict) -> QemuRescue:
    if rescue["kind"] != "qemu-serial":
        raise RescueError(f"no adapter for rescue kind {rescue['kind']!r}")
    return QemuRescue(rescue["console_log"], rescue["monitor"],
                      rescue.get("boot_command"), rescue.get("restore_command"))
