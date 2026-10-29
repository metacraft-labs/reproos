#!/usr/bin/env python3
"""test_reproos_anywhere_installer_confinement_and_isolation (M2, MS-1 CONF/FLOW).

"Removing each capability, writable-path or egress/zone control
independently makes the hardening gate fail; the allowed installer
channel remains usable."

Each takeover environment is booted directly (QEMU -kernel/-initrd, a
blank disk, user-mode networking) with a session archive authorizing one
per-plan key. For every control the gate's assertion is run twice: on a
build that carries the control (must hold) and on a build with exactly
that control removed (must FAIL -- otherwise the assertion would not
notice the control missing):

  gate         an arbitrary command over the session key is refused (126,
               REFUSED on the console) while `identity` works
  ro-store     the verified closure cannot be modified (`touch /nix/store/x`)
  egress       the installer cannot open a connection out (to a listener the
               test runs on the host), while inbound SSH keeps working
  caps         a session cannot reprogram the network or the egress filter
               (`nft flush ruleset`, `ip link add`), and its bounding set
               lacks the kernel-code, tracing, raw-memory and audit
               capabilities, while mounting (the storage work) keeps working
  per-plan key a key other than this plan's session key is refused

    test_confinement.py --artifacts DIR
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "tools" / "anywhere"))
sys.path.insert(0, str(HERE))

import variants  # noqa: E402
from reproos_anywhere import cpio  # noqa: E402

READY = re.compile(r"REPROOS_ANYWHERE_INSTALLER:READY session=\S+ nonce=\S+ boot_id=\S+ "
                   r"hostkey=(ssh-ed25519 [A-Za-z0-9+/=]+)")
FIRMWARE = Path(os.environ.get("ANYWHERE_OVMF_DIR", "/run/current-system/sw/share/qemu"))


def keypair(directory: Path, name: str) -> Path:
    path = directory / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(path)], check=True)
    return path


class Installer:
    """One takeover environment, booted directly from its kernel/initrd."""

    def __init__(self, image: Path, session_pub: str, work: Path):
        self.work = work
        work.mkdir(parents=True)
        archive = cpio.build([(".", 0o755, None), ("etc", 0o755, None), ("etc/anywhere", 0o755, None),
                              ("etc/anywhere/session.pub", 0o644, (session_pub + "\n").encode())])
        initrd = work / "initrd.img"
        initrd.write_bytes(cpio.append_to_initrd((image / "initrd.img").read_bytes(), archive))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(work / "disk.qcow2"), "4G"], check=True)
        self.console = work / "console.log"
        mac = "52:54:00:%02x:%02x:%02x" % tuple(os.urandom(3))
        subprocess.run([
            "qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-kernel", str(image / "vmlinuz"), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 anywhere.session={secrets.token_hex(8)} "
                       f"anywhere.nonce={secrets.token_hex(16)} anywhere.mac={mac} anywhere.net=dhcp",
            "-drive", f"file={work / 'disk.qcow2'},if=none,id=d0,format=qcow2",
            "-device", "virtio-blk-pci,drive=d0,serial=AW-CONFINEMENT",
            "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device", f"virtio-net-pci,netdev=n0,mac={mac}",
            "-display", "none", "-serial", f"file:{self.console}",
            "-pidfile", str(work / "qemu.pid"), "-daemonize"], check=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            text = self.console.read_text(errors="replace") if self.console.exists() else ""
            m = READY.search(text)
            if m:
                self.hostkey = m.group(1)
                break
            time.sleep(1)
        else:
            raise AssertionError(f"installer did not announce itself:\n{text[-2000:]}")
        (work / "known_hosts").write_text(f"[127.0.0.1]:{self.port} {self.hostkey}\n")
        # The installer starts sshd only after its announcement has drained
        # to the console: wait for the SSH banner, as the controller does.
        deadline = time.monotonic() + 60
        while True:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=5) as conn:
                    if conn.recv(64).startswith(b"SSH-"):
                        break
            except OSError:
                pass
            if time.monotonic() > deadline:
                raise AssertionError("installer sshd never answered after its announcement")
            time.sleep(1)

    def ssh(self, key: Path, command: str, timeout: float = 60) -> subprocess.CompletedProcess:
        # The installer's serial console is synchronous at 115200 baud and
        # carries every audit record; right after boot a request can wait
        # behind that backlog, so one slow first answer is retried.
        try:
            return self._ssh(key, command, timeout)
        except subprocess.TimeoutExpired:
            return self._ssh(key, command, timeout)

    def _ssh(self, key: Path, command: str, timeout: float) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["ssh", "-F", "/dev/null", "-o", f"UserKnownHostsFile={self.work / 'known_hosts'}",
             "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
             "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR", "-i", str(key), "-p", str(self.port),
             "root@127.0.0.1", command], capture_output=True, text=True, timeout=timeout)

    def stop(self) -> None:
        try:
            os.kill(int((self.work / "qemu.pid").read_text()), 15)
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass


def listener() -> tuple[int, threading.Event]:
    """A host-side TCP listener the installer must NOT be able to reach
    (QEMU user networking maps 10.0.2.2:<port> to the host's loopback)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(1)
    hit = threading.Event()

    def accept():
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not hit.is_set():
            try:
                conn, _ = srv.accept()
                hit.set()
                conn.close()
            except socket.timeout:
                continue
        srv.close()
    threading.Thread(target=accept, daemon=True).start()
    return srv.getsockname()[1], hit


# -- the assertions, each run against a build with and without its control --
def gate_holds(inst: Installer, key: Path) -> tuple[bool, str]:
    ok = inst.ssh(key, "anywhere-gate identity")
    arbitrary = inst.ssh(key, "id")
    refused = arbitrary.returncode == 126 and "uid=" not in arbitrary.stdout
    # The refusal line queues behind the audit records on the synchronous
    # console; give it time to drain before deciding it is missing. It must
    # arrive whole, as one kernel log record.
    deadline = time.monotonic() + 15
    while not (logged := "REPROOS_ANYWHERE_GATE:REFUSED unknown verb id\n" in inst.console.read_text(errors="replace")) \
            and time.monotonic() < deadline:
        time.sleep(0.5)
    return ok.returncode == 0 and "session=" in ok.stdout and refused and logged, \
        f"identity rc={ok.returncode}; `id` rc={arbitrary.returncode} out={arbitrary.stdout.strip()!r}"


def ro_store_holds(inst: Installer, key: Path) -> tuple[bool, str]:
    p = inst.ssh(key, "touch /nix/store/anywhere-intrusion && echo WROTE; true")
    return "WROTE" not in p.stdout, f"touch: {p.stdout.strip() or p.stderr.strip()[-120:]}"


def egress_holds(inst: Installer, key: Path) -> tuple[bool, str]:
    port, hit = listener()
    inst.ssh(key, f"nc -w 3 10.0.2.2 {port} </dev/null; true", timeout=40)
    time.sleep(1)
    channel = inst.ssh(key, "anywhere-gate identity").returncode == 0
    return (not hit.is_set()) and channel, f"outbound connection {'reached' if hit.is_set() else 'did not reach'} " \
                                           f"the host; inbound channel {'usable' if channel else 'BROKEN'}"


# Capabilities a session must never hold (linux/capability.h bit numbers).
FORBIDDEN_CAPS = {"net_admin": 12, "net_raw": 13, "sys_module": 16, "sys_rawio": 17, "sys_ptrace": 19,
                  "audit_control": 30, "mac_admin": 33, "bpf": 39}


def caps_holds(inst: Installer, key: Path) -> tuple[bool, str]:
    p = inst.ssh(key, "nft flush ruleset && echo FLUSHED; ip link add anywhere0 type dummy && echo LINKED; "
                      "grep CapBnd /proc/self/status; true")
    bound = int(next((ln.split()[1] for ln in p.stdout.splitlines() if ln.startswith("CapBnd:")), "f" * 16), 16)
    held = sorted(n for n, bit in FORBIDDEN_CAPS.items() if bound >> bit & 1)
    # The storage work keeps what it needs: mounting (sys_admin).
    storage = "MOUNTED" in inst.ssh(key, "mkdir -p /run/anywhere/work/t && "
                                         "mount -t tmpfs t /run/anywhere/work/t && echo MOUNTED").stdout
    ok = "FLUSHED" not in p.stdout and "LINKED" not in p.stdout and not held and storage
    return ok, (f"nft flush {'SUCCEEDED' if 'FLUSHED' in p.stdout else 'refused'}; "
                f"ip link add {'SUCCEEDED' if 'LINKED' in p.stdout else 'refused'}; "
                f"forbidden caps in bounding set: {','.join(held) or 'none'}; "
                f"storage verb {'works' if storage else 'BROKEN'}")


def session_key_holds(inst: Installer, own: Path, other: Path) -> tuple[bool, str]:
    mine = inst.ssh(own, "anywhere-gate identity").returncode == 0
    theirs = inst.ssh(other, "anywhere-gate identity").returncode == 0
    return mine and not theirs, f"own key {'works' if mine else 'FAILS'}, other key {'works' if theirs else 'refused'}"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--artifacts", required=True)
    args = p.parse_args()
    a = Path(args.artifacts).resolve()
    work = Path(tempfile.mkdtemp(prefix="confinement-", dir=a))
    keys_dir = work / "keys"
    keys_dir.mkdir()
    plan_key, other_key = keypair(keys_dir, "plan-a"), keypair(keys_dir, "plan-b")
    pub = lambda k: " ".join(Path(str(k) + ".pub").read_text().split()[:2])  # noqa: E731
    everything = list(variants.ALL_CONTROLS)
    no_gate = [c for c in everything if c != "gate"]
    cases = [
        # (control, check, build WITH it, build WITHOUT it)
        ("gate", gate_holds, everything, no_gate),
        ("ro-store", ro_store_holds, no_gate, [c for c in no_gate if c != "ro-store"]),
        ("egress", egress_holds, no_gate, [c for c in no_gate if c != "egress"]),
        ("caps", caps_holds, no_gate, [c for c in no_gate if c != "caps"]),
    ]
    results, failures = [], []
    try:
        for control, check, with_it, without_it in cases:
            for label, controls, must in (("with", with_it, True), ("without", without_it, False)):
                image = variants.build_installer(controls)
                inst = Installer(image, pub(plan_key), work / f"{control}-{label}")
                try:
                    held, detail = check(inst, plan_key)
                finally:
                    inst.stop()
                verdict = "ok" if held == must else "WRONG"
                print(f"  {control:9} {label:7} controls={','.join(controls) or '-':22} "
                      f"holds={held!s:5} {verdict}: {detail}", flush=True)
                results.append({"control": control, "build": label, "controls": controls,
                                "holds": held, "expected": must, "detail": detail})
                if held != must:
                    failures.append(f"{control} {label}")
        # Per-plan credential: the archive authorizes only THIS plan's key.
        inst = Installer(variants.build_installer(everything), pub(plan_key), work / "session-key")
        try:
            held, detail = session_key_holds(inst, plan_key, other_key)
        finally:
            inst.stop()
        print(f"  per-plan  key     {detail}", flush=True)
        results.append({"control": "per-plan-key", "holds": held, "detail": detail})
        if not held:
            failures.append("per-plan-key")
    finally:
        out = a / "evidence" / f"confinement-{int(time.time())}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2))
        shutil.rmtree(work, ignore_errors=True)
    if failures:
        print(f"test_reproos_anywhere_installer_confinement_and_isolation: FAIL ({', '.join(failures)})")
        return 1
    print(f"test_reproos_anywhere_installer_confinement_and_isolation: PASS -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
