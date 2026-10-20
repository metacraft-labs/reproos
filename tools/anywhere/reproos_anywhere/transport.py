"""The controller's only way to reach a machine: exact-key OpenSSH.

Every connection is made with a known_hosts file holding exactly one
key -- the one the caller pinned from an independent source (the
enrollment for the source system, the console announcement for the
installer, the controller-generated key for the installed system) --
and with every client feature that could widen the channel turned off:
no user or system ssh_config (``-F /dev/null``), no agent, no
forwarding of any kind, batch mode, a single host-key algorithm, and
``StrictHostKeyChecking=yes``. A changed or unknown key fails before
authentication, which is before anything is sent.

Output is size-bounded: a hostile endpoint cannot make the controller
buffer unbounded bytes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024
ALLOWED_KEY_TYPES = ("ssh-ed25519",)


class TransportError(RuntimeError):
    pass


class HostKeyRejected(TransportError):
    """The endpoint did not present the pinned key (or none at all)."""


def parse_host_key(line: str) -> tuple[str, str]:
    parts = line.strip().split()
    if len(parts) < 2 or parts[0] not in ALLOWED_KEY_TYPES:
        raise TransportError(f"host key must be one of {ALLOWED_KEY_TYPES}: {line!r}")
    if not all(c.isalnum() or c in "+/=" for c in parts[1]):
        raise TransportError("host key is not base64")
    return parts[0], parts[1]


def fingerprint(key_type: str, key_b64: str) -> str:
    import base64
    raw = base64.b64decode(key_b64)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


@dataclasses.dataclass(frozen=True)
class Endpoint:
    address: str
    port: int
    user: str
    host_key: str            # "ssh-ed25519 AAAA..."
    identity_file: Path      # client private key
    privilege: str = "root"  # "root" or "sudo"
    connect_timeout: int = 10

    def __post_init__(self) -> None:
        parse_host_key(self.host_key)
        if self.privilege not in ("root", "sudo"):
            raise TransportError(f"unsupported privilege model {self.privilege!r}")
        if not (0 < self.port < 65536):
            raise TransportError("bad port")


class Session:
    """A pinned SSH endpoint plus its private known_hosts file."""

    def __init__(self, endpoint: Endpoint, workdir: Path):
        self.endpoint = endpoint
        workdir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="known_hosts.", dir=workdir)
        key_type, key_b64 = parse_host_key(endpoint.host_key)
        host = endpoint.address if endpoint.port == 22 else f"[{endpoint.address}]:{endpoint.port}"
        with os.fdopen(fd, "w") as handle:
            handle.write(f"{host} {key_type} {key_b64}\n")
        self.known_hosts = Path(name)
        self.key_type = key_type

    def argv(self, remote: Optional[str] = None) -> list[str]:
        e = self.endpoint
        args = [
            "ssh", "-F", "/dev/null",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no",
            "-o", f"HostKeyAlgorithms={self.key_type}",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", f"ConnectTimeout={e.connect_timeout}",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=6",
            "-o", "LogLevel=ERROR",
            "-i", str(e.identity_file),
            "-p", str(e.port),
            "-l", e.user,
            "-T",
            e.address,
        ]
        if remote is not None:
            args.append(remote)
        return args

    def run(self, remote: str, *, stdin: bytes | None = None,
            stdin_file: Path | None = None, timeout: float = 120,
            privileged: bool = False, max_output: int = DEFAULT_MAX_OUTPUT,
            check: bool = True) -> subprocess.CompletedProcess:
        if privileged and self.endpoint.privilege == "sudo":
            remote = "sudo -n -- sh -c " + sh_quote(remote)
        source = open(stdin_file, "rb") if stdin_file is not None else None
        try:
            proc = subprocess.run(
                self.argv(remote),
                input=stdin if source is None else None,
                stdin=source if source is not None else (None if stdin is not None else subprocess.DEVNULL),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise TransportError(f"timed out after {timeout}s: {remote[:80]}") from error
        finally:
            if source is not None:
                source.close()
        if len(proc.stdout) > max_output or len(proc.stderr) > max_output:
            raise TransportError(f"output exceeds {max_output} bytes")
        err = proc.stderr.decode("utf-8", "replace")
        if proc.returncode == 255 and ("Host key verification failed" in err or
                                       "REMOTE HOST IDENTIFICATION HAS CHANGED" in err or
                                       "No ED25519 host key is known" in err or
                                       "host key" in err.lower()):
            detail = next((line for line in err.splitlines()
                           if "fingerprint" in line.lower() or "verification failed" in line.lower()),
                          err.strip().splitlines()[-1] if err.strip() else "")
            raise HostKeyRejected(f"{e_addr(self.endpoint)} did not present the pinned "
                                  f"{self.key_type} host key ({detail.strip()})")
        if check and proc.returncode != 0:
            raise TransportError(
                f"remote command failed ({proc.returncode}): {remote[:120]}\n{err.strip()[:2000]}")
        return proc

    def reachable(self, timeout: float = 15, probe: str = "true") -> bool:
        try:
            self.run(probe, timeout=timeout)
            return True
        except HostKeyRejected:
            raise
        except TransportError:
            return False

    def stream(self, local: Path, offset: int, remote: str, *, max_rate: int = 0,
               timeout: float = 3600) -> None:
        """Send ``local`` from byte ``offset`` to the stdin of ``remote``,
        at most ``max_rate`` bytes per second when it is non-zero. A lost
        connection raises; whatever reached the remote end stays there for
        the caller to verify and resume from."""
        import time
        proc = subprocess.Popen(self.argv(remote), stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        started = time.monotonic()
        sent = 0
        try:
            with open(local, "rb") as handle:
                handle.seek(offset)
                for chunk in iter(lambda: handle.read(256 * 1024), b""):
                    proc.stdin.write(chunk)
                    sent += len(chunk)
                    if max_rate:
                        ahead = sent / max_rate - (time.monotonic() - started)
                        if ahead > 0:
                            time.sleep(ahead)
                    if time.monotonic() - started > timeout:
                        raise TransportError(f"transfer exceeded {timeout}s")
            proc.stdin.close()
            rc = proc.wait(timeout=max(60.0, timeout - (time.monotonic() - started)))
        except (BrokenPipeError, OSError) as error:
            proc.kill()
            proc.wait()
            raise TransportError(f"connection lost after {sent} bytes: {error}") from error
        except subprocess.TimeoutExpired as error:
            proc.kill()
            raise TransportError("transfer did not finish") from error
        if rc != 0:
            raise TransportError(f"transfer failed ({rc}) after {sent} bytes: "
                                 f"{proc.stderr.read().decode('utf-8', 'replace').strip()[-500:]}")

    def upload(self, local: Path, remote_path: str, *, privileged: bool = False,
               timeout: float = 900) -> str:
        """Stream ``local`` to ``remote_path`` and return the SHA-256 the
        REMOTE side computed; the caller compares it with the expected
        digest before using the file."""
        quoted = sh_quote(remote_path)
        self.run(f"cat > {quoted}", stdin_file=local, privileged=privileged,
                 timeout=timeout)
        out = self.run(f"sha256sum {quoted}", privileged=privileged).stdout.decode()
        return out.split()[0] if out.strip() else ""


def e_addr(e: "Endpoint") -> str:
    return f"{e.user}@{e.address}:{e.port}"


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
