"""Controller keys and signatures, through OpenSSH's own tooling.

The controller signs plans with ``ssh-keygen -Y sign`` under a fixed
namespace, so a plan signature can never be confused with an SSH
authentication or with a signature some other tool asked the same key
to make. Verification uses an allowed-signers file holding exactly the
controller's public key.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PLAN_NAMESPACE = "reproos-anywhere-plan@metacraft-labs.com"
SIGNER_ID = "reproos-anywhere-controller"


class KeyError_(RuntimeError):
    pass


def ensure_keypair(path: Path, comment: str) -> str:
    """Create an ed25519 key at ``path`` if absent; return the public line."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment,
                        "-f", str(path)], check=True)
    path.chmod(0o600)
    return public_line(path)


def public_line(private: Path) -> str:
    text = Path(str(private) + ".pub").read_text().split()
    return f"{text[0]} {text[1]}"


def sign(private: Path, data: bytes) -> bytes:
    proc = subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-n", PLAN_NAMESPACE,
                           "-f", str(private)], input=data, capture_output=True)
    if proc.returncode != 0:
        raise KeyError_(f"signing failed: {proc.stderr.decode().strip()}")
    return proc.stdout


def verify(public: str, data: bytes, signature: bytes, workdir: Path) -> bool:
    workdir.mkdir(parents=True, exist_ok=True)
    allowed = workdir / "allowed_signers"
    allowed.write_text(f"{SIGNER_ID} namespaces=\"{PLAN_NAMESPACE}\" {public}\n")
    sig = workdir / "candidate.sig"
    sig.write_bytes(signature)
    proc = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", SIGNER_ID,
                           "-n", PLAN_NAMESPACE, "-s", str(sig)], input=data, capture_output=True)
    return proc.returncode == 0
