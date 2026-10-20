"""A minimal, deterministic ``newc`` cpio writer for the session archive.

The takeover environment is the published installer initramfs plus ONE
small archive the controller appends, carrying only public material: the
controller's session key in ``authorized_keys`` and the signed handoff.
It is written here rather than by ``cpio(1)`` so its bytes are a pure
function of its contents (fixed mtime, uid/gid 0, inode numbers in
order) and so the controller needs no extra host tool.
"""

from __future__ import annotations


def _header(ino: int, mode: int, size: int, name: bytes) -> bytes:
    fields = [ino, mode, 0, 0, 1, 0, size, 0, 0, 0, 0, len(name) + 1, 0]
    return b"070701" + b"".join(b"%08X" % f for f in fields)


def _pad(n: int) -> bytes:
    return b"\0" * ((4 - n % 4) % 4)


def build(entries: list[tuple[str, int, bytes | None]]) -> bytes:
    """``entries``: (path, mode, data); data None means a directory."""
    out = bytearray()
    for ino, (path, mode, data) in enumerate(entries, 1):
        name = path.lstrip("/").encode()
        if data is None:
            head = _header(ino, 0o040000 | mode, 0, name)
            payload = b""
        else:
            head = _header(ino, 0o100000 | mode, len(data), name)
            payload = data
        out += head + name + b"\0"
        out += _pad(len(head) + len(name) + 1)
        out += payload + _pad(len(payload))
    trailer = b"TRAILER!!!"
    head = _header(0, 0, 0, trailer)
    out += head + trailer + b"\0" + _pad(len(head) + len(trailer) + 1)
    out += _pad(len(out)) if len(out) % 512 == 0 else b"\0" * (512 - len(out) % 512)
    return bytes(out)


def append_to_initrd(base: bytes, archive: bytes) -> bytes:
    """Concatenate, zero-padding the base so the archive starts aligned."""
    pad = (512 - len(base) % 512) % 512
    return base + b"\0" * pad + archive
