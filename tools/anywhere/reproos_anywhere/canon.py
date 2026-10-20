"""Canonical records: one byte encoding, one identity.

Every Anywhere artifact the controller persists (inventory, compatibility
report, plan, journal record, receipt) is a JSON object encoded exactly
one way -- sorted keys, no insignificant whitespace, ASCII only, no floats
-- and identified by the SHA-256 of those bytes. Two equal records have
one identity on every host; a record whose bytes are not canonical is
rejected on read rather than re-encoded, so a hand-edited file cannot
silently acquire a new identity.

(The approved M1 design names bounded SSZ for these records. The shared
SSZ codec it depends on does not exist yet; this module is the single
place that encoding decision lives, so swapping it is local. See the
milestones file, open gap Q3.)
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_RECORD_BYTES = 4 * 1024 * 1024


class CanonError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise CanonError(f"{path}: integer out of range")
        return
    if isinstance(value, float):
        raise CanonError(f"{path}: floats are not canonical")
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonError(f"{path}: non-string key")
            _check(item, f"{path}.{key}")
        return
    raise CanonError(f"{path}: unsupported type {type(value).__name__}")


def encode(value: Any) -> bytes:
    _check(value)
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(data) > MAX_RECORD_BYTES:
        raise CanonError(f"record exceeds {MAX_RECORD_BYTES} bytes")
    return data


def digest(value: Any) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonError(f"duplicate key {key!r}")
        out[key] = value
    return out


def decode(data: bytes) -> Any:
    """Parse canonical bytes; refuse anything that would re-encode differently."""
    if len(data) > MAX_RECORD_BYTES:
        raise CanonError(f"record exceeds {MAX_RECORD_BYTES} bytes")
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_unique,
                           parse_float=_no_float)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonError(f"not canonical JSON: {error}") from error
    if encode(value) != data:
        raise CanonError("bytes are not in canonical form")
    return value


def _no_float(text: str) -> Any:
    raise CanonError(f"float {text} is not canonical")


def write(path, value: Any) -> str:
    """Write canonically and durably; return the record's identity."""
    import os
    data = encode(value)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    dirfd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    return hashlib.sha256(data).hexdigest()


def read(path) -> Any:
    with open(path, "rb") as handle:
        return decode(handle.read())
