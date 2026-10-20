"""Enrollment: what the controller knows about a machine WITHOUT asking it.

Everything here comes from an independent management plane -- the
provider or supervisor that created the machine, or an operator who read
the values from a console -- never from the machine's own answers over
SSH. That independence is the point: the inventory the machine reports
is checked against this record, and a machine that lies about its disk
serials, its DMI identity or its SSH host key fails here instead of
being trusted.

Enrollment is TOML so an operator can write one; the controller reduces
it to a canonical record whose identity every later artifact binds.
"""

from __future__ import annotations

import datetime as _dt
import re
import tomllib
from pathlib import Path
from typing import Any

from . import canon
from .transport import parse_host_key

SCHEMA = "reproos-anywhere-enrollment/1"
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
SERIAL_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
RESCUE_KINDS = {"qemu-serial"}
# Independently enforced planning environments (enforced BELOW the guest):
#   qemu-drive-readonly  the target drive is attached read-only
#   qemu-snapshot        guest writes go to a discarded overlay; the drive
#                        itself is never written
READONLY_KINDS = {"qemu-drive-readonly", "qemu-snapshot"}


class EnrollmentError(ValueError):
    pass


def _need(table: dict, key: str, kind: type, where: str) -> Any:
    if key not in table:
        raise EnrollmentError(f"{where}.{key} is required")
    value = table[key]
    if kind is int and isinstance(value, bool):
        raise EnrollmentError(f"{where}.{key} must be an integer")
    if not isinstance(value, kind):
        raise EnrollmentError(f"{where}.{key} must be {kind.__name__}")
    return value


def _only(table: dict, allowed: set[str], where: str) -> None:
    extra = set(table) - allowed
    if extra:
        raise EnrollmentError(f"{where}: unknown keys {sorted(extra)}")


def load(path: Path, *, now: _dt.datetime | None = None) -> dict[str, Any]:
    with open(path, "rb") as handle:
        doc = tomllib.load(handle)
    return normalise(doc, base=path.parent, now=now)


def normalise(doc: dict, *, base: Path, now: _dt.datetime | None = None) -> dict[str, Any]:
    _only(doc, {"schema", "name", "expires", "ssh", "machine", "disks", "network",
                "rescue", "readonly"}, "enrollment")
    if doc.get("schema") != SCHEMA:
        raise EnrollmentError(f"schema must be {SCHEMA!r}")
    name = _need(doc, "name", str, "enrollment")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", name):
        raise EnrollmentError("name must be a lowercase DNS label")
    expires = _need(doc, "expires", str, "enrollment")
    try:
        when = _dt.datetime.strptime(expires, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError as error:
        raise EnrollmentError("expires must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)") from error
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if when <= now:
        raise EnrollmentError(f"enrollment expired at {expires}")

    ssh = _need(doc, "ssh", dict, "enrollment")
    _only(ssh, {"address", "port", "user", "privilege", "host_key", "identity_file"}, "ssh")
    host_key = _need(ssh, "host_key", str, "ssh")
    parse_host_key(host_key)
    privilege = ssh.get("privilege", "root")
    if privilege not in ("root", "sudo"):
        raise EnrollmentError("ssh.privilege must be root or sudo")
    identity = Path(_need(ssh, "identity_file", str, "ssh"))
    if not identity.is_absolute():
        identity = (base / identity).resolve()
    port = _need(ssh, "port", int, "ssh")
    if not 0 < port < 65536:
        raise EnrollmentError("ssh.port out of range")
    user = _need(ssh, "user", str, "ssh")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise EnrollmentError("ssh.user is not a valid account name")
    if privilege == "root" and user != "root":
        raise EnrollmentError("ssh.privilege = root requires ssh.user = root")

    machine = _need(doc, "machine", dict, "enrollment")
    _only(machine, {"product_uuid", "machine_id"}, "machine")
    if not machine:
        raise EnrollmentError("machine needs at least one independent identity (product_uuid)")
    for key, value in machine.items():
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F-]{16,64}", value):
            raise EnrollmentError(f"machine.{key} is not an identifier")

    disks = _need(doc, "disks", list, "enrollment")
    seen = set()
    targets = 0
    out_disks = []
    for i, d in enumerate(disks):
        if not isinstance(d, dict):
            raise EnrollmentError(f"disks[{i}] must be a table")
        _only(d, {"serial", "size_sectors", "role", "wwid"}, f"disks[{i}]")
        serial = _need(d, "serial", str, f"disks[{i}]")
        if not SERIAL_RE.match(serial):
            raise EnrollmentError(f"disks[{i}].serial is blank or not printable")
        if serial in seen:
            raise EnrollmentError(f"duplicate disk serial {serial}")
        seen.add(serial)
        role = d.get("role", "keep")
        if role not in ("target", "keep"):
            raise EnrollmentError(f"disks[{i}].role must be target or keep")
        targets += role == "target"
        out_disks.append({"serial": serial, "size_sectors": _need(d, "size_sectors", int, f"disks[{i}]"),
                          "role": role, "wwid": d.get("wwid", "")})
    if targets != 1:
        raise EnrollmentError("exactly one disk must have role = \"target\"")

    network = _need(doc, "network", dict, "enrollment")
    _only(network, {"mac"}, "network")
    mac = _need(network, "mac", str, "network").lower()
    if not MAC_RE.match(mac):
        raise EnrollmentError("network.mac is not a MAC address")

    rescue = _need(doc, "rescue", dict, "enrollment")
    _only(rescue, {"kind", "console_log", "monitor", "boot_command", "restore_command"}, "rescue")
    if rescue.get("kind") not in RESCUE_KINDS:
        raise EnrollmentError(f"rescue.kind must be one of {sorted(RESCUE_KINDS)}")
    out_rescue = {"kind": rescue["kind"],
                  "console_log": str((base / _need(rescue, "console_log", str, "rescue")).resolve()),
                  "monitor": str((base / _need(rescue, "monitor", str, "rescue")).resolve())}
    # Rescue-media boot through the management plane (a provider's rescue
    # system, or the test supervisor): argv lists. Both or neither.
    boot = rescue.get("boot_command")
    restore = rescue.get("restore_command")
    if (boot is None) != (restore is None):
        raise EnrollmentError("rescue.boot_command and rescue.restore_command go together")
    for key, value in (("boot_command", boot), ("restore_command", restore)):
        if value is not None:
            if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
                raise EnrollmentError(f"rescue.{key} must be a non-empty list of strings")
            out_rescue[key] = value

    readonly = doc.get("readonly")
    out_readonly = None
    if readonly is not None:
        _only(readonly, {"kind", "issued_by"}, "readonly")
        if readonly.get("kind") not in READONLY_KINDS:
            raise EnrollmentError(f"readonly.kind must be one of {sorted(READONLY_KINDS)}")
        out_readonly = {"kind": readonly["kind"], "issued_by": _need(readonly, "issued_by", str, "readonly")}

    record = {
        "schema": SCHEMA, "name": name, "expires": expires,
        "ssh": {"address": _need(ssh, "address", str, "ssh"), "port": port, "user": user,
                "privilege": privilege, "host_key": " ".join(host_key.split()[:2]),
                "identity_file": str(identity)},
        "machine": {k: v.lower() for k, v in sorted(machine.items())},
        "disks": out_disks,
        "network": {"mac": mac},
        "rescue": out_rescue,
        "readonly": out_readonly,
    }
    canon.encode(record)
    return record


def target_disk(enrollment: dict[str, Any]) -> dict[str, Any]:
    return next(d for d in enrollment["disks"] if d["role"] == "target")
