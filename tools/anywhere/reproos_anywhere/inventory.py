"""Parse the probe's output into a typed, bounded inventory.

The probe's bytes come from the machine being converted, which the safety
contract treats as a possibly hostile Edge: every line is checked against
a fixed vocabulary of sections, keys are bounded and unique, values are
bounded printable ASCII, and anything else rejects the WHOLE inventory --
a half-parsed inventory is never planned against.
"""

from __future__ import annotations

import re
from typing import Any

MAX_LINES = 20000
MAX_VALUE = 4096
SECTIONS = {
    "probe", "kernel", "os", "virt", "dmi", "machine", "firmware", "memory",
    "cpu", "disk", "part", "byid", "raid", "mount", "swap", "netif", "addr4",
    "route4", "dns", "netmgr", "ssh",
}
KEY_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,200}$")
DISK_FIELDS = {
    "size_sectors", "logical_block", "removable", "ro", "devnum", "serial",
    "wwid", "model", "dm_uuid", "md_level", "driver", "syspath", "slaves",
    "holders",
}
PART_FIELDS = {"disk", "number", "start", "size_sectors", "devnum", "holders"}
NETIF_FIELDS = {"mac", "operstate", "mtu", "wireless", "bridge", "driver", "physical"}


class InventoryError(ValueError):
    pass


def parse(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise InventoryError(f"probe produced more than {MAX_LINES} lines")
    raw: dict[str, dict[str, str]] = {s: {} for s in SECTIONS}
    for number, line in enumerate(lines, 1):
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "R":
            raise InventoryError(f"line {number}: not a probe record")
        _, section, key, value = fields
        if section not in SECTIONS:
            raise InventoryError(f"line {number}: unknown section {section!r}")
        if not KEY_RE.match(key):
            raise InventoryError(f"line {number}: bad key {key!r}")
        if len(value) > MAX_VALUE or any(not 32 <= ord(c) < 127 for c in value):
            raise InventoryError(f"line {number}: bad value for {section}.{key}")
        if key in raw[section]:
            raise InventoryError(f"line {number}: duplicate {section}.{key}")
        raw[section][key] = value
    if raw["probe"].get("version") != "1" or raw["probe"].get("complete") != "1":
        raise InventoryError("probe output is truncated or from another probe version")
    return _typed(raw)


def _int(value: str, what: str) -> int:
    if not re.fullmatch(r"[0-9]{1,20}", value or ""):
        raise InventoryError(f"{what}: not an unsigned integer: {value!r}")
    return int(value)


def _split_owner(section: dict[str, str], fields: set[str], what: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for key, value in section.items():
        name, _, field = key.rpartition(".")
        if not name or field not in fields:
            raise InventoryError(f"{what}: unexpected key {key!r}")
        out.setdefault(name, {})[field] = value
    for name, record in out.items():
        missing = fields - set(record)
        if missing:
            raise InventoryError(f"{what} {name}: missing {sorted(missing)}")
    return out


def _typed(raw: dict[str, dict[str, str]]) -> dict[str, Any]:
    disks = {}
    for name, d in _split_owner(raw["disk"], DISK_FIELDS, "disk").items():
        disks[name] = {
            "name": name,
            "size_sectors": _int(d["size_sectors"], f"disk {name} size"),
            "logical_block": _int(d["logical_block"], f"disk {name} block"),
            "removable": d["removable"] == "1",
            "read_only": d["ro"] == "1",
            "devnum": d["devnum"],
            "serial": d["serial"].strip(),
            "wwid": d["wwid"].strip(),
            "model": d["model"].strip(),
            "dm_uuid": d["dm_uuid"],
            "md_level": d["md_level"],
            "driver": d["driver"],
            "syspath": d["syspath"],
            "slaves": d["slaves"].split(),
            "holders": d["holders"].split(),
        }
    parts = {}
    for name, p in _split_owner(raw["part"], PART_FIELDS, "partition").items():
        if p["disk"] not in disks:
            raise InventoryError(f"partition {name} names unknown disk {p['disk']}")
        parts[name] = {
            "name": name, "disk": p["disk"],
            "number": _int(p["number"], f"partition {name} number"),
            "start": _int(p["start"], f"partition {name} start"),
            "size_sectors": _int(p["size_sectors"], f"partition {name} size"),
            "devnum": p["devnum"], "holders": p["holders"].split(),
        }
    netifs = {}
    for name, n in _split_owner(raw["netif"], NETIF_FIELDS, "interface").items():
        netifs[name] = {
            "name": name, "mac": n["mac"].lower(), "operstate": n["operstate"],
            "mtu": _int(n["mtu"], f"interface {name} mtu"),
            "wireless": n["wireless"] == "1", "bridge": n["bridge"] == "1",
            "driver": n["driver"], "physical": n["physical"] == "1",
        }
    mounts = []
    for key in sorted(raw["mount"], key=lambda k: _int(k, "mount index")):
        f = raw["mount"][key].split(" ")
        if len(f) < 4:
            raise InventoryError(f"mount {key}: malformed")
        mounts.append({"source": f[0], "target": f[1], "fstype": f[2], "options": f[3]})
    addrs = []
    for key in sorted(raw["addr4"], key=lambda k: _int(k, "addr index")):
        f = raw["addr4"][key].split(" ")
        if len(f) != 3 or f[2] not in ("dynamic", "static"):
            raise InventoryError(f"addr4 {key}: malformed")
        addrs.append({"interface": f[0], "cidr": f[1], "assignment": f[2]})
    routes = [raw["route4"][k] for k in sorted(raw["route4"], key=lambda k: _int(k, "route index"))]
    secure_boot = raw["firmware"].get("secure_boot", "")
    return {
        "probe_version": 1,
        "uid": _int(raw["probe"].get("uid", ""), "uid"),
        "kernel": {
            "release": raw["kernel"].get("release", ""),
            "machine": raw["kernel"].get("machine", ""),
            "cmdline": raw["kernel"].get("cmdline", ""),
            "kexec_load_disabled": raw["kernel"].get("kexec_load_disabled", ""),
            "lockdown": raw["kernel"].get("lockdown", ""),
        },
        "os": {k.lower(): v for k, v in raw["os"].items()},
        "virt": {
            "pid1": raw["virt"].get("pid1", ""),
            "container_marker": raw["virt"].get("container_marker", ""),
            "hypervisor": raw["virt"].get("cpu_hypervisor_flag", "0") not in ("", "0"),
        },
        "dmi": dict(raw["dmi"]),
        "machine": dict(raw["machine"]),
        "firmware": {
            "mode": raw["firmware"].get("mode", ""),
            "efi_bits": raw["firmware"].get("efi_bits", ""),
            "secure_boot": secure_boot,
        },
        "memory": {
            "total_kib": _int(raw["memory"].get("mem_total_kib", ""), "memory"),
            "available_kib": _int(raw["memory"].get("mem_available_kib", ""), "memory"),
        },
        "cpu_count": _int(raw["cpu"].get("count", ""), "cpu count"),
        "disks": disks,
        "partitions": parts,
        "by_id": dict(raw["byid"]),
        "mdstat": raw["raid"].get("mdstat", ""),
        "mounts": mounts,
        "swaps": [raw["swap"][k] for k in sorted(raw["swap"], key=lambda k: _int(k, "swap index"))],
        "interfaces": netifs,
        "ipv4": addrs,
        "routes4": routes,
        "dns": [raw["dns"][k] for k in sorted(raw["dns"], key=lambda k: _int(k, "dns index"))],
        "network_managers": sorted(raw["netmgr"]),
        "ssh_connection": raw["ssh"].get("connection", ""),
    }


# ---------------------------------------------------------------------------
# Derived facts.
# ---------------------------------------------------------------------------

def devname(source: str) -> str:
    return source[5:] if source.startswith("/dev/") else ""


def owner_disk(inv: dict[str, Any], node: str) -> str:
    """The whole disk a block node (disk or partition) belongs to, or ''."""
    if node in inv["disks"]:
        return node
    part = inv["partitions"].get(node)
    return part["disk"] if part else ""


def lower_disks(inv: dict[str, Any], node: str, seen: set[str] | None = None) -> set[str]:
    """Physical disks underneath a block node, following dm/md slaves."""
    seen = seen or set()
    if node in seen:
        return set()
    seen.add(node)
    disk = owner_disk(inv, node)
    if not disk:
        return set()
    record = inv["disks"][disk]
    if record["slaves"]:
        out: set[str] = set()
        for slave in record["slaves"]:
            out |= lower_disks(inv, slave, seen)
        return out
    return {disk}


def stacked_on(inv: dict[str, Any], disk: str) -> list[dict[str, str]]:
    """Every stacked device (LVM, LUKS, md) that sits on ``disk``."""
    out = []
    for name, record in inv["disks"].items():
        if name == disk or not record["slaves"]:
            continue
        if disk in lower_disks(inv, name):
            uuid = record["dm_uuid"]
            if uuid.startswith("LVM-"):
                kind = "lvm"
            elif uuid.startswith("CRYPT-"):
                kind = "luks"
            elif record["md_level"]:
                kind = "md-" + record["md_level"]
            elif uuid:
                kind = "dm:" + uuid.split("-", 1)[0].lower()
            else:
                kind = "stacked"
            out.append({"device": name, "kind": kind})
    return out


def mounts_on(inv: dict[str, Any], disk: str) -> list[dict[str, str]]:
    out = []
    for m in inv["mounts"]:
        node = devname(m["source"])
        if node and disk in lower_disks(inv, node):
            out.append(m)
    for s in inv["swaps"]:
        node = devname(s)
        if node and disk in lower_disks(inv, node):
            out.append({"source": s, "target": "[swap]", "fstype": "swap", "options": ""})
    return out


def root_mount(inv: dict[str, Any]) -> dict[str, str] | None:
    for m in inv["mounts"]:
        if m["target"] == "/":
            return m
    return None


def management_interface(inv: dict[str, Any]) -> dict[str, Any] | None:
    """The interface whose address the controller's SSH connection reached."""
    parts = inv["ssh_connection"].split()
    if len(parts) != 4:
        return None
    local_ip = parts[2]
    for a in inv["ipv4"]:
        if a["cidr"].split("/")[0] == local_ip:
            iface = inv["interfaces"].get(a["interface"])
            if iface is None:
                return None
            gateways = [r.split()[2] for r in inv["routes4"]
                        if r.startswith("default via ") and f" dev {a['interface']}" in r]
            return {**iface, "ipv4": a, "gateways": gateways, "local_ip": local_ip}
    return None
