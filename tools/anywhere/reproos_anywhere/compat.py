"""Compatibility predicates: inventory x enrollment x configuration x payload.

Each check is named, ordered and yields ``pass``, ``fail`` or
``requires`` (a condition only a later, separately verified stage can
satisfy -- e.g. root on the target disk requires the verified takeover).
A report with any ``fail`` is BLOCKED: it carries no target, no network
plan and cannot be turned into a plan. Unknown is never pass.

Every supported value below is a closed set. A distribution, firmware,
controller or network shape that is not listed fails, rather than
falling through to a less safe default.
"""

from __future__ import annotations

from typing import Any, Callable

from . import inventory as inv_mod
from .enrollment import target_disk

SUPPORTED_DISTRIBUTIONS = {"debian", "ubuntu", "fedora", "arch", "alpine", "nixos"}
SUPPORTED_ARCH = {"x86_64"}
SUPPORTED_DISK_DRIVERS = {"virtio_blk", "virtio_scsi", "sd", "nvme", "ahci"}
MIB = 1024 * 1024
# The installer's working set beyond its own image: tmpfs work files,
# sshd, the storage tools and page cache for the payload stream.
INSTALLER_WORKING_MIB = 384
# Disk headroom over the unpacked payload: journals, enrollment, logs.
DISK_MARGIN_PERCENT = 25


class Report:
    def __init__(self) -> None:
        self.checks: list[dict[str, str]] = []

    def add(self, check_id: str, verdict: str, detail: str) -> None:
        assert verdict in ("pass", "fail", "requires")
        self.checks.append({"id": check_id, "verdict": verdict, "detail": detail})

    @property
    def blocked(self) -> bool:
        return any(c["verdict"] == "fail" for c in self.checks)


def evaluate(inv: dict[str, Any], enrollment: dict[str, Any], config: dict[str, Any],
             payload: dict[str, Any], installer: dict[str, Any],
             render_layout: Callable[[str, int], dict[str, Any]],
             *, strict_readonly: bool) -> dict[str, Any]:
    r = Report()
    os_id = inv["os"].get("id", "")
    r.add("distribution", "pass" if os_id in SUPPORTED_DISTRIBUTIONS else "fail",
          f"ID={os_id or '<missing>'} (supported: {', '.join(sorted(SUPPORTED_DISTRIBUTIONS))})")
    marker = inv["virt"]["container_marker"]
    r.add("not-a-container", "fail" if marker else "pass",
          f"container marker {marker}" if marker else "no container marker")
    arch = inv["kernel"]["machine"]
    r.add("architecture", "pass" if arch in SUPPORTED_ARCH else "fail",
          arch if arch in SUPPORTED_ARCH else
          f"{arch}: ReproOS is built for {', '.join(sorted(SUPPORTED_ARCH))} only, so there is no "
          f"{arch} system to install")

    fw = inv["firmware"]
    if fw["mode"] != "uefi":
        r.add("firmware", "fail", f"{fw['mode'] or 'unknown'} firmware; the installed boot path is UEFI-only "
              "until a legacy-BIOS profile is qualified")
    elif fw["efi_bits"] != "64":
        r.add("firmware", "fail", f"{fw['efi_bits']}-bit UEFI is not supported")
    else:
        r.add("firmware", "pass", "64-bit UEFI")
    sb = fw["secure_boot"]
    r.add("secure-boot", "pass" if sb in ("0", "absent") else "fail",
          "disabled" if sb in ("0", "absent") else
          f"SecureBoot={sb or 'unknown'}; refused until a signed chain and recovery route are qualified")

    # --- identity: the machine must be the one the management plane enrolled.
    dmi_uuid = inv["dmi"].get("product_uuid", "").lower()
    want_uuid = enrollment["machine"].get("product_uuid", "")
    if want_uuid:
        r.add("machine-identity", "pass" if dmi_uuid == want_uuid else "fail",
              f"DMI product_uuid {dmi_uuid or '<unreadable>'} vs enrolled {want_uuid}")
    want_mid = enrollment["machine"].get("machine_id", "")
    if want_mid:
        mid = inv["machine"].get("machine_id", "").lower()
        r.add("machine-id", "pass" if mid == want_mid else "fail",
              f"/etc/machine-id {mid or '<missing>'} vs enrolled {want_mid}")

    # --- privilege
    if enrollment["ssh"]["privilege"] == "root":
        r.add("privilege", "pass" if inv["uid"] == 0 else "fail", f"uid {inv['uid']}")
    else:
        r.add("privilege", "requires", "non-interactive sudo is verified at apply time; "
              "planning never seeds a sudo timestamp")

    # --- disks: every enrolled disk must be reported, uniquely, with its size.
    by_serial: dict[str, list[str]] = {}
    for name, d in inv["disks"].items():
        if d["serial"]:
            by_serial.setdefault(d["serial"], []).append(name)
    dup = {s: n for s, n in by_serial.items() if len(n) > 1}
    r.add("disk-serials-unique", "fail" if dup else "pass",
          f"duplicate serials {dup}" if dup else "every reported serial is unique")
    target = None
    for d in enrollment["disks"]:
        names = by_serial.get(d["serial"], [])
        if len(names) != 1:
            r.add(f"disk:{d['serial']}", "fail", f"reported by {len(names)} disks")
            continue
        rec = inv["disks"][names[0]]
        if rec["size_sectors"] != d["size_sectors"]:
            r.add(f"disk:{d['serial']}", "fail",
                  f"{names[0]} has {rec['size_sectors']} sectors, enrolled {d['size_sectors']}")
            continue
        if d["wwid"] and rec["wwid"] != d["wwid"]:
            r.add(f"disk:{d['serial']}", "fail", f"wwid {rec['wwid']!r} vs enrolled {d['wwid']!r}")
            continue
        r.add(f"disk:{d['serial']}", "pass", f"{names[0]} {rec['size_sectors']} sectors via {rec['driver']}")
        if d["role"] == "target":
            target = rec
    if target is not None:
        drv = target["driver"]
        r.add("target-controller", "pass" if drv in SUPPORTED_DISK_DRIVERS else "fail",
              f"driver {drv or '<none>'}")
        r.add("target-not-removable", "fail" if target["removable"] else "pass",
              "removable media" if target["removable"] else "fixed disk")
        r.add("target-writable", "fail" if target["read_only"] and not strict_readonly else "pass",
              "read-only" + (" (enforced by the read-only planning environment)" if target["read_only"] else "")
              if target["read_only"] else "writable")
        stacked = inv_mod.stacked_on(inv, target["name"])
        kinds = sorted({s["kind"] for s in stacked})
        r.add("target-stacking", "fail" if stacked else "pass",
              f"{', '.join(kinds)} on the target; LVM, RAID and encryption are refused until qualified "
              "as complete layout profiles" if stacked else "no LVM, RAID or encryption on the target")
        root = inv_mod.root_mount(inv)
        root_node = inv_mod.devname(root["source"]) if root else ""
        on_target = bool(root_node) and target["name"] in inv_mod.lower_disks(inv, root_node)
        if root is None or not root_node:
            r.add("root-filesystem", "fail", "cannot attribute / to a block device "
                  f"({root['source'] if root else 'no / mount'}); network or overlay roots are refused")
        elif on_target:
            r.add("root-on-target", "requires",
                  "/ is on the target disk; destruction is authorised only from the verified "
                  "RAM-resident takeover environment")
        else:
            r.add("root-on-target", "pass", f"/ is on {root_node}, not the target")
    else:
        r.add("target-disk", "fail", "the enrolled target disk was not found exactly once")

    # --- network: the management path must be one the installer and the
    # installed system can reproduce without the source's configuration.
    mgmt = inv_mod.management_interface(inv)
    if mgmt is None:
        r.add("management-interface", "fail", "cannot attribute the SSH connection to an interface")
    else:
        problems = []
        if mgmt["mac"] != enrollment["network"]["mac"]:
            problems.append(f"MAC {mgmt['mac']} is not the enrolled {enrollment['network']['mac']}")
        if mgmt["wireless"]:
            problems.append("wireless")
        if mgmt["bridge"] or not mgmt["physical"]:
            problems.append("bridge, bond, VLAN or virtual interface")
        if len(mgmt["gateways"]) != 1:
            problems.append(f"{len(mgmt['gateways'])} default gateways")
        r.add("management-interface", "fail" if problems else "pass",
              "; ".join(problems) if problems else f"{mgmt['name']} {mgmt['mac']} {mgmt['ipv4']['cidr']}")
        cfg_mode = config.get("network", {}).get("ipv4")
        if mgmt["ipv4"]["assignment"] != "dynamic":
            r.add("network-persistence", "fail",
                  "the source uses static addressing; the reviewed machine configuration is DHCP-only, "
                  "so the installed system would lose its management address")
        elif cfg_mode != "dhcp":
            r.add("network-persistence", "fail", f"configuration network.ipv4 = {cfg_mode!r}")
        else:
            r.add("network-persistence", "pass", "DHCP on the source, the installer and the installed system")

    # --- takeover feasibility
    kexec_ok = inv["kernel"]["kexec_load_disabled"] == "0"
    lockdown = inv["kernel"]["lockdown"]
    locked = bool(lockdown) and "[none]" not in lockdown
    rescue_media = bool(enrollment["rescue"].get("boot_command"))
    if kexec_ok and not locked:
        takeover = "kexec"
        r.add("takeover", "pass", "kexec: kexec_load enabled, kernel lockdown none"
              + ("; rescue-media boot also available" if rescue_media else ""))
    elif rescue_media:
        takeover = "rescue-media"
        r.add("takeover", "pass", f"rescue-media through the management plane (kexec unavailable: "
              f"kexec_load_disabled={inv['kernel']['kexec_load_disabled']!r} lockdown={lockdown!r})")
    else:
        takeover = None
        r.add("takeover", "fail", f"kexec_load_disabled={inv['kernel']['kexec_load_disabled']!r} "
              f"lockdown={lockdown!r} and the rescue route cannot boot media; no takeover path")

    # --- resources, from measured sizes, not guesses
    staging = sum(f["size"] for f in installer["files"].values())
    ram_floor = staging * 2 + installer["initrd_unpacked_bytes"] + INSTALLER_WORKING_MIB * MIB
    have = inv["memory"]["total_kib"] * 1024
    r.add("memory", "pass" if have >= ram_floor else "fail",
          f"{have // MIB} MiB total, floor {ram_floor // MIB} MiB "
          f"(staged takeover image x2 + unpacked initrd + {INSTALLER_WORKING_MIB} MiB working set)")
    layout = None
    if target is not None:
        size_bytes = target["size_sectors"] * 512
        layout = render_layout(f"/dev/{target['name']}", size_bytes // (1000 ** 3))
        if "error" in layout:
            r.add("storage-layout", "fail", layout["error"])
            layout = None
        else:
            need = payload["rootfs_unpacked_bytes"] * (100 + DISK_MARGIN_PERCENT) // 100 \
                + layout["espSizeMib"] * MIB
            r.add("storage-capacity", "pass" if size_bytes >= need else "fail",
                  f"{size_bytes // MIB} MiB disk, needs {need // MIB} MiB "
                  f"(payload {payload['rootfs_unpacked_bytes'] // MIB} MiB + {DISK_MARGIN_PERCENT}% + ESP)")
            r.add("storage-layout", "pass", f"{layout['layout']} rendered by repro/disk_layouts.nim")

    # --- rescue and planning environment
    r.add("rescue-route", "pass", f"{enrollment['rescue']['kind']} console {enrollment['rescue']['console_log']}")
    qualified = bool(payload.get("qualified")) and bool(installer.get("qualified"))
    r.add("payload-qualification", "pass" if qualified else "requires",
          "qualified source closure" if qualified else
          f"payload kind {payload.get('kind')!r}, installer kind {installer.get('kind')!r}: a conversion "
          "with these artifacts is a protocol test, not a qualified ReproOS conversion")

    report = {
        "schema": "reproos-anywhere-compatibility/1",
        "blocked": r.blocked,
        "checks": r.checks,
        "conversion_qualified": False if r.blocked else qualified,
        "destructive_authorization": False,
        "requires": [c["id"] for c in r.checks if c["verdict"] == "requires"],
    }
    if not r.blocked and target is not None and mgmt is not None and layout is not None:
        report["target"] = {
            "kernel_name": target["name"], "serial": target["serial"],
            "size_sectors": target["size_sectors"], "logical_block": target["logical_block"],
            "syspath": target["syspath"], "devnum": target["devnum"], "driver": target["driver"],
            "wwid": target["wwid"],
        }
        report["network"] = {"mac": mgmt["mac"], "mode": "dhcp", "interface": mgmt["name"],
                             "cidr": mgmt["ipv4"]["cidr"], "gateway": mgmt["gateways"][0]}
        report["layout"] = layout
        report["takeover"] = {"default": takeover,
                              "available": [m for m, ok in (("kexec", kexec_ok and not locked),
                                                            ("rescue-media", rescue_media)) if ok]}
    return report
