#!/usr/bin/env python3
"""Project canonical ReproOS installer configuration into an Incus rootfs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from enum import Enum
from pathlib import Path
import shutil
import tomllib


class FieldClass(str, Enum):
    SHARED = "shared"
    CONTAINER = "container-specific"
    VM = "vm-specific"
    IGNORED = "ignored-with-reason"
    INVALID = "invalid-for-incus"


FIELD_RULES = (
    ("schema_version", FieldClass.SHARED, "schema identity is unchanged"),
    ("hostname", FieldClass.SHARED, "hostname is identical"),
    ("regional.locale", FieldClass.SHARED, "locale intent is identical"),
    ("regional.timezone", FieldClass.SHARED, "timezone intent is identical"),
    ("regional.keymap", FieldClass.SHARED, "keymap intent is retained"),
    ("user.name", FieldClass.SHARED, "account name is identical"),
    ("user.full_name", FieldClass.SHARED, "account metadata is identical"),
    ("user.password_hash", FieldClass.SHARED, "credential hash is copied without disclosure"),
    ("user.groups", FieldClass.SHARED, "supplementary groups are identical"),
    ("user.shell", FieldClass.SHARED, "login shell is identical"),
    ("disk.size_gb", FieldClass.IGNORED, "Incus owns the root volume"),
    ("disk.layout.type", FieldClass.IGNORED, "a container has no partition table"),
    ("disk.layout.esp_size_mib", FieldClass.IGNORED, "a container has no EFI system partition"),
    ("de.default", FieldClass.SHARED, "package intent is retained; seat activation is suppressed"),
    ("network.ipv4", FieldClass.CONTAINER, "DHCP is projected onto the Incus eth0 device"),
    ("activities.enabled", FieldClass.SHARED, "activity selection is identical"),
    ("install.target_device", FieldClass.IGNORED, "Incus creates the root volume"),
)


def nested(config: dict, path: str):
    value = config
    for component in path.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def require(config: dict, path: str):
    value = nested(config, path)
    if value is None or value == "":
        raise ValueError(f"INCUS_CONFIG_REQUIRED: missing {path}")
    return value


def projection_report(config_path: Path, config: dict) -> dict:
    if require(config, "network.ipv4") != "dhcp":
        raise ValueError(
            "INCUS_CONFIG_UNSUPPORTED_NETWORK_MODE: network.ipv4 must be dhcp"
        )
    require(config, "hostname")
    require(config, "user.name")
    require(config, "user.password_hash")

    fields = []
    for path, classification, reason in FIELD_RULES:
        if nested(config, path) is not None:
            fields.append(
                {
                    "path": path,
                    "classification": classification.value,
                    "projected": classification
                    in {FieldClass.SHARED, FieldClass.CONTAINER},
                    "reason": reason,
                }
            )

    differences = [field for field in fields if not field["projected"]]
    differences.extend(
        [
            {
                "path": "hardware.boot",
                "classification": FieldClass.VM.value,
                "projected": False,
                "reason": "kernel, firmware, initramfs, and bootloader are supplied by the host",
            },
            {
                "path": "services.display-manager",
                "classification": FieldClass.IGNORED.value,
                "projected": False,
                "reason": "the system-container profile has no graphical seat",
            },
        ]
    )
    config_bytes = config_path.read_bytes()
    return {
        "schema_version": 1,
        "configuration_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "realization_profile": {
            "kind": "incus-system-container",
            "architecture": "x86_64",
            "init": "systemd",
            "privilege": "unprivileged",
            "capabilities": {
                "kernel": {"provider": "host", "configurable": False},
                "devices": {"mode": "deny-by-default"},
                "nesting": {"enabled": False},
                "storage": {"provider": "incus-root-volume", "bootable": False},
                "network": {"provider": "incus-veth", "guest_mode": "dhcp"},
                "firmware": {"available": False},
                "remote_attestation": {"available": False},
            },
        },
        "fields": fields,
        "differences": differences,
    }


def write_text(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def rewrite_records(path: Path, removed: set[str], additions: list[str]) -> None:
    rows = []
    if path.exists():
        for row in path.read_text(encoding="utf-8").splitlines():
            if row and row.split(":", 1)[0] not in removed:
                rows.append(row)
    rows.extend(additions)
    write_text(path, "\n".join(rows) + "\n", 0o600 if path.name in {"shadow", "gshadow"} else 0o644)


def configure_accounts(rootfs: Path, config: dict) -> None:
    user = config["user"]
    name = str(user["name"])
    full_name = str(user.get("full_name", name)).replace(":", "")
    shell = str(user.get("shell", "/bin/bash"))
    password_hash = str(user["password_hash"])
    requested_groups = [str(group) for group in user.get("groups", [])]

    etc = rootfs / "etc"
    passwd = etc / "passwd"
    group = etc / "group"
    shadow = etc / "shadow"
    gshadow = etc / "gshadow"
    removed = {"live", name}
    rewrite_records(
        passwd,
        removed,
        [f"{name}:x:1000:1000:{full_name}:/home/{name}:{shell}"],
    )
    rewrite_records(
        shadow,
        removed,
        [f"{name}:{password_hash}:20000:0:99999:7:::"],
    )

    existing = []
    used_ids = set()
    if group.exists():
        for row in group.read_text(encoding="utf-8").splitlines():
            parts = row.split(":")
            if len(parts) == 4 and parts[0] not in removed:
                existing.append(parts)
                if parts[2].isdigit():
                    used_ids.add(int(parts[2]))
    preferred = {"wheel": 10, "audio": 29, "video": 44, "networkmanager": 102}
    by_name = {parts[0]: parts for parts in existing}
    for group_name in requested_groups:
        if group_name not in by_name:
            gid = preferred.get(group_name, 200)
            while gid in used_ids or gid == 1000:
                gid += 1
            used_ids.add(gid)
            parts = [group_name, "x", str(gid), ""]
            existing.append(parts)
            by_name[group_name] = parts
        members = [member for member in by_name[group_name][3].split(",") if member and member != "live"]
        if name not in members:
            members.append(name)
        by_name[group_name][3] = ",".join(sorted(members))
    existing.append([name, "x", "1000", ""])
    write_text(group, "\n".join(":".join(parts) for parts in existing) + "\n")

    gshadow_rows = []
    if gshadow.exists():
        for row in gshadow.read_text(encoding="utf-8").splitlines():
            if row and row.split(":", 1)[0] not in removed | set(requested_groups):
                gshadow_rows.append(row)
    for group_name in requested_groups:
        gshadow_rows.append(f"{group_name}:!::{name}")
    gshadow_rows.append(f"{name}:!::")
    write_text(gshadow, "\n".join(gshadow_rows) + "\n", 0o600)

    home = rootfs / "home" / name
    home.mkdir(parents=True, exist_ok=True)
    write_text(home / ".profile", "export PATH=/usr/local/bin:/usr/bin:/usr/sbin\n")


def configure_rootfs(rootfs: Path, artifacts: Path, output: Path, config: dict, report: dict) -> None:
    hostname = str(config["hostname"])
    repro = rootfs / "etc" / "repro"
    repro.mkdir(parents=True, exist_ok=True)
    for name in ("auto-config.toml", "system.nim", "home.nim"):
        shutil.copyfile(artifacts / name, repro / name)
    shutil.copyfile(output / "hardware.nim", repro / "hardware.nim")
    shutil.copyfile(output / "projection-report.json", repro / "realization.json")
    write_text(repro / "generation", report["configuration_sha256"] + "\n")

    write_text(rootfs / "etc" / "hostname", hostname + "\n")
    write_text(
        rootfs / "etc" / "hosts",
        f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n::1 localhost\n",
    )
    write_text(rootfs / "etc" / "machine-id", "")
    configure_accounts(rootfs, config)

    init = rootfs / "usr" / "sbin" / "init"
    init.parent.mkdir(parents=True, exist_ok=True)
    if init.exists() or init.is_symlink():
        init.unlink()
    init.symlink_to("../lib/systemd/systemd")

    systemd = rootfs / "etc" / "systemd" / "system"
    systemd.mkdir(parents=True, exist_ok=True)
    for relative in (
        "display-manager.service",
        "graphical.target.wants/reproos-installer-frame-ready.service",
        "multi-user.target.wants/reproos-installer-autorun.service",
    ):
        path = systemd / relative
        if path.exists() or path.is_symlink():
            path.unlink()
    default_target = systemd / "default.target"
    if default_target.exists() or default_target.is_symlink():
        default_target.unlink()
    default_target.symlink_to("/usr/lib/systemd/system/multi-user.target")

    network_script = rootfs / "usr" / "lib" / "reproos" / "incus-udhcpc"
    write_text(
        network_script,
        "#!/usr/bin/busybox sh\n"
        "case \"${1:-}\" in\n"
        "  deconfig) /usr/bin/busybox ip addr flush dev \"$interface\" ;;\n"
        "  bound|renew)\n"
        "    /usr/bin/busybox ip addr flush dev \"$interface\"\n"
        "    /usr/bin/busybox ip addr add \"$ip/$subnet\" dev \"$interface\"\n"
        "    /usr/bin/busybox ip link set \"$interface\" up\n"
        "    /usr/bin/busybox ip route del default 2>/dev/null || true\n"
        "    set -- ${router:-}; [ \"$#\" -eq 0 ] || /usr/bin/busybox ip route add default via \"$1\"\n"
        "    : > /etc/resolv.conf\n"
        "    for server in ${dns:-}; do echo \"nameserver $server\" >> /etc/resolv.conf; done\n"
        "    ;;\n"
        "esac\n",
        0o755,
    )
    write_text(
        systemd / "reproos-incus-network.service",
        "[Unit]\nDescription=Configure the Incus network device\n"
        "After=local-fs.target\nBefore=network-online.target sshd.service\n"
        "Wants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        "ExecStart=/usr/bin/busybox ip link set eth0 up\n"
        "ExecStart=/usr/bin/busybox udhcpc -q -n -t 20 -T 1 -i eth0 -s /usr/lib/reproos/incus-udhcpc\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )

    ssh_dir = rootfs / "etc" / "ssh"
    for host_key in ssh_dir.glob("ssh_host_*"):
        host_key.unlink()
    write_text(
        ssh_dir / "sshd_config",
        "Port 22\nListenAddress 0.0.0.0\nProtocol 2\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\n"
        "HostKey /etc/ssh/ssh_host_rsa_key\n"
        "PermitRootLogin no\nPasswordAuthentication yes\n"
        "PubkeyAuthentication yes\nUsePAM no\nStrictModes yes\n"
        "PidFile /run/sshd.pid\nSubsystem sftp internal-sftp\n",
        0o600,
    )
    write_text(
        systemd / "sshd.service",
        "[Unit]\nDescription=OpenSSH server\nAfter=reproos-incus-network.service\n"
        "Wants=reproos-incus-network.service\n\n[Service]\nType=simple\n"
        "RuntimeDirectory=sshd\nExecStartPre=/usr/bin/ssh-keygen -A\n"
        "ExecStart=/usr/sbin/sshd -D -e\nRestart=on-failure\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )

    health_script = rootfs / "usr" / "lib" / "reproos" / "container-health"
    write_text(
        health_script,
        "#!/usr/bin/busybox sh\nset -eu\n"
        f"[ \"$(hostname)\" = \"{hostname}\" ]\n"
        "test -s /etc/repro/system.nim\ntest -s /etc/repro/realization.json\n"
        "test -s /etc/repro/generation\nmkdir -p /run/reproos /var/lib/reproos/health\n"
        "echo REPROOS_INCUS_HEALTH:PASS > /run/reproos/healthy\n"
        "cp /run/reproos/healthy /var/lib/reproos/health/last-pass\n",
        0o755,
    )
    write_text(
        systemd / "reproos-container-health.service",
        "[Unit]\nDescription=Verify the ReproOS container generation\n"
        "After=sshd.service\nWants=sshd.service\n\n[Service]\nType=oneshot\n"
        "ExecStart=/usr/lib/reproos/container-health\nRemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
    )
    wants = systemd / "multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    for unit in (
        "reproos-incus-network.service",
        "sshd.service",
        "reproos-container-health.service",
    ):
        link = wants / unit
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(f"/etc/systemd/system/{unit}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path)
    args = parser.parse_args()

    with args.config.open("rb") as handle:
        config = tomllib.load(handle)
    report = projection_report(args.config, config)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        args.output_dir / "projection-report.json",
        json.dumps(report, indent=2, sort_keys=True) + "\n",
    )
    hardware = (
        "# /etc/repro/hardware.nim -- Incus realization projection\n"
        "import repro_profile\n\n"
        "hardware \"INCUS\":\n"
        "  cpu:\n"
        "    arch: \"x86_64\"\n"
        "    microcode: \"none\"\n"
    )
    write_text(args.output_dir / "hardware.nim", hardware)
    if args.rootfs:
        configure_rootfs(args.rootfs, args.artifacts_dir, args.output_dir, config, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=os.sys.stderr)
        raise SystemExit(2)
