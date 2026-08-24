#!/usr/bin/env python3
"""Validate public ReproOS machine profiles and compile instance enrollment."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import re
import tomllib
import uuid
from pathlib import Path
from typing import Any


PUBLIC_SCHEMA = 2
ENROLLMENT_SCHEMA = 1
HOSTNAME_RE = re.compile(
    r"(?=^.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)
LABEL_RE = re.compile(r"[A-Z0-9_]{1,32}$")
SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
}

PUBLIC_FIELDS = {
    "schema_version",
    "hostname",
    "regional.locale",
    "regional.timezone",
    "regional.keymap",
    "user.name",
    "user.full_name",
    "user.locked",
    "user.groups",
    "user.shell",
    "sudo.policy",
    "sudo.users",
    "disk.size_gb",
    "disk.layout.type",
    "disk.layout.esp_size_mib",
    "de.default",
    "network.ipv4",
    "ssh.enabled",
    "ssh.permit_root_login",
    "ssh.password_authentication",
    "ssh.authorized_keys_source",
    "firewall.default_policy",
    "firewall.allowed_tcp_ports",
    "firewall.ssh_source_cidrs",
    "first_boot.enrollment",
    "first_boot.enrollment_label",
    "activities.enabled",
    "install.target_device",
}
ENROLLMENT_FIELDS = {
    "schema_version",
    "machine_id",
    "ssh.authorized_keys",
}


class ConfigError(ValueError):
    pass


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigError(f"{path} does not contain a TOML table")
    return value


def flatten(value: dict[str, Any], prefix: str = "") -> set[str]:
    fields: set[str] = set()
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(child, dict):
            fields.update(flatten(child, path))
        else:
            fields.add(path)
    return fields


def field(config: dict[str, Any], path: str, expected: type) -> Any:
    value: Any = config
    for component in path.split("."):
        if not isinstance(value, dict) or component not in value:
            raise ConfigError(f"missing required field: {path}")
        value = value[component]
    if expected is int and isinstance(value, bool):
        raise ConfigError(f"{path} must be an integer")
    if not isinstance(value, expected):
        raise ConfigError(f"{path} must be {expected.__name__}")
    return value


def string_list(config: dict[str, Any], path: str, *, nonempty: bool = True) -> list[str]:
    values = field(config, path, list)
    if nonempty and not values:
        raise ConfigError(f"{path} must not be empty")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ConfigError(f"{path} must contain non-empty strings")
    return values


def require_exact(value: Any, expected: Any, path: str) -> None:
    if value != expected:
        raise ConfigError(f"{path} must be {expected!r}, got {value!r}")


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def validate_public(config: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(flatten(config) - PUBLIC_FIELDS)
    if unknown:
        raise ConfigError("unknown public configuration fields: " + ", ".join(unknown))

    require_exact(field(config, "schema_version", int), PUBLIC_SCHEMA, "schema_version")
    hostname = field(config, "hostname", str)
    if not HOSTNAME_RE.fullmatch(hostname):
        raise ConfigError("hostname must be a valid lower-case DNS hostname")

    for path in ("regional.locale", "regional.timezone", "regional.keymap"):
        if not field(config, path, str).strip():
            raise ConfigError(f"{path} must not be empty")

    user = field(config, "user.name", str)
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ConfigError("user.name must be a valid local account name")
    for path in ("user.full_name", "user.shell"):
        if not field(config, path, str).strip():
            raise ConfigError(f"{path} must not be empty")
    require_exact(field(config, "user.locked", bool), True, "user.locked")
    groups = string_list(config, "user.groups")

    require_exact(field(config, "sudo.policy", str), "passwordless", "sudo.policy")
    sudo_users = string_list(config, "sudo.users")
    if user not in sudo_users or "wheel" not in groups:
        raise ConfigError("the administrative user must be in sudo.users and user.groups wheel")

    if field(config, "disk.size_gb", int) < 4:
        raise ConfigError("disk.size_gb must be at least 4")
    require_exact(field(config, "disk.layout.type", str), "uefi-ext4", "disk.layout.type")
    if field(config, "disk.layout.esp_size_mib", int) < 128:
        raise ConfigError("disk.layout.esp_size_mib must be at least 128")
    require_exact(field(config, "network.ipv4", str), "dhcp", "network.ipv4")

    require_exact(field(config, "ssh.enabled", bool), True, "ssh.enabled")
    require_exact(
        field(config, "ssh.permit_root_login", bool), False, "ssh.permit_root_login"
    )
    require_exact(
        field(config, "ssh.password_authentication", bool),
        False,
        "ssh.password_authentication",
    )
    require_exact(
        field(config, "ssh.authorized_keys_source", str),
        "instance-enrollment",
        "ssh.authorized_keys_source",
    )

    require_exact(
        field(config, "firewall.default_policy", str), "deny", "firewall.default_policy"
    )
    ports = field(config, "firewall.allowed_tcp_ports", list)
    if any(isinstance(port, bool) or not isinstance(port, int) for port in ports):
        raise ConfigError("firewall.allowed_tcp_ports must contain integers")
    if ports != sorted(set(ports)) or any(port not in range(1, 65536) for port in ports):
        raise ConfigError("firewall.allowed_tcp_ports must be sorted unique TCP ports")
    if 22 not in ports:
        raise ConfigError("SSH is enabled but TCP port 22 is not allowed")

    source_cidrs = string_list(config, "firewall.ssh_source_cidrs")
    for source in source_cidrs:
        try:
            network = ipaddress.ip_network(source, strict=True)
        except ValueError as exc:
            raise ConfigError(f"invalid firewall.ssh_source_cidrs entry: {source}") from exc
        if network.prefixlen == 0 or not (
            network.is_private or network.is_loopback or network.is_link_local
        ):
            raise ConfigError(f"SSH source must be bounded to a non-public network: {source}")

    require_exact(
        field(config, "first_boot.enrollment", str), "required", "first_boot.enrollment"
    )
    label = field(config, "first_boot.enrollment_label", str)
    if not LABEL_RE.fullmatch(label):
        raise ConfigError("first_boot.enrollment_label must be an uppercase disk label")

    string_list(config, "activities.enabled", nonempty=False)
    if not field(config, "install.target_device", str).startswith("/dev/"):
        raise ConfigError("install.target_device must be an absolute /dev path")
    if not field(config, "de.default", str).strip():
        raise ConfigError("de.default must not be empty")

    generation = canonical_digest(config)
    return {
        "schema_version": 1,
        "public_image_cache_key": generation,
        "configuration_generation": generation,
        "hostname": hostname,
        "remote_access": {
            "user": user,
            "port": 22,
            "authentication": "public-key",
            "authorized_keys_source": "instance-enrollment",
            "source_cidrs": source_cidrs,
        },
        "identity_evidence": {
            "machine_id": "/etc/machine-id",
            "generation_id": "/etc/repro/generation",
            "ssh_host_key_fingerprint": "/var/lib/reproos/ssh-host-key-fingerprint",
            "install_source": "/var/lib/reproos/install-source",
        },
        "first_boot": {"enrollment": "required", "label": label},
    }


def parse_public_key(value: str) -> tuple[str, str]:
    if "PRIVATE KEY" in value or "\n" in value or "\r" in value:
        raise ConfigError("ssh.authorized_keys must contain public keys, not private key data")
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] not in SSH_KEY_TYPES:
        raise ConfigError("ssh.authorized_keys contains an unsupported public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError as exc:
        raise ConfigError("ssh.authorized_keys contains invalid base64") from exc
    if len(blob) < 16:
        raise ConfigError("ssh.authorized_keys contains a truncated public key")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"{parts[0]} {parts[1]}" + (f" {' '.join(parts[2:])}" if len(parts) > 2 else ""), f"SHA256:{fingerprint}"


def compile_enrollment(public_manifest: dict[str, Any], enrollment: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(flatten(enrollment) - ENROLLMENT_FIELDS)
    if unknown:
        raise ConfigError("unknown enrollment fields: " + ", ".join(unknown))
    require_exact(
        field(enrollment, "schema_version", int), ENROLLMENT_SCHEMA, "schema_version"
    )
    try:
        machine_id = uuid.UUID(field(enrollment, "machine_id", str))
    except ValueError as exc:
        raise ConfigError("machine_id must be a UUID") from exc
    keys = string_list(enrollment, "ssh.authorized_keys")
    parsed = [parse_public_key(key) for key in keys]
    normalized_keys = [key for key, _ in parsed]
    if len(normalized_keys) != len(set(normalized_keys)):
        raise ConfigError("ssh.authorized_keys must not contain duplicates")

    public_key = field(public_manifest, "public_image_cache_key", str)
    payload = {
        "schema_version": ENROLLMENT_SCHEMA,
        "public_image_cache_key": public_key,
        "machine_id": machine_id.hex,
        "ssh": {
            "authorized_keys": normalized_keys,
            "authorized_key_fingerprints": [fingerprint for _, fingerprint in parsed],
        },
    }
    payload["instance_injection_key"] = canonical_digest(payload)
    return payload


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--config", type=Path, required=True)
    validate_parser.add_argument("--output", type=Path, required=True)
    enroll_parser = subparsers.add_parser("enroll")
    enroll_parser.add_argument("--public-manifest", type=Path, required=True)
    enroll_parser.add_argument("--enrollment", type=Path, required=True)
    enroll_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "validate":
            result = validate_public(load_toml(args.config))
        else:
            public_manifest = json.loads(args.public_manifest.read_text(encoding="ascii"))
            result = compile_enrollment(public_manifest, load_toml(args.enrollment))
        write_json(args.output, result)
    except (ConfigError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
