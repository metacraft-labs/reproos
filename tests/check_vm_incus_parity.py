#!/usr/bin/env python3
"""Compare the shared contract of VM and Incus ReproOS realizations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tomllib


SHARED_FIELDS = {
    "schema_version",
    "hostname",
    "regional.locale",
    "regional.timezone",
    "regional.keymap",
    "user.name",
    "user.full_name",
    "user.password_hash",
    "user.groups",
    "user.shell",
    "de.default",
    "activities.enabled",
}

EXPECTED_DIFFERENCES = {
    "disk.size_gb": "ignored-with-reason",
    "disk.layout.type": "ignored-with-reason",
    "disk.layout.esp_size_mib": "ignored-with-reason",
    "install.target_device": "ignored-with-reason",
    "hardware.boot": "vm-specific",
    "services.display-manager": "ignored-with-reason",
}

PACKAGE_HASH_FIELDS = {
    "package.bash.sha256",
    "package.busybox.sha256",
    "package.openssh.sha256",
    "package.systemd.sha256",
}

RUNTIME_CONTRACT = {
    "service.sshd.enabled": "yes",
    "service.sshd.active": "yes",
    "network.default-route": "present",
    "network.resolver": "configured",
    "application.ssh-response": "REPROOS_RUNTIME_OK",
    "health": "pass",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_contract(path: Path) -> dict[str, str]:
    contract: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            raise ValueError(f"malformed contract line in {path}: {line!r}")
        key, value = line.split("=", 1)
        if not key or key in contract:
            raise ValueError(f"invalid contract key in {path}: {key!r}")
        contract[key] = value
    return contract


def expected_contract(config_path: Path, artifacts: Path) -> dict[str, str]:
    with config_path.open("rb") as handle:
        config = tomllib.load(handle)
    user = config["user"]
    groups = sorted({str(group) for group in user["groups"]} | {str(user["name"])})
    expected = {
        "hostname": str(config["hostname"]),
        "user": ":".join(
            [
                "1000",
                "1000",
                str(user["full_name"]),
                f"/home/{user['name']}",
                str(user["shell"]),
            ]
        ),
        "groups": ",".join(groups),
    }
    for name in ("auto-config.toml", "home.nim", "system.nim"):
        expected[name] = sha256(artifacts / name)
    generation = sha256(config_path)
    expected["generation"] = hashlib.sha256(
        (generation + "\n").encode("utf-8")
    ).hexdigest()
    expected.update(RUNTIME_CONTRACT)
    return expected


def check_realization_contract(
    label: str,
    contract: dict[str, str],
    expected: dict[str, str],
    realization_groups: set[str],
) -> None:
    expected_keys = set(expected) | PACKAGE_HASH_FIELDS
    if set(contract) != expected_keys:
        raise ValueError(
            f"{label} contract schema differs: "
            f"missing={sorted(expected_keys - set(contract))!r} "
            f"extra={sorted(set(contract) - expected_keys)!r}"
        )
    expected_without_groups = {
        key: value for key, value in expected.items() if key != "groups"
    }
    actual_without_groups = {
        key: value
        for key, value in contract.items()
        if key != "groups" and key not in PACKAGE_HASH_FIELDS
    }
    if actual_without_groups != expected_without_groups:
        raise ValueError(
            f"{label} contract differs from reviewed intent: {contract!r}"
        )

    for key in PACKAGE_HASH_FIELDS:
        if not re.fullmatch(r"[0-9a-f]{64}", contract[key]):
            raise ValueError(f"{label} package identity is malformed: {key}")

    configured_groups = set(expected["groups"].split(","))
    actual_groups = set(contract.get("groups", "").split(","))
    wanted_groups = configured_groups | realization_groups
    if actual_groups != wanted_groups:
        raise ValueError(
            f"{label} groups differ from reviewed intent: "
            f"expected={sorted(wanted_groups)!r} actual={sorted(actual_groups)!r}"
        )


def check_shared_package_identities(
    vm: dict[str, str], container: dict[str, str]
) -> None:
    differences = {
        key: (vm[key], container[key])
        for key in PACKAGE_HASH_FIELDS
        if vm[key] != container[key]
    }
    if differences:
        raise ValueError(
            f"VM and Incus source-built package identities differ: {differences!r}"
        )


def check_report(report_path: Path, config_path: Path) -> None:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("configuration_sha256") != sha256(config_path):
        raise ValueError("projection report does not identify the tested configuration")

    fields = {field["path"]: field for field in report.get("fields", [])}
    for path in SHARED_FIELDS:
        field = fields.get(path)
        if not field or field.get("classification") != "shared" or not field.get("projected"):
            raise ValueError(f"shared projection field is not preserved: {path}")

    network = fields.get("network.ipv4")
    if not network or network.get("classification") != "container-specific" or not network.get("projected"):
        raise ValueError("container network projection is not documented")
    network_capability = (
        report.get("realization_profile", {}).get("capabilities", {}).get("network")
    )
    if network_capability != {
        "provider": "incus-veth",
        "guest_mode": "profile-static-with-dhcp-fallback",
    }:
        raise ValueError("container network realization mode is not documented")

    differences = {
        difference["path"]: difference
        for difference in report.get("differences", [])
    }
    for path, classification in EXPECTED_DIFFERENCES.items():
        difference = differences.get(path)
        if not difference or difference.get("classification") != classification:
            raise ValueError(f"intentional realization difference is missing: {path}")
        if difference.get("projected") or not difference.get("reason"):
            raise ValueError(f"realization difference is not justified: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vm", type=Path, required=True)
    parser.add_argument("--container", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()

    vm = load_contract(args.vm)
    container = load_contract(args.container)
    expected = expected_contract(args.config, args.artifacts)
    check_realization_contract("VM", vm, expected, {"seat"})
    check_realization_contract("Incus", container, expected, set())
    check_shared_package_identities(vm, container)
    check_report(args.report, args.config)
    print("ReproOS VM and Incus shared realization contract: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"VM_INCUS_PARITY_FAILED: {error}")
        raise SystemExit(1)
