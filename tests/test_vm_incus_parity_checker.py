#!/usr/bin/env python3
"""Focused regressions for the VM/Incus semantic parity checker."""

from __future__ import annotations

from pathlib import Path

from check_vm_incus_parity import (
    PACKAGE_HASH_FIELDS,
    check_realization_contract,
    check_shared_package_identities,
    expected_contract,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "tests" / "fixtures" / "auto-config-minimal.toml"
ARTIFACTS = ROOT / "tests" / "golden" / "installer-artifacts"


def contract_with_groups(groups: set[str]) -> dict[str, str]:
    contract = expected_contract(CONFIG, ARTIFACTS)
    contract["groups"] = ",".join(sorted(groups))
    for index, field in enumerate(sorted(PACKAGE_HASH_FIELDS), start=1):
        contract[field] = f"{index:064x}"
    return contract


def expect_failure(operation, message: str) -> None:
    try:
        operation()
    except ValueError:
        return
    raise AssertionError(message)


def main() -> None:
    configured_groups = set(
        expected_contract(CONFIG, ARTIFACTS)["groups"].split(",")
    )
    vm = contract_with_groups(configured_groups | {"seat"})
    container = contract_with_groups(configured_groups)

    check_realization_contract("VM", vm, expected_contract(CONFIG, ARTIFACTS), {"seat"})
    check_realization_contract(
        "Incus", container, expected_contract(CONFIG, ARTIFACTS), set()
    )
    check_shared_package_identities(vm, container)

    drifted_package = dict(container)
    drifted_package["package.busybox.sha256"] = "f" * 64
    expect_failure(
        lambda: check_shared_package_identities(vm, drifted_package),
        "package drift was accepted",
    )

    missing_runtime_field = dict(container)
    del missing_runtime_field["network.resolver"]
    expect_failure(
        lambda: check_realization_contract(
            "Incus", missing_runtime_field, expected_contract(CONFIG, ARTIFACTS), set()
        ),
        "an incomplete runtime contract was accepted",
    )

    print("ReproOS VM/Incus parity checker regressions: PASS")


if __name__ == "__main__":
    main()
