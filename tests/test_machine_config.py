#!/usr/bin/env python3
"""Focused regressions for reusable machine profiles and enrollment."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/reproos-machine-config.py"
SPEC = importlib.util.spec_from_file_location("reproos_machine_config", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def valid_public() -> dict:
    return MODULE.load_toml(ROOT / "tests/fixtures/auto-config-minimal.toml")


def valid_enrollment(key_blob: str) -> dict:
    return {
        "schema_version": 1,
        "machine_id": "83fddb41-b072-45e1-8e44-7ef56f4463a7",
        "ssh": {
            "authorized_keys": [f"ssh-ed25519 {key_blob} reproos-test"],
        },
    }


def bash_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    result = subprocess.run(
        ["bash", "-lc", 'cygpath -u "$1"', "bash", str(path)],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


class MachineConfigurationTests(unittest.TestCase):
    def test_network_launcher_allows_an_offline_machine(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reproos-offline-network-") as raw:
            root = Path(raw)
            network_root = root / "net"
            network_root.mkdir()
            ready_file = root / "network-ready"
            busybox = root / "busybox"
            busybox.write_text("#!/bin/sh\nexec \"$@\"\n")
            busybox.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "REPROOS_SYS_CLASS_NET": bash_path(network_root),
                    "REPROOS_NETWORK_INTERFACE_ATTEMPTS": "0",
                    "REPROOS_NETWORK_READY_FILE": bash_path(ready_file),
                    "REPROOS_BUSYBOX": bash_path(busybox),
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    bash_path(
                        ROOT / "recipes/reproos-image/scripts/reproos-network"
                    ),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("continuing offline", result.stdout)
            self.assertEqual(ready_file.read_text(), "offline\n")
            waiter = subprocess.run(
                [
                    "bash",
                    bash_path(
                        ROOT
                        / "recipes/reproos-image/scripts/reproos-network-wait"
                    ),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(waiter.returncode, 0, waiter.stderr)

            ready_file.unlink()
            env["REPROOS_NETWORK_READY_ATTEMPTS"] = "0"
            waiter = subprocess.run(
                [
                    "bash",
                    bash_path(
                        ROOT
                        / "recipes/reproos-image/scripts/reproos-network-wait"
                    ),
                ],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(waiter.returncode, 0, waiter.stderr)
            self.assertIn("continuing offline", waiter.stderr)
            self.assertEqual(ready_file.read_text(), "offline\n")

    def test_remote_access_configuration_validation(self) -> None:
        config = valid_public()
        manifest = MODULE.validate_public(config)
        self.assertEqual(manifest["remote_access"]["authentication"], "public-key")
        self.assertEqual(manifest["identity_evidence"]["machine_id"], "/etc/machine-id")

        mutations = []
        for path, value in (
            (("user", "locked"), False),
            (("ssh", "permit_root_login"), True),
            (("ssh", "password_authentication"), True),
            (("ssh", "authorized_keys_source"), "embedded"),
            (("firewall", "default_policy"), "allow"),
            (("firewall", "ssh_source_cidrs"), ["0.0.0.0/0"]),
        ):
            mutated = copy.deepcopy(config)
            mutated[path[0]][path[1]] = value
            mutations.append(mutated)
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                with self.assertRaises(MODULE.ConfigError):
                    MODULE.validate_public(mutated)

        manifest_stub = {"public_image_cache_key": "a" * 64}
        with self.assertRaises(MODULE.ConfigError):
            MODULE.compile_enrollment(
                manifest_stub,
                {
                    "schema_version": 1,
                    "machine_id": "83fddb41-b072-45e1-8e44-7ef56f4463a7",
                    "ssh": {"authorized_keys": ["-----BEGIN OPENSSH PRIVATE KEY-----"]},
                },
            )

        with tempfile.TemporaryDirectory(prefix="reproos-enrollment-") as raw:
            root = Path(raw) / "root"
            enrollment = Path(raw) / "enrollment"
            (root / "etc/repro").mkdir(parents=True)
            (root / "etc/reproos").mkdir(parents=True)
            (root / "var/lib/reproos").mkdir(parents=True)
            enrollment.mkdir()
            (root / "etc/repro/auto-config.toml").write_bytes(
                (ROOT / "tests/fixtures/auto-config-minimal.toml").read_bytes()
            )
            (root / "etc/reproos/auto-config.toml").write_text(
                "installer media configuration\n"
            )
            (root / "etc/repro/generation").write_text("generation-test\n")
            (root / "var/lib/reproos/install-source").write_text(
                "unattended-installer\n"
            )
            (root / "etc/passwd").write_text(
                "root:x:0:0:root:/root:/bin/sh\n"
                "live:x:1000:1000:Live User:/home/live:/bin/bash\n"
            )
            (root / "etc/shadow").write_text("root:!:::::::\nlive:!:::::::\n")
            (root / "etc/group").write_text(
                "root:x:0:\nwheel:x:10:live\naudio:x:29:live\n"
                "video:x:44:live\nlive:x:1000:\n"
            )
            (root / "etc/gshadow").write_text(
                "root:*::\nwheel:*::live\naudio:*::live\n"
                "video:*::live\nlive:!::\n"
            )
            (enrollment / "machine-id").write_text(
                "83fddb41-b072-45e1-8e44-7ef56f4463a7\n"
            )
            (enrollment / "authorized_keys").write_text(
                "ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE= test\n"
            )
            env = os.environ.copy()
            env.update(
                {
                    "REPROOS_ROOT": bash_path(root),
                    "REPROOS_ENROLLMENT_DIR": bash_path(enrollment),
                    "REPROOS_SSH_HOST_KEY_FINGERPRINT": "SHA256:test-host-key",
                    "REPROOS_TEST_MODE": "1",
                    "MSYS2_ARG_CONV_EXCL": "*",
                }
            )
            subprocess.run(
                [
                    "bash",
                    bash_path(
                        ROOT
                        / "recipes/reproos-image/scripts/reproos-first-boot-enroll"
                    ),
                ],
                check=True,
                env=env,
                text=True,
                capture_output=True,
            )
            identity = json.loads(
                (root / "var/lib/reproos/identity.json").read_text()
            )
            self.assertEqual(
                identity["machine_id"], "83fddb41b07245e18e447ef56f4463a7"
            )
            self.assertEqual(identity["install_source"], "unattended-installer")
            self.assertTrue((root / "var/lib/reproos/enrollment.complete").exists())
            self.assertIn("repro:x:1000:1000:", (root / "etc/passwd").read_text())
            self.assertNotIn("live:", (root / "etc/passwd").read_text())
            self.assertIn(
                "repro:x:20000:0:99999:7:::",
                (root / "etc/shadow").read_text(),
            )
            group_records = (root / "etc/group").read_text().splitlines()
            for group_name in ("wheel", "audio", "video", "networkmanager", "seat"):
                self.assertTrue(
                    any(
                        record.split(":", 1)[0] == group_name
                        and "repro" in record.rsplit(":", 1)[1].split(",")
                        for record in group_records
                    ),
                    f"missing repro membership in {group_name}",
                )
            gids = [record.split(":")[2] for record in group_records]
            self.assertEqual(len(gids), len(set(gids)))
            names = [record.split(":")[0] for record in group_records]
            self.assertEqual(len(names), len(set(names)))
            gshadow_records = (
                root / "etc/gshadow"
            ).read_text().splitlines()
            self.assertFalse(any(
                record.split(":", 1)[0] == "live"
                for record in gshadow_records
            ))
            for group_name in (
                "wheel", "audio", "video", "networkmanager", "seat"
            ):
                self.assertTrue(
                    any(
                        record.split(":", 1)[0] == group_name
                        and "repro" in record.rsplit(":", 1)[1].split(",")
                        for record in gshadow_records
                    ),
                    f"missing repro gshadow membership in {group_name}: "
                    f"{gshadow_records}",
                )
            self.assertIn("repro:!::", gshadow_records)
            self.assertEqual((root / "etc/machine-id").read_text().strip(), identity["machine_id"])
            self.assertEqual(
                (root / "etc/hostname").read_text().strip(), "reproos-smoke"
            )
            sddm = (root / "etc/sddm.conf.d/00-autologin.conf").read_text()
            self.assertIn("User=repro", sddm)
            self.assertIn("Session=sway", sddm)
            self.assertFalse((root / "etc/reproos/auto-config.toml").exists())
            self.assertTrue(
                (
                    root
                    / "etc/reproos/auto-config.toml.disabled-after-install"
                ).is_file()
            )

    def test_instance_secrets_do_not_affect_public_image_cache_key(self) -> None:
        public_manifest = MODULE.validate_public(valid_public())
        first = MODULE.compile_enrollment(
            public_manifest,
            valid_enrollment("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="),
        )
        second = MODULE.compile_enrollment(
            public_manifest,
            valid_enrollment("QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="),
        )
        self.assertEqual(
            first["public_image_cache_key"], second["public_image_cache_key"]
        )
        self.assertNotEqual(first["instance_injection_key"], second["instance_injection_key"])
        self.assertNotEqual(
            first["ssh"]["authorized_key_fingerprints"],
            second["ssh"]["authorized_key_fingerprints"],
        )


if __name__ == "__main__":
    unittest.main()
