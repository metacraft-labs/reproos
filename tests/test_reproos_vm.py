#!/usr/bin/env python3
"""Regression tests for the vm-harness ReproOS install workflow."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/reproos-vm.py"
SPEC = importlib.util.spec_from_file_location("reproos_vm", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReproosVmWorkflowTests(unittest.TestCase):
    def arguments(self, root: Path, command: str):
        iso = root / "reproos-unattended.iso"
        iso.write_bytes(b"unattended-iso")
        return MODULE.parser().parse_args([
            command,
            "--state-dir", str(root / "state"),
            "--target-disk", str(root / "state/reproos-installed.qcow2"),
            "--iso", str(iso),
            "--vm-harness", "fake-vm-harness",
            "--acceleration", "tcg",
            "--cpus", "3",
            "--memory-mb", "3072",
            "--timeout-sec", "30",
            "--ssh-ready-timeout-sec", "12",
        ])

    def test_reproos_vm_harness_override_wins_over_tool_provider(self):
        with mock.patch.dict(
            "os.environ",
            {
                "VM_HARNESS_BIN": "provider-vm-harness",
                "REPROOS_VM_HARNESS_BIN": "campaign-vm-harness",
            },
            clear=False,
        ):
            args = MODULE.parser().parse_args(["install"])

        self.assertEqual(args.vm_harness, "campaign-vm-harness")

    def test_unattended_vm_rejects_live_media_false_positive(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            root = Path(raw)
            calls: list[list[str]] = []

            def fake_vmh(_binary: str, arguments: list[str]) -> None:
                calls.append(arguments)
                if arguments[0] == "install":
                    target = Path(arguments[arguments.index("--target-disk") + 1])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(b"installed-disk")

            def fake_enrollment(_args, state: Path):
                paths = MODULE.enrollment_paths(state)
                paths["media"].mkdir(parents=True, exist_ok=True)
                paths["private_key"].write_text("private-key")
                paths["public_key"].write_text(
                    "ssh-ed25519 AAAATEST reproos-vm-acceptance\n"
                )
                (paths["media"] / "authorized_keys").write_text(
                    paths["public_key"].read_text()
                )
                (paths["media"] / "machine-id").write_text("a" * 32 + "\n")
                paths["iso"].write_bytes(b"enrollment-iso")
                return paths

            with mock.patch.object(MODULE, "run_vmh", side_effect=fake_vmh), \
                    mock.patch.object(
                        MODULE,
                        "prepare_enrollment",
                        side_effect=fake_enrollment,
                    ):
                install_args = self.arguments(root, "install")
                install_args.replace = True
                stale_diagnostic = (
                    root / "state/install/live-progress.png"
                )
                stale_diagnostic.parent.mkdir(parents=True)
                stale_diagnostic.write_bytes(b"stale-frame")
                MODULE.install(install_args, [])
                self.assertFalse(stale_diagnostic.exists())
                verify_args = self.arguments(root, "verify-installed-boot")
                MODULE.verify_installed_boot(verify_args, [])
                ssh_args = self.arguments(root, "ssh")
                MODULE.ssh_installed(ssh_args, ["uname", "-a"])

            self.assertEqual(calls[0][0], "install")
            self.assertEqual(calls[0][calls[0].index("--kind") + 1], "iso")
            self.assertEqual(
                calls[0][calls[0].index("--expect") + 1],
                MODULE.INSTALL_MARKER,
            )
            self.assertEqual(
                calls[0][calls[0].index("--graphics") + 1], "vnc"
            )
            self.assertEqual(
                calls[0][calls[0].index("--video") + 1], "virtio"
            )
            self.assertEqual(
                calls[0][calls[0].index("--acceleration") + 1], "tcg"
            )
            self.assertEqual(calls[1][0], "boot")
            self.assertEqual(calls[1][calls[1].index("--kind") + 1], "qcow2")
            self.assertTrue(
                calls[1][calls[1].index("--source-image") + 1].endswith(
                    "reproos-installed.qcow2"
                )
            )
            self.assertEqual(
                calls[1][calls[1].index("--expect") + 1],
                MODULE.INSTALLED_HEALTH_MARKER,
            )
            self.assertEqual(
                calls[1][calls[1].index("--graphics") + 1], "vnc"
            )
            self.assertEqual(
                calls[1][calls[1].index("--video") + 1], "virtio"
            )
            self.assertEqual(
                calls[1][calls[1].index("--acceleration") + 1], "tcg"
            )
            self.assertEqual(calls[1][calls[1].index("--cpus") + 1], "3")
            self.assertEqual(
                calls[1][calls[1].index("--memory-mb") + 1], "3072"
            )
            self.assertEqual(
                calls[1][calls[1].index("--ssh-ready-timeout-sec") + 1],
                "12",
            )
            self.assertNotIn("reproos-unattended.iso", calls[1])
            self.assertTrue(
                calls[1][calls[1].index("--secondary-iso") + 1].endswith(
                    "reproos-enrollment.iso"
                )
            )
            self.assertEqual(
                calls[1][calls[1].index("--ssh-forward-port") + 1],
                "auto",
            )
            self.assertEqual(
                calls[1][calls[1].index("--ssh-user") + 1], "repro"
            )
            self.assertTrue(
                calls[1][calls[1].index("--ssh-private-key") + 1].endswith(
                    "id_ed25519"
                )
            )
            self.assertNotIn("--ssh-password-env", calls[1])
            self.assertTrue(
                calls[1][calls[1].index("--ssh-known-hosts") + 1].endswith(
                    "ssh_known_hosts"
                )
            )
            self.assertEqual(
                calls[1][calls[1].index("--ssh-host-key-alias") + 1],
                "reproos-" + "a" * 32,
            )
            command = calls[1][calls[1].index("--") + 1:]
            self.assertEqual(command[:2], ["/bin/sh", "-c"])
            self.assertIn("/var/lib/reproos/health-status", command[2])
            self.assertIn("REPROOS_HEALTH:PASS", command[2])
            self.assertIn("enrollment.complete", command[2])
            self.assertIn("identity.json", command[2])
            ssh_command = calls[2][calls[2].index("--") + 1:]
            self.assertEqual(ssh_command, ["uname", "-a"])
            self.assertNotIn("reproos-unattended.iso", calls[2])

            stage = (
                ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh"
            ).read_text()
            self.assertIn(
                "ConditionPathExists=/var/lib/reproos/installation-receipt.json",
                stage,
            )
            self.assertIn('test -s "$receipt"', stage)
            self.assertNotIn(
                '> "$STAGE_DIR/var/lib/reproos/installation-receipt.json"',
                stage,
            )
            self.assertIn(
                "recipes/reproos-image/scripts/reproos-health-check",
                stage,
            )
            self.assertIn(
                "ConditionPathExists=/var/lib/reproos/installation-receipt.json",
                stage,
            )

            manifest = json.loads(
                (root / "state/install-manifest.json").read_text()
            )
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["disk_format"], "qcow2")
            self.assertEqual(len(manifest["installed_disk_sha256"]), 64)
            self.assertEqual(
                manifest["embedded_machine_profile"],
                "auto-config-minimal.toml",
            )
            self.assertEqual(manifest["expected_hostname"], "reproos-smoke")
            self.assertEqual(manifest["ssh_user"], "repro")
            self.assertEqual(manifest["enrollment_machine_id"], "a" * 32)
            self.assertEqual(
                manifest["ssh_host_key_alias"], "reproos-" + "a" * 32
            )

    def test_enrollment_media_contains_only_public_instance_material(self):
        with tempfile.TemporaryDirectory(prefix="reproos-enrollment-") as raw:
            state = Path(raw) / "state"
            args = self.arguments(Path(raw), "install")
            args.replace = True
            known_hosts = MODULE.enrollment_paths(state)["known_hosts"]
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            known_hosts.write_text("stale host identity\n")

            def fake_checked(label: str, command: list[str]):
                if label == "ssh-keygen":
                    private_key = Path(command[command.index("-f") + 1])
                    private_key.write_text("private-key")
                    private_key.with_suffix(".pub").write_text(
                        "ssh-ed25519 AAAATEST reproos-vm-acceptance\n"
                    )
                elif label == "xorriso":
                    Path(command[command.index("-o") + 1]).write_bytes(b"iso")

            with mock.patch.object(
                MODULE, "run_checked", side_effect=fake_checked
            ):
                paths = MODULE.prepare_enrollment(args, state)

            self.assertTrue(paths["private_key"].is_file())
            self.assertTrue(paths["iso"].is_file())
            self.assertFalse(paths["known_hosts"].exists())
            self.assertEqual(
                (paths["media"] / "authorized_keys").read_text(),
                paths["public_key"].read_text(),
            )
            machine_id = (paths["media"] / "machine-id").read_text().strip()
            self.assertRegex(machine_id, r"^[0-9a-f]{32}$")
            self.assertNotIn("private-key", (
                paths["media"] / "authorized_keys"
            ).read_text())

    def test_stale_known_hosts_requires_explicit_replacement(self):
        with tempfile.TemporaryDirectory(prefix="reproos-enrollment-") as raw:
            state = Path(raw) / "state"
            args = self.arguments(Path(raw), "install")
            known_hosts = MODULE.enrollment_paths(state)["known_hosts"]
            known_hosts.parent.mkdir(parents=True, exist_ok=True)
            known_hosts.write_text("stale host identity\n")

            with self.assertRaisesRegex(
                MODULE.VmWorkflowError,
                "incomplete enrollment state; pass --replace",
            ):
                MODULE.prepare_enrollment(args, state)

            self.assertEqual(known_hosts.read_text(), "stale host identity\n")

    def test_installer_writes_durable_configuration_after_root_mirror(self):
        source = (
            ROOT / "apps/reproos-installer/src/installer_state.cpp"
        ).read_text()
        mirror = source.index("if (!runReproSystemApply(target))")
        durable = source.index(
            'writeConfigurationArtifacts(target + "/etc/repro"', mirror
        )
        receipt = source.index("installation-receipt.json", durable)
        unmount = source.index("if (!runReproDiskUnmount(target))", receipt)
        self.assertLess(mirror, durable)
        self.assertLess(durable, receipt)
        self.assertLess(receipt, unmount)

    def test_installer_uses_the_installed_root_initramfs(self):
        installer = (
            ROOT / "apps/reproos-installer/src/installer_state.cpp"
        ).read_text()
        iso_builder = (
            ROOT / "recipes/reproos-iso/scripts/build-iso.sh"
        ).read_text()
        iso_recipe = (
            ROOT / "recipes/reproos-iso/package.nim"
        ).read_text()
        self.assertIn(
            'QStringLiteral("/run/live/medium/reproos/disk-initrd.img")',
            installer,
        )
        self.assertIn('"--initrd", diskInitrd', installer)
        self.assertIn("REPRO_INITRAMFS_INIT=init-disk", iso_builder)
        self.assertIn(
            'cp "$DISK_INIT_OUT" "$WORK/reproos/disk-initrd.img"',
            iso_builder,
        )
        self.assertIn("reproos-unattended-disk-initramfs.img", iso_recipe)

    def test_first_boot_converts_live_session_to_installed_session(self):
        enrollment = (
            ROOT / "recipes/reproos-image/scripts/reproos-first-boot-enroll"
        ).read_text()
        stage = (
            ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh"
        ).read_text()
        self.assertIn('chown -R "$user:$user" "$home"', enrollment)
        self.assertIn("User=$user", enrollment)
        self.assertIn("Session=sway", enrollment)
        self.assertIn("auto-config.toml.disabled-after-install", enrollment)
        self.assertIn(
            "Before=sddm.service sshd.service reproos-health-check.service",
            stage,
        )
        enrollment_unit = stage[stage.index(
            'cat > "$STAGE_DIR/etc/systemd/system/'
            'reproos-first-boot-enroll.service"'
        ):]
        self.assertIn(
            "ConditionPathExists=/var/lib/reproos/installation-receipt.json",
            enrollment_unit.split("\nEOF\n", 1)[0],
        )

    def test_installer_autorun_matches_an_exact_kernel_token(self):
        stage = (
            ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh"
        ).read_text()
        self.assertIn(
            "repro.installer.autorun=1) autorun=true", stage
        )
        self.assertNotIn(
            "grep -qE '(^| )repro\\.installer\\.autorun=1( |$)'", stage
        )
        self.assertIn(
            "repro.installer.diag=1) diagnostics=true", stage
        )
        self.assertIn(
            'if [ "$diagnostics" = true ]; then\n'
            "  export REPRO_INSTALLER_DIAG=1\n"
            "else\n"
            "  unset REPRO_INSTALLER_DIAG",
            stage,
        )
        iso_builder = (
            ROOT / "recipes/reproos-iso/scripts/build-iso.sh"
        ).read_text()
        self.assertIn(
            'REPRO_INSTALLER_DIAG_PARAM=" repro.installer.diag=1"',
            iso_builder,
        )
        self.assertIn(
            "${REPRO_INSTALLER_AUTORUN_PARAM}${REPRO_INSTALLER_DIAG_PARAM}",
            iso_builder,
        )

    def test_unattended_e2e_includes_installed_desktop_guiassert(self):
        e2e = (
            ROOT / "tests/e2e-unattended-vm-installs.sh"
        ).read_text()
        self.assertIn('--screenshot "$screenshot"', e2e)
        self.assertIn("test-installed-desktop-frame.sh", e2e)
        self.assertIn("GuiAssert: PASS", e2e)

    def test_host_key_negative_edge_requires_mismatch_diagnostics(self):
        negative_edge = (
            ROOT / "tests/test-vm-ssh-host-key-mismatch.sh"
        ).read_text()
        self.assertIn("REMOTE HOST IDENTIFICATION HAS CHANGED", negative_edge)
        self.assertIn("unexpected VM failure", negative_edge)


if __name__ == "__main__":
    unittest.main()
