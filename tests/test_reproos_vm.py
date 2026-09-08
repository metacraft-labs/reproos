#!/usr/bin/env python3
"""Regression tests for the vm-harness ReproOS install workflow."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
                "REPROOS_VM_HARNESS_BIN": "stub-vm-harness",
            },
            clear=False,
        ):
            args = MODULE.parser().parse_args(["install"])

        self.assertEqual(args.vm_harness, "stub-vm-harness")

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
                    mock.patch.object(MODULE, "read_vmh_status", side_effect=
                        lambda *_: {"state": "running" if any(
                            call[0] == "boot" for call in calls) else "absent"}), \
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
            self.assertIn("--keep", calls[1])
            self.assertEqual(calls[1][calls[1].index("--name") + 1],
                             "reproos-" + "a" * 32)
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
            self.assertIn("root=/var/lib/reproos", command[2])
            self.assertIn('health="$root/health-status"', command[2])
            self.assertIn("REPROOS_HEALTH:PASS", command[2])
            self.assertIn("enrollment.complete", command[2])
            self.assertIn("identity.json", command[2])
            self.assertEqual(calls[2][:2], ["instance", "exec"])
            self.assertEqual(calls[3][:2], ["instance", "exec"])
            ssh_command = calls[3][calls[3].index("--") + 1:]
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

    @unittest.skipUnless(os.name == "posix", "guest probe requires a POSIX shell")
    def test_installed_health_probe_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="reproos health '") as raw:
            root = Path(raw)
            files = {
                "health-status": "REPROOS_HEALTH:PASS\n",
                "enrollment.complete": "",
                "identity.json": "{}\n",
                "installation-receipt.json": "{}\n",
            }
            for name, contents in files.items():
                (root / name).write_text(contents)

            def run_probe(hostname="reproos-test"):
                command = MODULE.installed_health_probe(hostname, str(root))
                # Keep the real test/grep builtins and avoid waiting on failures.
                command[2] = ("hostname() { printf '%s\\n' reproos-test; }; "
                              "sleep() { :; }; " + command[2])
                return subprocess.run(command, text=True, capture_output=True)

            result = run_probe()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("REPROOS_SSH_ACCEPTANCE:PASS", result.stdout)
            for failure in ["hostname", *files]:
                with self.subTest(failure=failure):
                    if failure == "hostname":
                        result = run_probe("different-host")
                    else:
                        (root / failure).unlink()
                        result = run_probe()
                        (root / failure).write_text(files[failure])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("REPROOS_SSH_ACCEPTANCE:PASS", result.stdout)

    def test_installed_configuration_uses_manifest_disk_location(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            root = Path(raw)
            args = self.arguments(root, "verify-installed-boot")
            state = args.state_dir
            state.mkdir()
            target = root / "external" / "installed.qcow2"
            target.parent.mkdir()
            target.write_bytes(b"installed")
            manifest = {
                "schema_version": 1, "installed_disk": str(target),
                "expected_hostname": "reproos-smoke", "ssh_user": "repro",
                "ssh_host_key_alias": "reproos-instance",
            }
            (state / "install-manifest.json").write_text(json.dumps(manifest))
            enrollment = MODULE.enrollment_paths(state)
            enrollment["root"].mkdir()
            enrollment["private_key"].write_bytes(b"key")
            enrollment["iso"].write_bytes(b"iso")
            args.target_disk = None
            self.assertEqual(MODULE.installed_configuration(args)[1], target)
            args.target_disk = root / "wrong.qcow2"
            with self.assertRaisesRegex(MODULE.VmWorkflowError, "does not match"):
                MODULE.installed_configuration(args)

            # Older manifests can recover an external disk with an explicit path.
            manifest["installed_disk"] = target.name
            (state / "install-manifest.json").write_text(json.dumps(manifest))
            args.target_disk = target
            self.assertEqual(MODULE.installed_configuration(args)[1], target)

    def test_invalid_install_manifest_reports_workflow_error(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            root = Path(raw)
            args = self.arguments(root, "verify-installed-boot")
            args.state_dir.mkdir()
            for contents in ("{", "[]", '{"schema_version": 99}'):
                with self.subTest(contents=contents):
                    (args.state_dir / "install-manifest.json").write_text(contents)
                    with self.assertRaises(MODULE.VmWorkflowError):
                        MODULE.installed_configuration(args)

    def test_running_instance_is_reused_for_interactive_ssh_and_literal_exec(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            args = self.arguments(Path(raw), "ssh")
            prefix = ["instance", "ssh", "same-instance", "--state-dir", raw]
            with mock.patch.object(MODULE, "ensure_installed") as ensure, \
                    mock.patch.object(MODULE, "instance_command",
                                      return_value=prefix) as instance, \
                    mock.patch.object(MODULE, "run_vmh") as run:
                MODULE.ssh_installed(args, [])
                instance.assert_called_once_with(args, "ssh")
                run.assert_called_once_with(args.vm_harness, prefix)
                ensure.assert_called_once_with(args)
                run.reset_mock()
                instance.reset_mock()
                command = ["printf", "%s\\n", "space ' quote", "$(touch sentinel)", ""]
                MODULE.ssh_installed(args, command)
                instance.assert_called_once_with(args, "exec")
                run.assert_called_once_with(args.vm_harness, [*prefix, "--", *command])

    def test_stopped_instance_starts_without_recreating_disk_or_enrollment(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            args = self.arguments(Path(raw), "installed")
            for state in ["stopped", "destroyed"]:
                with self.subTest(state=state), \
                        mock.patch.object(MODULE, "installed_configuration",
                            return_value=({"expected_hostname": "test"}, None, {})), \
                        mock.patch.object(MODULE, "instance_status",
                            side_effect=[{"state": state}, {"state": "running"}]), \
                        mock.patch.object(MODULE, "instance_command",
                            return_value=["instance", "start", "same-instance"]), \
                        mock.patch.object(MODULE, "boot_installed") as boot, \
                        mock.patch.object(MODULE, "prepare_enrollment") as enroll, \
                        mock.patch.object(MODULE, "run_vmh") as run:
                    self.assertEqual(MODULE.ensure_installed(args)["state"], "running")
                    boot.assert_not_called()
                    enroll.assert_not_called()
                    run.assert_called_once_with(args.vm_harness,
                        ["instance", "start", "same-instance"])

    def test_inspection_and_teardown_never_materialize_a_vm(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            for operation in ["status", "logs", "stop", "destroy"]:
                with self.subTest(operation=operation):
                    args = self.arguments(Path(raw), operation)
                    prefix = ["instance", operation, "same-instance"]
                    with mock.patch.object(MODULE, "ensure_installed") as ensure, \
                            mock.patch.object(MODULE, "instance_status",
                                return_value={"state": "stopped"}), \
                            mock.patch.object(MODULE, "instance_command",
                                return_value=prefix), \
                            mock.patch.object(MODULE, "run_vmh") as run, \
                            mock.patch("builtins.print"):
                        MODULE.inspect_installed(args, [])
                        ensure.assert_not_called()
                        if operation != "status":
                            run.assert_called_once_with(args.vm_harness, prefix)

    def test_unknown_or_failed_observation_never_triggers_boot(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            args = self.arguments(Path(raw), "installed")
            with mock.patch.object(MODULE, "installed_configuration",
                    return_value=({}, None, {})), \
                    mock.patch.object(MODULE, "instance_status",
                        return_value={"state": "failed"}), \
                    mock.patch.object(MODULE, "boot_installed") as boot:
                with self.assertRaisesRegex(MODULE.VmWorkflowError, "VM is failed"):
                    MODULE.ensure_installed(args)
                boot.assert_not_called()

    def test_status_protocol_errors_are_not_treated_as_absence(self):
        cases = [(1, "", "backend unavailable"), (0, "not-json", ""),
                 (0, "{}", ""), (0, '{"state":"unknown"}', "")]
        for code, stdout, stderr in cases:
            with self.subTest(stdout=stdout, code=code), \
                    mock.patch.object(MODULE.subprocess, "run", return_value=
                        subprocess.CompletedProcess([], code, stdout, stderr)):
                with self.assertRaises(MODULE.VmWorkflowError):
                    MODULE.read_vmh_status("vm-harness", ["instance", "status", "test"])

    def test_guest_command_exit_status_is_preserved(self):
        with mock.patch.object(MODULE.subprocess, "run", return_value=
                subprocess.CompletedProcess([], 23)):
            with self.assertRaises(MODULE.VmWorkflowError) as raised:
                MODULE.run_vmh("vm-harness", ["instance", "exec", "test", "--", "false"])
            self.assertEqual(raised.exception.exit_code, 23)

    def test_install_replacement_does_not_delete_disk_when_runtime_purge_fails(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            args = self.arguments(Path(raw), "install")
            args.replace = True
            args.state_dir.mkdir()
            args.target_disk.write_bytes(b"persistent guest data")
            manifest = args.state_dir / "install-manifest.json"
            manifest.write_text("retained manifest")
            status = {"state": "running", "receipt_exists": True,
                      "instance_id": "00000000-0000-4000-8000-000000000001"}
            with mock.patch.object(MODULE, "instance_status", return_value=status), \
                    mock.patch.object(MODULE, "instance_command",
                        return_value=["instance", "destroy", "same-instance"]), \
                    mock.patch.object(MODULE, "run_vmh",
                        side_effect=MODULE.VmWorkflowError("instance operation is busy")) as run, \
                    mock.patch.object(MODULE, "prepare_enrollment") as enrollment:
                with self.assertRaisesRegex(MODULE.VmWorkflowError, "busy"):
                    MODULE.install(args, [])
                run.assert_called_once_with(args.vm_harness,
                    ["instance", "destroy", "same-instance", "--instance-id",
                     status["instance_id"], "--purge"])
                enrollment.assert_not_called()
            self.assertEqual(args.target_disk.read_bytes(), b"persistent guest data")
            self.assertEqual(manifest.read_text(), "retained manifest")

    def test_workflow_lock_rejects_concurrent_mutation_and_releases_on_error(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            state = Path(raw)
            with self.assertRaisesRegex(RuntimeError, "failed operation"):
                with MODULE.workflow_lock(state):
                    with self.assertRaisesRegex(MODULE.VmWorkflowError, "busy"):
                        with MODULE.workflow_lock(state, timeout=0):
                            self.fail("concurrent operation acquired the instance")
                    raise RuntimeError("failed operation")
            with MODULE.workflow_lock(state, timeout=0):
                pass

    def test_removed_runtime_with_retained_receipt_reuses_the_active_disk(self):
        with tempfile.TemporaryDirectory(prefix="reproos-vm-") as raw:
            args = self.arguments(Path(raw), "installed")
            with mock.patch.object(MODULE, "installed_configuration",
                    return_value=({}, None, {})), \
                    mock.patch.object(MODULE, "instance_status", side_effect=[
                        {"state": "absent", "receipt_exists": True},
                        {"state": "running"}]), \
                    mock.patch.object(MODULE, "instance_command",
                        return_value=["instance", "start", "same-instance"]), \
                    mock.patch.object(MODULE, "boot_installed") as boot, \
                    mock.patch.object(MODULE, "run_vmh") as run:
                MODULE.ensure_installed(args)
                boot.assert_not_called()
                run.assert_called_once()

    def test_forwarded_guest_options_are_not_consumed_by_host_parser(self):
        with mock.patch.object(MODULE, "ssh_installed") as ssh:
            result = MODULE.main(["exec", "--", "printf", "--state-dir", "guest"])
        self.assertEqual(result, 0)
        self.assertEqual(ssh.call_args.args[1], ["printf", "--state-dir", "guest"])

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
