#!/usr/bin/env python3
"""Focused regressions for reusable machine profiles and enrollment.

No mocks: every enrollment case runs the shipped
``reproos-first-boot-enroll`` script against a real root-prefixed directory
tree, and the transient machine-id case uses a real read-only bind mount in
an unprivileged user + mount namespace rather than a simulated one.
"""

from __future__ import annotations

import copy
import ctypes
import ctypes.util
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
ENROLL_SCRIPT = ROOT / "recipes/reproos-image/scripts/reproos-first-boot-enroll"
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


def prepare_enrollment_root(base: Path) -> tuple[Path, Path, dict]:
    """Lay out a root-prefixed installed tree plus an enrollment directory.

    Returns ``(root, enrollment, env)``: ``env`` runs the real
    ``reproos-first-boot-enroll`` against ``root`` (``REPROOS_ROOT``) in test
    mode, so the script touches nothing outside ``base``.
    """
    root = base / "root"
    enrollment = base / "enrollment"
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
    return root, enrollment, env


# mount(2) flags (<linux/mount.h>), used to reproduce systemd's transient
# read-only /etc/machine-id bind mount without the mount(8) binary.
MS_RDONLY = 0x1
MS_REMOUNT = 0x20
MS_BIND = 0x1000
MS_REC = 0x4000
MS_PRIVATE = 0x40000


def enter_user_mount_namespace() -> None:
    """Become root of a fresh user + mount namespace (unshare(2)).

    Runs in a ``subprocess`` ``preexec_fn``, i.e. in the forked child before
    exec, so the test process itself never changes namespaces. It is done in
    Python rather than with util-linux ``unshare``/``mount`` because a build
    action's PATH carries only declared tool identities and ``unshare`` has
    none; ``python3`` is already the action's interpreter.
    """
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    # user_namespaces(7): an unprivileged process must deny setgroups before
    # it may write a gid_map.
    with open("/proc/self/setgroups", "w") as handle:
        handle.write("deny")
    with open("/proc/self/uid_map", "w") as handle:
        handle.write(f"0 {uid} 1")
    with open("/proc/self/gid_map", "w") as handle:
        handle.write(f"0 {gid} 1")
    # Keep the mounts below private to this namespace.
    libc_mount(None, "/", None, MS_REC | MS_PRIVATE)


def libc_mount(
    source: str | None, target: str, fstype: str | None, flags: int
) -> None:
    """Call mount(2) through libc, raising OSError on failure."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.mount.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
        ctypes.c_ulong, ctypes.c_void_p,
    ]
    encode = lambda value: None if value is None else os.fsencode(value)
    if libc.mount(encode(source), encode(target), encode(fstype), flags, None):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def transient_machine_id_namespace(transient: Path, target: Path):
    """Return a ``preexec_fn`` that mounts ``transient`` read-only on ``target``.

    This is exactly the shape systemd gives a first boot whose
    ``/etc/machine-id`` is empty: a read-only bind mount of a transient id
    over the persistent file.
    """
    def setup() -> None:
        enter_user_mount_namespace()
        libc_mount(str(transient), str(target), None, MS_BIND)
        libc_mount(
            None, str(target), None, MS_REMOUNT | MS_BIND | MS_RDONLY
        )
    return setup


def unit_text(path: Path, start: str, end: str) -> str:
    """Return the heredoc body that follows ``start`` in ``path``."""
    text = path.read_text()
    body = text[text.index(start) + len(start):]
    return body[: body.index(end)]


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
            root, _, env = prepare_enrollment_root(Path(raw))
            subprocess.run(
                ["bash", bash_path(ENROLL_SCRIPT)],
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

    def test_enrollment_commits_machine_id_under_transient_mount(self) -> None:
        """Enrollment succeeds while systemd's transient machine-id is mounted.

        On first boot of a root whose ``/etc/machine-id`` is empty, systemd
        bind-mounts a transient, read-only id over the file until
        ``systemd-machine-id-commit.service`` commits it
        (https://www.freedesktop.org/software/systemd/man/latest/machine-id.html).
        This test reproduces exactly that mount with no mocks: the real
        enrollment script runs inside an unprivileged user + mount namespace
        in which ``$root/etc/machine-id`` is a read-only bind mount of a file
        holding a different (transient) id, set up with unshare(2) and
        mount(2) in the child before exec. A positive control first proves
        the mount really refuses writes, so a pass cannot come from a mount
        that silently failed to apply.
        """
        if not sys.platform.startswith("linux"):
            self.skipTest(
                "requires Linux mount and user namespaces to reproduce "
                "systemd's transient /etc/machine-id bind mount"
            )
        try:
            subprocess.run(
                [sys.executable, "-c", "pass"],
                preexec_fn=enter_user_mount_namespace,
                check=True,
            )
        except subprocess.SubprocessError as error:
            self.skipTest(
                "the kernel refuses unprivileged user + mount namespaces "
                f"(unshare(CLONE_NEWUSER | CLONE_NEWNS) failed: {error})"
            )

        transient_id = "0123456789abcdef0123456789abcdef"
        enrolled_id = "83fddb41b07245e18e447ef56f4463a7"
        with tempfile.TemporaryDirectory(prefix="reproos-enrollment-") as raw:
            root, _, env = prepare_enrollment_root(Path(raw))
            # First boot: the persistent file exists and is empty.
            (root / "etc/machine-id").write_text("")
            transient = Path(raw) / "transient-machine-id"
            transient.write_text(transient_id + "\n")
            namespace_script = r"""
set -eu
target="$1/etc/machine-id"
if (printf 'x\n' > "$target") 2>/dev/null; then
  echo "CONTROL:transient mount is writable" >&2
  exit 90
fi
status=0
bash "$2" || status=$?
echo "ENROLL_STATUS=$status"
if awk -v p="$target" '$5 == p { found=1 } END { exit(found ? 0 : 1) }' \
     /proc/self/mountinfo; then
  echo "MOUNT_STILL_PRESENT"
else
  echo "MOUNT_DETACHED"
fi
exit "$status"
"""
            result = subprocess.run(
                [
                    "bash", "-c", namespace_script, "namespace",
                    str(root), str(ENROLL_SCRIPT),
                ],
                preexec_fn=transient_machine_id_namespace(
                    transient, root / "etc/machine-id"
                ),
                env=env,
                text=True,
                capture_output=True,
            )
            detail = f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            self.assertNotIn("CONTROL:", result.stderr, detail)
            self.assertEqual(result.returncode, 0, detail)
            self.assertIn("ENROLL_STATUS=0", result.stdout, detail)
            self.assertIn("MOUNT_DETACHED", result.stdout, detail)
            self.assertIn(
                f"REPROOS_ENROLLMENT:PASS:machine_id={enrolled_id}",
                result.stdout,
                detail,
            )
            # Outside the namespace the persistent file underneath holds the
            # enrolled id, and the transient source is untouched.
            self.assertEqual(
                (root / "etc/machine-id").read_text(), enrolled_id + "\n"
            )
            self.assertEqual(transient.read_text(), transient_id + "\n")
            identity = json.loads(
                (root / "var/lib/reproos/identity.json").read_text()
            )
            self.assertEqual(identity["machine_id"], enrolled_id)
            self.assertTrue(
                (root / "var/lib/reproos/enrollment.complete").exists()
            )

    def test_enrollment_units_order_after_machine_id_commit(self) -> None:
        """Every copy of the enrollment unit waits for the machine-id commit."""
        units = {
            "configure-installed-root.sh": unit_text(
                ROOT / "recipes/reproos-image/scripts/configure-installed-root.sh",
                "<<'ENROLL_UNIT_EOF'\n",
                "\nENROLL_UNIT_EOF\n",
            ),
            "stage-de-rootfs.sh": unit_text(
                ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
                'cat > "$STAGE_DIR/etc/systemd/system/'
                "reproos-first-boot-enroll.service\" <<'EOF'\n",
                "\nEOF\n",
            ),
            # The ReproOS Anywhere fixture payload carries the same unit text
            # verbatim, indented inside a Nix string.
            "tests/anywhere/fixture/payload.nix": unit_text(
                ROOT / "tests/anywhere/fixture/payload.nix",
                "cat > $R/etc/systemd/system/"
                "reproos-first-boot-enroll.service <<'EOF'\n",
                "\n  EOF\n",
            ),
        }
        for name, unit in units.items():
            with self.subTest(unit=name):
                self.assertIn(
                    "ExecStart=/usr/local/sbin/reproos-first-boot-enroll", unit
                )
                after = [
                    token
                    for line in map(str.strip, unit.splitlines())
                    if line.startswith("After=")
                    for token in line[len("After="):].split()
                ]
                self.assertIn("systemd-machine-id-commit.service", after)
                self.assertIn("local-fs.target", after)

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
