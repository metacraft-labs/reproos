#!/usr/bin/env python3
"""Small, real archive fixtures; no guest, rootfs build, or root access needed."""

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "image_metadata", ROOT / "tools/reproos_image_metadata.py")
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=60, **kwargs).stdout


class ImageMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux":
            raise unittest.SkipTest(
                "test-image-metadata requires Linux: POSIX inode semantics and /proc mountinfo")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="reproos-image-metadata-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / "rootfs"
        for directory in ("etc", "usr/bin", "opt/store/sudo/bin", "home/live",
                          "home/alice", "var/empty", "tmp"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
            (self.root / directory).chmod(0o755)
        (self.root / "etc/passwd").write_text(
            "root:x:0:0:root:/root:/bin/sh\n"
            "live:x:1000:1002:Live:/home/live:/bin/sh\n"
            "alice:x:1001:1003:Alice:/home/alice:/bin/sh\n")
        (self.root / "home/live").chmod(0o700)
        (self.root / "home/alice/note with spaces").write_text("user data\n")
        (self.root / "home/alice/note with spaces").chmod(0o644)
        (self.root / "tmp").chmod(0o1777)
        (self.root / "etc/sudo.conf").write_text("# sudo configuration\n")
        (self.root / "etc/sudoers").write_text("root ALL=(ALL:ALL) ALL\n")
        self.sudo = self.root / "opt/store/sudo/bin/sudo"
        self.sudo.write_text("fixture executable\n")
        self.sudo.chmod(0o755)
        (self.root / "usr/bin/sudo").symlink_to("/opt/store/sudo/bin/sudo")
        (self.root / "usr/bin/sudoedit").symlink_to("sudo")
        self.alias = self.root / "opt/store/sudo/bin/alias"
        os.link(self.sudo, self.alias)
        self.cache = self.work / "cached-sudo"
        os.link(self.sudo, self.cache)
        (self.root / "usr/bin/unapproved").write_text("not privileged\n")
        (self.root / "usr/bin/unapproved").chmod(0o6755)
        (self.root / 'home/alice/quote"and\\slash').write_text("quoted name\n")
        self.outside = self.work / "outside"
        self.outside.mkdir()
        (self.outside / "sentinel").write_text("untouched\n")
        (self.root / "home/alice/external").symlink_to(self.outside)

    def snapshot(self):
        result = []
        for path in metadata.Policy(self.root).entries():
            info = path.lstat()
            content = (path.read_bytes() if stat.S_ISREG(info.st_mode) else
                       os.readlink(path) if path.is_symlink() else None)
            result.append((path, info.st_uid, info.st_gid, info.st_mode,
                           info.st_ino, content))
        return result

    def test_real_squashfs_metadata_and_source_unchanged(self):
        for tool in ("mksquashfs", "unsquashfs"):
            self.assertIsNotNone(shutil.which(tool), f"declared tool missing: {tool}")
        self.root.chmod(0o700)
        before = self.snapshot()
        policy = metadata.Policy(self.root)
        pseudo, image = self.work / "rootfs.pseudo", self.work / "rootfs.squashfs"
        policy.squashfs(pseudo)
        run("mksquashfs", str(self.root), str(image), "-all-root", "-root-mode", "0755", "-pseudo-override",
            "-pf", str(pseudo), "-no-hardlinks", "-no-xattrs", "-noappend",
            "-no-progress", "-quiet", "-processors", "1",
            env={**os.environ, "SOURCE_DATE_EPOCH": "1735689600"})
        listing = run("unsquashfs", "-lln", str(image))
        self.assertRegex(listing, re.compile(r"^drwxr-xr-x\s+0/0\s+.* squashfs-root$", re.M))
        expected = {
            "etc": ("drwxr-xr-x", "0/0"),
            "usr/bin": ("drwxr-xr-x", "0/0"),
            "etc/sudo.conf": ("-rw-r--r--", "0/0"),
            "etc/sudoers": ("-r--r-----", "0/0"),
            "opt/store/sudo/bin/sudo": ("-rwsr-xr-x", "0/0"),
            "opt/store/sudo/bin/alias": ("-rwxr-xr-x", "0/0"),
            "usr/bin/unapproved": ("-rwxr-xr-x", "0/0"),
            "home/live": ("drwx------", "1000/1002"),
            "home/alice/note with spaces": ("-rw-r--r--", "1001/1003"),
            "tmp": ("drwxrwxrwt", "0/0"),
            "var/empty": ("drwxr-xr-x", "0/0"),
        }
        for name, (mode, owner) in expected.items():
            with self.subTest(path=name):
                self.assertRegex(listing, re.compile(
                    r"^" + re.escape(mode) + r"\s+" + re.escape(owner) +
                    r"\s+.* squashfs-root/" + re.escape(name) + r"$", re.M))
        self.assertIn("squashfs-root/usr/bin/sudo -> /opt/store/sudo/bin/sudo", listing)
        self.assertEqual(before, self.snapshot())

    def test_real_tar_metadata_determinism_and_source_unchanged(self):
        before = self.snapshot()
        policy = metadata.Policy(self.root)
        images = [self.work / "one.tar", self.work / "two.tar"]
        policy.archive(images[0], None, 1735689600)
        original_iterdir = Path.iterdir
        with patch.object(Path, "iterdir", lambda path: iter(reversed(list(original_iterdir(path))))):
            policy.archive(images[1], None, 1735689600)
        self.assertEqual(hashlib.sha256(images[0].read_bytes()).digest(),
                         hashlib.sha256(images[1].read_bytes()).digest())
        with tarfile.open(images[0]) as archive:
            for path in policy.entries():
                name = "rootfs" if path == self.root else "rootfs/" + path.relative_to(self.root).as_posix()
                entry = archive.getmember(name)
                self.assertEqual((entry.uid, entry.gid, entry.mode), policy.metadata(path))
                self.assertEqual(entry.mtime, 1735689600)
            self.assertTrue(archive.getmember("rootfs/opt/store/sudo/bin/alias").isreg())
            self.assertEqual(archive.getmember("rootfs/usr/bin/sudo").linkname,
                             "/opt/store/sudo/bin/sudo")
        self.assertEqual(before, self.snapshot())

    def test_apply_detaches_cache_and_does_not_follow_symlinks(self):
        cache_before = self.cache.stat()
        calls = []
        # Rootless CI checks the actual chmod/replace path; ownership calls are
        # observed explicitly. Archive tests above exercise real numeric owners.
        with patch.object(os, "geteuid", return_value=0), patch.object(
                os, "chown", side_effect=lambda *a, **kw: calls.append((a, kw))):
            metadata.Policy(self.root).apply()
        self.assertEqual(stat.S_IMODE(self.sudo.stat().st_mode), 0o4755)
        self.assertEqual(stat.S_IMODE(self.alias.stat().st_mode), 0o755)
        self.assertEqual(self.cache.stat().st_mode, cache_before.st_mode)
        self.assertEqual(self.cache.stat().st_uid, cache_before.st_uid)
        self.assertNotEqual(self.sudo.stat().st_ino, cache_before.st_ino)
        self.assertFalse(any(path.is_relative_to(self.outside) for (path, *_), _ in calls))
        self.assertTrue(all(kw == {"follow_symlinks": False} for _, kw in calls))
        self.assertIn(((self.root / "home/live", 1000, 1002), {"follow_symlinks": False}), calls)

    def test_refuse_sudo_escape_loop_dangling_or_user_home(self):
        link = self.root / "usr/bin/sudo"
        for target in ("../../../../outside", "/usr/bin/sudoedit", "/missing",
                       "/home/alice/note with spaces"):
            with self.subTest(target=target):
                link.unlink()
                link.symlink_to(target)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    metadata.Policy(self.root)

    def test_guest_relative_directory_symlinks(self):
        (self.root / "bin").symlink_to("usr/bin")
        self.assertEqual(metadata.guest_path(self.root, "/bin/sudoedit"), self.sudo)

    def test_configuration_symlinks_resolve_in_guest_and_secure_parents(self):
        config = self.root / "etc/sudo.conf"
        target = self.root / "opt/store/sudo/sudo.conf"
        config.rename(target)
        config.symlink_to("/opt/store/sudo/sudo.conf")
        (self.root / "usr/bin").chmod(0o777)
        policy = metadata.Policy(self.root)
        self.assertEqual(policy.metadata(target), (0, 0, 0o644))
        self.assertEqual(policy.metadata(self.root / "usr/bin"), (0, 0, 0o755))
        config.unlink()
        config.symlink_to(self.outside / "sentinel")
        with self.assertRaises(FileNotFoundError):
            metadata.Policy(self.root)

    def test_refuse_output_inside_source_and_unprivileged_apply(self):
        policy = metadata.Policy(self.root)
        with self.assertRaises(ValueError):
            policy.archive(self.root / "archive.tar", None, 0)
        with self.assertRaises(ValueError):
            policy.squashfs(self.root / "metadata.pseudo")
        with patch.object(os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                policy.apply()

    def test_refuse_mounted_descendant_before_chown(self):
        policy = metadata.Policy(self.root)
        mountinfo = f"1 2 3:4 / {self.root}/tmp/bind rw - ext4 /dev/test rw\n"
        with patch.object(os, "geteuid", return_value=0), patch.object(
                Path, "read_text", return_value=mountinfo), patch.object(os, "chown") as chown:
            with self.assertRaisesRegex(ValueError, "mounted image descendant"):
                policy.apply()
            chown.assert_not_called()

    def test_refuse_device_boundary_before_chown(self):
        policy = metadata.Policy(self.root)
        original = Path.lstat

        def changed_device(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if Path(path) == self.root / "tmp":
                values = list(result)
                values[2] += 1
                return os.stat_result(values)
            return result

        with patch.object(os, "geteuid", return_value=0), patch.object(
                Path, "lstat", new=changed_device), patch.object(os, "chown") as chown:
            with self.assertRaisesRegex(ValueError, "filesystem boundary"):
                policy.apply()
            chown.assert_not_called()

    def test_packaging_and_health_use_policy(self):
        # An INVOCATION with its operation, not a mention. A header comment
        # naming this file is not a carrier of the policy, and every image
        # ReproOS ships has to be one: the ISO's SquashFS, the container
        # tar, the writable installed root, and the integrity-checked ext4
        # root -- which needs both halves, because applying the policy
        # without re-reading it is how an unpoliced image reaches a hash.
        for script, operation in (
                ("recipes/reproos-iso/scripts/build-iso.sh", "squashfs"),
                ("recipes/reproos-container/scripts/build-incus-image.sh", "tar"),
                ("recipes/reproos-image/scripts/build-reproos-image.sh", "apply"),
                ("recipes/reproos-image/scripts/build-verity-root.sh", "ext4-apply"),
                ("recipes/reproos-image/scripts/build-verity-root.sh", "ext4-verify")):
            text = (ROOT / script).read_text()
            # Fold backslash continuations: an invocation is a LOGICAL line.
            logical = re.sub(r"\\\n\s*", " ", text)
            named = [line for line in logical.splitlines()
                     if not line.lstrip().startswith("#")
                     and re.search(r"reproos_image_metadata\.py|\$INODE_POLICY",
                                   line)]
            self.assertTrue(
                any(re.search(r"(^|[\"'\s])" + re.escape(operation) + r"\s",
                              line) for line in named),
                f"{script} never runs the guest inode policy with `{operation}`")
        stage = (ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh").read_text()
        self.assertIn('rm -f "$STAGE_DIR/etc/sudoers"', stage)
        self.assertIn('cp "$SCRIPT_DIR_SELF/../config/sudoers"', stage)
        self.assertIn('cp "$SCRIPT_DIR_SELF/../config/pam-sudo"', stage)
        self.assertIn('"$install_usr/libexec/sudo/sudoers.so"', stage)
        sudoers = (ROOT / "recipes/reproos-iso/config/sudoers").read_text()
        self.assertIn("%sudo ALL=(ALL:ALL) NOPASSWD: ALL", sudoers)
        self.assertIn("%wheel ALL=(ALL:ALL) NOPASSWD: ALL", sudoers)
        pam = (ROOT / "recipes/reproos-iso/config/pam-sudo").read_text()
        self.assertIn("account include common-account", pam)
        self.assertIn("session include common-session-noninteractive", pam)
        health = (ROOT / "recipes/reproos-image/scripts/reproos-health-check").read_text()
        self.assertIn('busybox su -s /bin/sh "$expected_user"', health)
        self.assertIn("sudo -n /usr/bin/id -u", health)
        self.assertIn("sudo:root-setuid", health)
        self.assertIn("-root-mode 0755", (ROOT / "recipes/reproos-iso/scripts/build-iso.sh").read_text())

    def test_health_requires_successful_exit_and_root_stdout(self):
        health = (ROOT / "recipes/reproos-image/scripts/reproos-health-check").read_text()
        snippet = health.split("# Running sudo as root", 1)[1].split("\nexpected_groups=", 1)[0]
        snippet = "# Running sudo as root" + snippet
        fake = self.work / "busybox"
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "declared tool missing: bash")
        snippet = snippet.replace("/usr/bin/busybox", shlex.quote(str(fake)))
        for output, status, expected in (("0", 0, "PASS"), ("0", 7, "FAIL"),
                                         ("1000", 0, "FAIL"), ("", 0, "FAIL")):
            with self.subTest(output=output, status=status):
                fake.write_text(f"#!{bash}\nprintf '%s\\n' {shlex.quote(output)}\nexit {status}\n")
                fake.chmod(0o755)
                result = run(bash, "-c", "expected_user=fixture\nuser_record_found=1\n"
                             "pass() { printf 'PASS\\n'; }\nfail() { printf 'FAIL\\n'; }\n" + snippet)
                self.assertEqual(result.strip(), expected)

    def test_unsupported_hosts_skip_before_fixture_setup(self):
        for platform in ("win32", "darwin"):
            with self.subTest(platform=platform), patch.object(sys, "platform", platform):
                with self.assertRaisesRegex(unittest.SkipTest, "requires Linux"):
                    self.setUpClass()


if __name__ == "__main__":
    unittest.main(verbosity=2)
