#!/usr/bin/env python3
"""Exercise the ISO builder's source-bootloader preflight without an image."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "recipes/reproos-iso/scripts/build-iso.sh"


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux ISO builder")
class SourceBootloaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="source grub ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "catalog"
        self.prefix = self.source / "grub/.repro/output/install/usr"
        self.bin = self.root / "host-bin"
        self.bin.mkdir()
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "declared bash is missing")
        for tool in ("dirname", "readlink"):
            resolved = shutil.which(tool)
            self.assertIsNotNone(resolved, f"declared {tool} is missing")
            (self.bin / tool).symlink_to(resolved)
        self.marker = self.root / "host-tool-used"
        for tool in ("grub-mkrescue", "grub-mkimage"):
            target = self.prefix / "bin" / tool
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o755)
            ambient = self.bin / tool
            ambient.write_text(
                f"#!/bin/sh\nprintf used > '{self.marker}'\nexit 89\n",
                encoding="utf-8",
            )
            ambient.chmod(0o755)
        for platform in ("i386-pc", "x86_64-efi"):
            directory = self.prefix / "lib/grub" / platform
            directory.mkdir(parents=True)
            (directory / "modinfo.sh").write_text("fixture module info\n")

    def run_builder(self, source=True):
        env = os.environ.copy()
        env.update(PATH=str(self.bin), SOURCE_DATE_EPOCH="1735689600",
                   LC_ALL="C", TZ="UTC", REPRO_LIVE_INIT="0")
        env.pop("DISK_INIT_OUT", None)
        if source:
            env["REPRO_FROM_SOURCE_ROOT"] = str(self.source)
        else:
            env.pop("REPRO_FROM_SOURCE_ROOT", None)
        result = subprocess.run(
            [self.bash, str(BUILDER), str(self.root / "missing-kernel"),
             str(self.root / "missing-initramfs"), str(self.root / "out.iso")],
            env=env, text=True, capture_output=True, timeout=10,
        )
        self.assertFalse(self.marker.exists(), result.stderr)
        self.assertFalse((self.root / "out.iso").exists())
        return result

    def assert_rejected(self, expected):
        result = self.run_builder()
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertIn("source GRUB", result.stderr)
        self.assertIn(expected, result.stderr)
        self.assertNotIn("input missing:", result.stderr)

    def test_complete_source_prefix_reaches_kernel_preflight(self):
        result = self.run_builder()
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("input missing:", result.stderr)

    def test_legacy_non_source_invocation_reaches_kernel_preflight(self):
        result = self.run_builder(source=False)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("input missing:", result.stderr)

    def test_missing_source_prefix_rejects_ambient_tools(self):
        self.source = self.root / "missing-source"
        self.assert_rejected("prefix")

    def test_missing_tool_rejects_ambient_replacement(self):
        for tool in ("grub-mkrescue", "grub-mkimage"):
            with self.subTest(tool=tool):
                path = self.prefix / "bin" / tool
                saved = path.read_bytes()
                path.unlink()
                self.assert_rejected(tool)
                path.write_bytes(saved)
                path.chmod(0o755)

    def test_non_executable_tool_is_rejected(self):
        path = self.prefix / "bin/grub-mkrescue"
        path.chmod(0o644)
        self.assert_rejected("grub-mkrescue")

    def test_directory_is_not_an_executable_tool(self):
        path = self.prefix / "bin/grub-mkrescue"
        path.unlink()
        path.mkdir()
        self.assert_rejected("grub-mkrescue")

    def test_tool_symlink_cannot_escape_source_prefix(self):
        path = self.prefix / "bin/grub-mkimage"
        path.unlink()
        path.symlink_to(self.bin / "grub-mkimage")
        self.assert_rejected("outside")

    def test_missing_platform_metadata_rejects_partial_hybrid(self):
        for platform in ("i386-pc", "x86_64-efi"):
            with self.subTest(platform=platform):
                path = self.prefix / "lib/grub" / platform / "modinfo.sh"
                path.unlink()
                self.assert_rejected(platform)
                path.write_text("fixture module info\n")

    def test_platform_symlink_cannot_escape_source_prefix(self):
        directory = self.prefix / "lib/grub/x86_64-efi"
        outside = self.root / "host-modules"
        directory.rename(outside)
        directory.symlink_to(outside, target_is_directory=True)
        self.assert_rejected("outside")

    def test_internal_tool_symlink_is_accepted(self):
        path = self.prefix / "bin/grub-mkimage"
        path.rename(path.with_name("actual-mkimage"))
        path.symlink_to("actual-mkimage")
        result = self.run_builder()
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("input missing:", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
