#!/usr/bin/env python3
"""Image-namespace runtime preflight with real ELF files, without root or a VM.

The loader/libc fixtures are compiled ELF stand-ins, not an ABI or boot test.
The shipped normalizer and real patchelf inspect and modify the ELF consumers.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "recipes/reproos-iso/scripts"
spec = importlib.util.spec_from_file_location(
    "source_runtime_providers", SCRIPTS / "source-runtime-providers.py")
providers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(providers)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux image runtime gate")
class ImagePaths(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="reproos-image-paths-")
        self.addCleanup(temporary.cleanup)
        self.stage = Path(temporary.name) / "image"
        self.source = self.stage / "opt/source"
        self.source.mkdir(parents=True)
        self.file = self.source / "libfixture.so.1"
        self.file.write_bytes(b"fixture")
        self.file.chmod(0o755)

    def test_image_root_absolute_relative_and_parent_links(self):
        (self.source / "relative.so").symlink_to(self.file.name)
        (self.source / "absolute.so").symlink_to("/opt/source/relative.so")
        (self.source / "rooted.so").symlink_to("../../../../opt/source/absolute.so")
        (self.stage / "alias").symlink_to("/opt/source")
        for path in ("/opt/source/relative.so", "/opt/source/absolute.so",
                     "/opt/source/rooted.so", "/alias/libfixture.so.1"):
            with self.subTest(path=path):
                self.assertEqual(providers.runtime_file(
                    self.stage, path, source=self.source, executable=True), self.file)

    def test_rejects_missing_loop_directory_and_file_traversal(self):
        (self.source / "loop.so").symlink_to("loop.so")
        for path in ("/opt/source/missing.so", "/opt/source/loop.so", "/opt/source",
                     "/opt/source/libfixture.so.1/", "/opt/source/libfixture.so.1/..",
                     "/opt/source/libfixture.so.1/../libfixture.so.1"):
            with self.subTest(path=path):
                with self.assertRaises((providers.ImagePathError, OSError)):
                    providers.runtime_file(self.stage, path, source=self.source)

    def test_library_cannot_resolve_outside_source_mirror(self):
        outside = self.stage / "opt/source-other"
        outside.mkdir()
        (outside / "library.so").write_bytes(b"not source")
        (self.source / "library.so").symlink_to("../source-other/library.so")
        with self.assertRaisesRegex(providers.ImagePathError, "outside source mirror"):
            providers.runtime_file(self.stage, "/opt/source/library.so", source=self.source)

    def test_link_limit(self):
        for index in range(41):
            (self.source / f"link{index}.so").symlink_to(
                self.file.name if index == 0 else f"link{index - 1}.so")
        self.assertEqual(providers.runtime_file(
            self.stage, "/opt/source/link39.so", source=self.source), self.file)
        with self.assertRaisesRegex(providers.ImagePathError, "40 links"):
            providers.runtime_file(self.stage, "/opt/source/link40.so", source=self.source)

    def test_executable_permission_and_absolute_path_required(self):
        self.file.chmod(0o644)
        with self.assertRaisesRegex(providers.ImagePathError, "not executable"):
            providers.runtime_file(self.stage, "/opt/source/libfixture.so.1", executable=True)
        with self.assertRaisesRegex(providers.ImagePathError, "not absolute"):
            providers.resolve_image_path(self.stage, "opt/source/libfixture.so.1")

    def test_index_keeps_invalid_aliases_and_whitespace(self):
        (self.source / "broken alias.so").symlink_to("absent")
        (self.source / "directory.so").symlink_to(".")
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / "source-runtime-providers.py"),
             str(self.stage), str(self.source)], check=True, capture_output=True)
        fields = result.stdout.split(b"\0")
        self.assertEqual(fields.pop(), b"")
        self.assertEqual(len(fields) % 3, 0)
        records = {os.fsdecode(fields[i]): fields[i + 1:i + 3]
                   for i in range(0, len(fields), 3)}
        self.assertEqual(records[self.file.name][1], b"")
        self.assertEqual(records["broken alias.so"][0], b"/opt/source/broken alias.so")
        self.assertIn(b"unresolved image path", records["broken alias.so"][1])
        self.assertIn(b"not a regular file", records["directory.so"][1])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux image runtime gate")
class RuntimeNormalizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("clang", "patchelf", "bash", "python3", "find", "sort", "mktemp",
                     "rm", "readlink", "wc", "cut", "sed", "tail", "chmod", "touch",
                     "mv", "head"):
            if shutil.which(tool) is None:
                raise RuntimeError(f"missing declared runtime-test tool: {tool}")
        temporary = tempfile.TemporaryDirectory(prefix="reproos-runtime-elf-")
        cls.addClassCleanup(temporary.cleanup)
        cls.fixtures = Path(temporary.name)
        source = cls.fixtures / "fixture.c"
        source.write_text("int fixture_probe(void) { return 42; }\n")
        cls.provider = cls.fixtures / "libfixture-probe.so"
        subprocess.run(["clang", "-shared", "-fPIC", "-nostdlib", str(source),
                        "-Wl,-soname,libfixture-probe.so", "-o", str(cls.provider)], check=True)
        source.write_text("int fixture_probe(void);\n"
                          "int needs_probe(void) { return fixture_probe(); }\n")
        cls.consumer = cls.fixtures / "libconsumer.so"
        subprocess.run(["clang", "-shared", "-fPIC", "-nostdlib", str(source),
                        "-L", str(cls.fixtures), "-lfixture-probe",
                        "-Wl,-rpath,/repro/store/old/lib", "-o", str(cls.consumer)], check=True)
        needed = subprocess.check_output(["patchelf", "--print-needed", str(cls.consumer)], text=True)
        if needed.splitlines() != ["libfixture-probe.so"]:
            raise AssertionError(f"unexpected fixture DT_NEEDED: {needed!r}")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="reproos-normalizer-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / "image"
        self.source = self.stage / "opt/source"
        self.library = self.source / "probe/.repro/output/install/lib/libfixture-probe.so"
        self.library.parent.mkdir(parents=True)
        self.loader_path = "/opt/source/glibc/.repro/output/install/lib/ld-linux-fixture.so.2"
        self.loader = self.stage / self.loader_path.lstrip("/")
        self.loader.parent.mkdir(parents=True)
        # These files exercise image path auditing, not execution of a libc ABI.
        shutil.copyfile(self.provider, self.loader)
        self.loader.chmod(0o755)
        shutil.copyfile(self.provider, self.loader.parent / "libc.so.6")
        self.consumer_copy = self.source / "consumer/libconsumer.so"
        self.consumer_copy.parent.mkdir()
        shutil.copyfile(self.consumer, self.consumer_copy)

    def normalize(self, code=0, diagnostic=None):
        before = self.consumer_copy.read_bytes()
        result = subprocess.run(
            ["bash", str(SCRIPTS / "normalize-source-runtime.sh"), str(self.stage),
             str(self.source), self.loader_path, "2.42"], text=True, capture_output=True)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        if diagnostic:
            self.assertIn(diagnostic, result.stderr)
        if code:
            self.assertNotIn("verified source-only ELF runtime closure", result.stdout)
            self.assertEqual(self.consumer_copy.read_bytes(), before, "preflight mutated ELF")
        else:
            self.assertIn("verified source-only ELF runtime closure", result.stdout)
            rpath = subprocess.check_output(
                ["patchelf", "--print-rpath", str(self.consumer_copy)], text=True).strip()
            self.assertEqual(rpath, "/" + self.library.parent.relative_to(self.stage).as_posix())
        return result

    def test_regular_provider_and_unused_broken_development_alias(self):
        shutil.copyfile(self.provider, self.library)
        (self.library.parent / "unused.so").symlink_to("not-built")
        self.normalize()

    def test_relative_and_image_absolute_provider_links(self):
        other = self.source / "other/.repro/output/install/lib/libactual.so.1"
        other.parent.mkdir(parents=True)
        shutil.copyfile(self.provider, other)
        for target in (os.path.relpath(other, self.library.parent),
                       "/" + other.relative_to(self.stage).as_posix()):
            with self.subTest(target=target):
                self.library.symlink_to(target)
                self.normalize()
                self.library.unlink()

    def test_rejects_host_only_dangling_loop_directory_and_outside_mirror(self):
        outside = self.stage / "vendor/libfixture-probe.so"
        outside.parent.mkdir()
        shutil.copyfile(self.provider, outside)
        for target in (str(self.provider), "absent.so", self.library.name, ".",
                       "/vendor/libfixture-probe.so"):
            with self.subTest(target=target):
                self.library.symlink_to(target)
                self.normalize(75, "invalid-provider:libfixture-probe.so:")
                self.library.unlink()

    def test_invalid_first_provider_does_not_fall_back_to_another_package(self):
        shutil.copyfile(self.provider, self.library)
        earlier = self.source / "aaa/libfixture-probe.so"
        earlier.parent.mkdir()
        earlier.symlink_to("missing")
        self.normalize(75, "invalid-provider:libfixture-probe.so:")

    def test_loader_and_libc_are_checked_in_the_image(self):
        shutil.copyfile(self.provider, self.library)
        for selected in (self.loader, self.loader.parent / "libc.so.6"):
            with self.subTest(selected=selected.name):
                selected.unlink()
                selected.symlink_to(self.provider)
                self.normalize(65, "incomplete source glibc")
                selected.unlink()
                shutil.copyfile(self.provider, selected)
                selected.chmod(0o755)
        actual = self.loader.parent / "real-loader.so"
        self.loader.rename(actual)
        self.loader.symlink_to("/" + actual.relative_to(self.stage).as_posix())
        self.normalize()

    def test_shebang_preflight_uses_image_interpreter_and_preserves_failed_input(self):
        shutil.copyfile(self.provider, self.library)
        script = self.stage / "usr/bin/example"
        script.parent.mkdir(parents=True)
        original = b"#!/nix/store/old-python/bin/python3 -I\nprint('fixture')\n"
        script.write_bytes(original)
        script.chmod(0o755)
        interpreter = script.parent / "python3"
        host = self.root / "host-python"
        host.write_bytes(b"fixture, not executed\n")
        host.chmod(0o755)
        interpreter.symlink_to(host)
        self.normalize(75, "missing-shebang-interpreter:/usr/bin/python3")
        self.assertEqual(script.read_bytes(), original)
        interpreter.unlink()
        actual = self.source / "python/bin/python3"
        actual.parent.mkdir(parents=True)
        shutil.copyfile(host, actual)
        actual.chmod(0o755)
        interpreter.symlink_to("/" + actual.relative_to(self.stage).as_posix())
        self.normalize()
        self.assertEqual(script.read_bytes(), b"#!/usr/bin/python3 -I\nprint('fixture')\n")
        self.assertEqual(script.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main(verbosity=2)
