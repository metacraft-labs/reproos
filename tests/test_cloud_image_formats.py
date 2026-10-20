#!/usr/bin/env python3
"""verify_cloud_image_formats_are_reproducible (Cloud Images M2).

Converts one source disk to every provider format twice, in separate output
directories, and requires byte-identical artifacts and manifests. Also checks
each format is what its provider asks for (matrix section 5.2): a fixed VHD
whose size is a whole MiB with a valid footer, a GCE tarball holding one
oldgnu `disk.raw` whose size is a whole GiB, a sparse raw.

The source is a small synthetic disk with data at scattered offsets, made
with the real qemu-img; nothing is mocked. The installed ReproOS disk goes
through the same code; its run is recorded in the milestone, not here, because
this gate must not need a multi-hour image build.

Positive control for the epoch: changing SOURCE_DATE_EPOCH changes the VHD
and the tarball and nothing else, which shows the epoch is their only time
input and that the comparison above is not vacuous.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/reproos-cloud-image.py"
SPEC = importlib.util.spec_from_file_location("reproos_cloud_image", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

QEMU_IMG = shutil.which("qemu-img")


def make_source(directory: Path) -> Path:
    raw = directory / "source.raw"
    with raw.open("wb") as handle:
        handle.truncate(70 * MODULE.MIB + 12345)  # deliberately not MiB-aligned
        for offset in (0, 3 * MODULE.MIB + 17, 40 * MODULE.MIB, 70 * MODULE.MIB):
            handle.seek(offset)
            handle.write(bytes(range(256)) * 16)
    qcow2 = directory / "source.qcow2"
    subprocess.run([QEMU_IMG, "convert", "-q", "-f", "raw", "-O", "qcow2",
                    str(raw), str(qcow2)], check=True)
    return qcow2


@unittest.skipUnless(QEMU_IMG and shutil.which("tar") and shutil.which("gzip"),
                     "qemu-img, tar and gzip are required")
class CloudImageFormats(unittest.TestCase):
    def test_verify_cloud_image_formats_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cloud-image-") as scratch:
            base = Path(scratch)
            source = make_source(base)
            first = MODULE.convert(source, base / "a", list(MODULE.FORMATS),
                                   "generation-test", "uefi-ext4", 1735689600,
                                   qemu_img=QEMU_IMG)
            second = MODULE.convert(source, base / "b", list(MODULE.FORMATS),
                                    "generation-test", "uefi-ext4", 1735689600,
                                    qemu_img=QEMU_IMG)
            self.assertEqual(first, second)
            self.assertEqual((base / "a/manifest.json").read_bytes(),
                             (base / "b/manifest.json").read_bytes())
            for name in MODULE.FORMATS:
                self.assertEqual(
                    MODULE.sha256_file(base / "a" / first["artifacts"][name]["file"]),
                    MODULE.sha256_file(base / "b" / second["artifacts"][name]["file"]),
                    name)

            raw = base / "a/reproos.raw"
            self.assertEqual(raw.stat().st_size % MODULE.MIB, 0)
            self.assertLess(raw.stat().st_blocks * 512, raw.stat().st_size)  # sparse

            vhd = base / "a/reproos.vhd"
            # A fixed VHD probes as raw (it is raw data plus a footer), so name it.
            info = MODULE.image_info(QEMU_IMG, vhd, "vpc")
            self.assertEqual(info["format"], "vpc")
            self.assertEqual(info["virtual-size"] % MODULE.MIB, 0)
            self.assertEqual(info["virtual-size"], raw.stat().st_size)
            footer = vhd.read_bytes()[-512:]
            self.assertEqual(footer[:8], b"conectix")
            stored = struct.unpack(">I", footer[64:68])[0]
            zeroed = footer[:64] + b"\0\0\0\0" + footer[68:]
            self.assertEqual(stored, (~sum(zeroed)) & 0xFFFFFFFF)
            self.assertEqual(struct.unpack(">I", footer[24:28])[0],
                             1735689600 - MODULE.VHD_EPOCH)

            with tarfile.open(base / "a/reproos-gce.tar.gz") as archive:
                members = archive.getmembers()
            self.assertEqual([m.name for m in members], ["disk.raw"])
            self.assertEqual(members[0].size % MODULE.GIB, 0)
            self.assertEqual(members[0].mtime, 1735689600)
            self.assertEqual((members[0].uid, members[0].gid), (0, 0))

            # Positive control: the epoch is the only time input.
            third = MODULE.convert(source, base / "c", list(MODULE.FORMATS),
                                   "generation-test", "uefi-ext4", 1767225600,
                                   qemu_img=QEMU_IMG)
            changed = {name for name in MODULE.FORMATS
                       if third["artifacts"][name]["sha256"]
                       != first["artifacts"][name]["sha256"]}
            self.assertEqual(changed, {"vhd", "gce"})

    def test_vhd_footer_without_normalization_is_not_reproducible(self) -> None:
        # Falsifier for the footer normalization: qemu-img's own footer
        # carries a random unique id, so two plain conversions differ.
        with tempfile.TemporaryDirectory(prefix="cloud-image-") as scratch:
            base = Path(scratch)
            source = make_source(base)
            digests = set()
            for name in ("x.vhd", "y.vhd"):
                subprocess.run([QEMU_IMG, "convert", "-q", "-O", "vpc", "-o",
                                "subformat=fixed,force_size=on", str(source),
                                str(base / name)], check=True)
                digests.add(MODULE.sha256_file(base / name))
            self.assertEqual(len(digests), 2)


if __name__ == "__main__":
    unittest.main()
