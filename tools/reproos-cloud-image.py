#!/usr/bin/env python3
"""Convert one canonical ReproOS disk into every provider upload format.

Cloud Images M2. The system closure is built once; a cloud image is the
installed disk of that generation, and each provider format is a pure
conversion of it, never a rebuild (spec/ReproOS-Cloud-Image-Provider-Matrix.md
section 5). This tool does the conversion and nothing else:

  raw       sparse raw, the canonical artifact (AWS EBS snapshot, Hetzner
            rescue dd, DigitalOcean, OpenStack where the cloud converts)
  qcow2     compat 1.1, fixed options (OpenStack Glance, OCI, local boots)
  vhd       fixed VHD, size rounded up to a whole MiB (Azure)
  gce       disk.raw in an oldgnu sparse tar, gzip -n, raw size rounded up
            to a whole GiB (Google Compute Engine)

Every conversion is reproducible from the same input bytes and
SOURCE_DATE_EPOCH: options are explicit, not ambient; the VHD footer's
timestamp comes from SOURCE_DATE_EPOCH and its unique id from the content
digest, with the footer checksum recomputed; the tar entry's mtime, owner and
mode are fixed and gzip writes no name or time.

The manifest binds generation, source disk, boot layout and each artifact's
format, virtual size and SHA-256. It is written for a signer to sign; this
tool holds no key.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


MIB = 1 << 20
GIB = 1 << 30
VHD_EPOCH = 946684800  # 2000-01-01T00:00:00Z, the VHD timestamp origin
FORMATS = ("raw", "qcow2", "vhd", "gce")
MANIFEST_SCHEMA = "reproos.cloud-image-manifest.v1"


class ImageError(Exception):
    pass


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, text=True, capture_output=True, **kwargs)
    if result.returncode != 0:
        raise ImageError(f"{argv[0]} failed ({result.returncode}): "
                         f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def image_info(qemu_img: str, path: Path, fmt: str = "") -> dict:
    argv = [qemu_img, "info", "--output=json"] + (["-f", fmt] if fmt else [])
    return json.loads(run(argv + [str(path)]).stdout)


def round_up(value: int, unit: int) -> int:
    return -(-value // unit) * unit


def to_raw(qemu_img: str, source: Path, out: Path, size: int) -> None:
    run([qemu_img, "convert", "-q", "-O", "raw", "-S", "4096", str(source), str(out)])
    if out.stat().st_size < size:
        os.truncate(out, size)


def to_qcow2(qemu_img: str, raw: Path, out: Path) -> None:
    run([qemu_img, "convert", "-q", "-f", "raw", "-O", "qcow2", "-S", "4096",
         "-o", "compat=1.1,cluster_size=65536,lazy_refcounts=off,"
               "compression_type=zlib,preallocation=off",
         str(raw), str(out)])


def normalize_vhd_footer(path: Path, epoch: int, content_digest: str) -> None:
    """Make the fixed-VHD footer a function of the content and the epoch.

    The footer is the file's last 512 bytes: timestamp at offset 24 (seconds
    since 2000-01-01, big-endian), checksum at 64 (ones' complement of the
    byte sum with the checksum field zeroed), unique id at 68.
    """
    with path.open("r+b") as handle:
        handle.seek(-512, os.SEEK_END)
        footer = bytearray(handle.read(512))
        if footer[0:8] != b"conectix":
            raise ImageError(f"{path}: no VHD footer cookie")
        footer[24:28] = struct.pack(">I", max(0, epoch - VHD_EPOCH))
        footer[68:84] = uuid.UUID(content_digest[:32]).bytes
        footer[64:68] = b"\0\0\0\0"
        footer[64:68] = struct.pack(">I", (~sum(footer)) & 0xFFFFFFFF)
        handle.seek(-512, os.SEEK_END)
        handle.write(footer)


def to_vhd(qemu_img: str, raw: Path, out: Path, epoch: int, digest: str) -> None:
    # Azure: fixed VHD whose virtual size is a whole MiB. The raw canonical is
    # already rounded (to_raw is called with a MiB multiple); force_size keeps
    # qemu-img from substituting its CHS geometry for the requested size.
    run([qemu_img, "convert", "-q", "-f", "raw", "-O", "vpc",
         "-o", "subformat=fixed,force_size=on", str(raw), str(out)])
    normalize_vhd_footer(out, epoch, digest)


def to_gce(raw: Path, out: Path, epoch: int, tar: str, gzip: str) -> None:
    # GCE: a file named disk.raw, size a whole GiB, in an oldgnu tar, gzipped.
    with tempfile.TemporaryDirectory(prefix="reproos-gce-") as scratch:
        disk = Path(scratch) / "disk.raw"
        run(["cp", "--sparse=always", str(raw), str(disk)])
        os.truncate(disk, round_up(disk.stat().st_size, GIB))
        os.utime(disk, (epoch, epoch))
        tar_out = Path(scratch) / "image.tar"
        run([tar, "--format=oldgnu", "--sparse", "--numeric-owner",
             "--owner=0", "--group=0", "--mode=0644", f"--mtime=@{epoch}",
             "-C", scratch, "-cf", str(tar_out), "disk.raw"])
        with out.open("wb") as handle:
            subprocess.run([gzip, "-n", "-9", "-c", str(tar_out)], stdout=handle,
                           check=True)


def convert(source: Path, out_dir: Path, formats: list[str], generation: str,
            layout: str, epoch: int, qemu_img: str = "qemu-img",
            tar: str = "tar", gzip: str = "gzip") -> dict:
    info = image_info(qemu_img, source)
    virtual = round_up(int(info["virtual-size"]), MIB)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = out_dir / "reproos.raw"
    to_raw(qemu_img, source, raw, virtual)
    raw_digest = sha256_file(raw)
    artifacts = {"raw": raw}
    if "qcow2" in formats:
        artifacts["qcow2"] = out_dir / "reproos.qcow2"
        to_qcow2(qemu_img, raw, artifacts["qcow2"])
    if "vhd" in formats:
        artifacts["vhd"] = out_dir / "reproos.vhd"
        to_vhd(qemu_img, raw, artifacts["vhd"], epoch, raw_digest)
    if "gce" in formats:
        artifacts["gce"] = out_dir / "reproos-gce.tar.gz"
        to_gce(raw, artifacts["gce"], epoch, tar, gzip)
    if "raw" not in formats:
        artifacts.pop("raw")
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "generation": generation,
        "boot_layout": layout,
        "source_disk": {"format": info.get("format"),
                        "virtual_size": int(info["virtual-size"])},
        "canonical_raw_sha256": raw_digest,
        "source_date_epoch": epoch,
        "artifacts": {
            name: {"file": path.name, "format": name,
                   "virtual_size": virtual if name != "gce"
                   else round_up(virtual, GIB),
                   "bytes": path.stat().st_size,
                   "sha256": sha256_file(path)}
            for name, path in sorted(artifacts.items())
        },
    }
    if "raw" not in formats:
        raw.unlink()
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="installed disk (qcow2 or raw)")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--format", action="append", choices=FORMATS,
                        help="repeatable; default: all")
    parser.add_argument("--generation", required=True)
    parser.add_argument("--layout", default="uefi-ext4")
    parser.add_argument("--source-date-epoch", type=int,
                        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    parser.add_argument("--qemu-img", default=shutil.which("qemu-img") or "qemu-img")
    args = parser.parse_args(argv)
    try:
        manifest = convert(args.source, args.out, args.format or list(FORMATS),
                           args.generation, args.layout, args.source_date_epoch,
                           qemu_img=args.qemu_img)
    except ImageError as exc:
        print(f"reproos-cloud-image: {exc}", file=sys.stderr)
        return 1
    for name, artifact in manifest["artifacts"].items():
        print(f"{name}\t{artifact['sha256']}\t{artifact['file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
