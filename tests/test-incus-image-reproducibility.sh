#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rootfs="$repo_root/recipes/reproos-iso/build/de-rootfs"
projection="$repo_root/recipes/reproos-container/build/projection"
builder="$repo_root/recipes/reproos-container/scripts/build-incus-image.sh"
work="$(mktemp -d -t reproos-incus-repro-XXXXXX)"
trap 'rm -rf "$work"' EXIT

for pass in first second; do
  mkdir -p "$work/$pass"
  SOURCE_DATE_EPOCH=1735689600 bash "$builder" \
    "$rootfs" "$projection" \
    "$work/$pass/reproos-incus.tar.xz" \
    "$work/$pass/incus-baseline.manifest"
done
cmp "$work/first/reproos-incus.tar.xz" "$work/second/reproos-incus.tar.xz"
cmp "$work/first/incus-baseline.manifest" "$work/second/incus-baseline.manifest"
python3 - \
  "$work/first/reproos-incus.tar.xz" \
  "$work/first/incus-baseline.manifest" <<'PY'
import posixpath
import re
import sys
import tarfile


archive = sys.argv[1]
manifest_path = sys.argv[2]
with tarfile.open(archive, mode="r:xz") as bundle:
    members = {member.name: member for member in bundle.getmembers()}
    metadata_member = members.get("metadata.yaml")
    if metadata_member is None:
        raise SystemExit("Incus image member missing: metadata.yaml")
    metadata_source = bundle.extractfile(metadata_member)
    if metadata_source is None:
        raise SystemExit("Incus image metadata cannot be read")
    metadata = metadata_source.read().decode("utf-8")


def require_member(name):
    member = members.get(name)
    if member is None:
        raise SystemExit(f"Incus image member missing: {name}")
    return member


require_member("rootfs/usr/sbin/init")

etc_repro = require_member("rootfs/etc/repro")
if not etc_repro.issym() or etc_repro.linkname != "/var/lib/reproos/current-generation":
    raise SystemExit("/etc/repro does not select the active configuration generation")

current = require_member("rootfs/var/lib/reproos/current-generation")
if not current.issym() or not re.fullmatch(r"generations/[0-9a-f]{64}", current.linkname):
    raise SystemExit("current-generation does not select a content-addressed generation")
generation = current.linkname.rsplit("/", 1)[1]
if f"  reproos.generation: {generation}\n" not in metadata:
    raise SystemExit("Incus metadata does not identify the configuration generation")

manifest = dict(
    line.split("=", 1)
    for line in open(manifest_path, encoding="utf-8").read().splitlines()
)
if manifest.get("generation") != generation:
    raise SystemExit("bundle manifest does not identify the configuration generation")

generation_root = posixpath.normpath(
    posixpath.join("rootfs/var/lib/reproos", current.linkname)
)
for artifact in (
    "auto-config.toml",
    "generation",
    "hardware.nim",
    "home.nim",
    "realization.json",
    "system.nim",
):
    require_member(posixpath.join(generation_root, artifact))

machine_only_prefixes = ("rootfs/boot/", "rootfs/usr/lib/modules/")
if any(name.startswith(machine_only_prefixes) for name in members):
    raise SystemExit("machine-only boot artifacts remain in the Incus image")
PY
echo "ReproOS Incus image reproducibility: PASS"
