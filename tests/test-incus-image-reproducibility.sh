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
  SOURCE_DATE_EPOCH=1735689600 "$builder" \
    "$rootfs" "$projection" \
    "$work/$pass/reproos-incus.tar.xz" \
    "$work/$pass/incus-baseline.manifest"
done
cmp "$work/first/reproos-incus.tar.xz" "$work/second/reproos-incus.tar.xz"
cmp "$work/first/incus-baseline.manifest" "$work/second/incus-baseline.manifest"
xz -dc "$work/first/reproos-incus.tar.xz" | tar -tf - >"$work/contents"
grep -Fx metadata.yaml "$work/contents" >/dev/null
grep -Fx rootfs/usr/sbin/init "$work/contents" >/dev/null
grep -Fx rootfs/etc/repro/realization.json "$work/contents" >/dev/null
if grep -Eq '^rootfs/(boot/|usr/lib/modules/)' "$work/contents"; then
  echo "machine-only boot artifacts remain in the Incus image" >&2
  exit 1
fi
echo "ReproOS Incus image reproducibility: PASS"
