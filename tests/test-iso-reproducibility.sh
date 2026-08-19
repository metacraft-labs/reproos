#!/usr/bin/env bash
# Rebuild the ISO from the same source-built inputs and require byte identity.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
packages_root="${REPROBUILD_PACKAGES_ROOT:-$repo_root/../reprobuild-packages}"
recipe_dir="$repo_root/recipes/reproos-iso"
source_root="$packages_root/packages/source"
kernel_root="$source_root/kernel/.repro/output/install"
busybox_root="$source_root/busybox/.repro/output/install"
kernel="$kernel_root/usr/lib/reproos-kernel/vmlinuz"
rootfs="$recipe_dir/build/de-rootfs"
baseline_iso="$recipe_dir/build/reproos.iso"

for input in "$kernel" "$baseline_iso"; do
  if [ ! -s "$input" ]; then
    echo "test-iso-reproducibility: required input missing: $input" >&2
    exit 66
  fi
done
if [ ! -d "$rootfs" ]; then
  echo "test-iso-reproducibility: rootfs missing: $rootfs" >&2
  exit 66
fi

work="$(mktemp -d -t reproos-iso-reproducibility-XXXXXX)"
trap 'rm -rf "$work"' EXIT

SOURCE_DATE_EPOCH=1735689600 \
LC_ALL=C \
TZ=UTC \
REPROBUILD_PACKAGES_ROOT="$packages_root" \
REPRO_FROM_SOURCE_ROOT="$source_root" \
REPRO_KERNEL_INSTALL_ROOT="$kernel_root" \
REPRO_BUSYBOX_INSTALL_ROOT="$busybox_root" \
REPRO_DE_ROOTFS_DIR="$rootfs" \
REPRO_GRUB_VARIANT=multi-de \
REPRO_LIVE_INIT=1 \
REPRO_LIVE_INIT_OUT="$work/reproos-initramfs.img" \
REPRO_INSTALLER_AUTORUN=0 \
bash "$recipe_dir/scripts/build-iso.sh" \
  "$kernel" \
  "$work/reproos-initramfs.img" \
  "$work/reproos.iso"

if ! cmp -s "$baseline_iso" "$work/reproos.iso"; then
  echo "test-iso-reproducibility: repeated build is not byte-identical" >&2
  sha256sum "$baseline_iso" "$work/reproos.iso" >&2
  exit 1
fi

sha256sum "$baseline_iso"
echo "test-iso-reproducibility: PASS"
