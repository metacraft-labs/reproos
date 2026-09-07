#!/usr/bin/env bash
# Rebuild the boot media from the same source-built inputs and require byte
# identity -- artifact by artifact, in the order the builder writes them.
#
# The ISO embeds the initramfs, so an ISO that differs tells you nothing
# about WHERE the build stopped being reproducible: an initramfs whose
# entry order drifted produces a different ISO, and so does an ISO whose
# volume descriptor drifted while the initramfs inside it is identical.
# Comparing the initramfs FIRST, and reporting the first artifact that
# differs, is the difference between a diagnosis and a symptom. The
# registered Nim gate `test-image-reproducibility` compares the installed
# image the same way and holds this script to the same contract.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
packages_root="${REPROBUILD_PACKAGES_ROOT:-$repo_root/../reprobuild-packages}"
recipe_dir="$repo_root/recipes/reproos-iso"
source_root="$packages_root/packages/source"
kernel_root="$source_root/kernel/.repro/output/install"
busybox_root="$source_root/busybox/.repro/output/install"
kernel="$kernel_root/usr/lib/reproos-kernel/vmlinuz"
rootfs="$recipe_dir/build/de-rootfs"

# Pipeline order: the initramfs is authored first and then embedded, so a
# difference in it explains a difference in the ISO but not the reverse.
ARTIFACTS=(
  reproos-initramfs.img
  reproos.iso
)

baseline_initramfs="$recipe_dir/build/reproos-initramfs.img"
baseline_iso="$recipe_dir/build/reproos.iso"

for input in "$kernel" "$baseline_initramfs" "$baseline_iso"; do
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

# sha256 rather than `cmp`: `sha256sum` is a declared tool identity of this
# action and `cmp` (diffutils) is not, so comparing digests keeps the gate
# runnable under the hermetic PATH the engine gives it.
digest_of() {
  sha256sum "$1" | awk '{print $1}'
}
size_of() {
  wc -c < "$1" | awk '{print $1}'
}

for artifact in "${ARTIFACTS[@]}"; do
  baseline="$recipe_dir/build/$artifact"
  rebuilt="$work/$artifact"
  if [ ! -s "$rebuilt" ]; then
    echo "test-iso-reproducibility: the rebuild produced no $artifact" >&2
    exit 67
  fi
  baseline_sha="$(digest_of "$baseline")"
  rebuilt_sha="$(digest_of "$rebuilt")"
  if [ "$baseline_sha" != "$rebuilt_sha" ]; then
    {
      echo "test-iso-reproducibility: first differing artifact: $artifact"
      echo "  the build already on disk: bytes=$(size_of "$baseline") sha256=$baseline_sha"
      echo "  the rebuild:               bytes=$(size_of "$rebuilt") sha256=$rebuilt_sha"
      echo "  later artifacts are not compared; the earliest divergence is the one to fix"
    } >&2
    exit 1
  fi
  echo "test-iso-reproducibility: $artifact identical (sha256=$baseline_sha)"
done

echo "test-iso-reproducibility: PASS"
