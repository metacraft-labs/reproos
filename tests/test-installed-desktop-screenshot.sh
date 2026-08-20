#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${REPROOS_IMAGE:-$repo_root/recipes/reproos-image/build/reproos-installed.qcow2}"
output="${1:-$repo_root/build/test-installed-desktop-screenshot/desktop.png}"
boot_output="$repo_root/build/test-installed-desktop-screenshot/boot"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"

if [[ -z "${LIBVIRT_DEFAULT_URI:-}" &&
      -S "/run/user/$UID/libvirt/libvirt-sock" &&
      ! -S /run/libvirt/libvirt-sock &&
      ! -S /run/libvirt/virtqemud-sock ]]; then
  export LIBVIRT_DEFAULT_URI=qemu:///session
fi

if [[ ! -s "$image" ]]; then
  echo "installed image missing: $image" >&2
  echo "run: repro build image" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")" "$boot_output"
rm -f "$output"

"$vm_harness" boot \
  --backend auto \
  --source-image "$image" \
  --kind qcow2 \
  --generation 2 \
  --graphics vnc \
  --video virtio \
  --expect 'REPROOS_HEALTH:PASS' \
  --timeout-sec 300 \
  --screenshot "$output" \
  --screenshot-delay-sec 3 \
  --output-dir "$boot_output"

test -s "$output"
bash "$repo_root/tests/test-installed-desktop-frame.sh" "$output"
printf 'installed desktop screenshot: PASS\nframe=%s\n' "$output"
