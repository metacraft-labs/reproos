#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
iso="$repo_root/recipes/reproos-iso/build/reproos.iso"
output="${1:-$repo_root/build/test-installer-vm-screenshot/welcome.png}"
boot_output="$repo_root/build/test-installer-vm-screenshot/boot"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"

mkdir -p "$(dirname "$output")" "$boot_output"
rm -f "$output"

"$vm_harness" boot \
  --backend auto \
  --source-image "$iso" \
  --kind iso \
  --generation 2 \
  --graphics vnc \
  --video virtio \
  --expect REPROOS_INSTALLER_FRAME_READY \
  --timeout-sec 300 \
  --screenshot "$output" \
  --output-dir "$boot_output"

test -s "$output"
bash "$repo_root/tests/test-installer-vm-frame.sh" "$output"
printf 'installer VM screenshot: PASS\nframe=%s\n' "$output"
