#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state_dir=${REPROOS_VM_STATE_DIR:-$repo_root/build/e2e-unattended-vm}
screenshot="$state_dir/verify-installed-boot/desktop.png"

python3 "$repo_root/tools/reproos-vm.py" install \
  --state-dir "$state_dir" --replace
mkdir -p "$state_dir/verify-installed-boot"
python3 "$repo_root/tools/reproos-vm.py" verify-installed-boot \
  --state-dir "$state_dir" \
  --screenshot "$screenshot" \
  --screenshot-delay-sec "${REPROOS_SCREENSHOT_DELAY_SEC:-20}" | \
  tee "$state_dir/verify-installed-boot/command.log"

test -s "$state_dir/install-manifest.json"
test -s "$state_dir/reproos-enrollment.iso"
test -s "$state_dir/enrollment/id_ed25519"
test -s "$state_dir/install/boot.serial.log"
test -s "$state_dir/verify-installed-boot/boot.serial.log"
test -s "$screenshot"
grep -qF '=== REPROOS-INSTALLER-AUTORUN-END RC=0 ===' \
  "$state_dir/install/boot.serial.log"
grep -qE '=== REPROOS-INSTALLED-BOOT source=unattended-installer generation=[0-9a-f]+ ===' \
  "$state_dir/verify-installed-boot/boot.serial.log"
grep -qF 'REPROOS_SSH_ACCEPTANCE:PASS hostname=reproos-smoke' \
  "$state_dir/verify-installed-boot/command.log"
bash "$repo_root/tests/test-installed-desktop-frame.sh" "$screenshot"

printf 'unattended installed-disk VM and GuiAssert: PASS\nstate=%s\n' \
  "$state_dir"
