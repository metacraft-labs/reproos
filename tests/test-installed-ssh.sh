#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${REPROOS_IMAGE:-$repo_root/recipes/reproos-image/build/reproos-installed.qcow2}"
harness_image="${REPROOS_HARNESS_IMAGE:-$image}"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
output_dir="$repo_root/build/test-installed-ssh"
boot_output="$output_dir/boot"
command_output="$output_dir/command.log"

if [[ -z "${LIBVIRT_DEFAULT_URI:-}" &&
      -S "/run/user/$UID/libvirt/libvirt-sock" &&
      ! -S /run/libvirt/libvirt-sock &&
      ! -S /run/libvirt/virtqemud-sock ]]; then
  export LIBVIRT_DEFAULT_URI=qemu:///session
fi

if [[ ! -s "$image" ]]; then
  echo "installed image missing: $image" >&2
  echo "run: repro build image --tool-provisioning=from-source" >&2
  exit 1
fi

check_hostname=0
if [[ "$#" -eq 0 ]]; then
  set -- hostname
  check_hostname=1
fi

# The checked-in smoke fixture intentionally uses this known acceptance-only
# credential. A caller can override it when booting an image from another config.
export REPROOS_SSH_PASSWORD="${REPROOS_SSH_PASSWORD:-reproos}"
rm -rf "$boot_output"
mkdir -p "$output_dir"

"$vm_harness" boot \
  --backend auto \
  --source-image "$harness_image" \
  --kind qcow2 \
  --generation 2 \
  --graphics vnc \
  --video virtio \
  --expect 'REPROOS_HEALTH:PASS' \
  --timeout-sec 300 \
  --ssh-forward-port auto \
  --ssh-user repro \
  --ssh-password-env REPROOS_SSH_PASSWORD \
  --output-dir "$boot_output" \
  -- "$@" | tee "$command_output"

if [[ "$check_hostname" -eq 1 ]] &&
   ! grep -Fqx 'reproos-smoke' "$command_output"; then
  echo "SSH hostname check failed; expected reproos-smoke" >&2
  exit 1
fi
