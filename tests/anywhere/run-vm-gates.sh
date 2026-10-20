#!/usr/bin/env bash
# Run the ReproOS Anywhere VM gates against freshly built fixture artifacts.
#
#   tests/anywhere/run-vm-gates.sh e2e        e2e_reproos_anywhere_converts_linux_vm
#   tests/anywhere/run-vm-gates.sh diskid     test_reproos_anywhere_disk_identity_mismatch
#   tests/anywhere/run-vm-gates.sh negatives  takeover tamper + old-system false positive
#   tests/anywhere/run-vm-gates.sh resume     e2e_reproos_anywhere_apply_resumes_after_disconnect
#
# Every VM is an unprivileged QEMU/KVM guest under build/anywhere/run that
# the gate destroys; images are digest-pinned (tests/anywhere/distros.json)
# and cached under build/anywhere/images. A missing tool or /dev/kvm is a
# failure with a remedy, never a skip.
set -euo pipefail
gate=${1:?usage: run-vm-gates.sh e2e|diskid|negatives|resume [distro...]}
shift
here=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
repo=$(cd "$here/../.." && pwd)
art=${ANYWHERE_ARTIFACTS:-$repo/build/anywhere}
for tool in nix-build qemu-system-x86_64 qemu-img ssh ssh-keygen xorriso cpio curl python3; do
  command -v "$tool" >/dev/null || { echo "run-vm-gates: missing $tool; run from a shell that provides it" >&2; exit 2; }
done
[ -w /dev/kvm ] || { echo "run-vm-gates: /dev/kvm is not writable; the Anywhere VM gates need KVM" >&2; exit 2; }
"$here/build-fixtures.sh" "$art" "${REPROBUILD_SOURCE_ROOT:-$repo/../reprobuild}" >/dev/null
mkdir -p "$art/images"
export ANYWHERE_IMAGE_CACHE=${ANYWHERE_IMAGE_CACHE:-$art/images}
case "$gate" in
  e2e) [ "$#" -gt 0 ] || set -- debian ubuntu fedora arch alpine nixos
       exec python3 "$here/e2e_convert.py" --artifacts "$art" "$@" ;;
  diskid) exec python3 "$here/test_disk_identity_mismatch.py" --artifacts "$art" "$@" ;;
  negatives) exec python3 "$here/test_negatives.py" --artifacts "$art" "$@" ;;
  resume) exec python3 "$here/test_resume.py" --artifacts "$art" ;;
  *) echo "run-vm-gates: unknown gate $gate" >&2; exit 64 ;;
esac
