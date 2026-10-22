#!/usr/bin/env bash
# Run the ReproOS Anywhere VM gates against freshly built fixture artifacts.
#
#   tests/anywhere/run-vm-gates.sh e2e        e2e_reproos_anywhere_converts_linux_vm
#   tests/anywhere/run-vm-gates.sh diskid     test_reproos_anywhere_disk_identity_mismatch
#   tests/anywhere/run-vm-gates.sh negatives  takeover tamper + old-system false positive
#   tests/anywhere/run-vm-gates.sh resume     e2e_reproos_anywhere_apply_resumes_after_disconnect
#   tests/anywhere/run-vm-gates.sh detection  test_reproos_anywhere_detection_and_append_only_capture
#   tests/anywhere/run-vm-gates.sh confinement test_reproos_anywhere_installer_confinement_and_isolation
#   tests/anywhere/run-vm-gates.sh recovery   e2e_reproos_anywhere_failure_recovery_matrix
#   tests/anywhere/run-vm-gates.sh refusals   preflight refusals on real LVM/LUKS/RAID/static/BIOS/arm64 sources
#   tests/anywhere/run-vm-gates.sh drill      e2e_reproos_anywhere_compromise_drill
#   tests/anywhere/run-vm-gates.sh controllers the conversion over virtio-scsi, AHCI and NVMe targets
#   tests/anywhere/run-vm-gates.sh convert    the conversion through `reproos-anywhere convert DEST MACHINE`
#
# Every VM is an unprivileged QEMU/KVM guest under build/anywhere/run that
# the gate destroys; images are digest-pinned (tests/anywhere/distros.json)
# and cached under build/anywhere/images. A missing tool or /dev/kvm is a
# failure with a remedy, never a skip.
set -euo pipefail
gate=${1:?usage: run-vm-gates.sh e2e|diskid|negatives|resume|detection|confinement|recovery|refusals|drill|controllers|convert [distro...]}
shift
here=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
repo=$(cd "$here/../.." && pwd)
art=${ANYWHERE_ARTIFACTS:-$repo/build/anywhere}
for tool in nix-build qemu-system-x86_64 qemu-system-aarch64 qemu-img ssh ssh-keygen xorriso cpio curl python3; do
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
  detection) exec python3 "$here/test_detection.py" --artifacts "$art" ;;
  confinement) exec python3 "$here/test_confinement.py" --artifacts "$art" ;;
  recovery) exec python3 "$here/test_recovery.py" --artifacts "$art" ;;
  refusals) exec python3 "$here/test_preflight_refusals.py" --artifacts "$art" ;;
  drill) exec python3 "$here/test_compromise_drill.py" --artifacts "$art" ;;
  controllers) for ctl in virtio-scsi ahci nvme; do
                 python3 "$here/e2e_convert.py" --artifacts "$art" --controller "$ctl" debian || exit 1
               done ;;
  convert) [ "$#" -gt 0 ] || set -- debian alpine
           exec python3 "$here/e2e_convert.py" --artifacts "$art" --convert "$@" ;;
  *) echo "run-vm-gates: unknown gate $gate" >&2; exit 64 ;;
esac
