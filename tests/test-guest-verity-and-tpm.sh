#!/usr/bin/env bash
set -euo pipefail

# Compile and run the booted-guest dm-verity / TPM gate.
#
# The gate imports the vm-harness sibling's Nim library (`boot_smoke.nim`)
# rather than shelling out to the vm-harness CLI, because it needs the
# ordered multi-line assertion the CLI's single `--expect` does not
# express, plus the direct-kernel-boot and vTPM fields on
# `BootSmokeSpec`. `config.nims` puts the sibling on the Nim path.
#
# `nim` is taken from the ambient development shell, the same way
# tests/test-reproos-image-boot-smoke.sh does; this script deliberately
# does not re-exec through `nix develop`, because entering a sibling's
# dev shell also runs its git-hooks shellHook against whatever repository
# is the current directory, which a test must not do.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vm_harness_src="${VM_HARNESS_SRC:-$repo_root/../vm-harness/src}"
checker="$repo_root/build/test-guest-verity-and-tpm/check-guest-verity-and-tpm"

if [[ ! -f "$vm_harness_src/vm_harness.nim" ]]; then
  echo "vm-harness checkout missing: $vm_harness_src" >&2
  echo "set VM_HARNESS_SRC to the vm-harness repository" >&2
  exit 2
fi

if ! command -v nim >/dev/null; then
  echo "nim is required to build the guest verity/TPM gate" >&2
  echo "enter the development shell (direnv allow / nix develop)" >&2
  exit 2
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --out:"$checker" \
  "$repo_root/tests/test_guest_verity_and_tpm_available.nim"
"$checker"
