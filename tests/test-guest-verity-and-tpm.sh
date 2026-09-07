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
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-guest-verity-tpm` in
# repro/workflows.nim):
#
#   nim         -- compiles this gate.
#   clang       -- the C compiler `nim c` lowers to and shells out to.
#   mkdir       -- creates the gate's build directory.
#   bash        -- the artifact-conditional half runs
#                  recipes/reproos-iso/scripts/build-initramfs.sh.
#
# `vm-harness` is deliberately NOT declared. This gate links the sibling's
# Nim LIBRARY and drives qemu through it; it never runs the vm-harness CLI.
# Declaring the identity would make `repro build` build that CLI through
# the cross-repo producer edge before this gate could start -- and here it
# did exactly that, and failed in `vm_harness.cli.build` without ever
# reaching the gate.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

repo_root="$(nim_gate_repo_root)"
vm_harness_src="${VM_HARNESS_SRC:-$repo_root/../vm-harness/src}"

if [[ ! -f "$vm_harness_src/vm_harness.nim" ]]; then
  echo "vm-harness checkout missing: $vm_harness_src" >&2
  echo "set VM_HARNESS_SRC to the vm-harness repository" >&2
  exit 2
fi

nim_gate_run test-guest-verity-tpm \
  tests/test_guest_verity_and_tpm_available.nim \
  bash
