#!/usr/bin/env bash
set -euo pipefail

# Compile and run the ReproOS image boot-smoke gate.
#
# The gate imports the vm-harness sibling's Nim library (`boot_smoke.nim`)
# rather than shelling out to the vm-harness CLI, because case 1 needs the
# matching engine (`SerialLineBuffer` / `expectLineImpl`) directly and case
# 2 needs the ordered multi-line assertion the CLI's single `--expect` does
# not express. `config.nims` puts the sibling on the Nim path.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-image-boot-smoke` in
# repro/workflows.nim):
#
#   nim         -- compiles this gate.
#   clang       -- the C compiler `nim c` lowers to and shells out to.
#   mkdir       -- creates the gate's build directory.
#
# `vm-harness` is deliberately NOT declared. This gate links the sibling's
# Nim LIBRARY (`boot_smoke.nim`, put on the Nim path by config.nims) and
# drives qemu through it; it never runs the vm-harness CLI. Declaring the
# identity would make `repro build` build that CLI through the cross-repo
# producer edge before this gate could start.
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

nim_gate_run test-image-boot-smoke \
  tests/test_reproos_image_boot_smoke.nim
