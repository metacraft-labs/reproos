#!/usr/bin/env bash
set -euo pipefail

# Compile and run the initramfs dm-verity / TPM enablement gate.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on
# `reproos.test-initramfs-verity-tpm` in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#   bash   -- the artifact-conditional half runs
#             recipes/reproos-iso/scripts/build-initramfs.sh; it reports a
#             visible skip when the source-built kernel and BusyBox
#             install mirrors are absent, which is an ARTIFACT skip, not a
#             tool skip.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-initramfs-verity-tpm \
  tests/test_initramfs_verity_and_tpm_modules.nim \
  bash
