#!/usr/bin/env bash
set -euo pipefail

# Compile and run the dm-verity read-only root gate.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-verity-root` in
# repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#   bash   -- the opt-in layers run the shipped
#             recipes/reproos-image/scripts/build-verity-root.sh and
#             recipes/reproos-iso/scripts/build-initramfs.sh.
#
# `veritysetup`, `mkfs.ext4` and `qemu-system-x86_64` are deliberately
# NOT declared. `cryptsetup` and `e2fsprogs` are from-source packages in
# this project, so naming them would make an always-on gate bootstrap
# them before it could run -- and the always-on layer needs neither: it
# builds real dm-verity Merkle trees in Nim and checks them against a
# known answer that a real veritysetup produced. The layers that DO need
# those tools are opt-in, and when they are asked for a missing tool is a
# loud failure rather than a skip:
#
#   REPROOS_VERITY_TOOL_GATE=1   run the real veritysetup / mkfs.ext4
#                                comparison (~20s)
#   REPROOS_VERITY_GUEST_GATE=1  boot a real guest on the product's own
#                                initramfs over a real verity image and
#                                read the result off its serial console
#                                (~1 min)
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-verity-root tests/test_verity_root.nim bash
