#!/usr/bin/env bash
set -euo pipefail

# Compile and run the unified-kernel-image gate.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-uki` in
# repro/workflows.nim):
#
#   nim    -- compiles this gate, and the gate compiles the shipped
#             tools/reproos_uki.nim so that the assembler under test is
#             the one the recipe ships rather than a second copy.
#   clang  -- the C compiler `nim c` lowers to and shells out to, and the
#             compiler the boot layer builds the guest's freestanding
#             /init with.
#   mkdir  -- creates the gate's build directory.
#
# `qemu-system-x86_64`, `mkfs.vfat` and `mtools` are deliberately NOT
# declared. `dosfstools` and `mtools` are from-source packages in this
# project, so naming them would make an always-on gate bootstrap them --
# and the always-on layer needs none of them: it assembles unified kernel
# images against a synthetic PE stub it builds from the specification.
# The layers that DO need them are conditional, and when they run a
# missing tool is a loud failure rather than a skip:
#
#   (automatic)                 the real-stub layer runs whenever a copy
#                               of the pinned EFI stub is present, and
#                               reports a visible skip naming the remedy
#                               when it is not (~10s)
#   REPROOS_UKI_BOOT_GATE=1     boot a real unified kernel image off a
#                               FAT ESP through OVMF in a transient QEMU
#                               guest and read /proc/cmdline off its
#                               serial console (~40s)
#
# REPROOS_UKI_KEEP=1 keeps the working directories, which is the only way
# to read a passing boot's serial transcript.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-uki tests/test_uki.nim
