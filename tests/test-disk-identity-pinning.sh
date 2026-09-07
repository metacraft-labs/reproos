#!/usr/bin/env bash
set -euo pipefail

# Compile and run the disk-identity pinning gate.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on
# `reproos.test-disk-identity-pinning` in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#
# Nothing else. The always-on layers drive Reprobuild's apply driver in
# its own argv-capture mode, so they spawn no disk tools at all.
#
# The gate's opt-in layer (REPROOS_DISK_IDENTITY_FILESYSTEM_GATE=1) does
# run mkfs.ext4 / mkfs.vfat / mkswap / sgdisk against file-backed images.
# Those four are deliberately NOT declared here: each has a from-source
# recipe in reprobuild-packages, so naming them would make an always-on
# gate build four source packages before it could run. When that layer is
# asked for and a tool is absent, the gate FAILS and names it -- being
# asked to do something and being unable to is never a skip.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-disk-identity-pinning \
  tests/test_disk_identity_pinning.nim
