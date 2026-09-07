#!/usr/bin/env bash
set -euo pipefail

# Compile and run the typed disk-layout preset gates.
#
# The gate imports Reprobuild's `repro_profile` types and its
# `parseSystemHardwareJson` decoder directly, so that the JSON the
# registry renders is checked against the same parser `repro disk apply`
# uses rather than against a second implementation of it. `config.nims`
# puts the sibling's libs on the Nim path.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-disk-layout-presets`
# in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#   bash   -- the gate replays the image driver's `printf '%b'` hand-off
#             through a real bash rather than reasoning about it.
#   git    -- the gate re-derives the uefi-ext4 golden from an earlier
#             revision of the driver, at a pinned commit.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-disk-layout-presets \
  tests/test_disk_layout_presets.nim \
  bash git
