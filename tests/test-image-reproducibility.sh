#!/usr/bin/env bash
set -euo pipefail

# Compile and run the image reproducibility gate.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on
# `reproos.test-image-reproducibility` in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#   bash   -- the opt-in build-twice case rebuilds the image through
#             recipes/reproos-image/scripts/build-reproos-image.sh. That
#             case reports a visible skip when it is not requested, or
#             when the artifacts it needs are absent, which is an
#             ARTIFACT skip, not a tool skip.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-image-reproducibility \
  tests/test_reproos_image_reproducibility.nim \
  bash
