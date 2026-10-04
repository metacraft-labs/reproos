#!/usr/bin/env bash
# Gate: the layout a profile names is the layout its image was built with.
#
# The image build publishes a record saying which disk layout it
# resolved, bound to the digest of the partition table that layout
# renders; the attestation activity reads the layout out of that record
# instead of out of a string the profile wrote. This gate drives both
# halves against the real presets, the real record schema and the real
# activity validator.
#
# TOOL CONTRACT
#
# Only the always-on layer's tools: bash, nim, mkdir and a C compiler
# (clang). The declarations live in two places and must agree — here, and
# in the action's `.withToolIdentities([...])` in `repro/workflows.nim`.
# A tool that is missing while a layer is running is a LOUD FAILURE,
# never a skip: `tests/nim-gate.sh` exits 2 naming both declaration
# sites.
#
# There is no opt-in layer and no environment switch. Nothing here boots,
# partitions, or needs a built sibling: the gate renders partition tables
# in process and compares them.
set -euo pipefail

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-image-layout-record tests/test_image_layout_record.nim
