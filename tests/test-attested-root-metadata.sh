#!/usr/bin/env bash
set -euo pipefail

# Compile and run the gate over the guest inode policy inside the
# integrity-checked root image: root-owned inodes, a setuid `sudo`, and an
# image that does not carry them refused rather than hashed.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-attested-root-metadata`
# in repro/workflows.nim):
#
#   nim     -- compiles this gate.
#   clang   -- the C compiler `nim c` lowers to and shells out to.
#   mkdir   -- creates the gate's build directory.
#   python3 -- runs the shipped guest inode policy, whose SquashFS
#              renderer the always-on layer drives over a fixture root.
#
# `sudo`, `mkfs.ext4`, `debugfs`, `mount` and `veritysetup` are
# deliberately NOT declared, for the same reason the carrier and root-order
# gates do not declare them: `e2fsprogs` and `cryptsetup` are from-source
# packages in this project, so naming them would make an always-on gate
# bootstrap them. The layer that needs them is opt-in, and when it IS asked
# for, a missing tool is a loud failure and never a skip -- a green run
# that made no image would be worse than a red one.
#
#   (default)                             the always-on layer reads the
#                                         shipped builder, the shipped ISO
#                                         script and the shipped recipe,
#                                         and drives the shipped SquashFS
#                                         renderer (~2s)
#   REPROOS_ATTESTED_ROOT_METADATA_GATE=1 build a purpose-built root with
#                                         deliberately wrong metadata,
#                                         image it with the shipped
#                                         build-verity-root.sh, loop-mount
#                                         it READ-ONLY and read every
#                                         owner and mode back out with the
#                                         kernel's own ext4 driver; then
#                                         falsify it three ways (~1 min,
#                                         needs sudo, mkfs.ext4 and
#                                         debugfs)
#
# REPROOS_ATTESTED_ROOT_METADATA_KEEP=1 keeps the work directory. The loop
# mount is torn down either way.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-attested-root-metadata tests/test_attested_root_metadata.nim \
  python3
