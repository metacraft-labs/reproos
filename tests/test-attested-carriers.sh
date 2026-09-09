#!/usr/bin/env bash
set -euo pipefail

# Compile and run the gate over the step that puts an integrity-checked
# root onto the partitions the measured kernel command line names.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-attested-carriers`
# in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#
# `sudo`, `qemu-img`, `qemu-nbd`, `sgdisk`, `veritysetup`, `mkfs.ext4`
# and `modprobe` are deliberately NOT declared, for the same reason the
# verity-root gate does not declare `cryptsetup` and `e2fsprogs`: those
# two are from-source packages in this project, so naming them would make
# an always-on gate bootstrap them. The layer that needs them is opt-in,
# and when it IS asked for a missing tool is a loud failure and never a
# skip -- a green run that wrote no disk would be worse than a red one.
#
#   (default)                        the always-on layer reads the
#                                    shipped driver, the shipped carrier
#                                    writer and the shipped recipe (~1s)
#   REPROOS_ATTESTED_CARRIER_GATE=1  create a transient qcow2, apply the
#                                    real attested layout to it over a
#                                    loopback NBD node, write a real
#                                    verity pair onto the carriers
#                                    through the shipped writer, and
#                                    verify the pair ON THE PARTITIONS
#                                    (~2 min, needs sudo and the nbd
#                                    module)
#
# REPROOS_ATTESTED_CARRIER_KEEP=1 keeps the work directory and the qcow2.
# The NBD connection is torn down either way.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-attested-carriers tests/test_attested_carriers.nim
