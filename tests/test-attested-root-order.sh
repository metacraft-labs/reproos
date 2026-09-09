#!/usr/bin/env bash
set -euo pipefail

# Compile and run the gate over the ORDER an attested image is built in:
# the root is configured before its hash is taken, and the arm that
# installs it cannot mount a hashed carrier writably.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-attested-root-order`
# in repro/workflows.nim):
#
#   nim    -- compiles this gate.
#   clang  -- the C compiler `nim c` lowers to and shells out to.
#   mkdir  -- creates the gate's build directory.
#
# `sudo`, `qemu-img`, `qemu-nbd`, `sgdisk`, `veritysetup`, `mkfs.ext4`,
# `mount` and `modprobe` are deliberately NOT declared, for the same
# reason the carrier gate does not declare them: `cryptsetup` and
# `e2fsprogs` are from-source packages in this project, so naming them
# would make an always-on gate bootstrap them. The layer that needs them
# is opt-in, and when it IS asked for a missing tool is a loud failure
# and never a skip -- a green run that wrote no disk would be worse than
# a red one.
#
#   (default)                          the always-on layer reads the
#                                      shipped driver, stager,
#                                      configuration script, mount guard
#                                      and recipe (~1s)
#   REPROOS_ATTESTED_ROOT_ORDER_GATE=1 configure a purpose-built root
#                                      with the shipped script, image it,
#                                      apply the real attested layout to
#                                      a transient qcow2 over a loopback
#                                      NBD node, write the pair, verify
#                                      it against the root hash the
#                                      command line pins, drive the mount
#                                      guard at a real carrier, and
#                                      falsify the whole thing with a
#                                      read-write mount that writes
#                                      nothing (~3 min, needs sudo and
#                                      the nbd module)
#
# REPROOS_ATTESTED_ROOT_ORDER_KEEP=1 keeps the work directory and the
# qcow2. The NBD connection and every mount are torn down either way.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-attested-root-order tests/test_attested_root_order.nim
