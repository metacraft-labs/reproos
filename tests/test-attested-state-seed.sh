#!/usr/bin/env bash
set -euo pipefail

# Compile and run the gate over the first-boot state seed of an
# integrity-checked root: the configured account's home and /var content
# live in a factory tree INSIDE the measured root, are copied out onto the
# separate /var and /home volumes at first boot, and are never copied over
# again.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on `reproos.test-attested-state-seed`
# in repro/workflows.nim):
#
#   nim     -- compiles this gate.
#   clang   -- the C compiler `nim c` lowers to and shells out to.
#   mkdir   -- creates the gate's build directory.
#   bash    -- the shipped configuration script the opt-in layer runs.
#   python3 -- runs the shipped state seed tool, which the always-on
#              layer drives over purpose-built roots.
#
# `sudo`, `qemu-nbd`, `sgdisk`, `veritysetup`, `mkfs.ext4` and `mount` are
# deliberately NOT declared, for the same reason the carrier, root-order
# and root-metadata gates do not declare them: `cryptsetup` and
# `e2fsprogs` are from-source packages in this project, so naming them
# would make an always-on gate bootstrap them. The layer that needs them
# is opt-in, and when it IS asked for a missing tool is a loud failure and
# never a skip -- a green run that seeded nothing would be worse than a
# red one.
#
#   (default)                    the always-on layer reads the shipped
#                                configuration script, stager, initramfs
#                                and recipe for invocations, and drives
#                                the shipped seed tool over purpose-built
#                                roots including every refusal it makes
#                                (~3s)
#   REPROOS_STATE_SEED_GATE=1    configure a root with the shipped
#                                script, seed and detach it, image it,
#                                apply the real uefi-attested layout to a
#                                transient qcow2 over a loopback NBD node,
#                                and ACTIVATE that disk TWICE through
#                                dm-verity -- running the real
#                                systemd-tmpfiles the image ships over the
#                                real /var and /home partitions each time,
#                                with the state modified in between
#                                (~4 min, needs sudo, the nbd module and
#                                the from-source systemd)
#
# REPROOS_STATE_SEED_KEEP=1 keeps the work directory and the qcow2. The
# dm-verity device, the NBD connection and every mount are torn down
# either way.
#
# This script deliberately does not re-exec through `nix develop`, because
# entering a sibling's dev shell also runs its git-hooks shellHook against
# whatever repository is the current directory, which a test must not do.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-attested-state-seed tests/test_attested_state_seed.nim \
  bash python3
