#!/usr/bin/env bash
# Gate: what an attested image will measure, said before it boots.
#
# TOOL CONTRACT
#
# This wrapper declares only what the ALWAYS-ON layer needs: bash, nim,
# mkdir and a C compiler (clang), exactly as the sibling Nim gates do.
# The declarations live in two places and must agree — here, and in the
# action's `.withToolIdentities([...])` in `repro/workflows.nim`. A tool
# that is missing while a layer is running is a LOUD FAILURE, never a
# skip: `tests/nim-gate.sh` exits 2 naming both declaration sites.
#
# DELIBERATELY NOT DECLARED HERE, AND WHERE THEY ARE DECLARED INSTEAD
#
#   qemu-system-x86_64, swtpm, mkfs.vfat, mmd, mcopy, xz
#     The boot layer's tools. This wrapper's `nim_gate_run` call does not
#     name them, because naming them here would make them required of
#     EVERY action that runs this script -- including the always-on
#     `test-measurement-manifest` gate, whose tool set is the Nim gate
#     toolchain and nothing else.
#
#     They are declared on the SECOND action that runs this same script:
#     `attestation-local-vm`, the named edge whose whole purpose is the
#     measured boot. `repro build attestation-local-vm` runs it. That
#     edge declares the boot layer ON, declares these tools for itself
#     (pinned, from `repro/measured_boot_tools.nim`, so nothing is
#     bootstrapped from source), and names the directory the evidence
#     lands in. Under the always-on gate the layer is reported as
#     UNREACHABLE and a request for it FAILS rather than skipping.
#
#   the `repro` CLI
#     The manifest is emitted by `repro attest expect`. The gate finds
#     the sibling build of it and reports a visible skip naming the
#     remedy when it is absent, because a checkout cannot assume the
#     sibling toolchain has been built.
#
# ENVIRONMENT SWITCHES
#
#   REPROOS_PCR_BOOT_GATE=1   run the measured-boot layer (~2 min): two
#                             transient QEMU guests, each with its own
#                             swtpm-backed TPM 2.0, booting a real
#                             unified kernel image through OVMF and
#                             reading PCR 11 back out of the register.
#   REPROOS_PCR_KEEP=1        keep the working directory for inspection.
#   REPROOS_PCR_EVIDENCE_DIR=<dir>
#                             preserve what the boot measured under this
#                             directory: each guest's serial transcript,
#                             the TCG event log the firmware published to
#                             it, the software TPM's log and state, the
#                             predicted and observed registers, the
#                             document the shipped emitter wrote, and the
#                             verdict. Naming it also makes the gate
#                             REFUSE to exit 0 unless it really read a
#                             register off a machine.
#   REPRO_BIN=<path>          use this `repro` binary.
#   REPROOS_PCR_GUEST_KERNEL=<path>       the guest kernel.
#   REPROOS_PCR_GUEST_MODULE_DIR=<path>   its module tree, when the TPM
#                             drivers are modular rather than built in.
set -euo pipefail

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-measurement-manifest tests/test_measurement_manifest.nim
