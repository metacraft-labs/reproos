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
# DELIBERATELY NOT DECLARED
#
#   qemu-system-x86_64, swtpm, mkfs.vfat, mtools (mmd/mcopy), xz
#     The boot layer's tools. They are not tool identities in this
#     project, so an action that declared them would try to provision
#     them from source. The boot layer is therefore OPT-IN and runnable
#     only from an ambient shell; under the engine it reports a visible
#     skip that names every artifact and tool it wants.
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
#   REPRO_BIN=<path>          use this `repro` binary.
#   REPROOS_PCR_GUEST_KERNEL=<path>       the guest kernel.
#   REPROOS_PCR_GUEST_MODULE_DIR=<path>   its module tree, when the TPM
#                             drivers are modular rather than built in.
set -euo pipefail

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_run test-measurement-manifest tests/test_measurement_manifest.nim
