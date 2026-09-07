#!/usr/bin/env bash
set -euo pipefail

# Compile and run the "one renderer for the disko document" gates.
#
# Tool contract (see tests/nim-gate.sh, and the matching
# `.withToolIdentities([...])` list on
# `reproos.test-installer-disk-layout-parity` in repro/workflows.nim):
#
#   nim      -- drives the registry in repro/disk_layouts.nim, re-derives
#               the generated installer tables, and compiles each rendered
#               hardware.nim through repro_profile's own `hardware` macro.
#   mkdir    -- creates the gate's build directory.
#   python3  -- the gate compares tools/reproos-machine-config.py's
#               refusals against the registry's.
#   clang    -- the C compiler `nim c` lowers to, and a C++17 compiler for
#               the SHIPPED
#               apps/reproos-installer/src/disk_layouts.cpp (not a copy
#               of it), so the installer's own output can be diffed
#               against the registry's without a Qt toolchain being
#               present. Both come out of the same clang bin directory.
#
#               `clang` rather than `gcc` because that is what this
#               workspace can actually provision for a build action: the
#               sibling reprobuild-packages carries a from-source `gcc`
#               recipe, and naming `gcc` under from-source provisioning
#               would make this always-on gate bootstrap a whole GCC
#               before it could compile 200 lines of C++. The compiler is
#               invoked as `c++`, which both the gcc wrapper and the clang
#               wrapper provide, so a development shell and a build action
#               compile the same sources with whichever toolchain they
#               were given -- and the gate fails loudly when neither is
#               there.
#
# Nothing here is re-execed through `nix develop`, for the reason
# tests/nim-gate.sh records: entering a sibling's dev shell also runs its
# git-hooks shellHook against whatever repository is the current
# directory, which a test must not do.
#
# Set REPROOS_INSTALLER_BIN to compare against a built Qt installer as
# well; without one the gate reports a visible skip for that case and
# still compares the shipped sources.

# shellcheck source=tests/nim-gate.sh
. "${BASH_SOURCE[0]%/*}/nim-gate.sh"

nim_gate_require_any test-installer-disk-layout-parity \
  "a C++17 compiler is required (declare the 'clang' tool identity)" \
  c++ clang++ g++

nim_gate_run test-installer-disk-layout-parity \
  tests/test_installer_disk_layout_parity.nim \
  python3
