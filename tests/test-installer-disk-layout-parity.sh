#!/usr/bin/env bash
set -euo pipefail

# Compile and run the "one renderer for the disko document" gates.
#
# The gate needs two compilers and says so rather than skipping:
#
#   nim  -- to drive the registry in repro/disk_layouts.nim, to
#           re-derive the generated installer tables, and to compile
#           each rendered hardware.nim through repro_profile's own
#           `hardware` macro.
#   g++  -- to compile the SHIPPED
#           apps/reproos-installer/src/disk_layouts.cpp (not a copy of
#           it) so the installer's own output can be diffed against the
#           registry's without a Qt toolchain being present.
#
# Neither is re-execed through `nix develop`, for the reason
# tests/test-disk-layout-presets.sh records: entering a sibling's dev
# shell also runs its git-hooks shellHook against whatever repository is
# the current directory, which a test must not do.
#
# Set REPROOS_INSTALLER_BIN to compare against a built Qt installer as
# well; without one the gate reports a visible skip for that case and
# still compares the shipped sources.

# Resolved with bash parameter expansion rather than `dirname`, because
# a registered build action's PATH carries only the tool identities the
# action declares -- and under `repro build` this script's first
# diagnostic should be the accurate "nim is required", not a confusing
# "dirname: command not found". See the note on the required tools below.
script_dir="${BASH_SOURCE[0]%/*}"
repo_root="$(cd "$script_dir/.." && pwd)"
work_dir="$repo_root/build/test-installer-disk-layout-parity"
checker="$work_dir/check-parity"

if ! command -v nim >/dev/null; then
  echo "nim is required to build the installer disk-layout parity gate" >&2
  echo "enter the development shell (direnv allow / nix develop)" >&2
  exit 2
fi
if ! command -v python3 >/dev/null; then
  echo "python3 is required: this gate also compares" >&2
  echo "tools/reproos-machine-config.py's refusals against the registry's" >&2
  exit 2
fi
if ! command -v g++ >/dev/null; then
  echo "g++ is required: this gate compiles the installer's shipped" >&2
  echo "apps/reproos-installer/src/disk_layouts.cpp and diffs its output" >&2
  echo "against repro/disk_layouts.nim" >&2
  exit 2
fi

mkdir -p "$work_dir"
nim c --hints:off --warnings:off \
  --out:"$checker" \
  "$repo_root/tests/test_installer_disk_layout_parity.nim"
"$checker"
