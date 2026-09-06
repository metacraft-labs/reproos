#!/usr/bin/env bash
set -euo pipefail

# Compile and run the typed disk-layout preset gates.
#
# The gate imports Reprobuild's `repro_profile` types and its
# `parseSystemHardwareJson` decoder directly, so that the JSON the
# registry renders is checked against the same parser `repro disk apply`
# uses rather than against a second implementation of it. `config.nims`
# puts the sibling's libs on the Nim path.
#
# `nim` is taken from the ambient development shell, the same way
# tests/test-initramfs-verity-tpm-modules.sh does; this script
# deliberately does not re-exec through `nix develop`, because entering a
# sibling's dev shell also runs its git-hooks shellHook against whatever
# repository is the current directory, which a test must not do.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/build/test-disk-layout-presets/check-disk-layout-presets"

if ! command -v nim >/dev/null; then
  echo "nim is required to build the disk-layout preset gate" >&2
  echo "enter the development shell (direnv allow / nix develop)" >&2
  exit 2
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --out:"$checker" \
  "$repo_root/tests/test_disk_layout_presets.nim"
"$checker"
