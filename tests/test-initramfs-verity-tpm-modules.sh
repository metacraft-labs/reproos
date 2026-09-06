#!/usr/bin/env bash
set -euo pipefail

# Compile and run the initramfs dm-verity / TPM enablement gate.
#
# `nim` is taken from the ambient development shell, the same way
# tests/test-reproos-image-boot-smoke.sh does; this script deliberately
# does not re-exec through `nix develop`, because entering a sibling's
# dev shell also runs its git-hooks shellHook against whatever repository
# is the current directory, which a test must not do.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$repo_root/build/test-initramfs-verity-tpm/check-initramfs-verity-tpm"

if ! command -v nim >/dev/null; then
  echo "nim is required to build the initramfs verity/TPM gate" >&2
  echo "enter the development shell (direnv allow / nix develop)" >&2
  exit 2
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --out:"$checker" \
  "$repo_root/tests/test_initramfs_verity_and_tpm_modules.nim"
"$checker"
