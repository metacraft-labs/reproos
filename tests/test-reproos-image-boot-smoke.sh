#!/usr/bin/env bash
set -euo pipefail

# Compile and run the ReproOS image boot-smoke gate.
#
# The gate imports the vm-harness sibling's Nim library (`boot_smoke.nim`)
# rather than shelling out to the vm-harness CLI, because case 1 needs the
# matching engine (`SerialLineBuffer` / `expectLineImpl`) directly and case
# 2 needs the ordered multi-line assertion the CLI's single `--expect` does
# not express. `config.nims` puts the sibling on the Nim path.
#
# `nim` is taken from the ambient development shell, the same way
# vm-harness's own `just test` does; this script deliberately does not
# re-exec through `nix develop`, because entering a sibling's dev shell
# also runs its git-hooks shellHook against whatever repository is the
# current directory, which a test must not do.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vm_harness_src="${VM_HARNESS_SRC:-$repo_root/../vm-harness/src}"
checker="$repo_root/build/test-reproos-image-boot-smoke/check-reproos-image-boot-smoke"

if [[ ! -f "$vm_harness_src/vm_harness.nim" ]]; then
  echo "vm-harness checkout missing: $vm_harness_src" >&2
  echo "set VM_HARNESS_SRC to the vm-harness repository" >&2
  exit 2
fi

if ! command -v nim >/dev/null; then
  echo "nim is required to build the ReproOS image boot-smoke gate" >&2
  echo "enter the development shell (direnv allow / nix develop)" >&2
  exit 2
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --out:"$checker" \
  "$repo_root/tests/test_reproos_image_boot_smoke.nim"
"$checker"
