#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gui_assert_root="${GUI_ASSERT_ROOT:-$repo_root/../GuiAssert}"
frame="${1:?usage: test-installer-vm-frame.sh FRAME.png}"
checker="$repo_root/build/test-installer-vm-frame/check-installer-vm-frame"

if [[ ! -f "$gui_assert_root/flake.nix" || ! -f "$gui_assert_root/src/gui_assert.nim" ]]; then
  echo "GuiAssert checkout missing: $gui_assert_root" >&2
  exit 2
fi

if [[ "${GUIASSERT_DEV_SHELL:-0}" != 1 ]]; then
  nix_bin="${NIX_BIN:-$(command -v nix || true)}"
  if [[ -z "$nix_bin" ]]; then
    echo "nix is required to enter GuiAssert's pinned VM-frame environment" >&2
    exit 2
  fi
  exec "$nix_bin" develop "path:$gui_assert_root" --command \
    env GUIASSERT_DEV_SHELL=1 bash "$0" "$frame"
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --path:"$gui_assert_root/src" \
  --out:"$checker" \
  "$repo_root/tests/test_installer_vm_frame.nim"
"$checker" "$frame"
