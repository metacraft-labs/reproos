#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gui_assert_root="${GUI_ASSERT_ROOT:-$repo_root/../GuiAssert}"
current_dir="${REPROOS_VISUAL_OUTPUT:-$repo_root/build/test-installer-visuals/current}"
golden_dir="$repo_root/tests/golden/installer-screens"
checker="$repo_root/build/test-installer-visuals/check-installer-visuals"

if [[ ! -f "$gui_assert_root/flake.nix" || ! -f "$gui_assert_root/src/gui_assert.nim" ]]; then
  echo "GuiAssert checkout missing: $gui_assert_root" >&2
  echo "set GUI_ASSERT_ROOT to the GuiAssert repository" >&2
  exit 2
fi

if [[ "${GUIASSERT_DEV_SHELL:-0}" != 1 ]]; then
  nix_bin="${NIX_BIN:-$(command -v nix || true)}"
  if [[ -z "$nix_bin" ]]; then
    echo "nix is required to enter GuiAssert's pinned visual-test environment" >&2
    exit 2
  fi
  exec "$nix_bin" develop "path:$gui_assert_root" --command \
    env GUIASSERT_DEV_SHELL=1 bash "$0" "$@"
fi

bash "$repo_root/tools/capture-installer-screens.sh" --output "$current_dir"

if [[ "${1:-}" == --update-goldens ]]; then
  rm -rf "$golden_dir"
  mkdir -p "$golden_dir"
  cp -a "$current_dir/." "$golden_dir/"
  echo "updated installer visual goldens: $golden_dir"
fi

mkdir -p "$(dirname "$checker")"
nim c --hints:off --warnings:off \
  --path:"$gui_assert_root/src" \
  --out:"$checker" \
  "$repo_root/tests/test_installer_visuals.nim"
"$checker" "$current_dir" "$golden_dir"
