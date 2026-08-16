#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
screen=welcome
size=1180x760
config=""
no_build=0

usage() {
  cat <<'EOF'
usage: run-installer-preview.sh [--screen ID] [--size WIDTHxHEIGHT]
                                [--config FILE] [--no-build]

Launch the real installer as a regular, non-destructive desktop app. The
preview seeds representative disk/account data and simulates installation,
so every wizard screen can be exercised without a VM or writable target disk.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --screen) screen="${2:?missing --screen value}"; shift 2 ;;
    --size) size="${2:?missing --size value}"; shift 2 ;;
    --config) config="${2:?missing --config value}"; shift 2 ;;
    --no-build) no_build=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$size" in
  *x*) ;;
  *) echo "invalid --size: expected WIDTHxHEIGHT" >&2; exit 2 ;;
esac

# shellcheck source=tools/installer-dev-runtime.sh
source "$repo_root/tools/installer-dev-runtime.sh"
reproos_installer_runtime_init "$repo_root"
if [ "$no_build" -eq 0 ]; then
  reproos_build_installer
fi
reproos_require_installer

if [ -z "${QT_QPA_PLATFORM:-}" ]; then
  if [ -n "${WAYLAND_DISPLAY:-}" ]; then
    export QT_QPA_PLATFORM=wayland
  elif [ -n "${DISPLAY:-}" ]; then
    export QT_QPA_PLATFORM=xcb
  else
    echo "no desktop display detected (WAYLAND_DISPLAY and DISPLAY are empty)" >&2
    exit 3
  fi
fi

# WSLg and minimal development hosts do not necessarily expose Mesa DRI
# drivers to the source-built Qt runtime. Software Qt Quick still renders the
# real QML application through Wayland and keeps the preview host-independent.
export QT_QUICK_BACKEND="${QT_QUICK_BACKEND:-software}"

args=(--preview --visual-screen "$screen" --window-size "$size")
if [ -n "$config" ]; then
  args+=(--config "$config")
fi

echo "Launching non-destructive installer preview ($screen at $size)"
exec "$REPROOS_INSTALLER_BIN" "${args[@]}"
