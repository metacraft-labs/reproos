#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="$repo_root/build/visual-review/installer"
view=all
size=all
no_build=0

usage() {
  cat <<'EOF'
usage: capture-installer-screens.sh [--view ID|all] [--size NAME|all]
                                    [--output DIR] [--no-build]

Named sizes: wide (1280x800), vm (1024x768), compact (960x720)
Named views: welcome, locale, keyboard, users, disk, deSelect,
             activities, summary, install, finished
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --view) view="${2:?missing --view value}"; shift 2 ;;
    --size) size="${2:?missing --size value}"; shift 2 ;;
    --output) output_root="${2:?missing --output value}"; shift 2 ;;
    --no-build) no_build=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

views=(welcome locale keyboard users disk deSelect activities summary install finished)
sizes=(wide vm compact)

contains() {
  local needle="$1"; shift
  local item
  for item in "$@"; do
    [ "$item" = "$needle" ] && return 0
  done
  return 1
}

if [ "$view" != all ] && ! contains "$view" "${views[@]}"; then
  echo "unknown view: $view" >&2
  exit 2
fi
if [ "$size" != all ] && ! contains "$size" "${sizes[@]}"; then
  echo "unknown size: $size" >&2
  exit 2
fi

# shellcheck source=tools/installer-dev-runtime.sh
source "$repo_root/tools/installer-dev-runtime.sh"
reproos_installer_runtime_init "$repo_root"
if [ "$no_build" -eq 0 ]; then
  reproos_build_installer
fi
reproos_require_installer

if [ "$view" = all ] && [ "$size" = all ]; then
  rm -rf "$output_root"
fi
mkdir -p "$output_root"

captured=0
for current_view in "${views[@]}"; do
  [ "$view" = all ] || [ "$view" = "$current_view" ] || continue
  for current_size in "${sizes[@]}"; do
    [ "$size" = all ] || [ "$size" = "$current_size" ] || continue
    case "$current_size" in
      wide) dimensions=1280x800 ;;
      vm) dimensions=1024x768 ;;
      compact) dimensions=960x720 ;;
    esac
    output="$output_root/${current_view}-${current_size}.png"
    QT_QPA_PLATFORM=offscreen \
    QT_QUICK_BACKEND=software \
      "$REPROOS_INSTALLER_BIN" \
        --visual-screen "$current_view" \
        --window-size "$dimensions" \
        --screenshot "$output"
    [ -s "$output" ] || {
      echo "empty screenshot: $output" >&2
      exit 4
    }
    captured=$((captured + 1))
  done
done

printf 'captured=%d\noutput=%s\n' "$captured" "$output_root"
