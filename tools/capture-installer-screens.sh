#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer_project="$repo_root/apps/reproos-installer"
installer_bin="$installer_project/.repro/output/install/usr/bin/reproos-installer"
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

if [ "$no_build" -eq 0 ]; then
  repro_bin="${REPRO_BIN:-repro}"
  "$repro_bin" build "$installer_project" --tool-provisioning=from-source
fi
if [ ! -x "$installer_bin" ]; then
  echo "installer binary missing: $installer_bin" >&2
  echo "run without --no-build or set REPRO_BIN" >&2
  exit 3
fi

source_root="${REPRO_FROM_SOURCE_ROOT:-$repo_root/../reprobuild-packages/packages/source}"
qt_plugin_path=""
qml_import_path=""
qpa_plugin_path=""
for qt_package in qt6-base qt6-declarative qt6-quickcontrols2 qt6-wayland qt6-tools; do
  prefix="$source_root/$qt_package/.repro/output/install/usr"
  for plugins in "$prefix/plugins" "$prefix/lib/qt-6/plugins"; do
    if [ -d "$plugins" ]; then
      qt_plugin_path="$plugins${qt_plugin_path:+:$qt_plugin_path}"
      if [ -d "$plugins/platforms" ]; then
        qpa_plugin_path="$plugins/platforms${qpa_plugin_path:+:$qpa_plugin_path}"
      fi
    fi
  done
  for imports in "$prefix/qml" "$prefix/lib/qt-6/qml"; do
    if [ -d "$imports" ]; then
      qml_import_path="$imports${qml_import_path:+:$qml_import_path}"
    fi
  done
done

if [ -z "$qml_import_path" ] || [ -z "$qpa_plugin_path" ]; then
  echo "source-built Qt QML or platform plugins are missing under $source_root" >&2
  exit 3
fi

fontconfig_path="$source_root/fontconfig/.repro/output/install/usr/etc/fonts"
if [ ! -d "$fontconfig_path" ]; then
  fontconfig_path="/etc/fonts"
fi

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
    QT_QUICK_CONTROLS_STYLE=Basic \
    QT_PLUGIN_PATH="$qt_plugin_path" \
    QT_QPA_PLATFORM_PLUGIN_PATH="$qpa_plugin_path" \
    QML2_IMPORT_PATH="$qml_import_path" \
    FONTCONFIG_PATH="$fontconfig_path" \
      "$installer_bin" \
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
