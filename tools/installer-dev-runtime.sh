#!/usr/bin/env bash

# Shared source-built Qt runtime setup for the interactive preview and
# deterministic screenshot tools. This file is sourced, not executed.

reproos_installer_runtime_init() {
  local repo_root="${1:?missing repository root}"
  local qt_plugin_path=""
  local qml_import_path=""
  local qpa_plugin_path=""
  local qt_package prefix plugins imports

  REPROOS_INSTALLER_PROJECT="$repo_root"
  REPROOS_INSTALLER_BIN="$repo_root/.repro/output/install/usr/bin/reproos-installer"
  REPROOS_SOURCE_ROOT="${REPRO_FROM_SOURCE_ROOT:-$repo_root/../reprobuild-packages/packages/source}"

  for qt_package in qt6-base qt6-declarative qt6-quickcontrols2 qt6-wayland qt6-tools; do
    prefix="$REPROOS_SOURCE_ROOT/$qt_package/.repro/output/install/usr"
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
    echo "source-built Qt QML or platform plugins are missing under $REPROOS_SOURCE_ROOT" >&2
    return 3
  fi

  local fontconfig_path="$REPROOS_SOURCE_ROOT/fontconfig/.repro/output/install/usr/etc/fonts"
  if [ ! -d "$fontconfig_path" ]; then
    fontconfig_path="/etc/fonts"
  fi

  local font_file="$REPROOS_SOURCE_ROOT/dejavu-fonts/.repro/output/install/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
  if [ -f "$font_file" ]; then
    export REPROOS_INSTALLER_FONT_FILE="$font_file"
  fi

  export QT_PLUGIN_PATH="$qt_plugin_path${QT_PLUGIN_PATH:+:$QT_PLUGIN_PATH}"
  export QT_QPA_PLATFORM_PLUGIN_PATH="$qpa_plugin_path${QT_QPA_PLATFORM_PLUGIN_PATH:+:$QT_QPA_PLATFORM_PLUGIN_PATH}"
  export QML2_IMPORT_PATH="$qml_import_path${QML2_IMPORT_PATH:+:$QML2_IMPORT_PATH}"
  export FONTCONFIG_PATH="$fontconfig_path"
  export QT_QUICK_CONTROLS_STYLE="${QT_QUICK_CONTROLS_STYLE:-Basic}"
}

reproos_build_installer() {
  local repro_bin="${REPRO_BIN:-repro}"
  (
    cd "$REPROOS_INSTALLER_PROJECT"
    "$repro_bin" build installer --tool-provisioning=from-source
  )
}

reproos_require_installer() {
  if [ ! -x "$REPROOS_INSTALLER_BIN" ]; then
    echo "installer binary missing: $REPROOS_INSTALLER_BIN" >&2
    echo "run: repro build installer --tool-provisioning=from-source" >&2
    return 3
  fi
}
