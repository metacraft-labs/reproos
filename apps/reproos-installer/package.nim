## Source-built Qt/QML installer package.
##
## The repository root is the Reprobuild project root. Keep paths in this
## module root-relative so every ReproOS artifact participates in one graph.

import std/os

import repro_project_dsl
import repro_dsl_stdlib/constructors
import repro_dsl_stdlib/types/package_result

const
  ReproosInstallerInstallActionId* = "cmake-install-reproosInstaller"
  ReproosInstallerBinary* =
    "build/reproos-installer/out/usr/bin/reproos-installer"

package reproosInstaller:
  defaultToolProvisioning "from-source"

  versions:
    "0.1.0":
      sourceRevision = "0.1.0"
      sourceUrl = "in-tree:apps/reproos-installer"
      sourceRepository = "https://github.com/metacraft-labs/ReproOS"

  nativeBuildDeps:
    "cmake >=3.16"
    "ninja >=1.10"
    "gcc >=11"

  buildDeps:
    "qt6-base >=6.6"
    "qt6-declarative >=6.6"
    "qt6-tools >=6.6"
    "qt6-quickcontrols2 >=6.6"

  config:
    discard

  executable `reproos-installer`:
    discard

  build:
    setCurrentOwningPackageOverride("reproosInstaller")
    try:
      # These Qt packages live in the federated sibling catalog instead of
      # below this project, so CMake cannot discover their config roots from
      # the installer source directory.
      let qt6SiblingsRoot = block:
        let configured = getEnv("REPRO_FROM_SOURCE_ROOT")
        if configured.len > 0:
          configured
        else:
          parentDir(activeProviderProjectRoot()) /
            "reprobuild-packages" / "packages" / "source"
      let qtBase = packageInstallMirrorCmakeRoot(
        qt6SiblingsRoot, "qt6-base")
      let qtDecl = packageInstallMirrorCmakeRoot(
        qt6SiblingsRoot, "qt6-declarative")
      let qtQc2 = packageInstallMirrorCmakeRoot(
        qt6SiblingsRoot, "qt6-quickcontrols2")
      let opts = @[
        "CMAKE_POLICY_VERSION_MINIMUM=3.16",
        "CMAKE_BUILD_TYPE=Release",
        "CMAKE_MODULE_PATH=" & qtBase & "/Qt6;" &
          qtBase & "/Qt6/platforms",
        "Qt6Qml_DIR=" & qtDecl & "/Qt6Qml",
        "Qt6Quick_DIR=" & qtDecl & "/Qt6Quick",
        "Qt6QmlMeta_DIR=" & qtDecl & "/Qt6QmlMeta",
        "Qt6QmlModels_DIR=" & qtDecl & "/Qt6QmlModels",
        "Qt6QmlWorkerScript_DIR=" & qtDecl & "/Qt6QmlWorkerScript",
        "Qt6QmlIntegration_DIR=" & qtDecl & "/Qt6QmlIntegration",
        "Qt6QuickControls2_DIR=" & qtQc2 & "/Qt6QuickControls2",
        "Qt6QuickTemplates2_DIR=" & qtQc2 & "/Qt6QuickTemplates2",
      ]
      let pkg = cmake_package(
        srcDir = "apps/reproos-installer",
        buildDir = "build/reproos-installer",
        generator = "Ninja",
        cacheVars = opts,
        allowSourceWrites = true)
      discard pkg.executable("reproos-installer")
      discard target("installer", pkg.installEdge)
    finally:
      clearCurrentOwningPackageOverride()

  runtimeDeps:
    discard
