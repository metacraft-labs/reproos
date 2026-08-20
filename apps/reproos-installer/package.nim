## Source-built Qt/QML installer package.
##
## The repository root is the Reprobuild project root. Keep paths in this
## module root-relative so every ReproOS artifact participates in one graph.

import repro_project_dsl
import repro_dsl_stdlib/constructors
import repro_dsl_stdlib/types/package_result

const
  ReproosInstallerReadyActionId* = "install-mirror-reproosInstaller"
  ReproosInstallerBinary* =
    ".repro/output/install/usr/bin/reproos-installer"

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
      let opts = @[
        "CMAKE_POLICY_VERSION_MINIMUM=3.16",
        "CMAKE_BUILD_TYPE=Release",
      ]
      let pkg = cmake_package(
        srcDir = "apps/reproos-installer",
        buildDir = "build/reproos-installer",
        generator = "Ninja",
        cacheVars = opts,
        allowSourceWrites = true)
      discard pkg.executable("reproos-installer")
      discard target("installer",
        BuildActionDef(id: ReproosInstallerReadyActionId))
    finally:
      clearCurrentOwningPackageOverride()

  runtimeDeps:
    discard
