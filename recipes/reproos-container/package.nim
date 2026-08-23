## Native ReproOS Incus system-container image.
##
## Configuration projection is a small independent output. Image assembly
## consumes that projection and the same cached source-only rootfs used by the
## ISO and installed VM image.

import std/[os, strutils]

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import "../../apps/reproos-installer/package" as installerPackage
import "../reproos-iso/package" as isoPackage

const
  ReproosIncusProjectionActionId* =
    "reproosContainer.project_configuration"
  ReproosIncusProjectionOutput* =
    "recipes/reproos-container/build/projection"
  ReproosIncusImageActionId* = "reproosContainer.build_image"
  ReproosIncusImageOutput* =
    "recipes/reproos-container/build/reproos-incus.tar.xz"
  ReproosIncusBundleManifest* =
    "recipes/reproos-container/build/incus-baseline.manifest"

package reproosContainer:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "bash"
    "python3"
    "tar"
    "xz"

  build:
    let projectRoot = activeProviderProjectRoot()
    let projectionCommand = @[
      "set -euo pipefail;",
      "rm -rf build/projection;",
      "mkdir -p build/projection/artifacts;",
      "CONFIG=\"${REPRO_AUTO_CONFIG:-../../tests/fixtures/auto-config-minimal.toml}\";",
      "../../" & installerPackage.ReproosInstallerBinary &
        " --config \"$CONFIG\" --emit-artifacts build/projection/artifacts;",
      "python3 scripts/project-incus-config.py" &
        " --config build/projection/artifacts/auto-config.toml" &
        " --artifacts-dir build/projection/artifacts" &
        " --output-dir build/projection;",
    ].join(" ")
    let projectionAction = shell(
      command = projectionCommand,
      actionId = ReproosIncusProjectionActionId,
      deps = @[installerPackage.ReproosInstallerReadyActionId],
      actionCachePolicy = acfpHybrid,
      extraInputs = @[
        "recipes/reproos-container/scripts/project-incus-config.py",
        "tests/fixtures/auto-config-minimal.toml",
        installerPackage.ReproosInstallerBinary,
      ],
      extraOutputs = @["build/projection"])
    appendRegisteredActionToolIdentityRefs(projectionAction.id,
      @["python3"])
    setRegisteredActionCwd(projectionAction.id, acwdCustom,
      "recipes/reproos-container")
    let projectionOutputAbs = projectRoot / ReproosIncusProjectionOutput
    setRegisteredActionDependencyPolicy(projectionAction.id,
      automaticMonitorPolicy(@[projectionOutputAbs]))
    discard target("incus-projection", projectionAction)

    let imageCommand = @[
      "set -euo pipefail;",
      "bash scripts/build-incus-image.sh" &
        " ../reproos-iso/build/de-rootfs" &
        " build/projection" &
        " build/reproos-incus.tar.xz" &
        " build/incus-baseline.manifest;",
    ].join(" ")
    let imageAction = shell(
      command = imageCommand,
      actionId = ReproosIncusImageActionId,
      deps = @[
        isoPackage.ReproosIsoRootfsActionId,
        projectionAction.id,
      ],
      actionCachePolicy = acfpHybrid,
      extraInputs = @[
        isoPackage.ReproosIsoRootfsOutput,
        ReproosIncusProjectionOutput,
        "recipes/reproos-container/scripts/build-incus-image.sh",
        "recipes/reproos-container/scripts/project-incus-config.py",
      ],
      extraOutputs = @[
        "build/reproos-incus.tar.xz",
        "build/incus-baseline.manifest",
        "build/reproos-incus.sha256",
      ])
    appendRegisteredActionToolIdentityRefs(imageAction.id,
      @["bash", "python3", "tar", "xz"])
    setRegisteredActionCwd(imageAction.id, acwdCustom,
      "recipes/reproos-container")
    let imageBuildDirAbs = projectRoot /
      "recipes/reproos-container/build"
    setRegisteredActionDependencyPolicy(imageAction.id,
      automaticMonitorPolicy(@[imageBuildDirAbs]))
    discard target("incus-image", imageAction)
