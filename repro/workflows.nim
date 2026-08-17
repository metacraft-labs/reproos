## Automated checks and interactive ReproOS development workflows.

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import repro_resources/run_edge

import "../apps/reproos-installer/package" as installerPackage
import "../recipes/reproos-iso/package" as isoPackage
import "../recipes/reproos-image/package" as imagePackage

proc withToolIdentities(action: BuildActionDef;
                        tools: openArray[string]): BuildActionDef =
  appendRegisteredActionToolIdentityRefs(action.id, tools)
  action

package reproosWorkflows:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "bash"
    "python3"
    "vm_harness"

  build:
    let sourceComposition = shell(
      command = "python3 tests/check_source_composition.py",
      actionId = "reproos.check-source-composition",
      extraInputs = @[
        "tests/check_source_composition.py",
        "AGENTS.md",
        "README.md",
        "repro.nim",
        "apps/reproos-installer/package.nim",
        "recipes/reproos-iso/package.nim",
        "recipes/reproos-image/package.nim",
        "repro/workflows.nim",
        "repro/package_sets.nim",
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/scripts/normalize-source-runtime.sh",
        "recipes/reproos-iso/scripts/build-base-rootfs.sh",
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "apps/reproos-installer/qml/main.qml",
        "apps/reproos-installer/qml/screens/DeSelect.qml",
        "apps/reproos-installer/qml/screens/Activities.qml",
      ],
      cacheable = false).withToolIdentities(["python3"])

    let installerScreenshots = shell(
      command = "bash tools/capture-installer-screens.sh --no-build \"$@\"",
      args = @["reproos-installer-screenshots"],
      actionId = "reproos.capture-installer-screens",
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "tools/capture-installer-screens.sh",
        "tools/installer-dev-runtime.sh",
      ],
      cacheable = false).withToolIdentities(["bash"])
    run("installer-screenshots", build = installerScreenshots.id,
      owningPackage = "reproosWorkflows")

    let previewInstaller = shell(
      command = "bash tools/run-installer-preview.sh --no-build \"$@\"",
      args = @["reproos-installer-preview"],
      actionId = "reproos.preview-installer",
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "tools/run-installer-preview.sh",
        "tools/installer-dev-runtime.sh",
      ],
      cacheable = false).withToolIdentities(["bash"])
    run("installer", build = previewInstaller.id,
      owningPackage = "reproosWorkflows")

    let testInstallerPreview = shell(
      command = "bash tests/test-installer-preview.sh",
      actionId = "reproos.test-installer-preview",
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "tests/test-installer-preview.sh",
        "tools/installer-dev-runtime.sh",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts/auto-config.toml",
      ],
      cacheable = false).withToolIdentities(["bash"])
    discard target("test-installer-preview", testInstallerPreview)

    let testInstallerVisuals = shell(
      command = "bash tests/test-installer-visuals.sh \"$@\"",
      args = @["reproos-installer-visuals"],
      actionId = "reproos.test-installer-visuals",
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "tests/test-installer-visuals.sh",
        "tests/test_installer_visuals.nim",
        "tools/capture-installer-screens.sh",
        "tools/installer-dev-runtime.sh",
        "tests/golden/installer-screens",
      ],
      cacheable = false).withToolIdentities(["bash"])
    discard target("test-installer-visuals", testInstallerVisuals)
    run("installer-accept-goldens", build = testInstallerVisuals.id,
      args = @["--update-goldens"], owningPackage = "reproosWorkflows")

    let testInstallerArtifacts = shell(
      command = "bash tests/test-installer-artifacts.sh",
      actionId = "reproos.test-installer-artifacts",
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "tests/test-installer-artifacts.sh",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
      ],
      cacheable = false).withToolIdentities(["bash"])
    discard target("test-installer-artifacts", testInstallerArtifacts)

    let bootIso = shell(
      command = "vm-harness boot --backend auto --source-image \"" &
        isoPackage.ReproosIsoOutput & "\" --kind iso --keep \"$@\"",
      args = @["reproos-boot-iso"],
      actionId = "reproos.boot-iso",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    run("boot-iso", build = bootIso.id,
      owningPackage = "reproosWorkflows")

    let testIso = shell(
      command = "vm-harness boot --backend auto --source-image \"" &
        isoPackage.ReproosIsoOutput &
        "\" --kind iso --expect \"Linux version\" --timeout-sec 300",
      actionId = "reproos.test-iso",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    discard target("test-iso", testIso)

    let bootImage = shell(
      command = "vm-harness boot --backend auto --source-image \"" &
        imagePackage.ReproosImageOutput & "\" --kind qcow2 --keep \"$@\"",
      args = @["reproos-boot-image"],
      actionId = "reproos.boot-image",
      deps = @[imagePackage.ReproosImageBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    run("boot-image", build = bootImage.id,
      owningPackage = "reproosWorkflows")

    let testImageHealth = shell(
      command = "bash tests/test-installed-image-health.sh",
      actionId = "reproos.test-image-health",
      deps = @[imagePackage.ReproosImageBuildActionId],
      extraInputs = @["tests/test-installed-image-health.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-image-health", testImageHealth)

    let testUnattendedInstall = shell(
      command = "bash tests/test-unattended-install.sh",
      actionId = "reproos.test-unattended-install",
      deps = @[
        installerPackage.ReproosInstallerInstallActionId,
        imagePackage.ReproosImageBuildActionId,
      ],
      extraInputs = @[
        "tests/test-unattended-install.sh",
        "tests/test-installed-image-health.sh",
        "tests/fixtures/auto-config-minimal.toml",
      ],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-unattended-install", testUnattendedInstall)

    discard target("test-source-composition", sourceComposition)
    discard collect("lint", actions = @[sourceComposition])

    discard collect("test", actions = @[
      sourceComposition,
      testInstallerPreview,
      testInstallerVisuals,
      testInstallerArtifacts,
      testIso,
      testImageHealth,
      testUnattendedInstall,
    ])
