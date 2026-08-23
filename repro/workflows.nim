## Automated checks and interactive ReproOS development workflows.

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import repro_resources/run_edge

import "../apps/reproos-installer/package" as installerPackage
import "../recipes/reproos-iso/package" as isoPackage
import "../recipes/reproos-image/package" as imagePackage
import "../recipes/reproos-container/package" as containerPackage

proc withToolIdentities(action: BuildActionDef;
                        tools: openArray[string]): BuildActionDef =
  appendRegisteredActionToolIdentityRefs(action.id, tools)
  action

proc withHostVmRuntime(command: string): string =
  ## Prefer an available unprivileged libvirt session when no system daemon is
  ## running. This keeps local VM workflows usable on NixOS and WSL hosts while
  ## preserving explicit operator configuration and system-libvirt defaults.
  "if [ -z \"${LIBVIRT_DEFAULT_URI:-}\" ] && " &
    "[ -S \"/run/user/$UID/libvirt/libvirt-sock\" ] && " &
    "[ ! -S /run/libvirt/libvirt-sock ] && " &
    "[ ! -S /run/libvirt/virtqemud-sock ]; then " &
    "export LIBVIRT_DEFAULT_URI=qemu:///session; fi; " & command

package reproosWorkflows:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "bash"
    "python3"
    "vm-harness"
    "openssh"

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
      deps = @[installerPackage.ReproosInstallerReadyActionId],
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
      deps = @[installerPackage.ReproosInstallerReadyActionId],
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
      deps = @[installerPackage.ReproosInstallerReadyActionId],
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
      deps = @[installerPackage.ReproosInstallerReadyActionId],
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

    let inspectInstallerVmFrame = shell(
      command = "bash tests/test-installer-vm-frame.sh \"$@\"",
      args = @["reproos-installer-vm-frame"],
      actionId = "reproos.inspect-installer-vm-frame",
      extraInputs = @[
        "tests/test-installer-vm-frame.sh",
        "tests/test_installer_vm_frame.nim",
      ],
      cacheable = false).withToolIdentities(["bash"])
    run("installer-vm-frame", build = inspectInstallerVmFrame.id,
      owningPackage = "reproosWorkflows")

    let captureInstallerVmScreenshot = shell(
      command = withHostVmRuntime(
        "bash tests/test-installer-vm-screenshot.sh \"$@\""),
      args = @["reproos-installer-vm-screenshot"],
      actionId = "reproos.capture-installer-vm-screenshot",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      extraInputs = @[
        "tests/test-installer-vm-screenshot.sh",
        "tests/test-installer-vm-frame.sh",
        "tests/test_installer_vm_frame.nim",
      ],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("installer-vm-screenshot", build = captureInstallerVmScreenshot.id,
      owningPackage = "reproosWorkflows")

    let testInstallerArtifacts = shell(
      command = "bash tests/test-installer-artifacts.sh",
      actionId = "reproos.test-installer-artifacts",
      deps = @[installerPackage.ReproosInstallerReadyActionId],
      extraInputs = @[
        "tests/test-installer-artifacts.sh",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
      ],
      cacheable = false).withToolIdentities(["bash"])
    discard target("test-installer-artifacts", testInstallerArtifacts)

    let cacheBackfill = shell(
      command = "python3 tools/cache_reproos_packages.py \"$@\"",
      args = @["reproos-cache-backfill"],
      actionId = "reproos.cache-source-packages",
      deps = @[sourceComposition.id],
      extraInputs = @[
        "tools/cache_reproos_packages.py",
        "tests/check_source_composition.py",
        "repro/package_sets.nim",
      ],
      cacheable = false).withToolIdentities(["python3"])
    run("cache-backfill", build = cacheBackfill.id,
      owningPackage = "reproosWorkflows")

    let testCacheBackfill = shell(
      command = "python3 tests/test_cache_reproos_packages.py",
      actionId = "reproos.test-cache-backfill",
      extraInputs = @[
        "tests/test_cache_reproos_packages.py",
        "tools/cache_reproos_packages.py",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test-cache-backfill", testCacheBackfill)

    let testIncusProjection = shell(
      command = "python3 tests/test_incus_projection.py",
      actionId = "reproos.test-incus-projection",
      extraInputs = @[
        "tests/test_incus_projection.py",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
        "recipes/reproos-container/scripts/project-incus-config.py",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test-incus-projection", testIncusProjection)

    let testIncusHelper = shell(
      command = "python3 tests/test_reproos_incus_helper.py",
      actionId = "reproos.test-incus-helper",
      extraInputs = @[
        "tests/test_reproos_incus_helper.py",
        "tools/reproos-incus.sh",
      ],
      cacheable = false).withToolIdentities(["python3", "bash"])
    discard target("test-incus-helper", testIncusHelper)

    let importIncus = shell(
      command = "bash tools/reproos-incus.sh import",
      actionId = "reproos.incus-import",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @["tools/reproos-incus.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("incus-import", build = importIncus.id,
      owningPackage = "reproosWorkflows")

    let launchIncus = shell(
      command = "bash tools/reproos-incus.sh launch",
      actionId = "reproos.incus-launch",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @["tools/reproos-incus.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("incus-launch", build = launchIncus.id,
      owningPackage = "reproosWorkflows")

    let shellIncus = shell(
      command = "bash tools/reproos-incus.sh shell",
      actionId = "reproos.incus-shell",
      extraInputs = @["tools/reproos-incus.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("incus-shell", build = shellIncus.id,
      owningPackage = "reproosWorkflows")

    let logsIncus = shell(
      command = "bash tools/reproos-incus.sh logs",
      actionId = "reproos.incus-logs",
      extraInputs = @["tools/reproos-incus.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("incus-logs", build = logsIncus.id,
      owningPackage = "reproosWorkflows")

    let destroyIncus = shell(
      command = "bash tools/reproos-incus.sh destroy",
      actionId = "reproos.incus-destroy",
      extraInputs = @["tools/reproos-incus.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("incus-destroy", build = destroyIncus.id,
      owningPackage = "reproosWorkflows")

    let testIncusLifecycle = shell(
      command = "bash tests/test-incus-lifecycle.sh",
      actionId = "reproos.test-incus-lifecycle",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @[
        "tests/test-incus-lifecycle.sh",
        "tools/reproos-incus.sh",
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "vm-harness", "openssh",
      ])
    discard target("test-incus-lifecycle", testIncusLifecycle)

    let testIncusReproducibility = shell(
      command = "bash tests/test-incus-image-reproducibility.sh",
      actionId = "reproos.test-incus-reproducibility",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @[
        "tests/test-incus-image-reproducibility.sh",
        "recipes/reproos-container/scripts/build-incus-image.sh",
        containerPackage.ReproosIncusProjectionOutput,
        isoPackage.ReproosIsoRootfsOutput,
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "tar", "xz",
      ])
    discard target("test-incus-reproducibility", testIncusReproducibility)

    let testVmIncusParity = shell(
      command = withHostVmRuntime(
        "bash tests/test-vm-incus-parity.sh"),
      actionId = "reproos.test-vm-incus-parity",
      deps = @[
        imagePackage.ReproosImageBuildActionId,
        containerPackage.ReproosIncusImageActionId,
      ],
      extraInputs = @[
        "tests/test-vm-incus-parity.sh",
        "tests/check_vm_incus_parity.py",
        "tests/test-installed-ssh.sh",
        "tools/reproos-incus.sh",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
        containerPackage.ReproosIncusProjectionOutput,
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "vm-harness", "openssh",
      ])
    discard target("test-vm-incus-parity", testVmIncusParity)

    let bootIso = shell(
      command = withHostVmRuntime(
        "vm-harness boot --backend auto --source-image \"" &
        isoPackage.ReproosIsoOutput &
        "\" --kind iso --generation 2 --graphics vnc --video virtio " &
        "--viewer \"$@\""),
      args = @["reproos-boot-iso"],
      actionId = "reproos.boot-iso",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    run("boot-iso", build = bootIso.id,
      owningPackage = "reproosWorkflows")

    let testIso = shell(
      command = withHostVmRuntime(
        "vm-harness boot --backend auto --source-image \"" &
        isoPackage.ReproosIsoOutput &
        "\" --kind iso --expect \"Linux version\" --timeout-sec 300"),
      actionId = "reproos.test-iso",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    discard target("test-iso", testIso)

    let testIsoReproducibility = shell(
      command = "bash tests/test-iso-reproducibility.sh",
      actionId = "reproos.test-iso-reproducibility",
      deps = @[isoPackage.ReproosIsoBuildActionId],
      extraInputs = @[
        "tests/test-iso-reproducibility.sh",
        isoPackage.ReproosIsoRootfsOutput,
        isoPackage.ReproosIsoOutput,
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init",
      ],
      cacheable = false).withToolIdentities([
        "bash",
        "busybox",
        "coreutils",
        "dosfstools",
        "gawk",
        "grub",
        "kernel",
        "kmod",
        "mtools",
        "squashfs-tools",
        "xz",
        "xorriso",
        "zstd",
      ])
    discard target("test-iso-reproducibility", testIsoReproducibility)

    let bootImage = shell(
      command = withHostVmRuntime(
        "vm-harness boot --backend auto --source-image \"" &
        imagePackage.ReproosImageOutput &
        "\" --kind qcow2 --generation 2 --graphics vnc --video virtio " &
        "--viewer \"$@\""),
      args = @["reproos-boot-image"],
      actionId = "reproos.boot-image",
      deps = @[imagePackage.ReproosImageBuildActionId],
      cacheable = false).withToolIdentities(["vm-harness"])
    run("boot-image", build = bootImage.id,
      owningPackage = "reproosWorkflows")

    let testImageHealth = shell(
      command = withHostVmRuntime(
        "bash tests/test-installed-image-health.sh"),
      actionId = "reproos.test-image-health",
      deps = @[imagePackage.ReproosImageBuildActionId],
      extraInputs = @["tests/test-installed-image-health.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-image-health", testImageHealth)

    let testInstalledDesktop = shell(
      command = withHostVmRuntime(
        "bash tests/test-installed-desktop-screenshot.sh"),
      actionId = "reproos.test-installed-desktop",
      deps = @[imagePackage.ReproosImageBuildActionId],
      extraInputs = @[
        "tests/test-installed-desktop-screenshot.sh",
        "tests/test-installed-desktop-frame.sh",
        "tests/test_installed_desktop_frame.nim",
      ],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-installed-desktop", testInstalledDesktop)

    let sshImage = shell(
      command = withHostVmRuntime(
        "bash tests/test-installed-ssh.sh \"$@\""),
      args = @["reproos-image-ssh"],
      actionId = "reproos.image-ssh",
      deps = @[imagePackage.ReproosImageBuildActionId],
      extraInputs = @["tests/test-installed-ssh.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    run("image-ssh", build = sshImage.id,
      owningPackage = "reproosWorkflows")

    let testInstalledSsh = shell(
      command = withHostVmRuntime(
        "bash tests/test-installed-ssh.sh"),
      actionId = "reproos.test-installed-ssh",
      deps = @[imagePackage.ReproosImageBuildActionId],
      extraInputs = @["tests/test-installed-ssh.sh"],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-installed-ssh", testInstalledSsh)

    let testUnattendedInstall = shell(
      command = "bash tests/test-unattended-install.sh",
      actionId = "reproos.test-unattended-install",
      deps = @[
        installerPackage.ReproosInstallerReadyActionId,
        imagePackage.ReproosImageBuildActionId,
        testInstalledSsh.id,
      ],
      extraInputs = @[
        "tests/test-unattended-install.sh",
        "tests/fixtures/auto-config-minimal.toml",
      ],
      cacheable = false).withToolIdentities(["bash"])
    discard target("test-unattended-install", testUnattendedInstall)

    discard target("test-source-composition", sourceComposition)
    discard collect("lint", actions = @[sourceComposition])

    discard collect("test", actions = @[
      sourceComposition,
      testInstallerPreview,
      testInstallerVisuals,
      testInstallerArtifacts,
      testCacheBackfill,
      testIncusProjection,
      testIncusHelper,
      testIsoReproducibility,
      testIso,
      testImageHealth,
      testInstalledDesktop,
      testInstalledSsh,
      testUnattendedInstall,
    ])

    discard collect("incus-acceptance", actions = @[
      testIncusProjection,
      testIncusHelper,
      testIncusReproducibility,
      testIncusLifecycle,
      testVmIncusParity,
    ])
