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
  ## running. Start that session after a host reboot when the provisioned
  ## libvirt package is available. This keeps local VM workflows usable on
  ## NixOS and WSL hosts while preserving explicit operator configuration and
  ## system-libvirt defaults.
  ## Host VM tools must resolve libraries from the host ABI, not the source
  ## package closure used by ReproOS build actions.
  ## These no-op references declare overrides consumed by nested scripts as
  ## reprobuild environment passthroughs.
  ": \"${REPROOS_VM_STATE_DIR:-}\" \"${REPROOS_VM_BACKEND:-}\" " &
    "\"${REPROOS_VM_ACCELERATION:-}\" \"${REPROOS_UNATTENDED_ISO:-}\" " &
    "\"${REPROOS_VM_HARNESS_BIN:-}\" \"${VM_HARNESS_BIN:-}\" " &
    "\"${GUI_ASSERT_ROOT:-}\" \"${SSH_KEYGEN_BIN:-}\" " &
    "\"${XORRISO_BIN:-}\"; " &
    "if [ \"$(uname -s 2>/dev/null || true)\" = Linux ] && " &
    "[ -z \"${LIBVIRT_DEFAULT_URI:-}\" ] && " &
    "[ ! -S /run/libvirt/libvirt-sock ] && " &
    "[ ! -S /run/libvirt/virtqemud-sock ]; then " &
    "runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$UID}; " &
    "session_sock=$runtime_dir/libvirt/libvirt-sock; " &
    "if [ ! -S \"$session_sock\" ]; then " &
    "command -v libvirtd >/dev/null 2>&1 || { " &
    "echo 'ReproOS VM workflow: libvirtd is unavailable' >&2; exit 69; }; " &
    "mkdir -p \"$runtime_dir/libvirt\" \"$HOME/.config/libvirt\" " &
    "\"$HOME/.cache/libvirt\" \"$HOME/.local/share/libvirt\"; " &
    "libvirtd -d; i=0; while [ ! -S \"$session_sock\" ] && " &
    "[ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done; fi; " &
    "[ -S \"$session_sock\" ] || { " &
    "echo 'ReproOS VM workflow: libvirt session did not start' >&2; " &
    "exit 69; }; export XDG_RUNTIME_DIR=\"$runtime_dir\"; " &
    "export LIBVIRT_DEFAULT_URI=qemu:///session; fi; " &
    "unset LD_LIBRARY_PATH DYLD_LIBRARY_PATH; " & command

package reproosWorkflows:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "bash"
    "cpio"
    "find"
    "gzip"
    "sed"
    "python3"
    "vm-harness"
    "openssh"
    "xorriso"

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

    let testRemoteAccessConfiguration = shell(
      command = "python3 tests/test_machine_config.py " &
        "MachineConfigurationTests." &
        "test_remote_access_configuration_validation",
      actionId = "reproos.test-remote-access-configuration",
      extraInputs = @[
        "tests/test_machine_config.py",
        "tools/reproos-machine-config.py",
        "tests/fixtures/auto-config-minimal.toml",
        "recipes/reproos-image/scripts/reproos-first-boot-enroll",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test_remote_access_configuration_validation",
      testRemoteAccessConfiguration)

    let testInstanceSecretsCacheKey = shell(
      command = "python3 tests/test_machine_config.py " &
        "MachineConfigurationTests." &
        "test_instance_secrets_do_not_affect_public_image_cache_key",
      actionId = "reproos.test-instance-secrets-cache-key",
      extraInputs = @[
        "tests/test_machine_config.py",
        "tools/reproos-machine-config.py",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/fixtures/instance-enrollment.toml",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test_instance_secrets_do_not_affect_public_image_cache_key",
      testInstanceSecretsCacheKey)

    let testReproosVmWorkflow = shell(
      command = "python3 tests/test_reproos_vm.py",
      actionId = "reproos.test-vm-install-workflow",
      extraInputs = @[
        "tests/test_reproos_vm.py",
        "tools/reproos-vm.py",
        "apps/reproos-installer/src/installer_state.cpp",
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test_unattended_vm_rejects_live_media_false_positive",
      testReproosVmWorkflow)

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

    let testIncusPublication = shell(
      command = "python3 tests/test_incus_publication.py",
      actionId = "reproos.test-incus-publication",
      extraInputs = @[
        "tests/test_incus_publication.py",
        "tools/reproos-incus-publication.py",
      ],
      cacheable = false).withToolIdentities(["python3", "openssh"])
    discard target("test-incus-publication", testIncusPublication)

    let testIncusSecondHost = shell(
      command = "bash tests/test-incus-second-host.sh",
      actionId = "reproos.test-incus-second-host",
      extraInputs = @[
        "tests/test-incus-second-host.sh",
        "tests/remote-incus-acceptance.sh",
        "tools/reproos-incus-publication.py",
      ],
      cacheable = false).withToolIdentities(["bash", "openssh"])
    discard target("test-incus-second-host", testIncusSecondHost)

    let testVmIncusParityChecker = shell(
      command = "python3 tests/test_vm_incus_parity_checker.py",
      actionId = "reproos.test-vm-incus-parity-checker",
      extraInputs = @[
        "tests/test_vm_incus_parity_checker.py",
        "tests/check_vm_incus_parity.py",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
      ],
      cacheable = false).withToolIdentities(["python3"])
    discard target("test-vm-incus-parity-checker", testVmIncusParityChecker)

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

    let publishIncus = shell(
      command = "python3 tools/reproos-incus-publication.py publish \"$@\"",
      args = @["reproos-incus-publish"],
      actionId = "reproos.incus-publish",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @["tools/reproos-incus-publication.py"],
      cacheable = false).withToolIdentities(["python3", "openssh"])
    run("incus-publish", build = publishIncus.id,
      owningPackage = "reproosWorkflows")

    let pullIncus = shell(
      command = "python3 tools/reproos-incus-publication.py pull \"$@\"",
      args = @["reproos-incus-pull"],
      actionId = "reproos.incus-pull",
      extraInputs = @["tools/reproos-incus-publication.py"],
      cacheable = false).withToolIdentities(["python3", "openssh"])
    run("incus-pull", build = pullIncus.id,
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

    let testIncusParallelIsolation = shell(
      command = "bash tests/test-incus-parallel-isolation.sh",
      actionId = "reproos.test-incus-parallel-isolation",
      deps = @[containerPackage.ReproosIncusImageActionId],
      extraInputs = @[
        "tests/test-incus-parallel-isolation.sh",
        "tools/reproos-incus.sh",
      ],
      cacheable = false).withToolIdentities(["bash", "vm-harness"])
    discard target("test-incus-parallel-isolation", testIncusParallelIsolation)

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

    let installVm = shell(
      command = withHostVmRuntime(
        "python3 tools/reproos-vm.py install \"$@\""),
      args = @["reproos-vm-install"],
      actionId = "reproos.vm-install",
      deps = @[isoPackage.ReproosUnattendedIsoBuildActionId],
      extraInputs = @[
        "tools/reproos-vm.py",
        "tests/fixtures/auto-config-minimal.toml",
      ],
      cacheable = false).withToolIdentities([
        "python3", "vm-harness", "openssh", "xorriso",
      ])
    run("vm-install", build = installVm.id,
      owningPackage = "reproosWorkflows")

    let verifyInstalledVmBoot = shell(
      command = withHostVmRuntime(
        "python3 tools/reproos-vm.py verify-installed-boot \"$@\""),
      args = @["reproos-vm-verify-installed-boot"],
      actionId = "reproos.vm-verify-installed-boot",
      extraInputs = @["tools/reproos-vm.py"],
      cacheable = false).withToolIdentities(["python3", "vm-harness"])
    run("vm-verify-installed-boot", build = verifyInstalledVmBoot.id,
      owningPackage = "reproosWorkflows")

    let sshInstalledVm = shell(
      command = withHostVmRuntime(
        "python3 tools/reproos-vm.py ssh \"$@\""),
      args = @["reproos-vm-ssh"],
      actionId = "reproos.vm-ssh",
      extraInputs = @["tools/reproos-vm.py"],
      cacheable = false).withToolIdentities(["python3", "vm-harness"])
    run("vm-ssh", build = sshInstalledVm.id,
      owningPackage = "reproosWorkflows")

    let e2eUnattendedVmInstall = shell(
      command = withHostVmRuntime(
        "bash tests/e2e-unattended-vm-installs.sh"),
      actionId = "reproos.e2e-unattended-vm-install",
      deps = @[isoPackage.ReproosUnattendedIsoBuildActionId],
      extraInputs = @[
        "tests/e2e-unattended-vm-installs.sh",
        "tests/test-installed-desktop-frame.sh",
        "tests/test_installed_desktop_frame.nim",
        "tools/reproos-vm.py",
        "tests/fixtures/auto-config-minimal.toml",
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "vm-harness", "openssh", "xorriso",
      ])
    discard target("e2e_unattended_vm_installs_and_boots_target_disk",
      e2eUnattendedVmInstall)

    let testVmSshHostKeyMismatch = shell(
      command = withHostVmRuntime(
        "bash tests/test-vm-ssh-host-key-mismatch.sh"),
      actionId = "reproos.test-vm-ssh-host-key-mismatch",
      deps = @[e2eUnattendedVmInstall.id],
      extraInputs = @[
        "tests/test-vm-ssh-host-key-mismatch.sh",
        "tools/reproos-vm.py",
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "vm-harness", "openssh",
      ])
    discard target("test_vm_ssh_host_key_mismatch_fails_closed",
      testVmSshHostKeyMismatch)

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
        "cpio",
        "dosfstools",
        "find",
        "gawk",
        "gzip",
        "grub",
        "kernel",
        "kmod",
        "mtools",
        "sed",
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
      testRemoteAccessConfiguration,
      testInstanceSecretsCacheKey,
      testReproosVmWorkflow,
      testCacheBackfill,
      testIncusProjection,
      testIncusHelper,
      testIncusPublication,
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
      testIncusPublication,
      testVmIncusParityChecker,
      testIncusReproducibility,
      testIncusLifecycle,
      testIncusParallelIsolation,
      testVmIncusParity,
    ])

    discard collect("incus-remote-acceptance", actions = @[
      testIncusPublication,
      testIncusSecondHost,
    ])
