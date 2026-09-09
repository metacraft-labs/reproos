## Automated checks and interactive ReproOS development workflows.

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import repro_dsl_stdlib/packages/nix
# The Nim-based gates below compile and run a Nim test through
# tests/nim-gate.sh. Their provisioning metadata has to be REGISTERED, not
# merely named: `toInterfaceToolUse` copies the provisioning block off the
# package whose name matches the `uses:` selector, and it only sees packages
# whose module was imported before `package reproosWorkflows:` fires. Without
# these imports the selectors below resolve to nothing and the plan dies with
# "no stdlib provisioning channel declared on the tool use".
#
# None of `nim`, `clang`, `git` or `mkdir` has a sibling from-source recipe in
# reprobuild-packages, so under this project's `defaultToolProvisioning
# "from-source"` each falls through to the pinned-nixpkgs channel these modules
# declare. That is the whole reason `clang` is the declared C/C++ compiler
# rather than `gcc`: reprobuild-packages DOES carry a from-source `gcc`, and
# naming it would make every always-on gate bootstrap a GCC before it could
# run.
import repro_dsl_stdlib/packages/nim
import repro_dsl_stdlib/packages/clang
import repro_dsl_stdlib/packages/git
# `mkdir` (and the rest of the coreutils command names) live here.
import repro_dsl_stdlib/packages/host_system_tools
import repro_resources/run_edge
import ./image_metadata_tools

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
  "unset LD_LIBRARY_PATH DYLD_LIBRARY_PATH; " &
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
    "export LIBVIRT_DEFAULT_URI=qemu:///session; fi; " & command

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
    "mksquashfs"
    "unsquashfs"
    "nix"
    "vm-harness"
    "ssh"
    "ssh-keygen"
    "xorriso"
    # The Nim-gate tool set. `nim` compiles every tests/test_*.nim gate and
    # `mkdir` creates its build directory. `clang` is the compiler those
    # gates compile WITH -- `nim c` lowers Nim to C and shells out to a C
    # compiler, and the installer parity gate additionally compiles the
    # shipped disk_layouts.cpp as `c++`; both come out of the same clang
    # bin directory. `git` lets the disk-layout gate re-derive its golden
    # from an earlier revision of the driver instead of skipping that
    # case. A `uses:` entry is necessary but NOT sufficient -- the
    # action has to name it too,
    # which is what the .withToolIdentities([...]) calls below do.
    "nim"
    "mkdir"
    "clang"
    "git"

  devEnv:
    useTool("python3")
    useTool("vm-harness")
    useTool("ssh")
    task("vm-ssh",
      command = withHostVmRuntime("python3 tools/reproos-vm.py ssh --"),
      description = "Open an interactive shell in the retained installed VM")
    task("vm-exec",
      command = withHostVmRuntime("python3 tools/reproos-vm.py exec --"),
      description = "Execute a command in the retained installed VM")
    task("vm-status",
      command = withHostVmRuntime("python3 tools/reproos-vm.py status"),
      description = "Inspect installed VM identity and runtime state")
    task("vm-logs",
      command = withHostVmRuntime("python3 tools/reproos-vm.py logs"),
      description = "Read retained installed VM serial output")
    task("vm-stop",
      command = withHostVmRuntime("python3 tools/reproos-vm.py stop"),
      description = "Stop the installed VM and preserve its writable disk")
    task("vm-destroy",
      command = withHostVmRuntime("python3 tools/reproos-vm.py destroy"),
      description = "Remove installed VM runtime and preserve persistent state")

  build:
    let sourceComposition = shell(
      command = "python3 tests/check_source_composition.py",
      actionId = "reproos.check-source-composition",
      extraInputs = @[
        "tests/check_source_composition.py",
        "tools/reproos_image_metadata.py",
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
        "recipes/reproos-image/scripts/configure-installed-root.sh",
        "recipes/reproos-image/scripts/stage-installed-root.sh",
        "recipes/reproos-image/scripts/image-config.sh",
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
      cacheable = false).withToolIdentities(["bash", "nix"])
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
      cacheable = false).withToolIdentities(["bash", "nix"])
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
      cacheable = false).withToolIdentities(["bash", "nix", "vm-harness"])
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
      cacheable = false).withToolIdentities(["python3", "ssh", "ssh-keygen"])
    discard target("test-incus-publication", testIncusPublication)

    let testIncusSecondHost = shell(
      command = "bash tests/test-incus-second-host.sh",
      actionId = "reproos.test-incus-second-host",
      extraInputs = @[
        "tests/test-incus-second-host.sh",
        "tests/remote-incus-acceptance.sh",
        "tools/reproos-incus-publication.py",
      ],
      cacheable = false).withToolIdentities(["bash", "ssh", "ssh-keygen"])
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
      cacheable = false).withToolIdentities(["python3", "ssh", "ssh-keygen"])
    run("incus-publish", build = publishIncus.id,
      owningPackage = "reproosWorkflows")

    let pullIncus = shell(
      command = "python3 tools/reproos-incus-publication.py pull \"$@\"",
      args = @["reproos-incus-pull"],
      actionId = "reproos.incus-pull",
      extraInputs = @["tools/reproos-incus-publication.py"],
      cacheable = false).withToolIdentities(["python3", "ssh", "ssh-keygen"])
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
        "bash", "python3", "vm-harness", "ssh", "ssh-keygen",
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
        "bash", "python3", "vm-harness", "ssh", "ssh-keygen",
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
        "python3", "vm-harness", "ssh", "ssh-keygen", "xorriso",
      ])
    run("vm-install", build = installVm.id,
      owningPackage = "reproosWorkflows")

    let installedVm = shell(
      command = withHostVmRuntime(
        "python3 tools/reproos-vm.py installed \"$@\""),
      args = @["reproos-vm-installed"],
      actionId = "reproos.vm-installed",
      deps = @[isoPackage.ReproosUnattendedIsoBuildActionId],
      extraInputs = @[
        "tools/reproos-vm.py",
        "tests/fixtures/auto-config-minimal.toml",
      ],
      cacheable = false).withToolIdentities([
        "python3", "vm-harness", "ssh", "ssh-keygen", "xorriso",
      ])
    run("vm-installed", build = installedVm.id,
      owningPackage = "reproosWorkflows")

    let verifyInstalledVmBoot = shell(
      command = withHostVmRuntime(
        "python3 tools/reproos-vm.py verify-installed-boot \"$@\""),
      args = @["reproos-vm-verify-installed-boot"],
      actionId = "reproos.vm-verify-installed-boot",
      extraInputs = @["tools/reproos-vm.py"],
      cacheable = false).withToolIdentities([
        "python3", "vm-harness", "ssh", "ssh-keygen",
      ])
    run("vm-verify-installed-boot", build = verifyInstalledVmBoot.id,
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
        "bash", "python3", "nix", "vm-harness", "ssh", "ssh-keygen", "xorriso",
      ])
    discard target("e2e_unattended_vm_installs_and_boots_target_disk",
      e2eUnattendedVmInstall)

    let e2eVmPersistentLifecycle = shell(
      command = withHostVmRuntime(
        "python3 tests/test-vm-persistent-lifecycle.py"),
      actionId = "reproos.e2e-vm-persistent-lifecycle",
      deps = @[e2eUnattendedVmInstall.id],
      extraInputs = @[
        "tests/test-vm-persistent-lifecycle.py", "tools/reproos-vm.py",
      ],
      cacheable = false).withToolIdentities([
        "python3", "vm-harness", "ssh", "ssh-keygen",
      ])
    discard target("e2e_vm_persistent_lifecycle", e2eVmPersistentLifecycle)

    let testVmSshHostKeyMismatch = shell(
      command = withHostVmRuntime(
        "bash tests/test-vm-ssh-host-key-mismatch.sh"),
      actionId = "reproos.test-vm-ssh-host-key-mismatch",
      deps = @[e2eVmPersistentLifecycle.id],
      extraInputs = @[
        "tests/test-vm-ssh-host-key-mismatch.sh",
        "tools/reproos-vm.py",
      ],
      cacheable = false).withToolIdentities([
        "bash", "python3", "vm-harness", "ssh", "ssh-keygen",
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
      cacheable = false).withToolIdentities(["bash", "nix", "vm-harness"])
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

    # Serial boot-smoke gate for the installed image.
    #
    # It does NOT declare the `vm-harness` tool identity, and that is a
    # declaration, not an omission: the gate links the sibling's Nim
    # LIBRARY (`boot_smoke.nim`, put on the Nim path by config.nims) and
    # drives qemu through it; it never runs the `vm-harness` CLI. Naming
    # the identity would make the engine build that CLI through the
    # cross-repo producer edge before a gate that never invokes it could
    # start -- measured here: `repro build test-guest-verity-tpm` failed in
    # `vm_harness.cli.build`, having never reached the gate at all.
    #
    # Deliberately NOT dependent on ReproosImageBuildActionId: its first case replays the
    # recorded boot transcript through vm-harness's matching engine and
    # must run everywhere in under a second, while its second case boots a
    # real image only when one is already present and otherwise reports a
    # visible skip. Making the image a dependency would turn a cheap,
    # always-on regression check into a multi-hour build.
    let testImageBootSmoke = shell(
      command = "bash tests/test-reproos-image-boot-smoke.sh",
      actionId = "reproos.test-image-boot-smoke",
      extraInputs = @[
        "tests/test-reproos-image-boot-smoke.sh",
        "tests/nim-gate.sh",
        "tests/test_reproos_image_boot_smoke.nim",
        "tests/fixtures/reproos-boot-serial-m9r71-v4.log",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-image-boot-smoke", testImageBootSmoke)

    # dm-verity / TPM enablement in the initramfs. Its first case reads
    # the shipped builder and init scripts and asserts the module
    # selection list and the loader lists agree; it needs nothing built
    # and runs in under a second. Its second case builds a real
    # initramfs against a source-built kernel module tree when one is
    # present, and otherwise reports a visible skip. Not dependent on
    # the kernel package, for the same reason the boot smoke is not
    # dependent on the image: an always-on check must not turn into a
    # multi-hour build.
    let testInitramfsVerityTpm = shell(
      command = "bash tests/test-initramfs-verity-tpm-modules.sh",
      actionId = "reproos.test-initramfs-verity-tpm",
      extraInputs = @[
        "tests/test-initramfs-verity-tpm-modules.sh",
        "tests/nim-gate.sh",
        "tests/test_initramfs_verity_and_tpm_modules.nim",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-initramfs-verity-tpm", testInitramfsVerityTpm)

    # The typed disk-layout preset registry. Pure declaration checking:
    # it renders every registered preset, decodes the result through
    # Reprobuild's own parser, and compares the uefi-ext4 rendering
    # against the bytes the retired heredoc emitted. Nothing is built,
    # so this runs in under a second and is not dependent on the image
    # action -- which is the point, since it is the regression check
    # that guards what the image action feeds to `repro disk apply`.
    let testDiskLayoutPresets = shell(
      command = "bash tests/test-disk-layout-presets.sh",
      actionId = "reproos.test-disk-layout-presets",
      extraInputs = @[
        "tests/test-disk-layout-presets.sh",
        "tests/nim-gate.sh",
        "tests/test_disk_layout_presets.nim",
        "tests/golden/disko-uefi-ext4.json",
        "tests/fixtures/auto-config-minimal.toml",
        "repro/disk_layouts.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/image-config.sh",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang", "git",
      ])
    discard target("test-disk-layout-presets", testDiskLayoutPresets)

    # One renderer for the disko document. The registry is compiled into
    # the installer's C++ table and the config validator's JSON by
    # tools/gen_disk_layouts.nim; this gate re-derives both and requires
    # the checked-in bytes to match, compiles the installer's SHIPPED
    # disk_layouts.cpp with g++ and diffs its documents and refusals
    # against the registry's, and checks that the image driver refuses
    # when /etc/repro/disko.json is not the document it applies. Runs
    # without the Qt toolchain on purpose, so it stays a fast always-on
    # check; it additionally compares against a built installer binary
    # when one is present (REPROOS_INSTALLER_BIN, or the recipe's
    # output path) and reports a visible skip when it is not.
    let testInstallerDiskLayoutParity = shell(
      command = "bash tests/test-installer-disk-layout-parity.sh",
      actionId = "reproos.test-installer-disk-layout-parity",
      extraInputs = @[
        "tests/test-installer-disk-layout-parity.sh",
        "tests/nim-gate.sh",
        "tests/test_installer_disk_layout_parity.nim",
        "tests/fixtures/auto-config-minimal.toml",
        "tests/golden/installer-artifacts",
        "repro/disk_layouts.nim",
        "tools/gen_disk_layouts.nim",
        "tools/disk_layouts_generated.json",
        "apps/reproos-installer/src/disk_layouts.h",
        "apps/reproos-installer/src/disk_layouts.cpp",
        "apps/reproos-installer/src/disk_layouts_generated.h",
        "apps/reproos-installer/src/installer_state.cpp",
        "tools/reproos-machine-config.py",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang", "python3",
      ])
    discard target("test-installer-disk-layout-parity",
      testInstallerDiskLayoutParity)

    # The same claim, observed from inside a running guest: the ReproOS
    # kernel direct-kernel-booted with the product's own initramfs and a
    # vTPM attached, reporting dm-verity and a TPM 2.0 on the serial
    # console. Artifact-conditional on the source-built kernel and
    # BusyBox; a visible skip naming the remedy when they are absent.
    #
    # As with the boot-smoke gate above, `vm-harness` is deliberately NOT
    # a declared tool identity here: this gate consumes the sibling's Nim
    # library, not its CLI.
    let testGuestVerityTpm = shell(
      command = "bash tests/test-guest-verity-and-tpm.sh",
      actionId = "reproos.test-guest-verity-tpm",
      extraInputs = @[
        "tests/test-guest-verity-and-tpm.sh",
        "tests/nim-gate.sh",
        "tests/test_guest_verity_and_tpm_available.nim",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init-attest-probe",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-guest-verity-tpm", testGuestVerityTpm)

    # Image reproducibility, in layers. The always-on layers re-derive
    # every input the image is built from -- twice, into two clean trees,
    # the second under a different caller environment and the opposite
    # directory enumeration order -- and check that every authored
    # artifact on the image's path pins its timestamps, its entry order
    # and its otherwise-random identifiers. They need nothing built and
    # run in under a second. The build-twice byte comparison is opt-in
    # (REPROOS_IMAGE_REPRODUCIBILITY_GATE=1) because an image build takes
    # hours and needs sudo; it reports a visible skip naming the remedy
    # when it is not asked for, never a silent pass.
    #
    # Deliberately NOT dependent on the image build action, for the same
    # reason the boot-smoke gate is not: an always-on regression check
    # must not turn into a multi-hour build.
    let testImageReproducibility = shell(
      command = "bash tests/test-image-reproducibility.sh",
      actionId = "reproos.test-image-reproducibility",
      extraInputs = @[
        "tests/test-image-reproducibility.sh",
        "tests/nim-gate.sh",
        "tests/test_reproos_image_reproducibility.nim",
        "tools/reproos_image_metadata.py",
        "recipes/reproos-container/package.nim",
        "recipes/reproos-container/scripts/build-incus-image.sh",
        "tests/test-iso-reproducibility.sh",
        "tests/fixtures/auto-config-minimal.toml",
        "repro/disk_layouts.nim",
        "repro/package_sets.nim",
        "repro/workflows.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-iso/package.nim",
        "apps/reproos-installer/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/scripts/build-iso.sh",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-image-reproducibility", testImageReproducibility)

    # The image's filesystem and partition-table identifiers.
    #
    # Not folded into the reproducibility gate above: that one is about
    # the image's INPUTS being a function of the tree, this one is about
    # what `repro disk apply` writes onto the disk. Keeping them apart
    # means a failure says which of the two it is.
    let testDiskIdentityPinning = shell(
      command = "bash tests/test-disk-identity-pinning.sh",
      actionId = "reproos.test-disk-identity-pinning",
      extraInputs = @[
        "tests/test-disk-identity-pinning.sh",
        "tests/nim-gate.sh",
        "tests/test_disk_identity_pinning.nim",
        "tests/fixtures/auto-config-minimal.toml",
        "repro/disk_layouts.nim",
        "repro/package_sets.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
      ],
      cacheable = false).withToolIdentities([
        "nim", "mkdir", "clang",
      ])
    discard target("test-disk-identity-pinning", testDiskIdentityPinning)

    # The integrity-checked read-only root.
    #
    # Its always-on layer builds real dm-verity Merkle trees in Nim and
    # checks them against a known answer a real `veritysetup` produced,
    # so it needs no tool beyond the Nim gate set and runs in about a
    # second. Two heavier layers are opt-in and report a visible skip
    # naming the remedy: REPROOS_VERITY_TOOL_GATE=1 runs the shipped
    # build-verity-root.sh against real mkfs.ext4 and veritysetup, and
    # REPROOS_VERITY_GUEST_GATE=1 boots a real guest on the product's own
    # init-disk initramfs and reads the result off its serial console.
    #
    # `cryptsetup`, `e2fsprogs` and qemu are deliberately NOT declared as
    # identities: the first two are from-source packages here, so naming
    # them would make an always-on gate bootstrap them.
    let testVerityRoot = shell(
      command = "bash tests/test-verity-root.sh",
      actionId = "reproos.test-verity-root",
      extraInputs = @[
        "tests/test-verity-root.sh",
        "tests/nim-gate.sh",
        "tests/test_verity_root.nim",
        "repro/verity.nim",
        "repro/disk_layouts.nim",
        "recipes/reproos-image/scripts/build-verity-root.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-verity-root", testVerityRoot)

    # The measured boot artifact.
    #
    # A unified kernel image puts the kernel, the initrd and the KERNEL
    # COMMAND LINE into one PE binary, so the dm-verity root hash the
    # command line pins is inside the thing firmware measures. On a GRUB
    # boot it would not be: grub.cfg is an editable file on the ESP and
    # firmware measures the loader, not the string the loader passes on.
    #
    # The always-on layer assembles real unified kernel images against a
    # synthetic PE stub it builds from the specification, so it needs no
    # artifact and no tool beyond the Nim gate set and runs in about a
    # second. A second layer runs automatically whenever a copy of the
    # PINNED EFI stub is present -- it assembles against the real stub
    # and requires the SHIPPED tools/reproos_uki.nim to produce the same
    # bytes -- and reports a visible skip naming the remedy when it is
    # not. A third is opt-in (REPROOS_UKI_BOOT_GATE=1) and boots a real
    # image off a FAT ESP through OVMF, reading /proc/cmdline out of the
    # running guest.
    #
    # qemu, `dosfstools` and `mtools` are deliberately NOT declared as
    # identities: the last two are from-source packages here, so naming
    # them would make an always-on gate bootstrap them.
    let testUki = shell(
      command = "bash tests/test-uki.sh",
      actionId = "reproos.test-uki",
      extraInputs = @[
        "tests/test-uki.sh",
        "tests/nim-gate.sh",
        "tests/test_uki.nim",
        "repro/uki.nim",
        "repro/verity.nim",
        "repro/disk_layouts.nim",
        "tools/reproos_uki.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-uki", testUki)

    let testImageMetadata = shell(
      command = "python3 tests/test_image_metadata.py",
      actionId = "reproos.test-image-metadata",
      extraInputs = @[
        "tests/test_image_metadata.py",
        "tools/reproos_image_metadata.py",
        "repro/image_metadata_tools.nim",
        "recipes/reproos-iso/config/sudoers",
        "recipes/reproos-iso/config/pam-sudo",
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/reproos-health-check",
        "recipes/reproos-container/scripts/build-incus-image.sh",
      ],
      cacheable = false).withToolIdentities(["python3"])
    # Other hosts report an explicit skip before POSIX fixture setup, like the
    # Linux guest gates; they must not provision Linux-only archive tools.
    when defined(linux):
      appendRegisteredActionToolIdentityRefs(testImageMetadata.id,
        @["bash", "mksquashfs", "unsquashfs"])
    discard target("test-image-metadata", testImageMetadata)

    # One generation per boot, and a reboot to change it.
    #
    # The launch measurement is taken once, at boot, over the unified
    # kernel image the firmware loaded, and nothing extends it. So an
    # attested instance runs one generation for the lifetime of a boot: an
    # apply STAGES the new one into the slot the machine is not running
    # from, reports reboot-required, and leaves the running generation's
    # artifacts untouched; a rollback re-selects the previous pair, which
    # has been sitting in its slot since it was staged. Asking for the
    # switch to take effect on the running system is refused, and the
    # refusal is keyed on there being a measurement to contradict rather
    # than being a blanket no.
    #
    # The always-on layer stages real unified kernel images -- assembled
    # against a synthetic PE stub it builds from the specification -- into
    # a real store on a real directory, so it needs no artifact and no
    # tool beyond the Nim gate set. A second layer runs automatically
    # whenever a copy of the pinned EFI stub is present and requires the
    # SHIPPED tools/reproos_generation.nim to produce the same store bytes
    # as the module. A third is opt-in
    # (REPROOS_GENERATION_BOOT_GATE=1) and boots one real FAT32 ESP four
    # times through OVMF, reading /proc/cmdline out of each guest.
    #
    # qemu, `dosfstools` and `mtools` are deliberately NOT declared as
    # identities: the last two are from-source packages here, so naming
    # them would make an always-on gate bootstrap them.
    let testGenerations = shell(
      command = "bash tests/test-generations.sh",
      actionId = "reproos.test-generations",
      extraInputs = @[
        "tests/test-generations.sh",
        "tests/nim-gate.sh",
        "tests/test_generations.nim",
        "repro/generations.nim",
        "repro/uki.nim",
        "repro/verity.nim",
        "repro/disk_layouts.nim",
        "tools/reproos_generation.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/stage-installed-root.sh",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-generations", testGenerations)

    # The step that makes a measured command line true of a disk.
    #
    # An attested boot resolves a dm-verity root hash and two volume
    # specifiers out of a command line that sits inside the binary
    # firmware measures. All three were produced and pinned long before
    # anything put a byte on a partition, and an image built that way
    # boots, resolves both specifiers to volumes that really exist, and
    # finds them empty. This gate covers the copy that closes that gap,
    # and the checks it makes on the result.
    #
    # The always-on layer reads the shipped image driver, the shipped
    # carrier writer and the shipped recipe: the writer is called on the
    # attested arm and nowhere else, before anything is mounted; carriers
    # are addressed by PARTUUID read back off the partition table rather
    # than by a partition number or a filesystem label a Merkle tree
    # cannot have; the bytes are read back and compared with no opt-out;
    # and every tool the writer runs is a declared identity. The opt-in
    # layer (REPROOS_ATTESTED_CARRIER_GATE=1) applies the real layout to
    # a transient qcow2 over a loopback NBD node, writes a real pair
    # through the shipped writer, and verifies it on the partitions --
    # with a flipped byte as the negative half.
    #
    # `sudo`, qemu, `sgdisk`, `cryptsetup` and `e2fsprogs` are
    # deliberately NOT declared as identities: the last two are
    # from-source packages here, so naming them would make an always-on
    # gate bootstrap them.
    let testAttestedCarriers = shell(
      command = "bash tests/test-attested-carriers.sh",
      actionId = "reproos.test-attested-carriers",
      extraInputs = @[
        "tests/test-attested-carriers.sh",
        "tests/nim-gate.sh",
        "tests/test_attested_carriers.nim",
        "tests/fixtures/auto-config-minimal.toml",
        "repro/generations.nim",
        "repro/verity.nim",
        "repro/disk_layouts.nim",
        "repro/package_sets.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/write-verity-carriers.sh",
        "recipes/reproos-image/scripts/build-verity-root.sh",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-attested-carriers", testAttestedCarriers)

    # The ORDER the attested image is built in.
    #
    # The root of an attested image is a finished dm-verity image whose
    # bytes a measured command line names, so every step that configures
    # it has to run BEFORE the hash is taken -- and the arm that installs
    # it must be unable to mount a carrier writably, because a read-write
    # mount that writes nothing already breaks the pair. The always-on
    # layer reads the shipped driver, stager, configuration script, mount
    # guard and recipe; the opt-in layer configures a real root, images
    # it, applies the real layout to a real disk, verifies the pair
    # against the hash the command line pins, and falsifies that with a
    # zero-write mount.
    #
    # `sudo`, qemu, `sgdisk`, `cryptsetup` and `e2fsprogs` are
    # deliberately NOT declared as identities, for the same reason as the
    # carrier gate above.
    let testAttestedRootOrder = shell(
      command = "bash tests/test-attested-root-order.sh",
      actionId = "reproos.test-attested-root-order",
      extraInputs = @[
        "tests/test-attested-root-order.sh",
        "tests/nim-gate.sh",
        "tests/test_attested_root_order.nim",
        "tests/fixtures/auto-config-minimal.toml",
        "repro/generations.nim",
        "repro/uki.nim",
        "repro/verity.nim",
        "repro/disk_layouts.nim",
        "repro/package_sets.nim",
        "recipes/reproos-image/package.nim",
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/stage-installed-root.sh",
        "recipes/reproos-image/scripts/configure-installed-root.sh",
        "recipes/reproos-image/scripts/image-config.sh",
        "recipes/reproos-image/scripts/mount-guard.sh",
        "recipes/reproos-image/scripts/write-verity-carriers.sh",
        "recipes/reproos-image/scripts/build-verity-root.sh",
        "recipes/reproos-image/scripts/reproos-health-check",
        "recipes/reproos-image/scripts/reproos-first-boot-enroll",
        "recipes/reproos-image/scripts/reproos-network",
        "recipes/reproos-image/scripts/reproos-network-wait",
        "recipes/reproos-image/scripts/reproos-network.service",
        "recipes/reproos-image/scripts/reproos-udhcpc-hook",
        "recipes/reproos-image/scripts/reproos-sway.conf",
        "recipes/reproos-image/scripts/reproos-desktop.qml",
        "recipes/reproos-image/scripts/repro-sway-diag",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-attested-root-order", testAttestedRootOrder)

    # What the image will measure, said before it boots.
    #
    # A stub extends PCR 11 with the unified kernel image's own sections
    # before it starts the kernel, so the register is a pure function of
    # the image and the build can write it down. The always-on layer is
    # the schema and the calculator; the artifact-conditional layer runs
    # the SHIPPED `repro attest expect`; the opt-in layer boots the image
    # with a software TPM attached and reads the register back out.
    #
    # `qemu-system-x86_64`, `swtpm`, `dosfstools`, `mtools` and `xz` are
    # deliberately NOT declared: the boot layer is opt-in and ambient, and
    # naming from-source packages would make an always-on gate bootstrap
    # them.
    let testMeasurementManifest = shell(
      command = "bash tests/test-measurement-manifest.sh",
      actionId = "reproos.test-measurement-manifest",
      extraInputs = @[
        "tests/test-measurement-manifest.sh",
        "tests/nim-gate.sh",
        "tests/test_measurement_manifest.nim",
        "repro/attest.nim",
        "repro/uki.nim",
        "repro/verity.nim",
        "repro/generations.nim",
        "recipes/reproos-image/package.nim",
      ],
      cacheable = false).withToolIdentities([
        "bash", "nim", "mkdir", "clang",
      ])
    discard target("test-measurement-manifest", testMeasurementManifest)

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
      testImageReproducibility,
      testImageMetadata,
      testDiskIdentityPinning,
      testVerityRoot,
      testUki,
      testGenerations,
      testAttestedCarriers,
      testAttestedRootOrder,
      testMeasurementManifest,
      testIso,
      testImageBootSmoke,
      testInitramfsVerityTpm,
      testGuestVerityTpm,
      testDiskLayoutPresets,
      testInstallerDiskLayoutParity,
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
