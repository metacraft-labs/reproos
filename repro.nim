import repro_project_dsl

package reproos:
  defaultToolProvisioning "path"

  devEnv:
    task "check",
      command = "pwsh -NoProfile -File tests/check_source_composition.ps1",
      description = "Validate ReproOS source package composition"
    task "installer-screenshots",
      command = "bash tools/capture-installer-screens.sh",
      description = "Capture every installer screen at the visual-review sizes"
    task "test-installer-artifacts",
      command = "bash tests/test-installer-artifacts.sh",
      description = "Verify installer artifacts and unattended config replay"
    task "build-iso",
      command = "repro build recipes/reproos-iso --tool-provisioning=from-source",
      description = "Build the bootable ReproOS ISO from source packages"
    task "build-image",
      command = "repro build recipes/reproos-image --tool-provisioning=from-source",
      description = "Build the installed ReproOS QCOW2 image"
    task "boot-iso",
      command = "vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --keep",
      description = "Boot the newest ReproOS ISO in a VM"
    task "test-iso",
      command = "vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --expect \"Linux version\" --timeout-sec 300",
      description = "Boot-test the newest ReproOS ISO"
    task "boot-image",
      command = "vm-harness boot --backend auto --source-image recipes/reproos-image/build/reproos-installed.qcow2 --kind qcow2 --keep",
      description = "Boot the newest installed ReproOS image in a VM"
    task "test-image-health",
      command = "bash tests/test-installed-image-health.sh",
      description = "Boot the installed image and require the health sentinel"
    task "test-unattended-install",
      command = "bash tests/test-unattended-install.sh",
      description = "Replay installer config, build an image, and health-test it"
