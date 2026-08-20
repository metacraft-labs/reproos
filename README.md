# ReproOS

ReproOS is a bootable operating system composed by Reprobuild from reusable,
source-built packages. The repository root contains the canonical project graph.

## Build Outputs

Run builds from the repository root:

```console
repro build installer
repro build rootfs
repro build iso
repro build image
repro build
```

`installer`, `rootfs`, `iso`, and `image` are named outputs. `rootfs` stages the
source-built graphical filesystem as an independently cacheable directory; the
`iso` output consumes it. The default target builds the installer, ISO, and
image. The project defaults to `from-source` provisioning, so the explicit
`--tool-provisioning=from-source` flag is only needed when overriding another
environment setting.

The `rootfs` output must be materialized on a case-sensitive filesystem because
Linux package trees can contain names that differ only by case. In WSL, prefer a
checkout in the Linux filesystem. For a checkout on NTFS, empty
`recipes/reproos-iso/build` and enable its per-directory case-sensitivity flag
before the first build:

```console
fsutil.exe file setCaseSensitiveInfo recipes\reproos-iso\build enable
```

## Tests

Validate the graph contract without building product artifacts:

```console
repro lint
```

The complete product suite is the conventional `test` collection:

```console
repro test
```

Focused targets are available while iterating:

```console
repro build test-installer-preview
repro build test-installer-visuals
repro build test-installer-artifacts
repro build test-source-composition
repro build test-iso-reproducibility
repro build test-iso
repro build test-image-health
repro build test-installed-desktop
repro build test-unattended-install
```

The unattended test compares the wizard's generated configuration with the
reviewed fixture, applies it to the installed image build, and runs the boot
health check. The installed-desktop gate captures the graphical session after
that health marker and checks its readiness panel with GuiAssert.

## Interactive Workflows

Installer design does not require a VM. Launch the source-built Qt application
as a regular, non-destructive desktop app:

```console
repro run installer
repro run installer -- --screen users --size 1024x768
repro run installer-screenshots
repro run installer-accept-goldens
repro run installer-vm-frame -- FRAME.png
repro run installer-vm-screenshot
```

Preview mode exercises the complete wizard and simulates installation. The
final step writes `auto-config.toml`, `system.nim`, `hardware.nim`, `disko.json`,
and `home.nim` beneath a temporary configuration directory printed in the log.
On Windows the launcher uses WSLg.

VM workflows are reserved for integration and acceptance:

```console
repro run boot-iso
repro run boot-image
```

`installer-vm-screenshot` builds the ISO, waits for the first rendered wizard
frame, captures it from a self-cleaning libvirt VM, and runs the GuiAssert
welcome-screen gate.

`boot-iso` and `boot-image` open the VM in `virt-viewer`. Closing the viewer
reclaims the transient domain and its writable disk overlay; the ISO or QCOW2
build output is never modified.

`repro tasks` lists every interactive workflow. See
`tools/visual-review-brief.md` for the screenshot review process.

## Project Layout

The root `repro.nim` composes focused package modules:

- `apps/reproos-installer/package.nim` builds the Qt/QML installer.
- `recipes/reproos-iso/package.nim` builds the live bootable ISO.
- `recipes/reproos-image/package.nim` builds the installed QCOW2 image.
- `repro/workflows.nim` defines tests and interactive run edges.

Reusable package interfaces and source recipes live in the sibling
`reprobuild-packages` repository. ReproOS owns product composition, installer
sources, boot assets, and product-level tests. The normal workspace places
`reprobuild`, `reprobuild-packages`, `vm-harness`, and this repository side by
side. `REPRO_FROM_SOURCE_ROOT` and `REPROBUILD_PACKAGES_ROOT` can override that
layout.
