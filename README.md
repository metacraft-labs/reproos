# ReproOS

ReproOS is a bootable operating system composed by Reprobuild from reusable,
source-built packages. The repository root contains the canonical project graph.

## Build Outputs

Run builds from the repository root:

```console
repro build installer
repro build iso
repro build image
repro build
```

`installer`, `iso`, and `image` are named outputs. The default target builds all
three. The project defaults to `from-source` provisioning, so the explicit
`--tool-provisioning=from-source` flag is only needed when overriding another
environment setting.

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
repro build test-iso
repro build test-image-health
repro build test-unattended-install
```

The unattended test compares the wizard's generated configuration with the
reviewed fixture, applies it to the installed image build, and runs the boot
health check.

## Interactive Workflows

Installer design does not require a VM. Launch the source-built Qt application
as a regular, non-destructive desktop app:

```console
repro run installer
repro run installer -- --screen users --size 1024x768
repro run installer-screenshots
repro run installer-accept-goldens
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
