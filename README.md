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
repro build incus-projection
repro build incus-image
repro build
```

`installer`, `rootfs`, `iso`, `image`, `incus-projection`, and `incus-image` are
named outputs. `rootfs` stages the source-built graphical filesystem as an
independently cacheable directory; the ISO, installed image, and Incus image
consume it. `incus-projection` translates the reviewed unattended configuration
into a typed system-container profile. `incus-image` creates
`recipes/reproos-container/build/reproos-incus.tar.xz` and its baseline manifest.
The default target builds the installer, ISO, installed image, and Incus image.
The project defaults to `from-source` provisioning, so the explicit
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
repro build test-installed-ssh
repro build test-unattended-install
repro build test-incus-projection
repro build test-incus-helper
repro build test-incus-publication
repro build test-incus-second-host
repro build test-incus-reproducibility
repro build test-incus-lifecycle
repro build test-vm-incus-parity
repro build incus-acceptance
repro build incus-remote-acceptance
```

The unattended test compares the wizard's generated configuration with the
reviewed fixture, applies it to the installed image build, waits for the boot
health marker, and verifies the configured hostname over SSH. The
installed-desktop gate captures the graphical session after that health marker
and checks its readiness panel with GuiAssert.

`incus-acceptance` runs the complete container gate: configuration projection,
helper regressions, byte-reproducible image authoring, an isolated live Incus
lifecycle, and the shared installed-VM/container contract. The live gates need
a running Incus daemon and a libvirt-capable `vm-harness` host.

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
repro run cache-backfill -- --verify-only
repro run cache-backfill -- --verify-only --resume --jobs 8
repro run image-ssh
repro run image-ssh -- uname -a
repro run incus-import
repro run incus-launch
repro run incus-shell
repro run incus-logs
repro run incus-destroy
repro run incus-publish -- --destination PUBLICATION_DIR --signing-key KEY
repro run incus-pull -- --base-url URL --trusted-key KEY.pub --project PROJECT
```

Cache verification is sequential by default. Use `--jobs` for bounded parallel
package-graph checks; the atomic report remains resumable if the run is
interrupted.

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

`cache-backfill` derives its package list and cache keys from the source-only
ISO graph, publishes only missing materialized entries, and verifies every key
against `https://repro-cache.metacraft-labs.com`. Publishing requires the
authorized `REPRO_BINARY_CACHE_KEY_PATH` and `REPRO_BINARY_CACHE_CERT_PATH`
environment variables. Use `-- --packages-root PATH` when the
`reprobuild-packages` checkout is not the normal sibling directory. Long audits
can use `-- --resume` to reuse completed packages from the report when the
Reprobuild executable and source catalog fingerprints still match.

`boot-iso` and `boot-image` open the VM in `virt-viewer`. Closing the viewer
reclaims the transient domain and its writable disk overlay; the ISO or QCOW2
build output is never modified.

`image-ssh` creates the same self-cleaning overlay without opening a viewer,
forwards a loopback-only host port to the guest, and runs the requested command
through OpenSSH. Its default command verifies the smoke image hostname.

The Incus workflows use an isolated `reproos-dev` project, dedicated host
bridge, and dedicated storage pool. The generated profile gives the container a
deterministic address with DHCP fallback, while ownership guards leave default
and unrelated Incus resources untouched.
`incus-launch` imports the source-built image and keeps the container running;
use `incus-shell` or `incus-logs` to inspect it and `incus-destroy` to remove the
instance, image, bridge, project, and pool. Container configuration is selected
from immutable `/var/lib/reproos/generations` entries with the
`reproos-generation` switch and rollback command. See
`recipes/reproos-container/README.md` for overrides and acceptance details.

`incus-publish` writes an authenticated static catalog whose image paths include
the complete configuration generation and whose immutable alias is that
64-character digest. It signs canonical JSON
with an OpenSSH Ed25519 key and refuses to replace an existing generation with
different bytes. `incus-pull` verifies the signed index and generation manifest,
then verifies the archive size, SHA-256, and embedded generation before invoking
the selected Incus daemon. The corresponding environment variables are
`REPROOS_INCUS_PUBLICATION_DIR`, `REPROOS_INCUS_SIGNING_KEY`,
`REPROOS_INCUS_SIGNING_KEY_ID`, `REPROOS_INCUS_PUBLICATION_URL`, and
`REPROOS_INCUS_TRUSTED_KEY`.

`incus-remote-acceptance` adds a clean-host gate over SSH. It uploads only the
pull client and trusted public key, imports an exact signed generation, launches
two containers on owned temporary resources, and verifies generation health,
SSH, peer reachability, an exact application response, closed undeclared ports,
and cleanup. Configure `REPROOS_INCUS_SECOND_HOST_SSH`,
`REPROOS_INCUS_PUBLICATION_URL`, `REPROOS_INCUS_TRUSTED_KEY`,
`REPROOS_INCUS_SIGNING_KEY_ID`, and `REPROOS_INCUS_GENERATION`.

`repro tasks` lists every interactive workflow. See
`tools/visual-review-brief.md` for the screenshot review process.

## Project Layout

The root `repro.nim` composes focused package modules:

- `apps/reproos-installer/package.nim` builds the Qt/QML installer.
- `recipes/reproos-iso/package.nim` builds the live bootable ISO.
- `recipes/reproos-image/package.nim` builds the installed QCOW2 image.
- `recipes/reproos-container/package.nim` builds the native Incus image and
  configuration projection.
- `repro/workflows.nim` defines tests and interactive run edges.

Reusable package interfaces and source recipes live in the sibling
`reprobuild-packages` repository. ReproOS owns product composition, installer
sources, boot assets, and product-level tests. The normal workspace places
`reprobuild`, `reprobuild-packages`, `vm-harness`, and this repository side by
side. `REPRO_FROM_SOURCE_ROOT` and `REPROBUILD_PACKAGES_ROOT` can override that
layout.
