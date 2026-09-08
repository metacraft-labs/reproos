# ReproOS

ReproOS is a bootable operating system composed by Reprobuild from reusable,
source-built packages. The repository root contains the canonical project graph.

## Build Outputs

Run builds from the repository root:

```console
repro build installer
repro build rootfs
repro build iso
repro build unattended-iso
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
repro build test_remote_access_configuration_validation
repro build test_instance_secrets_do_not_affect_public_image_cache_key
repro build test_unattended_vm_rejects_live_media_false_positive
repro build test-source-composition
repro build test-iso-reproducibility
repro build test-image-reproducibility
repro build test-image-metadata
repro build test-iso
repro build test-image-health
repro build test-installed-desktop
repro build test-installed-ssh
repro build test-unattended-install
repro build unattended-iso
repro build e2e_unattended_vm_installs_and_boots_target_disk
repro build test_vm_ssh_host_key_mismatch_fails_closed
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

`test-image-metadata` checks real archive ownership, sudo privileges, and health
exit-status handling on Linux without a VM or root access. Other hosts report an
explicit platform skip. See [Image Metadata](docs/image-metadata.md).

The unattended test compares the wizard's generated configuration with the
reviewed fixture, applies it to the installed image build, waits for the boot
health marker, and verifies the configured hostname over SSH. The
installed-desktop gate captures the graphical session after that health marker
and checks its readiness panel with GuiAssert. The unattended installed-disk
E2E edge runs that same graphical gate after installation, reboot, and SSH
health verification.

The reviewed schema-v2 machine profile contains only cacheable public intent.
It keeps the account locked, enables key-only SSH, and requires a separately
injected first-boot enrollment profile. Validate or compile that boundary with:

```console
python3 tools/reproos-machine-config.py validate \
  --config tests/fixtures/auto-config-minimal.toml \
  --output build/public-machine-profile.json
python3 tools/reproos-machine-config.py enroll \
  --public-manifest build/public-machine-profile.json \
  --enrollment INSTANCE.toml \
  --output build/instance-enrollment.json
```

The public image cache key is independent of machine UUIDs and authorized
keys. Enrollment outputs are per-instance material and must not be published as
reusable image artifacts.

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
repro run vm-install
repro run vm-install -- --replace
repro run vm-installed
repro run vm-verify-installed-boot
repro run vm-ssh
repro run vm-exec -- uname -a
repro run vm-status
repro run vm-logs
repro run vm-stop
repro run vm-destroy
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

`vm-install` boots the dedicated unattended ISO through `vm-harness`, installs
onto a caller-owned disk under `build/reproos-vm`, requires the install success
marker and a clean guest shutdown, and writes a content-identity manifest. It
does not include instance keys in the installer media. The target is preserved
for subsequent commands; an existing disk is refused unless `--replace` is
explicitly passed. `vm-verify-installed-boot` detaches the installer, attaches a
separate first-boot enrollment ISO, accepts only the installed-disk receipt
conditioned health marker, retains the installed-disk receipt marker in its
serial evidence, and verifies the configured hostname over key-only SSH.
`vm-installed` installs if necessary, then starts or reuses a retained VM.
`vm-ssh` opens an interactive terminal; `vm-exec -- COMMAND...` runs an ad hoc
command through the same loopback-only SSH forward and preserves its exit code.
For compatibility, `vm-ssh -- COMMAND...` also executes a command. The shell is
a dev-environment task so terminal streams are inherited. Manual lifecycle and
inspection commands are also tasks, preserving their output and exit status;
automated checks and image-dependent operations remain named graph edges.
Arguments after `vm-ssh --` or `vm-exec --` belong to the guest command;
select the local instance through `REPROOS_VM_STATE_DIR`.

The durable lifecycle currently requires Linux/libvirt. The first connection
uses trust on first use and pins the guest host key in
`build/reproos-vm/ssh_known_hosts`. Reconnects reuse the same writable disk,
enrollment identity, and host-key alias. `vm-status` returns JSON with the
instance UUID, actual writable disk, backend state, and diagnostic paths.
`vm-logs` reads retained serial output. Neither command creates a VM.

`vm-stop` shuts down the guest while preserving its definition and disk.
`vm-destroy` also removes the runtime definition, but preserves its writable
disk, backing image, firmware state, keys, and logs. `vm-installed` restores
that same instance after either operation. Mutation commands refuse concurrent
operations; finish an interactive session before stopping or replacing its VM.
The runtime is explicitly retained until stopped or destroyed; automatic
Reprobuild lease expiry is not yet enabled for these tasks.

Only `vm-install -- --replace` purges the previous owned runtime and writable
state before replacing the installation disk and enrollment. This discards
guest changes and resets trust. Use a different `REPROOS_VM_STATE_DIR` to keep
multiple installations. Boot settings are chosen on first creation; reconnects
use the retained configuration rather than silently replacing it.

`repro build e2e_vm_persistent_lifecycle` performs unattended installation and
desktop acceptance, then verifies reconnect, stop/start, and destroy/restore.
It checks a guest filesystem write, machine identity, and pinned SSH trust
across these transitions and records `lifecycle.json` in the test state
directory. It destroys the runtime at exit but retains diagnostics and disks.

The unattended media embeds `tests/fixtures/auto-config-minimal.toml`; changing
that file invalidates the rootfs action. Set `REPROOS_VM_STATE_DIR`,
`REPROOS_VM_BACKEND`, `REPROOS_UNATTENDED_ISO`, or
`REPROOS_VM_HARNESS_BIN` to override the local state, backend, media, or harness
binary. Set `REPROOS_VM_ACCELERATION=tcg` when nested KVM is unavailable or
unreliable; the default is `auto`. Installation creates QCOW2 on libvirt and
VHDX on Hyper-V; durable SSH lifecycle acceptance on Hyper-V is still pending.

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
Reprobuild executable and source catalog fingerprints still match. Resumed
entries are looked up again on the cache server; missing entries are audited
again and republished unless `--verify-only` is set. Verification and publication
counts describe the current run, not the saved report.

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
