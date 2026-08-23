# ReproOS Incus Image

This package projects the reviewed unattended ReproOS configuration into a
native Incus system-container image. It consumes the same source-built rootfs
as the ISO and installed QCOW2 image; host-distribution packages are not copied
into the artifact.

## Build Outputs

Run from the repository root:

```console
repro build incus-projection
repro build incus-image
```

The projection is written beneath `recipes/reproos-container/build/projection`.
The image bundle contains `reproos-incus.tar.xz`, `reproos-incus.sha256`, and
`incus-baseline.manifest`. Set `REPRO_AUTO_CONFIG` to project another reviewed
unattended configuration.

The archive metadata and baseline manifest record the full configuration
SHA-256 as the image generation. That identity is preserved by signed
publication and remote pull workflows.

## Manual Lifecycle

The lifecycle tasks require a running Incus daemon, the `incus` client, and
`vm-harness`:

```console
repro run incus-import
repro run incus-launch
repro run incus-shell
repro run incus-logs
repro run incus-destroy
```

`incus-launch` creates the isolated `reproos-dev` project, `reproos0` bridge,
and `reproos-storage` pool, imports the built image, and leaves the container
running. The project profile supplies a deterministic IPv4 address with DHCP
fallback. `incus-destroy` removes only resources carrying the matching
`user.reproos.*` ownership metadata. It refuses the default project and storage
pool, reserved host bridges, and any unowned project, bridge, pool, or instance.

The following environment variables select non-default resources:

- `REPROOS_INCUS_IMAGE` selects the image archive.
- `REPROOS_INCUS_PROJECT` selects the isolated project.
- `REPROOS_INCUS_NETWORK` selects the host bridge; Linux limits its name to 15
  characters.
- `REPROOS_INCUS_STORAGE` selects the isolated storage pool.
- `REPROOS_INCUS_INSTANCE` and `REPROOS_INCUS_ALIAS` select instance and image
  names.
- `VM_HARNESS_BIN` selects the `vm-harness` executable.
- `VMH_INCUS_CMD` selects the Incus client command.

## Signed Publication

Publish the built bundle to a directory served by an ordinary static HTTP
server:

```console
repro run incus-publish -- \
  --destination /srv/reproos/incus \
  --signing-key /run/keys/reproos-release \
  --key-id reproos-release
```

No signing key belongs in this repository. The task also accepts
`REPROOS_INCUS_PUBLICATION_DIR`, `REPROOS_INCUS_SIGNING_KEY`, and
`REPROOS_INCUS_SIGNING_KEY_ID`. Each generation directory is immutable;
republishing identical bytes is idempotent, while a conflicting image is
rejected. `index.json` identifies the current generation and retains every
previous generation by its full SHA-256.

On another Incus host, trust the public key and import either the signed current
generation or an exact generation. The immutable image alias is the complete
64-character generation digest, which fits Incus's alias length limit:

```console
repro run incus-pull -- \
  --base-url https://images.example.test/reproos/incus \
  --trusted-key /etc/reproos/release-key.pub \
  --key-id reproos-release \
  --generation GENERATION \
  --project reproos-test
```

`incus-pull` verifies both OpenSSH signatures, the manifest digest, image size,
image digest, generation-addressed paths and alias, and the generation embedded
in `metadata.yaml` before it runs `incus image import`. Use `--no-import` for a
verification-only pull or `--output-dir` to retain the authenticated archive.
Repeated pulls are idempotent. If a prior attempt imported the signed
fingerprint but stopped before assigning its alias, the pull repairs that alias;
an alias that points to a different fingerprint is rejected.
`REPROOS_INCUS_PUBLICATION_URL`, `REPROOS_INCUS_TRUSTED_KEY`,
`REPROOS_INCUS_GENERATION`, and `VMH_INCUS_CMD` provide environment-based
configuration for remote acceptance automation.

## Configuration Generations

Container configuration lives in immutable directories under
`/var/lib/reproos/generations`. `/var/lib/reproos/current-generation` selects
the active directory atomically, and `/etc/repro` resolves through that link.
The image starts with the unattended configuration hash as its generation ID.

Inside a running container, root can manage prepared configuration generations
with:

```console
reproos-generation current
reproos-generation list
reproos-generation stage <id> <source-directory>
reproos-generation switch <id>
reproos-generation rollback
```

A staged directory must contain `auto-config.toml`, `system.nim`, `home.nim`,
`hardware.nim`, `realization.json`, and a `generation` file whose content is
the requested ID. Staging copies and makes the directory read-only. Switching
records the former target as `previous-generation`; rollback atomically swaps
the two links. Reboot after switch or rollback to exercise the complete boot
and health path.

## Acceptance

Run the complete gate on a Linux host with Incus and libvirt available:

```console
repro build incus-acceptance
```

Focused targets are `test-incus-projection`, `test-incus-helper`,
`test-incus-publication`, `test-vm-incus-parity-checker`,
`test-incus-reproducibility`,
`test-incus-lifecycle`, `test-incus-parallel-isolation`, and
`test-vm-incus-parity`. The lifecycle test validates import, boot health, SSH,
snapshot restore, generation switch and rollback across real reboots, and
cleanup. The parallel isolation test launches two independent projects,
bridges, pools, and instances concurrently. The parity test compares the
selected generation, generated files,
representative source-built runtime package hashes, SSH service state,
normalized route and resolver availability, and an application response over
SSH. It also verifies that the installed VM and container realize the same
configuration contract, with only declared realization-specific capabilities.
