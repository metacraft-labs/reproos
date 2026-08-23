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

`incus-launch` creates the isolated `reproos-dev` project and `reproos0` bridge,
imports the built image, and leaves the container running. The project profile
supplies a deterministic IPv4 address with DHCP fallback. `incus-destroy`
removes the instance, imported image, bridge, and project without modifying the
default Incus project or its networks.

The following environment variables select non-default resources:

- `REPROOS_INCUS_IMAGE` selects the image archive.
- `REPROOS_INCUS_PROJECT` selects the isolated project.
- `REPROOS_INCUS_NETWORK` selects the host bridge; Linux limits its name to 15
  characters.
- `REPROOS_INCUS_INSTANCE` and `REPROOS_INCUS_ALIAS` select instance and image
  names.
- `VM_HARNESS_BIN` selects the `vm-harness` executable.
- `VMH_INCUS_CMD` selects the Incus client command.

## Acceptance

Run the complete gate on a Linux host with Incus and libvirt available:

```console
repro build incus-acceptance
```

Focused targets are `test-incus-projection`, `test-incus-helper`,
`test-incus-reproducibility`, `test-incus-lifecycle`, and
`test-vm-incus-parity`. The lifecycle test validates import, boot health, SSH,
snapshot restore, generation rollback, and cleanup. The parity test verifies
that the installed VM and container realize the same configuration contract,
with only declared realization-specific capabilities.
