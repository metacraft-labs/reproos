# ReproOS ISO

This recipe builds a deterministic BIOS and UEFI bootable ISO from the source
package closure in the sibling `reprobuild-packages` repository.

The build has three product inputs:

- The kernel image and module tree from `packages/source/kernel`.
- Static BusyBox from `packages/source/busybox` for early userspace.
- The 114-package root filesystem closure shared with `reproos-image`.

`scripts/build-initramfs.sh` creates the live initramfs. It discovers the ISO,
mounts `/live/filesystem.squashfs`, creates a writable overlay, and switches to
the staged root. `scripts/build-iso.sh` wraps the root and boot assets with
GRUB, xorriso, and pinned reproducibility metadata.

```console
repro build-iso
repro boot-iso
repro test-iso
```

The direct target remains available as:

```console
repro build recipes/reproos-iso --tool-provisioning=from-source
```

Use `REPROBUILD_PACKAGES_ROOT` to select a non-sibling package repository.
Use `REPRO_FROM_SOURCE_ROOT` to select its `packages/source` directory
directly.
