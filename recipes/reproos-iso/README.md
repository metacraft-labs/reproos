# ReproOS ISO

The `iso` target builds a deterministic BIOS and UEFI bootable image from the
source package closure in the sibling `reprobuild-packages` repository.

Its product inputs are the source-built kernel and modules, static BusyBox for
early userspace, the shared root filesystem closure, and the ReproOS installer.
`scripts/build-initramfs.sh` creates the live initramfs and pivots into the
staged SquashFS root. `scripts/build-iso.sh` assembles the boot assets with GRUB,
xorriso, and pinned reproducibility metadata.

```console
repro build iso
repro build test-iso
repro run boot-iso
```

The artifact is written to `recipes/reproos-iso/build/reproos.iso`.
`REPROBUILD_PACKAGES_ROOT` selects a non-sibling package repository;
`REPRO_FROM_SOURCE_ROOT` selects its `packages/source` directory directly.
