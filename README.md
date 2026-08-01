# ReproOS

ReproOS is a bootable operating-system image composed with reprobuild from
reusable source package recipes.

```console
repro build-iso
repro test-iso
```

`build-iso` builds `recipes/reproos-iso` with from-source provisioning. The ISO
uses the kernel and modules from `reprobuild-packages/packages/source/kernel`,
builds its initramfs from that kernel plus source-built BusyBox, and stages the
same source package closure as the bootable QCOW2 target.

`boot-iso` leaves a VM running for interactive inspection. `test-iso` uses
vm-harness to boot the newest ISO and requires a serial Linux kernel banner.

The normal workspace layout places `reprobuild`, `reprobuild-packages`,
`vm-harness`, and this repository side by side. Override the source catalog
with `REPRO_FROM_SOURCE_ROOT` or `REPROBUILD_PACKAGES_ROOT` when needed.

