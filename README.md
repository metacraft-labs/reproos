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

## Installer design loop

Installer design does not require a VM. Launch the real source-built Qt app as
a regular desktop window:

```console
repro preview-installer
bash tools/run-installer-preview.sh --screen users --size 1024x768 --no-build
pwsh tools/run-installer-preview.ps1 -Screen users -Size 1024x768 -NoBuild
```

Preview mode seeds representative account and disk data and forces every
installation command through the non-destructive simulation path. Back,
Continue, and the simulated install can therefore be exercised across the
complete wizard. On Windows, run the command in WSLg; the Qt window appears on
the Windows desktop. A VM boot is reserved for final ISO integration and font,
compositor, and boot-environment acceptance.

For automated visual review, `repro installer-screenshots` captures every
named screen at wide, VM, and compact sizes without booting a VM. See
`tools/visual-review-brief.md` for the agent review loop.

The normal workspace layout places `reprobuild`, `reprobuild-packages`,
`vm-harness`, and this repository side by side. Override the source catalog
with `REPRO_FROM_SOURCE_ROOT` or `REPROBUILD_PACKAGES_ROOT` when needed.
