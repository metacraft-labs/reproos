# ReproOS

ReproOS is a bootable operating-system image composed with reprobuild from
reusable source package recipes.

```console
just build-iso
just test-iso
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
just installer
repro preview-installer
bash tools/run-installer-preview.sh --screen users --size 1024x768 --no-build
pwsh tools/run-installer-preview.ps1 -Screen users -Size 1024x768 -NoBuild
```

`just installer` is the normal contributor entry point. It selects the native
launcher for Windows or Linux, builds the installer from source, and opens it
in preview mode. Preview mode seeds representative account and disk data and
forces every installation command through the non-destructive simulation
path. Back, Continue, and the simulated install can therefore be exercised
across the complete wizard. Running the final simulated step writes
`auto-config.toml`, `system.nim`, `hardware.nim`, `disko.json`, and `home.nim`
under `/tmp/repro-installer-<pid>/configuration`; the exact paths appear in the
install output.

On Windows, the command uses WSLg and the Qt window appears on the Windows
desktop. A VM boot is reserved for final ISO integration and font, compositor,
and boot-environment acceptance. Use the launcher scripts directly when a
specific starting screen, window size, existing config, or no-build run is
needed.

For automated visual review, `repro installer-screenshots` captures every
named screen at wide, VM, and compact sizes without booting a VM. See
`tools/visual-review-brief.md` for the agent review loop.

The normal workspace layout places `reprobuild`, `reprobuild-packages`,
`vm-harness`, and this repository side by side. Override the source catalog
with `REPRO_FROM_SOURCE_ROOT` or `REPROBUILD_PACKAGES_ROOT` when needed.

## Contributor commands

Run these from the repository root:

```console
just check       # Validate that both bootable targets use the source catalog
just installer   # Build and open the safe local installer workflow
just build-iso   # Build the bootable ISO from source recipes
just test-iso    # Boot the ISO and verify the serial kernel banner
just boot-iso    # Leave the ISO running in a VM for interactive acceptance
```

Reusable package interfaces and recipes belong in the sibling
`reprobuild-packages` repository. This repository owns the ReproOS image
composition, installer, boot assets, and product-level tests.
