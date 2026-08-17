# ReproOS Installed Image

The `image` target produces a fully installed, bootable QCOW2 artifact. It
stages the same source-built root filesystem as the ISO, applies an installer
configuration to the disk, and installs the boot loader without a boot-time
installer step.

```console
repro build image
repro build test-image-health
repro run boot-image
```

`REPRO_AUTO_CONFIG` may point to a generated `auto-config.toml`; otherwise the
minimal reviewed fixture is used. The artifact is written to
`recipes/reproos-image/build/reproos-installed.qcow2`.

The driver requires a host-capable NBD environment and setuid `sudo`. All other
commands and source package outputs are declared in the package module and
resolved by Reprobuild.
