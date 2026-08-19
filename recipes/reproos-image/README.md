# ReproOS Installed Image

The `image` target produces a fully installed, bootable QCOW2 artifact. It
consumes the ISO package's cacheable source-built root filesystem, builds a
separate cacheable disk initramfs, applies an installer configuration to the
disk, and installs the boot loader without a boot-time installer step.

```console
repro build image
repro build test-image-health
repro run boot-image
```

`REPRO_AUTO_CONFIG` may point to a generated `auto-config.toml`; otherwise the
minimal reviewed fixture is used. The artifact is written to
`recipes/reproos-image/build/reproos-installed.qcow2`.

The final disk-assembly edge requires a host-capable NBD environment and setuid
`sudo`, so it is explicitly non-cacheable. All reusable inputs remain ordinary
Reprobuild outputs, and all other commands and source package outputs are
declared in the package module.
