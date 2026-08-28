## Deterministic hybrid (BIOS + UEFI) ReproOS ISO package.
##
## Wraps the ``scripts/build-iso.sh`` driver that calls grub-mkrescue +
## xorriso inside a WSL2 distro on Windows (the host does not ship
## xorriso) or directly on Linux. The recipe declares the typed
## ``(kernel, initramfs, scripts)`` -> ``iso`` action so the engine can
## fingerprint the inputs, action-cache the output, and emit one
## bit-identical ISO per build.
##
## The source-built kernel, modules, and BusyBox installation mirrors come
## from the sibling reprobuild-packages catalog. The recipe builds its live
## initramfs locally and stages the same source package closure as the QCOW2
## image target.

import std/[os, strutils]

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import "../../apps/reproos-installer/package" as installerPackage
import "../../repro/package_sets" as packageSets

const
  ReproosIsoRootfsActionId* = "reproosIso.stage_rootfs"
  ReproosIsoRootfsOutput* = "recipes/reproos-iso/build/de-rootfs"
  ReproosIsoBuildActionId* = "reproosIso.build_iso"
  ReproosIsoOutput* = "recipes/reproos-iso/build/reproos.iso"
  ReproosUnattendedIsoBuildActionId* = "reproosIso.build_unattended_iso"
  ReproosUnattendedIsoOutput* =
    "recipes/reproos-iso/build/reproos-unattended.iso"

proc buildIsoCommand(initramfsOutput, diskInitramfsOutput, isoOutput: string;
                     installerAutorun: bool): string =
  let autorun = if installerAutorun: "1" else: "0"
  @[
    "set -euo pipefail;",
    "WORKSPACE_ROOT=\"$(cd ../../.. && pwd)\";",
    "PACKAGES_ROOT=\"${REPROBUILD_PACKAGES_ROOT:-$WORKSPACE_ROOT/reprobuild-packages}\";",
    "export REPROBUILD_PACKAGES_ROOT=\"$PACKAGES_ROOT\";",
    "export REPRO_FROM_SOURCE_ROOT=\"$PACKAGES_ROOT/packages/source\";",
    "export REPRO_KERNEL_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install\";",
    "export REPRO_BUSYBOX_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/busybox/.repro/output/install\";",
    "mkdir -p build;",
    "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " &
      "REPRO_DE_ROOTFS_DIR=\"$PWD/build/de-rootfs\" " &
      "REPRO_GRUB_VARIANT=multi-de " &
      "REPRO_LIVE_INIT=1 " &
      "REPRO_LIVE_INIT_OUT=\"$PWD/" & initramfsOutput & "\" " &
      "REPRO_DISK_INIT_OUT=\"$PWD/" & diskInitramfsOutput & "\" " &
      "REPRO_INSTALLER_AUTORUN=" & autorun & " " &
      "bash scripts/build-iso.sh " &
      "\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz\" " &
      initramfsOutput & " " & isoOutput,
  ].join(" ")

package reproosIso:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "patchelf"
    "xorriso"
    "mtools"
    "squashfs-tools"

  # The DSL currently extracts dependency declarations as string literals.
  # The graph-quality check keeps this block identical to the canonical set.
  buildDeps:
    "sway"
    "sddm"
    "systemd"
    "util-linux"
    "kmod"
    "dbus"
    "sudo"
    "e2fsprogs"
    "dosfstools"
    "btrfs-progs"
    "shadow-utils"
    "iana-tzdata"
    "parted"
    "lvm2"
    "popt"
    "gdisk"
    "libgpg-error"
    "libgcrypt"
    "json-c"
    "cryptsetup"
    "less"
    "procps"
    "rsync"
    "strace"
    "iputils"
    "nano"
    "iproute2"
    "kbd"
    "xkeyboard-config"
    "libxkbfile"
    "xkbcomp"
    "libx11"
    "libxau"
    "libxfont2"
    "libattr"
    "libacl"
    "cairo"
    "libcap"
    "libcap-ng"
    "openssl"
    "openssh"
    "curl"
    "libdrm"
    "libevdev"
    "expat"
    "libffi"
    "libiconv"
    "fontconfig"
    "libfontenc"
    "freetype"
    "gcc"
    "glib2"
    "gdk-pixbuf"
    "gmp"
    "harfbuzz"
    "icu"
    "libinput"
    "lzo"
    "libmd"
    "mpc"
    "mpfr"
    "ncurses"
    "nettle"
    "pam"
    "pango"
    "libpciaccess"
    "pcre2"
    "pixman"
    "libjpeg"
    "libpng"
    "libtiff"
    "readline"
    "libseccomp"
    "sqlite"
    "clingo"
    "wayland"
    "wlroots"
    "libxcb"
    "xcb-util"
    "xcb-util-cursor"
    "xcb-util-image"
    "xcb-util-keysyms"
    "xcb-util-renderutil"
    "xcb-util-wm"
    "libxcvt"
    "libxkbcommon"
    "libxml2"
    "libxdmcp"
    "libdisplay-info"
    "fribidi"
    "mtdev"
    "libseat"
    "zlib"
    "zstd"
    "libaio"
    "audit"
    "libbsd"
    "mesa"
    "llvm"
    "qt6-base"
    "qt6-declarative"
    "qt6-quickcontrols2"
    "qt6-wayland"
    "adwaita-icon-theme"
    "dejavu-fonts"
    "xorg-server"
    "xz"
    "tar"
    "bash"
    "gawk"
    "grep"
    "perl"
    "python3"
    "glibc"
    "coreutils"
    "grub"
    "kernel"
    "musl"
    "busybox"
    "ca-certificates"
    "libxcrypt"

  build:
    let projectRoot = activeProviderProjectRoot()
    let reprobuildRoot = getEnv("REPROBUILD_SRC", "../reprobuild")
    let reproCliInput = reprobuildRoot / "build" / "bin" / "repro"

    # Rootfs staging is the expensive package-composition step. Keep it as a
    # directory output so Reprobuild can cache and restore it independently of
    # the comparatively small initramfs and ISO authoring step.
    let stageRootfsCommand = @[
      "set -euo pipefail;",
      "WORKSPACE_ROOT=\"$(cd ../../.. && pwd)\";",
      "PACKAGES_ROOT=\"${REPROBUILD_PACKAGES_ROOT:-$WORKSPACE_ROOT/reprobuild-packages}\";",
      "REPROBUILD_ROOT=\"${REPROBUILD_SRC:-$WORKSPACE_ROOT/reprobuild}\";",
      "export REPROBUILD_PACKAGES_ROOT=\"$PACKAGES_ROOT\";",
      "export REPRO_FROM_SOURCE_ROOT=\"$PACKAGES_ROOT/packages/source\";",
      "export REPROBUILD_SRC=\"$REPROBUILD_ROOT\";",
      "export REPRO_CLI_BIN=\"$REPROBUILD_ROOT/build/bin/repro\";",
      "export REPROOS_INSTALLER_BIN=\"$PWD/../../" &
        installerPackage.ReproosInstallerBinary & "\";",
      "export REPROOS_SOURCE_RECIPES=\"" &
        packageSets.ReproosGraphicalRootfsPackages.join(" ") & "\";",
      "if [ -d build/de-rootfs ]; then chmod -R u+w build/de-rootfs 2>/dev/null || true; fi;",
      "rm -rf build/de-rootfs;",
      "mkdir -p build/de-rootfs;",
      "REPRO_LIVE_TARGET=graphical bash scripts/stage-de-rootfs.sh build/de-rootfs;",
    ].join(" ")
    let stageRootfsAction = shell(
      command = stageRootfsCommand,
      actionId = ReproosIsoRootfsActionId,
      deps = @[installerPackage.ReproosInstallerReadyActionId],
      actionCachePolicy = acfpHybrid,
      extraInputs = @[
        reproCliInput,
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        "recipes/reproos-iso/scripts/normalize-source-runtime.sh",
        "recipes/reproos-iso/scripts/build-base-rootfs.sh",
        "recipes/reproos-image/scripts/reproos-first-boot-enroll",
        "recipes/reproos-image/scripts/reproos-health-check",
        "recipes/reproos-image/scripts/reproos-sway.conf",
        "recipes/reproos-image/scripts/reproos-desktop.qml",
        "recipes/reproos-image/scripts/reproos-network",
        "recipes/reproos-image/scripts/reproos-network-wait",
        "recipes/reproos-image/scripts/reproos-network.service",
        "recipes/reproos-image/scripts/reproos-udhcpc-hook",
        "tests/fixtures/auto-config-minimal.toml",
        installerPackage.ReproosInstallerBinary,
      ],
      extraOutputs = @["build/de-rootfs"])
    appendRegisteredActionToolIdentityRefs(stageRootfsAction.id,
      @["bash", "patchelf"] & packageSets.ReproosGraphicalRootfsPackages)
    setRegisteredActionCwd(stageRootfsAction.id, acwdCustom,
      "recipes/reproos-iso")
    let rootfsOutputAbs = projectRoot / ReproosIsoRootfsOutput
    setRegisteredActionDependencyPolicy(stageRootfsAction.id,
      automaticMonitorPolicy(@[rootfsOutputAbs]))
    discard target("rootfs", stageRootfsAction)

    # ISO authoring consumes the cached rootfs plus the source-built boot and
    # image tooling. Timestamps, locale, and timezone are pinned by the driver.
    let buildIsoAction = shell(
      command = buildIsoCommand(
        "build/reproos-initramfs.img",
        "build/reproos-iso-disk-initramfs.img",
        "build/reproos.iso", false),
      actionId = ReproosIsoBuildActionId,
      deps = @[stageRootfsAction.id],
      extraInputs = @[
        ReproosIsoRootfsOutput,
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
        "../reprobuild-packages/packages/source/busybox/.repro/output/install/usr/bin/busybox",
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      extraOutputs = @[
        "build/reproos-initramfs.img",
        "build/reproos-iso-disk-initramfs.img",
        "build/reproos.iso",
      ])
    appendRegisteredActionToolIdentityRefs(buildIsoAction.id,
      @[
        "bash",
        "busybox",
        "coreutils",
        "cpio",
        "dosfstools",
        "find",
        "gawk",
        "gzip",
        "grub",
        "kernel",
        "kmod",
        "mtools",
        "sed",
        "squashfs-tools",
        "xz",
        "xorriso",
        "zstd",
      ])
    setRegisteredActionCwd(buildIsoAction.id, acwdCustom,
      "recipes/reproos-iso")
    let initramfsOutputAbs = projectRoot /
      "recipes/reproos-iso/build/reproos-initramfs.img"
    let diskInitramfsOutputAbs = projectRoot /
      "recipes/reproos-iso/build/reproos-iso-disk-initramfs.img"
    let isoOutputAbs = projectRoot / ReproosIsoOutput
    setRegisteredActionDependencyPolicy(buildIsoAction.id,
      automaticMonitorPolicy(@[
        initramfsOutputAbs,
        diskInitramfsOutputAbs,
        isoOutputAbs,
      ]))
    discard target("iso", buildIsoAction)

    # Keep unattended boot media as a distinct immutable output. The autorun
    # kernel command line is part of this action's literal command and cache
    # key, so a normal interactive ISO can never be mistaken for install media.
    let buildUnattendedIsoAction = shell(
      command = buildIsoCommand(
        "build/reproos-unattended-initramfs.img",
        "build/reproos-unattended-disk-initramfs.img",
        "build/reproos-unattended.iso", true),
      actionId = ReproosUnattendedIsoBuildActionId,
      deps = @[stageRootfsAction.id],
      extraInputs = @[
        ReproosIsoRootfsOutput,
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
        "../reprobuild-packages/packages/source/busybox/.repro/output/install/usr/bin/busybox",
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      extraOutputs = @[
        "build/reproos-unattended-initramfs.img",
        "build/reproos-unattended-disk-initramfs.img",
        "build/reproos-unattended.iso",
      ])
    appendRegisteredActionToolIdentityRefs(buildUnattendedIsoAction.id,
      @[
        "bash",
        "busybox",
        "coreutils",
        "cpio",
        "dosfstools",
        "find",
        "gawk",
        "gzip",
        "grub",
        "kernel",
        "kmod",
        "mtools",
        "sed",
        "squashfs-tools",
        "xz",
        "xorriso",
        "zstd",
      ])
    setRegisteredActionCwd(buildUnattendedIsoAction.id, acwdCustom,
      "recipes/reproos-iso")
    let unattendedInitramfsOutputAbs = projectRoot /
      "recipes/reproos-iso/build/reproos-unattended-initramfs.img"
    let unattendedDiskInitramfsOutputAbs = projectRoot /
      "recipes/reproos-iso/build/reproos-unattended-disk-initramfs.img"
    let unattendedIsoOutputAbs = projectRoot / ReproosUnattendedIsoOutput
    setRegisteredActionDependencyPolicy(buildUnattendedIsoAction.id,
      automaticMonitorPolicy(@[
        unattendedInitramfsOutputAbs,
        unattendedDiskInitramfsOutputAbs,
        unattendedIsoOutputAbs,
      ]))
    discard target("unattended-iso", buildUnattendedIsoAction)
