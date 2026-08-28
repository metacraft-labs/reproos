## Deterministic installed ReproOS disk-image package.
##
## The build stages the same source package closure as the ISO, applies the
## generated installer configuration to a QCOW2 device, and installs the boot
## loader. The resulting image is ready for VM boot and health testing.

import std/[os, strutils]

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import "../../apps/reproos-installer/package" as installerPackage
import "../reproos-iso/package" as isoPackage
import "../../repro/package_sets" as packageSets

const
  ReproosDiskInitrdActionId* = "reproosImage.build_disk_initrd"
  ReproosDiskInitrdOutput* =
    "recipes/reproos-image/build/reproos-disk-initramfs.img"
  ReproosImageBuildActionId* = "reproosImage.build_image"
  ReproosImageOutput* =
    "recipes/reproos-image/build/reproos-installed.qcow2"

# Keep this list aligned with bare commands invoked by the image driver.
# ``sudo`` is host-provided because its setuid semantics cannot be supplied by
# a store-managed executable profile.
const reproosImageRuntimeTools = @[
  # Disk image, partitioning, filesystems, and boot loader.
  "qemu-img",
  "qemu-nbd",
  "parted",
  "partprobe",
  "sgdisk",
  "mkfs.ext4",
  "mkfs.vfat",
  "grub-install",
  "grub-mkconfig",
  "rsync",
  "patchelf",
  # NBD lifecycle and mounted filesystem operations.
  "modprobe",
  "rmmod",
  "lsmod",
  "mount",
  "umount",
  "mountpoint",
  # Configuration parsing and deterministic tree manipulation.
  "awk",
  "sed",
  "grep",
  "sha256sum",
  "dirname",
  "basename",
  "chmod",
  "mv",
  "cp",
  "rm",
  "mkdir",
  "ls",
  "cat",
  "sleep",
  "sync",
  "touch",
  "du",
  "df",
  "tail",
]

package reproosImage:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "bash"
    "cpio"
    "find"
    "gzip"
    "sed"

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

  runtimeDeps:
    # Each bare command used by the image driver has a resolved identity.
    "qemu-img"
    "qemu-nbd"
    "parted"
    "partprobe"
    "sgdisk"
    "mkfs.ext4"
    "mkfs.vfat"
    "grub-install"
    "grub-mkconfig"
    "rsync"
    "patchelf"
    "modprobe"
    "rmmod"
    "lsmod"
    "mount"
    "umount"
    "mountpoint"
    "awk"
    "sed"
    "grep"
    "sha256sum"
    "dirname"
    "basename"
    "chmod"
    "mv"
    "cp"
    "rm"
    "mkdir"
    "ls"
    "cat"
    "sleep"
    "sync"
    "touch"
    "du"
    "df"
    "tail"

  build:
    let projectRoot = activeProviderProjectRoot()
    let reprobuildRoot = getEnv("REPROBUILD_SRC", "../reprobuild")
    let reproCliInput = reprobuildRoot / "build" / "bin" / "repro"

    # The installed system needs a disk-root initramfs rather than the ISO's
    # live-media initramfs. Build and cache it independently of privileged
    # disk assembly.
    let buildDiskInitrdCommand = @[
      "set -euo pipefail;",
      "WORKSPACE_ROOT=\"$(cd ../../.. && pwd)\";",
      "PACKAGES_ROOT=\"${REPROBUILD_PACKAGES_ROOT:-$WORKSPACE_ROOT/reprobuild-packages}\";",
      "export REPROBUILD_PACKAGES_ROOT=\"$PACKAGES_ROOT\";",
      "export REPRO_FROM_SOURCE_ROOT=\"$PACKAGES_ROOT/packages/source\";",
      "export REPRO_KERNEL_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install\";",
      "export REPRO_BUSYBOX_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/busybox/.repro/output/install\";",
      "mkdir -p build;",
      "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
      "REPRO_INITRAMFS_INIT=init-disk",
      "bash ../reproos-iso/scripts/build-initramfs.sh",
      "build/reproos-disk-initramfs.img;",
    ].join(" ")
    let buildDiskInitrdAction = shell(
      command = buildDiskInitrdCommand,
      actionId = ReproosDiskInitrdActionId,
      extraInputs = @[
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
        "../reprobuild-packages/packages/source/busybox/.repro/output/install/usr/bin/busybox",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      extraOutputs = @["build/reproos-disk-initramfs.img"])
    appendRegisteredActionToolIdentityRefs(buildDiskInitrdAction.id, @[
      "bash",
      "busybox",
      "coreutils",
      "cpio",
      "find",
      "gzip",
      "kernel",
      "kmod",
      "sed",
      "xz",
      "zstd",
    ])
    setRegisteredActionCwd(buildDiskInitrdAction.id, acwdCustom,
      "recipes/reproos-image")
    let diskInitrdOutputAbs = projectRoot / ReproosDiskInitrdOutput
    setRegisteredActionDependencyPolicy(buildDiskInitrdAction.id,
      automaticMonitorPolicy(@[diskInitrdOutputAbs]))
    discard target("disk-initramfs", buildDiskInitrdAction)

    # The default fixture supports reproducible smoke builds. Tests can supply
    # a generated configuration through REPRO_AUTO_CONFIG.
    let buildImageCommand = @[
      "set -euo pipefail;",
      "mkdir -p build;",
      "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
      "REPROOS_SOURCE_RECIPES=\"" &
        packageSets.ReproosGraphicalRootfsPackages.join(" ") & "\"",
      "REPRO_AUTO_CONFIG=\"${REPRO_AUTO_CONFIG:-../../tests/fixtures/auto-config-minimal.toml}\"",
      "REPROOS_INSTALLER_BIN=\"$PWD/../../" &
        installerPackage.ReproosInstallerBinary & "\"",
      "REPROOS_STAGED_ROOTFS=\"$PWD/../reproos-iso/build/de-rootfs\"",
      "REPROOS_DISK_INITRD=\"$PWD/build/reproos-disk-initramfs.img\"",
      "REPRO_QCOW2_SEED=\"${REPRO_QCOW2_SEED:-deadbeefcafebabe}\"",
      "REPRO_BIN=\"" & reproCliInput & "\"",
      "LD_LIBRARY_PATH= PATH=/run/current-system/sw/bin:$PATH",
      "bash scripts/build-reproos-image.sh build/reproos-installed.qcow2",
      ">build/reproos-image-build.log 2>&1",
    ].join(" ")
    let buildImageAction = shell(
      command = buildImageCommand,
      actionId = ReproosImageBuildActionId,
      deps = @[
        installerPackage.ReproosInstallerReadyActionId,
        isoPackage.ReproosIsoRootfsActionId,
        buildDiskInitrdAction.id,
      ],
      extraInputs = @[
        reproCliInput,
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/repro-sway-diag",
        "recipes/reproos-image/scripts/reproos-sway.conf",
        "recipes/reproos-image/scripts/reproos-desktop.qml",
        "recipes/reproos-image/scripts/reproos-health-check",
        "recipes/reproos-image/scripts/reproos-first-boot-enroll",
        "recipes/reproos-image/scripts/reproos-network",
        "recipes/reproos-image/scripts/reproos-network-wait",
        "recipes/reproos-image/scripts/reproos-network.service",
        "recipes/reproos-image/scripts/reproos-udhcpc-hook",
        "tests/fixtures/auto-config-minimal.toml",
        installerPackage.ReproosInstallerBinary,
        isoPackage.ReproosIsoRootfsOutput,
        ReproosDiskInitrdOutput,
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
      ],
      extraOutputs = @[
        "build/reproos-installed.qcow2",
      ],
      cacheable = false)
    # The opaque shell driver receives the exact executable profiles declared
    # above, plus all staged package outputs.
    appendRegisteredActionToolIdentityRefs(buildImageAction.id,
      reproosImageRuntimeTools & packageSets.ReproosGraphicalRootfsPackages)
    setRegisteredActionCwd(buildImageAction.id, acwdCustom,
      "recipes/reproos-image")
    let imageBuildDirAbs = projectRoot / "recipes/reproos-image/build"
    setRegisteredActionDependencyPolicy(buildImageAction.id,
      automaticMonitorPolicy(@[imageBuildDirAbs]))
    discard target("image", buildImageAction)
