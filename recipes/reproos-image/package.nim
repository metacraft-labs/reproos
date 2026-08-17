## Deterministic installed ReproOS disk-image package.
##
## The build stages the same source package closure as the ISO, applies the
## generated installer configuration to a QCOW2 device, and installs the boot
## loader. The resulting image is ready for VM boot and health testing.

import std/strutils

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import "../../apps/reproos-installer/package" as installerPackage
import "../../repro/package_sets" as packageSets

const
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
    "curl"
    "libdrm"
    "libevdev"
    "expat"
    "libffi"
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
      "REPRO_QCOW2_SEED=\"${REPRO_QCOW2_SEED:-deadbeefcafebabe}\"",
      "LD_LIBRARY_PATH= PATH=/run/current-system/sw/bin:$PATH",
      "bash scripts/build-reproos-image.sh build/reproos-installed.qcow2",
      ">build/reproos-image-build.log 2>&1",
    ].join(" ")
    let buildImageAction = shell(
      command = buildImageCommand,
      actionId = ReproosImageBuildActionId,
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/repro-sway-diag",
        "recipes/reproos-image/scripts/reproos-health-check",
        "tests/fixtures/auto-config-minimal.toml",
        installerPackage.ReproosInstallerBinary,
        # ISO and image builds share one source-package staging pipeline.
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        "recipes/reproos-iso/scripts/relocate-nix-to-repro.sh",
        "recipes/reproos-iso/scripts/normalize-source-runtime.sh",
        "recipes/reproos-iso/scripts/build-base-rootfs.sh",
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init-disk",
      ],
      extraOutputs = @[
        "build/reproos-installed.qcow2",
      ])
    # The opaque shell driver receives the exact executable profiles declared
    # above, plus all staged package outputs.
    appendRegisteredActionToolIdentityRefs(buildImageAction.id,
      reproosImageRuntimeTools & packageSets.ReproosGraphicalRootfsPackages)
    setRegisteredActionCwd(buildImageAction.id, acwdCustom,
      "recipes/reproos-image")
    discard target("image", buildImageAction)
