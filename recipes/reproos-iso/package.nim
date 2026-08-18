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

import std/strutils

import repro_project_dsl
import repro_dsl_stdlib/packages/sh
import "../../apps/reproos-installer/package" as installerPackage
import "../../repro/package_sets" as packageSets

const
  ReproosIsoBuildActionId* = "reproosIso.build_iso"
  ReproosIsoOutput* = "recipes/reproos-iso/build/reproos.iso"

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

  build:
    # The driver owns deterministic rootfs staging, initramfs generation,
    # grub-mkrescue, and the final checksum. The action declares every source
    # input and pins timestamps, locale, and timezone.
    let buildIsoCommand = @[
      "set -euo pipefail;",
      "PACKAGES_ROOT=\"${REPROBUILD_PACKAGES_ROOT:-$(cd ../../.. && pwd)/reprobuild-packages}\";",
      "export REPROBUILD_PACKAGES_ROOT=\"$PACKAGES_ROOT\";",
      "export REPRO_FROM_SOURCE_ROOT=\"$PACKAGES_ROOT/packages/source\";",
      "export REPROOS_INSTALLER_BIN=\"$PWD/../../" &
        installerPackage.ReproosInstallerBinary & "\";",
      "export REPRO_KERNEL_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install\";",
      "export REPRO_BUSYBOX_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/busybox/.repro/output/install\";",
      "export REPROOS_SOURCE_RECIPES=\"" &
        packageSets.ReproosGraphicalRootfsPackages.join(" ") & "\";",
      # Install mirrors may contain read-only files. Make a stale staging tree
      # writable before replacing it.
      "if [ -d build/de-rootfs ]; then chmod -R u+w build/de-rootfs 2>/dev/null || true; fi;",
      "rm -rf build/de-rootfs;",
      "mkdir -p build/de-rootfs build;",
      "REPRO_LIVE_TARGET=graphical bash scripts/stage-de-rootfs.sh build/de-rootfs;",
      "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " &
        "REPRO_DE_ROOTFS_DIR=\"$PWD/build/de-rootfs\" " &
        "REPRO_GRUB_VARIANT=multi-de " &
        "REPRO_LIVE_INIT=1 " &
        "REPRO_LIVE_INIT_OUT=\"$PWD/build/reproos-initramfs.img\" " &
        # Autorun remains opt-in for unattended installation tests.
        "REPRO_INSTALLER_AUTORUN=\"${REPRO_INSTALLER_AUTORUN:-0}\" " &
        "bash scripts/build-iso.sh " &
        "\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz\" " &
        "build/reproos-initramfs.img build/reproos.iso",
    ].join(" ")
    let buildIsoAction = shell(
      command = buildIsoCommand,
      actionId = ReproosIsoBuildActionId,
      deps = @[installerPackage.ReproosInstallerInstallActionId],
      extraInputs = @[
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
        "../reprobuild-packages/packages/source/busybox/.repro/output/install/usr/bin/busybox",
        "recipes/reproos-iso/scripts/build-iso.sh",
        "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        "recipes/reproos-iso/scripts/normalize-source-runtime.sh",
        # The live initramfs pivots into the staged SquashFS root.
        "recipes/reproos-iso/scripts/build-initramfs.sh",
        "recipes/reproos-iso/initramfs/init",
        # Source package install mirrors populate this rootfs skeleton.
        "recipes/reproos-iso/scripts/build-base-rootfs.sh",
        installerPackage.ReproosInstallerBinary,
      ],
      extraOutputs = @[
        "build/reproos-initramfs.img",
        "build/reproos.iso",
      ])
    appendRegisteredActionToolIdentityRefs(buildIsoAction.id,
      @["bash", "patchelf", "xorriso", "mtools", "squashfs-tools"] &
        packageSets.ReproosGraphicalRootfsPackages)
    setRegisteredActionCwd(buildIsoAction.id, acwdCustom,
      "recipes/reproos-iso")
    discard target("iso", buildIsoAction)
