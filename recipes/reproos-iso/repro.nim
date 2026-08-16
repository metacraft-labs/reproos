## Deterministic hybrid (BIOS + UEFI) ReproOS ISO recipe.
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

const reproosIsoRootfsDeps = @[
  "sway",
  "sddm",
  "systemd",
  "util-linux",
  "kmod",
  "dbus",
  "sudo",
  "e2fsprogs",
  "dosfstools",
  "btrfs-progs",
  "shadow-utils",
  "iana-tzdata",
  "parted",
  "lvm2",
  "popt",
  "gdisk",
  "libgpg-error",
  "libgcrypt",
  "json-c",
  "cryptsetup",
  "less",
  "procps",
  "rsync",
  "strace",
  "iputils",
  "nano",
  "iproute2",
  "kbd",
  "xkeyboard-config",
  "libxkbfile",
  "xkbcomp",
  "libx11",
  "libxau",
  "libxfont2",
  "libattr",
  "libacl",
  "cairo",
  "libcap",
  "libcap-ng",
  "openssl",
  "curl",
  "libdrm",
  "libevdev",
  "expat",
  "libffi",
  "fontconfig",
  "libfontenc",
  "freetype",
  "gcc",
  "glib2",
  "gdk-pixbuf",
  "gmp",
  "harfbuzz",
  "icu",
  "libinput",
  "lzo",
  "libmd",
  "mpc",
  "mpfr",
  "ncurses",
  "nettle",
  "pam",
  "pango",
  "libpciaccess",
  "pcre2",
  "pixman",
  "libjpeg",
  "libpng",
  "libtiff",
  "readline",
  "libseccomp",
  "sqlite",
  "clingo",
  "wayland",
  "wlroots",
  "libxcb",
  "xcb-util",
  "xcb-util-cursor",
  "xcb-util-image",
  "xcb-util-keysyms",
  "xcb-util-renderutil",
  "xcb-util-wm",
  "libxcvt",
  "libxkbcommon",
  "libxml2",
  "libxdmcp",
  "libdisplay-info",
  "fribidi",
  "mtdev",
  "libseat",
  "zlib",
  "zstd",
  "libaio",
  "audit",
  "libbsd",
  "mesa",
  "llvm",
  "qt6-base",
  "qt6-declarative",
  "qt6-quickcontrols2",
  "qt6-wayland",
  "adwaita-icon-theme",
  "dejavu-fonts",
  "xorg-server",
  "xz",
  "tar",
  "bash",
  "gawk",
  "perl",
  "python3",
  "glibc",
  "coreutils",
  "grub",
  "kernel",
  "musl",
  "busybox",
  "ca-certificates",
  "libxcrypt",
  "reproos-installer",
]

package reproosIso:
  defaultToolProvisioning "from-source"

  uses:
    "sh"
    "patchelf"

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
    "reproos-installer"

  build:
    # Drive the ISO build through the build-iso.sh script. The script
    # is the unit-of-execution boundary: it brings up the mformat shim
    # (pinning the FAT volume serial), the grub-mkrescue / xorriso
    # invocation (pinning every other reproducibility-hazardous field),
    # and the sha256 self-report. The recipe layer above only
    # constrains the (inputs, env, output) contract.
    #
    # The ``sh`` typed-tool call below records the env + arg surface
    # the engine fingerprints. ``SOURCE_DATE_EPOCH = 1735689600`` is
    # 2025-01-01T00:00:00Z; that constant is the source of truth for
    # every timestamp downstream of this recipe. ``LC_ALL=C`` + ``TZ=UTC``
    # pin locale + timezone for ASCII-formatted timestamps in the PVD.
    #
    # Inputs declared as ``extraInputs`` so the engine recomputes the
    # action's fingerprint when the source kernel, BusyBox, or scripts change:
    # The script is invoked relative to the recipe directory by the
    # ``cd`` prefix; the engine sets the working dir to the repo root
    # (the action picks up the recipe dir via the literal path). This
    # mirrors the ``apps/repro-*`` action shape that ``apps/repro.nim``
    # uses for the per-binary nim.c(...) calls.
    # M9.R.16.6 — the repro engine sets cwd to the recipe directory
    # (``recipes/reproos-iso``) before launching the shell action, so
    # the historical ``cd recipes/reproos-iso &&`` prefix bombs out
    # with ``No such file or directory``. Drop the prefix; paths are
    # already relative to the recipe dir.
    #
    # M9.R.16.8 — graphical ISO variant. Stage the source-built Sway +
    # SDDM rootfs before invoking grub-mkrescue; build-iso.sh wraps it in a
    # deterministic SquashFS at /live/filesystem.squashfs. The GRUB
    # variant retains its historical ``multi-de`` API name, but advertises
    # only sessions that are actually present in the source closure.
    shell(
      command = ("set -euo pipefail; " &
                 "PACKAGES_ROOT=\"${REPROBUILD_PACKAGES_ROOT:-$(cd ../../.. && pwd)/reprobuild-packages}\"; " &
                 "export REPROBUILD_PACKAGES_ROOT=\"$PACKAGES_ROOT\"; " &
                 "export REPRO_FROM_SOURCE_ROOT=\"$PACKAGES_ROOT/packages/source\"; " &
                 "export REPRO_KERNEL_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install\"; " &
                 "export REPRO_BUSYBOX_INSTALL_ROOT=\"$PACKAGES_ROOT/packages/source/busybox/.repro/output/install\"; " &
                 "export REPROOS_SOURCE_RECIPES=\"" &
                 reproosIsoRootfsDeps.join(" ") & "\"; " &
                 # M9.R.27.6 — stage-de-rootfs.sh mirrors /nix/store
                 # paths which are read-only (cp -a preserves perms).
                 # On re-runs the `rm -rf` of the stale dir hits
                 # ``Permission denied`` for every read-only file
                 # inside the mirror. ``chmod -R u+w`` first so the
                 # cleanup succeeds without sudo.
                 "if [ -d build/de-rootfs ]; then chmod -R u+w build/de-rootfs 2>/dev/null || true; fi; " &
                 "rm -rf build/de-rootfs && mkdir -p build/de-rootfs build; " &
                 "REPRO_LIVE_TARGET=graphical bash scripts/stage-de-rootfs.sh build/de-rootfs; " &
                 "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " &
                 "REPRO_DE_ROOTFS_DIR=\"$PWD/build/de-rootfs\" " &
                 "REPRO_GRUB_VARIANT=multi-de " &
                 "REPRO_LIVE_INIT=1 " &
                 "REPRO_LIVE_INIT_OUT=\"$PWD/build/reproos-initramfs.img\" " &
                 # M9.R.39.2 -- pass the REPRO_INSTALLER_AUTORUN env var
                 # through so build-iso.sh appends repro.installer
                 # .autorun=1 to the default GRUB menu entry's cmdline,
                 # triggering the reproos-installer-autorun.service
                 # systemd unit at boot.  Default is empty so the live
                 # ISO behaves normally unless the investigator opts in
                 # via the env var at build time.
                 "REPRO_INSTALLER_AUTORUN=\"${REPRO_INSTALLER_AUTORUN:-0}\" " &
                 "bash scripts/build-iso.sh " &
                 "\"$PACKAGES_ROOT/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz\" " &
                 "build/reproos-initramfs.img " &
                 "build/reproos.iso"),
      actionId = "reproosIso.build_iso",
      # M9.R.16.7 — extraInputs/extraOutputs are resolved relative to
      # the action's cwd (the recipe directory). The legacy
      # ``recipes/reproos-iso/...`` prefix was duplicated under the
      # action cwd; drop it.
      extraInputs = @[
        "../../../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../../../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
        "../../../reprobuild-packages/packages/source/busybox/.repro/output/install/usr/bin/busybox",
        "scripts/build-iso.sh",
        "scripts/stage-de-rootfs.sh",
        "scripts/normalize-source-runtime.sh",
        # Live-init initramfs builder + its product-owned init script.
        # Regenerates the initramfs in-tree so the
        # SquashFS payload is consumed by the kernel via pivot_root
        # instead of the d-i text installer ignoring it.
        "scripts/build-initramfs.sh",
        "initramfs/init",
        # Deterministic package-free rootfs skeleton. Source recipe install
        # mirrors provide every executable, library, unit, and data file.
        "scripts/build-base-rootfs.sh",
        # M9.R.19.3 -- the ReproOS Installer wizard binary, built by
        # the apps/reproos-installer/ recipe via the c_cpp_cmake
        # convention. Declared here as a verbatim path-extraInput so
        # the engine refingerprints the ISO build when the wizard
        # binary changes. stage-de-rootfs.sh consumes it via a fixed
        # repo-relative path (see the M9.R.19.3 block in that script);
        # without this declaration the engine would not see binary
        # updates as ISO-cache invalidations.
        "../../apps/reproos-installer/.repro/output/install/usr/bin/reproos-installer",
      ],
      extraOutputs = @[
        "build/reproos-initramfs.img",
        "build/reproos.iso",
      ])
