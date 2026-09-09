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
import "../../repro/disk_layouts" as diskLayouts
import "../../repro/verity" as verity
import "../../repro/uki" as ukiModule
import "../../repro/attest" as attestModule
import "../../repro/generations" as generations

const
  ReproosDiskInitrdActionId* = "reproosImage.build_disk_initrd"
  ReproosDiskInitrdOutput* =
    "recipes/reproos-image/build/reproos-disk-initramfs.img"
  ReproosImageBuildActionId* = "reproosImage.build_image"
  ReproosImageOutput* =
    "recipes/reproos-image/build/reproos-installed.qcow2"

  ReproosStageInstalledRootActionId* = "reproosImage.stage_installed_root"
  ReproosInstalledRootOutput* = "recipes/reproos-image/build/installed-root"
    ## The INSTALLED root, as a directory, complete before anything takes
    ## a hash over it.
    ##
    ## This exists because of an order rather than for tidiness. On the
    ## attested layout the root filesystem's bytes are named by a
    ## dm-verity root hash that is baked into a unified kernel image
    ## firmware measures, so every step that configures the root -- the
    ## configuration bundle, the accounts, the services, the desktop --
    ## has to have already happened when ``build_verity_root`` runs. The
    ## image driver installs this; it does not build it, and it does not
    ## write to it.

  ReproosVerityRootActionId* = "reproosImage.build_verity_root"
  ReproosVerityRootDir* = "recipes/reproos-image/build/verity"
  ReproosVerityDataImageOutput* =
    ReproosVerityRootDir & "/" & verity.VerityDataImageFileName
  ReproosVerityHashTreeOutput* =
    ReproosVerityRootDir & "/" & verity.VerityHashTreeFileName
  ReproosVerityRootHashOutput* =
    ReproosVerityRootDir & "/" & verity.VerityRootHashFileName
    ## Where the root hash lands. This is the value the boot artifact has
    ## to carry on its kernel command line for the launch measurement to
    ## cover the root filesystem; a consumer reads it from here rather
    ## than re-deriving it, so there is one answer per build.
  ReproosVerityManifestOutput* =
    ReproosVerityRootDir & "/" & verity.VerityManifestFileName

  ReproosUkiToolActionId* = "reproosImage.build_uki_tool"
  ReproosUkiToolBinary* = "recipes/reproos-image/build/bin/reproos-uki"
    ## The typed assembler. Built by ``nim.c`` — a typed DSL edge, not a
    ## shell escape — so the compiler, the source and the binary are all
    ## declared to the graph.
  ReproosGenerationToolActionId* = "reproosImage.build_generation_tool"
  ReproosGenerationToolBinary* =
    "recipes/reproos-image/build/bin/reproos-generation"
    ## The generation stager. It puts a unified kernel image into one of
    ## the ESP's two generation slots and points the next boot at it; on
    ## an attested machine it refuses to write the slot the machine is
    ## running from, because the launch measurement of this boot was taken
    ## over exactly those bytes.
  ReproosUkiActionId* = "reproosImage.build_uki"
  ReproosUkiDir* = "recipes/reproos-image/build/uki"
  ReproosUkiOutput* = ReproosUkiDir & "/" & ukiModule.UkiFileName
    ## The unified kernel image: kernel, initrd, kernel command line and
    ## EFI stub in one PE binary. What firmware loads, and what a launch
    ## measurement covers in one piece — which is the whole reason the
    ## root hash rides on the command line INSIDE it rather than in a
    ## loader configuration file beside it.
  ReproosUkiManifestOutput* =
    ReproosUkiDir & "/" & ukiModule.UkiManifestFileName
  ReproosUkiDigestOutput* = ReproosUkiDir & "/" & ukiModule.UkiDigestFileName
  ReproosUkiCmdlineOutput* =
    ReproosUkiDir & "/" & ukiModule.UkiCmdlineFileName

  ReproosAttestActionId* = "reproosImage.build_measurement_manifest"
  ReproosAttestDir* = "recipes/reproos-image/build/attest"
  ReproosAttestManifestOutput* =
    ReproosAttestDir & "/" & attestModule.AttestManifestFileName
    ## What a TPM will report when this image boots, written beside the
    ## image that will produce it. It is the build's half of every later
    ## verification: a running machine's evidence is compared against this
    ## document, and a verifier who does not want to trust it rebuilds the
    ## image and re-derives the same bytes.

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
  # The integrity-checked root's carriers. `dd` copies the two images
  # onto the partitions the measured command line names, `blockdev`
  # answers whether a carrier is big enough to hold one, and
  # `veritysetup` re-walks the written pair on the partitions rather
  # than on the files it came from. Without the last one the driver
  # would ship an image whose root it never checked once it was in
  # place; see recipes/reproos-image/scripts/write-verity-carriers.sh.
  "dd",
  "blockdev",
  "veritysetup",
  "wc",
  "tr",
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
    # The unified-kernel-image assembler is compiled from source by a
    # typed `nim.c` edge in the build block below. `nim` and `clang`
    # have no from-source recipe in reprobuild-packages, so under this
    # project's `defaultToolProvisioning "from-source"` both fall
    # through to the pinned nixpkgs channel rather than bootstrapping a
    # toolchain.
    "nim"
    "clang"

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

    # Resolve the disk layout HERE rather than in the driver. An unknown
    # or not-yet-buildable [disk.layout].type has to fail while the plan
    # is being built -- before the image action takes sudo, attaches an
    # NBD device and partitions it -- and the failure has to name the
    # legal set. repro/disk_layouts.nim owns that set; this is its only
    # consumer in the graph.
    let recipeDir = projectRoot / "recipes" / "reproos-image"
    let autoConfigSetting = block:
      let configured = getEnv("REPRO_AUTO_CONFIG")
      if configured.len > 0: configured
      else: "../../tests/fixtures/auto-config-minimal.toml"
    # The driver resolves a relative REPRO_AUTO_CONFIG against the recipe
    # directory; resolve it the same way so both read one file.
    let autoConfigPath =
      if isAbsolute(autoConfigSetting): autoConfigSetting
      else: recipeDir / autoConfigSetting
    if not fileExists(autoConfigPath):
      raise newException(ValueError,
        "recipes/reproos-image: REPRO_AUTO_CONFIG does not exist: " &
        autoConfigPath)
    let layoutRequest = diskLayouts.parseDiskLayoutRequest(
      readFile(autoConfigPath), "reproos-image", "/dev/nbd0")
    let layoutError = diskLayouts.validateDiskLayoutRequest(layoutRequest)
    if layoutError.len > 0:
      raise newException(ValueError,
        "recipes/reproos-image: " & autoConfigPath & ": " & layoutError)
    # The bytes the driver writes to $WORK/disko.json, rendered from the
    # typed DiskLayout the preset builds. Carried as one line with \n
    # escapes so the shell command below stays a single line; a quote or
    # a backslash would need escaping rules this deliberately does not
    # have, so refuse to emit one instead of guessing.
    let diskoSpec = diskLayouts.renderDiskoJson(
      layoutRequest.name, layoutRequest.params)
    for ch in diskoSpec:
      if ch == '\'' or ch == '\\':
        raise newException(ValueError,
          "recipes/reproos-image: layout " & layoutRequest.name &
          " rendered a disko document containing a quote or a backslash," &
          " which the single-line environment hand-off cannot carry")
    let diskoSpecLine = diskoSpec.replace("\n", "\\n")

    # The identity document that rides beside the disko document.
    #
    # Without it, `repro disk apply` leaves every filesystem UUID, the
    # ext4 directory-hash seed, the FAT volume serial and the GPT GUIDs
    # to the tools, which take them from the clock and the system RNG --
    # so two builds of identical inputs produce different bytes. The
    # seed is derived from the auto-config, the ordered source-package
    # closure, the layout and its sizing (repro/disk_layouts.nim), so
    # the same inputs give the same disk on any host.
    #
    # It is carried the same way the disko document is: rendered here,
    # written by the driver into the work directory next to disko.json,
    # and found by `repro disk apply` by convention. Nothing has to
    # remember to forward it at the call site.
    let diskIdentitySpec = diskLayouts.renderDiskIdentityJson(
      readFile(autoConfigPath),
      packageSets.ReproosGraphicalRootfsPackages, layoutRequest)
    for ch in diskIdentitySpec:
      if ch == '\'' or ch == '\\':
        raise newException(ValueError,
          "recipes/reproos-image: the disk identity document contains a" &
          " quote or a backslash, which the single-line environment" &
          " hand-off cannot carry")
    let diskIdentitySpecLine = diskIdentitySpec.replace("\n", "\\n")

    # ---------------------------------------------------------------
    # The installed root, staged BEFORE its hash is taken.
    #
    # On the writable-root layout the image driver mounts the root and
    # then spends nine phases configuring it, and that is fine there:
    # nothing has made a claim about those bytes.
    #
    # On the attested layout it is not fine, and the failure is silent.
    # The root is a finished image whose every byte the root hash covers,
    # that hash is inside the unified kernel image firmware measures, and
    # the image is a mountable ext4 sitting at offset 0 of a carrier --
    # so the old order MOUNTED IT, configured it, exited 0, and shipped
    # an image whose root no longer matched the root hash on its own
    # measured command line. A read-write mount that writes nothing is
    # enough to do it: ext4 stamps the superblock's mount state on mount.
    #
    # So the configuration moves ahead of the hash, into its own action
    # over a plain directory. This action is registered ONLY for the
    # attested layout: the writable-root build configures its root in
    # place, on a filesystem it just created, and would otherwise pay for
    # a second full copy of the closure it then threw away.
    let isAttestedLayout = layoutRequest.name == "uefi-attested"
    var stageInstalledRootDeps: seq[string] = @[]
    if isAttestedLayout:
      let stageInstalledRootCommand = @[
        "set -euo pipefail;",
        "mkdir -p build;",
        "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
        "REPROOS_STAGED_ROOTFS=\"$PWD/../reproos-iso/build/de-rootfs\"",
        "REPRO_AUTO_CONFIG=\"${REPRO_AUTO_CONFIG:-../../tests/fixtures/auto-config-minimal.toml}\"",
        "REPROOS_INSTALLER_BIN=\"$PWD/../../" &
          installerPackage.ReproosInstallerBinary & "\"",
        "REPROOS_DISKO_SPEC='" & diskoSpecLine & "'",
        "REPRO_BIN=\"" & reproCliInput & "\"",
        "LD_LIBRARY_PATH= PATH=/run/current-system/sw/bin:$PATH",
        "bash scripts/stage-installed-root.sh build/installed-root",
        ">build/stage-installed-root.log 2>&1",
      ].join(" ")
      let stageInstalledRootAction = shell(
        command = stageInstalledRootCommand,
        actionId = ReproosStageInstalledRootActionId,
        deps = @[installerPackage.ReproosInstallerReadyActionId,
                 isoPackage.ReproosIsoRootfsActionId],
        extraInputs = @[
          "recipes/reproos-image/scripts/stage-installed-root.sh",
          "recipes/reproos-image/scripts/configure-installed-root.sh",
          "recipes/reproos-image/scripts/image-config.sh",
          installerPackage.ReproosInstallerBinary,
          isoPackage.ReproosIsoRootfsOutput,
          reproCliInput,
        ],
        # Declared outputs are resolved against the action's cwd
        # (`recipes/reproos-image`, set below), so this is the relative
        # spelling -- exactly as the sibling actions and the ISO recipe's
        # `build/de-rootfs` do it. `ReproosInstalledRootOutput` is the
        # project-root-relative form and belongs in the extraInputs of
        # the actions that CONSUME this tree, not here: using it here
        # would name a path under
        # `recipes/reproos-image/recipes/reproos-image/`, which nothing
        # produces.
        extraOutputs = @["build/installed-root"])
      # The same profile the image driver gets, because it runs the same
      # configuration phases: the desktop packages are symlinked into the
      # tree by path, so the action has to be able to see them.
      appendRegisteredActionToolIdentityRefs(stageInstalledRootAction.id,
        reproosImageRuntimeTools & packageSets.ReproosGraphicalRootfsPackages)
      setRegisteredActionCwd(stageInstalledRootAction.id, acwdCustom,
        "recipes/reproos-image")
      let installedRootAbs = projectRoot / ReproosInstalledRootOutput
      setRegisteredActionDependencyPolicy(stageInstalledRootAction.id,
        automaticMonitorPolicy(@[installedRootAbs]))
      discard target("installed-root", stageInstalledRootAction)
      stageInstalledRootDeps = @[stageInstalledRootAction.id]

    # ---------------------------------------------------------------
    # The integrity-checked read-only root.
    #
    # A read-only root that nothing checks is only a mount option: it
    # stops the running system writing to its own root, and stops
    # nothing else. What makes it an ATTESTABLE root is the dm-verity
    # Merkle tree built here, whose root hash is a short value that
    # changes if any byte of the root filesystem changes. A boot path
    # carrying that value, and a launch measurement covering that boot
    # path, together pin every byte of the root.
    #
    # Every value the tools would otherwise invent is derived HERE, from
    # the same identity seed the partition table's identifiers come
    # from, and passed in. The alternative -- letting `veritysetup`
    # choose a salt and `mke2fs` choose a UUID -- produces a different
    # root hash on every build, which would make the value meaningless
    # as a name for the bytes.
    #
    # This action is registered whatever layout is selected, because the
    # verity root is a function of the staged tree and not of the
    # partition table. What consumes it is the attested layout.
    let identitySeed = diskLayouts.reproosImageIdentitySeed(
      readFile(autoConfigPath),
      packageSets.ReproosGraphicalRootfsPackages, layoutRequest)
    let verityRootSpec = verity.verityRootSpec(identitySeed)
    let verityRootSpecError = verity.validateVeritySpec(verityRootSpec)
    if verityRootSpecError.len > 0:
      raise newException(ValueError,
        "recipes/reproos-image: " & verityRootSpecError)
    #
    # WHICH TREE THE HASH IS TAKEN OVER is decided by the layout, and it
    # is the point of the split. On the attested layout it is the
    # INSTALLED root -- the tree the action above configured -- because a
    # hash over anything else is a hash of a root the machine will never
    # run. On the writable-root layout nothing consumes this image, so it
    # keeps being taken over the graph-provided tree and costs nothing
    # extra.
    let verityStagedRootfs =
      if isAttestedLayout: "$PWD/build/installed-root"
      else: "$PWD/../reproos-iso/build/de-rootfs"
    let verityStagedRootfsInput =
      if isAttestedLayout: ReproosInstalledRootOutput
      else: isoPackage.ReproosIsoRootfsOutput
    let buildVerityRootCommand = @[
      "set -euo pipefail;",
      "mkdir -p build;",
      "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
      "REPROOS_STAGED_ROOTFS=\"" & verityStagedRootfs & "\"",
      "REPROOS_VERITY_SALT=\"" & verityRootSpec.salt & "\"",
      "REPROOS_VERITY_UUID=\"" & verityRootSpec.uuid & "\"",
      "REPROOS_VERITY_FS_UUID=\"" &
        verity.verityRootFsUuid(identitySeed) & "\"",
      "REPROOS_VERITY_FS_HASH_SEED=\"" &
        verity.verityRootFsHashSeed(identitySeed) & "\"",
      "bash scripts/build-verity-root.sh build/verity;",
    ].join(" ")
    let buildVerityRootAction = shell(
      command = buildVerityRootCommand,
      actionId = ReproosVerityRootActionId,
      deps = @[isoPackage.ReproosIsoRootfsActionId] & stageInstalledRootDeps,
      extraInputs = @[
        "recipes/reproos-image/scripts/build-verity-root.sh",
        verityStagedRootfsInput,
      ],
      extraOutputs = @[
        "build/verity/" & verity.VerityDataImageFileName,
        "build/verity/" & verity.VerityHashTreeFileName,
        "build/verity/" & verity.VerityRootHashFileName,
        "build/verity/" & verity.VerityManifestFileName,
      ])
    # `cryptsetup` is what supplies `veritysetup`, and `e2fsprogs` what
    # supplies `mkfs.ext4`. Both are already in the image's package
    # closure, so naming them here costs nothing beyond what the image
    # build already pays.
    appendRegisteredActionToolIdentityRefs(buildVerityRootAction.id, @[
      "bash",
      "coreutils",
      "cryptsetup",
      "e2fsprogs",
      "find",
      "gawk",
      "util-linux",
    ])
    setRegisteredActionCwd(buildVerityRootAction.id, acwdCustom,
      "recipes/reproos-image")
    let verityOutputDirAbs = projectRoot / ReproosVerityRootDir
    setRegisteredActionDependencyPolicy(buildVerityRootAction.id,
      automaticMonitorPolicy(@[verityOutputDirAbs]))
    discard target("verity-root", buildVerityRootAction)

    # ---------------------------------------------------------------
    # The unified kernel image.
    #
    # The read-only root already has a name that changes when any byte
    # of it changes: the dm-verity root hash the verity action above
    # writes. This is where that name is put somewhere a launch
    # measurement covers.
    #
    # A GRUB command line could carry the root hash too, and it would be
    # worth nothing: `grub.cfg` is a file on the ESP, firmware measures
    # the loader binary rather than the string the loader chooses to
    # pass on, and an attacker who edits one line boots the same signed
    # GRUB with a different root hash and identical PCRs. A unified
    # kernel image packs the kernel, the initrd, the command line and
    # the EFI stub into ONE PE binary, so the command line is inside the
    # thing that gets measured.
    #
    # Two properties of the edge below are load-bearing:
    #
    #   * The assembly is TYPED. `repro/uki.nim` owns the section set,
    #     the section order, the PE arithmetic and the composition of
    #     the command line out of the verity keys; the assembler is
    #     compiled from source by `nim.c` (a typed DSL edge) and invoked
    #     with an argv that `ukiAssembleArgv` renders from the same
    #     typed request the inputs and outputs below are derived from.
    #     There is no `objcopy` pipeline, no `ukify`, and no shell
    #     script. Stated precisely, because the distinction matters:
    #     the final process SPAWN below still goes through `shell`,
    #     which is the only surface the DSL offers for running a binary
    #     this project built (the installer is invoked the same way).
    #     What is typed is the request, the validation, the declared
    #     inputs, the declared outputs and the argv — not the exec.
    #   * It reads the root hash from the FILE the verity action writes,
    #     rather than being handed a value. The command line is
    #     therefore a function of the staged root closure, which is what
    #     makes "change one byte of the root and the measurement moves"
    #     true rather than aspirational.
    #
    # SIGNING IS OUT OF SCOPE, deliberately. The image below is
    # unsigned. `systemd-stub` measures the sections it consumes whether
    # or not the PE carries an Authenticode signature, so an unsigned
    # image is fully attestable on the TPM tier; Secure Boot firmware
    # will refuse to load it, so `sbsign` and a key-custody story remain
    # deferred. See the header of `repro/uki.nim`.
    # `cc = "clang"` is not a preference, it is the fix for a MEASURED
    # failure. `nim c` lowers Nim to C and shells out to a C compiler,
    # and `nim.c` defaults that compiler to `gcc` -- declaring `gcc` as
    # this edge's tool identity in the process. Under this project's
    # `defaultToolProvisioning "from-source"` a completed source mirror
    # outranks the pinned channel, and this workspace's from-source
    # `gcc` mirror is broken: its `cc1` cannot load `libmpc.so.3`.
    # Measured, before this argument existed: `repro build uki-tool`
    # failed with that loader error on every translation unit. `clang`
    # has no from-source recipe, so it falls through to the pinned
    # nixpkgs channel -- which is the same reason the Nim gates compile
    # with it.
    let ukiToolAction = nim.c(
      source = "tools/reproos_uki.nim",
      binary = ReproosUkiToolBinary,
      cc = "clang",
      # `CC` too, and for a SECOND measured reason. nixpkgs' `nim.cfg`
      # substitutes the caller's `$CC` into the backend's `.exe` setting
      # (`clang.exe %= "$CC"`), and the engine replaces only `PATH` in an
      # action -- every other variable is inherited. So a developer
      # shell's `CC=gcc` reached this edge even with `--cc:clang`
      # selected, and nim shelled out to a bare `gcc` the hermetic PATH
      # does not carry: exit 127, with the clang flag set (`-ferror-limit`)
      # visible in the failing command line. This is the same defect
      # `tests/nim-gate.sh` pins for the Nim gates; the compiler an edge
      # compiles with must come from its DECLARED identities, never from
      # the caller's environment.
      extraEnv = @[("CC", "clang")],
      actionId = ReproosUkiToolActionId,
      extraInputs = @["repro/uki.nim", "repro/verity.nim"])
    discard target("uki-tool", ukiToolAction)

    # The generation stager, built the same way and for the same reasons
    # (`cc`/`CC` pinned to clang; see the two paragraphs above).
    #
    # It is a separate binary from the assembler because it runs at a
    # different time and on a different machine: the assembler produces a
    # unified kernel image during the build, while the stager puts one
    # onto an ESP -- during the image build for the first generation, and
    # on the installed machine for every one after it. An attested
    # instance is where an apply has to be told that it may stage but not
    # switch, and this is the binary that tells it.
    let generationToolAction = nim.c(
      source = "tools/reproos_generation.nim",
      binary = ReproosGenerationToolBinary,
      cc = "clang",
      extraEnv = @[("CC", "clang")],
      actionId = ReproosGenerationToolActionId,
      extraInputs = @["repro/generations.nim", "repro/uki.nim",
                      "repro/verity.nim"])
    discard target("generation-tool", generationToolAction)

    # The stub. Resolved by content, not by path: `repro/uki.nim` pins
    # its sha256 and skips any candidate that is not those bytes, so a
    # host carrying fifty systemd versions resolves to one answer or to
    # none. A missing stub is reported by the action rather than raised
    # here, so that a `repro build` which does not select the UKI target
    # is not failed by a host that has no need of one.
    let resolvedStub = ukiModule.resolveUkiStub()
    # The volumes this generation's command line names. An installed image
    # is generation A: it is the first one on the machine, and the first
    # `repro infra apply` stages its successor into slot B rather than
    # over the top of it. The specifiers are PARTITION GUIDs derived from
    # the same identity seed the partition table's own identifiers come
    # from, so the measured command line names the exact partitions the
    # apply will create, before either the image or the machine exists —
    # and a filesystem label could not do it, because a Merkle tree
    # carries no filesystem and both root carriers hold an image with the
    # same one.
    let installedSlot = generations.gsA
    let bootDevices = generations.attestedBootDevices(
      identitySeed, installedSlot)
    let bootDeviceError =
      generations.validateAttestedBootDevices(bootDevices)
    if bootDeviceError.len > 0:
      raise newException(ValueError,
        "recipes/reproos-image: " & bootDeviceError)

    # Every partition whose bytes a root hash names -- BOTH slots, not
    # just the one being installed. Slot B is empty at install time and
    # is still a carrier: the moment an apply has staged into it, a
    # write-capable mount of it is exactly as destructive as one of slot
    # A, and a list that named only the installed slot would let the
    # second one through. The image driver refuses such a mount rather
    # than merely not performing it, and it can only do that if it is
    # told which partitions they are.
    var hashedCarrierSpecs: seq[string] = @[]
    for slot in [generations.gsA, generations.gsB]:
      let slotDevices = generations.attestedBootDevices(identitySeed, slot)
      let slotError = generations.validateAttestedBootDevices(slotDevices)
      if slotError.len > 0:
        raise newException(ValueError,
          "recipes/reproos-image: " & slotError)
      hashedCarrierSpecs.add slotDevices.data
      hashedCarrierSpecs.add slotDevices.hash
    for spec in hashedCarrierSpecs:
      if spec.contains(' ') or spec.contains('\'') or spec.contains('"'):
        raise newException(ValueError,
          "recipes/reproos-image: a carrier specifier " & spec.escape() &
          " cannot be carried in the space-separated hand-off the driver" &
          " reads it from")
    let hashedCarrierList = hashedCarrierSpecs.join(" ")
    let ukiRequest = ukiModule.UkiAssembleRequest(
      stubPath: resolvedStub,
      kernelPath: "../../../reprobuild-packages/packages/source/kernel/" &
        ".repro/output/install/usr/lib/reproos-kernel/vmlinuz",
      initrdPath: "build/reproos-disk-initramfs.img",
      verityRootHashPath: "build/verity/" & verity.VerityRootHashFileName,
      verityDataDevice: bootDevices.data,
      verityHashDevice: bootDevices.hash,
      stateVarDevice: bootDevices.stateVar,
      stateHomeDevice: bootDevices.stateHome,
      extraArgs: @[],
      osReleaseVersion: "0.1.0",
      unamePath: "../../../reprobuild-packages/packages/source/kernel/" &
        ".repro/output/install/usr/lib/reproos-kernel/kernel.release",
      sourceDateEpoch: 1735689600,
      outputDir: "build/uki")
    if resolvedStub.len > 0:
      let requestError = ukiModule.validateUkiAssembleRequest(ukiRequest)
      if requestError.len > 0:
        raise newException(ValueError,
          "recipes/reproos-image: " & requestError)
    var ukiArgv = ukiModule.ukiAssembleArgv(
      "$PWD/../../" & ReproosUkiToolBinary, ukiRequest)
    var ukiCommand = "set -euo pipefail; mkdir -p build/uki;"
    for a in ukiArgv:
      ukiCommand.add " " & quoteShellPosix(a)
    let buildUkiAction = shell(
      command = ukiCommand,
      actionId = ReproosUkiActionId,
      deps = @[ukiToolAction.id, buildVerityRootAction.id,
               buildDiskInitrdAction.id],
      extraInputs = @[
        ReproosUkiToolBinary,
        ReproosVerityRootHashOutput,
        ReproosDiskInitrdOutput,
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz",
        "../reprobuild-packages/packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/kernel.release",
      ],
      extraOutputs = ukiModule.ukiOutputPaths(ukiRequest))
    # The assembler is a self-contained binary that reads files and
    # writes files: it shells out to nothing, so the only identity this
    # edge needs is the shell that starts it.
    appendRegisteredActionToolIdentityRefs(buildUkiAction.id, @["bash"])
    setRegisteredActionCwd(buildUkiAction.id, acwdCustom,
      "recipes/reproos-image")
    let ukiOutputDirAbs = projectRoot / ReproosUkiDir
    setRegisteredActionDependencyPolicy(buildUkiAction.id,
      automaticMonitorPolicy(@[ukiOutputDirAbs]))
    discard target("uki", buildUkiAction)

    # What the image will measure, written before any machine has booted
    # it. The document is computed by `repro attest expect` -- the same
    # command a verifier runs when it rebuilds this image and compares --
    # so there is one implementation of the schema and of the PCR
    # calculator, exercised from both ends. What this recipe owns is the
    # EDGE: which artifacts the document is a function of, which backends
    # it asks for, and where it lands.
    let attestRequest = attestModule.AttestExpectRequest(
      ukiPath: "build/uki/" & ukiModule.UkiFileName,
      verityImagePath: "build/verity/" & verity.VerityDataImageFileName,
      verityRootHashPath: "build/verity/" & verity.VerityRootHashFileName,
      # The same seed the partition table's identifiers are derived from,
      # so the document names the configuration by the value that already
      # decides every other identity in this build.
      configFingerprint: identitySeed,
      backends: @(attestModule.AttestBackends),
      outputDir: "build/attest")
    let attestRequestError =
      attestModule.validateAttestExpectRequest(attestRequest)
    if attestRequestError.len > 0:
      raise newException(ValueError,
        "recipes/reproos-image: " & attestRequestError)
    var attestArgv = attestModule.attestExpectArgv(
      "$PWD/../../" & reproCliInput, attestRequest)
    var attestCommand = "set -euo pipefail; mkdir -p build/attest;"
    for a in attestArgv:
      attestCommand.add " " & quoteShellPosix(a)
    let buildAttestAction = shell(
      command = attestCommand,
      actionId = ReproosAttestActionId,
      deps = @[buildUkiAction.id, buildVerityRootAction.id],
      extraInputs = @[
        reproCliInput,
        ReproosUkiOutput,
        ReproosVerityDataImageOutput,
        ReproosVerityRootHashOutput,
      ],
      extraOutputs = attestModule.attestOutputPaths(attestRequest))
    appendRegisteredActionToolIdentityRefs(buildAttestAction.id, @["bash"])
    setRegisteredActionCwd(buildAttestAction.id, acwdCustom,
      "recipes/reproos-image")
    let attestOutputDirAbs = projectRoot / ReproosAttestDir
    setRegisteredActionDependencyPolicy(buildAttestAction.id,
      automaticMonitorPolicy(@[attestOutputDirAbs]))
    discard target("measurement-manifest", buildAttestAction)

    # The default fixture supports reproducible smoke builds. Tests can supply
    # a generated configuration through REPRO_AUTO_CONFIG.
    #
    # There is no REPROOS_SOURCE_RECIPES here. It belongs to the ISO
    # recipe, whose stage-de-rootfs.sh filters the source-package set
    # with it; this driver never runs that script and never reads the
    # variable, and the packages this action can reach are decided by
    # its tool identities below. An assignment nothing reads looks like
    # a pin and is not one.
    #
    # The boot path the driver installs is decided by the layout, and
    # the attested one needs the unified kernel image. It is named
    # unconditionally so the assignment is visible in one place, and
    # DEPENDED ON only when the selected layout actually boots from it
    # -- an unconditional dependency would make every uefi-ext4 image
    # build assemble a UKI it never installs, and fail on any host with
    # no copy of the pinned stub.
    let bootsFromUki = layoutRequest.name == "uefi-attested"
    let buildImageCommand = @[
      "set -euo pipefail;",
      "mkdir -p build;",
      "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
      "REPROOS_UKI=\"$PWD/build/uki/" & ukiModule.UkiFileName & "\"",
      "REPROOS_GENERATION_BIN=\"$PWD/../../" &
        ReproosGenerationToolBinary & "\"",
      "REPROOS_VERITY_ROOTHASH_FILE=\"$PWD/build/verity/" &
        verity.VerityRootHashFileName & "\"",
      "REPROOS_VERITY_DATA_DEVICE=\"" & bootDevices.data & "\"",
      "REPROOS_VERITY_HASH_DEVICE=\"" & bootDevices.hash & "\"",
      "REPROOS_HASHED_CARRIERS=\"" & hashedCarrierList & "\"",
      "REPRO_AUTO_CONFIG=\"${REPRO_AUTO_CONFIG:-../../tests/fixtures/auto-config-minimal.toml}\"",
      "REPROOS_INSTALLER_BIN=\"$PWD/../../" &
        installerPackage.ReproosInstallerBinary & "\"",
      "REPROOS_STAGED_ROOTFS=\"$PWD/../reproos-iso/build/de-rootfs\"",
      "REPROOS_DISK_INITRD=\"$PWD/build/reproos-disk-initramfs.img\"",
      "REPROOS_DISK_LAYOUT=\"" & layoutRequest.name & "\"",
      "REPROOS_DISK_LAYOUT_ESP_MIB=\"" &
        $layoutRequest.params.espSizeMib & "\"",
      "REPROOS_DISKO_SPEC='" & diskoSpecLine & "'",
      "REPROOS_DISKO_IDENTITY='" & diskIdentitySpecLine & "'",
      "REPRO_BIN=\"" & reproCliInput & "\"",
      "LD_LIBRARY_PATH= PATH=/run/current-system/sw/bin:$PATH",
      "bash scripts/build-reproos-image.sh build/reproos-installed.qcow2",
      ">build/reproos-image-build.log 2>&1",
    ].join(" ")
    let buildImageAction = shell(
      command = buildImageCommand,
      actionId = ReproosImageBuildActionId,
      deps = (if bootsFromUki:
                @[installerPackage.ReproosInstallerReadyActionId,
                  isoPackage.ReproosIsoRootfsActionId,
                  buildDiskInitrdAction.id,
                  buildUkiAction.id,
                  buildAttestAction.id,
                  generationToolAction.id]
              else:
                @[installerPackage.ReproosInstallerReadyActionId,
                  isoPackage.ReproosIsoRootfsActionId,
                  buildDiskInitrdAction.id]),
      extraInputs = @[
        reproCliInput,
        "recipes/reproos-image/scripts/build-reproos-image.sh",
        "recipes/reproos-image/scripts/write-verity-carriers.sh",
        "recipes/reproos-image/scripts/mount-guard.sh",
        "recipes/reproos-image/scripts/configure-installed-root.sh",
        "recipes/reproos-image/scripts/image-config.sh",
        "tools/reproos_image_metadata.py",
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
      ] & (if bootsFromUki:
             # The two files Phase 6b copies onto the root carriers, plus
             # the root hash it checks them against. Declared only on the
             # attested arm: on `uefi-ext4` nothing reads them, and an
             # unconditional input would make every ordinary image build
             # pay for an ext4 image of the whole closure and a Merkle
             # tree over it that it then throws away.
             @[ReproosVerityDataImageOutput,
               ReproosVerityHashTreeOutput,
               ReproosVerityRootHashOutput]
           else:
             @[]),
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
