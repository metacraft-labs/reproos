#!/usr/bin/env bash
# M9.R.50.2 -- build-reproos-image.sh: produce a fully-installed
# reproos-installed.qcow2 on the host.
#
# Pipeline:
#
#   1. Parse $REPRO_AUTO_CONFIG (TOML).
#   2. Validate the cacheable staged rootfs and boot artifacts supplied by
#      the Reprobuild graph.
#   3. Write out the disko JSON the plan rendered from the typed
#      layout preset (repro/disk_layouts.nim) named by [disk.layout].
#   4. qemu-img create -f qcow2 reproos-installed.qcow2 <size>.
#   5. sudo modprobe nbd; sudo qemu-nbd --connect=/dev/nbd0 <qcow2>.
#   6. repro disk apply --confirm --device /dev/nbd0 <disko.json>.
#   6b. (attested only) copy the integrity-checked root image and its
#      Merkle tree onto the carriers the measured command line names.
#   7. mount what the layout has a reason to mount, through
#      scripts/mount-guard.sh -- which REFUSES a write-capable mount of
#      any partition a root hash covers.
#   8. install the root and the boot path:
#      uefi-ext4     repro infra install-root --target $WORK/mnt ...
#      uefi-attested nothing to mirror; stage generation a onto the ESP.
#   9. configure the installed root (uefi-ext4 only -- on the attested
#      layout this already happened, in scripts/stage-installed-root.sh,
#      BEFORE the root hash was taken over the tree).
#   11. umount; sudo qemu-nbd --disconnect /dev/nbd0; sudo rmmod nbd.
#   12. mv qcow2 to the recipe's output path.
#
# THE HALVES. On the attested layout this driver is the SECOND half of
# the image build and it installs a disk; it does not build a root.
# The root is built, configured and imaged before it runs:
#
#   scripts/stage-installed-root.sh   the configured root, as a tree
#     -> scripts/build-verity-root.sh   its image + Merkle tree + hash
#       -> the unified kernel image, which pins that hash
#         -> this driver
#
# Anything this driver wrote into that root would make the installed
# image disagree with the root hash inside its own measured command
# line -- silently, because the carrier is a mountable ext4. Hence the
# mount guard rather than a convention.
#
# Input:
#   $1 = absolute output path for the qcow2.
#   REPRO_AUTO_CONFIG, REPROOS_STAGED_ROOTFS and REPROOS_DISK_INITRD env.
#   REPROOS_DISK_LAYOUT, REPROOS_DISK_LAYOUT_ESP_MIB and
#   REPROOS_DISKO_SPEC env, all set by recipes/reproos-image/package.nim
#   from the plan-resolved disk-layout preset.
#   SOURCE_DATE_EPOCH / LC_ALL / TZ for reproducibility.
#
# Output:
#   $1 (the qcow2).
#
# Exit codes:
#   0   = success
#   64  = bad invocation
#   65  = missing tool
#   66  = config parse error
#   67  = staged tree build failed
#   68  = qcow2 / nbd setup failed
#   69  = disk apply failed
#   70  = install-root failed
#   71  = config emit failed
#   72  = cleanup failed (warning, not fatal -- exit is from the
#         original failure), and dbus wiring failed
#   73  = sddm theme install failed
#   74  = sddm path shims / instrumentation failed
#   75  = seatd install failed
#   76  = post-boot health gate install failed
#   77  = the integrity-checked root did not land on its carriers
#         (attested layouts only; see write-verity-carriers.sh, whose
#         own codes are reported on stderr before this one)
#   78  = REFUSED a write-capable mount of a partition whose bytes a
#         root hash already names (see scripts/mount-guard.sh). This is
#         never a transient condition: it means an edit reintroduced
#         the write the measured layout exists to prevent.
#
# 71-76 are produced by scripts/configure-installed-root.sh and passed
# through unchanged, because they are the same failures they always
# were and only their file has moved.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <out.qcow2>" >&2
  exit 64
fi

OUT_QCOW2="$1"

: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set for reproducibility}"
: "${LC_ALL:?LC_ALL=C required}"
: "${TZ:?TZ=UTC required}"
: "${REPRO_AUTO_CONFIG:?REPRO_AUTO_CONFIG must be set}"

# The recipe engine sets cwd to recipes/reproos-image; the repo
# root is two levels up.
REPO_ROOT="$(cd ../.. && pwd)"
REPROBUILD_PACKAGES_ROOT="${REPROBUILD_PACKAGES_ROOT:-$REPO_ROOT/../reprobuild-packages}"
SOURCE_RECIPES_ROOT="${REPRO_FROM_SOURCE_ROOT:-$REPROBUILD_PACKAGES_ROOT/packages/source}"
TARGET_SOURCE_RECIPES_ROOT="/opt/repro/reprobuild-packages/packages/source"
RECIPE_DIR="$(pwd)"
SCRIPT_DIR_SELF="$(cd "$(dirname "$0")" && pwd)"

# Resolve the config path relative to the recipe dir if it's not
# absolute.
case "$REPRO_AUTO_CONFIG" in
  /*) ;;
  *)  REPRO_AUTO_CONFIG="$RECIPE_DIR/$REPRO_AUTO_CONFIG" ;;
esac
if [ ! -f "$REPRO_AUTO_CONFIG" ]; then
  echo "[build-reproos-image] config not found: $REPRO_AUTO_CONFIG" >&2
  exit 64
fi

echo "[build-reproos-image] config: $REPRO_AUTO_CONFIG"

# M9.R.53: sudo is the sole HOST-only tool escape hatch (it needs
# setuid so it can't be provisioned by a store-managed catalog).
# Resolve an absolute path (avoiding a bare ``sudo`` invocation that
# a scoop-style user-writable shim could shadow to a non-setuid
# copy) by probing the canonical host locations in order:
#
#   * /usr/bin/sudo    -- Debian / Ubuntu / Fedora / Arch / macOS
#   * /run/wrappers/bin/sudo  -- NixOS (security.sudo.enable = true)
#   * /usr/local/bin/sudo     -- rare source-install override
#
# Every other tool the script invokes is declared in
# recipes/reproos-image/package.nim. Reprobuild resolves those executable
# identities before starting this action.
SUDO=""
for cand in /usr/bin/sudo /run/wrappers/bin/sudo /usr/local/bin/sudo; do
  if [ -u "$cand" ] || [ -x "$cand" ]; then
    SUDO="$cand"
    break
  fi
done
if [ -z "$SUDO" ]; then
  echo "[build-reproos-image] required host tool missing: sudo" \
       "(probed /usr/bin/sudo /run/wrappers/bin/sudo /usr/local/bin/sudo;" \
       "sudo must be host-installed with setuid; declare-and-provision" \
       "does not apply to setuid binaries)" >&2
  exit 65
fi
echo "[build-reproos-image] sudo: $SUDO"

# Filesystem operations must use the host system's util-linux/coreutils
# binaries.  The from-source tool profile can put target binaries first on
# PATH; those binaries intentionally depend on the staged runtime and cannot
# mount the host's NBD devices.
resolve_host_tool() {
  local tool="$1"
  local candidate
  for candidate in \
    "/run/current-system/sw/bin/$tool" \
    "/usr/bin/$tool" \
    "/bin/$tool" \
    "/sbin/$tool"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "[build-reproos-image] required host tool missing: $tool" >&2
  return 1
}

# Where the unified kernel image is installed on the ESP. This is the
# same string repro/uki.nim declares as UkiEspFallbackPath; the UKI gate
# compares the two, so a change on either side that is not made on the
# other is a red test rather than an image that will not boot.
UKI_ESP_PATH=EFI/BOOT/BOOTX64.EFI

HOST_MOUNT_BIN="$(resolve_host_tool mount)"
HOST_UMOUNT_BIN="$(resolve_host_tool umount)"
HOST_MOUNTPOINT_BIN="$(resolve_host_tool mountpoint)"
HOST_SYNC_BIN="$(resolve_host_tool sync)"

# Required host tools.  Fail loudly if any are missing -- the recipe
# orchestrator already provisions these in the dev shell via the
# runtimeDeps: declaration on reproos-image (M9.R.53).  This local
# defence-in-depth loop catches any resolver bypass (e.g. direct
# invocation of build-reproos-image.sh outside the repro build
# harness) with the same clear diagnostic.
for tool in qemu-img qemu-nbd parted partprobe sgdisk mkfs.ext4 mkfs.vfat rsync grub-install grub-mkconfig modprobe mountpoint patchelf; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[build-reproos-image] required tool missing: $tool" >&2
    exit 65
  fi
done

# sudo applies its host secure_path, which intentionally excludes Repro's
# provisioned tool profile. Preserve the resolved binaries across that
# boundary by invoking the commands through their absolute paths.
QEMU_IMG_BIN="$(command -v qemu-img)"
QEMU_NBD_BIN="$(command -v qemu-nbd)"
PARTPROBE_BIN="$(command -v partprobe)"
MODPROBE_BIN="$(command -v modprobe)"
PATCHELF_BIN="$(command -v patchelf)"

# Locate the `repro` binary.  Probe order:
#   1. $REPRO_BIN env (caller override).
#   2. $REPO_ROOT/build/bin/repro (build_apps.sh output -- the
#      same binary the M9.R.46 driver scripts used).
#   3. $REPO_ROOT/apps/repro/.repro/output/install/usr/bin/repro
#      (per-recipe build output).
#   4. PATH lookup (dev shell provisioned).
REPRO_BIN="${REPRO_BIN:-}"
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  for cand in \
    "$REPO_ROOT/build/bin/repro" \
    "$REPO_ROOT/apps/repro/.repro/output/install/usr/bin/repro"; do
    if [ -x "$cand" ]; then
      REPRO_BIN="$cand"
      break
    fi
  done
fi
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  REPRO_BIN="$(command -v repro 2>/dev/null || true)"
fi
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  echo "[build-reproos-image] 'repro' binary not found; build via build_apps.sh first" >&2
  exit 65
fi
echo "[build-reproos-image] repro: $REPRO_BIN"

# Working dir under the recipe's build dir; cleaned on exit.
WORK="$RECIPE_DIR/build/work"
mkdir -p "$WORK"
STAGE_DIR="${REPROOS_STAGED_ROOTFS:?REPROOS_STAGED_ROOTFS must be set}"
case "$STAGE_DIR" in
  /*) ;;
  *) STAGE_DIR="$RECIPE_DIR/$STAGE_DIR" ;;
esac
MNT_DIR="$WORK/mnt"
mkdir -p "$MNT_DIR"

# ---------------------------------------------------------------
# Cleanup trap.  Best-effort: umount any mounted partitions,
# disconnect /dev/nbd0, rmmod nbd.  Don't mask the original exit
# code.
# ---------------------------------------------------------------
NBD_DEV=""
NBD_CONNECTED=0
MOUNTED_PATHS=()

cleanup() {
  local rc=$?
  set +e
  for p in "${MOUNTED_PATHS[@]}"; do
    if /usr/bin/env LD_LIBRARY_PATH= "$HOST_MOUNTPOINT_BIN" -q "$p"; then
      "$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_UMOUNT_BIN" "$p" 2>/dev/null \
        || "$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_UMOUNT_BIN" -l "$p" 2>/dev/null
    fi
  done
  if [ -n "$NBD_DEV" ] && [ "$NBD_CONNECTED" = "1" ]; then
    "$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$QEMU_NBD_BIN" \
      --disconnect "$NBD_DEV" 2>/dev/null || true
  fi
  exit $rc
}
trap cleanup EXIT

# ---------------------------------------------------------------
# TOML parsing.  Without a TOML library we use a small awk-based
# extractor for the already-normalized values. The installer owns
# schema validation and emits the canonical bundle consumed below.
# ---------------------------------------------------------------
INSTALLER_BIN="${REPROOS_INSTALLER_BIN:-$REPO_ROOT/.repro/output/install/usr/bin/reproos-installer}"
if [ ! -x "$INSTALLER_BIN" ]; then
  echo "[build-reproos-image] installer config emitter missing: $INSTALLER_BIN" >&2
  exit 65
fi
CONFIG_BUNDLE_DIR="$WORK/configuration"
rm -rf "$CONFIG_BUNDLE_DIR"
echo "[build-reproos-image] validating config and emitting canonical artifacts"
"$INSTALLER_BIN" --config "$REPRO_AUTO_CONFIG" \
  --emit-artifacts "$CONFIG_BUNDLE_DIR" \
  || { echo "[build-reproos-image] installer config validation failed" >&2; exit 66; }

# Every value below is read out of the canonical bundle by
# scripts/image-config.sh, which is the ONE reader of a validated
# auto-config.toml. It is a sourced fragment rather than code here
# because the root is now configured by a separate action
# (scripts/stage-installed-root.sh) that has to reach exactly the same
# answers -- see scripts/configure-installed-root.sh for why the
# configuration cannot happen in this driver on an attested layout.
# shellcheck source=recipes/reproos-image/scripts/image-config.sh
. "$SCRIPT_DIR_SELF/image-config.sh"
reproos_load_image_config "$CONFIG_BUNDLE_DIR/auto-config.toml" || exit 66
# The set of legal [disk.layout].type values is NOT listed here any
# more. It is declared once, as typed values, in repro/disk_layouts.nim,
# and resolved and validated at PLAN time by
# recipes/reproos-image/package.nim -- so a typo or an unbuildable
# layout fails before this driver takes sudo and attaches an NBD device,
# and the error names the legal set.
#
# What is left for the driver is a drift check. The disko document below
# was rendered by the plan from the plan's reading of the config; if the
# validated config this driver re-reads disagrees, the document would
# silently describe a different disk from the one that was asked for.
: "${REPROOS_DISK_LAYOUT:?REPROOS_DISK_LAYOUT must be set by the recipe (see recipes/reproos-image/package.nim)}"
: "${REPROOS_DISK_LAYOUT_ESP_MIB:?REPROOS_DISK_LAYOUT_ESP_MIB must be set by the recipe}"
: "${REPROOS_DISKO_SPEC:?REPROOS_DISKO_SPEC must be set by the recipe}"
: "${REPROOS_DISKO_IDENTITY:?REPROOS_DISKO_IDENTITY must be set by the recipe (see recipes/reproos-image/package.nim); without it every filesystem UUID, the ext4 directory-hash seed, the FAT volume serial and the GPT GUIDs come from the clock and the image is not reproducible}"
if [ "$DISK_TYPE" != "$REPROOS_DISK_LAYOUT" ] ||
   [ "$ESP_SIZE_MIB" != "$REPROOS_DISK_LAYOUT_ESP_MIB" ]; then
  echo "[build-reproos-image] disk layout drift: the plan resolved" \
       "type=$REPROOS_DISK_LAYOUT esp_size_mib=$REPROOS_DISK_LAYOUT_ESP_MIB" \
       "but the validated config asks for" \
       "type=$DISK_TYPE esp_size_mib=$ESP_SIZE_MIB;" \
       "re-plan so the layout is rendered from the config in effect" >&2
  exit 66
fi

echo "[build-reproos-image] hostname=$HOSTNAME_VAL user=$USER_NAME size_gb=$DISK_SIZE_GB layout=$DISK_TYPE de=$DE_DEFAULT"

# ---------------------------------------------------------------
# Phase 2: validate the graph-provided rootfs and disk boot artifacts.
# ---------------------------------------------------------------
if [ ! -d "$STAGE_DIR/etc" ] || [ ! -d "$STAGE_DIR/usr" ]; then
  echo "[build-reproos-image] staged rootfs is incomplete: $STAGE_DIR" >&2
  exit 67
fi
SOURCE_KERNEL_ROOT="$SOURCE_RECIPES_ROOT/kernel/.repro/output/install"
SOURCE_KERNEL_PAYLOAD="$SOURCE_KERNEL_ROOT/usr/lib/reproos-kernel"
SOURCE_KERNEL="${REPROOS_KERNEL_IMAGE:-$SOURCE_KERNEL_PAYLOAD/vmlinuz}"
DISK_INITRD="${REPROOS_DISK_INITRD:?REPROOS_DISK_INITRD must be set}"
case "$DISK_INITRD" in
  /*) ;;
  *) DISK_INITRD="$RECIPE_DIR/$DISK_INITRD" ;;
esac
if [ ! -s "$SOURCE_KERNEL" ] || [ ! -s "$DISK_INITRD" ]; then
  echo "[build-reproos-image] source kernel or disk initramfs missing" >&2
  exit 67
fi
echo "[build-reproos-image] staged rootfs: $STAGE_DIR ($(du -sh "$STAGE_DIR" | awk '{print $1}'))"
echo "[build-reproos-image] kernel: $SOURCE_KERNEL"
echo "[build-reproos-image] disk initramfs: $DISK_INITRD"

# ---------------------------------------------------------------
# Phase 3: write the disko JSON the plan rendered.
#
# There is no JSON here any more. The document is rendered from the
# typed disko model (repro_profile's DiskLayout / DiskSpec /
# PartitionSpec / ContentSpec) by repro/disk_layouts.nim at plan time
# and handed to this driver in REPROOS_DISKO_SPEC. That is the whole
# point of the change: one declaration of what a layout is, consumed by
# both the validator and the renderer, instead of a heredoc that could
# drift from the model the apply driver parses it back into.
#
# The value arrives as a single line with \n escapes, so that the
# recipe's shell command stays one line and needs no quoting beyond the
# single quotes around it (the plan refuses to emit a document
# containing a quote or a backslash). printf %b expands it; printf is a
# bash builtin, so this needs no additional tool identity.
# ---------------------------------------------------------------
DISKO_JSON="$WORK/disko.json"
printf '%b' "$REPROOS_DISKO_SPEC" > "$DISKO_JSON"
if [ ! -s "$DISKO_JSON" ]; then
  echo "[build-reproos-image] rendered disko spec is empty" >&2
  exit 66
fi
echo "[build-reproos-image] disko json: $DISKO_JSON (layout $REPROOS_DISK_LAYOUT)"

# The identity document rides beside the disko document, under the name
# `repro disk apply` looks for without being told: <layout>.identity.json.
# It carries the seed every filesystem UUID, the ext4 directory-hash
# seed, the FAT volume serial and the GPT GUIDs are derived from, which
# is what makes two builds of the same inputs produce the same bytes.
# The seed itself is derived at plan time from the auto-config, the
# source-package closure and the layout (repro/disk_layouts.nim).
DISKO_IDENTITY_JSON="${DISKO_JSON%.json}.identity.json"
printf '%b' "$REPROOS_DISKO_IDENTITY" > "$DISKO_IDENTITY_JSON"
if [ ! -s "$DISKO_IDENTITY_JSON" ]; then
  echo "[build-reproos-image] rendered disk identity document is empty" >&2
  exit 66
fi
echo "[build-reproos-image] disk identity: $DISKO_IDENTITY_JSON"

# ...and the engine that will read it has to be one that knows the
# document exists. An older `repro disk apply` ignores it silently and
# seeds every filesystem identifier from the clock, which produces a
# build that looks entirely healthy and is not reproducible. Checked
# here, before qemu-img and before sudo, so the cost of a stale engine
# binary is a second rather than an image. `case` is a shell builtin, so
# this needs no additional tool identity.
REPRO_DISK_USAGE="$("$REPRO_BIN" disk 2>&1 || true)"
case "$REPRO_DISK_USAGE" in
  *--identity*) ;;
  *)
    echo "[build-reproos-image] $REPRO_BIN has no \`disk apply --identity\`," \
         "so it would ignore $DISKO_IDENTITY_JSON and take every filesystem" \
         "UUID, the ext4 directory-hash seed, the FAT volume serial and the" \
         "GPT GUIDs from the clock. Rebuild the engine before building an" \
         "image." >&2
    exit 69
    ;;
esac

# ---------------------------------------------------------------
# Phase 3b: the installed image must describe the disk it actually has.
#
# Two documents leave this build. $DISKO_JSON is what `repro disk apply`
# partitions with, rendered by the plan for the build-time NBD node.
# $CONFIG_BUNDLE_DIR/disko.json is what Phase 9 copies into the
# installed root as /etc/repro/disko.json, rendered by the installer for
# the device the guest will see. They are the same layout rendered by
# the same registry (repro/disk_layouts.nim, compiled into the
# installer by tools/gen_disk_layouts.nim), so they must be the same
# bytes once the two identity parameters -- the spec id and the device
# node -- are normalised.
#
# They were not, before this check existed: the installer rendered its
# own JSON with empty labels, "noatime" instead of "defaults", no
# umask=0077 on the ESP, and /dev/vda regardless of the target. Every
# installed image carried a description of its own disk that disagreed
# with the disk it had. The comparison is done here, before qemu-img and
# before sudo, so a regression costs seconds rather than an image.
INSTALL_TARGET_DEVICE="$(toml_get "$CFG" "install" "target_device")"
INSTALL_TARGET_DEVICE="${INSTALL_TARGET_DEVICE:-/dev/vda}"
spec_id() {
  # The `"id": "<value>",` line of a pretty-printed disko document.
  sed -n 's/^  "id": "\(.*\)",$/\1/p' "$1" | sed -n '1p'
}
PLAN_ID="$(spec_id "$DISKO_JSON")"
INSTALLED_ID="$(spec_id "$CONFIG_BUNDLE_DIR/disko.json")"
if [ -z "$PLAN_ID" ]; then
  echo "[build-reproos-image] cannot read the spec id out of the" \
       "plan-rendered disko document; it is not the pretty-printed form" \
       "this check normalises" >&2
  exit 66
fi
if [ -z "$INSTALLED_ID" ]; then
  # The installer's document is not even the same shape -- a minified
  # one, say, from an installer built before it consumed the layout
  # registry. Leave the id alone so the comparison below reports the
  # whole difference rather than a substitution failure.
  INSTALLED_ID="$PLAN_ID"
fi
sed -e "s|\"$PLAN_ID\"|\"$INSTALLED_ID\"|" \
    -e "s|/dev/nbd0|$INSTALL_TARGET_DEVICE|g" \
    "$DISKO_JSON" > "$WORK/disko-as-installed.json"
APPLIED_SHA="$(sha256sum "$WORK/disko-as-installed.json" | awk '{print $1}')"
INSTALLED_SHA="$(sha256sum "$CONFIG_BUNDLE_DIR/disko.json" | awk '{print $1}')"
if [ "$APPLIED_SHA" != "$INSTALLED_SHA" ]; then
  echo "[build-reproos-image] the disko document the installer emits for" \
       "/etc/repro/disko.json is not the one this build applies" >&2
  echo "[build-reproos-image] --- applied (normalised), sha $APPLIED_SHA ---" >&2
  cat "$WORK/disko-as-installed.json" >&2
  echo "[build-reproos-image] --- installer's, sha $INSTALLED_SHA ---" >&2
  cat "$CONFIG_BUNDLE_DIR/disko.json" >&2
  echo "[build-reproos-image] both come from repro/disk_layouts.nim;" \
       "regenerate the installer's table with" \
       "\`nim r tools/gen_disk_layouts.nim\` and rebuild the installer" >&2
  exit 66
fi
echo "[build-reproos-image] /etc/repro/disko.json matches the applied" \
     "layout (id $INSTALLED_ID, device $INSTALL_TARGET_DEVICE, sha" \
     "$INSTALLED_SHA)"

# ---------------------------------------------------------------
# Phase 4: qemu-img create.
# ---------------------------------------------------------------
TMP_QCOW2="$WORK/reproos-installed.qcow2"
rm -f "$TMP_QCOW2"
LD_LIBRARY_PATH= "$QEMU_IMG_BIN" create -f qcow2 "$TMP_QCOW2" "${DISK_SIZE_GB}G" \
  || { echo "[build-reproos-image] qemu-img create failed" >&2; exit 68; }
echo "[build-reproos-image] qcow2 created: $TMP_QCOW2 (${DISK_SIZE_GB}G)"

# ---------------------------------------------------------------
# Phase 5: nbd module + qemu-nbd --connect.
# ---------------------------------------------------------------
if ! lsmod 2>/dev/null | grep -q '^nbd '; then
  echo "[build-reproos-image] modprobe nbd max_part=16"
  "$SUDO" "$MODPROBE_BIN" nbd max_part=16 \
    || { echo "[build-reproos-image] modprobe nbd failed" >&2; exit 68; }
fi
# Find a free /dev/nbdN.
NBD_DEV=""
for n in 0 1 2 3 4 5 6 7; do
  cand="/dev/nbd$n"
  if [ ! -e "$cand" ]; then continue; fi
  # /sys/block/nbdN/pid exists iff the device is in use.
  if [ -f "/sys/block/nbd$n/pid" ]; then continue; fi
  NBD_DEV="$cand"
  break
done
if [ -z "$NBD_DEV" ]; then
  echo "[build-reproos-image] no free /dev/nbdN available" >&2
  exit 68
fi
echo "[build-reproos-image] qemu-nbd --connect=$NBD_DEV $TMP_QCOW2"
"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$QEMU_NBD_BIN" \
  --connect="$NBD_DEV" "$TMP_QCOW2" \
  || { echo "[build-reproos-image] qemu-nbd connect failed" >&2; exit 68; }
NBD_CONNECTED=1

# Patch the disko JSON to point at the actual nbd device.
sed -i "s|/dev/nbd0|$NBD_DEV|g" "$DISKO_JSON"

# Wait for the kernel to scan the (empty) partition table.
"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$PARTPROBE_BIN" "$NBD_DEV" 2>/dev/null || true
sleep 2

# ---------------------------------------------------------------
# Phase 6: repro disk apply.
#
# Pass LD_LIBRARY_PATH explicitly through sudo because the repro
# binary dlopen()s libclingo.so via the env (the M9.R.46 clingo
# .rodata-bake issue) and sudo strips LD_LIBRARY_PATH by default
# under secure_path policy.  `sudo -E` would propagate the entire
# env but env_keep blocks LD_*; `env VAR=... sudo ...` propagates
# only the var we ask for.
# ---------------------------------------------------------------
echo "[build-reproos-image] repro disk apply --device $NBD_DEV --confirm $DISKO_JSON"
DISK_APPLY_PATH="$PATH"
E2FSPROGS_SBIN="$SOURCE_RECIPES_ROOT/e2fsprogs/.repro/output/install/usr/sbin"
REPRO_CLI_LD="$SOURCE_RECIPES_ROOT/clingo/.repro/output/install/usr/lib"
REPRO_CLI_LD="$REPRO_CLI_LD:$SOURCE_RECIPES_ROOT/sqlite/.repro/output/install/usr/lib"
DISK_APPLY_LD="$SOURCE_RECIPES_ROOT/e2fsprogs/.repro/output/install/usr/lib"
DISK_APPLY_LD="$DISK_APPLY_LD:$SOURCE_RECIPES_ROOT/parted/.repro/output/install/usr/lib"
DISK_APPLY_LD="$DISK_APPLY_LD:$SOURCE_RECIPES_ROOT/util-linux/.repro/output/install/usr/lib"
DISK_APPLY_LD="$DISK_APPLY_LD:$REPRO_CLI_LD"
DISK_APPLY_LD="$DISK_APPLY_LD:${LD_LIBRARY_PATH:-}"
if [ -x "$E2FSPROGS_SBIN/mkfs.ext4" ]; then
  DISK_APPLY_PATH="$E2FSPROGS_SBIN:$DISK_APPLY_PATH"
fi
# SOURCE_DATE_EPOCH / LC_ALL / TZ have to be named here for the same
# reason PATH and LD_LIBRARY_PATH are: sudo resets the environment, so a
# variable this script exports does not reach the command it runs unless
# it is passed as an explicit assignment. mkfs.ext4 stamps the
# superblock's creation and last-write times from SOURCE_DATE_EPOCH and
# there is no flag that pins them, so without this the filesystems come
# out different on every build no matter what identifiers are pinned.
"$SUDO" PATH="$DISK_APPLY_PATH" LD_LIBRARY_PATH="$DISK_APPLY_LD" \
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" LC_ALL="$LC_ALL" TZ="$TZ" \
  "$REPRO_BIN" disk apply --device "$NBD_DEV" --confirm "$DISKO_JSON" \
  || { echo "[build-reproos-image] disk apply failed" >&2; exit 69; }

# Re-scan the partition table.
"$SUDO" "$PARTPROBE_BIN" "$NBD_DEV" 2>/dev/null || true
sleep 2

# ---------------------------------------------------------------
# Phase 6b: put the integrity-checked root onto its carriers.
#
# Only the attested layout has any, and it has them because its root
# is not a filesystem this driver creates and fills. It is a finished
# image whose every byte the root hash covers, and that hash is already
# inside the unified kernel image firmware will measure. So the root
# arrives here as two files to be copied onto two partitions, and the
# copy has to happen BEFORE anything mounts anything: a carrier holds
# no filesystem, there is nothing to mount, and the state volumes the
# later phases do touch are unaffected by it.
#
# The carriers are found by matching the PARTUUID specifiers off the
# measured command line against the partition table `repro disk apply`
# just wrote, so this step is also the first moment at which the two
# can be observed to agree on a real disk rather than derived to agree
# on paper.
# ---------------------------------------------------------------
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    : "${REPROOS_VERITY_ROOTHASH_FILE:?REPROOS_VERITY_ROOTHASH_FILE must name the root hash the verity build produced}"
    : "${REPROOS_VERITY_DATA_DEVICE:?REPROOS_VERITY_DATA_DEVICE must name the carrier this generation's verity data image goes on}"
    : "${REPROOS_VERITY_HASH_DEVICE:?REPROOS_VERITY_HASH_DEVICE must name the carrier this generation's Merkle tree goes on}"
    VERITY_ART_DIR="$(dirname "$REPROOS_VERITY_ROOTHASH_FILE")"
    echo "[build-reproos-image] Phase 6b: writing the verity pair onto its carriers"
    # REPROOS_VERITY_CARRIER_VERIFY is PINNED here rather than
    # inherited. The writer supports switching its `veritysetup verify`
    # pass off, because a caller may not have the tool; this caller
    # does, and on this arm that walk is the strongest statement the
    # build makes -- it is the only check that reads the whole Merkle
    # tree back off the partitions the measured command line names. A
    # value that arrived from the ambient environment could turn it
    # off, and an attested image built with it off would look exactly
    # like one built with it on. So the assignment below overrides
    # whatever was exported, and the build pays for the walk every
    # time.
    SUDO="$SUDO" \
    REPROOS_VERITY_CARRIER_VERIFY=1 \
    REPROOS_VERITY_DATA_IMAGE="$VERITY_ART_DIR/reproos-root.verity.img" \
    REPROOS_VERITY_HASH_TREE="$VERITY_ART_DIR/reproos-root.verity.hashtree" \
    REPROOS_VERITY_ROOTHASH_FILE="$REPROOS_VERITY_ROOTHASH_FILE" \
    REPROOS_VERITY_DATA_DEVICE="$REPROOS_VERITY_DATA_DEVICE" \
    REPROOS_VERITY_HASH_DEVICE="$REPROOS_VERITY_HASH_DEVICE" \
      bash "$SCRIPT_DIR_SELF/write-verity-carriers.sh" "$NBD_DEV" \
      || { echo "[build-reproos-image] writing the verity carriers failed" >&2; exit 77; }
    ;;
esac

# ---------------------------------------------------------------
# Phase 7: mount what this layout has a reason to mount.
#
# THE MOUNT PLAN IS PART OF THE LAYOUT, not a constant, and on the
# attested layout it is the whole mechanism of the defect this phase
# was rewritten to make impossible.
#
#   uefi-ext4      ESP at p1, a writable ext4 root at p2, mounted
#                  read-write because the next phase fills it in.
#
#   uefi-attested  ONLY the ESP. There is no root filesystem to mount:
#                  / is /dev/mapper/reproos-root, a dm-verity device
#                  the initramfs activates from the root hash on the
#                  measured command line, and the p2 carrier merely
#                  holds the image that hash was taken over. Mounting
#                  that carrier read-write SUCCEEDS -- the image is a
#                  valid ext4 at offset 0 -- and by itself destroys the
#                  measurement, because ext4 stamps the superblock's
#                  mount state whether or not anything is written
#                  through the mount.
#
# So this driver does not merely avoid that mount; it cannot perform
# it. Every mount below goes through scripts/mount-guard.sh, which is
# told which partitions the root hash names and REFUSES a write-capable
# mount of any of them (exit 78). A future edit that reintroduces the
# convenient `mount ${NBD_DEV}p2` fails at build time with a
# diagnostic, instead of shipping an image that fails at first boot.
# ---------------------------------------------------------------
ESP_DEV="${NBD_DEV}p1"
ROOT_DEV="${NBD_DEV}p2"

# The partitions whose bytes a root hash names. Both generation slots
# are listed, not just the one being installed: slot B is empty today
# and is still a carrier, and a mount of it would be just as wrong the
# moment an apply has staged into it.
HASHED_CARRIERS=""
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    : "${REPROOS_HASHED_CARRIERS:?REPROOS_HASHED_CARRIERS must list every PARTUUID= specifier whose partition a root hash covers; without it the driver cannot refuse a write-capable mount of one}"
    HASHED_CARRIERS="$REPROOS_HASHED_CARRIERS"
    ;;
esac

mount_guarded() {
  # mount_guarded <device> <mountpoint> [mount options...]
  SUDO="$SUDO" \
  MOUNT_BIN="$HOST_MOUNT_BIN" \
  SGDISK_BIN="$(command -v sgdisk 2>/dev/null || true)" \
  REPROOS_HASHED_CARRIERS="$HASHED_CARRIERS" \
    bash "$SCRIPT_DIR_SELF/mount-guard.sh" "$@"
}

mount_failed() {
  # mount_failed <what> <device> <mountpoint> <exit code>
  #
  # The guard's exit code is PROPAGATED rather than folded into this
  # phase's 69. 78 means a write-capable mount of a partition a root hash
  # covers was refused, and that is not the same event as a mount that
  # would not go: it says an edit reintroduced the write the measured
  # layout exists to prevent, and the exit code is how a caller finds
  # that out without reading the log.
  local what="$1" dev="$2" at="$3" rc="$4"
  if [ "$rc" = "78" ]; then
    echo "[build-reproos-image] REFUSED to mount the $what ($dev) at $at;" \
         "the diagnostic above says why" >&2
  else
    echo "[build-reproos-image] mount $what failed (exit $rc)" >&2
  fi
  exit "$rc"
}

# Wait for the partition device nodes to appear.
for i in 1 2 3 4 5; do
  if [ -b "$ROOT_DEV" ] && [ -b "$ESP_DEV" ]; then break; fi
  sleep 1
done
if [ ! -b "$ROOT_DEV" ] || [ ! -b "$ESP_DEV" ]; then
  echo "[build-reproos-image] expected partition nodes did not appear: $ESP_DEV $ROOT_DEV" >&2
  exit 69
fi

case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    # $MNT_DIR is a plain directory on this arm and stays one. Only its
    # boot/ child becomes a mount point, so that the generation stager
    # writes onto the real ESP.
    "$SUDO" mkdir -p "$MNT_DIR/boot"
    mount_guarded "$ESP_DEV" "$MNT_DIR/boot" \
      || mount_failed esp "$ESP_DEV" "$MNT_DIR/boot" $?
    MOUNTED_PATHS+=("$MNT_DIR/boot")
    ;;
  *)
    mount_guarded "$ROOT_DEV" "$MNT_DIR" \
      || mount_failed root "$ROOT_DEV" "$MNT_DIR" $?
    MOUNTED_PATHS+=("$MNT_DIR")
    "$SUDO" mkdir -p "$MNT_DIR/boot"
    mount_guarded "$ESP_DEV" "$MNT_DIR/boot" \
      || mount_failed esp "$ESP_DEV" "$MNT_DIR/boot" $?
    MOUNTED_PATHS+=("$MNT_DIR/boot")
    ;;
esac

# ---------------------------------------------------------------
# Phase 8: put the root and the boot path onto the disk.
#
# WHICH BOOT PATH IS INSTALLED IS DECIDED BY THE LAYOUT, and the two
# are not variations of one thing:
#
#   uefi-ext4     GRUB. The loader reads its command line out of
#                 /boot/grub/grub.cfg, a file on the ESP. Nothing
#                 measures that file, and nothing needs to: this layout
#                 makes no integrity claim about its root. The root
#                 itself is mirrored here, by
#                 `repro infra install-root`:
#                   --source = the staged Nix-style tree (NOT the live
#                              host root)
#                   --target = our mount point
#                   --device = the nbd device for grub-install
#                   --disko  = our generated json
#
#   uefi-attested A unified kernel image. The kernel, the initrd and
#                 the kernel command line are inside ONE PE binary, so
#                 firmware measures the command line along with
#                 everything else it loads. That is the only reason the
#                 dm-verity root hash on that command line means
#                 anything: on a GRUB boot an attacker who can write to
#                 the ESP can change the expected root hash and every
#                 measurement still reads exactly as before.
#
#                 THERE IS NO ROOT MIRROR ON THIS ARM. The root was
#                 already mirrored, configured and imaged before this
#                 driver ran, and Phase 6b copied that image and its
#                 Merkle tree onto their carriers. Running install-root
#                 here would mirror a second, unmeasured copy of the
#                 tree into a directory nothing boots from -- and if
#                 that directory were the root carrier, it would break
#                 the very hash the command line pins. What is left for
#                 this arm is the ESP.
#
# GRUB is not merely unused on the attested layout -- it never gets
# written, because install-root is what writes it and install-root does
# not run here. A grub.cfg on that ESP would be an unmeasured second
# answer to "how does this machine boot", so the removal below stays as
# a belt-and-braces sweep.
# ---------------------------------------------------------------
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    : "${REPROOS_UKI:?REPROOS_UKI must point at the unified kernel image the recipe assembled; the attested layout has no other boot path}"
    : "${REPROOS_GENERATION_BIN:?REPROOS_GENERATION_BIN must point at the generation stager the recipe built; the attested ESP carries a generation store rather than a bare boot binary}"
    : "${REPROOS_VERITY_ROOTHASH_FILE:?REPROOS_VERITY_ROOTHASH_FILE must name the root hash the verity build produced}"
    : "${REPROOS_VERITY_DATA_DEVICE:?REPROOS_VERITY_DATA_DEVICE must name the carrier this generation's verity data image goes on}"
    : "${REPROOS_VERITY_HASH_DEVICE:?REPROOS_VERITY_HASH_DEVICE must name the carrier this generation's Merkle tree goes on}"
    if [ ! -s "$REPROOS_UKI" ]; then
      echo "[build-reproos-image] unified kernel image missing: $REPROOS_UKI" >&2
      exit 70
    fi
    # The removable-media fallback path, deliberately: it needs no NVRAM
    # boot entry, so one built image boots on any UEFI machine and in a
    # fresh VM whose variable store is empty.
    # The installed image is GENERATION A, and it is put on the ESP
    # through the same stager an apply uses rather than by copying the
    # binary into place here. That is not tidiness: an attested machine
    # boots one generation for the lifetime of a boot and a new one is
    # staged BESIDE it, so the ESP has to carry a generation store from
    # the first install -- two slots and an index -- or the first apply
    # would have nowhere to stage into and no previous pair to leave
    # selectable. The stager writes the slot, records what is in it, and
    # copies the selected slot's bytes to the fallback path UEFI loads.
    echo "[build-reproos-image] staging generation a into the ESP generation store"
    "$SUDO" "$REPROOS_GENERATION_BIN" stage \
      --esp "$MNT_DIR/boot" \
      --uki "$REPROOS_UKI" \
      --slot a \
      --attested \
      --verity-root-hash-file "$REPROOS_VERITY_ROOTHASH_FILE" \
      --verity-data "$REPROOS_VERITY_DATA_DEVICE" \
      --verity-hash "$REPROOS_VERITY_HASH_DEVICE" \
      || { echo "[build-reproos-image] staging generation a failed" >&2; exit 70; }
    "$SUDO" chmod 0644 "$MNT_DIR/boot/$UKI_ESP_PATH"
    # See the block comment above: a grub.cfg left behind is an
    # unmeasured second answer to "how does this machine boot".
    "$SUDO" rm -rf "$MNT_DIR/boot/grub"
    ;;
  *)
    INSTALL_ROOT_ARGS=(
      --target "$MNT_DIR"
      --source "$STAGE_DIR"
      --device "$NBD_DEV"
      --disko "$DISKO_JSON"
      --hostname "$HOSTNAME_VAL"
      --kernel "$SOURCE_KERNEL"
      --initrd "$DISK_INITRD"
    )
    echo "[build-reproos-image] repro infra install-root --target $MNT_DIR --source $STAGE_DIR --device $NBD_DEV"
    "$SUDO" LD_LIBRARY_PATH="$REPRO_CLI_LD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
      "$REPRO_BIN" infra install-root "${INSTALL_ROOT_ARGS[@]}" \
      || { echo "[build-reproos-image] install-root failed" >&2; exit 70; }
    # M9.R.51: rewrite build-time NBD device paths to stable filesystem
    # labels. install-root's renderInstalledGrubCfg + renderFstab bake
    # $NBD_DEV (e.g. /dev/nbd0p2) into grub.cfg's root= and fstab's
    # device columns. Device names differ between QEMU, Hyper-V, and
    # physical systems, while the filesystem labels are part of the
    # declared disk layout and remain stable.
    NBD_BASE="$(basename "$NBD_DEV")"       # e.g. nbd0
    echo "[build-reproos-image] rewriting $NBD_BASE partitions to filesystem labels in grub.cfg + fstab"
    for f in "$MNT_DIR/boot/grub/grub.cfg" "$MNT_DIR/etc/fstab"; do
      if [ -f "$f" ]; then
        "$SUDO" sed -i -E "s|/dev/${NBD_BASE}p1|LABEL=ESP|g; s|/dev/${NBD_BASE}p2|LABEL=reproos-root|g" "$f"
      fi
    done
    ;;
esac

# ---------------------------------------------------------------
# Phase 9: configure the installed root.
#
# The nine phases that used to live here -- the configuration bundle,
# the accounts, DHCP and OpenSSH, the graphical target and autologin,
# D-Bus, the SDDM theme, the compiled-in path shims, seatd and the
# post-boot health gate -- are now
# scripts/configure-installed-root.sh, and WHICH ROOT THEY RUN
# AGAINST IS DECIDED BY THE LAYOUT.
#
#   uefi-ext4      They run here, on the mounted root. Nothing has
#                  made a claim about that filesystem's bytes, so
#                  writing to it costs nothing.
#
#   uefi-attested  They have ALREADY RUN, in a different action, on
#                  the tree `build-verity-root.sh` then took the root
#                  hash over. By the time this driver has a disk the
#                  root is a finished image whose every byte the
#                  measurement names, and there is nothing left here
#                  to configure. Running them here would not merely be
#                  redundant: it would make the installed root
#                  disagree with the root hash inside its own measured
#                  command line, and it would do so silently.
#
# That is why the attested arm never mounts a root carrier at all
# (Phase 7) -- not even to look, because a read-write mount that
# writes nothing already updates the ext4 superblock's mount state
# and breaks the pair.
# ---------------------------------------------------------------
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    echo "[build-reproos-image] Phase 9: the root was configured before" \
         "its hash was taken; nothing to configure here"
    ;;
  *)
    echo "[build-reproos-image] Phase 9: configure the installed root at $MNT_DIR"
    SUDO="$SUDO" \
    REPROOS_CONFIG_BUNDLE_DIR="$CONFIG_BUNDLE_DIR" \
    REPROOS_WORK_DIR="$WORK" \
    REPROOS_SOURCE_RECIPES_ROOT="$SOURCE_RECIPES_ROOT" \
    REPROOS_TARGET_SOURCE_RECIPES_ROOT="$TARGET_SOURCE_RECIPES_ROOT" \
    REPROOS_PATCHELF_BIN="$PATCHELF_BIN" \
      bash "$SCRIPT_DIR_SELF/configure-installed-root.sh" "$MNT_DIR" \
      || exit $?
    ;;
esac

echo "[build-reproos-image] phase summary:"
echo "  staged tree:   $STAGE_DIR ($(du -sh "$STAGE_DIR" 2>/dev/null | awk '{print $1}'))"
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested)
    echo "  root:          on its carriers, integrity-checked; not mounted"
    ;;
  *)
    echo "  mnt root:      $MNT_DIR ($(df -h "$MNT_DIR" 2>/dev/null | tail -1 | awk '{print $3"/"$2}'))"
    ;;
esac
echo "  mnt esp:       $MNT_DIR/boot ($(df -h "$MNT_DIR/boot" 2>/dev/null | tail -1 | awk '{print $3"/"$2}'))"

# ---------------------------------------------------------------
# Phase 11: unmount + disconnect.
# Cleanup trap handles errors; on success we unmount cleanly so
# the qcow2 is fully flushed before we move it.
# ---------------------------------------------------------------
# Normalize the private installed copy, never the shared source stage. The ESP
# is FAT and cannot store Unix inode ownership or permission bits.
#
# On the attested layout the installed root is not here and must not be
# touched: it is the image on the carriers. Running the policy here
# would need that root mounted read-write, which is the one thing this
# arm refuses.
#
# AND IT IS NOT APPLIED ANYWHERE ELSE ON THAT ARM EITHER. The policy
# would have to move ahead of the hash with the rest of the
# configuration, and it cannot yet: `apply` is `os.chown` and refuses to
# run as anything but root, while scripts/stage-installed-root.sh must
# run UNPRIVILEGED because its output is a declared build artifact under
# build/ that the engine has to be able to replace. So an attested image
# built today would carry /etc/shadow owned by the BUILDING USER rather
# than 0:0 and /usr/bin/sudo without its setuid bit. That is precisely
# why the uefi-attested preset is still refused at plan time -- see the
# preset's own unbuildableReason in repro/disk_layouts.nim. Do not read
# this arm's silence as "the policy already ran".
case "$REPROOS_DISK_LAYOUT" in
  uefi-attested) ;;
  *)
    "$SUDO" "$(command -v python3)" \
      "$SCRIPT_DIR_SELF/../../../tools/reproos_image_metadata.py" \
      apply "$MNT_DIR" --skip boot
    ;;
esac
"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_SYNC_BIN"
sleep 2
# Unmount in reverse order (esp before root) so we don't try to
# unmount the parent while a child is still mounted.  Use lazy
# umount as fallback for stubbornly-busy mounts.
for ((i=${#MOUNTED_PATHS[@]}-1; i>=0; i--)); do
  p="${MOUNTED_PATHS[$i]}"
  "$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_UMOUNT_BIN" "$p" 2>/dev/null \
    || "$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_UMOUNT_BIN" -l "$p" 2>/dev/null \
    || { echo "[build-reproos-image] WARNING: failed to unmount $p" >&2; }
done
"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$HOST_SYNC_BIN"
sleep 1
MOUNTED_PATHS=()

"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$QEMU_NBD_BIN" --disconnect "$NBD_DEV"
NBD_CONNECTED=0

# ---------------------------------------------------------------
# Phase 12: stage the qcow2 at the recipe's output path.
# ---------------------------------------------------------------
mkdir -p "$(dirname "$OUT_QCOW2")"
mv "$TMP_QCOW2" "$OUT_QCOW2"
sha256sum "$OUT_QCOW2" | awk '{print "[build-reproos-image] sha256 " $1 "  " $2}'
ls -la "$OUT_QCOW2"

echo "[build-reproos-image] OK"
exit 0
