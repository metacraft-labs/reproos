#!/usr/bin/env bash
set -euo pipefail

# stage-installed-root.sh -- produce the INSTALLED root tree, complete,
# BEFORE anything takes a hash over it.
#
# THIS SCRIPT EXISTS BECAUSE OF AN ORDER, AND THE ORDER IS THE WHOLE
# POINT.
#
# The integrity-checked layout boots a dm-verity root. Its bytes are
# named by a root hash that `build-verity-root.sh` computes over a
# directory tree, and that hash is baked into a unified kernel image
# firmware measures. Everything the installed system needs in its root
# -- the configuration bundle, the accounts, DHCP and OpenSSH, the
# graphical session, the health gate -- therefore has to be in the tree
# BEFORE that hash is taken. Not "mostly": entirely. A read-write mount
# of the finished image that writes nothing at all already invalidates
# the pair, because ext4 stamps its superblock on mount.
#
# So the image build has two halves and this is the first one:
#
#   stage-installed-root.sh   the root, configured, as a directory
#     -> build-verity-root.sh   the image of it, and its root hash
#       -> the unified kernel image, which pins that hash
#         -> build-reproos-image.sh, which installs the image onto a
#            disk and NEVER writes to it
#
# Usage:
#   stage-installed-root.sh <output-tree>
#
# Required environment:
#   REPROOS_STAGED_ROOTFS    the graph-provided root filesystem this
#                            tree is mirrored from
#   REPRO_AUTO_CONFIG        the operator's configuration
#   REPROOS_INSTALLER_BIN    the installer, which is the validator and
#                            the canonical artifact emitter
#   REPROOS_DISKO_SPEC       the plan-rendered disko document, escaped
#                            as one line; the mount plan in the
#                            installed /etc/fstab is rendered from it
#   REPRO_BIN                the engine, for `repro infra install-root`
#
# Optional environment:
#   REPROOS_SOURCE_RECIPES_ROOT / REPROOS_TARGET_SOURCE_RECIPES_ROOT
#   REPROOS_WORK_DIR         scratch (default: <output-tree>.work)
#
# Exit codes:
#   64 = bad invocation
#   65 = a required tool is missing
#   66 = config validation failed
#   67 = the staged root filesystem is missing or unusable
#   70 = mirroring the root failed
#   71..77 = configure-installed-root.sh's own codes, passed through
#   78 = the root does not separate the state the attested layout puts on
#        its own volumes

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-tree>" >&2
  exit 64
fi
OUT_TREE="$1"
case "$OUT_TREE" in
  /*) ;;
  *) OUT_TREE="$PWD/$OUT_TREE" ;;
esac

: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set for reproducibility}"
: "${LC_ALL:?LC_ALL=C required}"
: "${TZ:?TZ=UTC required}"
: "${REPRO_AUTO_CONFIG:?REPRO_AUTO_CONFIG must be set}"
: "${REPROOS_STAGED_ROOTFS:?REPROOS_STAGED_ROOTFS must name the graph-provided root filesystem}"
: "${REPROOS_DISKO_SPEC:?REPROOS_DISKO_SPEC must carry the plan-rendered disko document; the installed /etc/fstab is rendered from it}"

SCRIPT_DIR_SELF="$(cd "$(dirname "$0")" && pwd)"
RECIPE_DIR="$(pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR_SELF/../../.." && pwd)"
REPROBUILD_PACKAGES_ROOT="${REPROBUILD_PACKAGES_ROOT:-$REPO_ROOT/../reprobuild-packages}"
SOURCE_RECIPES_ROOT="${REPROOS_SOURCE_RECIPES_ROOT:-${REPRO_FROM_SOURCE_ROOT:-$REPROBUILD_PACKAGES_ROOT/packages/source}}"
TARGET_SOURCE_RECIPES_ROOT="${REPROOS_TARGET_SOURCE_RECIPES_ROOT:-/opt/repro/reprobuild-packages/packages/source}"

STAGE_DIR="$REPROOS_STAGED_ROOTFS"
case "$STAGE_DIR" in
  /*) ;;
  *) STAGE_DIR="$RECIPE_DIR/$STAGE_DIR" ;;
esac
case "$REPRO_AUTO_CONFIG" in
  /*) ;;
  *) REPRO_AUTO_CONFIG="$RECIPE_DIR/$REPRO_AUTO_CONFIG" ;;
esac

WORK="${REPROOS_WORK_DIR:-${OUT_TREE}.work}"
mkdir -p "$WORK"

for tool in rsync awk sed sha256sum python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "[stage-installed-root] required tool missing: $tool" >&2
    exit 65
  fi
done

if [ ! -d "$STAGE_DIR/etc" ] || [ ! -d "$STAGE_DIR/usr" ]; then
  echo "[stage-installed-root] staged rootfs is incomplete: $STAGE_DIR" >&2
  exit 67
fi

REPRO_BIN="${REPRO_BIN:-}"
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  for cand in \
    "$REPO_ROOT/build/bin/repro" \
    "$REPO_ROOT/apps/repro/.repro/output/install/usr/bin/repro"; do
    if [ -x "$cand" ]; then REPRO_BIN="$cand"; break; fi
  done
fi
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  REPRO_BIN="$(command -v repro 2>/dev/null || true)"
fi
if [ -z "$REPRO_BIN" ] || [ ! -x "$REPRO_BIN" ]; then
  echo "[stage-installed-root] 'repro' binary not found" >&2
  exit 65
fi

INSTALLER_BIN="${REPROOS_INSTALLER_BIN:-$REPO_ROOT/.repro/output/install/usr/bin/reproos-installer}"
if [ ! -x "$INSTALLER_BIN" ]; then
  echo "[stage-installed-root] installer config emitter missing: $INSTALLER_BIN" >&2
  exit 65
fi

# ---------------------------------------------------------------------
# The canonical artifact bundle. Emitted here rather than taken from the
# image driver, because this half runs FIRST -- the driver has not
# started, and on the attested layout the answers this bundle carries
# have to be inside the root image the driver installs.
# ---------------------------------------------------------------------
CONFIG_BUNDLE_DIR="$WORK/configuration"
rm -rf "${CONFIG_BUNDLE_DIR:?}"
echo "[stage-installed-root] validating config and emitting canonical artifacts"
"$INSTALLER_BIN" --config "$REPRO_AUTO_CONFIG" \
  --emit-artifacts "$CONFIG_BUNDLE_DIR" \
  || { echo "[stage-installed-root] installer config validation failed" >&2; exit 66; }

# shellcheck source=recipes/reproos-image/scripts/image-config.sh
. "$SCRIPT_DIR_SELF/image-config.sh"
reproos_load_image_config "$CONFIG_BUNDLE_DIR/auto-config.toml" || exit 66

DISKO_JSON="$WORK/disko.json"
printf '%b' "$REPROOS_DISKO_SPEC" > "$DISKO_JSON"
if [ ! -s "$DISKO_JSON" ]; then
  echo "[stage-installed-root] rendered disko spec is empty" >&2
  exit 66
fi

# ---------------------------------------------------------------------
# Mirror the graph-provided root, then render the mount plan into it.
#
# `repro infra install-root` is the renderer for /etc/fstab, and it is
# used here for the same reason the driver used it: a second renderer
# would be a second answer to what the installed system's mount plan is.
# The target is a plain DIRECTORY rather than a mounted filesystem --
# which is the entire difference between this half and the old order --
# so --no-grub is passed and no --device is needed: nothing is being
# made bootable here, only complete.
# ---------------------------------------------------------------------
# `${VAR:?}` on every destructive path: this script runs under sudo in
# no configuration today, but `rm -rf ""/boot` is `rm -rf /boot`, and a
# guard that costs nothing belongs on a line that could.
rm -rf "${OUT_TREE:?}"
mkdir -p "$OUT_TREE"
echo "[stage-installed-root] mirroring $STAGE_DIR -> $OUT_TREE"
REPRO_CLI_LD="$SOURCE_RECIPES_ROOT/clingo/.repro/output/install/usr/lib"
REPRO_CLI_LD="$REPRO_CLI_LD:$SOURCE_RECIPES_ROOT/sqlite/.repro/output/install/usr/lib"
LD_LIBRARY_PATH="$REPRO_CLI_LD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$REPRO_BIN" infra install-root \
    --target "$OUT_TREE" \
    --source "$STAGE_DIR" \
    --disko "$DISKO_JSON" \
    --hostname "$HOSTNAME_VAL" \
    --no-grub \
  || { echo "[stage-installed-root] install-root failed" >&2; exit 70; }

# The device columns install-root renders are the BUILD-TIME node the
# plan's disko document names. Rewrite them to the stable identifiers
# the installed system will see, exactly as the driver has always done
# for the writable-root layout.
#
# The root line is deliberately absent on the attested layout: its
# carriers declare no filesystem and no mountpoint, so `collectMountPlan`
# produces no `/` entry. Naming a carrier at `/` would mount the
# unchecked bytes instead of the dm-verity device the initramfs
# activates.
if [ -f "$OUT_TREE/etc/fstab" ]; then
  # Read out of the document rather than defaulted to a device name: a
  # literal here would be a second opinion about which disk the plan
  # described, and it would be silently wrong the first time the plan
  # moved.
  DISKO_DEV="$(awk -F'"' '/"device"/ {print $4; exit}' "$DISKO_JSON")"
  if [ -z "$DISKO_DEV" ]; then
    echo "[stage-installed-root] the rendered disko document names no" \
         "device, so the mount plan cannot be rewritten to stable" \
         "identifiers and the installed fstab would carry a build-time" \
         "node" >&2
    exit 66
  fi
  DISKO_DEV_BASE="$(basename "$DISKO_DEV")"
  echo "[stage-installed-root] rewriting $DISKO_DEV_BASE partitions in fstab"
  sed -i -E "s|/dev/${DISKO_DEV_BASE}p1|LABEL=ESP|g; s|/dev/${DISKO_DEV_BASE}p2|LABEL=reproos-root|g" \
    "$OUT_TREE/etc/fstab"
fi

# /boot is where the ESP mounts. Anything install-root left there is a
# second, UNMEASURED description of how the machine boots, and on this
# layout it would also be several hundred megabytes of the 4 GiB carrier
# spent on a kernel the unified kernel image already carries.
rm -rf "${OUT_TREE:?}/boot"
mkdir -p "$OUT_TREE/boot"

# ---------------------------------------------------------------------
# Configure it. This is the step whose POSITION is the fix: it
# runs on a directory, before any hash exists, rather than on a mounted
# root after one has been taken.
# ---------------------------------------------------------------------
SUDO="/usr/bin/env" \
REPROOS_CONFIG_BUNDLE_DIR="$CONFIG_BUNDLE_DIR" \
REPROOS_WORK_DIR="$WORK" \
REPROOS_SOURCE_RECIPES_ROOT="$SOURCE_RECIPES_ROOT" \
REPROOS_TARGET_SOURCE_RECIPES_ROOT="$TARGET_SOURCE_RECIPES_ROOT" \
REPROOS_ATTESTATION_AGENT_BIN="${REPROOS_ATTESTATION_AGENT_BIN:-}" \
REPROOS_ATTESTATION_TIER="${REPROOS_ATTESTATION_TIER:-mock}" \
  bash "$SCRIPT_DIR_SELF/configure-installed-root.sh" "$OUT_TREE" \
  || exit $?

# ---------------------------------------------------------------------
# Separate the state, and refuse a tree that is not separated.
#
# The configuration above emitted the factory copy of /var and /home and
# the tmpfiles.d fragment that seeds them. On THIS layout the originals
# then have to go: /var and /home are separate volumes the initramfs
# mounts over the root, so anything left under them here is inside the
# measurement, invisible to the running machine, and a second answer to
# what the machine's state is. Emptying them leaves the two mount points
# the initramfs needs and nothing else.
#
# This is the attested half and it lives here rather than in the shared
# configuration script for the same reason every other step in this file
# does: the writable-root layout keeps its /var and /home, because there
# they ARE the root and nothing has made a claim about their bytes.
#
# The check afterwards reads the finished tree back. Its failure stops
# the staging, so the tree never exists, so `build-verity-root.sh` never
# runs and no root hash is ever taken over a root whose state would be
# shadowed. That is the reproducibility boundary for this property, and
# it is one step earlier than the hash rather than at it.
STATE_SEED_TOOL="$REPO_ROOT/tools/reproos_state_seed.py"
if [ ! -f "$STATE_SEED_TOOL" ]; then
  echo "[stage-installed-root] the state seed tool is missing:" \
       "$STATE_SEED_TOOL" >&2
  exit 78
fi
if ! python3 "$STATE_SEED_TOOL" detach "$OUT_TREE"; then
  echo "[stage-installed-root] the state volumes' content could not be" \
       "separated from the root that is about to be hashed" >&2
  exit 78
fi
if ! python3 "$STATE_SEED_TOOL" check "$OUT_TREE" --attested; then
  echo "[stage-installed-root] this root does not separate its writable" \
       "state, so an image made from it would boot, verify against its own" \
       "root hash, and offer no usable session" >&2
  exit 78
fi

echo "[stage-installed-root] OK $OUT_TREE"
exit 0
