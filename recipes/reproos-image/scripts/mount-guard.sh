#!/usr/bin/env bash
set -euo pipefail

# mount-guard.sh -- REFUSE a write-capable mount of a partition whose
# bytes a root hash already names, then mount whatever is left.
#
# WHY A REFUSAL AND NOT A CONVENTION.
#
# The integrity-checked layout puts a finished dm-verity data image on
# a carrier partition. That image is a valid ext4 filesystem at offset
# 0 of the carrier, so `mount <carrier> <dir>` SUCCEEDS -- it is
# exactly what a driver written for the writable-root layout would do,
# and it is what one did. Nothing complains. Every step afterwards
# exits 0. The damage shows up on somebody else's machine, at the
# first boot, as a verity failure on the one machine that was supposed
# to be the attestable one.
#
# And the damage does not need a single file to be written. ext4
# updates the superblock's mount state on any read-WRITE mount, so a
# mount that is immediately unmounted, having written nothing of its
# own, is already enough to make `veritysetup verify` reject the pair
# against the root hash on the measured command line. That is why this
# guard keys on the WRITE CAPABILITY of the mount and not on whether
# anything was written: by the time you could observe a write, the
# hash is already wrong.
#
# So the rule cannot be "the driver is careful". It is: a carrier the
# root hash covers is never mounted writably, and asking to is a hard
# failure with a diagnostic, here, at build time.
#
# Usage:
#   mount-guard.sh <device> <mountpoint> [mount options...]
#
# Required environment:
#   SUDO                        how to escalate
#   MOUNT_BIN                   the host mount(8) to run
#
# Optional environment:
#   REPROOS_HASHED_CARRIERS     space-separated `PARTUUID=` specifiers
#                               of every partition whose bytes a root
#                               hash names. EMPTY means the layout has
#                               none -- the writable-root layout -- and
#                               then this guard mounts and refuses
#                               nothing.
#   SGDISK_BIN                  the partition-table reader (default:
#                               the first `sgdisk` on PATH)
#
# Exit codes:
#   64 = usage
#   66 = a required tool is missing
#   68 = the carrier set could not be resolved against the device
#   69 = the mount itself failed
#   78 = REFUSED: a write-capable mount of a hashed carrier

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <device> <mountpoint> [mount options...]" >&2
  exit 64
fi
TARGET_DEV="$1"
MOUNT_POINT="$2"
shift 2
MOUNT_OPTS=("$@")

SUDO="${SUDO:-sudo}"
: "${MOUNT_BIN:?MOUNT_BIN must name the host mount(8) binary}"
HASHED_CARRIERS="${REPROOS_HASHED_CARRIERS:-}"

# ---------------------------------------------------------------------
# Is this mount write-capable?
#
# Read-only is stated as the `-r`/`--read-only` flag or an `ro` entry in
# `-o`; writable as `-w`/`--rw` or an `rw` entry. Everything else --
# INCLUDING the default -- is writable. The test is "can I prove it is
# read-only", never "does it look dangerous": an option this parser did
# not recognise has to fall on the refusing side.
#
# THE LAST SPECIFIER WINS, and that is not a detail. `mount(8)` applies
# the final ro/rw it is given, so `-o ro,rw` mounts READ-WRITE. A guard
# that answered "read-only" because the string `ro` appeared anywhere
# would wave `-o ro,rw`, `-o ro -o rw` and `-r -o rw` straight through
# -- each of which really does mount writably and really does break the
# pair. So this walks every option in order and keeps the last verdict,
# exactly as mount does, rather than stopping at the first `ro` it sees.
# ---------------------------------------------------------------------
mount_is_readonly() {
  local i=0 opt group tok
  # Empty = "no verdict yet" = the default, which is writable.
  local verdict=""
  scan_group() {
    local IFS=','
    for tok in $1; do
      case "$tok" in
        ro) verdict=ro ;;
        rw) verdict=rw ;;
      esac
    done
  }
  while [ "$i" -lt "${#MOUNT_OPTS[@]}" ]; do
    opt="${MOUNT_OPTS[$i]}"
    case "$opt" in
      -r|--read-only) verdict=ro ;;
      -w|--rw|--read-write) verdict=rw ;;
      -o)
        i=$((i + 1))
        if [ "$i" -lt "${#MOUNT_OPTS[@]}" ]; then
          group="${MOUNT_OPTS[$i]}"
          scan_group "$group"
        fi
        ;;
      -o*)
        group="${opt#-o}"
        scan_group "$group"
        ;;
    esac
    i=$((i + 1))
  done
  [ "$verdict" = "ro" ]
}

# ---------------------------------------------------------------------
# Which partition of which disk is <device>?
#
# The carriers are named on the measured command line by PARTUUID and
# nowhere else, so the only way to decide whether THIS device node is
# one of them is to read the partition table back off the disk it
# belongs to and compare GUIDs. Deriving the value again, or trusting a
# partition number, would be answering the question with the same
# assumption that produced the defect.
#
# `sgdisk -i` rather than blkid or /dev/disk/by-partuuid: no udev in
# the path, which matters for an NBD node that appeared seconds ago,
# and it is already a declared tool of every action that mounts here.
# ---------------------------------------------------------------------
partition_guid() {
  # partition_guid <whole-disk> <partition-number>
  "$SUDO" "$SGDISK_BIN" -i "$2" "$1" 2>/dev/null \
    | awk -F': ' '/Partition unique GUID/ {print $2}' \
    | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]'
}

if [ -n "$HASHED_CARRIERS" ]; then
  SGDISK_BIN="${SGDISK_BIN:-$(command -v sgdisk 2>/dev/null || true)}"
  if [ -z "$SGDISK_BIN" ]; then
    echo "mount-guard.sh: sgdisk is not available, so a mount of $TARGET_DEV" \
         "cannot be checked against the carriers the root hash names;" \
         "refusing rather than mounting something unchecked" >&2
    exit 66
  fi
  # Split <disk><p><n>. The device nodes this driver mounts are always
  # partitions of one disk (`/dev/nbd0p2`, `/dev/sda2`), so a node that
  # does not decompose is not a partition and cannot be a carrier.
  DISK_OF_TARGET=""
  PART_OF_TARGET=""
  case "$TARGET_DEV" in
    *p[0-9]|*p[0-9][0-9])
      PART_OF_TARGET="${TARGET_DEV##*p}"
      DISK_OF_TARGET="${TARGET_DEV%p"$PART_OF_TARGET"}"
      ;;
    *[0-9])
      PART_OF_TARGET="${TARGET_DEV##*[!0-9]}"
      DISK_OF_TARGET="${TARGET_DEV%"$PART_OF_TARGET"}"
      ;;
  esac
  if [ -z "$DISK_OF_TARGET" ] || [ -z "$PART_OF_TARGET" ]; then
    # Fail CLOSED. On a layout with hashed carriers every mount this
    # build performs is a partition of the disk being installed, so a
    # node that is not one means the plan has drifted into something
    # this guard cannot check -- and an unchecked mount is exactly what
    # it exists to prevent. Mounting anyway would make the refusal
    # conditional on the spelling of a device name.
    echo "mount-guard.sh: $TARGET_DEV is not a partition of a disk, so it" \
         "cannot be checked against the partitions the root hash names;" \
         "refusing rather than mounting something unchecked" >&2
    exit 68
  fi
  TARGET_GUID="$(partition_guid "$DISK_OF_TARGET" "$PART_OF_TARGET")"
  if [ -z "$TARGET_GUID" ]; then
    echo "mount-guard.sh: $TARGET_DEV has no readable partition GUID on" \
         "$DISK_OF_TARGET, so it cannot be checked against the" \
         "${HASHED_CARRIERS} the root hash names" >&2
    exit 68
  fi
  for spec in $HASHED_CARRIERS; do
    case "$spec" in
      PARTUUID=*) ;;
      *)
        echo "mount-guard.sh: a hashed carrier is named '$spec'; a verity" \
             "carrier holds no filesystem, so it can only be named by" \
             "PARTUUID=" >&2
        exit 68
        ;;
    esac
    wanted="$(printf '%s' "${spec#PARTUUID=}" | tr '[:upper:]' '[:lower:]')"
    if [ "$wanted" = "$TARGET_GUID" ]; then
      if mount_is_readonly; then
        break
      fi
      echo "mount-guard.sh: REFUSED a write-capable mount of $TARGET_DEV" \
           "at $MOUNT_POINT. That partition holds an integrity-checked" \
           "root image ($spec) whose every byte is named by the root hash" \
           "on this image's own kernel command line. Mounting it writably" \
           "rewrites the filesystem's mount state even if nothing is" \
           "written through the mount, and the installed image would then" \
           "fail to verify at boot. Configure the root before its image is" \
           "made -- scripts/configure-installed-root.sh -- or mount it" \
           "read-only with -o ro." >&2
      exit 78
    fi
  done
fi

"$SUDO" /usr/bin/env LD_LIBRARY_PATH= "$MOUNT_BIN" "${MOUNT_OPTS[@]}" \
  "$TARGET_DEV" "$MOUNT_POINT" \
  || { echo "mount-guard.sh: mounting $TARGET_DEV at $MOUNT_POINT failed" >&2
       exit 69; }
exit 0
