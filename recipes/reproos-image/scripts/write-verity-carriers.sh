#!/usr/bin/env bash
set -euo pipefail

# Write an integrity-checked root onto the two carrier partitions the
# measured kernel command line names.
#
# THIS IS THE STEP THAT MAKES A MEASURED COMMAND LINE TRUE. Everything
# before it produces a claim: `build-verity-root.sh` makes a read-only
# ext4 image and the dm-verity Merkle tree over it, and the unified
# kernel image carries the root hash plus the two device specifiers
# inside the binary firmware measures. None of that puts a single byte
# on a disk. Until something does, an attested instance boots, resolves
# the two specifiers to real partitions, and finds them empty -- a
# command line that names volumes that exist and say nothing.
#
# The carriers are addressed by PARTUUID, and that is not a stylistic
# choice:
#
#   * A Merkle tree is not a filesystem. It is a verity superblock and
#     a tree of digests, so it carries no filesystem label and no
#     filesystem UUID, and `findfs LABEL=...` can never resolve it.
#   * Both root slots hold an ext4 image with the same label
#     (`reproos-root`, written into the image by `build-verity-root.sh`
#     and covered by the root hash), so a label names two devices as
#     soon as a second generation is staged.
#
# So the specifiers on the command line are `PARTUUID=` values, derived
# at plan time from the build's identity seed by the same construction
# `repro disk apply` derives the GPT partition GUIDs with. This script
# resolves them by READING THE PARTITION TABLE BACK -- it does not
# recompute them and it does not trust a partition number. If the
# apply and the command line ever disagreed, the resolution fails here,
# at build time, instead of at boot on somebody else's machine.
#
# `sgdisk -i N` is the resolver rather than `blkid` or
# `/dev/disk/by-partuuid`: it reads the GPT off the device with no udev
# in the path, which matters because the device is an NBD node that
# appeared seconds ago, and it is already one of the image driver's
# declared tool identities.
#
# Usage:
#   write-verity-carriers.sh <device>
#
# Required environment:
#
#   REPROOS_VERITY_DATA_IMAGE   the read-only ext4 image the root hash
#                               was taken over
#   REPROOS_VERITY_HASH_TREE    the Merkle tree over that image
#   REPROOS_VERITY_ROOTHASH_FILE  the root hash, as the UKI pins it
#   REPROOS_VERITY_DATA_DEVICE  PARTUUID= specifier of the data carrier,
#                               verbatim from the measured command line
#   REPROOS_VERITY_HASH_DEVICE  PARTUUID= specifier of the tree carrier,
#                               verbatim from the measured command line
#
# Optional:
#   SUDO                        how to escalate (default: sudo)
#   REPROOS_VERITY_CARRIER_VERIFY=0  skip the `veritysetup verify` pass
#                               over the written partitions when the
#                               tool is not available. The read-back
#                               digest comparison is NOT optional and
#                               has no switch.
#
# Exit codes:
#   64 = usage
#   66 = a required tool is missing
#   67 = an input artifact is missing or unusable
#   68 = a specifier did not resolve to a partition on this device
#   69 = a carrier is too small for what has to go on it
#   70 = the bytes read back are not the bytes written
#   71 = the written pair does not verify against the pinned root hash

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <device>" >&2
  exit 64
fi
DEVICE="$1"

SUDO="${SUDO:-sudo}"

: "${REPROOS_VERITY_DATA_IMAGE:?REPROOS_VERITY_DATA_IMAGE must name the read-only root image build-verity-root.sh produced}"
: "${REPROOS_VERITY_HASH_TREE:?REPROOS_VERITY_HASH_TREE must name the Merkle tree build-verity-root.sh produced}"
: "${REPROOS_VERITY_ROOTHASH_FILE:?REPROOS_VERITY_ROOTHASH_FILE must name the root hash file the unified kernel image pins}"
: "${REPROOS_VERITY_DATA_DEVICE:?REPROOS_VERITY_DATA_DEVICE must carry the data carrier specifier from the measured command line}"
: "${REPROOS_VERITY_HASH_DEVICE:?REPROOS_VERITY_HASH_DEVICE must carry the Merkle tree carrier specifier from the measured command line}"

for tool in sgdisk dd sha256sum awk sed blockdev tr wc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "write-verity-carriers.sh: required tool missing: $tool" >&2
    exit 66
  fi
done

# Every command that runs UNDER sudo is resolved to an absolute path
# first, and that is a correctness requirement rather than a style.
# `sudo` applies its host `secure_path`, which deliberately excludes the
# tool profile Repro provisions for a build action -- so `sudo sgdisk`
# resolves to whatever the host happens to have, or to nothing at all,
# while `sgdisk` on the action's own PATH resolves to the version the
# graph declared. The image driver resolves its own privileged commands
# the same way and for the same reason.
SGDISK_BIN="$(command -v sgdisk)"
DD_BIN="$(command -v dd)"
BLOCKDEV_BIN="$(command -v blockdev)"

if [ ! -b "$DEVICE" ]; then
  echo "write-verity-carriers.sh: not a block device: $DEVICE" >&2
  exit 67
fi
for f in "$REPROOS_VERITY_DATA_IMAGE" "$REPROOS_VERITY_HASH_TREE" \
         "$REPROOS_VERITY_ROOTHASH_FILE"; do
  if [ ! -s "$f" ]; then
    echo "write-verity-carriers.sh: input missing or empty: $f" >&2
    exit 67
  fi
done

ROOT_HASH="$(sed -n '1s/[[:space:]]*$//p' "$REPROOS_VERITY_ROOTHASH_FILE")"
if [ -z "$ROOT_HASH" ]; then
  echo "write-verity-carriers.sh: no root hash in $REPROOS_VERITY_ROOTHASH_FILE" >&2
  exit 67
fi

# ---------------------------------------------------------------------
# Resolve a `PARTUUID=` specifier against the partition table that is
# actually on the device.
#
# Nothing here derives a value: the specifier comes off the measured
# command line and the GUIDs come off the disk, so a match is evidence
# that the two agree and a miss is a hard failure. The partition count
# comes from the GPT header rather than from the layout, so this stays
# correct if the layout gains a volume.
# ---------------------------------------------------------------------
partition_count() {
  "$SUDO" "$SGDISK_BIN" --print "$DEVICE" 2>/dev/null \
    | awk '/^Number /{seen=1; next} seen && $1 ~ /^[0-9]+$/ {n=$1} END {print n+0}'
}

resolve_partuuid() {
  # resolve_partuuid <what> <PARTUUID=...>
  local what="$1" spec="$2" wanted num guid
  case "$spec" in
    PARTUUID=*) wanted="${spec#PARTUUID=}" ;;
    *)
      echo "write-verity-carriers.sh: the $what is named '$spec'; a verity" \
           "carrier has no filesystem, so it can only be addressed by" \
           "PARTUUID=" >&2
      exit 68
      ;;
  esac
  wanted="$(printf '%s' "$wanted" | tr '[:upper:]' '[:lower:]')"
  local count
  count="$(partition_count)"
  if [ "$count" -lt 1 ]; then
    echo "write-verity-carriers.sh: $DEVICE has no partition table to" \
         "resolve the $what against" >&2
    exit 68
  fi
  for ((num = 1; num <= count; num++)); do
    guid="$("$SUDO" "$SGDISK_BIN" -i "$num" "$DEVICE" 2>/dev/null \
      | awk -F': ' '/Partition unique GUID/ {print $2}' \
      | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')"
    if [ -n "$guid" ] && [ "$guid" = "$wanted" ]; then
      printf '%s\n' "${DEVICE}p${num}"
      return 0
    fi
  done
  echo "write-verity-carriers.sh: the $what ($spec) does not name any of" \
       "the $count partitions on $DEVICE; the measured command line and" \
       "the partition table disagree, and an image shipped like this" \
       "would fail to find its own root at boot" >&2
  exit 68
}

DATA_PART="$(resolve_partuuid 'verity data carrier' "$REPROOS_VERITY_DATA_DEVICE")"
HASH_PART="$(resolve_partuuid 'verity hash-tree carrier' "$REPROOS_VERITY_HASH_DEVICE")"
if [ "$DATA_PART" = "$HASH_PART" ]; then
  echo "write-verity-carriers.sh: both specifiers resolved to $DATA_PART" >&2
  exit 68
fi
echo "[verity-carriers] data $REPROOS_VERITY_DATA_DEVICE -> $DATA_PART"
echo "[verity-carriers] hash $REPROOS_VERITY_HASH_DEVICE -> $HASH_PART"

# ---------------------------------------------------------------------
# Write, then read back and compare.
#
# The read-back is the whole point of this function existing rather than
# a bare `dd` on the driver's command line. A short write, a carrier one
# block too small, or a device that silently swallowed the tail all
# produce a disk that boots to a verity failure, and the only cheap
# place to catch them is here, against the file that is still on disk.
# `veritysetup verify` below is a second, independent check of the same
# bytes THROUGH THE PAIR, so a data image that landed correctly beside a
# truncated tree is caught too.
# ---------------------------------------------------------------------
write_carrier() {
  # write_carrier <what> <file> <partition>
  local what="$1" file="$2" part="$3" size capacity got want
  size="$(wc -c < "$file")"
  if [ ! -b "$part" ]; then
    echo "write-verity-carriers.sh: $part is not a block device" >&2
    exit 68
  fi
  capacity="$("$SUDO" "$BLOCKDEV_BIN" --getsize64 "$part")"
  if [ "$capacity" -lt "$size" ]; then
    echo "write-verity-carriers.sh: the $what needs $size bytes and" \
         "$part holds $capacity; widen the carrier in the layout rather" \
         "than truncating an image the root hash was taken over" >&2
    exit 69
  fi
  echo "[verity-carriers] writing $what: $size bytes -> $part"
  "$SUDO" "$DD_BIN" if="$file" of="$part" bs=4M conv=fsync status=none \
    || { echo "write-verity-carriers.sh: writing the $what failed" >&2; exit 70; }

  want="$(sha256sum "$file" | awk '{print $1}')"
  got="$("$SUDO" "$DD_BIN" if="$part" bs=4M iflag=count_bytes count="$size" \
    status=none | sha256sum | awk '{print $1}')"
  if [ "$want" != "$got" ]; then
    echo "write-verity-carriers.sh: the $what did not land intact on" \
         "$part: wrote sha256=$want, read back sha256=$got over $size" \
         "bytes" >&2
    exit 70
  fi
  echo "[verity-carriers] $what verified on $part sha256=$got"
}

write_carrier 'verity data image' "$REPROOS_VERITY_DATA_IMAGE" "$DATA_PART"
write_carrier 'verity hash tree' "$REPROOS_VERITY_HASH_TREE" "$HASH_PART"

# ---------------------------------------------------------------------
# The pair, checked on the partitions rather than on the files.
#
# This is the same walk the kernel makes per block, made once for every
# block, and it is made against exactly the two devices the measured
# command line names -- so what passes here is the thing an attested
# boot will activate, not the artifacts it was copied from.
# ---------------------------------------------------------------------
if [ "${REPROOS_VERITY_CARRIER_VERIFY:-1}" = "1" ]; then
  VERITYSETUP_BIN="$(command -v veritysetup 2>/dev/null || true)"
  if [ -z "$VERITYSETUP_BIN" ]; then
    echo "write-verity-carriers.sh: veritysetup is not on PATH; the" \
         "written pair cannot be verified on the partitions it was" \
         "written to" >&2
    exit 66
  fi
  echo "[verity-carriers] veritysetup verify $DATA_PART $HASH_PART $ROOT_HASH"
  if ! "$SUDO" "$VERITYSETUP_BIN" verify "$DATA_PART" "$HASH_PART" "$ROOT_HASH"; then
    echo "write-verity-carriers.sh: the pair on $DATA_PART / $HASH_PART" \
         "does not verify against the root hash the unified kernel image" \
         "pins ($ROOT_HASH); this image would fail closed at boot" >&2
    exit 71
  fi
  echo "[verity-carriers] the installed pair verifies against $ROOT_HASH"
fi

echo "[verity-carriers] OK"
exit 0
