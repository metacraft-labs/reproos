#!/usr/bin/env bash
set -euo pipefail

# Build the integrity-checked read-only root of an attestable ReproOS
# image: a read-only ext4 image of the staged root filesystem, plus the
# dm-verity Merkle tree over it, plus the root hash that names its exact
# bytes.
#
# The root hash is the point of this script. It is a short value that
# changes if any byte of the root filesystem changes, so a boot path that
# carries it -- and a launch measurement that covers that boot path --
# transitively pins the whole root filesystem. Everything below exists to
# make that value a function of the staged tree and nothing else.
#
# The image also carries the GUEST INODE POLICY -- root-owned inodes, a
# setuid `sudo`, group- and other-write stripped from the trusted
# directories. It has to be applied before the hash, because after it
# there is nothing left that may write to these bytes; and it is applied
# to the IMAGE rather than to the tree, because the build is
# unprivileged. See `tools/reproos_image_metadata.py`, which is the one
# owner of that policy for every carrier ReproOS ships.
#
# Usage:
#   build-verity-root.sh <output-directory>
#
# Required environment (all set by recipes/reproos-image/package.nim,
# which derives every pinned value from the build's identity seed):
#
#   REPROOS_STAGED_ROOTFS      the directory to turn into the root image
#   REPROOS_VERITY_SALT        hex, pinned; without it veritysetup draws
#                              32 bytes from the system RNG and two
#                              builds of identical inputs disagree
#   REPROOS_VERITY_UUID        the hash device's UUID
#   REPROOS_VERITY_FS_UUID     the root filesystem's UUID
#   REPROOS_VERITY_FS_HASH_SEED  the ext4 directory-hash seed, which is a
#                              SECOND random value in mke2fs
#   SOURCE_DATE_EPOCH          pinned; mke2fs writes it into the
#                              superblock timestamps
#
# Optional:
#   REPROOS_VERITY_ROOT_SIZE_MIB  override the computed image size
#
# Exit codes:
#   64 = usage
#   66 = a required tool is missing
#   67 = the staged root filesystem is missing or unusable
#   68 = making the root filesystem image failed
#   69 = verity formatting failed
#   70 = the guest inode policy could not be carried into the image
#   71 = the image does not carry the guest inode policy, so no root hash
#        may be taken over it
#
# Outputs, written into <output-directory>:
#   reproos-root.verity.img       the read-only ext4 data image
#   reproos-root.verity.hashtree  the Merkle tree over it
#   reproos-root.verity.roothash  the root hash, one line, no newline
#                                 decoration beyond the trailing one
#   reproos-root.verity.json      geometry + root hash, machine-readable
#
# The geometry constants below are the ones repro/verity.nim declares.
# They are duplicated here rather than passed because they are not
# per-build values -- and the verity gate compares the two declarations,
# so a change on either side that is not made on the other is a red test
# rather than an image that boots differently.
VERITY_HASH_NAME=sha256
VERITY_DATA_BLOCK_SIZE=4096
VERITY_HASH_BLOCK_SIZE=4096
VERITY_SUPERBLOCK_FORMAT=1

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <output-directory>" >&2
  exit 64
fi
OUT_DIR="$1"

: "${REPROOS_STAGED_ROOTFS:?REPROOS_STAGED_ROOTFS must be set}"
: "${REPROOS_VERITY_SALT:?REPROOS_VERITY_SALT must be set; without a pinned salt veritysetup takes one from the system RNG and the root hash moves between builds}"
: "${REPROOS_VERITY_UUID:?REPROOS_VERITY_UUID must be set}"
: "${REPROOS_VERITY_FS_UUID:?REPROOS_VERITY_FS_UUID must be set}"
: "${REPROOS_VERITY_FS_HASH_SEED:?REPROOS_VERITY_FS_HASH_SEED must be set}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set; mke2fs writes it into the superblock}"

for tool in mkfs.ext4 debugfs veritysetup find awk sha256sum python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "build-verity-root.sh: required tool missing: $tool" >&2
    exit 66
  fi
done

SCRIPT_DIR_SELF="$(cd "$(dirname "$0")" && pwd)"
INODE_POLICY="$SCRIPT_DIR_SELF/../../../tools/reproos_image_metadata.py"
if [ ! -f "$INODE_POLICY" ]; then
  echo "build-verity-root.sh: the guest inode policy is missing: $INODE_POLICY" >&2
  exit 66
fi

if [ ! -d "$REPROOS_STAGED_ROOTFS" ]; then
  echo "build-verity-root.sh: staged root filesystem missing: $REPROOS_STAGED_ROOTFS" >&2
  exit 67
fi

mkdir -p "$OUT_DIR"
DATA_IMG="$OUT_DIR/reproos-root.verity.img"
HASH_IMG="$OUT_DIR/reproos-root.verity.hashtree"
ROOTHASH_FILE="$OUT_DIR/reproos-root.verity.roothash"
MANIFEST="$OUT_DIR/reproos-root.verity.json"
rm -f "$DATA_IMG" "$HASH_IMG" "$ROOTHASH_FILE" "$MANIFEST"

# ---------------------------------------------------------------------
# Size the image.
#
# From the SUM OF FILE SIZES, not from `du`. `du` reports blocks the
# build host's own filesystem allocated, so the same staged tree measures
# differently on ext4 and on ZFS and on a host with a different block
# size -- and the image size is an input to the root hash. Apparent size
# is a property of the tree alone.
#
# The 40% headroom covers ext4 metadata (inode tables, the block bitmap,
# the directory entries themselves) and is a fixed factor rather than a
# measurement, again because a measurement would be host-dependent.
# ---------------------------------------------------------------------
if [ -n "${REPROOS_VERITY_ROOT_SIZE_MIB:-}" ]; then
  SIZE_MIB="$REPROOS_VERITY_ROOT_SIZE_MIB"
  echo "[verity-root] size: ${SIZE_MIB}M (REPROOS_VERITY_ROOT_SIZE_MIB)"
else
  CONTENT_BYTES="$(find "$REPROOS_STAGED_ROOTFS" -type f -printf '%s\n' 2>/dev/null \
    | awk '{ total += $1 } END { printf "%d", total }')"
  if [ -z "$CONTENT_BYTES" ] || [ "$CONTENT_BYTES" -le 0 ]; then
    echo "build-verity-root.sh: staged root filesystem holds no files: $REPROOS_STAGED_ROOTFS" >&2
    exit 67
  fi
  SIZE_MIB="$(awk -v b="$CONTENT_BYTES" 'BEGIN {
    mib = (b * 14 / 10) / 1048576
    n = int(mib) + 1
    if (n < 64) n = 64
    printf "%d", n
  }')"
  echo "[verity-root] size: ${SIZE_MIB}M for ${CONTENT_BYTES} bytes of content"
fi

# ---------------------------------------------------------------------
# The read-only ext4 image.
#
# -b 4096 is not a preference. A dm-verity device reports a 4096-byte
# logical block, and a filesystem made with a smaller block size cannot
# be mounted off one: the kernel refuses with "bad block size". mke2fs
# picks 1024 for small filesystems, so leaving it unset produces an image
# that verifies perfectly and will not mount.
#
# ^has_journal because nothing will ever write to this filesystem, and a
# journal is both dead weight and a source of bytes that are not a
# function of the staged tree.
# ---------------------------------------------------------------------
echo "[verity-root] mkfs.ext4 -b $VERITY_DATA_BLOCK_SIZE -d $REPROOS_STAGED_ROOTFS"
if ! mkfs.ext4 -q -F \
    -b "$VERITY_DATA_BLOCK_SIZE" \
    -d "$REPROOS_STAGED_ROOTFS" \
    -U "$REPROOS_VERITY_FS_UUID" \
    -E "hash_seed=$REPROOS_VERITY_FS_HASH_SEED" \
    -O '^has_journal' \
    -m 0 \
    -L reproos-root \
    "$DATA_IMG" "${SIZE_MIB}M"; then
  echo "build-verity-root.sh: mkfs.ext4 failed" >&2
  exit 68
fi

# ---------------------------------------------------------------------
# The guest inode policy, carried INTO the image.
#
# `mkfs.ext4 -d` copies the staged tree's ownership and modes, and the
# tree was staged by an unprivileged build -- so without this step the
# root ships /etc/shadow owned by whoever happens to hold the building
# user's uid, and /usr/bin/sudo with no setuid bit, which is an installed
# system with no privilege escalation at all.
#
# It cannot be fixed by chowning the tree: `apply` needs uid 0, and a
# root-owned tree under build/ is one the engine can neither replace nor
# clean. The ISO has never had this problem because `mksquashfs -pf`
# takes ownership and modes as a document. `mke2fs` has no pseudo-file,
# so the same document is applied to the finished image instead --
# unprivileged, deterministic, and out of the SAME policy the ISO's
# pseudo-file and the container tar are written from.
#
# THE ORDER HERE IS THE POINT. The policy is applied and then
# INDEPENDENTLY re-read out of the image, and only then is a root hash
# taken. An image that does not carry the policy is refused rather than
# hashed: once the hash exists it is baked into a measured command line,
# and nothing may write to the image again to fix it.
# ---------------------------------------------------------------------
echo "[verity-root] applying the guest inode policy to $DATA_IMG"
if ! python3 "$INODE_POLICY" ext4-apply "$REPROOS_STAGED_ROOTFS" \
    --image "$DATA_IMG"; then
  echo "build-verity-root.sh: the guest inode policy could not be carried into the root image" >&2
  exit 70
fi
if ! python3 "$INODE_POLICY" ext4-verify "$REPROOS_STAGED_ROOTFS" \
    --image "$DATA_IMG"; then
  echo "build-verity-root.sh: the root image does not carry the guest inode policy; refusing to take a root hash over it" >&2
  exit 71
fi

# ---------------------------------------------------------------------
# The Merkle tree.
#
# Every value veritysetup would otherwise invent is passed. The block
# sizes and the hash name are passed even though they are the current
# defaults, because a default is a value that can move with the tool
# version and take every root hash with it.
# ---------------------------------------------------------------------
echo "[verity-root] veritysetup format"
if ! veritysetup format "$DATA_IMG" "$HASH_IMG" \
    "--hash=$VERITY_HASH_NAME" \
    "--data-block-size=$VERITY_DATA_BLOCK_SIZE" \
    "--hash-block-size=$VERITY_HASH_BLOCK_SIZE" \
    "--format=$VERITY_SUPERBLOCK_FORMAT" \
    "--salt=$REPROOS_VERITY_SALT" \
    "--uuid=$REPROOS_VERITY_UUID" \
    > "$OUT_DIR/veritysetup-format.log" 2>&1; then
  cat "$OUT_DIR/veritysetup-format.log" >&2
  echo "build-verity-root.sh: veritysetup format failed" >&2
  exit 69
fi

ROOT_HASH="$(awk '/^Root hash:/ { print $NF }' "$OUT_DIR/veritysetup-format.log")"
DATA_BLOCKS="$(awk '/^Data blocks:/ { print $NF }' "$OUT_DIR/veritysetup-format.log")"
if [ -z "$ROOT_HASH" ]; then
  cat "$OUT_DIR/veritysetup-format.log" >&2
  echo "build-verity-root.sh: veritysetup format reported no root hash" >&2
  exit 69
fi

# Read it back through the verifier rather than trusting the formatter's
# own report. `veritysetup verify` walks the whole tree against the data
# image, so this is the same check the kernel makes per block, made once
# for every block.
if ! veritysetup verify "$DATA_IMG" "$HASH_IMG" "$ROOT_HASH" \
    > "$OUT_DIR/veritysetup-verify.log" 2>&1; then
  cat "$OUT_DIR/veritysetup-verify.log" >&2
  echo "build-verity-root.sh: the tree just written does not verify against the image it was taken over" >&2
  exit 69
fi

printf '%s\n' "$ROOT_HASH" > "$ROOTHASH_FILE"

DATA_SHA="$(sha256sum "$DATA_IMG" | awk '{print $1}')"
HASH_SHA="$(sha256sum "$HASH_IMG" | awk '{print $1}')"

cat > "$MANIFEST" <<EOF
{
  "schema": "reproos.verity-root.v1",
  "rootHash": "$ROOT_HASH",
  "hashName": "$VERITY_HASH_NAME",
  "salt": "$REPROOS_VERITY_SALT",
  "uuid": "$REPROOS_VERITY_UUID",
  "dataBlockSize": $VERITY_DATA_BLOCK_SIZE,
  "hashBlockSize": $VERITY_HASH_BLOCK_SIZE,
  "dataBlocks": $DATA_BLOCKS,
  "dataImageSha256": "$DATA_SHA",
  "hashTreeSha256": "$HASH_SHA",
  "superblockVersion": $VERITY_SUPERBLOCK_FORMAT
}
EOF

echo "[verity-root] OK root hash $ROOT_HASH"
echo "[verity-root] data  $DATA_IMG sha256=$DATA_SHA"
echo "[verity-root] hash  $HASH_IMG sha256=$HASH_SHA"
