## The dm-verity shape of the ReproOS read-only root.
##
## ## Why this module exists
##
## The attestable image mounts its root read-only *and* proves, on every
## block read, that the block is the one the build produced. That proof is
## a Merkle tree over the root filesystem image: the leaves are digests of
## the data blocks, each interior block holds the digests of the blocks
## below it, and the whole thing collapses to a single **root hash**. The
## kernel is handed the root hash out of band and re-derives every digest
## on the path to any block it is asked for; a block that does not hash to
## what its parent says fails the read with ``EIO`` rather than being
## served.
##
## The root hash is therefore the *name* of the root filesystem's exact
## bytes, and it is what turns "the image is read-only" into "the image is
## the one that was built". It is a short, fixed-size value, which is why
## it can ride on the kernel command line and be covered by a launch
## measurement.
##
## ## What lives here and what does not
##
## Here: the geometry (block sizes, hash algorithm, superblock layout),
## the derivation of the salt and hash-device UUID from the build's
## identity seed, the Merkle construction itself, and the two renderings
## the rest of the system consumes — the ``veritysetup format`` argv and
## the kernel command-line fragment.
##
## Not here: partitioning (``repro/disk_layouts.nim``), the seed's
## definition (also ``repro/disk_layouts.nim`` — this module is handed a
## seed, it does not decide what one is a function of), and how the boot
## path carries the root hash into a measurement. The last of those is
## the business of whatever assembles the boot artifact; this module only
## states the string it must carry, in ``verityCmdlineFragment``.
##
## ## Why a second implementation of a published format
##
## ``veritysetup format`` is the reference producer and the image build
## runs it. This module re-derives the same bytes independently, and that
## is deliberate, for three reasons:
##
##   1. **The root hash becomes predictable at plan time.** A value that
##      only exists after a multi-hour privileged build cannot be pinned
##      into anything the build itself produces. A pure function of the
##      inputs can.
##   2. **Two implementations must agree.** A hash tree that only its own
##      producer can reproduce is not evidence of anything. The gate
##      compares this construction against ``veritysetup``'s output byte
##      for byte, and against the running kernel's opinion, which is the
##      only opinion that matters at boot.
##   3. **Gates can build real verity images with no privileged tooling
##      and no from-source package.** ``cryptsetup`` is a from-source
##      package in this project; naming it as a tool identity would make
##      an always-on gate bootstrap it. Producing the tree here costs
##      nothing.
##
## ## The format, precisely
##
## Reproduced from the kernel's ``drivers/md/dm-verity-target.c`` — the
## consumer, and therefore the authority — not from a description of it:
##
##   * ``hashesPerBlock = hashBlockSize div digestSize``; the level index
##     shift is ``log2(hashesPerBlock)``.
##   * ``levels`` is the smallest ``n`` with
##     ``(dataBlocks - 1) shr (shift * n) == 0``.
##   * Level ``i`` holds one digest per block of the level below it (per
##     *data* block, for level 0), so it occupies
##     ``((dataBlocks - 1) shr (shift * (i+1))) + 1`` hash blocks — the
##     position the LAST data block reaches at level ``i``, divided down
##     one more level, plus one. Equivalently, the chain
##     ``n → ceil(n / hashesPerBlock) → …`` down to a single block.
##     Sizing a level from ``dataBlocks`` alone, as
##     ``ceil((dataBlocks shr (shift*i)) / hashesPerBlock)``, is off by one
##     whenever the level below ends in a partly-filled block: 16385 data
##     blocks give a level 0 of 129 blocks, so level 1 needs 2 blocks and
##     that expression says 1.
##   * The levels are laid out on the hash device **top level first**,
##     descending to level 0. (``verity_ctr`` walks ``i`` from
##     ``levels-1`` down to ``0`` assigning positions.)
##   * With superblock format 1 — the default, and what this module
##     emits — a block's digest is ``H(salt || block)``. Format 0 appends
##     the salt instead; ReproOS does not emit it.
##   * A digest occupies ``1 shl (hashBlockBits - shiftBits)`` bytes of
##     its parent block, which is exactly ``digestSize`` for the sha256 /
##     4096-byte pairing below and is why no padding appears between
##     sibling digests. Unused tail space in a hash block is zero.
##   * The **root hash** is the digest of the whole top-level hash block,
##     zero padding included.
##
## ## No mocking
##
## Nothing here executes anything or reads any state it was not handed a
## path to. ``formatVerity`` reads a file and writes a file; everything
## else is a pure function of its arguments.

import std/[os, strutils]

import nimcrypto/[hash, sha2]

import repro_profile/disk_identity

type
  VeritySpec* = object
    ## The geometry of one verity image. Every field is pinned rather
    ## than defaulted by the tool, because a value the tool chooses is a
    ## value that can move between tool versions and take the root hash
    ## with it.
    hashName*: string        ## the digest, as both the kernel and
                             ## ``veritysetup`` spell it
    dataBlockSize*: int
    hashBlockSize*: int
    salt*: string            ## lower-case hex, no ``0x``
    uuid*: string            ## of the hash device, in the superblock
    superblockVersion*: int  ## the on-disk format; 1 is the only one
                             ## ReproOS emits

  VerityImage* = object
    ## What formatting produced. ``rootHash`` is the value the boot path
    ## must carry; the rest is what lets a reader check the geometry
    ## without re-deriving it.
    rootHash*: string
    dataBlocks*: int
    hashBlocks*: int
    levels*: int
    spec*: VeritySpec

  VerityCorruption* = object
    ## Where a verification walk first disagreed with the tree.
    dataBlock*: int          ## the data block whose digest was wrong
    expected*: string
    actual*: string

const
  VerityDigestSize* = 32
    ## sha256. Named because the level arithmetic below is only correct
    ## for a digest that divides the hash block size.

  VerityHashName* = "sha256"
    ## The one digest ReproOS emits. Not configurable: a per-image choice
    ## of hash would make the root hash's meaning depend on a field
    ## nothing else carries, and sha256 is what the kernel's shash and
    ## every measurement consumer already agree on.

  VerityDataBlockSize* = 4096
  VerityHashBlockSize* = 4096
    ## 4096 both sides. The data block size is also the block size the
    ## root filesystem must be made with: a filesystem with a smaller
    ## block size cannot be mounted off a verity device, because the
    ## device reports a 4096-byte logical block and the mount is refused
    ## with ``bad block size``.

  VeritySuperblockVersion* = 1
  VeritySuperblockMagic* = "verity\0\0"
  VeritySuperblockSize* = 512
    ## The superblock occupies one whole hash block; only the first 512
    ## bytes are defined and the rest is zero.

  VerityHashTypeNormal* = 1
    ## Hash type 1 ("normal"). Type 0 is the Chrome OS variant, which
    ## salts on the other side of the block; ReproOS does not emit it.

  VeritySaltPurpose* = "verity/root/salt"
  VerityUuidPurpose* = "verity/root/uuid"
    ## Purpose strings in the sense of ``repro_profile/disk_identity``:
    ## stable names that scope one derivation under the build's seed.
    ## Changing either changes every root hash ReproOS has ever produced,
    ## which is why they are spelled out rather than built.

  VerityRootHashCmdlineKey* = "reproos.verity.roothash"
  VerityDataDeviceCmdlineKey* = "reproos.verity.data"
  VerityHashDeviceCmdlineKey* = "reproos.verity.hash"
  VerityStateVarCmdlineKey* = "reproos.state.var"
  VerityStateHomeCmdlineKey* = "reproos.state.home"
    ## The kernel command-line keys the initrd parses. Namespaced under
    ## ``reproos.`` so they cannot collide with a kernel or module
    ## parameter, and spelled here so the initrd, the boot-artifact
    ## assembler and the gates cannot drift apart.

  VerityRootHashFileName* = "reproos-root.verity.roothash"
  VerityDataImageFileName* = "reproos-root.verity.img"
  VerityHashTreeFileName* = "reproos-root.verity.hashtree"
  VerityManifestFileName* = "reproos-root.verity.json"
    ## The artifact names the image recipe emits. One declaration, so a
    ## consumer that wants the root hash looks it up rather than guessing
    ## at a path.

# ---------------------------------------------------------------------
# The spec, and how its two unpinned values are derived.
# ---------------------------------------------------------------------

proc deriveVeritySalt*(seed: string): string =
  ## The per-build salt, as lower-case hex.
  ##
  ## A verity salt has no secrecy requirement — it is written in the
  ## superblock and passed on the kernel command line — but it must be
  ## *fixed*, because ``veritysetup`` otherwise draws 32 bytes from the
  ## system RNG and two builds of identical inputs get different root
  ## hashes. Deriving it from the build's identity seed makes it a
  ## function of the same inputs every other identifier in the image is a
  ## function of.
  ##
  ## An empty seed yields "", which every caller reads as "this build is
  ## not reproducible" and refuses rather than papering over.
  if seed.len == 0:
    return ""
  var name = newStringOfCap(16 + seed.len + 1 + VeritySaltPurpose.len)
  for b in DiskIdentityNamespace:
    name.add char(b)
  name.add seed
  name.add '\n'
  name.add VeritySaltPurpose
  toLowerAscii($sha256.digest(name))

proc deriveVerityUuid*(seed: string): string =
  ## The hash device's UUID, an RFC 4122 v5 value under the same
  ## namespace every other pinned identifier in the image uses.
  deriveUuid(DiskIdentity(seed: seed), VerityUuidPurpose)

const VerityRootNodeKey* = "verity.root"
  ## The node key the read-only root's own filesystem identifiers are
  ## derived under, in the sense of ``repro_profile/disk_identity``. It is
  ## deliberately NOT the ``main.root`` key the partition-table apply
  ## uses: the verity data image is built as a file, before any partition
  ## exists, and giving it the partition's key would hand two different
  ## filesystems the same UUID.

proc verityRootFsUuid*(seed: string): string =
  ## The ext4 UUID of the read-only root image. Pinned for the same
  ## reason every other filesystem identifier in the image is: ``mke2fs``
  ## otherwise takes it from the clock, and the root hash covers the
  ## superblock it is written into.
  deriveUuid(DiskIdentity(seed: seed),
             filesystemUuidPurpose(VerityRootNodeKey))

proc verityRootFsHashSeed*(seed: string): string =
  ## The ext4 directory-hash seed of the read-only root image. A separate
  ## random value in ``mke2fs``, so pinning the UUID alone leaves the
  ## root hash moving between builds.
  deriveUuid(DiskIdentity(seed: seed),
             filesystemHashSeedPurpose(VerityRootNodeKey))

proc verityRootSpec*(seed: string): VeritySpec =
  ## The spec for the root filesystem of one build.
  VeritySpec(
    hashName: VerityHashName,
    dataBlockSize: VerityDataBlockSize,
    hashBlockSize: VerityHashBlockSize,
    salt: deriveVeritySalt(seed),
    uuid: deriveVerityUuid(seed),
    superblockVersion: VeritySuperblockVersion)

proc validateVeritySpec*(spec: VeritySpec): string =
  ## "" when the spec is usable, otherwise the operator-facing reason.
  if spec.hashName != VerityHashName:
    return "verity hash algorithm " & spec.hashName.escape() &
      " is not supported; ReproOS emits " & VerityHashName.escape()
  if spec.dataBlockSize != VerityDataBlockSize:
    return "verity data block size must be " & $VerityDataBlockSize &
      " (got " & $spec.dataBlockSize & ")"
  if spec.hashBlockSize != VerityHashBlockSize:
    return "verity hash block size must be " & $VerityHashBlockSize &
      " (got " & $spec.hashBlockSize & ")"
  if spec.superblockVersion != VeritySuperblockVersion:
    return "verity superblock version must be " &
      $VeritySuperblockVersion & " (got " & $spec.superblockVersion & ")"
  if spec.salt.len == 0:
    return "the verity salt is empty, which means no identity seed " &
      "reached this build; without one veritysetup draws the salt from " &
      "the system RNG and two builds of identical inputs produce " &
      "different root hashes"
  if spec.salt.len mod 2 != 0 or spec.salt.len > 512:
    return "the verity salt must be an even number of hex digits, at " &
      "most 512 (got " & $spec.salt.len & ")"
  for c in spec.salt:
    if c notin {'0'..'9', 'a'..'f'}:
      return "the verity salt must be lower-case hex (got " &
        spec.salt.escape() & ")"
  if spec.uuid.len == 0:
    return "the verity hash device has no UUID; it is derived from the " &
      "same identity seed as the salt"
  ""

# ---------------------------------------------------------------------
# Geometry. The arithmetic dm-verity itself does, in the same order.
# ---------------------------------------------------------------------

proc hashesPerBlock*(spec: VeritySpec): int {.inline.} =
  spec.hashBlockSize div VerityDigestSize

proc hashShiftBits*(spec: VeritySpec): int =
  ## ``fls(hashesPerBlock) - 1``: how many index bits one level consumes.
  ## Counted rather than taken from a floating-point log, because the
  ## level arithmetic is exact integer arithmetic and a rounding error
  ## here would move every offset in the tree.
  var n = spec.hashesPerBlock
  while n > 1:
    n = n shr 1
    result.inc

proc verityLevels*(spec: VeritySpec; dataBlocks: int): int =
  ## The number of hash-tree levels for this many data blocks. Zero data
  ## blocks means no tree, which the callers below refuse before they get
  ## here.
  if dataBlocks <= 0:
    return 0
  let shift = spec.hashShiftBits
  result = 0
  while shift * result < 64 and ((dataBlocks - 1) shr (shift * result)) != 0:
    result.inc

proc verityLevelSizes*(spec: VeritySpec; dataBlocks: int): seq[int] =
  ## How many hash blocks each level occupies, level 0 first.
  ##
  ## A level holds one digest per block of the level beneath it, so its
  ## size is fixed by where the LAST data block lands: level ``i`` must
  ## reach position ``(dataBlocks - 1) shr (shift * i)``, and the block
  ## holding that position is that value shifted down once more. Sizing a
  ## level from ``dataBlocks`` directly under-counts by one whenever the
  ## level beneath ends in a partly-filled block — see the module header.
  let shift = spec.hashShiftBits
  result = @[]
  for i in 0 ..< spec.verityLevels(dataBlocks):
    result.add ((dataBlocks - 1) shr (shift * (i + 1))) + 1

proc verityLevelOffsets*(spec: VeritySpec; dataBlocks: int): seq[int] =
  ## The first hash block of each level, level 0 first, counted from the
  ## start of the hash *area* (that is, after the superblock).
  ##
  ## The levels are placed top-first: the single root block sits at
  ## offset 0 and level 0 sits last. This is not a convention this module
  ## picked — ``verity_ctr`` assigns positions walking the levels
  ## downwards, and the kernel will read the tree at these offsets
  ## whatever a producer thinks.
  let sizes = spec.verityLevelSizes(dataBlocks)
  result = newSeq[int](sizes.len)
  var pos = 0
  for i in countdown(sizes.len - 1, 0):
    result[i] = pos
    pos += sizes[i]

proc verityHashBlocks*(spec: VeritySpec; dataBlocks: int): int =
  ## Hash blocks in the tree, superblock excluded.
  for s in spec.verityLevelSizes(dataBlocks):
    result += s

proc verityHashDeviceBytes*(spec: VeritySpec; dataBlocks: int): int64 =
  ## How large a volume the whole hash device needs: the superblock, which
  ## occupies one full hash block, plus the tree.
  ##
  ## Exposed because the partition table has to declare a volume big enough
  ## to hold it, and a size guessed there rather than derived here is a
  ## number that silently stops fitting when the root grows.
  int64(1 + spec.verityHashBlocks(dataBlocks)) * int64(spec.hashBlockSize)

# ---------------------------------------------------------------------
# The construction.
# ---------------------------------------------------------------------

proc saltBytes(spec: VeritySpec): string =
  result = newStringOfCap(spec.salt.len div 2)
  var i = 0
  while i < spec.salt.len:
    result.add char(parseHexInt(spec.salt[i .. i + 1]))
    i += 2

proc blockDigest(spec: VeritySpec; salt, data: openArray[char]): string =
  ## ``H(salt || block)`` — superblock format 1. Returned as raw bytes,
  ## not hex, because it is written into a parent block far more often
  ## than it is printed.
  var ctx: sha256
  ctx.init()
  if salt.len > 0:
    ctx.update(cast[ptr byte](unsafeAddr salt[0]), uint(salt.len))
  if data.len > 0:
    ctx.update(cast[ptr byte](unsafeAddr data[0]), uint(data.len))
  let d = ctx.finish()
  ctx.clear()
  result = newString(VerityDigestSize)
  for i in 0 ..< VerityDigestSize:
    result[i] = char(d.data[i])

proc toHexLower(s: string): string =
  result = newStringOfCap(s.len * 2)
  for c in s:
    result.add toLowerAscii(toHex(int(uint8(c)), 2))

proc verityDataBlocks*(spec: VeritySpec; dataSize: int64): int =
  ## The number of whole data blocks in an image of this size. A trailing
  ## partial block is a defect, not something to round: the caller checks
  ## with ``validateVerityDataSize`` first.
  int(dataSize div int64(spec.dataBlockSize))

proc validateVerityDataSize*(spec: VeritySpec; dataSize: int64): string =
  if dataSize <= 0:
    return "the verity data image is empty"
  if dataSize mod int64(spec.dataBlockSize) != 0:
    return "the verity data image is " & $dataSize & " bytes, which is " &
      "not a whole number of " & $spec.dataBlockSize & "-byte blocks; " &
      "dm-verity covers whole blocks and a partial tail block would be " &
      "outside the tree"
  ""

proc buildVerityTree*(spec: VeritySpec; data: string): (string, string) =
  ## Build the hash area for ``data`` in memory. Returns
  ## ``(hashArea, rootHashHex)``; ``hashArea`` excludes the superblock.
  ##
  ## In memory on purpose: the tree for a 4 GiB root at these block sizes
  ## is 32 MiB, and holding it whole is what lets the levels be written
  ## in the top-first order the kernel reads them in without seeking.
  let dataBlocks = spec.verityDataBlocks(data.len.int64)
  let sizes = spec.verityLevelSizes(dataBlocks)
  let offsets = spec.verityLevelOffsets(dataBlocks)
  let salt = spec.saltBytes()
  let hbs = spec.hashBlockSize

  if sizes.len == 0:
    # A single data block has no tree above it: dm-verity's root hash IS
    # that block's digest and the hash device carries the superblock and
    # nothing else. Handled rather than left to fall off the end, because
    # the arithmetic below indexes level 0 unconditionally.
    return ("", toHexLower(spec.blockDigest(salt,
      toOpenArray(data, 0, spec.dataBlockSize - 1))))

  var levelData: seq[string] = @[]
  for s in sizes:
    levelData.add newString(s * hbs)

  # Level 0 hashes the data blocks.
  for b in 0 ..< dataBlocks:
    let d = spec.blockDigest(salt,
      toOpenArray(data, b * spec.dataBlockSize,
                  (b + 1) * spec.dataBlockSize - 1))
    for i in 0 ..< VerityDigestSize:
      levelData[0][b * VerityDigestSize + i] = d[i]

  # Every other level hashes whole blocks of the level below.
  for lvl in 1 ..< sizes.len:
    for b in 0 ..< sizes[lvl - 1]:
      let d = spec.blockDigest(salt,
        toOpenArray(levelData[lvl - 1], b * hbs, (b + 1) * hbs - 1))
      for i in 0 ..< VerityDigestSize:
        levelData[lvl][b * VerityDigestSize + i] = d[i]

  var area = newString(spec.verityHashBlocks(dataBlocks) * hbs)
  for lvl in 0 ..< sizes.len:
    let at = offsets[lvl] * hbs
    for i in 0 ..< levelData[lvl].len:
      area[at + i] = levelData[lvl][i]

  let top = levelData[^1]
  let rootHash = spec.blockDigest(salt, toOpenArray(top, 0, hbs - 1))
  (area, toHexLower(rootHash))

proc verityRootHash*(spec: VeritySpec; data: string): string =
  ## The root hash alone, for callers that only need the name of the
  ## bytes and not the tree.
  buildVerityTree(spec, data)[1]

proc renderVeritySuperblock*(spec: VeritySpec; dataBlocks: int): string =
  ## One hash block: the 512-byte ``struct verity_sb`` cryptsetup writes,
  ## zero padded. Little-endian throughout, as the format is.
  ##
  ## Written here rather than delegated so that a hash device this module
  ## produced is one ``veritysetup open`` accepts with no arguments
  ## beyond the root hash — the superblock is where the geometry lives at
  ## activation time.
  var sb = newString(VeritySuperblockSize)
  proc put(at: int; s: string) =
    for i in 0 ..< s.len:
      sb[at + i] = s[i]
  proc putLe(at, width: int; value: uint64) =
    for i in 0 ..< width:
      sb[at + i] = char((value shr (8 * i)) and 0xFF'u64)

  put(0, VeritySuperblockMagic)
  putLe(8, 4, uint64(spec.superblockVersion))
  putLe(12, 4, uint64(VerityHashTypeNormal))
  # The UUID's 16 bytes, in the order they are printed.
  var hex = ""
  for c in spec.uuid:
    if c != '-': hex.add c
  var i = 0
  while i < 32:
    sb[16 + i div 2] = char(parseHexInt(hex[i .. i + 1]))
    i += 2
  put(32, spec.hashName)
  putLe(64, 4, uint64(spec.dataBlockSize))
  putLe(68, 4, uint64(spec.hashBlockSize))
  putLe(72, 8, uint64(dataBlocks))
  let salt = spec.saltBytes()
  putLe(80, 2, uint64(salt.len))
  put(88, salt)

  sb & newString(spec.hashBlockSize - VeritySuperblockSize)

proc formatVerity*(spec: VeritySpec; dataPath, hashPath: string): VerityImage =
  ## Read the data image, write the hash device, return the root hash.
  ##
  ## Raises ``ValueError`` with an operator-facing reason for a spec or a
  ## data image it cannot honour; a verity image that is nearly right is
  ## worse than none.
  let specError = validateVeritySpec(spec)
  if specError.len > 0:
    raise newException(ValueError, "formatVerity: " & specError)
  if not fileExists(dataPath):
    raise newException(ValueError,
      "formatVerity: no data image at " & dataPath)
  let data = readFile(dataPath)
  let sizeError = validateVerityDataSize(spec, data.len.int64)
  if sizeError.len > 0:
    raise newException(ValueError, "formatVerity: " & sizeError)

  let dataBlocks = spec.verityDataBlocks(data.len.int64)
  let (area, rootHash) = buildVerityTree(spec, data)
  writeFile(hashPath, renderVeritySuperblock(spec, dataBlocks) & area)
  VerityImage(
    rootHash: rootHash,
    dataBlocks: dataBlocks,
    hashBlocks: spec.verityHashBlocks(dataBlocks),
    levels: spec.verityLevels(dataBlocks),
    spec: spec)

proc findVerityCorruption*(spec: VeritySpec; data: string;
                           hashArea: string): seq[VerityCorruption] =
  ## Every data block whose digest disagrees with the level-0 tree in
  ## ``hashArea`` (which excludes the superblock).
  ##
  ## This is the check the kernel performs per read, run over the whole
  ## image at once. It is what lets a gate name *which* block a mutation
  ## landed in, rather than only that the root hash moved.
  result = @[]
  let dataBlocks = spec.verityDataBlocks(data.len.int64)
  let offsets = spec.verityLevelOffsets(dataBlocks)
  if offsets.len == 0:
    return
  let salt = spec.saltBytes()
  let base = offsets[0] * spec.hashBlockSize
  for b in 0 ..< dataBlocks:
    let want = hashArea[base + b * VerityDigestSize ..<
                        base + (b + 1) * VerityDigestSize]
    let got = spec.blockDigest(salt,
      toOpenArray(data, b * spec.dataBlockSize,
                  (b + 1) * spec.dataBlockSize - 1))
    if want != got:
      result.add VerityCorruption(
        dataBlock: b, expected: toHexLower(want), actual: toHexLower(got))

# ---------------------------------------------------------------------
# The two renderings the rest of the system consumes.
# ---------------------------------------------------------------------

proc verityFormatArgs*(spec: VeritySpec; dataPath, hashPath: string):
    seq[string] =
  ## The exact ``veritysetup format`` argv the image build runs.
  ##
  ## Every value that would otherwise be invented is passed: without
  ## ``--salt`` the salt comes from the system RNG and without ``--uuid``
  ## the hash device's UUID does too, so two builds of identical inputs
  ## would differ. The block sizes and hash name are passed rather than
  ## defaulted because a default is a value that can move with the tool.
  @[
    "format",
    dataPath,
    hashPath,
    "--hash=" & spec.hashName,
    "--data-block-size=" & $spec.dataBlockSize,
    "--hash-block-size=" & $spec.hashBlockSize,
    "--format=" & $spec.superblockVersion,
    "--salt=" & spec.salt,
    "--uuid=" & spec.uuid,
  ]

proc verityCmdlineFragment*(rootHash, dataDevice, hashDevice: string):
    string =
  ## What the boot path must carry so the initrd can activate the root.
  ##
  ## The root hash is the load-bearing half. Pinning it in a kernel
  ## command line that is itself measured is what makes the measurement
  ## cover every byte of the root filesystem: change one byte of the root
  ## closure and the root hash changes, so the command line changes, so
  ## the measurement changes. A root hash the guest could choose at boot
  ## would prove nothing at all.
  VerityRootHashCmdlineKey & "=" & rootHash & " " &
    VerityDataDeviceCmdlineKey & "=" & dataDevice & " " &
    VerityHashDeviceCmdlineKey & "=" & hashDevice

proc stateCmdlineFragment*(varDevice, homeDevice: string): string =
  ## The state volumes the initrd mounts read-write before it switches
  ## root. Declared beside the verity keys because they are the other
  ## half of the same decision: everything writable is named here, so
  ## everything NOT named here is on the measured, read-only surface.
  ## An empty device is omitted rather than emitted empty, so a layout
  ## with no separate ``/home`` produces a command line that says so.
  var parts: seq[string] = @[]
  if varDevice.len > 0:
    parts.add VerityStateVarCmdlineKey & "=" & varDevice
  if homeDevice.len > 0:
    parts.add VerityStateHomeCmdlineKey & "=" & homeDevice
  parts.join(" ")

proc verityTableLine*(image: VerityImage; dataDevice, hashDevice: string):
    string =
  ## The device-mapper table for this image, as ``dmsetup create`` takes
  ## it. The image build activates through ``veritysetup``, which builds
  ## the same line from the superblock; this rendering exists so a
  ## reader — and a gate — can see what that amounts to, and so a
  ## recovery path that has no ``veritysetup`` still has a table to load.
  ##
  ## The hash device offset is 1 block: the superblock occupies the
  ## first, and the tree starts after it.
  let sectorsPerBlock = image.spec.dataBlockSize div 512
  "0 " & $(image.dataBlocks * sectorsPerBlock) & " verity " &
    $image.spec.superblockVersion & " " & dataDevice & " " & hashDevice &
    " " & $image.spec.dataBlockSize & " " & $image.spec.hashBlockSize &
    " " & $image.dataBlocks & " 1 " & image.spec.hashName & " " &
    image.rootHash & " " & image.spec.salt

proc renderVerityManifest*(image: VerityImage): string =
  ## The manifest written beside the image. Hand-rendered, in a fixed key
  ## order, because it is compared byte for byte by its gate and because
  ## the measurement manifest that will consume it is a build artifact,
  ## not a document anyone edits.
  "{\n" &
  "  \"schema\": \"reproos.verity-root.v1\",\n" &
  "  \"rootHash\": \"" & image.rootHash & "\",\n" &
  "  \"hashName\": \"" & image.spec.hashName & "\",\n" &
  "  \"salt\": \"" & image.spec.salt & "\",\n" &
  "  \"uuid\": \"" & image.spec.uuid & "\",\n" &
  "  \"dataBlockSize\": " & $image.spec.dataBlockSize & ",\n" &
  "  \"hashBlockSize\": " & $image.spec.hashBlockSize & ",\n" &
  "  \"dataBlocks\": " & $image.dataBlocks & ",\n" &
  "  \"hashBlocks\": " & $image.hashBlocks & ",\n" &
  "  \"levels\": " & $image.levels & ",\n" &
  "  \"superblockVersion\": " & $image.spec.superblockVersion & "\n" &
  "}\n"
