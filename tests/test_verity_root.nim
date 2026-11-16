## Gate: the read-only root is integrity-checked, and the check works.
##
## ## What is being claimed
##
## An attestable image's root filesystem is a dm-verity image: a Merkle
## tree is taken over it at build time, and the tree collapses to one
## **root hash** that names its exact bytes. The kernel is handed that
## root hash from outside the disk and re-derives the digests on the path
## to every block it reads, so a block that has been altered fails the
## read instead of being served. Three properties have to hold for that
## to be worth anything, and they are this gate's three registered cases:
##
##   * ``t_verity_root_is_read_only`` — the root really is read-only and
##     the writable state really is elsewhere.
##   * ``t_verity_detects_corruption`` — a single altered byte makes the
##     read of its block FAIL. This is the negative case the whole
##     measurement chain rests on: a verity root that quietly serves
##     altered bytes is worse than no verity at all, because it looks
##     protected.
##   * ``t_verity_root_hash_is_deterministic`` — two builds of the same
##     inputs produce the same root hash, and a change to the root
##     closure changes it. A root hash that moves on its own cannot be
##     pinned into anything.
##
## ## The layers, and what each is worth
##
##   1. **The tree, and what it is a function of** (always on, ~2s, no
##      external tools). ``repro/verity.nim`` builds real Merkle trees
##      over real byte arrays here. It is checked against a KNOWN ANSWER
##      that ``veritysetup format`` produced — so this layer is not a
##      construction checking itself — and then exercised for
##      determinism, for corruption localisation, and against mutations
##      that must redden it.
##
##      This PROVES the tree is the published dm-verity format and that
##      the root hash is a pure function of the bytes. It proves NOTHING
##      about the kernel, about a mount, or about what a running system
##      does with a corrupted block.
##
##   2. **The reference implementation agrees** (opt-in,
##      ``REPROOS_VERITY_TOOL_GATE=1``, ~20s). The shipped
##      ``build-verity-root.sh`` is run for real against a staged tree,
##      twice, and its two outputs compared byte for byte; the tree it
##      produced through ``veritysetup`` is compared byte for byte
##      against the one built in layer 1.
##
##      Opt-in because it needs ``mkfs.ext4`` and ``veritysetup``, and
##      both are from-source packages in this project: declaring them as
##      tool identities would make an always-on gate bootstrap them.
##      When it IS asked for and a tool is missing it FAILS — it does not
##      skip.
##
##   3. **The kernel agrees, in a booted guest** (opt-in,
##      ``REPROOS_VERITY_GUEST_GATE=1``, ~1 min). A guest is booted on
##      the product's OWN ``init-disk`` initramfs, built by the product's
##      OWN ``build-initramfs.sh``, over a verity image built by the
##      product's OWN ``build-verity-root.sh``. Three boots:
##
##        * clean — verity activates, ``/`` refuses a write, ``/var``
##          accepts one, and the payload reads back.
##        * corrupted — one byte flipped in the data image; reading the
##          affected block must FAIL. The same boot then reads the same
##          block straight off the raw device, with dm-verity out of the
##          path, and must get the altered bytes back. That second read
##          is the falsification: it shows the failure came from verity
##          and not from a disk that simply cannot be read.
##        * wrong root hash — activation must fail closed and the boot
##          must stop, rather than fall through to an unchecked mount.
##
##      This is the only layer that proves anything about a running
##      system. It is opt-in because it needs QEMU, a kernel with a
##      module tree, a static BusyBox and a ``veritysetup`` binary to
##      stage; when it is not asked for it says so and names the remedy,
##      and it never passes silently.
##
## ## What no layer here proves
##
## Nothing here builds a ReproOS image. The verity root under test in
## layers 2 and 3 is a small purpose-built tree, not the 118-package
## ReproOS closure, and no partition table, boot loader or installed
## system is involved. What is exercised is the real product code that
## would build and boot the real one.
##
## ## Mocking
##
## None. Layer 1 is pure computation checked against an external known
## answer. Layer 2 runs the real ``mkfs.ext4`` and the real
## ``veritysetup`` through the shipped script. Layer 3 runs a real QEMU
## on a real kernel with the real initramfs builder and the real
## ``init-disk``; the assertions are read off the guest's own serial
## console.

import std/[options, os, osproc, strutils, times]

import "../repro/verity"
import "../repro/disk_layouts"
import "../repro/uki"
import "./root_policy_fixture"
import "./gate_layers"

import nimcrypto/[hash, sha2]

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  ToolGateEnv = "REPROOS_VERITY_TOOL_GATE"
  GuestGateEnv = "REPROOS_VERITY_GUEST_GATE"
  HardeningGateEnv = "REPROOS_ATTESTED_HARDENING_GATE"

  VmNamePrefix = "reproos-att-verity-"
    ## Every VM this gate creates is named under the shared
    ## ``reproos-att-`` prefix, so a sweep can find whatever a crashed
    ## run left behind and nothing here can be confused with the
    ## production guests that share this host.

  # ------------------------------------------------------------------
  # The known answer.
  #
  # Produced by cryptsetup's `veritysetup format` over the deterministic
  # image `katImage()` builds below, with the salt and UUID spelled out
  # so the value depends on nothing this repository can quietly change:
  #
  #   veritysetup format kat.img kat.hash --hash=sha256 \
  #     --data-block-size=4096 --hash-block-size=4096 --format=1 \
  #     --salt=<KatSalt> --uuid=<KatUuid>
  #
  # It is the anchor that stops layer 1 from being a construction that
  # agrees with itself. Layer 2 re-derives it with a real veritysetup, so
  # a wrong constant here does not survive a run with the tools present.
  # ------------------------------------------------------------------
  KatBlocks = 256
  KatSalt = "526570726f4f5320766572697479206b6e6f776e2d616e73776572" &
            "2074657374"
  KatUuid = "00000000-0000-5000-8000-000000000001"
  KatDataSha256 =
    "5d5cf5c559352e933477a5ec14b29edd10fe745adfbbc585e8e46669d0181b39"
  KatHashDeviceSha256 =
    "7c4097cc4187dae2d6c5efef597beb5143d69641d07803fe75ccc53203f3e0a4"
  KatRootHash =
    "1088359ddf0ac36cb88ca0886dde79bd2d323259a8de072e0ee8652c1a6c2c11"

var
  failures = 0
  passes = 0
  skips = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message
  passes.inc

proc skip(message: string) =
  echo "[skip] " & message
  skips.inc

proc check(condition: bool; what: string) =
  if condition: pass(what) else: fail(what)

proc sha256Hex(s: string): string =
  toLowerAscii($sha256.digest(s))

proc envOr(name, fallback: string): string =
  let v = getEnv(name)
  if v.len > 0: v else: fallback

proc katSpec(): VeritySpec =
  VeritySpec(
    hashName: VerityHashName,
    dataBlockSize: VerityDataBlockSize,
    hashBlockSize: VerityHashBlockSize,
    salt: KatSalt,
    uuid: KatUuid,
    superblockVersion: VeritySuperblockVersion)

proc katImage(): string =
  ## A byte-exact, tool-free data image. Block ``i`` is
  ## ``sha256("reproos-verity-kat:i")`` repeated to fill the block, so
  ## the image is reproducible from this description alone in any
  ## language — which is what makes the golden above checkable by
  ## someone who does not trust this file.
  result = newStringOfCap(KatBlocks * VerityDataBlockSize)
  for i in 0 ..< KatBlocks:
    let d = sha256.digest("reproos-verity-kat:" & $i)
    var blockBytes = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      blockBytes[j] = char(d.data[j])
    for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
      result.add blockBytes

# =====================================================================
# Layer 1 — the tree, and what it is a function of. Always on.
# =====================================================================

block layerKnownAnswer:
  let spec = katSpec()
  let data = katImage()
  check(sha256Hex(data) == KatDataSha256,
        "the known-answer data image is the one the golden was taken over")

  let (area, rootHash) = buildVerityTree(spec, data)
  check(rootHash == KatRootHash,
        "the root hash equals the one veritysetup produced (" &
        KatRootHash & ")")

  let device = renderVeritySuperblock(spec, KatBlocks) & area
  check(sha256Hex(device) == KatHashDeviceSha256,
        "the whole hash device -- superblock and tree -- is byte-identical " &
        "to veritysetup's")

  # The mutations. Each is a plausible implementation mistake, and each
  # must change the root hash: if any of them did not, the construction
  # would not be the format the kernel reads.
  block saltIsLoadBearing:
    var other = spec
    other.salt = "00" & KatSalt[2 .. ^1]
    check(buildVerityTree(other, data)[1] != KatRootHash,
          "changing one byte of the salt changes the root hash")

  block everyDataBlockIsCovered:
    for at in [0, VerityDataBlockSize, (KatBlocks - 1) * VerityDataBlockSize,
               KatBlocks * VerityDataBlockSize - 1]:
      var mutated = data
      mutated[at] = char(uint8(mutated[at]) xor 0xFF'u8)
      if buildVerityTree(spec, mutated)[1] == KatRootHash:
        fail("flipping the byte at offset " & $at &
             " did not change the root hash, so that byte is not covered")
        break
    pass("flipping a byte at the first, second, last-block and last " &
         "offsets each changes the root hash")

  block levelOrderIsLoadBearing:
    # The levels sit on the hash device top-first. A producer that wrote
    # them bottom-first would build a tree the kernel reads at the wrong
    # offsets, and every read would fail. The offsets must therefore not
    # be ascending with the level index.
    let offsets = spec.verityLevelOffsets(KatBlocks)
    check(offsets.len >= 2 and offsets[0] > offsets[^1],
          "the hash tree is laid out top level first, as the kernel " &
          "reads it")

  block geometryMatchesTheKernelArithmetic:
    # Re-derived here from the rule rather than from the module, so the
    # module cannot define its own correctness -- and re-derived by a
    # DIFFERENT route than the module takes. The module sizes level i by
    # a closed form over the last data block's position; this walks the
    # chain instead, one level at a time, because that is the property
    # the construction actually needs: level i must hold one digest per
    # BLOCK of level i-1.
    #
    # The two derivations disagree exactly where a level ends in a
    # partly-filled block -- 16385 data blocks fill 129 level-0 blocks,
    # so level 1 needs 2 -- and sizing a level from `dataBlocks shr
    # (shift*i)` alone says 1 there. The boundary sizes below are in this
    # list because that class of size is the one a formula can get wrong
    # while every power-of-two size still looks right.
    var bad: seq[string] = @[]
    for blocks in [1, 2, 127, 128, 129, 16383, 16384, 16385, 16386,
                   16511, 16512, 16513, 1048576, 2097152, 2097153]:
      var levels = 0
      while 7 * levels < 64 and ((blocks - 1) shr (7 * levels)) != 0:
        levels.inc
      if spec.verityLevels(blocks) != levels:
        bad.add $blocks & ": levels " & $spec.verityLevels(blocks) &
          " != " & $levels
      var chain: seq[int] = @[]
      var below = blocks
      while below > 1:
        below = (below div 128) + (if below mod 128 != 0: 1 else: 0)
        chain.add below
      let sizes = spec.verityLevelSizes(blocks)
      if sizes != chain:
        bad.add $blocks & ": sizes " & $sizes & " != " & $chain
      if chain.len != levels:
        bad.add $blocks & ": the chain gives " & $chain.len &
          " levels, the shift rule gives " & $levels
      var total = 0
      for s in chain: total += s
      if spec.verityHashBlocks(blocks) != total:
        bad.add $blocks & ": hash blocks " & $spec.verityHashBlocks(blocks) &
          " != " & $total
      # The invariant the construction depends on, stated separately so a
      # size that violates it is named rather than showing up as an index
      # error inside buildVerityTree: every level must have room for the
      # digests of the level beneath it.
      for i in 1 ..< sizes.len:
        if sizes[i] * VerityHashBlockSize <
            sizes[i - 1] * VerityDigestSize:
          bad.add $blocks & ": level " & $i & " (" & $sizes[i] &
            " blocks) cannot hold level " & $(i - 1) & "'s " &
            $sizes[i - 1] & " digests"
    check(bad.len == 0,
          "level counts and level sizes match dm-verity's own arithmetic " &
          "for 1 block through 8 GiB, including the sizes where a level " &
          "ends in a partly-filled block" &
          (if bad.len > 0: " -- " & bad.join("; ") else: ""))

  block theConstructionSurvivesTheBoundarySizes:
    # The arithmetic above is checked at 16385 blocks; this BUILDS there.
    # An implementation that sized level 1 at one block would not produce
    # a wrong tree here, it would walk off the end of one -- so this is
    # the case that turns a silent formula error into a red test.
    var big = newStringOfCap(16385 * VerityDataBlockSize)
    for i in 0 ..< 16385:
      let d = sha256.digest("reproos-verity-boundary:" & $i)
      var blockBytes = newString(VerityDigestSize)
      for j in 0 ..< VerityDigestSize:
        blockBytes[j] = char(d.data[j])
      for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
        big.add blockBytes
    # Caught rather than allowed to propagate: a level sized too small
    # does not return a wrong tree, it writes off the end of one, and an
    # uncaught IndexDefect would take every check after this one with it
    # instead of reporting one red line.
    var bigArea = ""
    var bigRoot = ""
    var buildError = ""
    try:
      (bigArea, bigRoot) = buildVerityTree(spec, big)
    except Exception as e:
      buildError = $e.name & ": " & e.msg
    check(buildError.len == 0 and bigRoot.len == 64 and
          bigArea.len == spec.verityHashBlocks(16385) * VerityHashBlockSize and
          spec.verityHashBlocks(16385) == 132,
          "a tree over 16385 data blocks -- one block past a full level -- " &
          "builds, and occupies the 132 hash blocks the chain says it does " &
          "(got " & $spec.verityHashBlocks(16385) &
          (if buildError.len > 0: ", and building it raised " & buildError
           else: "") & ")")
    if buildError.len == 0:
      check(findVerityCorruption(spec, big, bigArea).len == 0,
            "that tree verifies against the image it was taken over")
      var movedBig = big
      let atBig = 16384 * VerityDataBlockSize + 5
      movedBig[atBig] = char(uint8(movedBig[atBig]) xor 0xFF'u8)
      let foundBig = findVerityCorruption(spec, movedBig, bigArea)
      check(foundBig.len == 1 and foundBig[0].dataBlock == 16384,
            "and the LAST data block -- the one whose position decides " &
            "every level's size -- is covered by it")
    else:
      fail("the 16385-block tree could not be built, so the two checks " &
           "that depend on it did not run: " & buildError)

  block aSingleDataBlockHasNoTree:
    # dm-verity's degenerate case: one data block, zero levels, and the
    # root hash is that block's own digest. veritysetup writes a hash
    # device of nothing but the superblock for it. Checked because the
    # level arithmetic indexes level 0 and there is no level 0 here.
    let lone = newString(VerityDataBlockSize)
    check(spec.verityLevels(1) == 0 and spec.verityHashBlocks(1) == 0,
          "one data block has no hash tree above it")
    let (loneArea, loneRoot) = buildVerityTree(spec, lone)
    check(loneArea.len == 0 and loneRoot.len == 64,
          "building it yields an empty hash area and a root hash rather " &
          "than an index error")

block layerCorruptionLocalisation:
  let spec = katSpec()
  let data = katImage()
  let (area, _) = buildVerityTree(spec, data)

  check(findVerityCorruption(spec, data, area).len == 0,
        "an untouched image reports no corrupted block")

  var bad: seq[string] = @[]
  for target in [0, 1, 127, 128, 255]:
    var mutated = data
    let at = target * VerityDataBlockSize + 17
    mutated[at] = char(uint8(mutated[at]) xor 0x01'u8)
    let found = findVerityCorruption(spec, mutated, area)
    if found.len != 1 or found[0].dataBlock != target:
      bad.add "block " & $target & " -> " &
        (if found.len == 0: "nothing" else: $found[0].dataBlock &
         " (" & $found.len & " reports)")
  check(bad.len == 0,
        "a one-bit change in block N is reported as block N and nothing " &
        "else" & (if bad.len > 0: " -- " & bad.join("; ") else: ""))

  # The negative: a verifier that always said "clean" would pass the
  # first case above. This is the case that would catch it.
  var wiped = area
  for i in 0 ..< VerityDigestSize:
    wiped[spec.verityLevelOffsets(KatBlocks)[0] * VerityHashBlockSize + i] =
      '\0'
  check(findVerityCorruption(spec, data, wiped).len == 1,
        "zeroing one leaf digest is reported, so the verifier is not " &
        "returning 'clean' unconditionally")

block layerDeterminism:
  # t_verity_root_hash_is_deterministic, at the level of the derivation.
  # The bytes half of the same claim is layer 2's.
  let seedA = "reproos-image-v1:aaaa"
  let seedB = "reproos-image-v1:bbbb"
  let specA1 = verityRootSpec(seedA)
  let specA2 = verityRootSpec(seedA)
  let specB = verityRootSpec(seedB)

  check(specA1 == specA2,
        "one seed derives one salt, one hash-device UUID and one geometry")
  check(specA1.salt != specB.salt and specA1.uuid != specB.uuid,
        "a different seed derives a different salt and UUID")
  check(validateVeritySpec(specA1).len == 0,
        "a spec derived from a seed is usable")
  check(validateVeritySpec(verityRootSpec("")).len > 0,
        "a spec derived from NO seed is refused, naming the salt as the " &
        "reason -- an unseeded build must fail rather than emit an image " &
        "whose root hash moves")
  check(verityRootFsUuid(seedA) != verityRootFsHashSeed(seedA),
        "the root image's filesystem UUID and its directory-hash seed " &
        "are different values, as mke2fs treats them")
  check(verityRootFsUuid(seedA) != specA1.uuid,
        "the root filesystem's UUID is not the hash device's UUID")

  let data = katImage()
  let h1 = verityRootHash(specA1, data)
  let h2 = verityRootHash(specA2, data)
  check(h1 == h2, "the same seed and the same bytes give the same root hash")
  check(verityRootHash(specB, data) != h1,
        "the same bytes under a different seed give a different root hash")

  var moved = data
  moved[3 * VerityDataBlockSize] =
    char(uint8(moved[3 * VerityDataBlockSize]) xor 0x80'u8)
  check(verityRootHash(specA1, moved) != h1,
        "one changed byte anywhere in the root closure changes the root hash")

block layerDeclarationsAgree:
  # The three places the verity contract is spelled out have to say the
  # same thing. They are in three languages, so nothing but a check like
  # this keeps them in step.
  let builder = readFile(
    RepoRoot / "recipes/reproos-image/scripts/build-verity-root.sh")
  var missing: seq[string] = @[]
  for expected in [
      "VERITY_HASH_NAME=" & VerityHashName,
      "VERITY_DATA_BLOCK_SIZE=" & $VerityDataBlockSize,
      "VERITY_HASH_BLOCK_SIZE=" & $VerityHashBlockSize,
      "VERITY_SUPERBLOCK_FORMAT=" & $VeritySuperblockVersion]:
    if expected notin builder:
      missing.add expected
  check(missing.len == 0,
        "build-verity-root.sh declares the same geometry repro/verity.nim " &
        "does" & (if missing.len > 0: " -- missing " & missing.join(", ")
                  else: ""))

  # The argv the script builds must be the argv verityFormatArgs renders.
  let spec = katSpec()
  let args = verityFormatArgs(spec, "$DATA_IMG", "$HASH_IMG")
  var absent: seq[string] = @[]
  for flag in ["--hash=$VERITY_HASH_NAME",
               "--data-block-size=$VERITY_DATA_BLOCK_SIZE",
               "--hash-block-size=$VERITY_HASH_BLOCK_SIZE",
               "--format=$VERITY_SUPERBLOCK_FORMAT",
               "--salt=$REPROOS_VERITY_SALT",
               "--uuid=$REPROOS_VERITY_UUID"]:
    if flag notin builder:
      absent.add flag
  check(absent.len == 0 and args.len == 9,
        "the script passes every value veritysetup would otherwise invent" &
        (if absent.len > 0: " -- missing " & absent.join(", ") else: ""))

  let initDisk = readFile(RepoRoot / "recipes/reproos-iso/initramfs/init-disk")
  var unparsed: seq[string] = @[]
  for key in [VerityRootHashCmdlineKey, VerityDataDeviceCmdlineKey,
              VerityHashDeviceCmdlineKey, VerityStateVarCmdlineKey,
              VerityStateHomeCmdlineKey]:
    if (key & "=*)") notin initDisk:
      unparsed.add key
  check(unparsed.len == 0,
        "init-disk parses exactly the kernel command-line keys " &
        "repro/verity.nim declares" &
        (if unparsed.len > 0: " -- missing " & unparsed.join(", ") else: ""))

  check("veritysetup open" in initDisk and
        "rescue \"verity activation failed" in initDisk,
        "init-disk activates verity and treats a failure as fatal")
  check("mount -t \"$ROOT_FSTYPE\" -o ro \"$ROOT_DEV\"" in initDisk,
        "init-disk mounts the root read-only")
  check("-o \"$STATE_MOUNT_OPTS\"" in initDisk and
        "mount_state" in initDisk,
        "init-disk mounts the state volumes read-write")
  # The persistence surface of an integrity-checked root. The state
  # volumes outlive the boot and nothing measures them, so on that layout
  # they must be mounted so that nothing planted on them can run, gain
  # privilege through a setuid bit, or reach a device through a planted
  # node -- and module loading and kexec close before init runs. The
  # booted-guest layer below (REPROOS_ATTESTED_HARDENING_GATE) attacks
  # each of these; this is the cheap check that the shipped script still
  # says so.
  check("STATE_MOUNT_OPTS='rw,nosuid,nodev,noexec'" in initDisk,
        "init-disk mounts an integrity-checked root's state volumes " &
        "noexec, nosuid and nodev")
  check("close_one_way /proc/sys/kernel/modules_disabled" in initDisk and
        "close_one_way /proc/sys/kernel/kexec_load_disabled" in initDisk,
        "init-disk closes module loading and kexec before switching into " &
        "an integrity-checked root")
  check("/sys/kernel/security/lockdown" in initDisk and
        "rescue \"the command line asks for lockdown=" in initDisk,
        "init-disk refuses an attested root when the kernel did not " &
        "honour the lockdown the command line asks for")
  # A refusal on that layout must stop the boot, not hand a root shell
  # to whoever holds the console -- on a cloud or confidential VM, the
  # operator or host the measurement is meant to exclude. The booted
  # guest layer's wrong-hash case below observes it; this is the cheap
  # check that the script still says so.
  let rescueAt = initDisk.find("rescue() {")
  let rescueEnd = initDisk.find("\n}\n", max(rescueAt, 0))
  let rescueBody =
    if rescueAt >= 0 and rescueEnd > rescueAt: initDisk[rescueAt .. rescueEnd]
    else: ""
  let noShellAt = rescueBody.find("if [ -n \"$VERITY_ROOTHASH\" ]; then")
  check(noShellAt >= 0 and "exit 1" in rescueBody[noShellAt .. ^1] and
        rescueBody.find("exec /bin/sh") > noShellAt,
        "init-disk's rescue stops the boot on an integrity-checked root " &
        "before it would exec a shell")

  let initramfsBuilder = readFile(
    RepoRoot / "recipes/reproos-iso/scripts/build-initramfs.sh")
  check("REPRO_INITRAMFS_VERITY" in initramfsBuilder and
        "veritysetup" in initramfsBuilder,
        "build-initramfs.sh can stage the one non-busybox binary " &
        "init-disk needs")

  # The preset's operator-facing reason has to keep up with what is
  # true. It said there was no verity image; there is one now, and a
  # reason that is no longer true is worse than no reason.
  let preset = findDiskLayoutPreset("uefi-attested")
  check(preset.isSome, "the attested layout preset is still registered")
  if preset.isSome:
    let reason = preset.get().unbuildableReason
    check("no verity image" notin reason,
          "the attested preset no longer claims there is no verity image")
    check(reason.len > 0 and preset.get().status == dlsDeclared,
          "the attested preset is still refused, and still says why -- " &
          "the root hash has nowhere measured to ride yet")

block layerCmdlineFragment:
  # What the boot artifact has to carry. Small, but it is the seam
  # between the verity image and the measurement that will consume it,
  # so it is pinned rather than assumed.
  let fragment = verityCmdlineFragment(KatRootHash, "/dev/vda2", "/dev/vda6")
  check(KatRootHash in fragment,
        "the command-line fragment carries the root hash verbatim")
  check(fragment.count('=') == 3 and fragment.split(' ').len == 3,
        "the fragment is exactly three key=value pairs")
  let spec = katSpec()
  let image = VerityImage(rootHash: KatRootHash, dataBlocks: KatBlocks,
                          hashBlocks: 3, levels: 2, spec: spec)
  let table = verityTableLine(image, "/dev/vda2", "/dev/vda6")
  check(table.startsWith("0 " & $(KatBlocks * 8) & " verity 1 ") and
        KatRootHash in table and KatSalt in table,
        "the device-mapper table names the same root hash and salt")
  check(renderVerityManifest(image).contains("\"rootHash\": \"" &
        KatRootHash & "\""),
        "the manifest carries the root hash under a stable key")
  check(stateCmdlineFragment("/dev/vda4", "/dev/vda5") ==
        VerityStateVarCmdlineKey & "=/dev/vda4 " &
        VerityStateHomeCmdlineKey & "=/dev/vda5" and
        stateCmdlineFragment("/dev/vda4", "") ==
        VerityStateVarCmdlineKey & "=/dev/vda4",
        "the state-volume fragment names every writable volume and " &
        "omits the ones the layout does not have")

# =====================================================================
# Layer 2 — the reference implementation agrees. Opt-in.
# =====================================================================

proc requireTool(gate, tool: string): string =
  ## Layer 2 and 3 tools are NOT declared identities, for the reason in
  ## the header. When the layer is asked for, a missing one is a loud
  ## failure rather than a skip.
  let found = findExe(tool)
  if found.len == 0:
    fail(gate & ": required tool not found on PATH: " & tool &
         ". This layer was asked for, so its absence is a failure, not " &
         "a skip.")
  found

proc writeStagedTree(dir: string) =
  ## A small but genuine root filesystem: a script, a symlink farm, a
  ## nested directory and a multi-megabyte file, so the resulting ext4
  ## exercises more than a single block group.
  removeDir(dir)
  createDir(dir / "bin")
  createDir(dir / "etc")
  createDir(dir / "usr" / "share")
  writeFile(dir / "etc" / "marker", "reproos-verity-root-marker\n")
  writeFile(dir / "bin" / "hello", "#!/bin/sh\necho hello\n")
  var payload = newStringOfCap(2 * 1024 * 1024)
  for i in 0 ..< 512:
    let d = sha256.digest("payload:" & $i)
    var b = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      b[j] = char(d.data[j])
    for _ in 0 ..< 128:
      payload.add b
  writeFile(dir / "usr" / "share" / "payload", payload)
  # The shipped builder carries the guest inode policy into the image and
  # refuses to hash one it could not describe.
  writeRootPolicyFixture(dir)

proc runVerityRootBuilder(treeDir, outDir: string; extraEnv = ""): int =
  ## Drive the shipped builder with exactly the environment
  ## ``recipes/reproos-image/package.nim`` assembles for it, derived the
  ## same way from one seed.
  const seed = "reproos-image-v1:verity-gate"
  let spec = verityRootSpec(seed)
  let cmd =
    "REPROOS_STAGED_ROOTFS=" & quoteShell(treeDir) &
    " REPROOS_VERITY_SALT=" & spec.salt &
    " REPROOS_VERITY_UUID=" & spec.uuid &
    " REPROOS_VERITY_FS_UUID=" & verityRootFsUuid(seed) &
    " REPROOS_VERITY_FS_HASH_SEED=" & verityRootFsHashSeed(seed) &
    " SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " & extraEnv &
    " bash " & quoteShell(RepoRoot /
      "recipes/reproos-image/scripts/build-verity-root.sh") &
    " " & quoteShell(outDir)
  let r = execCmdEx(cmd)
  if r.exitCode != 0:
    stderr.writeLine(r.output)
  r.exitCode

block layerReferenceImplementation:
  let toolLayer = optInLayer(ToolGateEnv)
  if toolLayer.isBlocked:
    fail(blockedNote(ToolGateEnv,
      "bash tests/test-verity-root.sh, with " & ToolGateEnv & "=1"))
  elif toolLayer == lrNotRequested:
    skip("the reference-implementation layer did not run: NO real " &
         "veritysetup or mkfs.ext4 was executed and NO image bytes were " &
         "compared. " & notRequestedNote(ToolGateEnv) &
         " It takes ~20s and needs mkfs.ext4 and veritysetup on PATH.")
  else:
    let gate = "verity tool layer"
    discard requireTool(gate, "mkfs.ext4")
    let veritysetup = requireTool(gate, "veritysetup")
    if veritysetup.len > 0:
      let work = getTempDir() / "reproos-verity-tools-" &
        $getCurrentProcessId()
      removeDir(work)
      createDir(work)
      defer: removeDir(work)

      # 2a. The reference producer agrees with repro/verity.nim, byte for
      #     byte, over the known-answer image.
      let katPath = work / "kat.img"
      writeFile(katPath, katImage())
      let theirs = work / "kat.veritysetup.hash"
      let spec = katSpec()
      var argv = verityFormatArgs(spec, katPath, theirs)
      var cmd = quoteShell(veritysetup)
      for a in argv: cmd.add " " & quoteShell(a)
      let formatted = execCmdEx(cmd)
      if formatted.exitCode != 0:
        stderr.writeLine(formatted.output)
        fail("veritysetup format failed on the known-answer image")
      else:
        var reported = ""
        for line in formatted.output.splitLines():
          if line.startsWith("Root hash:"):
            reported = line.split()[^1]
        check(reported == KatRootHash,
              "the real veritysetup reports the golden root hash, so the " &
              "constant in this file is not a transcription of our own " &
              "output")
        let ours = work / "kat.ours.hash"
        let image = formatVerity(spec, katPath, ours)
        check(image.rootHash == KatRootHash,
              "formatVerity agrees with the golden")
        check(readFile(ours) == readFile(theirs),
              "the hash device repro/verity.nim writes is byte-identical " &
              "to the one veritysetup writes")

        # And the verifier the kernel effectively runs, run by the tool.
        let verified = execCmdEx(quoteShell(veritysetup) & " verify " &
          quoteShell(katPath) & " " & quoteShell(ours) & " " & KatRootHash)
        check(verified.exitCode == 0,
              "veritysetup verify accepts the tree repro/verity.nim built")

        # The negative: it must NOT accept the same tree against altered
        # data. Without this, "verify succeeded" would mean nothing.
        var mutated = katImage()
        mutated[100 * VerityDataBlockSize + 3] =
          char(uint8(mutated[100 * VerityDataBlockSize + 3]) xor 0xFF'u8)
        let mutatedPath = work / "kat.mutated.img"
        writeFile(mutatedPath, mutated)
        let rejected = execCmdEx(quoteShell(veritysetup) & " verify " &
          quoteShell(mutatedPath) & " " & quoteShell(ours) & " " &
          KatRootHash)
        check(rejected.exitCode != 0,
              "veritysetup verify REJECTS the same tree against an image " &
              "with one altered byte")

        # 2a'. The same comparison at a size where the geometry is easy
        #      to get wrong. 256 blocks fills every level exactly, so it
        #      cannot tell a correct level-sizing rule from one that
        #      under-counts a partly-filled level; 16385 blocks can, and
        #      is where the two implementations have to agree if the
        #      agreement is to mean anything for a real root image.
        var bigData = newStringOfCap(16385 * VerityDataBlockSize)
        for i in 0 ..< 16385:
          let d = sha256.digest("reproos-verity-boundary:" & $i)
          var b = newString(VerityDigestSize)
          for j in 0 ..< VerityDigestSize:
            b[j] = char(d.data[j])
          for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
            bigData.add b
        let bigPath = work / "boundary.img"
        writeFile(bigPath, bigData)
        let bigTheirs = work / "boundary.veritysetup.hash"
        let bigOurs = work / "boundary.ours.hash"
        var bigCmd = quoteShell(veritysetup)
        for a in verityFormatArgs(spec, bigPath, bigTheirs):
          bigCmd.add " " & quoteShell(a)
        let bigFormatted = execCmdEx(bigCmd)
        if bigFormatted.exitCode != 0:
          stderr.writeLine(bigFormatted.output)
          fail("veritysetup format failed on the 16385-block image")
        else:
          var bigReported = ""
          for line in bigFormatted.output.splitLines():
            if line.startsWith("Root hash:"):
              bigReported = line.split()[^1]
          let bigImage = formatVerity(spec, bigPath, bigOurs)
          check(bigImage.rootHash == bigReported,
                "at 16385 data blocks -- one past a full level -- " &
                "repro/verity.nim and veritysetup agree on the root hash")
          check(readFile(bigOurs) == readFile(bigTheirs),
                "and on the whole hash device, byte for byte, at that size")
          removeFile(bigPath)
          removeFile(bigTheirs)
          removeFile(bigOurs)

      # 2b. The shipped builder, run twice, produces the same bytes.
      let tree = work / "tree"
      writeStagedTree(tree)
      let outA = work / "outA"
      let outB = work / "outB"
      if runVerityRootBuilder(tree, outA) != 0:
        fail("build-verity-root.sh failed on its first run")
      elif runVerityRootBuilder(tree, outB,
             "REPROOS_VERITY_GATE_SECOND_RUN=1 TMPDIR=" &
             quoteShell(work / "tmp2")) != 0:
        fail("build-verity-root.sh failed on its second run")
      else:
        var firstDifference = ""
        for name in [VerityDataImageFileName, VerityHashTreeFileName,
                     VerityRootHashFileName, VerityManifestFileName]:
          if readFile(outA / name) != readFile(outB / name):
            firstDifference = name
            break
        check(firstDifference.len == 0,
              "two runs of build-verity-root.sh over one tree produce " &
              "identical artifacts" &
              (if firstDifference.len > 0:
                 " -- first difference in " & firstDifference else: ""))

        let rootHash = readFile(outA / VerityRootHashFileName).strip()
        check(rootHash.len == 64,
              "the builder emits a 64-hex-digit root hash")

        # The ext4 block size, read out of the superblock the builder
        # just wrote. `mke2fs` chooses 1024 for a small filesystem, and a
        # 1024-byte-block filesystem CANNOT be mounted off a dm-verity
        # device: the device reports a 4096-byte logical block and the
        # kernel refuses with "bad block size". The resulting image
        # verifies perfectly and will not boot, so this is checked at the
        # bytes rather than at the flag.
        let sb = readFile(outA / VerityDataImageFileName)
        var logBlockSize = 0
        for i in countdown(3, 0):
          logBlockSize = (logBlockSize shl 8) or int(uint8(sb[0x400 + 0x18 + i]))
        check(1024 shl logBlockSize == VerityDataBlockSize,
              "the root image's ext4 superblock declares a " &
              $VerityDataBlockSize & "-byte block size (read at offset " &
              "0x418), which is what makes it mountable off a verity " &
              "device -- got " & $(1024 shl logBlockSize))

        # The tree veritysetup wrote inside the shipped script must be
        # the tree repro/verity.nim would have written for the same
        # image. Two implementations, one artifact.
        const seed = "reproos-image-v1:verity-gate"
        let ourTree = work / "shipped.ours.hash"
        let ourImage = formatVerity(verityRootSpec(seed),
                                    outA / VerityDataImageFileName, ourTree)
        check(ourImage.rootHash == rootHash,
              "repro/verity.nim re-derives the root hash the shipped " &
              "script produced with veritysetup")
        check(readFile(ourTree) == readFile(outA / VerityHashTreeFileName),
              "and the whole hash tree, byte for byte")

        # And the closure really is what the root hash is a function of.
        writeFile(tree / "etc" / "marker", "reproos-verity-root-marker!\n")
        let outC = work / "outC"
        if runVerityRootBuilder(tree, outC) != 0:
          fail("build-verity-root.sh failed after the tree changed")
        else:
          check(readFile(outC / VerityRootHashFileName).strip() != rootHash,
                "changing one byte of the staged tree changes the root hash")

# =====================================================================
# Layer 3 — the kernel agrees, in a booted guest. Opt-in.
# =====================================================================

type
  GuestArtifacts = object
    kernel: string        ## bzImage
    moduleTree: string    ## the directory holding lib/modules/<release>
    release: string
    busybox: string
    veritysetup: string

proc discoverGuestArtifacts(): (GuestArtifacts, string) =
  ## Returns the artifacts and "" , or a partly-filled record and the
  ## reason it could not be completed. Order of preference: whatever the
  ## caller pinned, then the ReproOS source-built kernel (whose dm-verity
  ## is compiled in), then the running host's own kernel and module tree.
  var a: GuestArtifacts
  let packagesRoot = envOr("REPROBUILD_PACKAGES_ROOT",
                           RepoRoot.parentDir / "reprobuild-packages")
  let srcKernel = packagesRoot / "packages/source/kernel/.repro/output/install"
  let srcBusybox =
    packagesRoot / "packages/source/busybox/.repro/output/install"

  a.kernel = getEnv("REPROOS_VERITY_GUEST_KERNEL")
  a.moduleTree = getEnv("REPROOS_VERITY_GUEST_MODULES")
  if a.kernel.len == 0:
    if fileExists(srcKernel / "usr/lib/reproos-kernel/vmlinuz"):
      a.kernel = srcKernel / "usr/lib/reproos-kernel/vmlinuz"
      a.moduleTree = srcKernel / "usr/lib"
      a.release = readFile(
        srcKernel / "usr/lib/reproos-kernel/kernel.release").strip()
    elif fileExists("/run/booted-system/kernel"):
      a.kernel = "/run/booted-system/kernel"
      a.moduleTree = "/run/booted-system/kernel-modules/lib"
      a.release = execCmdEx("uname -r").output.strip()
  if a.release.len == 0:
    a.release = getEnv("REPROOS_VERITY_GUEST_RELEASE")
  if a.kernel.len == 0 or not fileExists(a.kernel):
    return (a, "no kernel: set REPROOS_VERITY_GUEST_KERNEL, or build the " &
      "source kernel, or run on a host that publishes " &
      "/run/booted-system/kernel")
  if a.release.len == 0 or
     not dirExists(a.moduleTree / "modules" / a.release):
    return (a, "no module tree for " & a.release & " under " & a.moduleTree &
      "; set REPROOS_VERITY_GUEST_MODULES and REPROOS_VERITY_GUEST_RELEASE")

  a.busybox = getEnv("REPROOS_VERITY_GUEST_BUSYBOX")
  if a.busybox.len == 0 and fileExists(srcBusybox / "usr/bin/busybox"):
    a.busybox = srcBusybox / "usr/bin/busybox"
  if a.busybox.len == 0 or not fileExists(a.busybox):
    return (a, "no static BusyBox: set REPROOS_VERITY_GUEST_BUSYBOX, or " &
      "build the source BusyBox")

  a.veritysetup = getEnv("REPROOS_VERITYSETUP_BIN")
  if a.veritysetup.len == 0:
    a.veritysetup = findExe("veritysetup")
  if a.veritysetup.len == 0 or not fileExists(a.veritysetup):
    return (a, "no veritysetup to stage into the initramfs: set " &
      "REPROOS_VERITYSETUP_BIN or put one on PATH")
  (a, "")

proc buildGuestInitramfs(work: string; artifacts: GuestArtifacts;
                         initramfs: string): bool =
  ## An init-disk initramfs that can activate verity, built by the
  ## PRODUCT's own builder. A fake install-mirror layout is laid out under
  ## ``work`` so build-initramfs.sh is driven exactly as the recipe drives
  ## it and nothing about it is special-cased for the test. Prints the
  ## builder's output and returns false when it fails.
  let fakeKernel = work / "kernel-root"
  let fakeBusybox = work / "busybox-root"
  createDir(fakeKernel / "usr/lib/reproos-kernel")
  createDir(fakeKernel / "usr/lib/modules")
  createDir(fakeBusybox / "usr/bin")
  copyFile(artifacts.kernel,
           fakeKernel / "usr/lib/reproos-kernel/vmlinuz")
  writeFile(fakeKernel / "usr/lib/reproos-kernel/kernel.release",
            artifacts.release & "\n")
  # The source kernel's install mirror carries its symbol map beside the
  # image, and the builder runs depmod against it when the module tree
  # was installed without one (the recipe passes DEPMOD=true). Carried
  # over when present, so the source-built kernel is driven exactly as
  # the recipe drives it.
  let systemMap = artifacts.kernel.parentDir / "System.map"
  if fileExists(systemMap):
    copyFile(systemMap, fakeKernel / "usr/lib/reproos-kernel/System.map")
  createSymlink(artifacts.moduleTree / "modules" / artifacts.release,
                fakeKernel / "usr/lib/modules" / artifacts.release)
  copyFile(artifacts.busybox, fakeBusybox / "usr/bin/busybox")
  setFilePermissions(fakeBusybox / "usr/bin/busybox",
    {fpUserRead, fpUserWrite, fpUserExec, fpGroupRead, fpGroupExec,
     fpOthersRead, fpOthersExec})
  let build = execCmdEx(
    "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC" &
    " REPRO_KERNEL_INSTALL_ROOT=" & quoteShell(fakeKernel) &
    " REPRO_BUSYBOX_INSTALL_ROOT=" & quoteShell(fakeBusybox) &
    " REPRO_INITRAMFS_INIT=init-disk" &
    " REPRO_INITRAMFS_VERITY=require" &
    " REPRO_VERITYSETUP_BIN=" & quoteShell(artifacts.veritysetup) &
    " bash " & quoteShell(RepoRoot /
      "recipes/reproos-iso/scripts/build-initramfs.sh") &
    " " & quoteShell(initramfs))
  if build.exitCode != 0:
    stderr.writeLine(build.output)
    return false
  true

const GuestApplets = [
  "sh", "mount", "umount", "cat", "ls", "dd", "touch", "echo", "mkdir",
  "sleep", "poweroff", "od", "printf", "sync", "tr", "grep",
]

proc writeGuestRootTree(dir, busybox: string; bypassBlock: int) =
  ## The root filesystem the guest switch_roots into. Its ``/sbin/init``
  ## IS the assertion: everything this layer claims is read off what it
  ## prints to the console.
  ##
  ## It carries its own static BusyBox, because after ``switch_root`` the
  ## initramfs is gone -- the assertions have to run out of the verity
  ## root itself, which is also the point: every one of those binaries is
  ## being read through dm-verity.
  removeDir(dir)
  for d in ["bin", "sbin", "etc", "proc", "sys", "dev", "run", "tmp",
            "var", "home", "usr/share"]:
    createDir(dir / d)
  copyFile(busybox, dir / "bin" / "busybox")
  setFilePermissions(dir / "bin" / "busybox", {fpUserRead, fpUserWrite,
    fpUserExec, fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  for applet in GuestApplets:
    createSymlink("busybox", dir / "bin" / applet)
  writeFile(dir / "etc" / "marker", "reproos-verity-root-marker\n")
  var payload = newStringOfCap(2 * 1024 * 1024)
  for i in 0 ..< 512:
    let d = sha256.digest("payload:" & $i)
    var b = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      b[j] = char(d.data[j])
    for _ in 0 ..< 128:
      payload.add b
  writeFile(dir / "usr" / "share" / "payload", payload)
  # The bypass block number is printed with a FIXED width, so that
  # rewriting it does not change /sbin/init's size and therefore does not
  # move any other file inside the image. The block the corrupted case
  # flips has to be found in one image and still be the same block in the
  # next one; a variable-width number would quietly break that.
  let bypass = align($bypassBlock, 8, '0')
  writeFile(dir / "sbin" / "init", """#!/bin/sh
export PATH=/bin:/sbin
echo "VERITY-GUEST-START" > /dev/console
if touch /verity-write-probe 2>/dev/null; then
  echo "VERITY-ROOT-WRITE=succeeded" > /dev/console
else
  echo "VERITY-ROOT-WRITE=refused" > /dev/console
fi
if touch /var/verity-write-probe 2>/dev/null; then
  echo "VERITY-VAR-WRITE=succeeded" > /dev/console
else
  echo "VERITY-VAR-WRITE=refused" > /dev/console
fi
if cat /etc/marker > /dev/console 2>/dev/null; then
  echo "VERITY-READ-MARKER=ok" > /dev/console
else
  echo "VERITY-READ-MARKER=failed" > /dev/console
fi
# Every redirect here goes to /dev/null. /tmp is ON THE READ-ONLY ROOT,
# so a redirect into it fails before the command runs -- which would make
# the payload read "fail" on a perfectly good image and turn the
# corruption case into a check that cannot tell the two apart.
if dd if=/usr/share/payload of=/dev/null bs=4096 >/dev/null 2>/dev/null; then
  echo "VERITY-READ-PAYLOAD=ok" > /dev/console
else
  echo "VERITY-READ-PAYLOAD=failed" > /dev/console
fi
BYPASS=$(dd if=/dev/vda bs=4096 skip=""" & bypass &
  """ count=1 2>/dev/null | od -An -tx1 -N16 | tr -d ' \n')
echo "VERITY-BYPASS-BLOCK=$BYPASS" > /dev/console
echo "VERITY-GUEST-DONE" > /dev/console
poweroff -f
""")
  setFilePermissions(dir / "sbin" / "init", {fpUserRead, fpUserWrite,
    fpUserExec, fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  # The shipped builder carries the guest inode policy into the image and
  # refuses to hash one it could not describe. Written LAST and with fixed
  # content, so the two builds this layer performs still lay the payload
  # down at the same block.
  writeRootPolicyFixture(dir)

proc plainVerityCmdline(rootHash: string): string =
  ## The command line layer 3 boots: verity keys and one state volume,
  ## nothing the attested UKI adds. Layer 4 boots the attested one.
  "console=ttyS0 panic=1 loglevel=6 " &
    verityCmdlineFragment(rootHash, "/dev/vda", "/dev/vdb") & " " &
    stateCmdlineFragment("/dev/vdc", "")

type GuestDrive = tuple[path: string, readOnly: bool]

proc runGuest(qemu, kernel, initramfs, cmdline: string;
              drives: openArray[GuestDrive];
              serialLog, caseName: string;
              timeoutSec: int): bool =
  ## One boot. Returns false when QEMU could not be started or did not
  ## finish inside the timeout; the caller reads the transcript either
  ## way, because a hung boot's partial transcript is the diagnosis.
  ##
  ## Every case is expected to end on its own: a guest that reaches its
  ## init powers off, and ``init-disk`` refusing an integrity-checked root
  ## panics the kernel, which ``panic=1`` and ``-no-reboot`` turn into an
  ## exit. A guest still running at the timeout is a failure.
  removeFile(serialLog)
  var args = @[
    "-name", VmNamePrefix & caseName & "-" & $getCurrentProcessId(),
    "-machine", "q35,accel=kvm:tcg",
    "-m", "1024", "-smp", "2",
    "-kernel", kernel,
    "-initrd", initramfs,
    "-append", cmdline,
  ]
  # Attached in order, so the first is /dev/vda, the second /dev/vdb...
  for d in drives:
    args.add "-drive"
    args.add "file=" & d.path & ",format=raw,if=virtio" &
      (if d.readOnly: ",readonly=on" else: "")
  args.add [
    "-nographic", "-no-reboot", "-display", "none", "-monitor", "none",
    "-serial", "file:" & serialLog,
  ]
  var p: Process
  try:
    p = startProcess(qemu, args = args, options = {poStdErrToStdOut})
  except OSError as e:
    fail("could not start " & qemu & ": " & e.msg)
    return false
  let deadline = epochTime() + float(timeoutSec)
  while p.running and epochTime() < deadline:
    sleep(200)
  if p.running:
    # An unconditional teardown: nothing this gate starts may outlive it.
    p.terminate()
    sleep(500)
    if p.running: p.kill()
    discard p.waitForExit()
    p.close()
    fail("the " & caseName & " guest did not end within " &
         $timeoutSec & "s")
    return false
  discard p.waitForExit()
  p.close()
  true

proc transcript(path: string): string =
  if fileExists(path): readFile(path) else: ""

block layerBootedGuest:
  let guestLayer = optInLayer(GuestGateEnv)
  if guestLayer.isBlocked:
    fail(blockedNote(GuestGateEnv,
      "bash tests/test-verity-root.sh, with " & GuestGateEnv & "=1"))
  elif guestLayer == lrNotRequested:
    skip("the booted-guest layer did not run: NO guest was booted, NO " &
         "verity table was loaded by a kernel, and nothing here is " &
         "evidence about a running system. " & notRequestedNote(GuestGateEnv) &
         " It takes ~1 min and needs qemu-system-x86_64, mkfs.ext4, a " &
         "kernel with a module tree, a static BusyBox and a veritysetup " &
         "to stage.")
  else:
    let gate = "verity guest layer"
    let (artifacts, why) = discoverGuestArtifacts()
    if why.len > 0:
      fail(gate & ": " & why & ". This layer was asked for, so a missing " &
           "artifact is a failure, not a skip.")
    else:
      let qemu = requireTool(gate, "qemu-system-x86_64")
      discard requireTool(gate, "mkfs.ext4")
      if qemu.len > 0:
        let work = getTempDir() / "reproos-verity-guest-" &
          $getCurrentProcessId()
        removeDir(work)
        createDir(work)

        # --- the initramfs, built by the PRODUCT's own builder --------
        let initramfs = work / "initramfs.img"
        if not buildGuestInitramfs(work, artifacts, initramfs):
          fail("build-initramfs.sh could not build an init-disk initramfs " &
               "that can activate verity")
          removeDir(work)
        else:
          pass("build-initramfs.sh staged veritysetup into the init-disk " &
               "initramfs (REPRO_INITRAMFS_VERITY=require)")

          # --- the verity root, built by the product's own builder ----
          #
          # Built twice, on purpose. The corrupted case has to flip a
          # byte in a block the guest will actually READ, so the guest's
          # /sbin/init must name that block -- and the block can only be
          # found by looking inside a finished image. So: build once to
          # locate the payload, write the block number into /sbin/init
          # (at a fixed width, so no file moves), build again, and
          # require that the payload did not move. If it did, the gate
          # says so rather than corrupting a block nothing reads and
          # calling the resulting silence a pass.
          let tree = work / "tree"
          let outDir = work / "verity"
          let dataImage = outDir / VerityDataImageFileName
          let hashTree = outDir / VerityHashTreeFileName

          var probe = newString(VerityDigestSize)
          let d0 = sha256.digest("payload:0")
          for j in 0 ..< VerityDigestSize:
            probe[j] = char(d0.data[j])

          proc locatePayloadBlock(): int =
            let image = readFile(dataImage)
            let at = image.find(probe & probe)
            if at < 0 or at mod VerityDataBlockSize != 0: -1
            else: at div VerityDataBlockSize

          writeGuestRootTree(tree, artifacts.busybox, bypassBlock = 0)
          var buildFailed = runVerityRootBuilder(tree, outDir) != 0
          var payloadBlock = if buildFailed: -1 else: locatePayloadBlock()
          if not buildFailed and payloadBlock >= 0:
            writeGuestRootTree(tree, artifacts.busybox, bypassBlock = payloadBlock)
            removeDir(outDir)
            buildFailed = runVerityRootBuilder(tree, outDir) != 0
            if not buildFailed and locatePayloadBlock() != payloadBlock:
              fail("the payload moved between the two builds, so the " &
                   "block the guest is told to read is not the block " &
                   "the corrupted case flips")
              buildFailed = true

          if buildFailed or payloadBlock < 0:
            if payloadBlock < 0:
              fail("could not locate the payload inside the root image")
            else:
              fail("build-verity-root.sh failed for the guest root")
            removeDir(work)
          else:
              block guestCases:
                let corruptBlock = payloadBlock
                let finalHash =
                  readFile(outDir / VerityRootHashFileName).strip()

                # A writable state volume.
                let varImage = work / "var.img"
                let mkvar = execCmdEx("mkfs.ext4 -q -F -b 4096 " &
                  "-O ^has_journal " & quoteShell(varImage) & " 16M")
                if mkvar.exitCode != 0:
                  stderr.writeLine(mkvar.output)
                  fail("could not create the state volume image")

                # ---- case 1: a clean image ------------------------
                let cleanLog = work / "serial-clean.log"
                if runGuest(qemu, artifacts.kernel, initramfs,
                            plainVerityCmdline(finalHash),
                            [(dataImage, true), (hashTree, true),
                             (varImage, false)], cleanLog, "clean", 180):
                  let t = transcript(cleanLog)
                  check("VERITY-GUEST-START" in t,
                        "the guest reached /sbin/init inside the verity " &
                        "root, so the initrd activated verity and " &
                        "switched into it")
                  check("VERITY-ROOT-WRITE=refused" in t,
                        "t_verity_root_is_read_only: writing to / fails")
                  check("VERITY-VAR-WRITE=succeeded" in t,
                        "t_verity_root_is_read_only: writing to /var " &
                        "succeeds")
                  check("VERITY-READ-MARKER=ok" in t and
                        "reproos-verity-root-marker" in t,
                        "a file reads back correctly through dm-verity")
                  check("VERITY-READ-PAYLOAD=ok" in t,
                        "the whole multi-megabyte payload reads back " &
                        "through dm-verity")
                  check("is corrupted" notin t,
                        "the kernel reported no corrupted block on a " &
                        "clean image")
                else:
                  stderr.writeLine(transcript(cleanLog))

                # ---- case 2: one byte flipped ---------------------
                let corrupt = work / "corrupt.img"
                copyFile(dataImage, corrupt)
                var bytes = readFile(corrupt)
                let flipAt = corruptBlock * VerityDataBlockSize + 11
                let original = bytes[flipAt]
                bytes[flipAt] = char(uint8(original) xor 0xFF'u8)
                writeFile(corrupt, bytes)
                let corruptLog = work / "serial-corrupt.log"
                if runGuest(qemu, artifacts.kernel, initramfs,
                            plainVerityCmdline(finalHash),
                            [(corrupt, true), (hashTree, true),
                             (varImage, false)], corruptLog, "corrupt", 180):
                  let t = transcript(corruptLog)
                  check("VERITY-GUEST-START" in t,
                        "the guest still booted -- the corruption is " &
                        "block-scoped, not a boot failure")
                  check("VERITY-READ-MARKER=ok" in t,
                        "an untouched block still reads")
                  check("VERITY-READ-PAYLOAD=failed" in t,
                        "t_verity_detects_corruption: the read of the " &
                        "altered block FAILS")
                  check("data block " & $corruptBlock & " is corrupted" in t,
                        "t_verity_detects_corruption: the kernel names " &
                        "block " & $corruptBlock & " as the corrupted one")
                  # The falsification. With verity out of the path the
                  # same block is served, and served ALTERED -- so the
                  # failure above came from the integrity check and not
                  # from an unreadable disk.
                  var expectedHex = ""
                  for i in 0 ..< 16:
                    expectedHex.add toLowerAscii(
                      toHex(int(uint8(bytes[corruptBlock *
                        VerityDataBlockSize + i])), 2))
                  check("VERITY-BYPASS-BLOCK=" & expectedHex in t,
                        "reading the same block straight off the raw " &
                        "device SUCCEEDS and hands back the altered " &
                        "bytes, which is what verity refused to do")
                else:
                  stderr.writeLine(transcript(corruptLog))

                # ---- case 3: a root hash that does not match -------
                #
                # The interesting part of this case is WHERE it stops.
                # `veritysetup open` only loads a table; it verifies
                # nothing, so activation succeeds even with a root hash
                # that is not the image's. The kernel catches it on the
                # first read of the top metadata block -- which is the
                # mount -- and the initrd stops there rather than falling
                # back to an unchecked mount. A boot that stops is the
                # correct outcome. On an integrity-checked root the initrd
                # offers no rescue shell -- the console belongs to whoever
                # runs the machine -- it exits, the kernel panics, and
                # ``panic=1`` with QEMU's ``-no-reboot`` ends the guest. So
                # a guest still running at the timeout is a guest sitting
                # in a shell, and fails.
                var wrong = finalHash
                wrong[0] = (if wrong[0] == '0': '1' else: '0')
                let wrongLog = work / "serial-wrong-hash.log"
                if runGuest(qemu, artifacts.kernel, initramfs,
                            plainVerityCmdline(wrong),
                            [(dataImage, true), (hashTree, true),
                             (varImage, false)], wrongLog, "wrong-hash", 60):
                  let t = transcript(wrongLog)
                  check("VERITY-GUEST-START" notin t,
                        "a root hash that does not match the image does " &
                        "NOT boot: the initrd never switched into a root")
                  check("metadata block" in t and "is corrupted" in t,
                        "the kernel refused the very first block of the " &
                        "hash tree, because it does not hash to the root " &
                        "hash it was given")
                  check("[disk-init] FATAL" in t,
                        "and the initrd stopped, rather than falling back " &
                        "to mounting the data device unchecked")
                  check("dropping to busybox shell" notin t and
                        "no rescue shell" in t,
                        "and it stopped the boot without offering a root " &
                        "shell on the console")
                else:
                  stderr.writeLine(transcript(wrongLog))

                echo "[info] guest transcripts under ", work
                echo "[info] root hash under test: ", finalHash
                # Nothing this gate started may outlive it -- unless the
                # caller asked to keep the evidence, which is the only
                # way to read a passing boot's serial transcript.
                if getEnv("REPROOS_VERITY_GUEST_KEEP") == "1":
                  echo "[info] kept (REPROOS_VERITY_GUEST_KEEP=1): ", work
                else:
                  removeDir(work)

# =====================================================================
# Layer 4 — what root can still do on a booted attested root. Opt-in.
#
# The launch measurement names the UKI and, through the root hash on its
# command line, every byte of the read-only root. It names nothing on the
# state volumes, and those volumes outlive the boot. So the question this
# layer asks is an attacker's: having had root once, what can I leave
# behind on /var or /home that runs again after the reboot that
# re-measures the machine, and what can I do to the running kernel while
# the measurement keeps naming the one that booted?
#
# The guest boots the product's own init-disk initramfs with the
# command line an attested UKI carries (``attestedKernelCmdline``, so
# ``lockdown=integrity`` and everything else the image measures), over a
# verity root whose /sbin/init is the attacker, running as root:
#
#   * plants a copy of a working binary on each state volume and runs it;
#   * plants a device node for kernel memory on a state volume and reads
#     through it;
#   * opens /dev/mem itself;
#   * loads a kernel module, and tries to switch module loading back on;
#   * reads the lockdown level and the kexec switch the kernel reports.
#
# And two controls, so the probes are not vacuous: the same planted
# binary DOES run from a tmpfs the attacker mounts itself (noexec on the
# state volumes removes the PERSISTENCE route; it does not stop root on a
# running machine from mounting something executable, and the spec says
# so), and the same binary runs from the verity root.
#
# Needs the ReproOS kernel: one built without the lockdown LSM ignores
# ``lockdown=integrity``, init-disk refuses to switch into the root, and
# this layer fails saying so.
# =====================================================================

const HardeningApplets = [
  "sh", "mount", "cat", "cp", "chmod", "mknod", "insmod", "dd", "echo",
  "mkdir", "grep", "poweroff", "true", "ls",
]

proc writeHardeningRootTree(dir, busybox, moduleFile: string) =
  ## The root the attacker runs from. ``moduleFile`` is a real ``.ko``
  ## from the guest kernel's module tree when it has one; with none, a
  ## file that is not a module at all, which a loader that is still open
  ## rejects with a DIFFERENT error from the one a closed loader gives.
  removeDir(dir)
  for d in ["bin", "sbin", "etc", "proc", "sys", "dev", "run", "tmp",
            "var", "home", "attacker-tmpfs", "usr/share"]:
    createDir(dir / d)
  copyFile(busybox, dir / "bin" / "busybox")
  setFilePermissions(dir / "bin" / "busybox", {fpUserRead, fpUserWrite,
    fpUserExec, fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  for applet in HardeningApplets:
    createSymlink("busybox", dir / "bin" / applet)
  if moduleFile.len > 0:
    copyFile(moduleFile, dir / "usr/share/probe.ko")
  else:
    writeFile(dir / "usr/share/probe.ko", "not a kernel module\n")
  # Every outcome line is `HARDENING-<probe>=<ok|refused> <message>`: the
  # message is the shell's own, so a refusal for the WRONG reason (a
  # missing file, say) is visible rather than read as protection.
  writeFile(dir / "sbin" / "init", """#!/bin/sh
export PATH=/bin:/sbin
say() { echo "$*" > /dev/console; }
probe() {
  # probe <name> <command...>: run it, report ok or refused + its message
  _name="$1"; shift
  _out="$("$@" 2>&1)" && say "HARDENING-$_name=ok $_out" \
    || say "HARDENING-$_name=refused $_out"
}
say "HARDENING-GUEST-START"
grep -E ' /(var|home) ' /proc/mounts | while read -r _l; do
  say "HARDENING-MOUNT $_l"
done
# A binary left on the persistent state volumes. Each copy keeps the
# name `busybox`: BusyBox picks the applet from argv[0], so a copy under
# any other name would fail with "applet not found" even where the kernel
# let it run, and the control below could not tell the two apart.
mkdir -p /var/planted /home/planted
cp /bin/busybox /var/planted/busybox && chmod 4755 /var/planted/busybox
cp /bin/busybox /home/planted/busybox && chmod 755 /home/planted/busybox
probe VAR-EXEC /var/planted/busybox echo planted-binary-ran
probe HOME-EXEC /home/planted/busybox echo planted-binary-ran
# A device node for kernel memory left on a state volume.
mknod /var/planted-mem c 1 1
probe VAR-DEVNODE dd if=/var/planted-mem of=/dev/null bs=1 count=1
# Kernel memory through the real node.
probe DEV-MEM dd if=/dev/mem of=/dev/null bs=1 count=1
# Code into the running kernel.
probe INSMOD insmod /usr/share/probe.ko
probe MODULES-REENABLE sh -c 'echo 0 > /proc/sys/kernel/modules_disabled'
say "HARDENING-MODULES-DISABLED=$(cat /proc/sys/kernel/modules_disabled 2>&1)"
if [ -e /proc/sys/kernel/kexec_load_disabled ]; then
  say "HARDENING-KEXEC=$(cat /proc/sys/kernel/kexec_load_disabled)"
else
  say "HARDENING-KEXEC=absent"
fi
[ -e /sys/kernel/security/lockdown ] || \
  mount -t securityfs none /sys/kernel/security 2>/dev/null
say "HARDENING-LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>&1)"
# Controls: the probe CAN observe a binary running.
probe ROOT-EXEC /bin/busybox echo root-binary-ran
mount -t tmpfs -o exec none /attacker-tmpfs && \
  cp /bin/busybox /attacker-tmpfs/busybox && \
  chmod 755 /attacker-tmpfs/busybox
probe TMPFS-EXEC /attacker-tmpfs/busybox echo planted-binary-ran
say "HARDENING-GUEST-DONE"
poweroff -f
""")
  setFilePermissions(dir / "sbin" / "init", {fpUserRead, fpUserWrite,
    fpUserExec, fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  writeRootPolicyFixture(dir)

proc firstModuleFile(moduleTree, release: string): string =
  ## Any loadable module the guest kernel ships, or "".
  ## Walked through its real path: ``walkDirRec`` does not descend
  ## through a symlinked root.
  let root = expandFilename(moduleTree / "modules" / release)
  if not dirExists(root): return ""
  for path in walkDirRec(root):
    if path.endsWith(".ko"):
      return path
  ""

proc hardeningLine(t, probe: string): string =
  ## The line the guest printed for one probe, or "" when it printed none.
  let marker = "HARDENING-" & probe & "="
  for line in t.splitLines():
    let at = line.find(marker)
    if at >= 0:
      return line[at + marker.len .. ^1].strip()
  ""

block layerAttestedHardening:
  let layer = optInLayer(HardeningGateEnv)
  if layer.isBlocked:
    fail(blockedNote(HardeningGateEnv,
      "bash tests/test-verity-root.sh, with " & HardeningGateEnv & "=1"))
  elif layer == lrNotRequested:
    skip("the attested-hardening layer did not run: NO guest was booted " &
         "with the attested command line, and nothing here is evidence " &
         "about what root can do on a running attested root. " &
         notRequestedNote(HardeningGateEnv) & " It takes ~1 min and needs " &
         "qemu-system-x86_64, mkfs.ext4, the ReproOS kernel with its " &
         "module tree (REPROOS_VERITY_GUEST_KERNEL / _MODULES / _RELEASE " &
         "or the source-built kernel), a static BusyBox and a veritysetup " &
         "to stage.")
  else:
    let gate = "attested-hardening layer"
    let (artifacts, why) = discoverGuestArtifacts()
    if why.len > 0:
      fail(gate & ": " & why & ". This layer was asked for, so a missing " &
           "artifact is a failure, not a skip.")
    else:
      let qemu = requireTool(gate, "qemu-system-x86_64")
      discard requireTool(gate, "mkfs.ext4")
      if qemu.len > 0:
        let work = getTempDir() / "reproos-attested-hardening-" &
          $getCurrentProcessId()
        removeDir(work)
        createDir(work)
        let initramfs = work / "initramfs.img"
        let tree = work / "tree"
        let outDir = work / "verity"
        let moduleFile = firstModuleFile(artifacts.moduleTree,
                                         artifacts.release)
        echo "[info] module the guest tries to load: ",
          (if moduleFile.len > 0: moduleFile else: "<none; a non-module>")
        writeHardeningRootTree(tree, artifacts.busybox, moduleFile)
        var varImage = work / "var.img"
        var homeImage = work / "home.img"
        var ready = buildGuestInitramfs(work, artifacts, initramfs)
        if not ready:
          fail(gate & ": build-initramfs.sh could not build an init-disk " &
               "initramfs that can activate verity")
        elif runVerityRootBuilder(tree, outDir) != 0:
          fail(gate & ": build-verity-root.sh failed for the attacker root")
          ready = false
        else:
          for img in [varImage, homeImage]:
            let mk = execCmdEx("mkfs.ext4 -q -F -b 4096 -O ^has_journal " &
                               quoteShell(img) & " 16M")
            if mk.exitCode != 0:
              stderr.writeLine(mk.output)
              fail(gate & ": could not create state volume " & img)
              ready = false
        if ready:
          let rootHash = readFile(outDir / VerityRootHashFileName).strip()
          # The command line an attested UKI carries, composed by the
          # function the UKI builder uses -- only the console is added,
          # because the assertions are read off the serial port.
          let cmdline = "console=ttyS0 panic=1 " &
            attestedKernelCmdline(rootHash, "/dev/vda", "/dev/vdb",
                                  "/dev/vdc", "/dev/vdd",
                                  extra = ["loglevel=6"])
          check(validateAttestedCmdline(cmdline, rootHash).len == 0,
                "the guest boots a command line the UKI builder would " &
                "accept for an attested image")
          let log = work / "serial-hardening.log"
          if runGuest(qemu, artifacts.kernel, initramfs, cmdline,
                      [(outDir / VerityDataImageFileName, true),
                       (outDir / VerityHashTreeFileName, true),
                       (varImage, false), (homeImage, false)],
                      log, "hardening", 180):
            let t = transcript(log)
            if "HARDENING-GUEST-START" notin t:
              stderr.writeLine(t)
              fail("t_attested_root_refuses_persistence: the attacker's " &
                   "/sbin/init never ran" &
                   (if "asks for lockdown=" in t:
                      " -- init-disk refused the root because the kernel " &
                      "did not honour lockdown=integrity. This kernel is " &
                      "not built with the lockdown LSM; boot the ReproOS " &
                      "kernel (REPROOS_VERITY_GUEST_KERNEL)."
                    else: ""))
            else:
              for line in t.splitLines():
                if "HARDENING-" in line: echo "[guest] ", line.strip()
              for volume in [" /var ", " /home "]:
                var mountOpts = ""
                for line in t.splitLines():
                  if "HARDENING-MOUNT " in line and volume in line:
                    mountOpts = line
                check("nosuid" in mountOpts and "nodev" in mountOpts and
                      "noexec" in mountOpts,
                      "t_attested_root_refuses_persistence:" & volume &
                      "is mounted nosuid,nodev,noexec (" & mountOpts.strip() &
                      ")")
              for (probe, what) in [("VAR-EXEC", "/var"),
                                    ("HOME-EXEC", "/home")]:
                let r = hardeningLine(t, probe)
                check(r.startsWith("refused") and
                      "Permission denied" in r,
                      "t_attested_root_refuses_persistence: a binary " &
                      "root planted on " & what & " does not run (" & r & ")")
              let dn = hardeningLine(t, "VAR-DEVNODE")
              check(dn.startsWith("refused") and "Permission denied" in dn,
                    "t_attested_root_refuses_persistence: a kernel-memory " &
                    "device node planted on /var cannot be opened (" & dn &
                    ")")
              let mem = hardeningLine(t, "DEV-MEM")
              check(mem.startsWith("refused") and
                    "Operation not permitted" in mem,
                    "t_attested_kernel_is_locked_down: root cannot open " &
                    "/dev/mem (" & mem & ")")
              check("[integrity]" in hardeningLine(t, "LOCKDOWN"),
                    "t_attested_kernel_is_locked_down: the kernel reports " &
                    "lockdown at integrity (" &
                    hardeningLine(t, "LOCKDOWN") & ")")
              let ins = hardeningLine(t, "INSMOD")
              check(ins.startsWith("refused") and
                    "Operation not permitted" in ins,
                    "t_attested_kernel_is_locked_down: root cannot load a " &
                    "kernel module after the initramfs (" & ins & ")")
              check(hardeningLine(t, "MODULES-REENABLE").startsWith(
                      "refused") and
                    hardeningLine(t, "MODULES-DISABLED") == "1",
                    "t_attested_kernel_is_locked_down: and cannot switch " &
                    "module loading back on")
              let kx = hardeningLine(t, "KEXEC")
              check(kx == "absent" or kx == "1",
                    "t_attested_kernel_is_locked_down: kexec is absent " &
                    "from the kernel or closed (" & kx & ")")
              check(hardeningLine(t, "ROOT-EXEC").startsWith(
                      "ok root-binary-ran"),
                    "control: the same binary runs from the verity root")
              check(hardeningLine(t, "TMPFS-EXEC").startsWith(
                      "ok planted-binary-ran"),
                    "control: the same binary runs from a tmpfs root " &
                    "mounts itself, so a refusal above is the state " &
                    "volumes' mount options and not the probe (and root on " &
                    "a RUNNING machine can still mount something " &
                    "executable -- the specified limit)")
          else:
            stderr.writeLine(transcript(log))
        echo "[info] hardening guest work dir: ", work
        if getEnv("REPROOS_VERITY_GUEST_KEEP") == "1":
          echo "[info] kept (REPROOS_VERITY_GUEST_KEEP=1): ", work
        else:
          removeDir(work)

if failures > 0:
  stderr.writeLine("test_verity_root: " & $failures & " check(s) failed, " &
                   $passes & " passed, " & $skips & " skipped")
  quit(1)
var veritySummary = "verity read-only root: PASS (" & $passes & " checks"
if layerSummaryFragment().len > 0:
  veritySummary.add ", " & layerSummaryFragment()
veritySummary.add ")"
echo veritySummary
