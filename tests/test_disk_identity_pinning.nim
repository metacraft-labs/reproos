## Gate: every filesystem and partition-table identifier the image build
## creates is a function of the build's inputs, not of the clock.
##
## ## What was wrong, and what this gate holds shut
##
## `repro disk apply` is what creates the filesystems in a ReproOS image.
## Left to themselves, the tools it drives invent their identifiers:
##
##   * `mkfs.ext4` takes the filesystem UUID **and** the directory-hash
##     seed — two separate values — from `time(0)` plus `/dev/urandom`.
##   * `mkswap` takes the swap UUID the same way, and does not honour
##     `SOURCE_DATE_EPOCH`.
##   * `mkfs.vfat` derives the FAT volume serial from the wall clock.
##   * `sgdisk` draws the GPT disk GUID and every partition GUID from the
##     system RNG.
##
## So two builds of identical inputs produced different bytes, and no
## claim about an image's hash could mean anything. The layout documents
## the image applies carry no identifiers, on purpose (they are installed
## on every machine built from the image, and machines must not share
## filesystem UUIDs); the seed rides in a sibling identity document that
## `repro disk apply` finds by convention.
##
## ## The layers, and what each is worth
##
##   1. **The apply pins every identifier** (always on, ~1s). The real
##      `applyDiskLayout` is driven over the real shipped presets with the
##      real derived seed, twice, the second time under a deliberately
##      different caller environment. Every identifier-bearing operation
##      must carry its pinned value, the two runs must agree operation for
##      operation, and no two nodes may be handed the same identifier.
##
##      This PROVES the arguments reach the tools and are a function of
##      the inputs. It does NOT prove a tool honours an argument.
##
##   2. **Nothing is pinned by accident** (always on, ~1s). The negative
##      layer. Each identifier is removed from a copy of the operation
##      list in turn, and each removal must turn layer 1 red *naming the
##      node and the identifier that lost its pin*. A seed made
##      time-varying must likewise redden the two-run comparison, naming
##      the first operation that drifted. Without this, layer 1 would
##      pass unchanged on a tree where nothing was pinned at all.
##
##   3. **The real tools honour the arguments** (opt-in, ~10s). The
##      derived argv is executed for real against file-backed images,
##      twice, and the results compared byte for byte; the pinned value is
##      then read back out of the documented on-disk offset. The same
##      argv with the identifiers stripped must produce two images that
##      differ, so the comparison is not vacuous.
##
##      Opt-in because it needs `mkfs.ext4`, `mkfs.vfat`, `mkswap` and
##      `sgdisk`, and those are from-source packages here: declaring them
##      as tool identities would make an always-on gate build four source
##      packages before it could run. When it is asked for and a tool is
##      missing, it FAILS — it does not skip.
##
## ## Mocking
##
## None. Layer 1 drives Reprobuild's real `applyDiskLayout` over the
## presets `repro/disk_layouts.nim` actually ships, with the seed the
## image recipe actually derives. Layer 3 runs the real `mkfs` binaries
## and reads the bytes back off disk. `REPRO_DISK_DRY_RUN=1` in layers 1
## and 2 is not a mock of the tools: it is the apply driver's own
## argv-capture mode, and layer 3 exists precisely because capturing argv
## is not the same as running it.

import std/[monotimes, os, osproc, strutils, tables, times]

import repro_profile/types
import repro_profile/disk_tools
import repro_profile/disk_identity
import repro_profile/disk_apply

import "../repro/disk_layouts"
import "../repro/package_sets"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  AutoConfigFixture = "tests/fixtures/auto-config-minimal.toml"

  RealToolsEnv = "REPROOS_DISK_IDENTITY_FILESYSTEM_GATE"
    ## The opt-in for layer 3. Set it to ``1`` to authorise real
    ## `mkfs`/`sgdisk` runs against file-backed images in a temp tree.

  IdentifierTools = ["sgdisk", "mkfs.ext4", "mkfs.vfat", "mkswap",
                     "mkfs.btrfs", "mkfs.xfs"]
    ## Every tool the apply driver runs that writes an identifier. An
    ## operation from one of these that carries no pinned value is the
    ## defect this gate exists for.

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

# ---------------------------------------------------------------------------
# Driving the real apply driver.
# ---------------------------------------------------------------------------

proc paramsFor(preset: DiskLayoutPreset): DiskLayoutParams =
  ## The parameters the image recipe would resolve for this preset out of
  ## the shipped fixture, floored at the preset's own minimum so that a
  ## preset needing a bigger disk than the fixture declares is still
  ## exercised rather than silently skipped.
  let configText = readFile(RepoRoot / AutoConfigFixture)
  var request = parseDiskLayoutRequest(configText, "reproos-image",
                                       "/dev/nbd0")
  request.name = preset.name
  if request.params.diskSizeGb < preset.minDiskSizeGb:
    request.params.diskSizeGb = preset.minDiskSizeGb
  request.params

proc requestFor(preset: DiskLayoutPreset): DiskLayoutRequest =
  DiskLayoutRequest(name: preset.name, params: paramsFor(preset))

proc identityFor(preset: DiskLayoutPreset): DiskIdentity =
  ## The identity the image recipe hands the driver: the seed derived
  ## from the auto-config, the source-package closure and the layout.
  ## Read back out of the rendered identity document rather than
  ## computed directly, so this gate exercises the bytes that actually
  ## travel to `repro disk apply`.
  let document = renderDiskIdentityJson(
    readFile(RepoRoot / AutoConfigFixture),
    ReproosGraphicalRootfsPackages, requestFor(preset))
  parseDiskIdentityDocument(document, "<rendered by the image recipe>")

proc capturedOperations(preset: DiskLayoutPreset;
                        identity: DiskIdentity): seq[ExecResult] =
  ## The operations `repro disk apply` would run for this preset. The
  ## apply driver's own dry-run mode builds the real argv without
  ## spawning anything, which is what makes this layer cost a second.
  putEnv("REPRO_DISK_DRY_RUN", "1")
  let layout = buildDiskLayout(preset.name, paramsFor(preset))
  let outcome = applyDiskLayout(layout, initTable[string, string](),
                                identity)
  if outcome.failure:
    fail("the apply driver failed for preset " & preset.name & ": " &
         outcome.failureMsg)
  outcome.operations

# ---------------------------------------------------------------------------
# What must be pinned, stated independently of the code that pins it.
#
# The expectations below are built from the LAYOUT, so this gate says
# what has to be true rather than reading back what disk_apply chose to
# do. That independence is what makes the negative layer able to name the
# node and the identifier that lost its pin.
# ---------------------------------------------------------------------------

type
  Expectation = object
    node: string        ## "main", "main.root" — what is being identified
    identifier: string  ## human name of the identifier
    tool: string        ## the tool whose argv must carry it
    device: string      ## the device that operation targets
    flag: string        ## the argv token introducing the value
    value: string       ## the exact value that must follow it

proc partitionDeviceFor(disk: DiskSpec; index: int): string =
  partitionDevicePath(disk.device, index)

proc filesystemExpectations(node, device: string; c: ContentSpec;
                            identity: DiskIdentity): seq[Expectation] =
  let uuid = identity.deriveUuid(filesystemUuidPurpose(node))
  case c.kind
  of cfsSwap:
    @[Expectation(node: node, identifier: "swap UUID", tool: "mkswap",
                  device: device, flag: "-U", value: uuid)]
  of cfsFilesystem:
    case c.format
    of "ext4":
      @[
        Expectation(node: node, identifier: "ext4 filesystem UUID",
                    tool: "mkfs.ext4", device: device, flag: "-U",
                    value: uuid),
        Expectation(node: node, identifier: "ext4 directory-hash seed",
                    tool: "mkfs.ext4", device: device, flag: "-E",
                    value: "hash_seed=" &
                      identity.deriveUuid(filesystemHashSeedPurpose(node))),
      ]
    of "vfat", "fat32":
      @[Expectation(node: node, identifier: "FAT volume serial",
                    tool: "mkfs.vfat", device: device, flag: "-i",
                    value: identity.deriveVolumeId(
                      filesystemVolumeIdPurpose(node)))]
    of "swap":
      @[Expectation(node: node, identifier: "swap UUID", tool: "mkswap",
                    device: device, flag: "-U", value: uuid)]
    of "btrfs":
      @[Expectation(node: node, identifier: "btrfs filesystem UUID",
                    tool: "mkfs.btrfs", device: device, flag: "-U",
                    value: uuid)]
    of "xfs":
      @[Expectation(node: node, identifier: "xfs filesystem UUID",
                    tool: "mkfs.xfs", device: device, flag: "-m",
                    value: "uuid=" & uuid)]
    else:
      fail("no identifier expectation is declared for filesystem format " &
           c.format & " at " & node & "; a format this gate does not know " &
           "about would be pinned by nothing and reported by nothing")
      @[]
  of cfsNone:
    # A carrier. The apply creates the partition and puts NOTHING on it,
    # because what goes there is a finished image the build produced --
    # an integrity-checked root and the Merkle tree over it, whose own
    # identifiers are inside bytes the root hash already covers. There is
    # no filesystem here to identify and no tool that could pin one, so
    # an empty list is the correct answer rather than a gap.
    #
    # The partition itself is NOT unpinned: `expectationsFor` adds a GPT
    # partition GUID expectation for every partition before it calls
    # this, whatever its content kind, and on this layout that GUID is
    # load-bearing -- it is what the measured kernel command line names
    # the carrier by.
    @[]
  else:
    # No ReproOS preset declares LUKS, LVM or ZFS content. If one starts
    # to, this gate has to learn what its identifiers are before it can
    # claim to cover the layout.
    fail("no identifier expectation is declared for content kind " &
         $c.kind & " at " & node)
    @[]

proc expectationsFor(layout: DiskLayout;
                     identity: DiskIdentity): seq[Expectation] =
  result = @[]
  for diskName, disk in layout.disks:
    if disk.`type`.len == 0 or disk.`type` == "gpt":
      result.add Expectation(node: diskName, identifier: "GPT disk GUID",
        tool: "sgdisk", device: disk.device, flag: "-U",
        value: identity.deriveUuid(diskGuidPurpose(diskName)))
    var num = 1
    for partName, part in disk.partitions:
      result.add Expectation(node: diskName & "/" & partName,
        identifier: "GPT partition GUID", tool: "sgdisk",
        device: disk.device, flag: "-u",
        value: $num & ":" & identity.deriveUuid(
          partitionGuidPurpose(diskName, partName)))
      result.add filesystemExpectations(diskName & "." & partName,
        partitionDeviceFor(disk, num), part.content, identity)
      num.inc

proc carries(op: ExecResult; flag, value: string): bool =
  for i in 0 ..< op.argv.len - 1:
    if op.argv[i] == flag and op.argv[i + 1] == value:
      return true
  false

proc unpinnedIdentifiers(ops: seq[ExecResult];
                         expectations: seq[Expectation]): seq[string] =
  ## One entry per identifier that is not pinned to its derived value.
  ## The node and the identifier lead, because "which filesystem, and
  ## which of its identifiers" is what an operator has to go and look at.
  result = @[]
  for want in expectations:
    if want.value.len == 0 or want.value.endsWith("="):
      result.add want.node & ": the " & want.identifier &
        " has no derived value; the seed did not reach it"
      continue
    var sawTool = false
    var found = false
    for op in ops:
      if op.tool != want.tool: continue
      if op.argv.len == 0 or op.argv[^1] != want.device: continue
      sawTool = true
      if op.carries(want.flag, want.value):
        found = true
        break
    if not sawTool:
      result.add want.node & ": no " & want.tool & " operation targets " &
        want.device & ", so its " & want.identifier & " is written by " &
        "nothing this gate can see"
    elif not found:
      result.add want.node & ": the " & want.identifier &
        " is not pinned — no " & want.tool & " operation on " &
        want.device & " carries " & want.flag & " " & want.value &
        "; it will be taken from the clock or the system RNG"

  # And the other direction: an operation that writes an identifier but
  # that no expectation covers would be silently unpinned.
  for op in ops:
    if op.tool notin IdentifierTools: continue
    if op.argv.len == 0: continue
    var covered = false
    for want in expectations:
      if want.tool == op.tool and op.argv[^1] == want.device:
        covered = true
        break
    if not covered:
      result.add "an operation writes an identifier that nothing in " &
        "this gate expects: " & op.cmd

proc duplicateIdentifiers(expectations: seq[Expectation]): seq[string] =
  ## Two nodes handed the same identifier would be a derivation that had
  ## stopped depending on which node it was deriving for — deterministic
  ## and useless.
  var seen = initTable[string, string]()
  result = @[]
  for want in expectations:
    if want.value.len == 0: continue
    if seen.hasKey(want.value):
      result.add "the same value " & want.value & " is used for both " &
        seen[want.value] & " and " & want.node & "/" & want.identifier
    else:
      seen[want.value] = want.node & "/" & want.identifier

# ---------------------------------------------------------------------------
# Comparing two runs.
# ---------------------------------------------------------------------------

type
  OperationDifference = object
    index: int
    a, b: string

proc firstDifferingOperation(a, b: seq[ExecResult]): OperationDifference =
  ## The EARLIEST operation whose argv differs. Order matters: the apply
  ## driver runs these in sequence, so the first difference is the first
  ## place the two runs diverged and everything after it is a
  ## consequence.
  result = OperationDifference(index: -1)
  let shared = min(a.len, b.len)
  for i in 0 ..< shared:
    if a[i].cmd != b[i].cmd:
      return OperationDifference(index: i, a: a[i].cmd, b: b[i].cmd)
  if a.len != b.len:
    return OperationDifference(index: shared,
      a: (if a.len > shared: a[shared].cmd else: "<no operation>"),
      b: (if b.len > shared: b[shared].cmd else: "<no operation>"))

const HostileEnvironment = [
  ("SOURCE_DATE_EPOCH", "917823600"),
  ("LC_ALL", "en_US.UTF-8"),
  ("LANG", "en_US.UTF-8"),
  ("TZ", "America/Havana"),
]

proc withHostileEnvironment(body: proc ()) =
  var saved: seq[(string, bool, string)] = @[]
  for (name, value) in HostileEnvironment:
    saved.add (name, existsEnv(name), getEnv(name))
    putEnv(name, value)
  try:
    body()
  finally:
    for (name, had, value) in saved:
      if had: putEnv(name, value)
      else: delEnv(name)

# ---------------------------------------------------------------------------
# Case 1 — t_disk_apply_pins_every_filesystem_identifier
# ---------------------------------------------------------------------------

proc caseApplyPinsEveryIdentifier() =
  var checked = 0
  for preset in DiskLayoutPresets:
    let identity = identityFor(preset)
    if not identity.isPinned:
      fail("t_disk_apply_pins_every_filesystem_identifier: the image " &
           "recipe derives no identity seed for preset " & preset.name)
      continue
    let layout = buildDiskLayout(preset.name, paramsFor(preset))
    let expectations = expectationsFor(layout, identity)
    if expectations.len == 0:
      fail("t_disk_apply_pins_every_filesystem_identifier: preset " &
           preset.name & " declares no identifiers at all, so this case " &
           "would pass without checking anything")
      continue

    let first = capturedOperations(preset, identity)
    var second: seq[ExecResult] = @[]
    withHostileEnvironment(proc () =
      second = capturedOperations(preset, identity))

    let violations = unpinnedIdentifiers(first, expectations)
    if violations.len > 0:
      for v in violations:
        fail("t_disk_apply_pins_every_filesystem_identifier: " &
             preset.name & ": " & v)
      continue

    let duplicates = duplicateIdentifiers(expectations)
    if duplicates.len > 0:
      for d in duplicates:
        fail("t_disk_apply_pins_every_filesystem_identifier: " &
             preset.name & ": " & d)
      continue

    let d = firstDifferingOperation(first, second)
    if d.index >= 0:
      fail("t_disk_apply_pins_every_filesystem_identifier: " & preset.name &
           ": the two applies diverge at operation " & $d.index & "\n" &
           "  first run:  " & d.a & "\n" &
           "  second run (different SOURCE_DATE_EPOCH/TZ/LC_ALL/LANG): " &
             d.b & "\n" &
           "  later operations are not compared; the earliest divergence " &
           "is the one to fix")
      continue

    # A different auto-config must move every identifier, or the seed is
    # not a function of the configuration it claims to be a function of.
    let otherSeed = reproosImageIdentitySeed(
      readFile(RepoRoot / AutoConfigFixture) & "\n# one more line\n",
      ReproosGraphicalRootfsPackages, requestFor(preset))
    let otherExpectations = expectationsFor(layout,
      DiskIdentity(seed: otherSeed))
    var moved = 0
    for i in 0 ..< expectations.len:
      if expectations[i].value != otherExpectations[i].value: moved.inc
    if moved != expectations.len:
      fail("t_disk_apply_pins_every_filesystem_identifier: " & preset.name &
           ": only " & $moved & " of " & $expectations.len &
           " identifiers changed when the auto-config changed; the rest " &
           "are not a function of the build's inputs")
      continue

    checked.inc
    pass("t_disk_apply_pins_every_filesystem_identifier: " & preset.name &
         ": all " & $expectations.len & " identifiers (" &
         $first.len & " operations) are derived from the recipe's seed, " &
         "are distinct, re-derive identically under a different caller " &
         "environment, and all move when the auto-config does")

  if checked != DiskLayoutPresets.len:
    fail("t_disk_apply_pins_every_filesystem_identifier: only " & $checked &
         " of " & $DiskLayoutPresets.len & " shipped presets were checked")

# ---------------------------------------------------------------------------
# Case 2 — NEGATIVE: t_an_unpinned_filesystem_identifier_is_reported_red
#
# Each identifier is taken back out, one at a time, and the check above
# must go red naming the node and the identifier that lost its pin. A
# control runs first: the unperturbed operation list must be green, so
# that an injection and not the copying is what reddens.
# ---------------------------------------------------------------------------

proc withoutFlagValue(ops: seq[ExecResult]; tool, device, flag,
                      value: string): (seq[ExecResult], bool) =
  ## A copy of ``ops`` with one ``<flag> <value>`` pair removed from the
  ## matching operation — exactly what a regression that stopped passing
  ## that identifier would look like.
  var out0 = ops
  for i in 0 ..< out0.len:
    if out0[i].tool != tool: continue
    if out0[i].argv.len == 0 or out0[i].argv[^1] != device: continue
    var argv: seq[string] = @[]
    var j = 0
    var removed = false
    while j < out0[i].argv.len:
      if not removed and j + 1 < out0[i].argv.len and
         out0[i].argv[j] == flag and out0[i].argv[j + 1] == value:
        removed = true
        j += 2
        continue
      argv.add out0[i].argv[j]
      j.inc
    if removed:
      out0[i].argv = argv
      out0[i].cmd = renderArgv(argv)
      return (out0, true)
  (out0, false)

proc caseUnpinnedIdentifierIsReportedRed() =
  let preset = DiskLayoutPresets[1]   ## uefi-attested: ESP + ext4 + swap
  let identity = identityFor(preset)
  let layout = buildDiskLayout(preset.name, paramsFor(preset))
  let expectations = expectationsFor(layout, identity)
  let ops = capturedOperations(preset, identity)

  # Control.
  let control = unpinnedIdentifiers(ops, expectations)
  if control.len > 0:
    fail("t_an_unpinned_filesystem_identifier_is_reported_red: the " &
         "UNPERTURBED operation list is not green, so nothing an " &
         "injection proves can be attributed to the injection: " &
         control.join("; "))
    return
  pass("t_an_unpinned_filesystem_identifier_is_reported_red: the " &
       "unperturbed operation list for " & preset.name & " is green, so " &
       "an injection below is the only thing that can redden it")

  var injected = 0
  for want in expectations:
    let (perturbed, removed) = withoutFlagValue(ops, want.tool,
      want.device, want.flag, want.value)
    if not removed:
      fail("t_an_unpinned_filesystem_identifier_is_reported_red: could " &
           "not un-pin " & want.node & "/" & want.identifier &
           "; the argument it removes is not in the operation list, so " &
           "this gate is no longer proving anything about it")
      continue
    let reported = unpinnedIdentifiers(perturbed, expectations)
    if reported.len == 0:
      fail("t_an_unpinned_filesystem_identifier_is_reported_red: " &
           "un-pinning " & want.node & "/" & want.identifier &
           " did NOT redden the check")
      continue
    var named = 0
    for r in reported:
      if r.startsWith(want.node & ":") and want.identifier in r: named.inc
    if named == 0:
      fail("t_an_unpinned_filesystem_identifier_is_reported_red: " &
           "un-pinning " & want.node & "/" & want.identifier &
           " reddened the check, but no violation named it: " &
           reported.join("; "))
      continue
    if reported.len != named:
      fail("t_an_unpinned_filesystem_identifier_is_reported_red: " &
           "un-pinning " & want.node & "/" & want.identifier &
           " reddened identifiers it did not touch: " & reported.join("; "))
      continue
    injected.inc
  if injected == expectations.len:
    pass("t_an_unpinned_filesystem_identifier_is_reported_red: each of " &
         "the " & $expectations.len & " identifiers, removed one at a " &
         "time, turns the check red naming exactly that node and that " &
         "identifier")

  # The whole-mechanism regression: the seed stops reaching the apply.
  # This is what the tree looked like before the identity document
  # existed, and it must be loud rather than merely different.
  let unpinnedOps = capturedOperations(preset, DiskIdentity())
  let unpinnedReport = unpinnedIdentifiers(unpinnedOps, expectations)
  if unpinnedReport.len < expectations.len:
    fail("t_an_unpinned_filesystem_identifier_is_reported_red: an apply " &
         "with no identity at all reported only " & $unpinnedReport.len &
         " of " & $expectations.len & " identifiers as unpinned")
  else:
    pass("t_an_unpinned_filesystem_identifier_is_reported_red: an apply " &
         "that receives no identity document is reported red on all " &
         $expectations.len & " identifiers, naming each node and " &
         "identifier")

  # And the exact regression this gate exists for: an identifier that
  # goes back to being seeded from the clock. Two applies then differ,
  # and the comparison has to name the FIRST operation that drifted
  # rather than merely reporting that the two runs are not the same.
  proc clockSeeded(): DiskIdentity =
    DiskIdentity(seed: "clock:" & $getMonoTime().ticks & ":" &
      formatFloat(epochTime(), ffDecimal, 6))
  let runA = capturedOperations(preset, clockSeeded())
  let runB = capturedOperations(preset, clockSeeded())
  let drift = firstDifferingOperation(runA, runB)
  # The earliest operation that CAN drift: everything before it (umount,
  # wipefs) carries no identifier. Requiring the comparison to name that
  # one is what makes "the first drifting operation" mean *first* rather
  # than "some operation".
  var firstIdentifierOp = -1
  for i, op in runA:
    if op.tool in IdentifierTools:
      firstIdentifierOp = i
      break
  if drift.index < 0:
    fail("t_an_unpinned_filesystem_identifier_is_reported_red: a " &
         "time-varying seed did NOT make the two applies differ, so the " &
         "two-run comparison cannot detect a clock-seeded identifier")
  elif drift.index != firstIdentifierOp:
    fail("t_an_unpinned_filesystem_identifier_is_reported_red: a " &
         "time-varying seed made the applies differ first at operation " &
         $drift.index & " rather than at the first identifier-bearing " &
         "one (" & $firstIdentifierOp & "); the comparison names a " &
         "consequence rather than a cause")
  else:
    pass("t_an_unpinned_filesystem_identifier_is_reported_red: a seed " &
         "taken from the clock makes two applies differ and the " &
         "comparison names the first drifting operation:\n" &
         "         " & drift.a & "\n      vs " & drift.b)

# ---------------------------------------------------------------------------
# Case 3 — opt-in: the real tools honour the arguments.
# ---------------------------------------------------------------------------

const
  ImageBytesForFilesystem = 64 * 1024 * 1024
  ImageBytesForSwap = 16 * 1024 * 1024
  GptProbeBytes = 1024 * 1024
    ## sgdisk writes the primary GPT in the first sectors and the backup
    ## in the last; comparing those two windows compares everything it
    ## wrote without reading a multi-gigabyte sparse file end to end.

  # Offsets of each identifier in the on-disk format. Reading the value
  # back is what distinguishes "we passed the flag" from "the tool
  # honoured it".
  Ext4SuperblockOffset = 1024
  Ext4UuidOffset = Ext4SuperblockOffset + 0x68
  Ext4HashSeedOffset = Ext4SuperblockOffset + 0xEC
  FatVolumeIdOffset = 0x43
  SwapUuidOffset = 1024 + 12

proc createSparseFile(path: string; size: int64) =
  var f = open(path, fmWrite)
  f.setFilePos(size - 1)
  f.write('\0')
  f.close()

proc readBytes(path: string; offset, count: int): string =
  var f = open(path, fmRead)
  defer: f.close()
  f.setFilePos(offset)
  result = newString(count)
  discard f.readBuffer(addr result[0], count)

proc hexOf(s: string): string =
  result = ""
  for c in s:
    result.add toHex(int(uint8(c)), 2).toLowerAscii()

proc uuidBytesHex(uuid: string): string =
  uuid.replace("-", "").toLowerAscii()

proc imageActionEpoch(): string =
  ## The ``SOURCE_DATE_EPOCH`` the image build action pins, read out of
  ## the recipe rather than repeated here. The tool runs below use it
  ## because that is the environment the real apply happens in: an
  ## ext4 superblock carries creation and last-write timestamps that no
  ## mke2fs flag can pin, and — measured — a FAT32 boot sector written
  ## without it is not reproducible either.
  let recipe = readFile(RepoRoot / "recipes/reproos-image/package.nim")
  const needle = "SOURCE_DATE_EPOCH="
  let at = recipe.find(needle)
  if at < 0:
    fail("t_pinned_identifiers_survive_the_real_tools: the image recipe " &
         "no longer pins SOURCE_DATE_EPOCH; the filesystem timestamps " &
         "are then a function of when the build ran")
    return ""
  var i = at + needle.len
  result = ""
  while i < recipe.len and recipe[i] in {'0' .. '9'}:
    result.add recipe[i]
    i.inc

proc runTool(argv: seq[string]; epoch: string): (string, int) =
  ## Run one captured operation for real, in the environment the image
  ## build gives it. ``epoch`` empty deliberately unsets the variable —
  ## that is how the control runs below show it is load-bearing.
  let hadEpoch = existsEnv("SOURCE_DATE_EPOCH")
  let savedEpoch = getEnv("SOURCE_DATE_EPOCH")
  if epoch.len > 0: putEnv("SOURCE_DATE_EPOCH", epoch)
  else: delEnv("SOURCE_DATE_EPOCH")
  try:
    result = execCmdEx(renderArgv(argv))
  finally:
    if hadEpoch: putEnv("SOURCE_DATE_EPOCH", savedEpoch)
    else: delEnv("SOURCE_DATE_EPOCH")

proc digestOfWindows(path: string; size: int64): string =
  ## The first and last window of a possibly-huge sparse image: sgdisk
  ## writes the primary GPT at the start and the backup at the end, and
  ## reading a multi-gigabyte hole between them would prove nothing and
  ## cost minutes.
  hexOf(readBytes(path, 0, GptProbeBytes)) & ":" &
    hexOf(readBytes(path, int(size) - GptProbeBytes, GptProbeBytes))

proc caseRealToolsHonourTheArguments(workRoot: string) =
  if getEnv(RealToolsEnv) != "1":
    skip("t_pinned_identifiers_survive_the_real_tools: not requested (" &
         RealToolsEnv & " is not 1). NO REAL FILESYSTEM WAS CREATED and " &
         "no on-disk identifier was read back; the layers above compared " &
         "argv only.\n" &
         "  To run it: re-run this gate with " & RealToolsEnv & "=1 on a " &
         "PATH carrying mkfs.ext4, mkfs.vfat, mkswap and sgdisk. It " &
         "creates file-backed images under a temp tree, runs the derived " &
         "argv against them twice, compares the bytes and reads each " &
         "pinned value back out of the on-disk format. It is not on by " &
         "default because those four tools are from-source packages " &
         "here, and declaring them would make this gate build four " &
         "source packages before it could run.")
    return

  var missing: seq[string] = @[]
  for tool in ["mkfs.ext4", "mkfs.vfat", "mkswap", "sgdisk"]:
    if findExe(tool).len == 0: missing.add tool
  if missing.len > 0:
    fail("t_pinned_identifiers_survive_the_real_tools: requested, but " &
         "these tools are not on PATH: " & missing.join(", ") &
         ". Asked for and unable to run is a failure, not a skip.")
    return

  let preset = DiskLayoutPresets[1]   ## the one with all four formats
  let identity = identityFor(preset)
  let layout = buildDiskLayout(preset.name, paramsFor(preset))
  let expectations = expectationsFor(layout, identity)
  let ops = capturedOperations(preset, identity)
  let diskSize = int64(paramsFor(preset).diskSizeGb) * 1024 * 1024 * 1024
  let epoch = imageActionEpoch()
  if epoch.len == 0: return

  removeDir(workRoot)
  createDir(workRoot)

  # ---- The partition table.
  var gptDigests: seq[string] = @[]
  for run in 0 ..< 2:
    let image = workRoot / ("disk-" & $run & ".img")
    createSparseFile(image, diskSize)
    for op in ops:
      if op.tool != "sgdisk": continue
      var argv = op.argv
      argv[^1] = image
      let (output, code) = runTool(argv, epoch)
      if code != 0:
        fail("t_pinned_identifiers_survive_the_real_tools: " &
             renderArgv(argv) & " exited " & $code & ": " & output)
        return
    gptDigests.add digestOfWindows(image, diskSize)
    if run == 0: sleep(1100)
  if gptDigests[0] != gptDigests[1]:
    fail("t_pinned_identifiers_survive_the_real_tools: two runs of the " &
         "same sgdisk argv, a second apart, produced different partition " &
         "tables; the GPT disk GUID or a partition GUID is still random")
    return

  # And the control: the same argv with the GUIDs removed must NOT be
  # reproducible, or the comparison above is proving nothing.
  var unpinnedDigests: seq[string] = @[]
  for run in 0 ..< 2:
    let image = workRoot / ("disk-unpinned-" & $run & ".img")
    createSparseFile(image, diskSize)
    for op in ops:
      if op.tool != "sgdisk": continue
      var argv: seq[string] = @[]
      var j = 0
      while j < op.argv.len:
        if op.argv[j] in ["-U", "-u"] and j + 1 < op.argv.len:
          j += 2
          continue
        argv.add op.argv[j]
        j.inc
      argv[^1] = image
      let (output, code) = runTool(argv, epoch)
      if code != 0:
        fail("t_pinned_identifiers_survive_the_real_tools: control run " &
             renderArgv(argv) & " exited " & $code & ": " & output)
        return
    unpinnedDigests.add digestOfWindows(image, diskSize)
  if unpinnedDigests[0] == unpinnedDigests[1]:
    fail("t_pinned_identifiers_survive_the_real_tools: sgdisk WITHOUT " &
         "the pinned GUIDs produced two identical partition tables, so " &
         "the comparison above cannot tell a pinned table from an " &
         "unpinned one")
    return
  pass("t_pinned_identifiers_survive_the_real_tools: sgdisk writes a " &
       "byte-identical GPT twice with the derived GUIDs, and two " &
       "different ones without them")

  # ---- The filesystems.
  var checkedFilesystems = 0
  for op in ops:
    if op.tool == "sgdisk": continue
    if op.tool notin IdentifierTools: continue
    let bytes =
      if op.tool == "mkswap": ImageBytesForSwap else: ImageBytesForFilesystem
    var digests: seq[string] = @[]
    var images: seq[string] = @[]
    for run in 0 ..< 2:
      let image = workRoot / (op.tool & "-" & $checkedFilesystems & "-" &
                              $run & ".img")
      createSparseFile(image, bytes)
      var argv = op.argv
      argv[^1] = image
      let (output, code) = runTool(argv, epoch)
      if code != 0:
        fail("t_pinned_identifiers_survive_the_real_tools: " &
             renderArgv(argv) & " exited " & $code & ": " & output)
        return
      digests.add hexOf(readFile(image))
      images.add image
      if run == 0: sleep(1100)
    if digests[0] != digests[1]:
      fail("t_pinned_identifiers_survive_the_real_tools: two runs of " &
           op.cmd & ", a second apart, produced different bytes")
      return

    # Read the pinned value back out of the on-disk format. This is the
    # difference between "the flag was passed" and "the tool used it".
    var want = ""
    var got = ""
    var which = ""
    case op.tool
    of "mkfs.ext4":
      for e in expectations:
        if e.tool == "mkfs.ext4" and e.device == op.argv[^1]:
          if e.flag == "-U":
            want = uuidBytesHex(e.value)
            got = hexOf(readBytes(images[0], Ext4UuidOffset, 16))
            which = e.node & " ext4 UUID"
            if want != got:
              fail("t_pinned_identifiers_survive_the_real_tools: " & which &
                   " on disk is " & got & ", not the derived " & want)
              return
          else:
            want = uuidBytesHex(e.value.replace("hash_seed=", ""))
            got = hexOf(readBytes(images[0], Ext4HashSeedOffset, 16))
            which = e.node & " ext4 directory-hash seed"
            if want != got:
              fail("t_pinned_identifiers_survive_the_real_tools: " & which &
                   " on disk is " & got & ", not the derived " & want)
              return
    of "mkfs.vfat":
      for e in expectations:
        if e.tool == "mkfs.vfat" and e.device == op.argv[^1]:
          # The FAT volume serial is stored little-endian.
          let raw = readBytes(images[0], FatVolumeIdOffset, 4)
          var reversed = ""
          for i in countdown(3, 0): reversed.add raw[i]
          want = e.value.toLowerAscii()
          got = hexOf(reversed)
          if want != got:
            fail("t_pinned_identifiers_survive_the_real_tools: " & e.node &
                 " FAT volume serial on disk is " & got &
                 ", not the derived " & want)
            return
    of "mkswap":
      for e in expectations:
        if e.tool == "mkswap" and e.device == op.argv[^1]:
          want = uuidBytesHex(e.value)
          got = hexOf(readBytes(images[0], SwapUuidOffset, 16))
          if want != got:
            fail("t_pinned_identifiers_survive_the_real_tools: " & e.node &
                 " swap UUID on disk is " & got & ", not the derived " &
                 want)
            return
    else: discard
    checkedFilesystems.inc

  if checkedFilesystems == 0:
    fail("t_pinned_identifiers_survive_the_real_tools: no filesystem was " &
         "created, so nothing was proved")
    return

  # Control: without the identifiers, two runs a second apart must
  # differ, or "byte-identical" above means nothing.
  var reproducibleWithoutPinning = 0
  for op in ops:
    if op.tool notin ["mkfs.ext4", "mkswap"]: continue
    let bytes =
      if op.tool == "mkswap": ImageBytesForSwap else: ImageBytesForFilesystem
    var digests: seq[string] = @[]
    for run in 0 ..< 2:
      let image = workRoot / ("control-" & op.tool & "-" & $run & ".img")
      createSparseFile(image, bytes)
      var argv: seq[string] = @[]
      var j = 0
      while j < op.argv.len:
        if op.argv[j] in ["-U", "-i", "-E"] and j + 1 < op.argv.len:
          j += 2
          continue
        argv.add op.argv[j]
        j.inc
      argv[^1] = image
      let (output, code) = runTool(argv, epoch)
      if code != 0:
        fail("t_pinned_identifiers_survive_the_real_tools: control run " &
             renderArgv(argv) & " exited " & $code & ": " & output)
        return
      digests.add hexOf(readFile(image))
      if run == 0: sleep(1100)
    if digests[0] == digests[1]:
      reproducibleWithoutPinning.inc
  if reproducibleWithoutPinning > 0:
    fail("t_pinned_identifiers_survive_the_real_tools: " &
         $reproducibleWithoutPinning & " filesystem(s) came out " &
         "byte-identical WITHOUT the pinned identifiers, so this gate " &
         "cannot tell a pinned filesystem from an unpinned one")
    return

  # Second control: the identifiers alone are not enough. The ext4
  # superblock's creation and last-write times, and — measured — the
  # FAT32 boot sector, still move unless SOURCE_DATE_EPOCH is pinned,
  # and no mkfs flag covers that. Run the fully-pinned argv again with
  # the epoch UNSET and require the result to differ, so this gate can
  # never come out green on a host that merely happened to export one.
  var epochDependent: seq[string] = @[]
  for op in ops:
    if op.tool notin ["mkfs.ext4", "mkfs.vfat"]: continue
    var digests: seq[string] = @[]
    for run in 0 ..< 2:
      let image = workRoot / ("no-epoch-" & op.tool & "-" & $run & ".img")
      createSparseFile(image, ImageBytesForFilesystem)
      var argv = op.argv
      argv[^1] = image
      let (output, code) = runTool(argv, "")
      if code != 0:
        fail("t_pinned_identifiers_survive_the_real_tools: epoch control " &
             renderArgv(argv) & " exited " & $code & ": " & output)
        return
      digests.add hexOf(readFile(image))
      # Long enough to cross a FAT directory-entry timestamp bucket,
      # which has two-second granularity; a shorter gap makes this
      # control report "reproducible" for the wrong reason.
      if run == 0: sleep(2500)
    if digests[0] != digests[1] and op.tool notin epochDependent:
      epochDependent.add op.tool
  if epochDependent.len == 0:
    fail("t_pinned_identifiers_survive_the_real_tools: with " &
         "SOURCE_DATE_EPOCH unset, every filesystem still came out " &
         "byte-identical — so the epoch this gate runs the tools under " &
         "is doing nothing, and the byte comparison above is not the " &
         "evidence it claims to be")
    return
  pass("t_pinned_identifiers_survive_the_real_tools: the identifiers are " &
       "necessary but not sufficient — with SOURCE_DATE_EPOCH unset, " &
       epochDependent.join(" and ") & " write different bytes on two " &
       "runs even with every identifier pinned, which is why the apply " &
       "happens under the epoch the image action pins (" & epoch & ")")

  pass("t_pinned_identifiers_survive_the_real_tools: " &
       $checkedFilesystems & " real filesystems created twice from the " &
       "derived argv are byte-identical and carry the derived identifier " &
       "at its documented on-disk offset; the same argv without the " &
       "identifiers is not reproducible")

# ---------------------------------------------------------------------------

let workRoot = RepoRoot / "build" / "test-disk-identity-pinning" / "work"

caseApplyPinsEveryIdentifier()
caseUnpinnedIdentifierIsReportedRed()
caseRealToolsHonourTheArguments(workRoot)

delEnv("REPRO_DISK_DRY_RUN")

if failures > 0:
  stderr.writeLine("test_disk_identity_pinning: " & $failures &
                   " check(s) failed")
  quit(1)

var summary = "disk identity pinning: PASS (" & $passes & " checks"
if skips > 0:
  summary.add ", " & $skips & " SKIPPED -- no real filesystem was created"
summary.add ")"
echo summary
