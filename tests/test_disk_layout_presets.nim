## Gates for the typed disk-layout preset registry.
##
## Three claims, one per gate, and each one is narrower than it may
## first look. Read the "proves / does not prove" note on each.
##
## ## t_disk_layout_preset_registry
##
## Every registered preset survives the whole chain the recipe puts it
## through: an ``auto-config.toml`` naming it parses into a typed
## request, the request builds a ``DiskLayout`` out of Reprobuild's own
## profile types, that renders to JSON, and the JSON parses back through
## Reprobuild's ``parseSystemHardwareJson`` into a value that re-renders
## to the same bytes. So the document the recipe hands to ``repro disk
## apply`` is not merely well-formed, it decodes into the typed layout
## the preset declared, with nothing lost on the way.
##
## The negative half: an unregistered name must be rejected, and the
## rejection must name every legal value. A validator that rejected
## everything would pass that on its own, so the same case requires each
## registered name to be accepted.
##
## ## t_uefi_ext4_disko_document_unchanged
##
## This is a refactor. The claim it has to support is "nothing about the
## shipped image changed", and the honest form of that claim at a level
## this gate can run is:
##
##   *The bytes the recipe writes to ``$WORK/disko.json`` for the
##   uefi-ext4 layout are identical to the bytes the retired heredoc
##   wrote.*
##
## That is the artifact being refactored. Everything downstream of it --
## the sgdisk calls ``repro disk apply`` derives, the mkfs calls, the
## labels, the fstab and grub.cfg ``repro infra install-root`` renders
## from the same document -- is a pure function of those bytes plus the
## staged tree, which this change does not touch.
##
## It does NOT prove that the qcow2 is byte-identical. Nothing here
## builds a qcow2: a ReproOS image build is a multi-hour, 118-source-
## package job that needs ``sudo`` and ``modprobe nbd``, so this gate
## deliberately does not attempt one, and no claim about the image's
## bytes is made from it. A build-twice byte-equality gate for the image
## itself is separate work.
##
## The golden file is not a transcription. ``tests/golden/
## disko-uefi-ext4.json`` was produced by expanding the heredoc out of
## the pre-refactor revision of the driver, and when ``git`` and that
## revision
## are available this gate re-derives it from the same blob and requires
## the golden to match -- so the golden cannot drift away from what the
## script actually emitted. The gate also asserts the heredoc is really
## gone from the current driver, because a comparison against a golden
## would otherwise pass just as happily on an unrefactored tree.
##
## ## t_uefi_attested_partition_table
##
## The staged uefi-attested layout has an ESP, TWO carrier pairs -- a root
## and a Merkle-tree volume per generation slot -- and distinct ``/var``,
## ``/home`` and swap volumes at the sizes the preset declares. Nothing
## mounts at ``/``: on this layout the root is the dm-verity device the
## initramfs activates from the root hash on the measured kernel command
## line.
##
## It does NOT prove that any of those volumes is ever written, or that
## the layout is installable. ``uefi-attested`` declares a *shape*; the
## image driver still does not put the verity data image or its Merkle
## tree onto the carriers, and the state volumes are not encrypted. The
## preset is refused at plan time for exactly that reason, and this gate
## asserts the refusal rather than pretending otherwise.
##
## ## Mocking
##
## None. The gate calls the shipped registry in ``repro/disk_layouts.nim``
## and decodes its output with Reprobuild's shipped
## ``parseSystemHardwareJson``; it reads the shipped driver and the
## shipped recipe rather than copies of them; and the pre-refactor
## baseline comes out of git history, not out of a fixture somebody
## typed.

import std/[options, os, osproc, strutils, tables]

import repro_profile/types
import repro_profile/emit

import "../repro/generations"
import "../repro/disk_layouts"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  GoldenUefiExt4 = RepoRoot / "tests" / "golden" / "disko-uefi-ext4.json"
  DriverPath = RepoRoot / "recipes" / "reproos-image" / "scripts" /
    "build-reproos-image.sh"
  RecipePath = RepoRoot / "recipes" / "reproos-image" / "package.nim"

  PreB1Revision = "e7b8fe379a2bcc50b019c658de83a26c48b1d37a"
    ## The commit this refactor was implemented on top of -- the last
    ## revision whose
    ## driver still contained the disko heredoc. The baseline for the
    ## non-change claim is re-derived from this blob.
  DriverRepoPath = "recipes/reproos-image/scripts/build-reproos-image.sh"

  FixtureEspSizeMib = 512
    ## The values tests/fixtures/auto-config-minimal.toml declares, which
    ## are also the driver's defaults; the golden was rendered with them.
  FixtureDiskSizeGb = 8
  ImageLayoutId = "reproos-image"
  ImageLayoutDevice = "/dev/nbd0"

  AbsentMountpoint = "/reproos-control-mountpoint-that-no-preset-declares"
    ## A mountpoint no layout declares. Every "does the layout have X"
    ## helper below is run against it too: if the finder reported it
    ## present, none of the positive assertions would mean anything.
  UnknownPresetName = "uefi-reproos-control-not-a-preset"

var failures = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message

proc skip(message: string) =
  echo "[skip] " & message

proc paramsFor(diskSizeGb: int): DiskLayoutParams =
  DiskLayoutParams(
    id: ImageLayoutId,
    device: ImageLayoutDevice,
    espSizeMib: FixtureEspSizeMib,
    diskSizeGb: diskSizeGb)

proc tomlFor(name: string; diskSizeGb: int): string =
  ## A minimal auto-config.toml naming a layout. Deliberately carries
  ## the surrounding noise -- comments, other sections, a key with the
  ## same name in a different section -- that the shell ``toml_get`` the
  ## plan's reader mirrors has to cope with.
  """# generated by tests/test_disk_layout_presets.nim
hostname = "reproos-smoke"

[user]
name = "repro"
type = "not-the-layout-type"

[disk]
size_gb = """ & $diskSizeGb & """

[disk.layout]
type = """" & name & """"   # trailing comment
esp_size_mib = """ & $FixtureEspSizeMib & """

[de]
default = "sway"
"""

proc contentSummary(c: ContentSpec): string =
  ## A total, comparable rendering of a content node. Nim cannot derive
  ## ``==`` for ``ContentSpec`` (it is a case object, and the generated
  ## comparison needs a parallel ``fields`` iterator), so structural
  ## equality is compared on this instead -- and a mismatch prints as a
  ## readable diff rather than as "false".
  case c.kind
  of cfsFilesystem:
    "filesystem|" & c.format & "|" & c.mountpoint & "|" &
      c.mountOptions.join(",") & "|" & c.label & "|subvols=" & $c.subvols.len
  of cfsSwap:
    "swap|priority=" & $c.swapPriority & "|discard=" & c.swapDiscardPolicy
  of cfsNone: "none"
  of cfsEncrypted: "encrypted|" & c.encryption.`type`
  of cfsLvm: "lvm|" & c.vg & "|volumes=" & $c.volumes.len
  of cfsZfs: "zfs|" & c.pool & "|" & c.dataset

proc layoutSummary(l: DiskLayout): string =
  for diskName, disk in l.disks:
    result.add diskName & " {" & disk.device & ", " & disk.`type` & "}\n"
    for pName, p in disk.partitions:
      result.add "  " & pName & " [" & p.`type` & ", " & p.size &
        ", bootable=" & $p.bootable & "] " & contentSummary(p.content) & "\n"
  result.add "pools=" & $l.pools.len & "\n"

proc partitionOf(layout: DiskLayout; name: string): Option[PartitionSpec] =
  for _, disk in layout.disks:
    if disk.partitions.hasKey(name):
      return some(disk.partitions[name])
  none(PartitionSpec)

proc partitionAtMountpoint(layout: DiskLayout;
                           mountpoint: string): Option[string] =
  ## The partition name whose content mounts at ``mountpoint``.
  for _, disk in layout.disks:
    for pName, p in disk.partitions:
      if p.content.kind == cfsFilesystem and p.content.mountpoint == mountpoint:
        return some(pName)
  none(string)

# ---------------------------------------------------------------------------
# t_disk_layout_preset_registry
# ---------------------------------------------------------------------------

block registryRoundTrip:
  if DiskLayoutPresets.len == 0:
    fail("t_disk_layout_preset_registry: the registry is empty")
    break registryRoundTrip

  var checked = 0
  for preset in DiskLayoutPresets:
    let toml = tomlFor(preset.name, max(preset.minDiskSizeGb, FixtureDiskSizeGb))
    let req = parseDiskLayoutRequest(toml, ImageLayoutId, ImageLayoutDevice)
    if req.name != preset.name:
      fail("t_disk_layout_preset_registry: TOML naming " & preset.name &
           " parsed as " & req.name)
      continue
    if req.params.espSizeMib != FixtureEspSizeMib:
      fail("t_disk_layout_preset_registry: " & preset.name &
           ": esp_size_mib parsed as " & $req.params.espSizeMib)
      continue

    let layout = buildDiskLayout(req.name, req.params)
    if layout.disks.len == 0:
      fail("t_disk_layout_preset_registry: " & preset.name &
           " built an empty layout")
      continue

    let rendered = renderDiskoJson(req.name, req.params)
    if not rendered.endsWith("\n"):
      fail("t_disk_layout_preset_registry: " & preset.name &
           " rendered a document with no trailing newline")
      continue

    # Decode with Reprobuild's own parser -- the one `repro disk apply`
    # uses -- and re-render. Equal bytes means the document carries the
    # whole typed layout and nothing but it.
    var decoded: SystemHardwareSpec
    try:
      decoded = parseSystemHardwareJson(rendered)
    except CatchableError as e:
      fail("t_disk_layout_preset_registry: " & preset.name &
           ": repro_profile could not parse the rendered document: " & e.msg)
      continue
    if decoded.disko.isNone:
      fail("t_disk_layout_preset_registry: " & preset.name &
           ": the decoded spec has no disko block")
      continue
    if renderDiskoDocument(decoded) != rendered:
      fail("t_disk_layout_preset_registry: " & preset.name &
           ": TOML -> typed -> JSON -> typed -> JSON is not stable")
      continue
    if layoutSummary(decoded.disko.get()) != layoutSummary(layout):
      fail("t_disk_layout_preset_registry: " & preset.name &
           ": the decoded layout differs from the one the preset built\n" &
           "--- built ---\n" & layoutSummary(layout) &
           "--- decoded ---\n" & layoutSummary(decoded.disko.get()))
      continue

    let accepted = validateDiskLayoutRequest(req)
    case preset.status
    of dlsBuildable:
      if accepted.len > 0:
        fail("t_disk_layout_preset_registry: " & preset.name &
             " is registered buildable but the validator rejected it: " &
             accepted)
        continue
    of dlsDeclared:
      # A declared-but-not-buildable preset must still render (it just
      # did) and must still be refused, with its reason.
      if accepted.len == 0:
        fail("t_disk_layout_preset_registry: " & preset.name &
             " is registered as not-yet-buildable but the validator " &
             "accepted it")
        continue
      if preset.unbuildableReason notin accepted:
        fail("t_disk_layout_preset_registry: " & preset.name &
             " was refused without its recorded reason")
        continue
    checked.inc

  if checked != DiskLayoutPresets.len:
    break registryRoundTrip
  pass("t_disk_layout_preset_registry: all " & $checked &
       " preset(s) round-trip TOML -> typed -> JSON -> typed")

block registryRejectsUnknown:
  let toml = tomlFor(UnknownPresetName, 64)
  let req = parseDiskLayoutRequest(toml, ImageLayoutId, ImageLayoutDevice)
  let message = validateDiskLayoutRequest(req)
  if message.len == 0:
    fail("t_disk_layout_preset_registry: the unknown layout " &
         UnknownPresetName & " was accepted")
    break registryRejectsUnknown
  if UnknownPresetName notin message:
    fail("t_disk_layout_preset_registry: the rejection does not quote " &
         "the offending name")
    break registryRejectsUnknown
  var unlisted: seq[string]
  for name in diskLayoutPresetNames():
    if name notin message:
      unlisted.add(name)
  if unlisted.len > 0:
    fail("t_disk_layout_preset_registry: the rejection does not name " &
         "the legal value(s): " & unlisted.join(", "))
    break registryRejectsUnknown
  pass("t_disk_layout_preset_registry: an unknown layout is refused and " &
       "the refusal names all " & $diskLayoutPresetNames().len &
       " legal value(s)")

block planIsWiredToTheValidator:
  ## The message above is only worth anything if the PLAN consults it.
  ## Read the shipped recipe rather than trusting that it does.
  if not fileExists(RecipePath):
    fail("t_disk_layout_preset_registry: recipe missing: " & RecipePath)
    break planIsWiredToTheValidator
  let recipe = readFile(RecipePath)
  var missing: seq[string]
  for needle in ["validateDiskLayoutRequest", "parseDiskLayoutRequest",
                 "renderDiskoJson", "raise newException"]:
    if needle notin recipe:
      missing.add(needle)
  if missing.len > 0:
    fail("t_disk_layout_preset_registry: the image recipe does not " &
         "resolve the layout at plan time; missing: " & missing.join(", "))
    break planIsWiredToTheValidator
  if "REPROOS_DISKO_SPEC" notin recipe:
    fail("t_disk_layout_preset_registry: the recipe does not hand the " &
         "rendered layout to the driver")
    break planIsWiredToTheValidator
  # Falsifiability of the reader itself.
  if "uefi-reproos-control-not-a-preset" in recipe:
    fail("t_disk_layout_preset_registry: the recipe reader matches a " &
         "control string that is not in the file")
    break planIsWiredToTheValidator
  pass("t_disk_layout_preset_registry: the image recipe resolves, " &
       "validates and renders the layout at plan time")

block planRejectsUnknownEndToEnd:
  ## Opt-in: actually run the plan against a config naming an unknown
  ## layout and require it to fail with the listing. Off by default
  ## because it re-enters the build engine from inside a test, which
  ## costs minutes and needs an engine new enough to run in this
  ## repository at all.
  ##
  ## Dropping the provider-graph snapshot first is NOT optional here,
  ## and the reason is a real limitation worth knowing about. The engine
  ## caches the whole provider graph in a snapshot keyed by the compiled
  ## provider's artifact id; while that snapshot is fresh it does not run
  ## the provider at all (``providerInvocations: 0``), so no plan-time
  ## code runs -- this validation included. Changing
  ## ``REPRO_AUTO_CONFIG`` is not a source change, so it does not
  ## invalidate the snapshot, and neither ``--rebuild`` nor
  ## ``--force-rebuild`` reaches this particular cache. Measured on this
  ## host: with the snapshot warm, an unknown layout lints GREEN
  ## (``providerInvocations: 0``, exit 0); with the snapshot removed the
  ## same config fails with exit 1 out of ``buildReproosImagePackage``.
  ##
  ## That is not a hole through which a bad layout reaches a disk: on a
  ## stale plan the driver's layout-drift check refuses before any
  ## privileged step, and the installer's own config validator refuses
  ## earlier still. But it does mean "fails at plan time" holds when the
  ## plan is evaluated, not unconditionally.
  ##
  ## The snapshot is a regenerable cache under the gitignored
  ## ``.repro/``; the next build rebuilds it.
  let reproBin = getEnv("REPROOS_DISK_LAYOUT_PLAN_GATE")
  if reproBin.len == 0:
    skip("t_disk_layout_preset_registry: end-to-end plan rejection not " &
         "run. Set REPROOS_DISK_LAYOUT_PLAN_GATE=<path to repro> to run " &
         "`repro lint` against a config naming an unknown layout.")
    break planRejectsUnknownEndToEnd
  let work = getTempDir() / "reproos-b1-plan-gate"
  createDir(work)
  let badConfig = work / "auto-config-unknown-layout.toml"
  writeFile(badConfig, tomlFor(UnknownPresetName, 64))
  putEnv("REPRO_AUTO_CONFIG", badConfig)
  removeDir(RepoRoot / ".repro" / "build" / "repro" / "provider-graph")
  let (output, code) = execCmdEx(
    reproBin & " lint --no-runquota", workingDir = RepoRoot)
  delEnv("REPRO_AUTO_CONFIG")
  removeDir(work)
  if code == 0:
    fail("t_disk_layout_preset_registry: the plan succeeded with " &
         "[disk.layout].type = " & UnknownPresetName)
    break planRejectsUnknownEndToEnd
  if UnknownPresetName notin output:
    fail("t_disk_layout_preset_registry: the plan failed but never " &
         "named the offending layout")
    break planRejectsUnknownEndToEnd
  for name in diskLayoutPresetNames():
    if name notin output:
      fail("t_disk_layout_preset_registry: the plan failure does not " &
           "list the legal value " & name)
      break planRejectsUnknownEndToEnd
  pass("t_disk_layout_preset_registry: the plan itself refuses an " &
       "unknown layout and lists the legal set")

# ---------------------------------------------------------------------------
# t_uefi_ext4_disko_document_unchanged
# ---------------------------------------------------------------------------

var goldenText = ""

block goldenMatchesTypedRenderer:
  if not fileExists(GoldenUefiExt4):
    fail("t_uefi_ext4_disko_document_unchanged: golden missing: " & GoldenUefiExt4)
    break goldenMatchesTypedRenderer
  goldenText = readFile(GoldenUefiExt4)
  let rendered = renderDiskoJson("uefi-ext4", paramsFor(FixtureDiskSizeGb))
  if rendered != goldenText:
    fail("t_uefi_ext4_disko_document_unchanged: the typed renderer no longer " &
         "reproduces the pre-refactor disko document.\n--- expected (" &
         $goldenText.len & " bytes) ---\n" & goldenText &
         "--- got (" & $rendered.len & " bytes) ---\n" & rendered)
    break goldenMatchesTypedRenderer
  pass("t_uefi_ext4_disko_document_unchanged: the typed uefi-ext4 renderer emits " &
       "the pre-refactor disko document byte for byte (" &
       $goldenText.len & " bytes)")

block goldenIsDerivedFromThePreRefactorDriver:
  ## Re-derive the baseline from the driver as it stood before the
  ## refactor, so
  ## that the golden cannot quietly become a description of the new
  ## behaviour instead of a record of the old one.
  if goldenText.len == 0:
    break goldenIsDerivedFromThePreRefactorDriver
  if findExe("git").len == 0:
    skip("t_uefi_ext4_disko_document_unchanged: git not available; the golden " &
         "could not be re-derived from " & PreB1Revision)
    break goldenIsDerivedFromThePreRefactorDriver
  let (blob, code) = execCmdEx("git show " & PreB1Revision & ":" &
    DriverRepoPath, workingDir = RepoRoot)
  if code != 0:
    skip("t_uefi_ext4_disko_document_unchanged: revision " & PreB1Revision &
         " is not reachable in this checkout; the golden could not be " &
         "re-derived from the pre-refactor driver")
    break goldenIsDerivedFromThePreRefactorDriver

  # Extract the heredoc body and expand the single variable it used.
  const openMark = "cat > \"$DISKO_JSON\" <<EOF\n"
  let openIdx = blob.find(openMark)
  if openIdx < 0:
    fail("t_uefi_ext4_disko_document_unchanged: the pre-refactor driver at " &
         PreB1Revision & " has no disko heredoc; the pinned revision is " &
         "wrong")
    break goldenIsDerivedFromThePreRefactorDriver
  let bodyStart = openIdx + openMark.len
  let closeIdx = blob.find("\nEOF\n", bodyStart)
  if closeIdx < 0:
    fail("t_uefi_ext4_disko_document_unchanged: the pre-refactor heredoc is not " &
         "terminated")
    break goldenIsDerivedFromThePreRefactorDriver
  let expanded = blob[bodyStart ..< closeIdx + 1].replace(
    "${ESP_SIZE_MIB}", $FixtureEspSizeMib)
  if "$" in expanded:
    fail("t_uefi_ext4_disko_document_unchanged: the pre-refactor heredoc expanded " &
         "more than ESP_SIZE_MIB; the baseline is incomplete")
    break goldenIsDerivedFromThePreRefactorDriver
  if expanded != goldenText:
    fail("t_uefi_ext4_disko_document_unchanged: the golden does not match what " &
         "the driver at " & PreB1Revision & " emitted")
    break goldenIsDerivedFromThePreRefactorDriver
  pass("t_uefi_ext4_disko_document_unchanged: the golden is the heredoc from " &
       PreB1Revision[0 ..< 12] & ", re-derived from the blob")

block heredocIsActuallyGone:
  ## Without this, the two cases above would pass unchanged on a tree
  ## where nothing had been refactored at all.
  if not fileExists(DriverPath):
    fail("t_uefi_ext4_disko_document_unchanged: driver missing: " & DriverPath)
    break heredocIsActuallyGone
  let driver = readFile(DriverPath)
  if "cat > \"$DISKO_JSON\"" in driver:
    fail("t_uefi_ext4_disko_document_unchanged: the driver still writes the disko " &
         "document from a heredoc")
    break heredocIsActuallyGone
  if "\"cpuMicrocode\"" in driver or "\"kernelModules\"" in driver:
    fail("t_uefi_ext4_disko_document_unchanged: the driver still contains " &
         "hand-written disko JSON")
    break heredocIsActuallyGone
  if "REPROOS_DISKO_SPEC" notin driver:
    fail("t_uefi_ext4_disko_document_unchanged: the driver does not consume the " &
         "layout the plan rendered")
    break heredocIsActuallyGone
  if "uefi-ext4)" in driver:
    fail("t_uefi_ext4_disko_document_unchanged: the driver still carries its own " &
         "list of legal layout names")
    break heredocIsActuallyGone
  pass("t_uefi_ext4_disko_document_unchanged: the driver renders no JSON of its " &
       "own and consumes the plan-rendered layout")

block driverDefaultsStillAgreeWithThePlan:
  ## The golden was rendered with the driver's defaults. If the two
  ## readers of auto-config.toml ever disagree about what "unset" means,
  ## the byte comparison above would be measuring the wrong inputs.
  if not fileExists(DriverPath):
    break driverDefaultsStillAgreeWithThePlan
  let driver = readFile(DriverPath)
  var wrong: seq[string]
  if "DISK_SIZE_GB=\"${DISK_SIZE_GB:-" & $DefaultDiskSizeGb & "}\"" notin driver:
    wrong.add("size_gb default != " & $DefaultDiskSizeGb)
  if "ESP_SIZE_MIB=\"${ESP_SIZE_MIB:-" & $DefaultEspSizeMib & "}\"" notin driver:
    wrong.add("esp_size_mib default != " & $DefaultEspSizeMib)
  if "DISK_TYPE=\"${DISK_TYPE:-" & DefaultDiskLayoutName & "}\"" notin driver:
    wrong.add("layout default != " & DefaultDiskLayoutName)
  if wrong.len > 0:
    fail("t_uefi_ext4_disko_document_unchanged: the driver and repro/" &
         "disk_layouts.nim disagree about the config defaults: " &
         wrong.join("; "))
    break driverDefaultsStillAgreeWithThePlan
  pass("t_uefi_ext4_disko_document_unchanged: the driver and the plan apply the " &
       "same auto-config.toml defaults")

block theDriverWritesExactlyThoseBytes:
  ## The last gap in the byte claim: the plan renders the document, but
  ## the DRIVER writes it, through a `\n`-escaped environment value and
  ## `printf '%b'`. Run that hand-off for real rather than reasoning
  ## about it -- an escaping bug here would change every installed
  ## image while every check above stayed green.
  if goldenText.len == 0:
    break theDriverWritesExactlyThoseBytes
  if findExe("bash").len == 0:
    fail("t_uefi_ext4_disko_document_unchanged: bash is required to exercise the " &
         "driver's printf hand-off")
    break theDriverWritesExactlyThoseBytes
  let escaped = goldenText.replace("\n", "\\n")
  if "\n" in escaped:
    fail("t_uefi_ext4_disko_document_unchanged: the escaped document is not a " &
         "single line; the recipe's shell command would be malformed")
    break theDriverWritesExactlyThoseBytes
  if "'" in escaped:
    fail("t_uefi_ext4_disko_document_unchanged: the escaped document contains a " &
         "single quote and cannot be carried in the recipe's assignment")
    break theDriverWritesExactlyThoseBytes
  let written = execProcess("bash",
    args = ["-c", "printf '%b' \"$1\"", "bash", escaped],
    options = {poUsePath})
  if written != goldenText:
    fail("t_uefi_ext4_disko_document_unchanged: printf '%b' of the escaped " &
         "document produced " & $written.len & " bytes, not the " &
         $goldenText.len & " the plan rendered")
    break theDriverWritesExactlyThoseBytes
  pass("t_uefi_ext4_disko_document_unchanged: the driver's printf hand-off " &
       "reproduces the rendered document exactly (" & $written.len &
       " bytes)")

block shippedFixtureStillRendersTheGolden:
  ## The end the recipe actually takes: read the real fixture, resolve
  ## it the way the plan does, render, compare.
  if goldenText.len == 0:
    break shippedFixtureStillRendersTheGolden
  let fixture = RepoRoot / "tests" / "fixtures" / "auto-config-minimal.toml"
  if not fileExists(fixture):
    fail("t_uefi_ext4_disko_document_unchanged: fixture missing: " & fixture)
    break shippedFixtureStillRendersTheGolden
  let req = parseDiskLayoutRequest(readFile(fixture), ImageLayoutId,
    ImageLayoutDevice)
  let refusal = validateDiskLayoutRequest(req)
  if refusal.len > 0:
    fail("t_uefi_ext4_disko_document_unchanged: the shipped fixture no longer " &
         "plans: " & refusal)
    break shippedFixtureStillRendersTheGolden
  if renderDiskoJson(req.name, req.params) != goldenText:
    fail("t_uefi_ext4_disko_document_unchanged: the shipped fixture no longer " &
         "renders the pre-refactor document")
    break shippedFixtureStillRendersTheGolden
  pass("t_uefi_ext4_disko_document_unchanged: tests/fixtures/auto-config-minimal" &
       ".toml renders the pre-refactor document unchanged")

# ---------------------------------------------------------------------------
# t_uefi_attested_partition_table
# ---------------------------------------------------------------------------

block attestedPartitionTable:
  let preset = findDiskLayoutPreset("uefi-attested")
  if preset.isNone:
    fail("t_uefi_attested_partition_table: uefi-attested is not registered")
    break attestedPartitionTable
  let params = paramsFor(preset.get().minDiskSizeGb)
  let layout = buildDiskLayout("uefi-attested", params)

  # The control first: if the finders below matched anything, none of
  # the assertions after them would carry information.
  if partitionAtMountpoint(layout, AbsentMountpoint).isSome:
    fail("t_uefi_attested_partition_table: the mountpoint finder matched " &
         "a mountpoint no preset declares")
    break attestedPartitionTable
  if partitionOf(layout, "reproos-control-absent-partition").isSome:
    fail("t_uefi_attested_partition_table: the partition finder matched " &
         "a partition no preset declares")
    break attestedPartitionTable

  # ESP.
  let esp = partitionOf(layout, "esp")
  if esp.isNone:
    fail("t_uefi_attested_partition_table: no ESP")
    break attestedPartitionTable
  let espSpec = esp.get()
  if espSpec.`type` != "esp" or not espSpec.bootable:
    fail("t_uefi_attested_partition_table: the ESP is not a bootable " &
         "esp partition (type=" & espSpec.`type` & " bootable=" &
         $espSpec.bootable & ")")
    break attestedPartitionTable
  if espSpec.size != $params.espSizeMib & "M":
    fail("t_uefi_attested_partition_table: the ESP is " & espSpec.size &
         ", not the declared " & $params.espSizeMib & "M")
    break attestedPartitionTable
  if espSpec.content.kind != cfsFilesystem or
     espSpec.content.format != "vfat" or
     espSpec.content.mountpoint != "/boot":
    fail("t_uefi_attested_partition_table: the ESP does not carry a vfat " &
         "/boot filesystem")
    break attestedPartitionTable

  # The root. On this layout NOTHING mounts at /, and that is the shape
  # rather than an omission: the root is the dm-verity device the
  # initramfs activates from the root hash on the measured kernel command
  # line, so the partitions below are carriers for a finished image and a
  # partition mounted at / would be a second, unchecked answer to what the
  # root is. There are TWO of them, because an attested instance runs one
  # generation for the lifetime of a boot and the previous generation's
  # root has to stay intact for a rollback to be atomic.
  if partitionAtMountpoint(layout, "/").isSome:
    fail("t_uefi_attested_partition_table: a partition mounts at /, which " &
         "would be an unchecked second answer to what the root is on a " &
         "layout whose root is a dm-verity device")
    break attestedPartitionTable
  var rootSlots: seq[string] = @[]
  for slot in [gsA, gsB]:
    for (name, declared) in [(rootPartitionName(slot), AttestedRootSize),
                             (hashPartitionName(slot), AttestedHashTreeSize)]:
      let found = partitionOf(layout, name)
      if found.isNone:
        fail("t_uefi_attested_partition_table: no " & name & " volume; a " &
             "generation is a unified kernel image AND the verity pair its " &
             "measured command line names, and there are two generations")
        break attestedPartitionTable
      let spec = found.get()
      if spec.size != declared:
        fail("t_uefi_attested_partition_table: " & name & " is " &
             spec.size & ", not the declared " & declared)
        break attestedPartitionTable
      if spec.content.kind != cfsNone:
        fail("t_uefi_attested_partition_table: " & name & " declares " &
             "content the apply would create; what goes there is a " &
             "finished image whose bytes the root hash covers, and an " &
             "mkfs at install time would overwrite it")
        break attestedPartitionTable
      rootSlots.add name

  # Distinct /var and /home volumes.
  var seen: seq[string] = rootSlots
  for (mountpoint, declaredSize) in [("/var", AttestedVarSize),
                                     ("/home", AttestedHomeSize)]:
    let name = partitionAtMountpoint(layout, mountpoint)
    if name.isNone:
      fail("t_uefi_attested_partition_table: nothing mounts at " &
           mountpoint)
      break attestedPartitionTable
    if name.get() in seen:
      fail("t_uefi_attested_partition_table: " & mountpoint &
           " shares partition " & name.get() & " with an earlier volume")
      break attestedPartitionTable
    seen.add(name.get())
    let spec = partitionOf(layout, name.get()).get()
    if spec.size != declaredSize:
      fail("t_uefi_attested_partition_table: " & mountpoint & " is " &
           spec.size & ", not the declared " & declaredSize)
      break attestedPartitionTable
    if "ro" in spec.content.mountOptions:
      fail("t_uefi_attested_partition_table: " & mountpoint &
           " is read-only; state volumes must be writable")
      break attestedPartitionTable

  # A swap volume, distinct from all of them.
  var swapName = ""
  for _, disk in layout.disks:
    for pName, p in disk.partitions:
      if p.content.kind == cfsSwap:
        swapName = pName
  if swapName.len == 0:
    fail("t_uefi_attested_partition_table: no swap volume")
    break attestedPartitionTable
  if swapName in seen:
    fail("t_uefi_attested_partition_table: swap shares a partition with " &
         "a mounted volume")
    break attestedPartitionTable
  let swapSpec = partitionOf(layout, swapName).get()
  if swapSpec.`type` != "swap":
    fail("t_uefi_attested_partition_table: the swap volume's partition " &
         "type is " & swapSpec.`type` & ", not swap")
    break attestedPartitionTable
  if swapSpec.size != AttestedSwapSize:
    fail("t_uefi_attested_partition_table: swap is " & swapSpec.size &
         ", not the declared " & AttestedSwapSize)
    break attestedPartitionTable

  # The fill-the-remainder partition has to be last: disk_apply turns
  # "100%" into sgdisk's fill-the-disk form, which is only correct for
  # the final entry.
  for _, disk in layout.disks:
    var idx = 0
    for pName, p in disk.partitions:
      idx.inc
      if p.size in ["100%", "remaining"] and idx != disk.partitions.len:
        fail("t_uefi_attested_partition_table: partition " & pName &
             " takes the remainder but is not last")
        break attestedPartitionTable

  pass("t_uefi_attested_partition_table: ESP + two carrier pairs for two " &
       "generations' integrity-checked roots + distinct /var, /home and " &
       "swap at the declared sizes (" &
       $layout.disks["main"].partitions.len & " partitions)")

block attestedIsDeclaredNotBuildable:
  ## The honest half of the claim: the registry declares the shape and
  ## refuses to
  ## install it. If this ever passes silently, an image built from
  ## uefi-attested would have a read-only root that nothing measures.
  let toml = tomlFor("uefi-attested", 64)
  let req = parseDiskLayoutRequest(toml, ImageLayoutId, ImageLayoutDevice)
  let refusal = validateDiskLayoutRequest(req)
  if refusal.len == 0:
    fail("t_uefi_attested_partition_table: uefi-attested is accepted for " &
         "building, but it has no verity content and no UKI behind it")
    break attestedIsDeclaredNotBuildable
  if "not yet buildable" notin refusal:
    fail("t_uefi_attested_partition_table: uefi-attested is refused, but " &
         "not as a declared-only layout: " & refusal)
    break attestedIsDeclaredNotBuildable
  pass("t_uefi_attested_partition_table: uefi-attested is refused at plan " &
       "time as declared-but-not-yet-buildable")

if failures > 0:
  stderr.writeLine("test_disk_layout_presets: " & $failures &
                   " check(s) failed")
  quit(1)
echo "disk layout presets: PASS"
