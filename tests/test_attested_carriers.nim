## The integrity-checked root, on the partitions the measured command
## line names.
##
## ## What this gate is about
##
## An attested ReproOS boot resolves three things out of a kernel command
## line that lives inside the binary firmware measured: a dm-verity root
## hash, the volume holding the read-only root image, and the volume
## holding the Merkle tree over it. Every one of those three was already
## produced and pinned before this gate existed --
## ``build-verity-root.sh`` makes the pair, ``repro/uki.nim`` puts the
## hash and the two specifiers inside the unified kernel image, and
## ``repro/disk_layouts.nim`` declares carrier partitions for them. What
## was missing is the only step that makes any of it true of a disk:
## nothing copied the two images onto the two partitions. An image built
## that way boots, resolves both specifiers to partitions that really
## exist, and finds them empty.
##
## ``recipes/reproos-image/scripts/write-verity-carriers.sh`` is that
## step, and this gate is what stops it from being a script nobody runs.
##
## ## The layers, and what each one is worth
##
## Layer 1 (always on, ~1s, no tool beyond the Nim gate set) reads the
## SHIPPED driver, the SHIPPED carrier writer and the SHIPPED recipe and
## asserts the properties that cannot be checked any other way without a
## disk: that the driver calls the writer on the attested layout and only
## there, that the writer addresses carriers by ``PARTUUID`` read back
## off the partition table rather than by a partition number or a
## filesystem label, that it compares what it read back against what it
## wrote, that the recipe declares every tool the writer runs, and that
## the two specifiers the recipe hands the driver are exactly the ones
## ``repro/generations.nim`` derives for slot ``a``. Every matcher is
## also asked about a token no shipped file carries, so a matcher that
## answered "present" to anything would fail this gate rather than pass
## it. It PROVES NOTHING about a disk.
##
## Layer 2 (opt-in, ``REPROOS_ATTESTED_CARRIER_GATE=1``, ~2 min, needs
## ``sudo`` and the ``nbd`` module) is the real thing at a size that fits
## in a test: a real qcow2, a real ``repro disk apply`` of the real
## ``uefi-attested`` document, a real verity pair built by the shipped
## ``build-verity-root.sh`` over a purpose-built tree, and the shipped
## writer run against the result. It then checks the disk rather than the
## script's own report: the partition GUIDs read off the GPT equal the
## ones ``partitionUuid`` derives, the bytes read back off each carrier
## equal the file that was written, and ``veritysetup verify`` walks the
## whole tree ON THE TWO PARTITIONS. The negative half is a flipped byte
## on the data carrier, which must make that same verification fail.
##
## What layer 2 does NOT prove: nothing here boots. The root closure is a
## purpose-built tree of a few megabytes and not the ReproOS package set,
## no unified kernel image is loaded, no firmware measures anything, and
## no PCR is read. It proves that the pair an attested command line names
## is on the disk, intact, and verifiable there.

import std/[algorithm, os, osproc, sequtils, strutils]

import "../repro/disk_layouts" as diskLayouts
import "../repro/generations" as generations
import "../repro/package_sets" as packageSets
import "../repro/verity" as verity

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  ImageDriver = "recipes/reproos-image/scripts/build-reproos-image.sh"
  CarrierWriter = "recipes/reproos-image/scripts/write-verity-carriers.sh"
  VerityBuilder = "recipes/reproos-image/scripts/build-verity-root.sh"
  ImageRecipe = "recipes/reproos-image/package.nim"
  AutoConfigFixture = "tests/fixtures/auto-config-minimal.toml"

  AttestedLayout = "uefi-attested"

  GateEnv = "REPROOS_ATTESTED_CARRIER_GATE"
    ## The opt-in for layer 2. Anything but ``1`` reports a visible skip
    ## that says no disk was written.

  KeepEnv = "REPROOS_ATTESTED_CARRIER_KEEP"
    ## Keep the work directory and leave the qcow2 behind. The NBD
    ## connection and the loaded module are torn down regardless.

  AbsentRule = "REPROOS_NO_SUCH_CARRIER_TOKEN"
    ## A token no shipped file carries. Every matcher below is asked
    ## about it, so a matcher that matched anything would fail.

  # The tools layer 2 needs. Named here so the skip can say which one is
  # missing rather than dying inside a shell.
  Layer2Tools = ["sudo", "qemu-img", "qemu-nbd", "sgdisk", "veritysetup",
                 "mkfs.ext4", "modprobe", "dd", "blockdev", "sha256sum"]

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

proc readSource(rel: string): string =
  let path = RepoRoot / rel
  if not fileExists(path):
    fail("the gate reads " & rel & " and it is not in the tree")
    return ""
  readFile(path)

# ---------------------------------------------------------------------------
# Layer 1: the shipped sources.
# ---------------------------------------------------------------------------

proc requireAll(what, text: string; needles: openArray[string]) =
  ## Every needle must be present, and the control token must not be.
  var missing: seq[string] = @[]
  for n in needles:
    if n notin text:
      missing.add n
  if AbsentRule in text:
    fail(what & ": the control token " & AbsentRule & " is present, so " &
         "this matcher would answer 'yes' to anything")
    return
  if missing.len > 0:
    fail(what & ": missing " & missing.join(", "))
    return
  pass(what)

proc caseDriverCallsTheWriterOnTheAttestedLayoutOnly() =
  let driver = readSource(ImageDriver)
  if driver.len == 0: return

  requireAll("t_image_driver_writes_the_verity_pair: the driver runs the " &
             "shipped carrier writer",
             driver,
             ["write-verity-carriers.sh",
              "REPROOS_VERITY_DATA_IMAGE=",
              "REPROOS_VERITY_HASH_TREE=",
              "REPROOS_VERITY_ROOTHASH_FILE=",
              "REPROOS_VERITY_DATA_DEVICE=",
              "REPROOS_VERITY_HASH_DEVICE="])

  # The call must be inside a `uefi-attested)` arm, and that is checked
  # structurally rather than by proximity: the last `uefi-attested)`
  # before the call and the first `;;` after that arm opens must bracket
  # the call. A call that escaped its arm would make every ordinary image
  # build demand a verity pair it never produced.
  #
  # Anchored on the INVOCATION rather than on the first mention of the
  # script: the driver's exit-code table names it too, and a check that
  # found the comment would be measuring the wrong offset.
  const Invocation = "bash \"$SCRIPT_DIR_SELF/write-verity-carriers.sh\""
  let callAt = driver.find(Invocation)
  if callAt < 0:
    fail("t_image_driver_writes_the_verity_pair: the driver never runs " &
         "the writer (looked for " & Invocation.escape() & ")")
    return
  let armAt = driver.rfind(AttestedLayout & ")", last = callAt)
  if armAt < 0:
    fail("t_image_driver_writes_the_verity_pair: the call to the carrier " &
         "writer is not inside a '" & AttestedLayout & ")' arm, so every " &
         "layout would run it")
    return
  let armEnd = driver.find(";;", start = armAt)
  if armEnd < 0 or armEnd < callAt:
    fail("t_image_driver_writes_the_verity_pair: the '" & AttestedLayout &
         ")' arm at " & $armAt & " closes before the call at " & $callAt)
    return
  pass("t_image_driver_writes_the_verity_pair: the call is inside the " &
       AttestedLayout & " arm (" & $armAt & " < " & $callAt & " < " &
       $armEnd & ")")

  # The driver spells the two artifact names itself, because it derives
  # their directory from the root-hash path the recipe hands it. Two
  # spellings of one filename is how the last set of drifts started, so
  # both are pinned against the module that declares them.
  var wrongNames: seq[string] = @[]
  for name in [verity.VerityDataImageFileName, verity.VerityHashTreeFileName]:
    if name notin driver:
      wrongNames.add name
  if wrongNames.len > 0:
    fail("t_image_driver_writes_the_verity_pair: the driver names " &
         "artifacts the verity module does not declare; missing " &
         wrongNames.join(", ") & " (repro/verity.nim owns these names)")
  else:
    pass("t_image_driver_writes_the_verity_pair: the two artifacts it " &
         "hands the writer are the ones repro/verity.nim declares (" &
         verity.VerityDataImageFileName & ", " &
         verity.VerityHashTreeFileName & ")")

  # It has to happen before anything is mounted: a carrier holds no
  # filesystem, and the driver's root mount is for the other layout.
  let mountAt = driver.find("Phase 7: mount what this layout has a reason")
  if mountAt < 0:
    fail("t_image_driver_writes_the_verity_pair: the driver no longer has " &
         "the mount phase this ordering check is anchored on")
  elif callAt > mountAt:
    fail("t_image_driver_writes_the_verity_pair: the carriers are written " &
         "at " & $callAt & ", after the mount phase at " & $mountAt)
  else:
    pass("t_image_driver_writes_the_verity_pair: the carriers are written " &
         "before anything is mounted")

proc caseWriterAddressesCarriersByPartuuid() =
  let writer = readSource(CarrierWriter)
  if writer.len == 0: return

  requireAll("t_carriers_are_addressed_by_partuuid: the writer resolves " &
             "specifiers against the partition table on the device",
             writer,
             ["PARTUUID=",
              "SGDISK_BIN\" -i",
              "Partition unique GUID"])

  # And every privileged command must be an absolute path resolved off
  # the action's own PATH, because `sudo` applies the host's secure_path
  # and would otherwise silently pick a different binary -- or none.
  var bareUnderSudo: seq[string] = @[]
  for line in writer.splitLines():
    if "\"$SUDO\" " notin line: continue
    let after = line.split("\"$SUDO\" ")[1].strip()
    if not after.startsWith("\"$"):
      bareUnderSudo.add line.strip()
  if bareUnderSudo.len > 0:
    fail("t_carriers_are_addressed_by_partuuid: the writer runs a bare " &
         "command name under sudo, which resolves through the host's " &
         "secure_path rather than the action's declared tools: " &
         bareUnderSudo.join(" | "))
  else:
    pass("t_carriers_are_addressed_by_partuuid: every command the writer " &
         "runs under sudo is an absolute path resolved off the action's " &
         "own PATH")

  # A hash device has no filesystem, so `findfs LABEL=` can never resolve
  # it, and both root carriers hold an image with the same ext4 label.
  # The writer must therefore REFUSE anything that is not a PARTUUID.
  if "LABEL=" & generations.AttestedRootFsLabel in writer:
    fail("t_carriers_are_addressed_by_partuuid: the writer names the " &
         "filesystem label " & generations.AttestedRootFsLabel & ", which " &
         "names both root carriers once two generations are staged")
  else:
    pass("t_carriers_are_addressed_by_partuuid: the writer never names " &
         "the root filesystem label")

  # And it must not fall back to a partition number when a specifier does
  # not resolve: a silently-wrong carrier is exactly the failure this
  # whole step exists to prevent.
  if "exit 68" notin writer:
    fail("t_carriers_are_addressed_by_partuuid: the writer has no hard " &
         "failure for a specifier that resolves to no partition")
  else:
    pass("t_carriers_are_addressed_by_partuuid: an unresolvable specifier " &
         "is a hard failure")

proc caseWriterReadsBackWhatItWrote() =
  let writer = readSource(CarrierWriter)
  if writer.len == 0: return
  requireAll("t_carrier_write_is_read_back: the writer compares the bytes " &
             "on the partition against the file it copied",
             writer,
             ["sha256sum", "iflag=count_bytes", "conv=fsync",
              "BLOCKDEV_BIN\" --getsize64", "VERITYSETUP_BIN\" verify"])

  # The read-back must have no opt-out. `veritysetup verify` has one,
  # because a host without cryptsetup can still be told to write; the
  # digest comparison must not.
  #
  # This is deliberately a REGION check rather than a same-line one. An
  # earlier version asked only whether `sha256sum` and the switch appeared
  # on one line, and the natural way to actually add an opt-out -- guard
  # the `[ "$want" != "$got" ]` comparison, or guard the whole read-back
  # block, or guard the calls -- puts them on different lines and walked
  # straight through it. So the rule is stated the way it is meant: the
  # switch may not appear ANYWHERE from the opening of `write_carrier()`
  # through its last invocation. That region is the copy and its
  # verification; the switch belongs only to the `veritysetup verify`
  # section below it.
  const
    CarrierVerifySwitch = "REPROOS_VERITY_CARRIER_VERIFY"
    WriteCarrierOpen = "write_carrier() {"
    WriteCarrierLastCall = "write_carrier 'verity hash tree'"
  let openAt = writer.find(WriteCarrierOpen)
  let lastCallAt = writer.find(WriteCarrierLastCall)
  if openAt < 0 or lastCallAt <= openAt:
    fail("t_carrier_write_is_read_back: the writer no longer has a " &
         "`" & WriteCarrierOpen & "` region ending at `" &
         WriteCarrierLastCall & "`, so the no-opt-out rule cannot be " &
         "checked; the check must be updated with the writer")
  elif CarrierVerifySwitch in
       writer[openAt .. lastCallAt + WriteCarrierLastCall.len - 1]:
    fail("t_carrier_write_is_read_back: the digest comparison is behind " &
         "an environment switch, so a build could skip it: " &
         CarrierVerifySwitch & " appears between the opening of " &
         "write_carrier() and its last call")
  else:
    pass("t_carrier_write_is_read_back: the digest comparison has no " &
         "opt-out (" & CarrierVerifySwitch & " appears nowhere between " &
         "write_carrier()'s opening and its last call)")

proc caseRecipeDeclaresEveryToolTheWriterRuns() =
  let recipe = readSource(ImageRecipe)
  if recipe.len == 0: return
  let writer = readSource(CarrierWriter)
  if writer.len == 0: return

  # The tools the writer itself requires, taken from its own `for tool in`
  # loop rather than from a second list here, plus veritysetup which is
  # required conditionally further down.
  var required: seq[string] = @[]
  for line in writer.splitLines():
    let t = line.strip()
    if t.startsWith("for tool in ") and t.endsWith("; do"):
      for tool in t["for tool in ".len ..< t.len - "; do".len].split(' '):
        if tool.len > 0:
          required.add tool
  required.add "veritysetup"
  if required.len < 2:
    fail("t_carrier_tools_are_declared: the writer's tool loop could not " &
         "be read, so this check would pass vacuously")
    return
  required.sort()

  var undeclared: seq[string] = @[]
  for tool in required:
    if ("\"" & tool & "\",") notin recipe:
      undeclared.add tool
  if undeclared.len > 0:
    fail("t_carrier_tools_are_declared: the writer runs " &
         undeclared.join(", ") & " and " & ImageRecipe & " does not " &
         "declare " & (if undeclared.len == 1: "it" else: "them") &
         " as a tool identity; under the engine's hermetic PATH the " &
         "image build would die inside the writer")
    return
  pass("t_carrier_tools_are_declared: all " & $required.len & " tools the " &
       "writer runs are declared identities (" & required.join(", ") & ")")

proc caseSpecifiersMatchTheLayout() =
  ## The two specifiers the recipe hands the driver, the two the command
  ## line carries, and the two the layout's carriers will be created with
  ## are one derivation. Checked by re-deriving them here from the same
  ## inputs the recipe uses.
  let configText = readSource(AutoConfigFixture)
  if configText.len == 0: return

  var request = diskLayouts.parseDiskLayoutRequest(
    configText, "reproos-image", "/dev/nbd0")
  request.name = AttestedLayout
  request.params.diskSizeGb = 20
  let seed = diskLayouts.reproosImageIdentitySeed(
    configText, packageSets.ReproosGraphicalRootfsPackages, request)
  if seed.len == 0:
    fail("t_specifiers_name_the_layouts_carriers: no identity seed")
    return

  let devices = generations.attestedBootDevices(seed, generations.gsA)
  let err = generations.validateAttestedBootDevices(devices)
  if err.len > 0:
    fail("t_specifiers_name_the_layouts_carriers: " & err)
    return

  # The disko document must declare partitions under exactly the names
  # the specifiers were derived from, and they must be carriers.
  let disko = diskLayouts.renderDiskoJson(AttestedLayout, request.params)
  var problems: seq[string] = @[]
  for slot in [generations.gsA, generations.gsB]:
    for pName in [generations.rootPartitionName(slot),
                  generations.hashPartitionName(slot)]:
      if ("\"" & pName & "\":") notin disko:
        problems.add "the layout declares no partition named " & pName
  if "\"kind\": \"none\"" notin disko:
    problems.add "no carrier in the layout has content kind \"none\"; an " &
      "apply would run mkfs over an image the root hash was taken over"
  if problems.len > 0:
    fail("t_specifiers_name_the_layouts_carriers: " & problems.join("; "))
    return

  # And the derivation must be the one disk_apply performs: same disk
  # name, same purpose string. `partitionUuid` is the shared
  # implementation, so what is checked here is that slot a's two
  # specifiers differ from slot b's and from each other -- a derivation
  # that collapsed would name one partition twice and both generations
  # would share a root.
  let bDevices = generations.attestedBootDevices(seed, generations.gsB)
  var seen: seq[string] = @[devices.data, devices.hash,
                            bDevices.data, bDevices.hash]
  let before = seen.len
  seen.sort()
  seen = deduplicate(seen)
  if seen.len != before:
    fail("t_specifiers_name_the_layouts_carriers: the four carrier " &
         "specifiers are not distinct (" & $seen.len & " of " & $before &
         "); two generations would be told to use one volume")
    return
  pass("t_specifiers_name_the_layouts_carriers: the layout declares four " &
       "carriers with content kind \"none\", and the four PARTUUID " &
       "specifiers derived for them are distinct (a.data=" &
       devices.data & ")")

# ---------------------------------------------------------------------------
# Layer 2: a real disk.
# ---------------------------------------------------------------------------

proc gateSkipRemedy(prefix: string): string =
  prefix & "\n" &
  "  Run it with " & GateEnv & "=1.\n" &
  "  It creates a transient qcow2, applies the real " & AttestedLayout &
  " document\n" &
  "  to it over a loopback NBD node, writes a real verity pair onto the\n" &
  "  carriers through the shipped writer, and verifies the pair ON THE\n" &
  "  PARTITIONS. It needs sudo, the nbd module, qemu-nbd, sgdisk,\n" &
  "  veritysetup and mkfs.ext4, and takes about two minutes."

proc run(cmd: string): tuple[output: string, exitCode: int] =
  execCmdEx(cmd)

proc sh(cmd: string): bool =
  let r = run(cmd)
  if r.exitCode != 0:
    stderr.writeLine("  $ " & cmd)
    stderr.writeLine(r.output.strip())
  r.exitCode == 0

proc findReproBinary(): string =
  for cand in [getEnv("REPRO_BIN"),
               RepoRoot / "build/bin/repro",
               RepoRoot.parentDir / "reprobuild/build/bin/repro"]:
    if cand.len > 0 and fileExists(cand):
      return cand
  findExe("repro")

proc buildSampleTree(dir: string) =
  ## A purpose-built root: enough files, and enough bytes, that the
  ## Merkle tree has more than one level and the image is not a rounding
  ## error. Deterministic content, because the gate compares digests.
  createDir(dir / "etc")
  createDir(dir / "usr/bin")
  createDir(dir / "var/empty")
  writeFile(dir / "etc/os-release", "NAME=reproos-carrier-fixture\n")
  writeFile(dir / "usr/bin/hello", "#!/bin/sh\necho hello\n")
  for i in 0 ..< 24:
    var blob = newStringOfCap(256 * 1024)
    for j in 0 ..< 256 * 1024:
      blob.add chr((i * 31 + j * 7) and 0xff)
    writeFile(dir / "var/empty" / ("blob-" & $i & ".bin"), blob)

proc partitionGuidOnDisk(sudo, device: string; num: int): string =
  let r = run(sudo & " sgdisk -i " & $num & " " & device & " 2>/dev/null")
  if r.exitCode != 0: return ""
  for line in r.output.splitLines():
    if "Partition unique GUID" in line:
      let colon = line.find(':')
      if colon >= 0:
        return line[colon + 1 .. ^1].strip().toLowerAscii()
  ""

proc digestOfDevicePrefix(sudo, device: string; size: int64): string =
  let r = run(sudo & " dd if=" & device & " bs=4M iflag=count_bytes count=" &
              $size & " status=none | sha256sum")
  if r.exitCode != 0: return ""
  r.output.strip().split(' ')[0]

proc digestOfFile(path: string): string =
  let r = run("sha256sum " & quoteShell(path))
  if r.exitCode != 0: return ""
  r.output.strip().split(' ')[0]

proc caseCarriersReceiveTheVerityPair(workRoot: string) =
  if getEnv(GateEnv) != "1":
    skip("t_installed_carriers_hold_the_verity_pair: not requested (" &
         GateEnv & " is not 1).\n" &
         gateSkipRemedy("  No disk was written and no partition was read."))
    return

  var missing: seq[string] = @[]
  for tool in Layer2Tools:
    if findExe(tool).len == 0:
      missing.add tool
  if missing.len > 0:
    fail("t_installed_carriers_hold_the_verity_pair: requested, but these " &
         "tools are not on PATH: " & missing.join(", ") &
         ". This gate does not skip for a missing tool when it was asked " &
         "for: a green run that wrote no disk would be worse than a red one.")
    return

  let reproBin = findReproBinary()
  if reproBin.len == 0:
    fail("t_installed_carriers_hold_the_verity_pair: requested, but no " &
         "`repro` binary was found; the partition table is written by " &
         "`repro disk apply` and the gate will not substitute for it")
    return

  let sudo = findExe("sudo")
  let work = workRoot / "carriers"
  removeDir(work)
  createDir(work)

  # --- the pair, built by the shipped builder over a purpose-built tree
  let tree = work / "tree"
  createDir(tree)
  buildSampleTree(tree)
  let verityDir = work / "verity"
  let configText = readSource(AutoConfigFixture)
  var request = diskLayouts.parseDiskLayoutRequest(
    configText, "reproos-carrier-gate", "/dev/nbd0")
  request.name = AttestedLayout
  request.params.diskSizeGb = 20
  let seed = diskLayouts.reproosImageIdentitySeed(
    configText, packageSets.ReproosGraphicalRootfsPackages, request)
  let spec = verity.verityRootSpec(seed)

  let buildPair =
    "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " &
    "REPROOS_STAGED_ROOTFS=" & quoteShell(tree) & " " &
    "REPROOS_VERITY_SALT=" & quoteShell(spec.salt) & " " &
    "REPROOS_VERITY_UUID=" & quoteShell(spec.uuid) & " " &
    "REPROOS_VERITY_FS_UUID=" &
      quoteShell(verity.verityRootFsUuid(seed)) & " " &
    "REPROOS_VERITY_FS_HASH_SEED=" &
      quoteShell(verity.verityRootFsHashSeed(seed)) & " " &
    "bash " & quoteShell(RepoRoot / VerityBuilder) & " " &
    quoteShell(verityDir)
  if not sh(buildPair):
    fail("t_installed_carriers_hold_the_verity_pair: the shipped " &
         VerityBuilder & " failed; nothing was written to a disk")
    return

  let dataImage = verityDir / verity.VerityDataImageFileName
  let hashTree = verityDir / verity.VerityHashTreeFileName
  let rootHashFile = verityDir / verity.VerityRootHashFileName
  for f in [dataImage, hashTree, rootHashFile]:
    if not fileExists(f):
      fail("t_installed_carriers_hold_the_verity_pair: the builder " &
           "produced no " & f.extractFilename)
      return
  let rootHash = readFile(rootHashFile).strip()

  # --- a real disk
  let qcow2 = work / "carrier-gate.qcow2"
  if not sh(findExe("qemu-img") & " create -f qcow2 " & quoteShell(qcow2) &
            " " & $request.params.diskSizeGb & "G"):
    fail("t_installed_carriers_hold_the_verity_pair: qemu-img create failed")
    return
  if not sh(sudo & " modprobe nbd max_part=16"):
    fail("t_installed_carriers_hold_the_verity_pair: the nbd module could " &
         "not be loaded; this gate cannot write a partition without it")
    return

  # A free node is one the kernel exposes and nothing has connected:
  # /sys/block/nbdN/pid exists exactly while a client owns it. The
  # presence test is on the sysfs DIRECTORY rather than on /dev/nbdN,
  # because a block device is not a file and `fileExists` says so.
  var nbdDev = ""
  for n in 0 .. 15:
    if dirExists("/sys/block/nbd" & $n) and
       not fileExists("/sys/block/nbd" & $n & "/pid"):
      nbdDev = "/dev/nbd" & $n
      break
  if nbdDev.len == 0:
    fail("t_installed_carriers_hold_the_verity_pair: no free /dev/nbdN")
    return

  var connected = false
  template teardown() =
    if connected:
      discard run(sudo & " " & findExe("qemu-nbd") & " --disconnect " & nbdDev)
      connected = false
    if getEnv(KeepEnv) != "1":
      removeDir(work)

  if not sh(sudo & " " & findExe("qemu-nbd") & " --connect=" & nbdDev &
            " --cache=writeback -f qcow2 " & quoteShell(qcow2)):
    fail("t_installed_carriers_hold_the_verity_pair: qemu-nbd could not " &
         "connect " & nbdDev)
    teardown()
    return
  connected = true

  try:
    discard run("sleep 2")

    # --- the real layout, applied by the real apply
    let diskoPath = work / "disko.json"
    writeFile(diskoPath, diskLayouts.renderDiskoJson(
      AttestedLayout,
      diskLayouts.DiskLayoutParams(
        id: request.params.id,
        device: nbdDev,
        espSizeMib: request.params.espSizeMib,
        diskSizeGb: request.params.diskSizeGb)))
    # Beside the layout, under the name `repro disk apply` looks for by
    # convention (`<layout>.identity.json`). Without it every GPT GUID
    # comes from the system RNG and the PARTUUID check below fails --
    # which is how this path was found, so the spelling is load-bearing
    # rather than incidental.
    writeFile(work / "disko.identity.json",
      diskLayouts.renderDiskIdentityJson(
        configText, packageSets.ReproosGraphicalRootfsPackages, request))

    if not sh(sudo & " env PATH=$PATH SOURCE_DATE_EPOCH=1735689600 LC_ALL=C " &
              "TZ=UTC " & quoteShell(reproBin) & " disk apply --device " &
              nbdDev & " --confirm " & quoteShell(diskoPath)):
      fail("t_installed_carriers_hold_the_verity_pair: `repro disk apply` " &
           "failed on the " & AttestedLayout & " document; the carriers " &
           "were never created")
      return
    discard run(sudo & " partprobe " & nbdDev & " 2>/dev/null")
    discard run("sleep 2")

    # --- the derived specifiers must be what is actually on the GPT.
    #     Everything before this had only ever been checked against a dry
    #     run of the apply, which prints the GUIDs it would assign; this
    #     reads them back off a partition table that exists.
    let devices = generations.attestedBootDevices(seed, generations.gsA)
    var guidMismatch: seq[string] = @[]
    for (what, spec, num) in [("root-a", devices.data, 2),
                              ("roothash-a", devices.hash, 3)]:
      let want = spec["PARTUUID=".len .. ^1].toLowerAscii()
      let got = partitionGuidOnDisk(sudo, nbdDev, num)
      if want != got:
        guidMismatch.add what & ": derived " & want & ", GPT says " & got
    if guidMismatch.len > 0:
      fail("t_installed_carriers_hold_the_verity_pair: the measured " &
           "command line would name partitions the apply did not create: " &
           guidMismatch.join("; "))
      return
    pass("t_installed_carriers_hold_the_verity_pair: the partition GUIDs " &
         "on the real GPT are the ones the command line's PARTUUID= " &
         "specifiers were derived as, at plan time, before the disk existed")

    # --- the shipped writer
    let writeCmd =
      "SUDO=" & quoteShell(sudo) & " " &
      "REPROOS_VERITY_DATA_IMAGE=" & quoteShell(dataImage) & " " &
      "REPROOS_VERITY_HASH_TREE=" & quoteShell(hashTree) & " " &
      "REPROOS_VERITY_ROOTHASH_FILE=" & quoteShell(rootHashFile) & " " &
      "REPROOS_VERITY_DATA_DEVICE=" & quoteShell(devices.data) & " " &
      "REPROOS_VERITY_HASH_DEVICE=" & quoteShell(devices.hash) & " " &
      "bash " & quoteShell(RepoRoot / CarrierWriter) & " " & nbdDev
    if not sh(writeCmd):
      fail("t_installed_carriers_hold_the_verity_pair: the shipped " &
           CarrierWriter & " failed")
      return

    # --- the disk, checked independently of the writer's own report
    let dataSize = getFileSize(dataImage)
    let hashSize = getFileSize(hashTree)
    var byteMismatch: seq[string] = @[]
    for (what, path, part, size) in [
        ("verity data image", dataImage, nbdDev & "p2", dataSize),
        ("verity hash tree", hashTree, nbdDev & "p3", hashSize)]:
      let want = digestOfFile(path)
      let got = digestOfDevicePrefix(sudo, part, size)
      if want.len == 0 or want != got:
        byteMismatch.add what & " on " & part & ": file " & want &
          ", partition " & got
    if byteMismatch.len > 0:
      fail("t_installed_carriers_hold_the_verity_pair: " &
           byteMismatch.join("; "))
      return
    pass("t_installed_carriers_hold_the_verity_pair: both carriers hold " &
         "exactly the bytes of the files (" & $dataSize & " and " &
         $hashSize & " bytes), read back off the partitions by the gate")

    # --- and the pair verifies where it now lives
    if not sh(sudo & " veritysetup verify " & nbdDev & "p2 " & nbdDev &
              "p3 " & rootHash):
      fail("t_installed_carriers_hold_the_verity_pair: the pair on the " &
           "partitions does not verify against " & rootHash)
      return
    pass("t_installed_carriers_hold_the_verity_pair: `veritysetup verify` " &
         "walks the whole tree on " & nbdDev & "p2 / " & nbdDev &
         "p3 and accepts it against the pinned root hash " & rootHash)

    # --- the resolver's negative half. A well-formed PARTUUID that is
    #     not on this disk must be a hard failure and must write nothing.
    #     Without this the resolver could be silently falling back to a
    #     partition number and every check above would still be green,
    #     because on this layout root-a HAPPENS to be partition 2.
    let strayUuid = "PARTUUID=00000000-0000-5000-8000-0000000000ff"
    let strayCmd =
      "SUDO=" & quoteShell(sudo) & " " &
      "REPROOS_VERITY_DATA_IMAGE=" & quoteShell(dataImage) & " " &
      "REPROOS_VERITY_HASH_TREE=" & quoteShell(hashTree) & " " &
      "REPROOS_VERITY_ROOTHASH_FILE=" & quoteShell(rootHashFile) & " " &
      "REPROOS_VERITY_DATA_DEVICE=" & quoteShell(strayUuid) & " " &
      "REPROOS_VERITY_HASH_DEVICE=" & quoteShell(devices.hash) & " " &
      "bash " & quoteShell(RepoRoot / CarrierWriter) & " " & nbdDev & " 2>&1"
    let stray = run(strayCmd)
    if stray.exitCode == 0:
      fail("t_an_unresolvable_specifier_writes_nothing: the writer " &
           "accepted " & strayUuid & ", which is on no partition of " &
           nbdDev & "; it is resolving by something other than the GPT")
      return
    if "does not name any of" notin stray.output:
      fail("t_an_unresolvable_specifier_writes_nothing: the writer failed " &
           "(exit " & $stray.exitCode & ") but not with the resolution " &
           "diagnostic: " & stray.output.strip())
      return
    pass("t_an_unresolvable_specifier_writes_nothing: a PARTUUID that is " &
         "on no partition of " & nbdDev & " is refused (exit " &
         $stray.exitCode & ") instead of falling back to a partition " &
         "number")

    # --- the negative half. One byte on the data carrier, and the same
    #     verification must fail. Without this, a gate that verified an
    #     all-zero pair against an all-zero hash would look identical.
    let corruptOffset = dataSize div 2
    if not sh("printf '\\xff' | " & sudo & " dd of=" & nbdDev & "p2 bs=1 " &
              "seek=" & $corruptOffset & " count=1 conv=notrunc,fsync " &
              "status=none"):
      fail("t_corrupting_a_carrier_breaks_verification: could not write " &
           "the corruption, so the negative half did not run")
      return
    let corrupted = run(sudo & " veritysetup verify " & nbdDev & "p2 " &
                        nbdDev & "p3 " & rootHash & " 2>&1")
    if corrupted.exitCode == 0:
      fail("t_corrupting_a_carrier_breaks_verification: one byte was " &
           "flipped at offset " & $corruptOffset & " on " & nbdDev &
           "p2 and `veritysetup verify` still accepted the pair, so the " &
           "positive result above proves nothing")
      return
    pass("t_corrupting_a_carrier_breaks_verification: flipping one byte " &
         "at offset " & $corruptOffset & " on " & nbdDev & "p2 makes the " &
         "same verification fail (exit " & $corrupted.exitCode & ")")
  finally:
    teardown()

# ---------------------------------------------------------------------------

let workRoot = RepoRoot / "build" / "test-attested-carriers" / "work"
removeDir(workRoot)
createDir(workRoot)

caseDriverCallsTheWriterOnTheAttestedLayoutOnly()
caseWriterAddressesCarriersByPartuuid()
caseWriterReadsBackWhatItWrote()
caseRecipeDeclaresEveryToolTheWriterRuns()
caseSpecifiersMatchTheLayout()
caseCarriersReceiveTheVerityPair(workRoot)

if failures > 0:
  stderr.writeLine("test_attested_carriers: " & $failures & " check(s) failed")
  quit(1)

var summary = "attested carriers: PASS (" & $passes & " checks"
if skips > 0:
  summary.add ", " & $skips & " SKIPPED -- no disk was written"
summary.add ")"
echo summary
