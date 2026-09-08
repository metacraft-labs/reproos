## Generations of an attested ReproOS, and the boot-time store that holds
## them.
##
## ## Why this module exists
##
## Atomic generation switching is the core ReproOS experience: build a new
## configuration, switch to it, roll back if it is wrong. On an *attested*
## machine that shape has to become stricter, and the reason is not policy —
## it is arithmetic.
##
## The launch measurement is taken **once, at boot**, over the boot artifact
## the firmware loaded: the unified kernel image, whose command line pins the
## dm-verity root hash of the root filesystem (``repro/uki.nim``,
## ``repro/verity.nim``). Nothing extends it afterwards. So a generation
## switched *while the machine is running* would not appear in it: the
## machine would be running configuration B while every report it produced
## said A. That is not a degraded guarantee, it is a false one — an
## attestation that is a lie about what is executing is worse than no
## attestation, because a verifier acts on it.
##
## Therefore:
##
##   * **An attested instance boots one generation and keeps it for the
##     lifetime of that boot.** There is no in-place switch, and this module
##     contains no code that performs one.
##   * **Applying a new configuration STAGES it and requires a reboot.** The
##     new unified kernel image and its verity pair are written to the slot
##     the machine is *not* running from, the next boot is pointed at them,
##     and the operation reports ``reboot-required``. The instance re-attests
##     under the new measurement after the reboot.
##   * **Rollback stays atomic.** The previous unified kernel image and its
##     verity pair remain in place and selectable, and a machine booted back
##     onto them re-attests under the *old* measurement — which identifies it
##     honestly as the old configuration, because the old command line, with
##     the old root hash, is what the firmware measured.
##
## ## The two slots
##
## Two generations must be able to exist at once, or "the previous pair stays
## selectable" is not implementable. So the attested layout carries two of
## everything a generation needs: two root carriers and two Merkle-tree
## volumes (``repro/disk_layouts.nim``), and the ESP carries two unified
## kernel images. The slots are named ``a`` and ``b`` and neither is
## privileged: which one is *current* is a property of the store, not of the
## partition table.
##
## ## What decides the boot, and what merely describes it
##
## Exactly one thing decides which generation boots: **the bytes at the
## removable-media fallback path** (``EFI/BOOT/BOOTX64.EFI``), because that
## is what UEFI loads and what the firmware measures. The index this module
## writes beside the slots is *metadata* — it lets an operator and a stager
## see which slot holds which generation and which one is selected — and the
## firmware never reads it. That asymmetry is deliberate and it is worth
## stating, because it is what makes the store unable to lie: an index that
## claimed a generation the fallback bytes do not match is a store this
## module *refuses* (``verifyGenerationStore``), and a machine booted from
## such a store would report what it actually ran regardless of what the
## index said.
##
## ## How a generation is named
##
## By the sha256 of its unified kernel image. That digest covers the kernel,
## the initrd, the pinned stub and the command line — and the command line
## pins the verity root hash, so the digest transitively names every byte of
## the root filesystem too. It is not a PCR value and nothing here computes
## one; it is the identity of the artifact whose measurement a verifier
## checks.
##
## ## Where the verity pair goes
##
## A generation is a *pair*: the unified kernel image and the read-only root
## it names. The image lives on the ESP; the root's data image and its Merkle
## tree live on that slot's two carrier volumes, named on the measured
## command line. This module declares which volumes those are, per slot, and
## refuses to stage a unified kernel image whose measured command line does
## not name the volumes of the slot it is being staged into. Writing the two
## images onto those volumes is block-device work the image driver does not
## do yet, which is why ``uefi-attested`` is still refused at plan time.
##
## ## Why the volumes are named by partition GUID and not by filesystem label
##
## A dm-verity hash device carries **no filesystem**, so it has no filesystem
## label and ``findfs LABEL=…`` can never resolve it — and with two root
## slots present, both carriers hold an ext4 image with the *same* label, so
## a label does not name one device either. Both are therefore named by
## ``PARTUUID=``, which the partition table sets and the initramfs resolves.
## The values are derived from the build's identity seed by the same RFC 4122
## v5 construction ``repro disk apply`` uses to assign them, so the command
## line can name the exact partitions the layout will create, before either
## exists.
##
## ## No mocking
##
## Every proc here is a pure function of its arguments except the store
## operations, which read and write real files under a directory the caller
## names. Nothing executes anything, and nothing reboots anything.

import std/[json, os, sha1, strutils]

import repro_profile/disk_identity

import "./uki" as uki
import "./verity" as verity

# ---------------------------------------------------------------------
# Slots.
# ---------------------------------------------------------------------

type
  GenerationSlot* = enum
    ## Which of the two generation slots a generation occupies. Neither is
    ## privileged; ``a`` is only the one an image is first installed into.
    gsA = "a"
    gsB = "b"

proc otherSlot*(slot: GenerationSlot): GenerationSlot =
  if slot == gsA: gsB else: gsA

const
  AttestedDiskName* = "main"
    ## The disk the attested layout declares. Named here because the
    ## partition GUID derivation is keyed on it and a second spelling of
    ## it would silently derive different identifiers.

  StateVarLabel* = "reproos-var"
  StateHomeLabel* = "reproos-home"
    ## The state volumes. These DO carry filesystems the layout creates, so
    ## a filesystem label names them, and there is one of each rather than
    ## one per slot: mutable state survives a generation switch, which is
    ## the whole point of keeping it off the measured surface.

  AttestedRootFsLabel* = "reproos-root"
    ## The ext4 label inside the verity data image itself, written by
    ## ``build-verity-root.sh``. It is NOT how the boot path names the
    ## carrier volume — with two slots staged, both carriers hold an image
    ## with this label, so it names two devices. It is recorded here so the
    ## collision is documented rather than rediscovered.

proc rootPartitionName*(slot: GenerationSlot): string =
  ## The layout's name for the carrier the verity DATA image is written to.
  "root-" & $slot

proc hashPartitionName*(slot: GenerationSlot): string =
  ## The layout's name for the carrier the verity Merkle TREE is written to.
  "roothash-" & $slot

# ---------------------------------------------------------------------
# The volumes one generation's command line names.
# ---------------------------------------------------------------------

type
  AttestedBootDevices* = object
    ## The volumes an attested command line names. Every field is a
    ## specifier the initramfs' ``resolve_spec`` understands.
    data*: string      ## the verity data image's carrier
    hash*: string      ## the Merkle tree's carrier
    stateVar*: string
    stateHome*: string

proc partitionUuid*(seed: string; partitionName: string): string =
  ## The GPT partition GUID ``repro disk apply`` will assign to
  ## ``partitionName``, derived from this build's identity seed.
  ##
  ## This is the same derivation the apply driver performs, taken here so
  ## the value can be put on a command line at PLAN time — before the
  ## partition, the image or the machine exists. An empty seed derives
  ## nothing, which every caller reads as "this build is not reproducible"
  ## and refuses rather than papering over.
  deriveUuid(DiskIdentity(seed: seed),
             partitionGuidPurpose(AttestedDiskName, partitionName))

proc attestedBootDevices*(seed: string;
                          slot: GenerationSlot): AttestedBootDevices =
  ## How the command line of a generation in ``slot`` names its volumes.
  AttestedBootDevices(
    data: "PARTUUID=" & partitionUuid(seed, rootPartitionName(slot)),
    hash: "PARTUUID=" & partitionUuid(seed, hashPartitionName(slot)),
    stateVar: "LABEL=" & StateVarLabel,
    stateHome: "LABEL=" & StateHomeLabel)

proc validateAttestedBootDevices*(devices: AttestedBootDevices): string =
  ## "" when the four specifiers are ones a boot could resolve.
  for (what, spec) in [("verity data device", devices.data),
                       ("verity hash device", devices.hash),
                       ("/var volume", devices.stateVar),
                       ("/home volume", devices.stateHome)]:
    if spec.len == 0:
      return "the " & what & " has no specifier; a build with no identity " &
        "seed derives no partition GUIDs, and a command line naming an " &
        "empty device would fail at boot rather than at build time"
    var value = ""
    for prefix in ["PARTUUID=", "LABEL=", "UUID="]:
      if spec.startsWith(prefix):
        value = spec[prefix.len .. ^1]
    if value.len == 0:
      return "the " & what & " is named " & spec.escape() & "; the " &
        "initramfs resolves LABEL=, UUID= and PARTUUID= and nothing else, " &
        "so any other spelling is a device that never appears"
  if devices.data == devices.hash:
    return "the verity data device and the Merkle tree device are the same " &
      "volume (" & devices.data & "); the tree is taken over the data " &
      "image's bytes, so it cannot live inside them"
  if devices.hash.startsWith("LABEL="):
    return "the Merkle tree device is named " & devices.hash.escape() &
      ", and a filesystem label can never resolve it: a dm-verity hash " &
      "device carries the verity superblock and the tree, not a " &
      "filesystem, so it has no label for findfs to match. Name it by " &
      "PARTUUID=, which the partition table sets and the initramfs " &
      "resolves."
  if devices.data.startsWith("LABEL="):
    return "the verity data device is named " & devices.data.escape() &
      ", and with two generation slots staged both carriers hold an ext4 " &
      "image with the same label (" & AttestedRootFsLabel & "), so a " &
      "label names two devices and findfs returns whichever it saw " &
      "first. Name it by PARTUUID=."
  ""

# ---------------------------------------------------------------------
# The identity of one generation.
# ---------------------------------------------------------------------

const
  GenerationIdPrefix* = "reproos-gen-"
  GenerationIdDigestChars* = 16
    ## A generation is named by the sha256 of its unified kernel image,
    ## truncated for legibility. The FULL digest is recorded beside it in
    ## the store and is what every comparison uses; the short form exists
    ## so an operator can say which generation is running out loud.

proc generationIdFor*(ukiDigest: string): string =
  ## The generation id of a unified kernel image with this digest.
  if ukiDigest.len < GenerationIdDigestChars:
    return ""
  GenerationIdPrefix & ukiDigest[0 ..< GenerationIdDigestChars]

# ---------------------------------------------------------------------
# The store on the ESP.
# ---------------------------------------------------------------------

const
  GenerationStoreDir* = "EFI/reproos"
    ## Where the staged unified kernel images live on the ESP, beside —
    ## never inside — ``EFI/BOOT``. The fallback binary UEFI loads is a
    ## COPY of one of them; nothing here is a loader configuration file and
    ## no firmware reads this directory.

  GenerationIndexFileName* = "generations.json"
  GenerationStoreSchema* = "reproos.generation-store.v1"

proc generationStoreDir*(espRoot: string): string =
  espRoot / GenerationStoreDir

proc generationSlotDir*(espRoot: string; slot: GenerationSlot): string =
  generationStoreDir(espRoot) / $slot

proc generationUkiPath*(espRoot: string; slot: GenerationSlot): string =
  ## Where the unified kernel image of the generation in ``slot`` is kept.
  generationSlotDir(espRoot, slot) / uki.UkiFileName

proc generationIndexPath*(espRoot: string): string =
  generationStoreDir(espRoot) / GenerationIndexFileName

proc espFallbackPath*(espRoot: string): string =
  ## The one path that decides the boot.
  espRoot / uki.UkiEspFallbackPath

type
  GenerationRef* = object
    ## One staged generation, as the store records it.
    slot*: GenerationSlot
    id*: string
    sequence*: int
      ## Monotonic staging order. It is what makes "the previous
      ## generation" a fact rather than a guess, and it is NOT renumbered
      ## by a rollback — a rolled-back machine is running the older
      ## configuration and the store says so.
    ukiDigest*: string
    ukiSize*: int
    verityRootHash*: string
    dataDevice*: string
    hashDevice*: string

  GenerationStore* = object
    espRoot*: string
    entries*: seq[GenerationRef]   ## at most one per slot
    current*: GenerationSlot
    hasCurrent*: bool
    nextSequence*: int

  GenerationOperation* = enum
    goStage = "stage"
    goRollback = "rollback"
    goActivateNow = "activate-now"
      ## The live switch. It exists as a named operation precisely so that
      ## refusing it is something a caller can ASK for and be told no,
      ## rather than a capability that is merely absent.

  GenerationOutcome* = object
    operation*: GenerationOperation
    selected*: GenerationRef      ## what the next boot will run
    previous*: GenerationRef      ## what stays selectable
    hasPrevious*: bool
    rebootRequired*: bool
    runningUnchanged*: bool
      ## Always true for the operations this module performs: none of them
      ## touches the generation the machine is executing.

proc entryFor*(store: GenerationStore;
               slot: GenerationSlot): GenerationRef =
  for e in store.entries:
    if e.slot == slot:
      return e
  GenerationRef()

proc hasEntry*(store: GenerationStore; slot: GenerationSlot): bool =
  for e in store.entries:
    if e.slot == slot:
      return true
  false

proc currentEntry*(store: GenerationStore): GenerationRef =
  if store.hasCurrent: store.entryFor(store.current) else: GenerationRef()

proc nextStagingSlot*(store: GenerationStore): GenerationSlot =
  ## The slot a new generation is staged into: the one the machine is not
  ## running from. This is the whole of the A/B discipline — staging into
  ## the current slot would overwrite the artifacts of the generation that
  ## is executing, which is what makes rollback impossible and what
  ## ``validateStageTarget`` refuses.
  if store.hasCurrent: otherSlot(store.current) else: gsA

# ---------------------------------------------------------------------
# The index. Hand-rendered in a fixed key order, parsed with the standard
# decoder — the same split the other artifact manifests in this project
# use, because the bytes are compared and an encoder's key order is not
# something to depend on.
# ---------------------------------------------------------------------

proc renderGenerationIndex*(store: GenerationStore): string =
  var lines: seq[string] = @[]
  for slot in [gsA, gsB]:
    if not store.hasEntry(slot): continue
    let e = store.entryFor(slot)
    lines.add "    {\"slot\": \"" & $e.slot & "\", " &
      "\"id\": \"" & e.id & "\", " &
      "\"sequence\": " & $e.sequence & ", " &
      "\"ukiDigest\": \"" & e.ukiDigest & "\", " &
      "\"ukiSize\": " & $e.ukiSize & ", " &
      "\"verityRootHash\": \"" & e.verityRootHash & "\", " &
      "\"verityDataDevice\": \"" & e.dataDevice & "\", " &
      "\"verityHashDevice\": \"" & e.hashDevice & "\"}"
  "{\n" &
  "  \"schema\": \"" & GenerationStoreSchema & "\",\n" &
  "  \"current\": \"" & (if store.hasCurrent: $store.current else: "") &
    "\",\n" &
  "  \"nextSequence\": " & $store.nextSequence & ",\n" &
  "  \"generations\": [\n" & lines.join(",\n") &
    (if lines.len > 0: "\n" else: "") & "  ]\n" &
  "}\n"

proc parseGenerationIndex*(espRoot, text: string): GenerationStore =
  ## Raises ``ValueError`` naming what is wrong. A store that cannot be
  ## understood is not treated as an empty one: the difference between "no
  ## generations" and "an index this build cannot read" is the difference
  ## between a first install and a downgrade, and guessing would overwrite
  ## a generation somebody may need.
  result.espRoot = espRoot
  var doc: JsonNode
  try:
    doc = parseJson(text)
  except CatchableError as e:
    raise newException(ValueError,
      "the generation index is not readable JSON: " & e.msg)
  if doc.kind != JObject or not doc.hasKey("schema"):
    raise newException(ValueError,
      "the generation index has no " & GenerationStoreSchema.escape() &
      " schema field")
  if doc["schema"].getStr() != GenerationStoreSchema:
    raise newException(ValueError,
      "the generation index declares schema " &
      doc["schema"].getStr().escape() & ", which this build does not " &
      "know; it understands " & GenerationStoreSchema.escape() & " only")
  let cur = (if doc.hasKey("current"): doc["current"].getStr() else: "")
  case cur
  of "":  result.hasCurrent = false
  of "a": result.hasCurrent = true; result.current = gsA
  of "b": result.hasCurrent = true; result.current = gsB
  else:
    raise newException(ValueError,
      "the generation index names slot " & cur.escape() &
      " as current; the only slots are \"a\" and \"b\"")
  result.nextSequence =
    if doc.hasKey("nextSequence"): doc["nextSequence"].getInt() else: 0
  if doc.hasKey("generations"):
    for node in doc["generations"]:
      var e: GenerationRef
      let slotText = node{"slot"}.getStr()
      case slotText
      of "a": e.slot = gsA
      of "b": e.slot = gsB
      else:
        raise newException(ValueError,
          "the generation index carries an entry for slot " &
          slotText.escape() & "; the only slots are \"a\" and \"b\"")
      if result.hasEntry(e.slot):
        raise newException(ValueError,
          "the generation index carries two entries for slot " & slotText)
      e.id = node{"id"}.getStr()
      e.sequence = node{"sequence"}.getInt()
      e.ukiDigest = node{"ukiDigest"}.getStr()
      e.ukiSize = node{"ukiSize"}.getInt()
      e.verityRootHash = node{"verityRootHash"}.getStr()
      e.dataDevice = node{"verityDataDevice"}.getStr()
      e.hashDevice = node{"verityHashDevice"}.getStr()
      result.entries.add e
  if result.hasCurrent and not result.hasEntry(result.current):
    raise newException(ValueError,
      "the generation index selects slot " & $result.current &
      ", which holds no generation")

proc readGenerationStore*(espRoot: string): GenerationStore =
  ## The store as it is on disk. An ESP with no store yet reads back as an
  ## empty store, which is what a first install writes into.
  let indexPath = generationIndexPath(espRoot)
  if not fileExists(indexPath):
    return GenerationStore(espRoot: espRoot, hasCurrent: false,
                           nextSequence: 1)
  result = parseGenerationIndex(espRoot, readFile(indexPath))
  if result.nextSequence <= 0:
    result.nextSequence = 1

# ---------------------------------------------------------------------
# The refusals. These are the whole of what stops an attested machine
# switching a generation under itself.
# ---------------------------------------------------------------------

proc validateStageTarget*(store: GenerationStore; slot: GenerationSlot;
                          attested: bool): string =
  ## "" when a generation may be written into ``slot``, otherwise the
  ## operator-facing reason.
  ##
  ## THE REFUSAL THIS MODULE EXISTS FOR. On an attested machine the slot
  ## being executed is off limits, always: its unified kernel image is the
  ## artifact the launch measurement was taken over, and its verity pair is
  ## the root the running kernel is reading through. Writing a new
  ## generation there would replace both while the machine kept executing
  ## the old one — every subsequent report would attest a configuration
  ## that is not what is running, and the previous pair rollback needs
  ## would be gone as well.
  ##
  ## The refusal is keyed on ATTESTATION, not on the operation: staging
  ## into the other slot is accepted on the same machine, in the same call,
  ## and the same write into the same slot is accepted when nothing is
  ## measured. A guard that refused everything would be indistinguishable
  ## from a feature that was never implemented.
  if not store.hasCurrent:
    return ""
  if slot != store.current:
    return ""
  if not attested:
    return ""
  let running = store.currentEntry()
  "refusing to write generation slot " & $slot & " while it is the " &
    "running generation (" & running.id & ").\n" &
    "  The launch measurement of this boot was taken over that slot's " &
    "unified kernel image and covers the root hash on its command line. " &
    "Replacing it now would leave the machine executing a configuration " &
    "no measurement describes, and would destroy the pair a rollback " &
    "needs.\n" &
    "  An attested instance runs one generation for the lifetime of a " &
    "boot. Stage into slot " & $otherSlot(slot) & " and reboot; the " &
    "instance re-attests under the new measurement afterwards."

proc validateGenerationUki*(image: string; rootHash: string;
                            devices: AttestedBootDevices): string =
  ## "" when ``image`` is a unified kernel image that may be staged as a
  ## generation whose root is ``rootHash`` on ``devices``.
  ##
  ## The command line inside the image is the authority, not the caller's
  ## claim about it: it is what firmware measures and what the kernel
  ## receives. So the store checks the artifact rather than recording what
  ## it was told.
  var cmdline: string
  try:
    cmdline = uki.ukiCmdline(image)
  except CatchableError as e:
    return "the staged artifact is not a readable unified kernel image: " &
      e.msg
  if cmdline.len == 0:
    return "the staged unified kernel image carries no " &
      uki.UkiCmdlineSection & " section, so nothing pins the root it " &
      "expects and nothing measures the root it gets"
  let cmdlineError = uki.validateAttestedCmdline(cmdline, rootHash)
  if cmdlineError.len > 0:
    return cmdlineError
  let deviceError = validateAttestedBootDevices(devices)
  if deviceError.len > 0:
    return deviceError
  if (verity.VerityDataDeviceCmdlineKey & "=" & devices.data) notin cmdline:
    return "the unified kernel image's measured command line does not name " &
      devices.data & " as its verity data device, so it belongs to a " &
      "different slot than the one it is being staged into; a generation " &
      "whose measured command line names another slot's volumes would " &
      "boot the wrong root or not boot at all"
  if (verity.VerityHashDeviceCmdlineKey & "=" & devices.hash) notin cmdline:
    return "the unified kernel image's measured command line does not name " &
      devices.hash & " as its Merkle tree device, so it belongs to a " &
      "different slot than the one it is being staged into"
  ""

# ---------------------------------------------------------------------
# Staging, selection and rollback.
# ---------------------------------------------------------------------

type
  GenerationStageRequest* = object
    ukiPath*: string
      ## The assembled unified kernel image to stage. Read here rather than
      ## handed over as bytes, because the digest that names the generation
      ## has to be taken over the artifact that is written.
    verityRootHash*: string
    devices*: AttestedBootDevices
    slot*: GenerationSlot
    attested*: bool
      ## Whether the target machine's boot is measured. It decides the
      ## refusal above and nothing else.

proc sha256Hex(s: string): string = uki.ukiDigest(s)

proc writeStore(store: GenerationStore) =
  createDir(generationStoreDir(store.espRoot))
  writeFile(generationIndexPath(store.espRoot),
            renderGenerationIndex(store))

proc selectSlot(store: var GenerationStore; slot: GenerationSlot) =
  ## Point the next boot at ``slot`` by making the fallback binary a copy
  ## of that slot's unified kernel image. A copy, not a symlink: FAT has no
  ## symlinks, and firmware loads bytes.
  let fallback = espFallbackPath(store.espRoot)
  createDir(fallback.parentDir())
  copyFile(generationUkiPath(store.espRoot, slot), fallback)
  store.current = slot
  store.hasCurrent = true

proc stageGeneration*(store: var GenerationStore;
                      request: GenerationStageRequest): GenerationOutcome =
  ## Write a generation into its slot and point the next boot at it.
  ##
  ## Raises ``ValueError`` with the operator-facing reason for anything it
  ## refuses. It performs NO live action: it writes files on the ESP and
  ## returns. The generation the machine is executing is untouched, which
  ## is what ``runningUnchanged`` records and what the caller reports.
  if not fileExists(request.ukiPath):
    raise newException(ValueError,
      "stageGeneration: no unified kernel image at " & request.ukiPath)
  let targetError = validateStageTarget(store, request.slot, request.attested)
  if targetError.len > 0:
    raise newException(ValueError, "stageGeneration: " & targetError)
  let image = readFile(request.ukiPath)
  let ukiError = validateGenerationUki(image, request.verityRootHash,
                                       request.devices)
  if ukiError.len > 0:
    raise newException(ValueError, "stageGeneration: " & ukiError)

  let previous = store.currentEntry()
  let hadPrevious = store.hasCurrent
  let digest = sha256Hex(image)
  var entry = GenerationRef(
    slot: request.slot,
    id: generationIdFor(digest),
    sequence: store.nextSequence,
    ukiDigest: digest,
    ukiSize: image.len,
    verityRootHash: request.verityRootHash,
    dataDevice: request.devices.data,
    hashDevice: request.devices.hash)

  createDir(generationSlotDir(store.espRoot, request.slot))
  writeFile(generationUkiPath(store.espRoot, request.slot), image)
  var kept: seq[GenerationRef] = @[]
  for e in store.entries:
    if e.slot != request.slot:
      kept.add e
  kept.add entry
  store.entries = kept
  store.nextSequence = store.nextSequence + 1
  store.selectSlot(request.slot)
  store.writeStore()

  GenerationOutcome(
    operation: (if hadPrevious and previous.slot == request.slot:
                  goActivateNow else: goStage),
    selected: entry,
    previous: previous,
    hasPrevious: hadPrevious and previous.slot != request.slot,
    rebootRequired: true,
    runningUnchanged: true)

proc rollbackGeneration*(store: var GenerationStore;
                         attested: bool): GenerationOutcome =
  ## Point the next boot back at the other slot.
  ##
  ## Nothing is rebuilt, nothing is copied out of an archive and nothing is
  ## renumbered: the previous generation's unified kernel image has been
  ## sitting in its slot the whole time, which is exactly why rollback is
  ## atomic. The sequence numbers are left alone so the store keeps saying
  ## which configuration is the older one — a machine rolled back is
  ## running the old configuration and re-attests as such.
  if not store.hasCurrent:
    raise newException(ValueError,
      "rollbackGeneration: this store holds no current generation, so " &
      "there is nothing to roll back from")
  let target = otherSlot(store.current)
  if not store.hasEntry(target):
    raise newException(ValueError,
      "rollbackGeneration: slot " & $target & " holds no generation, so " &
      "there is no previous configuration to roll back to. The current " &
      "generation (" & store.currentEntry().id & ") is the only one " &
      "staged; stage another before expecting to be able to leave it.")
  let leaving = store.currentEntry()
  let entry = store.entryFor(target)
  let ukiPath = generationUkiPath(store.espRoot, target)
  if not fileExists(ukiPath):
    raise newException(ValueError,
      "rollbackGeneration: the index records generation " & entry.id &
      " in slot " & $target & " but its unified kernel image is not on " &
      "the ESP (" & ukiPath & "); refusing to select a generation whose " &
      "boot artifact is missing")
  let onDisk = sha256Hex(readFile(ukiPath))
  if onDisk != entry.ukiDigest:
    raise newException(ValueError,
      "rollbackGeneration: the unified kernel image in slot " & $target &
      " has digest " & onDisk & ", not the " & entry.ukiDigest &
      " the index records for " & entry.id & "; the previous generation " &
      "is not the one the store claims and rolling back to it would boot " &
      "something nothing describes")
  discard attested
  store.selectSlot(target)
  store.writeStore()
  GenerationOutcome(
    operation: goRollback,
    selected: entry,
    previous: leaving,
    hasPrevious: true,
    rebootRequired: true,
    runningUnchanged: true)

# ---------------------------------------------------------------------
# Verification — what makes the index unable to lie.
# ---------------------------------------------------------------------

proc verifyGenerationStore*(store: GenerationStore): seq[string] =
  ## Every disagreement between what the index says and what is on the ESP.
  ## An empty result means the store describes itself truthfully.
  result = @[]
  if not store.hasCurrent:
    if store.entries.len > 0:
      result.add "the index holds " & $store.entries.len & " generation(s) " &
        "but selects none, so nothing says which one boots"
    return
  for e in store.entries:
    let path = generationUkiPath(store.espRoot, e.slot)
    if not fileExists(path):
      result.add "slot " & $e.slot & " records generation " & e.id &
        " but has no unified kernel image at " & path
      continue
    let bytes = readFile(path)
    let digest = sha256Hex(bytes)
    if digest != e.ukiDigest:
      result.add "slot " & $e.slot & " holds an image with digest " &
        digest & ", not the " & e.ukiDigest & " the index records"
      continue
    if generationIdFor(digest) != e.id:
      result.add "slot " & $e.slot & " records id " & e.id &
        " for an image whose digest names " & generationIdFor(digest)
    let cmdline = uki.ukiCmdline(bytes)
    if (verity.VerityRootHashCmdlineKey & "=" & e.verityRootHash) notin
        cmdline:
      result.add "the measured command line of " & e.id & " does not pin " &
        "the root hash " & e.verityRootHash & " the index records for it"
    if (verity.VerityDataDeviceCmdlineKey & "=" & e.dataDevice) notin cmdline:
      result.add "the measured command line of " & e.id & " does not name " &
        e.dataDevice & ", the verity data volume the index records"
  let fallback = espFallbackPath(store.espRoot)
  if not fileExists(fallback):
    result.add "there is no boot artifact at " & uki.UkiEspFallbackPath &
      ", so this ESP boots nothing"
    return
  let bootDigest = sha256Hex(readFile(fallback))
  let selected = store.currentEntry()
  if bootDigest != selected.ukiDigest:
    var owner = ""
    for e in store.entries:
      if e.ukiDigest == bootDigest:
        owner = " (they are " & e.id & ", in slot " & $e.slot & ")"
    result.add "the index selects " & selected.id & " but the bytes at " &
      uki.UkiEspFallbackPath & " have digest " & bootDigest & owner &
      "; the firmware loads those bytes and reads no index, so this " &
      "machine would boot a generation the store does not claim"

# ---------------------------------------------------------------------
# The report an apply prints.
# ---------------------------------------------------------------------

const RebootRequiredKey* = "reboot-required"
  ## The machine-readable half of the report. Spelled once so a caller
  ## greps for a constant rather than for prose.

proc renderGenerationOutcome*(outcome: GenerationOutcome): string =
  ## What an operator is told after a stage or a rollback.
  ##
  ## It says three things, and the third is the one that matters: what will
  ## run next, what stays available, and that NOTHING changed about what is
  ## running now. An operator who reads "applied" and assumes the machine
  ## switched would draw exactly the wrong conclusion from an attested
  ## instance.
  var lines: seq[string] = @[]
  lines.add "generation " & $outcome.operation
  lines.add "  next boot     : " & outcome.selected.id & "  (slot " &
    $outcome.selected.slot & ")"
  lines.add "  root hash     : " & outcome.selected.verityRootHash
  if outcome.hasPrevious:
    lines.add "  still staged  : " & outcome.previous.id & "  (slot " &
      $outcome.previous.slot & ") -- roll back to it with " &
      "`reproos-generation rollback`"
  else:
    lines.add "  still staged  : none -- this is the only generation on " &
      "this ESP, so there is nothing to roll back to yet"
  lines.add "  " & RebootRequiredKey & ": " &
    (if outcome.rebootRequired: "yes" else: "no")
  if outcome.runningUnchanged:
    lines.add "  The running generation is UNCHANGED. Its launch " &
      "measurement was taken at boot and nothing extends it, so a " &
      "generation switched underneath a running system would not appear " &
      "in any report it produced. Reboot to run the generation above; the " &
      "instance re-attests under its measurement afterwards."
  lines.join("\n") & "\n"

proc renderGenerationStatus*(store: GenerationStore): string =
  ## The store as an operator reads it.
  var lines: seq[string] = @[]
  lines.add "generation status"
  lines.add "  esp           : " & store.espRoot
  if not store.hasCurrent:
    lines.add "  selected      : none"
  else:
    lines.add "  selected      : " & store.currentEntry().id & "  (slot " &
      $store.current & ")"
  for slot in [gsA, gsB]:
    if not store.hasEntry(slot):
      lines.add "  slot " & $slot & "        : empty"
      continue
    let e = store.entryFor(slot)
    lines.add "  slot " & $slot & "        : " & e.id & "  seq " &
      $e.sequence & (if store.hasCurrent and store.current == slot:
                       "  <- next boot" else: "")
    lines.add "                  root " & e.verityRootHash
    lines.add "                  data " & e.dataDevice
    lines.add "                  hash " & e.hashDevice
  let problems = verifyGenerationStore(store)
  if problems.len == 0:
    lines.add "  verified      : the bytes at " & uki.UkiEspFallbackPath &
      " are the selected generation's"
  else:
    for p in problems:
      lines.add "  PROBLEM       : " & p
  lines.join("\n") & "\n"

# ---------------------------------------------------------------------
# The seed the generation store is derived under, for callers that have
# one. Kept here so that a consumer never re-implements the hashing.
# ---------------------------------------------------------------------

proc generationStoreFingerprint*(store: GenerationStore): string =
  ## A digest over what the store says, for a caller that wants to notice
  ## that a store changed without diffing it. Not a measurement.
  var material = GenerationStoreSchema & "\n"
  material.add (if store.hasCurrent: $store.current else: "-") & "\n"
  for slot in [gsA, gsB]:
    if not store.hasEntry(slot):
      material.add $slot & "=empty\n"
      continue
    let e = store.entryFor(slot)
    material.add $slot & "=" & e.ukiDigest & ":" & $e.sequence & "\n"
  toLowerAscii($secureHash(material))
