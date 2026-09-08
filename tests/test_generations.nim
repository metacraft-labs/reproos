## Gate: an attested machine runs one generation for the lifetime of a boot.
##
## ## What is being claimed
##
## ReproOS switches generations atomically. On an attested machine that has
## to become stricter, and the reason is arithmetic rather than policy: the
## launch measurement is taken ONCE, at boot, over the unified kernel image
## the firmware loaded, and nothing extends it afterwards. A generation
## switched while the machine was running would therefore not appear in it —
## the machine would execute configuration B while every report it produced
## said A. An attestation that is a lie about what is executing is worse than
## none, because a verifier acts on it.
##
## So three properties have to hold, and they are this gate's three
## registered cases:
##
##   * ``t_generation_switch_requires_reboot`` — applying a new configuration
##     STAGES it: the new unified kernel image goes into the slot the machine
##     is not running from, the next boot is pointed at it, the operation
##     reports ``reboot-required``, and the artifacts of the generation that
##     is running are not touched. After a reboot the new generation is what
##     runs.
##   * ``t_rollback_selects_previous_uki`` — the previous unified kernel
##     image is still in its slot and still selectable, and a machine booted
##     back onto it reports the OLD command line with the OLD root hash. That
##     is what "identifies itself honestly as the prior generation" means
##     concretely: the identity comes out of the measured artifact, not out
##     of anything the store or the running system says about itself.
##   * ``t_runtime_generation_switch_is_refused`` — asking for the switch to
##     take effect on the running system fails closed, on an attested machine
##     only, without having written anything.
##
## ## The layers, and what each is worth
##
##   1. **The model** (always on, ~2s, no external tool and no artifact).
##      Real unified kernel images — assembled by ``repro/uki.nim`` against a
##      synthetic PE32+ stub this file builds from the specification — are
##      staged into a real store on a real directory, rolled back, verified
##      and mutated. It PROVES the slot discipline, the refusals, and that
##      the store cannot describe itself falsely without saying so. It
##      proves NOTHING about firmware.
##
##   2. **The shipped tool** (artifact-conditional on the pinned EFI stub,
##      ~15s). Two real unified kernel images over the real stub, staged
##      twice: once through the module this gate drives directly and once
##      through the compiled ``tools/reproos_generation.nim``. The two stores
##      must be byte-identical — two paths, one artifact — and the tool's
##      exit codes must match the module's refusals.
##
##   3. **Four real boots** (opt-in, ``REPROOS_GENERATION_BOOT_GATE=1``,
##      ~4 min). Two generations with different verity root hashes, on one
##      real FAT32 ESP, through OVMF. Boot the first; stage the second; boot
##      the first slot's bytes again and see the first generation unchanged;
##      boot the ESP and see the second; roll back and see the first again.
##      The guest reports its own ``/proc/cmdline``, so every assertion is
##      about what the KERNEL received, not about what the store intended.
##
## ## What no layer here proves
##
## No PCR is read or computed; no TPM is attached. No ReproOS root is
## mounted: the verity root hashes are real values built by
## ``repro/verity.nim`` over purpose-built byte arrays, not over a ReproOS
## closure, and no verity device is activated in any guest. The kernel in
## layers 2 and 3 is whichever kernel the host can supply and the guest's
## userspace is a purpose-built freestanding init. And no ReproOS image is
## built: ``uefi-attested`` is still refused at plan time, which this gate
## asserts rather than works around.
##
## ## Mocking
##
## None. The synthetic stub in layer 1 is a FIXTURE — a real PE32+ image
## built from the specification, fed to the real assembler, with assertions
## about real PE bytes. The store operations write real files. Layers 2 and 3
## use the real pinned stub, the real shipped tool, a real kernel, real
## firmware and a real QEMU.

import std/[options, os, osproc, strutils, tables, times]

import repro_profile/types

import "../repro/generations"
import "../repro/uki"
import "../repro/verity"
import "../repro/disk_layouts"

import nimcrypto/[hash, sha2]

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  BootGateEnv = "REPROOS_GENERATION_BOOT_GATE"

  VmNamePrefix = "reproos-att-gen-"
    ## Every guest this gate starts is named under the shared
    ## ``reproos-att-`` prefix and torn down unconditionally, so nothing it
    ## creates can be confused with the production guests that share this
    ## host.

  PinnedEpoch = 1735689600'i64

  GateSeed = "reproos-image-v1:generation-gate"
    ## A build identity seed. Every partition GUID on the command lines
    ## below is derived from it exactly as the recipe derives them.

  GuestInitSource = """
/* The guest's /init. Freestanding on purpose: raw syscalls, no libc, no
 * BusyBox, no shell -- so the boot layer depends on nothing but the C
 * compiler this gate already declares, and the guest's userspace is a
 * function of THIS FILE. It prints /proc/cmdline, which on an attested
 * boot carries the generation's verity root hash, so what is asserted is
 * what the KERNEL received rather than what the store intended. */
static long sys(long n, long a, long b, long c, long d, long e) {
  long r;
  register long r10 __asm__("r10") = d;
  register long r8 __asm__("r8") = e;
  __asm__ volatile("syscall" : "=a"(r)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                   : "rcx", "r11", "memory");
  return r;
}
#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_mount 165
#define SYS_reboot 169
#define SYS_exit 60

static unsigned long slen(const char *s) {
  unsigned long n = 0; while (s[n]) n++; return n;
}
static int con = 1;
static void say(const char *s) { sys(SYS_write, con, (long)s, slen(s), 0, 0); }

void _start(void) {
  long fd = sys(SYS_open, (long)"/dev/console", 1 /* O_WRONLY */, 0, 0, 0);
  if (fd >= 0) con = (int)fd;
  sys(SYS_mount, (long)"none", (long)"/proc", (long)"proc", 0, 0);
  say("GEN-GUEST-START\n");
  long f = sys(SYS_open, (long)"/proc/cmdline", 0, 0, 0, 0);
  static char buf[8192];
  long n = f >= 0 ? sys(SYS_read, f, (long)buf, sizeof buf - 1, 0, 0) : -1;
  say("GEN-CMDLINE=");
  if (n > 0) {
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == 0)) n--;
    sys(SYS_write, con, (long)buf, n, 0, 0);
  }
  say("\nGEN-GUEST-DONE\n");
  /* LINUX_REBOOT_MAGIC1, MAGIC2, CMD_POWER_OFF */
  sys(SYS_reboot, 0xfee1deadL, 672274793L, 0x4321fedcL, 0, 0);
  sys(SYS_exit, 0, 0, 0, 0, 0);
}
"""

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

proc sha256Hex(s: string): string = toLowerAscii($sha256.digest(s))

proc scratch(name: string): string =
  let path = getTempDir() / "reproos-gen-" & name & "-" &
    $getCurrentProcessId()
  removeDir(path)
  createDir(path)
  path

# =====================================================================
# The synthetic stub layer 1 assembles against.
#
# A FIXTURE, not a mock: a real PE32+ EFI application built from the
# specification, so the always-on layer needs no systemd installed.
# =====================================================================

proc putU16(b: var string; at, v: int) =
  b[at] = char(v and 0xFF)
  b[at + 1] = char((v shr 8) and 0xFF)

proc putU32(b: var string; at: int; v: int64) =
  for i in 0 ..< 4:
    b[at + i] = char((v shr (8 * i)) and 0xFF)

const
  SynthOptionalHeaderSize = 240
  SynthPeOffset = 0x40
  SynthSectionTable = SynthPeOffset + 4 + 20 + SynthOptionalHeaderSize
  SynthFileAlignment = 512
  SynthSectionAlignment = 4096

proc syntheticStub(): string =
  let firstRaw = max(1536, SynthFileAlignment)
  result = newString(firstRaw + SynthFileAlignment)
  result[0] = 'M'
  result[1] = 'Z'
  putU32(result, 0x3C, SynthPeOffset)
  result[SynthPeOffset] = 'P'
  result[SynthPeOffset + 1] = 'E'
  let coff = SynthPeOffset + 4
  putU16(result, coff, 0x8664)
  putU16(result, coff + 2, 1)
  putU32(result, coff + 4, 315532800)
  putU16(result, coff + 16, SynthOptionalHeaderSize)
  putU16(result, coff + 18, 0x022E)
  let opt = coff + 20
  putU16(result, opt, 0x20B)
  putU32(result, opt + 32, SynthSectionAlignment)
  putU32(result, opt + 36, SynthFileAlignment)
  putU32(result, opt + 56, 2 * SynthSectionAlignment)
  putU32(result, opt + 60, 1536)
  putU32(result, opt + 64, 0)
  let at = SynthSectionTable
  for j, c in ".s0":
    result[at + j] = c
  putU32(result, at + 8, 16)
  putU32(result, at + 12, SynthSectionAlignment)
  putU32(result, at + 16, SynthFileAlignment)
  putU32(result, at + 20, firstRaw)
  putU32(result, at + 36, 0x40000040)

# ---------------------------------------------------------------------
# Two generations. Real verity root hashes over two byte arrays that
# differ in one byte, so the two are as different to a measurement as any
# two ReproOS closures would be.
# ---------------------------------------------------------------------

proc rootClosure(flip: bool): string =
  ## 64 blocks of derived bytes; ``flip`` changes exactly one of them.
  result = newStringOfCap(64 * VerityDataBlockSize)
  for i in 0 ..< 64:
    let d = sha256.digest("reproos-generation-kat:" & $i)
    var b = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      b[j] = char(d.data[j])
    for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
      result.add b
  if flip:
    let at = 7 * VerityDataBlockSize + 11
    result[at] = char(uint8(result[at]) xor 0x01'u8)

let
  verityGateSpec = verityRootSpec(GateSeed)
  rootHashA = verityRootHash(verityGateSpec, rootClosure(false))
  rootHashB = verityRootHash(verityGateSpec, rootClosure(true))
  devicesA = attestedBootDevices(GateSeed, gsA)
  devicesB = attestedBootDevices(GateSeed, gsB)

proc cmdlineFor(rootHash: string; devices: AttestedBootDevices;
                prefix = ""): string =
  prefix & attestedKernelCmdline(rootHash, devices.data, devices.hash,
                                 devices.stateVar, devices.stateHome)

proc synthUki(cmdline: string; kernel = "SYNTHETIC-KERNEL-PAYLOAD";
              initrd = "SYNTHETIC-INITRD-PAYLOAD"): string =
  assembleUki(syntheticStub(), ukiSections(UkiSpec(
    cmdline: cmdline,
    osRelease: defaultOsRelease("0.1.0"),
    uname: "6.12.0-reproos"), kernel, initrd), PinnedEpoch)

proc writeUki(dir, name, cmdline: string): string =
  createDir(dir)
  result = dir / name
  writeFile(result, synthUki(cmdline))

proc stageInto(store: var GenerationStore; ukiPath, rootHash: string;
               devices: AttestedBootDevices; slot: GenerationSlot;
               attested = true): GenerationOutcome =
  stageGeneration(store, GenerationStageRequest(
    ukiPath: ukiPath, verityRootHash: rootHash, devices: devices,
    slot: slot, attested: attested))

proc storeSnapshot(store: GenerationStore): string =
  ## Every byte of the store that decides a boot, in one string, so
  ## "nothing was written" is a single comparison rather than a list of
  ## things somebody remembered to check.
  var parts: seq[string] = @[]
  for slot in [gsA, gsB]:
    let p = generationUkiPath(store.espRoot, slot)
    parts.add $slot & "=" &
      (if fileExists(p): sha256Hex(readFile(p)) else: "-")
  let idx = generationIndexPath(store.espRoot)
  parts.add "index=" &
    (if fileExists(idx): sha256Hex(readFile(idx)) else: "-")
  let fb = espFallbackPath(store.espRoot)
  parts.add "boot=" & (if fileExists(fb): sha256Hex(readFile(fb)) else: "-")
  parts.join(" ")

# =====================================================================
# Layer 1 — the model. Always on.
# =====================================================================

block layerSlotsAndDeviceNaming:
  check(rootPartitionName(gsA) != rootPartitionName(gsB) and
        hashPartitionName(gsA) != hashPartitionName(gsB) and
        rootPartitionName(gsA) != hashPartitionName(gsA),
        "the two slots name four distinct volumes (" &
        rootPartitionName(gsA) & ", " & hashPartitionName(gsA) & ", " &
        rootPartitionName(gsB) & ", " & hashPartitionName(gsB) & ")")
  check(otherSlot(gsA) == gsB and otherSlot(gsB) == gsA,
        "the slots are each other's other")

  # The specifiers are derivable BEFORE the partition exists, and they
  # are the ones `repro disk apply` will assign, because both derive them
  # from the same seed with the same purpose string.
  check(devicesA.data != devicesB.data and devicesA.hash != devicesB.hash and
        devicesA.data != devicesA.hash,
        "each slot's verity pair is named by two distinct partition " &
        "GUIDs, and the two slots do not share one")
  check(devicesA.data.startsWith("PARTUUID=") and
        devicesA.hash.startsWith("PARTUUID=") and
        devicesA.data.len == "PARTUUID=".len + 36,
        "the verity pair is named by PARTUUID, in the 8-4-4-4-12 form " &
        "the initramfs' findfs takes (" & devicesA.data & ")")
  check(attestedBootDevices(GateSeed, gsA) == devicesA,
        "the derivation is a pure function of the seed and the slot")
  check(attestedBootDevices(GateSeed & "x", gsA).data != devicesA.data,
        "a different build seed gives different partition GUIDs, so two " &
        "images do not claim each other's volumes")
  check(devicesA.stateVar == "LABEL=" & StateVarLabel and
        devicesA.stateHome == devicesB.stateHome,
        "the state volumes are named by label and are SHARED by the " &
        "generations: mutable state survives a switch, which is why it " &
        "is off the measured surface in the first place")

  check(validateAttestedBootDevices(devicesA).len == 0,
        "the derived device set is accepted")
  check(validateAttestedBootDevices(attestedBootDevices("", gsA)).len > 0,
        "a build with NO identity seed derives no partition GUIDs and is " &
        "refused, rather than composing a command line naming an empty " &
        "device that fails at boot instead of at build time")

  # The two namings that cannot work, refused with the reason. Both were
  # live in the tree before this gate existed.
  var labelledHash = devicesA
  labelledHash.hash = "LABEL=reproos-roothash"
  let hashRefusal = validateAttestedBootDevices(labelledHash)
  check(hashRefusal.len > 0 and "no label for findfs" in hashRefusal,
        "naming the Merkle tree by a FILESYSTEM LABEL is refused: a " &
        "dm-verity hash device carries the superblock and the tree and " &
        "no filesystem, so findfs can never resolve one (" &
        hashRefusal.splitLines()[0] & ")")
  var labelledData = devicesA
  labelledData.data = "LABEL=" & AttestedRootFsLabel
  let dataRefusal = validateAttestedBootDevices(labelledData)
  check(dataRefusal.len > 0 and "two devices" in dataRefusal,
        "naming the verity data carrier by a filesystem label is refused " &
        "too: with two slots staged both carriers hold an ext4 image with " &
        "that same label")
  var samePair = devicesA
  samePair.hash = samePair.data
  check(validateAttestedBootDevices(samePair).len > 0,
        "a generation whose tree and data image are the same volume is " &
        "refused")
  var devicePath = devicesA
  devicePath.data = "/dev/vda2"
  check(validateAttestedBootDevices(devicePath).len > 0,
        "a bare device path is refused: /dev/vda2 on QEMU is " &
        "/dev/nvme0n1p2 on a laptop, and the initramfs resolves LABEL=, " &
        "UUID= and PARTUUID= only")

block layerGenerationIdentity:
  let image = synthUki(cmdlineFor(rootHashA, devicesA))
  let digest = sha256Hex(image)
  check(generationIdFor(digest) == GenerationIdPrefix &
          digest[0 ..< GenerationIdDigestChars],
        "a generation is named by the sha256 of its unified kernel image")
  let other = synthUki(cmdlineFor(rootHashB, devicesB))
  check(generationIdFor(sha256Hex(other)) != generationIdFor(digest),
        "two generations whose command lines differ have different ids, " &
        "because the command line is inside the image the digest covers")
  check(generationIdFor("abc").len == 0,
        "a digest too short to name a generation names none")

# ---------------------------------------------------------------------
# t_generation_switch_requires_reboot
# ---------------------------------------------------------------------

block tGenerationSwitchRequiresReboot:
  let work = scratch("stage")
  defer: removeDir(work)
  let esp = work / "esp"
  createDir(esp)
  let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
  let ukiB = writeUki(work / "in", "b.efi", cmdlineFor(rootHashB, devicesB))

  var store = readGenerationStore(esp)
  check(not store.hasCurrent and store.entries.len == 0,
        "an ESP with no store yet reads back as an empty store, which is " &
        "what a first install writes into")
  check(nextStagingSlot(store) == gsA,
        "the first generation goes into slot a")

  var first: GenerationOutcome
  try:
    first = stageInto(store, ukiA, rootHashA, devicesA, gsA)
  except ValueError as e:
    fail("t_generation_switch_requires_reboot: staging the first " &
         "generation raised: " & e.msg.splitLines()[0])
    break tGenerationSwitchRequiresReboot
  check(first.selected.verityRootHash == rootHashA and
        first.rebootRequired and not first.hasPrevious,
        "the first generation is staged and selected, with nothing to " &
        "roll back to yet")
  let afterFirst = storeSnapshot(store)
  let slotABytes = readFile(generationUkiPath(esp, gsA))

  check(nextStagingSlot(store) == gsB,
        "t_generation_switch_requires_reboot: the next generation is " &
        "staged into the slot the machine is NOT running from")

  # Guarded rather than called straight: a staging that RAISES here is
  # exactly what a broken slot discipline looks like, and it has to be a
  # named red line rather than an exception that takes every check after
  # it down with it.
  var outcome: GenerationOutcome
  var stageError = ""
  try:
    outcome = stageInto(store, ukiB, rootHashB, devicesB,
                        nextStagingSlot(store))
  except ValueError as e:
    stageError = e.msg
  if stageError.len > 0:
    fail("t_generation_switch_requires_reboot: staging the next " &
         "generation raised instead of writing the other slot: " &
         stageError.splitLines()[0])
    break tGenerationSwitchRequiresReboot
  check(outcome.operation == goStage and outcome.rebootRequired,
        "t_generation_switch_requires_reboot: staging reports " &
        "reboot-required")
  check(outcome.runningUnchanged,
        "t_generation_switch_requires_reboot: ... and reports that the " &
        "running generation is unchanged")
  let report = renderGenerationOutcome(outcome)
  check(RebootRequiredKey & ": yes" in report,
        "t_generation_switch_requires_reboot: the report an operator " &
        "reads says " & RebootRequiredKey & ": yes in machine-readable " &
        "form, not only in prose")
  check("UNCHANGED" in report and "Reboot to run" in report,
        "t_generation_switch_requires_reboot: ... and says what did NOT " &
        "happen, because an operator who read 'applied' and assumed the " &
        "machine had switched would draw exactly the wrong conclusion")
  check(outcome.hasPrevious and outcome.previous.verityRootHash == rootHashA,
        "t_generation_switch_requires_reboot: the report names the " &
        "generation that stays selectable")

  # THE PROPERTY. The generation that is running was not touched: its
  # unified kernel image is the same bytes it was before the stage.
  check(readFile(generationUkiPath(esp, gsA)) == slotABytes,
        "t_generation_switch_requires_reboot: the running generation's " &
        "unified kernel image is BYTE-IDENTICAL after the stage -- the " &
        "new generation went to the other slot and nothing overwrote the " &
        "artifact this boot's launch measurement was taken over")
  check(afterFirst != storeSnapshot(store),
        "... and the store did change, so the comparison above is not " &
        "passing because nothing happened at all")

  # What the next boot will run.
  let reread = readGenerationStore(esp)
  check(reread.hasCurrent and reread.current == gsB,
        "t_generation_switch_requires_reboot: the next boot is pointed " &
        "at the staged generation")
  check(sha256Hex(readFile(espFallbackPath(esp))) ==
          reread.entryFor(gsB).ukiDigest,
        "t_generation_switch_requires_reboot: and the bytes at " &
        UkiEspFallbackPath & " -- the only thing firmware reads -- are " &
        "that generation's")
  check(reread.entryFor(gsA).sequence < reread.entryFor(gsB).sequence,
        "the store records which configuration is the older one")
  check(verifyGenerationStore(reread).len == 0,
        "the store describes itself truthfully")

# ---------------------------------------------------------------------
# t_rollback_selects_previous_uki
# ---------------------------------------------------------------------

block tRollbackSelectsPreviousUki:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    let work = scratch("rollback")
    defer: removeDir(work)
    let esp = work / "esp"
    createDir(esp)
    let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
    let ukiB = writeUki(work / "in", "b.efi", cmdlineFor(rootHashB, devicesB))

    var store = readGenerationStore(esp)
    discard stageInto(store, ukiA, rootHashA, devicesA, gsA)
    let idA = store.entryFor(gsA).id
    let digestA = store.entryFor(gsA).ukiDigest
    let seqA = store.entryFor(gsA).sequence
    discard stageInto(store, ukiB, rootHashB, devicesB, gsB)
    let idB = store.entryFor(gsB).id

    let rolled = rollbackGeneration(store, attested = true)
    check(rolled.operation == goRollback and rolled.selected.id == idA,
          "t_rollback_selects_previous_uki: rollback selects the previous " &
          "generation (" & idA & ")")
    check(rolled.rebootRequired,
          "t_rollback_selects_previous_uki: and requires a reboot too -- " &
          "the running generation is fixed for this boot whichever " &
          "direction the switch goes")
    check(sha256Hex(readFile(espFallbackPath(esp))) == digestA,
          "t_rollback_selects_previous_uki: the bytes firmware will load " &
          "are the PREVIOUS generation's unified kernel image, unchanged " &
          "since it was staged -- nothing was rebuilt and nothing was " &
          "restored from anywhere")
    let cmdline = ukiCmdline(readFile(espFallbackPath(esp)))
    check((VerityRootHashCmdlineKey & "=" & rootHashA) in cmdline and
          rootHashB notin cmdline,
          "t_rollback_selects_previous_uki: and the command line INSIDE " &
          "those bytes pins the old root hash, so a machine booted from " &
          "them re-attests under the old measurement and identifies itself " &
          "as the old configuration")
    check(store.entryFor(gsA).sequence == seqA and
          store.entryFor(gsA).sequence < store.entryFor(gsB).sequence,
          "t_rollback_selects_previous_uki: the sequence numbers are NOT " &
          "renumbered -- a rolled-back machine is running the older " &
          "configuration and the store keeps saying so")
    check(store.hasEntry(gsB) and
          fileExists(generationUkiPath(esp, gsB)),
          "t_rollback_selects_previous_uki: the generation that was rolled " &
          "back FROM is still staged, so the move is reversible")
    check(verifyGenerationStore(store).len == 0,
          "t_rollback_selects_previous_uki: and the store is still honest")

    let back = rollbackGeneration(store, attested = true)
    check(back.selected.id == idB and
          sha256Hex(readFile(espFallbackPath(esp))) ==
            store.entryFor(gsB).ukiDigest,
          "t_rollback_selects_previous_uki: rolling forward again selects " &
          "the newer generation, so rollback is a selection and not a " &
          "one-way door")

    # The refusal that matters here: there is nothing to roll back to.
    let lone = scratch("rollback-lone")
    defer: removeDir(lone)
    createDir(lone / "esp")
    var single = readGenerationStore(lone / "esp")
    discard stageInto(single, ukiA, rootHashA, devicesA, gsA)
    var refused = ""
    try:
      discard rollbackGeneration(single, attested = true)
    except ValueError as e:
      refused = e.msg
    check(refused.len > 0 and "no previous configuration" in refused,
          "t_rollback_selects_previous_uki: a store with one generation " &
          "refuses to roll back rather than selecting an empty slot and " &
          "producing a machine that boots nothing")

    # And a store whose previous slot has been tampered with.
    let tampered = scratch("rollback-tampered")
    defer: removeDir(tampered)
    createDir(tampered / "esp")
    var two = readGenerationStore(tampered / "esp")
    discard stageInto(two, ukiA, rootHashA, devicesA, gsA)
    discard stageInto(two, ukiB, rootHashB, devicesB, gsB)
    writeFile(generationUkiPath(tampered / "esp", gsA),
              synthUki(cmdlineFor(rootHashA, devicesA, "console=ttyS0 ")))
    var tamperRefusal = ""
    try:
      discard rollbackGeneration(two, attested = true)
    except ValueError as e:
      tamperRefusal = e.msg
    check(tamperRefusal.len > 0 and "not the one the store claims" in
            tamperRefusal,
          "t_rollback_selects_previous_uki: rolling back to a slot whose " &
          "unified kernel image is not the one the index recorded is " &
          "REFUSED, naming both digests -- the previous generation has to " &
          "still be the previous generation")
  except CatchableError as e:
    fail("t_rollback_selects_previous_uki: the case ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

# ---------------------------------------------------------------------
# t_runtime_generation_switch_is_refused
#
# The negative case, and the one the whole design rests on. A live switch
# that silently succeeded would make every attestation the machine
# produced afterwards a lie about what is executing.
# ---------------------------------------------------------------------

block tRuntimeGenerationSwitchIsRefused:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    let work = scratch("refuse")
    defer: removeDir(work)
    let esp = work / "esp"
    createDir(esp)
    let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
    let ukiB = writeUki(work / "in", "b.efi", cmdlineFor(rootHashB, devicesB))
    # A generation that belongs in slot A, for the case where the live
    # switch is attempted with an image whose command line names the
    # running slot -- the shape an "upgrade in place" would actually take.
    let ukiA2 = writeUki(work / "in", "a2.efi",
                         cmdlineFor(rootHashB, devicesA))

    var store = readGenerationStore(esp)
    discard stageInto(store, ukiA, rootHashA, devicesA, gsA)
    discard stageInto(store, ukiB, rootHashB, devicesB, gsB)
    discard rollbackGeneration(store, attested = true)   # running slot a
    let before = storeSnapshot(store)

    let refusal = validateStageTarget(store, store.current, attested = true)
    check(refusal.len > 0,
          "t_runtime_generation_switch_is_refused: writing the slot the " &
          "machine is running from is refused on an attested machine")
    check(store.currentEntry().id in refusal and
          "launch measurement" in refusal and "reboot" in refusal,
          "t_runtime_generation_switch_is_refused: the refusal names the " &
          "running generation, why the measurement makes this impossible, " &
          "and the remedy -- stage into the other slot and reboot")

    # DISCRIMINATING, not blanket. Same machine, same call, other slot.
    check(validateStageTarget(store, otherSlot(store.current),
                              attested = true).len == 0,
          "t_runtime_generation_switch_is_refused: staging into the OTHER " &
          "slot on the same attested machine is accepted, so the refusal " &
          "is not a feature that was never implemented")
    # And keyed on attestation rather than on the operation.
    check(validateStageTarget(store, store.current, attested = false).len == 0,
          "t_runtime_generation_switch_is_refused: the same write into the " &
          "same slot is accepted when nothing is measured -- the refusal is " &
          "keyed on there being a launch measurement to contradict")

    # Through the operation, not only through the validator.
    var raised = ""
    try:
      discard stageInto(store, ukiA2, rootHashB, devicesA, store.current)
    except ValueError as e:
      raised = e.msg
    check(raised.len > 0 and "running generation" in raised,
          "t_runtime_generation_switch_is_refused: the staging operation " &
          "itself raises, so the refusal is not something a caller can " &
          "skip by not asking the validator")
    check(storeSnapshot(store) == before,
          "t_runtime_generation_switch_is_refused: and NOTHING was written " &
          "-- the store is byte-identical, so the refusal is not a partial " &
          "write followed by an error")

    # THE GUARD IS LOAD-BEARING. The same operation with the machine's boot
    # unmeasured really does overwrite the running slot -- so what stops it
    # above is the refusal and not an absent capability.
    let unguarded = scratch("refuse-unguarded")
    defer: removeDir(unguarded)
    let esp2 = unguarded / "esp"
    createDir(esp2)
    var plain = readGenerationStore(esp2)
    discard stageInto(plain, ukiA, rootHashA, devicesA, gsA)
    let runningBytes = readFile(generationUkiPath(esp2, gsA))
    discard stageInto(plain, ukiA2, rootHashB, devicesA, gsA,
                      attested = false)
    check(readFile(generationUkiPath(esp2, gsA)) != runningBytes and
          ukiCmdline(readFile(espFallbackPath(esp2))).contains(rootHashB),
          "t_runtime_generation_switch_is_refused: with the boot " &
          "unmeasured the SAME call replaces the running slot's unified " &
          "kernel image and the boot artifact with it -- which is exactly " &
          "what the refusal above prevents, and why it is a guard rather " &
          "than a decoration")
    check(not plain.hasEntry(gsB),
          "... and it destroys the pair a rollback would have needed: " &
          "there is no second generation left anywhere on that ESP")
  except CatchableError as e:
    fail("t_runtime_generation_switch_is_refused: the case ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

# ---------------------------------------------------------------------
# The store cannot describe itself falsely without saying so.
#
# The index is metadata: firmware reads the bytes at the fallback path
# and nothing else. So the index is not trusted -- it is CHECKED against
# the artifacts, and the check is what makes "the guest identifies itself
# honestly" a property of the system rather than of the store.
# ---------------------------------------------------------------------

block layerStoreCannotLie:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    let work = scratch("verify")
    defer: removeDir(work)
    let esp = work / "esp"
    createDir(esp)
    let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
    let ukiB = writeUki(work / "in", "b.efi", cmdlineFor(rootHashB, devicesB))
    var store = readGenerationStore(esp)
    discard stageInto(store, ukiA, rootHashA, devicesA, gsA)
    discard stageInto(store, ukiB, rootHashB, devicesB, gsB)
    check(verifyGenerationStore(store).len == 0,
          "an untouched store verifies clean")

    # The index says B; the bytes UEFI loads are A's.
    copyFile(generationUkiPath(esp, gsA), espFallbackPath(esp))
    let lied = verifyGenerationStore(store)
    check(lied.len == 1 and "would boot a generation the store does not " &
            "claim" in lied[0] and store.entryFor(gsA).id in lied[0],
          "an index that selects one generation while the fallback binary " &
          "is another's is caught, and the diagnostic names which one the " &
          "machine would actually boot")
    copyFile(generationUkiPath(esp, gsB), espFallbackPath(esp))
    check(verifyGenerationStore(store).len == 0, "and restoring it clears")

    # A slot's image replaced by different bytes.
    let saved = readFile(generationUkiPath(esp, gsA))
    writeFile(generationUkiPath(esp, gsA),
              synthUki(cmdlineFor(rootHashA, devicesA, "console=ttyS0 ")))
    check(verifyGenerationStore(store).len > 0,
          "a slot whose image is not the one the index recorded is caught")
    writeFile(generationUkiPath(esp, gsA), saved)

    # An index entry whose recorded root hash is not the one the image
    # measures. This is the shape of a store that claims a generation is
    # something it is not.
    var lying = store
    for i in 0 ..< lying.entries.len:
      if lying.entries[i].slot == gsA:
        lying.entries[i].verityRootHash = rootHashB
    let mismatch = verifyGenerationStore(lying)
    check(mismatch.len > 0 and "does not pin the root hash" in mismatch[0],
          "an index that records a root hash the image's measured command " &
          "line does not pin is caught -- the artifact is the authority " &
          "and the index is only a claim about it")

    # A missing boot artifact.
    removeFile(espFallbackPath(esp))
    let noBoot = verifyGenerationStore(store)
    check(noBoot.len > 0 and "boots nothing" in noBoot[^1],
          "an ESP with no binary at the fallback path is reported as " &
          "booting nothing rather than as fine")
  except CatchableError as e:
    fail("the store-honesty layer: the case ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

block layerIndexRefusals:
  let work = scratch("index")
  defer: removeDir(work)
  let esp = work / "esp"
  createDir(esp)
  createDir(generationStoreDir(esp))

  proc refusalFor(text: string): string =
    writeFile(generationIndexPath(esp), text)
    try:
      discard readGenerationStore(esp)
      ""
    except ValueError as e:
      e.msg

  check(refusalFor("not json at all").len > 0,
        "an index that is not readable JSON is REFUSED rather than " &
        "treated as an empty store; the difference between 'no " &
        "generations' and 'an index this build cannot read' is the " &
        "difference between a first install and overwriting one")
  check("schema" in refusalFor("{\"current\": \"a\"}"),
        "an index with no schema field is refused")
  let wrongSchema = refusalFor(
    "{\"schema\": \"reproos.generation-store.v9\", \"current\": \"\"}")
  check(wrongSchema.len > 0 and GenerationStoreSchema in wrongSchema,
        "an index declaring a schema this build does not know is refused, " &
        "naming the one it understands")
  check(refusalFor("{\"schema\": \"" & GenerationStoreSchema &
        "\", \"current\": \"c\"}").len > 0,
        "an index naming a slot that does not exist is refused")
  check(refusalFor("{\"schema\": \"" & GenerationStoreSchema &
        "\", \"current\": \"a\", \"generations\": []}").len > 0,
        "an index selecting a slot that holds no generation is refused")

block layerIndexIsDeterministic:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    let work = scratch("determinism")
    defer: removeDir(work)
    let esp = work / "esp"
    createDir(esp)
    let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
    let ukiB = writeUki(work / "in", "b.efi", cmdlineFor(rootHashB, devicesB))
    var store = readGenerationStore(esp)
    discard stageInto(store, ukiA, rootHashA, devicesA, gsA)
    discard stageInto(store, ukiB, rootHashB, devicesB, gsB)
    let text = readFile(generationIndexPath(esp))
    check(renderGenerationIndex(store) == text,
          "the index on disk is what the store renders")
    check(renderGenerationIndex(parseGenerationIndex(esp, text)) == text,
          "the index round-trips through its own parser byte for byte")
    check(generationStoreFingerprint(store) ==
            generationStoreFingerprint(parseGenerationIndex(esp, text)),
          "and a store read back from it is the same store")
  except CatchableError as e:
    fail("the index-determinism layer: the case ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

block layerStagingRefusals:
  let work = scratch("stage-refusals")
  defer: removeDir(work)
  let esp = work / "esp"
  createDir(esp)
  var store = readGenerationStore(esp)

  # A generation whose measured command line names the OTHER slot's
  # volumes. This is the mistake that produces a machine which boots and
  # then activates the wrong root -- or refuses to, having found no
  # device -- and it is caught at staging rather than at boot.
  let wrongSlot = writeUki(work / "in", "wrong.efi",
                           cmdlineFor(rootHashA, devicesB))
  var wrongRefusal = ""
  try:
    discard stageInto(store, wrongSlot, rootHashA, devicesA, gsA)
  except ValueError as e:
    wrongRefusal = e.msg
  check(wrongRefusal.len > 0 and "different slot" in wrongRefusal,
        "staging a unified kernel image whose MEASURED command line names " &
        "another slot's volumes is refused; the artifact is checked " &
        "rather than the caller's claim about it")

  # A generation whose command line does not pin the root hash the caller
  # says it does.
  let ukiA = writeUki(work / "in", "a.efi", cmdlineFor(rootHashA, devicesA))
  var hashRefusal = ""
  try:
    discard stageInto(store, ukiA, rootHashB, devicesA, gsA)
  except ValueError as e:
    hashRefusal = e.msg
  check(hashRefusal.len > 0,
        "staging an image whose measured command line does not pin the " &
        "root hash the store would record is refused")

  var missing = ""
  try:
    discard stageInto(store, work / "in" / "nope.efi", rootHashA,
                      devicesA, gsA)
  except ValueError as e:
    missing = e.msg
  check(missing.len > 0, "staging a unified kernel image that is not " &
        "there is refused")

  # Not a PE at all.
  let junk = work / "in" / "junk.efi"
  writeFile(junk, "this is not a PE image at all, not even close")
  var junkRefusal = ""
  try:
    discard stageInto(store, junk, rootHashA, devicesA, gsA)
  except ValueError as e:
    junkRefusal = e.msg
  check(junkRefusal.len > 0,
        "staging something that is not a unified kernel image is refused")
  check(not fileExists(generationIndexPath(esp)),
        "and none of those refusals left a store behind")

# ---------------------------------------------------------------------
# The declarations that have to agree.
# ---------------------------------------------------------------------

block layerDeclarationsAgree:
  # The layout carries both slots and both Merkle-tree volumes.
  let params = DiskLayoutParams(id: "reproos", device: "/dev/nbd0",
                                espSizeMib: 512, diskSizeGb: 32)
  let layout = buildDiskLayout("uefi-attested", params)
  let disk = layout.disks[AttestedDiskName]
  var missingVolumes: seq[string] = @[]
  for slot in [gsA, gsB]:
    for name in [rootPartitionName(slot), hashPartitionName(slot)]:
      if name notin disk.partitions:
        missingVolumes.add name
  check(missingVolumes.len == 0,
        "the attested layout declares both root slots and both " &
        "Merkle-tree volumes" &
        (if missingVolumes.len > 0: " -- missing " &
          missingVolumes.join(", ") else: ""))
  var wrongSizes: seq[string] = @[]
  for slot in [gsA, gsB]:
    if disk.partitions[rootPartitionName(slot)].size != AttestedRootSize:
      wrongSizes.add rootPartitionName(slot)
    if disk.partitions[hashPartitionName(slot)].size != AttestedHashTreeSize:
      wrongSizes.add hashPartitionName(slot)
    for name in [rootPartitionName(slot), hashPartitionName(slot)]:
      if disk.partitions[name].content.kind != cfsNone:
        wrongSizes.add name & " (carries a filesystem the apply would create)"
  check(wrongSizes.len == 0,
        "both slots are equal-sized carriers with no filesystem on them: " &
        "what goes there is a finished image whose bytes the root hash " &
        "covers, and an mkfs at install time would overwrite it" &
        (if wrongSizes.len > 0: " -- " & wrongSizes.join(", ") else: ""))

  var mountsAtRoot = ""
  for pName, p in disk.partitions:
    if p.content.kind == cfsFilesystem and p.content.mountpoint == "/":
      mountsAtRoot = pName
  check(mountsAtRoot.len == 0,
        "NOTHING mounts at / on the attested layout: the root is the " &
        "dm-verity device the initramfs activates from the root hash on " &
        "the measured command line, and a partition mounted there would " &
        "be a second, unchecked answer to what the root is (got " &
        mountsAtRoot.escape() & ")")

  # The Merkle-tree volume is big enough, derived through the verity
  # module rather than trusted from a comment.
  let dataBlocks = 4 * 1024 * 1024 * 1024 div VerityDataBlockSize
  let needed = verityHashDeviceBytes(verityGateSpec, dataBlocks)
  let declared = 64'i64 * 1024 * 1024
  check(AttestedHashTreeSize == "64M" and declared >= needed,
        "the declared " & AttestedHashTreeSize & " Merkle-tree volume " &
        "holds the tree a " & AttestedRootSize & " root needs (" &
        $needed & " bytes over " & $dataBlocks & " data blocks), " &
        "re-derived here through repro/verity.nim")
  check(needed > declared div 4,
        "... and the headroom is a margin rather than an order of " &
        "magnitude, so this check would notice the root growing")

  # The refusal keeps up with what is true.
  let preset = findDiskLayoutPreset("uefi-attested")
  check(preset.isSome, "the attested layout preset is still registered")
  if preset.isSome:
    let reason = preset.get().unbuildableReason
    check(preset.get().status == dlsDeclared and reason.len > 0,
          "the attested preset is STILL refused: declaring the volumes is " &
          "not the same as installing anything onto them")
    check("carries no volume for the hash tree" notin reason and
          "both hash-tree volumes" in reason,
          "the refusal no longer says the layout has no volume for the " &
          "hash tree, because it now has two")
    check("does not write" in reason,
          "and it names what is left: nothing writes the verity data " &
          "image or its Merkle tree onto those volumes")

  # The driver stages the installed image as a generation rather than
  # copying a binary into place, and passes the four things a stage needs.
  let driver = readFile(
    RepoRoot / "recipes/reproos-image/scripts/build-reproos-image.sh")
  var undeclared: seq[string] = @[]
  for name in ["REPROOS_GENERATION_BIN", "REPROOS_VERITY_ROOTHASH_FILE",
               "REPROOS_VERITY_DATA_DEVICE", "REPROOS_VERITY_HASH_DEVICE"]:
    if name notin driver:
      undeclared.add name
  check(undeclared.len == 0,
        "the image driver's attested arm is given the stager and the " &
        "three values a generation is staged from" &
        (if undeclared.len > 0: " -- missing " & undeclared.join(", ")
         else: ""))
  check("stage \\" in driver and "--slot a" in driver,
        "and it stages the installed image as generation a, so the ESP " &
        "carries a generation store from the first install and the first " &
        "apply has somewhere to stage into")
  # The attested arm's own fstab rewrite, identified by the string that
  # occurs in it and nowhere else. The uefi-ext4 arm still rewrites its
  # root to LABEL=reproos-root and must keep doing so -- that layout makes
  # no integrity claim and its root really is a partition.
  check("p2|/dev/mapper/reproos-root|g" in driver,
        "the attested arm rewrites fstab's root to " &
        "/dev/mapper/reproos-root rather than to a filesystem label: on " &
        "this layout / is the dm-verity device, and the carrier " &
        "partition it would otherwise name holds unchecked bytes")
  check("p2|LABEL=reproos-root|g" in driver,
        "... while the uefi-ext4 arm still names its root by label, " &
        "because that layout's root really is a partition")

  let recipe = readFile(RepoRoot / "recipes/reproos-image/package.nim")
  check("tools/reproos_generation.nim" in recipe and "nim.c(" in recipe,
        "the stager is built by a typed nim.c edge, like the assembler")
  check("attestedBootDevices(" in recipe,
        "the recipe derives the generation's volumes from the module " &
        "rather than spelling PARTUUIDs of its own")

  # The initramfs can resolve what the command line names.
  let initDisk = readFile(RepoRoot / "recipes/reproos-iso/initramfs/init-disk")
  check("PARTUUID=*" in initDisk,
        "the initramfs resolves PARTUUID=, which is how a generation's " &
        "verity pair is named")

# =====================================================================
# Layer 2 — the real, pinned stub and the shipped tool.
# =====================================================================

proc requireTool(gate, tool: string): string =
  ## ``followSymlinks = false``: every mtools command is a symlink to one
  ## multiplexer that dispatches on argv[0], and resolving the symlink
  ## hands it a name it answers with its own usage text and exit 1.
  let found = findExe(tool, followSymlinks = false)
  if found.len == 0:
    fail(gate & ": required tool not found on PATH: " & tool &
         ". This layer is running, so its absence is a failure, not a skip.")
  found

proc nimCcArgs(): string = getEnv("REPROOS_NIM_CC_ARGS")

proc runTool(bin: string; args: openArray[string]): tuple[
    code: int; output: string] =
  var cmd = quoteShell(bin)
  for a in args:
    cmd.add " " & quoteShell(a)
  let r = execCmdEx(cmd)
  (r.exitCode, r.output)

var realUkiA = ""
var realUkiB = ""
  ## Set by layer 2 and reused by layer 3, so the boot layer boots the
  ## same artifacts the tool staged.

block layerRealStubAndShippedTool:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    let stubPath = resolveUkiStub()
    if stubPath.len == 0:
      skip("the real-stub layer did not run: NO pinned EFI stub was found, " &
           "so NO real unified kernel image was staged and the shipped " &
           "stager was NOT run. " & describeUkiStubSearch())
    else:
      let gate = "generation real-stub layer"
      let work = scratch("tool")
      defer:
        if getEnv("REPROOS_GENERATION_KEEP") == "1":
          echo "[info] kept (REPROOS_GENERATION_KEEP=1): ", work
        else:
          removeDir(work)

      let kernelPath = work / "kernel.bin"
      let initrdPath = work / "initrd.img"
      writeFile(kernelPath, repeat("K", 300_000) & "\0\0kernel-tail")
      writeFile(initrdPath, repeat("I", 90_000) & "\0initrd-tail")

      proc realUki(cmdline, outPath: string): string =
        let image = assembleUkiFromFiles(UkiSpec(
          stubPath: stubPath, kernelPath: kernelPath, initrdPath: initrdPath,
          cmdline: cmdline, osRelease: defaultOsRelease("0.1.0"),
          uname: "", sourceDateEpoch: PinnedEpoch))
        writeFile(outPath, image)
        outPath

      realUkiA = realUki(cmdlineFor(rootHashA, devicesA), work / "gen-a.efi")
      realUkiB = realUki(cmdlineFor(rootHashB, devicesB), work / "gen-b.efi")
      # A THIRD image: a new root hash on slot A's volumes. This is the
      # shape an "upgrade in place" would take, and it is the only shape in
      # which the runtime-switch refusal is the ONLY thing standing in the
      # way -- an image belonging to the other slot would be refused by the
      # slot check instead, and the case would pass for the wrong reason.
      let realUkiA2 = realUki(cmdlineFor(rootHashB, devicesA),
                              work / "gen-a2.efi")
      check(sha256Hex(readFile(realUkiA)) != sha256Hex(readFile(realUkiB)),
            "two generations over the real pinned stub are two artifacts " &
            "(" & sha256Hex(readFile(realUkiA))[0 ..< 16] & "… and " &
            sha256Hex(readFile(realUkiB))[0 ..< 16] & "…)")

      # 2a. Through the module.
      let espModule = work / "esp-module"
      createDir(espModule)
      var moduleStore = readGenerationStore(espModule)
      discard stageInto(moduleStore, realUkiA, rootHashA, devicesA, gsA)
      discard stageInto(moduleStore, realUkiB, rootHashB, devicesB, gsB)
      discard rollbackGeneration(moduleStore, attested = true)

      # 2b. Through the SHIPPED tool.
      discard requireTool(gate, "nim")
      let toolBin = work / "reproos-generation"
      let compile = execCmdEx("nim c --hints:off --warnings:off " &
        nimCcArgs() & " --out:" & quoteShell(toolBin) & " " &
        quoteShell(RepoRoot / "tools/reproos_generation.nim"))
      if compile.exitCode != 0:
        stderr.writeLine(compile.output)
        fail(gate & ": the shipped stager does not compile")
      else:
        let espTool = work / "esp-tool"
        createDir(espTool)
        let rootHashFileA = work / "roothash-a"
        writeFile(rootHashFileA, rootHashA & "\n")
        let stageA = runTool(toolBin, ["stage", "--esp", espTool,
          "--uki", realUkiA, "--attested",
          "--verity-root-hash-file", rootHashFileA,
          "--verity-data", devicesA.data, "--verity-hash", devicesA.hash])
        check(stageA.code == 0,
              "the shipped stager stages the first generation (exit " &
              $stageA.code & ")")
        check(RebootRequiredKey & ": yes" in stageA.output,
              "and reports " & RebootRequiredKey & ": yes")
        # No --slot: the tool must choose the slot the machine is not
        # running from by itself, or an operator could stage over the top
        # of the running generation by omitting a flag.
        let stageB = runTool(toolBin, ["stage", "--esp", espTool,
          "--uki", realUkiB, "--attested",
          "--verity-root-hash", rootHashB,
          "--verity-data", devicesB.data, "--verity-hash", devicesB.hash])
        check(stageB.code == 0 and "(slot b)" in stageB.output,
              "t_generation_switch_requires_reboot: a stage that is not " &
              "told a slot picks the one the machine is NOT running from")
        let rollback = runTool(toolBin, ["rollback", "--esp", espTool,
                                         "--attested"])
        check(rollback.code == 0,
              "t_rollback_selects_previous_uki: the shipped stager rolls " &
              "back (exit " & $rollback.code & ")")

        var differences: seq[string] = @[]
        for rel in [GenerationStoreDir & "/" & GenerationIndexFileName,
                    GenerationStoreDir & "/a/" & UkiFileName,
                    GenerationStoreDir & "/b/" & UkiFileName,
                    UkiEspFallbackPath]:
          let a = espModule / rel
          let b = espTool / rel
          if not fileExists(a) or not fileExists(b) or
             readFile(a) != readFile(b):
            differences.add rel
        check(differences.len == 0,
              "the shipped tools/reproos_generation.nim produces the same " &
              "store, byte for byte, as the module this gate drives " &
              "directly -- two paths, one artifact" &
              (if differences.len > 0: " -- differ: " &
                differences.join(", ") else: ""))

        # THE REFUSAL, through the shipped surface. `activate-now` is a
        # subcommand that exists and is reachable; asking for it is how a
        # caller finds out that an attested instance will not do it.
        let beforeTool = sha256Hex(readFile(espTool / UkiEspFallbackPath))
        let live = runTool(toolBin, ["activate-now", "--esp", espTool,
          "--uki", realUkiA2, "--attested",
          "--verity-root-hash", rootHashB,
          "--verity-data", devicesA.data, "--verity-hash", devicesA.hash])
        check(live.code == 66,
              "t_runtime_generation_switch_is_refused: `activate-now` on an " &
              "attested store exits 66 (got " & $live.code & ")")
        check("running generation" in live.output and
              "launch measurement" in live.output,
              "t_runtime_generation_switch_is_refused: naming the running " &
              "generation and why the measurement forbids it")
        check(sha256Hex(readFile(espTool / UkiEspFallbackPath)) == beforeTool,
              "t_runtime_generation_switch_is_refused: and the bytes " &
              "firmware would load are unchanged")

        # The polarity, through the same surface: without --attested the
        # same command does the switch. The subcommand is implemented.
        let espPlain = work / "esp-plain"
        createDir(espPlain)
        discard runTool(toolBin, ["stage", "--esp", espPlain,
          "--uki", realUkiA, "--verity-root-hash", rootHashA,
          "--verity-data", devicesA.data, "--verity-hash", devicesA.hash])
        let beforePlain = sha256Hex(readFile(espPlain / UkiEspFallbackPath))
        let livePlain = runTool(toolBin, ["activate-now", "--esp", espPlain,
          "--uki", realUkiA2, "--verity-root-hash", rootHashB,
          "--verity-data", devicesA.data, "--verity-hash", devicesA.hash])
        check(livePlain.code == 0 and
              sha256Hex(readFile(espPlain / UkiEspFallbackPath)) !=
                beforePlain,
              "t_runtime_generation_switch_is_refused: the same subcommand " &
              "on an UNMEASURED boot succeeds and replaces the running " &
              "slot, so the refusal above is a guard over a real capability")

        # A store the tool cannot read is a refusal, not an empty store.
        let espBad = work / "esp-bad"
        createDir(generationStoreDir(espBad))
        writeFile(generationIndexPath(espBad), "{\"schema\": \"nope\"}")
        let bad = runTool(toolBin, ["status", "--esp", espBad])
        check(bad.code == 65,
              "the tool refuses an index it cannot understand rather than " &
              "treating it as a fresh ESP (exit " & $bad.code & ")")
  except CatchableError as e:
    fail("the real-stub layer: the layer ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

# =====================================================================
# Layer 3 — four real boots. Opt-in.
# =====================================================================

type
  BootArtifacts = object
    stub: string
    kernel: string
    ovmfCode: string
    ovmfVars: string

proc discoverBootArtifacts(): (BootArtifacts, string) =
  var a: BootArtifacts
  a.stub = resolveUkiStub()
  if a.stub.len == 0:
    return (a, "no pinned EFI stub.\n" & describeUkiStubSearch())
  a.kernel = getEnv("REPROOS_UKI_GUEST_KERNEL")
  if a.kernel.len == 0:
    let packagesRoot = block:
      let configured = getEnv("REPROBUILD_PACKAGES_ROOT")
      if configured.len > 0: configured
      else: RepoRoot.parentDir / "reprobuild-packages"
    let srcKernel = packagesRoot /
      "packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz"
    if fileExists(srcKernel):
      a.kernel = srcKernel
    elif fileExists("/run/booted-system/kernel"):
      a.kernel = "/run/booted-system/kernel"
  if a.kernel.len == 0 or not fileExists(a.kernel):
    return (a, "no kernel: set REPROOS_UKI_GUEST_KERNEL, or build the " &
      "source kernel, or run on a host that publishes " &
      "/run/booted-system/kernel")
  a.ovmfCode = getEnv("VMH_OVMF_CODE")
  a.ovmfVars = getEnv("VMH_OVMF_VARS")
  if a.ovmfCode.len == 0 or a.ovmfVars.len == 0:
    for pair in [("/run/libvirt/nix-ovmf/edk2-x86_64-code.fd",
                  "/run/libvirt/nix-ovmf/edk2-i386-vars.fd"),
                 ("/usr/share/OVMF/OVMF_CODE.fd",
                  "/usr/share/OVMF/OVMF_VARS.fd"),
                 ("/usr/share/edk2/ovmf/OVMF_CODE.fd",
                  "/usr/share/edk2/ovmf/OVMF_VARS.fd")]:
      if fileExists(pair[0]) and fileExists(pair[1]):
        a.ovmfCode = pair[0]
        a.ovmfVars = pair[1]
        break
  if a.ovmfCode.len == 0 or not fileExists(a.ovmfCode) or
     a.ovmfVars.len == 0 or not fileExists(a.ovmfVars):
    return (a, "no OVMF/edk2 firmware pair: set VMH_OVMF_CODE and " &
      "VMH_OVMF_VARS, or install OVMF")
  (a, "")

proc bootEsp(qemu, ovmfCode, ovmfVars, espImage, serialLog,
             caseName: string; timeoutSec: int): bool =
  ## One boot. Nothing this proc starts may outlive it.
  removeFile(serialLog)
  let args = @[
    "-name", VmNamePrefix & caseName & "-" & $getCurrentProcessId(),
    "-machine", "q35,accel=kvm:tcg",
    "-m", "2048", "-smp", "2",
    "-drive", "if=pflash,format=raw,readonly=on,file=" & ovmfCode,
    "-drive", "if=pflash,format=raw,file=" & ovmfVars,
    "-drive", "file=" & espImage & ",format=raw,if=virtio",
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
    p.terminate()
    sleep(500)
    if p.running: p.kill()
    discard p.waitForExit()
    p.close()
    fail("the " & caseName & " guest did not power off within " &
         $timeoutSec & "s")
    return false
  discard p.waitForExit()
  p.close()
  true

proc transcript(path: string): string =
  if fileExists(path): readFile(path) else: ""

block layerRealBoot:
  # Wrapped so that a mutation which makes a store operation RAISE
  # is a named red line rather than an exception that takes every
  # check after it down with it.
  try:
    if getEnv(BootGateEnv) != "1":
      skip("the boot layer did not run: NO firmware loaded a generation, NO " &
           "kernel was started, and nothing here is evidence that a staged " &
           "generation boots or that a rolled-back one boots the old " &
           "configuration. Set " & BootGateEnv & "=1 to run it (~4 min; " &
           "needs qemu-system-x86_64, mkfs.vfat, mtools, an OVMF pair, a " &
           "kernel and the pinned EFI stub).")
    else:
      let gate = "generation boot layer"
      let (artifacts, why) = discoverBootArtifacts()
      if why.len > 0:
        fail(gate & ": " & why & ". This layer was asked for, so a missing " &
             "artifact is a failure, not a skip.")
      else:
        let qemu = requireTool(gate, "qemu-system-x86_64")
        let mkfsVfat = requireTool(gate, "mkfs.vfat")
        let mmd = requireTool(gate, "mmd")
        let mcopy = requireTool(gate, "mcopy")
        let mdir = requireTool(gate, "mdir")
        let cc = block:
          var found = ""
          for candidate in ["clang", "cc", "gcc"]:
            let p = findExe(candidate)
            if p.len > 0:
              found = p
              break
          if found.len == 0:
            fail(gate & ": no C compiler on PATH; the guest's /init is " &
                 "compiled from source by this gate")
          found
        if qemu.len > 0 and mkfsVfat.len > 0 and mmd.len > 0 and
           mcopy.len > 0 and mdir.len > 0 and cc.len > 0:
          let work = scratch("boot")

          # --- the guest's userspace -----------------------------------
          let initSrc = work / "init.c"
          let initBin = work / "init"
          writeFile(initSrc, GuestInitSource)
          let ccRun = execCmdEx(quoteShell(cc) &
            " -static -nostdlib -ffreestanding -fno-stack-protector -O2 -o " &
            quoteShell(initBin) & " " & quoteShell(initSrc))
          if ccRun.exitCode != 0:
            stderr.writeLine(ccRun.output)
            fail(gate & ": the guest init did not compile")
            removeDir(work)
          else:
            proc newcArchive(entries: seq[(string, uint32, string)]): string =
              proc field(v: int): string = toHex(v, 8).toLowerAscii
              result = ""
              for (name, mode, body) in entries:
                var header = "070701"
                header.add field(0)
                header.add field(int(mode))
                header.add field(0)
                header.add field(0)
                header.add field(1)
                header.add field(0)
                header.add field(body.len)
                for _ in 0 ..< 4: header.add field(0)
                header.add field(name.len + 1)
                header.add field(0)
                result.add header
                result.add name
                result.add '\0'
                while result.len mod 4 != 0: result.add '\0'
                result.add body
                while result.len mod 4 != 0: result.add '\0'
              result.add "070701" & repeat(field(0), 6) & field(0) &
                repeat(field(0), 4) & field(len("TRAILER!!!") + 1) & field(0)
              result.add "TRAILER!!!\0"
              while result.len mod 4 != 0: result.add '\0'

            let initrdPath = work / "initrd.img"
            writeFile(initrdPath, newcArchive(@[
              ("proc", 0o040755'u32 or 0o040000'u32, ""),
              ("dev", 0o040755'u32 or 0o040000'u32, ""),
              ("init", 0o100755'u32, readFile(initBin)),
            ]))

            # --- two real generations ----------------------------------
            # `console=ttyS0` is what makes the guest's transcript readable;
            # everything after it is the attested command line the product
            # would boot with, and the two generations differ in the verity
            # root hash and in the slot their pair lives on.
            let cmdlineA = cmdlineFor(rootHashA, devicesA,
                                      "console=ttyS0 panic=1 ")
            let cmdlineB = cmdlineFor(rootHashB, devicesB,
                                      "console=ttyS0 panic=1 ")
            proc assemble(cmdline, path: string): string =
              let image = assembleUkiFromFiles(UkiSpec(
                stubPath: artifacts.stub, kernelPath: artifacts.kernel,
                initrdPath: initrdPath, cmdline: cmdline,
                osRelease: defaultOsRelease("0.1.0"), uname: "",
                sourceDateEpoch: PinnedEpoch))
              writeFile(path, image)
              path
            let bootUkiA = assemble(cmdlineA, work / "gen-a.efi")
            let bootUkiB = assemble(cmdlineB, work / "gen-b.efi")

            # --- the store, on a directory that IS the mounted ESP ------
            # The stager writes into a mounted ESP; a FAT image is built
            # from that directory for each boot because mounting FAT needs
            # privileges this gate does not take. Every boot below is over
            # a fresh image of the store as it stood at that moment.
            let espDir = work / "esp"
            createDir(espDir)
            var store = readGenerationStore(espDir)

            proc buildEsp(sourceDir, path: string;
                          fallbackFrom = ""): bool =
              removeFile(path)
              var f = open(path, fmWrite)
              f.setFilePos(96 * 1024 * 1024 - 1)
              f.write('\0')
              f.close()
              var mkdirs = ""
              for d in ["EFI", "EFI/BOOT", GenerationStoreDir,
                        GenerationStoreDir & "/a", GenerationStoreDir & "/b"]:
                mkdirs.add " ::/" & d
              var steps = @[
                ("mkfs.vfat", quoteShell(mkfsVfat) & " -n ESP -F 32 " &
                  quoteShell(path)),
                ("mmd", quoteShell(mmd) & " -i " & quoteShell(path) & mkdirs)]
              for rel in [GenerationStoreDir & "/" & GenerationIndexFileName,
                          GenerationStoreDir & "/a/" & UkiFileName,
                          GenerationStoreDir & "/b/" & UkiFileName,
                          UkiEspFallbackPath]:
                let src =
                  if rel == UkiEspFallbackPath and fallbackFrom.len > 0:
                    fallbackFrom
                  else: sourceDir / rel
                if not fileExists(src): continue
                steps.add ("mcopy", quoteShell(mcopy) & " -i " &
                  quoteShell(path) & " " & quoteShell(src) & " ::/" & rel)
              for (what, cmd) in steps:
                let r = execCmdEx(cmd)
                if r.exitCode != 0:
                  stderr.writeLine("[esp] " & what & " exited " &
                    $r.exitCode & "\n[esp] command: " & cmd &
                    "\n[esp] output: " & r.output)
                  return false
              true

            var bootIndex = 0
            proc bootStore(sourceDir, caseName: string;
                           fallbackFrom = ""): string =
              ## Build an ESP from the store as it stands and boot it;
              ## return the serial transcript.
              bootIndex.inc
              let img = work / ("esp-" & $bootIndex & ".img")
              if not buildEsp(sourceDir, img, fallbackFrom):
                fail(gate & ": could not build the ESP image for " & caseName)
                return ""
              let vars = work / ("vars-" & $bootIndex & ".fd")
              copyFile(artifacts.ovmfVars, vars)
              setFilePermissions(vars, {fpUserRead, fpUserWrite})
              let log = work / ("serial-" & caseName & ".log")
              if not bootEsp(qemu, artifacts.ovmfCode, vars, img, log,
                             caseName, 240):
                stderr.writeLine(transcript(log))
                return ""
              transcript(log)

            # ---- boot 1: generation A, freshly installed ---------------
            discard stageInto(store, bootUkiA, rootHashA, devicesA, gsA)
            let t1 = bootStore(espDir, "gen-a")
            check("GEN-GUEST-START" in t1 and
                  ("GEN-CMDLINE=" & cmdlineA) in t1 and
                  "GEN-GUEST-DONE" in t1,
                  "t_generation_switch_requires_reboot: firmware loaded the " &
                  "generation the store selected and the guest reports its " &
                  "command line, root hash included, byte for byte")

            # ---- stage generation B ------------------------------------
            let slotABytesBefore = readFile(generationUkiPath(espDir, gsA))
            let outcome = stageInto(store, bootUkiB, rootHashB, devicesB,
                                    nextStagingSlot(store))
            check(outcome.rebootRequired and
                  readFile(generationUkiPath(espDir, gsA)) == slotABytesBefore,
                  "t_generation_switch_requires_reboot: staging reports " &
                  "reboot-required and leaves the running generation's " &
                  "unified kernel image byte-identical on the ESP")

            # ---- boot 2: the running generation's own slot, AFTER the
            #      stage. This is what "does not alter the running
            #      generation" means on a machine: reboot the slot it was
            #      running from and it is still that generation.
            let t2 = bootStore(espDir, "gen-a-after-stage",
                               fallbackFrom = generationUkiPath(espDir, gsA))
            check(("GEN-CMDLINE=" & cmdlineA) in t2 and
                  rootHashB notin t2,
                  "t_generation_switch_requires_reboot: booting the slot " &
                  "that was running, from the ESP AS IT STANDS AFTER THE " &
                  "STAGE, still gives generation a -- the stage did not " &
                  "alter it, it added a second generation beside it")

            # ---- boot 3: the reboot the stage asked for -----------------
            let t3 = bootStore(espDir, "gen-b")
            check(("GEN-CMDLINE=" & cmdlineB) in t3 and
                  ("GEN-CMDLINE=" & cmdlineA) notin t3,
                  "t_generation_switch_requires_reboot: after the reboot " &
                  "the STAGED generation is what runs, and the guest " &
                  "reports its command line and its root hash")

            # ---- boot 4: rollback ---------------------------------------
            let rolled = rollbackGeneration(store, attested = true)
            check(rolled.selected.verityRootHash == rootHashA,
                  "t_rollback_selects_previous_uki: rollback selects the " &
                  "previous generation")
            let t4 = bootStore(espDir, "gen-a-rolled-back")
            check(("GEN-CMDLINE=" & cmdlineA) in t4 and rootHashB notin t4,
                  "t_rollback_selects_previous_uki: the prior unified " &
                  "kernel image BOOTS, and the running guest identifies " &
                  "itself as the prior generation -- the old root hash on " &
                  "the old command line, out of the artifact firmware " &
                  "measured, with the newer generation's hash nowhere in " &
                  "the transcript")

            # ---- and the live switch, refused, with the ESP unmoved ----
            let beforeLive = storeSnapshot(store)
            var liveRefusal = ""
            try:
              discard stageInto(store, bootUkiB, rootHashB, devicesB,
                                store.current)
            except ValueError as e:
              liveRefusal = e.msg
            check(liveRefusal.len > 0 and
                  storeSnapshot(store) == beforeLive,
                  "t_runtime_generation_switch_is_refused: on the ESP that " &
                  "has just been booted four times, asking for the switch " &
                  "to take effect now is refused and not one byte of the " &
                  "store moves")

            # What is actually on the ESP, read back through mtools rather
            # than from the directory the store was written into.
            let img = work / ("esp-" & $bootIndex & ".img")
            if fileExists(img):
              let listing = execCmdEx(quoteShell(mdir) & " -b -/ -i " &
                quoteShell(img) & " ::/")
              check(listing.exitCode == 0 and
                    ("::/" & GenerationStoreDir & "/a/" & UkiFileName) in
                      listing.output and
                    ("::/" & GenerationStoreDir & "/b/" & UkiFileName) in
                      listing.output and
                    ("::/" & UkiEspFallbackPath) in listing.output and
                    "grub" notin listing.output.toLowerAscii and
                    "loader" notin listing.output.toLowerAscii,
                    "t_rollback_selects_previous_uki: the real FAT32 ESP " &
                    "carries BOTH generations plus the fallback binary, and " &
                    "no loader configuration file of any kind -- the only " &
                    "thing that decided any of the four boots above is which " &
                    "bytes are at " & UkiEspFallbackPath)

            echo "[info] boot transcripts under ", work
            echo "[info] generation a: ", sha256Hex(readFile(bootUkiA))
            echo "[info] generation b: ", sha256Hex(readFile(bootUkiB))
            echo "[info] kernel: ", artifacts.kernel
            echo "[info] stub: ", artifacts.stub

            if getEnv("REPROOS_GENERATION_KEEP") == "1":
              echo "[info] kept (REPROOS_GENERATION_KEEP=1): ", work
            else:
              removeDir(work)
  except CatchableError as e:
    fail("the boot layer: the layer ABORTED rather than " &
         "reporting: " & e.msg.splitLines()[0])

if failures > 0:
  stderr.writeLine("test_generations: " & $failures & " check(s) failed, " &
                   $passes & " passed, " & $skips & " skipped")
  quit(1)
echo "generations under attestation: PASS (" & $passes & " checks, " &
     $skips & " skipped layer(s))"
