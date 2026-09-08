## Gate: the kernel command line is inside the measured boot artifact.
##
## ## What is being claimed
##
## The read-only root already has a short name — the dm-verity root hash
## — that changes when any byte of it changes. A boot path that carries
## that name is only worth something if the boot path is itself covered
## by the launch measurement. On a GRUB boot it is not: ``grub.cfg`` is a
## file on the ESP, firmware measures the loader binary rather than the
## string the loader passes on, and an attacker who edits one line boots
## the same signed GRUB with a different root hash and identical PCRs.
##
## A **unified kernel image** puts the kernel, the initrd, the command
## line and the EFI stub into one PE binary, so the command line is
## inside the thing that is measured. Four properties have to hold, and
## they are this gate's four registered cases:
##
##   * ``t_uki_is_deterministic`` — two builds of the same inputs produce
##     byte-identical images. An artifact whose bytes move on their own
##     cannot be the subject of a precomputed measurement.
##   * ``t_uki_cmdline_pins_verity_root_hash`` — the ``.cmdline`` section
##     carries exactly the root hash the verity build produced, and
##     changing the root closure changes both.
##   * ``t_uki_digest_changes_with_cmdline`` — a ONE-CHARACTER change to
##     the command line changes the image's digest. This is the property
##     the whole measurement chain rests on: if a command line could be
##     altered without moving the artifact, every PCR value downstream
##     would be a statement about nothing.
##   * ``t_uki_boots`` — a real machine boots one, and the command line
##     the kernel receives is the one inside the image.
##
## ## The layers, and what each is worth
##
##   1. **The assembler** (always on, ~1s, no external tool and no
##      artifact). The PE surgery in ``repro/uki.nim`` is exercised
##      against a synthetic PE32+ stub this file builds, so the layer
##      needs nothing installed. It PROVES the assembler is
##      deterministic, that every section round-trips byte for byte, that
##      the section table it writes is internally consistent, and that
##      the refusals fire. It proves NOTHING about the real stub, and
##      nothing about a machine.
##
##   2. **The real, pinned stub and the shipped tool**
##      (artifact-conditional; a visible skip naming the remedy when the
##      stub is absent, ~10s). The pinned ``linuxx64.efi.stub`` is
##      resolved BY CONTENT, a real UKI is assembled from it, and the
##      shipped ``tools/reproos_uki.nim`` is compiled and run against the
##      same inputs — its output must be byte-identical to the
##      in-process one. Two paths, one artifact. It PROVES the product's
##      own code produces the image the module describes. It does NOT
##      prove the image boots.
##
##   3. **A real boot** (opt-in, ``REPROOS_UKI_BOOT_GATE=1``, ~40s). A
##      UKI is written to a FAT ESP as the removable-media fallback
##      binary and handed to OVMF in a transient QEMU guest. The guest's
##      ``/init`` prints ``/proc/cmdline``, so the assertion is what the
##      KERNEL received, read off the serial console. It PROVES the image
##      is a bootable PE, that firmware and ``systemd-stub`` accept it,
##      and that the command line the kernel gets is the one inside the
##      measured binary — with no loader configuration file anywhere in
##      the path. It does NOT prove anything about PCR values (nothing
##      here reads a TPM), and it does NOT boot a ReproOS root: the
##      guest's userspace is a purpose-built 9 KB init, not the product's.
##
## ## What no layer here proves
##
## No ReproOS image is built and no verity root is mounted. The kernel in
## layers 2 and 3 is whichever kernel the host can supply, the initrd is
## purpose-built, and no TPM is attached, so nothing here is evidence
## about a PCR. What is exercised is the real product code that assembles
## the real image.
##
## ## Signing
##
## Every image here is UNSIGNED, deliberately. ``systemd-stub`` measures
## the sections it consumes whether or not the PE is signed, so an
## unsigned UKI is fully attestable on the TPM tier; Secure Boot firmware
## refuses to load one, so ``sbsign`` and a key-custody story remain
## deferred. The gate asserts that the manifest says so rather than
## leaving it implicit.
##
## ## Mocking
##
## None. Layer 1 computes over a synthetic stub it builds from the PE
## specification — that is a fixture, not a mock: the code under test is
## the real assembler and the assertions are about real PE bytes. Layers
## 2 and 3 use the real pinned stub, the real shipped tool, a real
## kernel, real firmware and a real QEMU.

import std/[options, os, osproc, strutils, tables, times]

import repro_profile/types

import "../repro/uki"
import "../repro/verity"
import "../repro/generations"
import "../repro/disk_layouts"

import nimcrypto/[hash, sha2]

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  BootGateEnv = "REPROOS_UKI_BOOT_GATE"

  VmNamePrefix = "reproos-att-uki-"
    ## Every guest this gate starts is named under the shared
    ## ``reproos-att-`` prefix and torn down unconditionally, so nothing
    ## it creates can be confused with the production guests that share
    ## this host.

  PinnedEpoch = 1735689600'i64
    ## The epoch the image recipe pins. Used here so the gate and the
    ## recipe agree on what a reproducible build's timestamp is.

  GateSeed = "reproos-image-v1:uki-gate-a"
    ## A build identity seed. The volumes an attested command line names
    ## are derived from one, per generation slot, exactly as the recipe
    ## derives them — see ``repro/generations.nim``.

  GuestInitSource = """
/* The guest's /init. Freestanding on purpose: raw syscalls, no libc, no
 * BusyBox, no shell. Two reasons. It makes the boot layer depend on
 * nothing but the C compiler this gate already declares -- a full-applet
 * static BusyBox is not something a checkout can assume. And it makes
 * the guest's userspace a function of THIS FILE, so the transcript it
 * prints cannot drift from what the gate asserts about it. */
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
  say("UKI-GUEST-START\n");
  long f = sys(SYS_open, (long)"/proc/cmdline", 0, 0, 0, 0);
  static char buf[8192];
  long n = f >= 0 ? sys(SYS_read, f, (long)buf, sizeof buf - 1, 0, 0) : -1;
  say("UKI-CMDLINE=");
  if (n > 0) {
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == 0)) n--;
    sys(SYS_write, con, (long)buf, n, 0, 0);
  }
  say("\nUKI-GUEST-DONE\n");
  /* LINUX_REBOOT_MAGIC1, MAGIC2, CMD_POWER_OFF */
  sys(SYS_reboot, 0xfee1deadL, 672274793L, 0x4321fedcL, 0, 0);
  sys(SYS_exit, 0, 0, 0, 0, 0);
}
"""

let GateBootDevices = attestedBootDevices(GateSeed, gsA)
  ## The volumes generation A's command line names, derived exactly as the
  ## recipe derives them.

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

# =====================================================================
# The synthetic stub layer 1 assembles against.
#
# A FIXTURE, not a mock: it is a real PE32+ image built from the
# specification, and the code under test is the real assembler operating
# on real PE bytes. It exists so that the always-on layer needs no
# systemd installed anywhere.
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

proc syntheticStub(headerRoom = 1536; sections = 1): string =
  ## A minimal but genuine PE32+ EFI application. ``headerRoom`` is
  ## ``SizeOfHeaders``; passing a small value is how the "a stub with no
  ## room for the section table" refusal is provoked.
  let firstRaw = max(headerRoom, SynthFileAlignment)
  result = newString(firstRaw + SynthFileAlignment)
  result[0] = 'M'
  result[1] = 'Z'
  putU32(result, 0x3C, SynthPeOffset)
  result[SynthPeOffset] = 'P'
  result[SynthPeOffset + 1] = 'E'
  let coff = SynthPeOffset + 4
  putU16(result, coff, 0x8664)                     # Machine: x86-64
  putU16(result, coff + 2, sections)               # NumberOfSections
  putU32(result, coff + 4, 315532800)              # TimeDateStamp
  putU16(result, coff + 16, SynthOptionalHeaderSize)
  putU16(result, coff + 18, 0x022E)                # Characteristics
  let opt = coff + 20
  putU16(result, opt, 0x20B)                       # PE32+
  putU32(result, opt + 32, SynthSectionAlignment)
  putU32(result, opt + 36, SynthFileAlignment)
  putU32(result, opt + 56, 2 * SynthSectionAlignment)  # SizeOfImage
  putU32(result, opt + 60, headerRoom)             # SizeOfHeaders
  putU32(result, opt + 64, 0)                      # CheckSum
  for i in 0 ..< sections:
    let at = SynthSectionTable + i * 40
    let name = ".s" & $i
    for j in 0 ..< name.len:
      result[at + j] = name[j]
    putU32(result, at + 8, 16)                                   # VirtualSize
    putU32(result, at + 12, (i + 1) * SynthSectionAlignment)     # VA
    putU32(result, at + 16, SynthFileAlignment)                  # SizeOfRawData
    putU32(result, at + 20, firstRaw)                            # PointerToRawData
    putU32(result, at + 36, 0x40000040)

proc synthSpec(cmdline: string; kernel = "SYNTHETIC-KERNEL-PAYLOAD";
               initrd = "SYNTHETIC-INITRD-PAYLOAD"): seq[UkiSection] =
  ukiSections(UkiSpec(
    cmdline: cmdline,
    osRelease: defaultOsRelease("0.1.0"),
    uname: "6.12.0-reproos"), kernel, initrd)

# =====================================================================
# Layer 1 — the assembler. Always on.
# =====================================================================

let katRootHash = block:
  # A REAL verity root hash, derived through repro/verity.nim over a real
  # byte array, rather than a literal. What the command line pins has to
  # be the value the verity build produces, so the gate derives it the
  # same way the build does.
  let spec = verityRootSpec("reproos-image-v1:uki-gate-a")
  var data = newStringOfCap(64 * VerityDataBlockSize)
  for i in 0 ..< 64:
    let d = sha256.digest("reproos-uki-kat:" & $i)
    var b = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      b[j] = char(d.data[j])
    for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
      data.add b
  verityRootHash(spec, data)

let katCmdline = attestedKernelCmdline(katRootHash,
  GateBootDevices.data, GateBootDevices.hash,
  GateBootDevices.stateVar, GateBootDevices.stateHome)

block layerAssemblerStructure:
  let stub = syntheticStub()
  let image = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)

  check(image.len > stub.len, "assembling appends to the stub")
  check(image[0 .. 1] == "MZ", "the result is still a PE image")

  let stubSections = readPeSections(stub)
  let sections = readPeSections(image)
  check(sections.len == stubSections.len + 5,
        "the section table grew by exactly the five sections a ReproOS " &
        "UKI carries (got " & $(sections.len - stubSections.len) & ")")

  # The order is the whole determinism story: two builds that emit the
  # same sections in a different order are different artifacts.
  var appended: seq[string] = @[]
  for s in sections[stubSections.len .. ^1]:
    appended.add s.name
  var declared: seq[string] = @[]
  for name in UkiSectionOrder: declared.add name
  check(appended == declared,
        "the sections are written in the declared order " &
        declared.join(", ") & " (got " & appended.join(", ") & ")")

  # The section table has to describe the file it is in. A table that
  # points past the end, overlaps itself, or is misaligned produces an
  # image firmware silently refuses to load.
  let layout = parsePeLayout(image)
  var problems: seq[string] = @[]
  var prevEnd = 0
  var prevVirtualEnd = 0
  for s in sections:
    if s.fileOffset + s.rawSize > image.len:
      problems.add s.name & ": raw data runs past the end of the file"
    if s.virtualSize > s.rawSize and s.rawSize > 0:
      problems.add s.name & ": VirtualSize " & $s.virtualSize &
        " exceeds SizeOfRawData " & $s.rawSize
    if s.fileOffset mod layout.fileAlignment != 0:
      problems.add s.name & ": PointerToRawData " & $s.fileOffset &
        " is not a multiple of FileAlignment " & $layout.fileAlignment
    if s.virtualAddress mod layout.sectionAlignment != 0:
      problems.add s.name & ": VirtualAddress is not section-aligned"
    if s.fileOffset < prevEnd:
      problems.add s.name & ": raw data overlaps the section before it"
    if s.virtualAddress < prevVirtualEnd:
      problems.add s.name & ": virtual address overlaps the section before it"
    prevEnd = s.fileOffset + s.rawSize
    prevVirtualEnd = s.virtualAddress + s.virtualSize
  check(problems.len == 0,
        "every section's raw data and virtual address are aligned, " &
        "in range and non-overlapping" &
        (if problems.len > 0: " -- " & problems.join("; ") else: ""))
  check(layout.sizeOfImage >= prevVirtualEnd and
        layout.sizeOfImage mod layout.sectionAlignment == 0,
        "SizeOfImage covers the last section and is section-aligned " &
        "(got " & $layout.sizeOfImage & ", last section ends at " &
        $prevVirtualEnd & ")")

  # The two header fields that would otherwise be a source of bytes that
  # are not a function of the inputs.
  let coff = layout.peOffset + 4
  var stamp = 0'i64
  for i in countdown(3, 0):
    stamp = (stamp shl 8) or int64(uint8(image[coff + 4 + i]))
  check(stamp == PinnedEpoch,
        "the COFF timestamp is SOURCE_DATE_EPOCH (" & $PinnedEpoch &
        "), not the stub's own or the wall clock -- got " & $stamp)
  var checksum = 0
  for i in countdown(3, 0):
    checksum = (checksum shl 8) or int(uint8(image[coff + 20 + 64 + i]))
  check(checksum == 0, "the PE checksum is zeroed rather than stale")

block layerSectionsRoundTrip:
  # A section that cannot be read back byte for byte is a section the
  # stub cannot consume. Two of the payloads below are chosen for the
  # boundary the padding rule lives on: one is exactly a multiple of the
  # file alignment and one is one byte past it.
  let stub = syntheticStub()
  let exact = repeat("K", 4 * SynthFileAlignment)
  let ragged = repeat("I", SynthFileAlignment + 1) & "\0\0trailing\0"
  let image = assembleUki(stub, synthSpec(katCmdline, exact, ragged),
                          PinnedEpoch)
  check(ukiSectionContent(image, UkiLinuxSection) == exact,
        "a kernel payload whose length is an exact multiple of the file " &
        "alignment reads back byte for byte")
  check(ukiSectionContent(image, UkiInitrdSection) == ragged,
        "an initrd payload with embedded NULs and a ragged length reads " &
        "back byte for byte, so the alignment padding is not handed back " &
        "as content")
  check(ukiCmdline(image) == katCmdline,
        "the command line reads back exactly as it was written")
  check(ukiSectionContent(image, UkiUnameSection) == "6.12.0-reproos",
        "the kernel release reads back")
  check(ukiSectionContent(image, ".nosuch").len == 0,
        "a section the image does not carry reads back as nothing")

# ---------------------------------------------------------------------
# t_uki_is_deterministic
# ---------------------------------------------------------------------

block tUkiIsDeterministicAssembler:
  let stub = syntheticStub()
  let a = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  let b = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  check(a == b,
        "t_uki_is_deterministic: two assemblies of the same inputs are " &
        "byte-identical")

  # The negative half. If the epoch were taken from the clock rather than
  # from the caller, the two images above would still be equal within one
  # second of each other and this gate would never notice.
  let later = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch + 1)
  check(later != a,
        "t_uki_is_deterministic: the COFF timestamp is really in the " &
        "image -- a different SOURCE_DATE_EPOCH gives different bytes, " &
        "so 'identical' above is not identical-by-not-looking")

  # And the caller's environment must not reach it. `assembleUki` is
  # pure, but a future implementation that read TZ or the locale would
  # pass every check above and fail here.
  let savedTz = getEnv("TZ")
  putEnv("TZ", "Pacific/Kiritimati")
  let underOtherTz = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  if savedTz.len > 0: putEnv("TZ", savedTz) else: delEnv("TZ")
  check(underOtherTz == a,
        "t_uki_is_deterministic: the assembly does not depend on the " &
        "caller's timezone")

# ---------------------------------------------------------------------
# t_uki_cmdline_pins_verity_root_hash
# ---------------------------------------------------------------------

block tUkiCmdlinePinsVerityRootHash:
  let stub = syntheticStub()
  let image = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  let carried = ukiCmdline(image)

  check(carried == katCmdline,
        "t_uki_cmdline_pins_verity_root_hash: the .cmdline section is " &
        "the composed command line, byte for byte")
  check(VerityRootHashCmdlineKey & "=" & katRootHash in carried,
        "t_uki_cmdline_pins_verity_root_hash: it carries " &
        VerityRootHashCmdlineKey & "=" & katRootHash)
  check(carried.count(katRootHash) == 1,
        "the root hash appears exactly once, so there is one answer to " &
        "what root this image expects")

  # The command line is composed from repro/verity.nim's renderings, not
  # from a literal here, so the keys the initrd parses and the keys the
  # image measures cannot drift.
  var missingKeys: seq[string] = @[]
  for key in [VerityRootHashCmdlineKey, VerityDataDeviceCmdlineKey,
              VerityHashDeviceCmdlineKey, VerityStateVarCmdlineKey,
              VerityStateHomeCmdlineKey]:
    if key & "=" notin carried:
      missingKeys.add key
  check(missingKeys.len == 0,
        "the measured command line names every key repro/verity.nim " &
        "declares and init-disk parses" &
        (if missingKeys.len > 0: " -- missing " & missingKeys.join(", ")
         else: ""))

  # CHANGING THE ROOT CLOSURE CHANGES BOTH. Derived end to end: two
  # different byte arrays through the real verity construction, two root
  # hashes, two command lines, two images.
  let specB = verityRootSpec("reproos-image-v1:uki-gate-a")
  var dataB = newStringOfCap(64 * VerityDataBlockSize)
  for i in 0 ..< 64:
    let d = sha256.digest("reproos-uki-kat:" & $i)
    var b = newString(VerityDigestSize)
    for j in 0 ..< VerityDigestSize:
      b[j] = char(d.data[j])
    for _ in 0 ..< (VerityDataBlockSize div VerityDigestSize):
      dataB.add b
  # One byte of the root closure.
  dataB[7 * VerityDataBlockSize + 11] =
    char(uint8(dataB[7 * VerityDataBlockSize + 11]) xor 0x01'u8)
  let rootHashB = verityRootHash(specB, dataB)
  check(rootHashB != katRootHash,
        "one changed byte of the root closure changes the verity root " &
        "hash (the premise this case rests on)")
  let cmdlineB = attestedKernelCmdline(rootHashB,
    GateBootDevices.data, GateBootDevices.hash,
    GateBootDevices.stateVar, GateBootDevices.stateHome)
  let imageB = assembleUki(stub, synthSpec(cmdlineB), PinnedEpoch)
  check(ukiCmdline(imageB) != carried and
        katRootHash notin ukiCmdline(imageB),
        "t_uki_cmdline_pins_verity_root_hash: changing the root closure " &
        "changes the command line, and the old root hash is gone from it")
  check(ukiDigest(imageB) != ukiDigest(image),
        "t_uki_cmdline_pins_verity_root_hash: ... and changes the image, " &
        "so a launch measurement over the image covers the root closure")

  # The refusals. A command line that has lost its root hash still boots
  # and still measures; it just silently drops the integrity check. So it
  # is refused at assembly rather than discovered at attestation time.
  check(validateAttestedCmdline(carried, katRootHash).len == 0,
        "a well-formed attested command line is accepted")
  check(validateAttestedCmdline(
          "ro quiet " & VerityDataDeviceCmdlineKey & "=/dev/vda2 " &
          VerityHashDeviceCmdlineKey & "=/dev/vda3", katRootHash).len > 0,
        "a command line WITHOUT the root hash is refused")
  check(validateAttestedCmdline(
          VerityRootHashCmdlineKey & "=" & katRootHash & " ro",
          katRootHash).len > 0,
        "a command line with a root hash but no data/hash device is " &
        "refused, because init-disk refuses that combination at boot")
  check(validateAttestedCmdline(carried, "not-a-root-hash").len > 0,
        "a root hash that is not 64 hex digits is refused")
  var truncated = katRootHash
  truncated[0] = (if truncated[0] == 'a': 'b' else: 'a')
  check(validateAttestedCmdline(carried, truncated).len > 0,
        "a command line pinning a DIFFERENT root hash from the one the " &
        "build produced is refused")

# ---------------------------------------------------------------------
# t_uki_digest_changes_with_cmdline
#
# The property the whole measurement chain rests on. Checked with
# same-length substitutions as well as with insertions: a length change
# moves every offset after the .cmdline section and would make the
# digest move for a reason that has nothing to do with the command
# line's content. A one-character SUBSTITUTION leaves the entire rest of
# the image byte-identical, so if the digest still moves, it moved
# because of the command line and nothing else.
# ---------------------------------------------------------------------

block tUkiDigestChangesWithCmdline:
  let stub = syntheticStub()
  let base = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  let baseDigest = ukiDigest(base)

  var bad: seq[string] = @[]
  for at in [0, 1, katCmdline.len div 2, katCmdline.len - 2,
             katCmdline.len - 1]:
    var mutated = katCmdline
    mutated[at] = (if mutated[at] == 'x': 'y' else: 'x')
    let image = assembleUki(stub, synthSpec(mutated), PinnedEpoch)
    if ukiDigest(image) == baseDigest:
      bad.add "offset " & $at
    if image.len != base.len:
      bad.add "offset " & $at & " changed the image LENGTH, so this case " &
        "is not the same-length substitution it claims to be"
  check(bad.len == 0,
        "t_uki_digest_changes_with_cmdline: substituting ONE character " &
        "anywhere in the command line -- first, second, middle, " &
        "second-to-last, last -- changes the image digest, with the " &
        "image the same length" &
        (if bad.len > 0: " -- " & bad.join("; ") else: ""))

  # The sharpest form: flip one character of the ROOT HASH itself. This
  # is the mutation an attacker would want, and it must be visible in
  # the artifact.
  var swapped = katCmdline
  let hashAt = swapped.find(katRootHash)
  # Guarded rather than indexed straight: a command line that has lost
  # its root hash is exactly the defect the case above tests for, and it
  # must be reported as a named red line rather than abort the run with
  # an index error and take every check after it down too.
  if hashAt < 0:
    fail("t_uki_digest_changes_with_cmdline: the composed command line " &
         "does not contain the root hash at all, so the mutation this " &
         "case rests on cannot be applied")
  else:
    swapped[hashAt] = (if swapped[hashAt] == '0': '1' else: '0')
    let swappedImage = assembleUki(stub, synthSpec(swapped), PinnedEpoch)
    check(ukiDigest(swappedImage) != baseDigest and
          swappedImage.len == base.len,
          "t_uki_digest_changes_with_cmdline: changing ONE character of " &
          "the root hash on the command line changes the image digest")

  # And the falsification: the only way the property above could fail is
  # for the command line not to be in the image at all. That is
  # unrepresentable -- a section list without .cmdline is refused.
  var withoutCmdline: seq[UkiSection] = @[]
  for s in synthSpec(katCmdline):
    if s.name != UkiCmdlineSection:
      withoutCmdline.add s
  check(validateUkiSections(withoutCmdline).len > 0,
        "t_uki_digest_changes_with_cmdline: a UKI without a .cmdline " &
        "section is REFUSED, so the property above cannot be lost by " &
        "quietly dropping the section")
  var raised = false
  try:
    discard assembleUki(stub, withoutCmdline, PinnedEpoch)
  except ValueError:
    raised = true
  check(raised, "... and the assembler raises rather than emitting one")

block layerRefusals:
  # Every one of these is a build failure by design: an image that is
  # nearly right is worse than none, because it looks measurable.
  let stub = syntheticStub()
  check(validateUkiSections(synthSpec(katCmdline)).len == 0,
        "the declared section list is accepted")

  var noKernel: seq[UkiSection] = @[]
  for s in synthSpec(katCmdline):
    if s.name != UkiLinuxSection: noKernel.add s
  check(validateUkiSections(noKernel).len > 0,
        "a UKI without a kernel is refused")

  var reordered = synthSpec(katCmdline)
  swap(reordered[0], reordered[1])
  check(validateUkiSections(reordered).len > 0,
        "sections handed over out of the declared order are refused, " &
        "rather than silently producing a different artifact for an " &
        "identical system")

  var duplicated = synthSpec(katCmdline)
  duplicated.add duplicated[0]
  check(validateUkiSections(duplicated).len > 0,
        "a duplicated section is refused")

  var empty = synthSpec(katCmdline)
  empty[0].content = ""
  check(validateUkiSections(empty).len > 0,
        "a present-but-empty section is refused")

  var longName = synthSpec(katCmdline)
  longName[0].name = ".averylongname"
  check(validateUkiSections(longName).len > 0,
        "a section name longer than the 8 bytes a COFF header holds is " &
        "refused")

  # A stub with no room in its headers for the new section entries. The
  # alternative to refusing is writing the table over the first
  # section's bytes and shipping an image that will not load.
  var cramped = false
  try:
    discard assembleUki(syntheticStub(headerRoom = 512),
                        synthSpec(katCmdline), PinnedEpoch)
  except ValueError as e:
    cramped = "header" in e.msg
  check(cramped,
        "a stub whose headers have no room for the section table is " &
        "refused, naming the headroom")

  # Not a PE at all.
  var notPe = false
  try:
    discard assembleUki("this is not a PE image at all, not even close",
                        synthSpec(katCmdline), PinnedEpoch)
  except ValueError:
    notPe = true
  check(notPe, "a stub that is not a PE image is refused")

  # The spec-level refusals.
  check(validateUkiSpec(UkiSpec(stubPath: "", kernelPath: "/dev/null",
        cmdline: "x", osRelease: "y", sourceDateEpoch: 1)).len > 0,
        "a spec with no stub is refused, naming where one is looked for")
  check(validateUkiStub("/nonexistent/linuxx64.efi.stub").len > 0,
        "a stub path that does not exist is refused")
  # The manifest's renderer has a fixed key order and no escaping rule,
  # so a command line it could not represent is refused at assembly
  # rather than producing a manifest a consumer cannot parse.
  block:
    let stubPath = resolveUkiStub()
    if stubPath.len > 0:
      # A real regular file for the kernel: `fileExists` is `S_ISREG`, so
      # /dev/null would trip the earlier "the kernel image does not
      # exist" arm and this case would pass for the wrong reason.
      let scratch = getTempDir() / "reproos-uki-quote-" &
        $getCurrentProcessId()
      createDir(scratch)
      defer: removeDir(scratch)
      let fakeKernel = scratch / "kernel.bin"
      writeFile(fakeKernel, "kernel")
      let quoted = UkiSpec(stubPath: stubPath, kernelPath: fakeKernel,
        cmdline: "root=\"x\"", osRelease: "y", sourceDateEpoch: 1)
      let refusal = validateUkiSpec(quoted)
      check(refusal.len > 0 and "quote" in refusal,
            "a command line carrying a quote or a backslash is refused, " &
            "naming why -- the manifest beside the image records it " &
            "(got " & refusal.escape() & ")")

block layerStubIsPinnedByContent:
  # The stub's bytes are inside the measurement twice over: they are most
  # of the PE firmware measures, and the stub is the code that decides
  # what gets extended into PCR 11. So it is identified by digest, and
  # anything else is refused naming BOTH digests.
  let work = getTempDir() / "reproos-uki-stubpin-" & $getCurrentProcessId()
  createDir(work)
  defer: removeDir(work)
  let impostor = work / "linuxx64.efi.stub"
  writeFile(impostor, syntheticStub())
  let refusal = validateUkiStub(impostor)
  check(refusal.len > 0 and PinnedUkiStubSha256 in refusal and
        sha256Hex(readFile(impostor)) in refusal,
        "a stub that is not the pinned bytes is refused, naming both the " &
        "digest it has and the digest it must have")
  check(PinnedUkiStubSha256.len == 64 and PinnedUkiStubName.len > 0 and
        PinnedUkiStubProvider.len > 0,
        "the pin names the artifact (" & PinnedUkiStubName & "), where " &
        "it comes from (" & PinnedUkiStubProvider & ") and its digest")
  check(describeUkiStubSearch().contains(PinnedUkiStubSha256) and
        describeUkiStubSearch().contains(UkiStubEnvVar),
        "the not-found diagnostic names the wanted digest and the " &
        "override, so it names the fix rather than only the symptom")

block layerSigningIsOutOfScope:
  # Recorded rather than left implicit. An unsigned UKI is fully
  # attestable on the TPM tier -- systemd-stub measures the sections it
  # consumes whether or not the PE is signed -- and is NOT loadable under
  # Secure Boot.
  let stub = syntheticStub()
  let image = assembleUki(stub, synthSpec(katCmdline), PinnedEpoch)
  let manifest = renderUkiManifest(UkiSpec(cmdline: katCmdline,
    osRelease: defaultOsRelease("0.1.0"), sourceDateEpoch: PinnedEpoch),
    image)
  check("\"signed\": false" in manifest,
        "the manifest states that the image is unsigned, so a consumer " &
        "reads the fact rather than assuming it")
  check("\"digest\": \"" & ukiDigest(image) & "\"" in manifest and
        "\"stubSha256\": \"" & PinnedUkiStubSha256 & "\"" in manifest,
        "the manifest carries the image digest and the pinned stub digest")
  check(renderUkiManifest(UkiSpec(cmdline: katCmdline,
          osRelease: defaultOsRelease("0.1.0"),
          sourceDateEpoch: PinnedEpoch), image) == manifest,
        "the manifest is deterministic")

  let uki = readFile(RepoRoot / "repro/uki.nim")
  check("sbsign" in uki and "Secure Boot" in uki,
        "repro/uki.nim records that signing is deferred and why an " &
        "unsigned image is still attestable on the TPM tier")
  let tool = readFile(RepoRoot / "tools/reproos_uki.nim")
  check("sbsign" notin tool.replace("sbsign remains deferred", ""),
        "the assembler does not sign, and does not pretend to")

# ---------------------------------------------------------------------
# The declarations that have to agree. They are in three languages, so
# nothing but a check like this keeps them in step.
# ---------------------------------------------------------------------

block layerDeclarationsAgree:
  let driver = readFile(
    RepoRoot / "recipes/reproos-image/scripts/build-reproos-image.sh")
  check("UKI_ESP_PATH=" & UkiEspFallbackPath in driver,
        "the image driver installs the UKI at the path repro/uki.nim " &
        "declares (" & UkiEspFallbackPath & ")")
  check("--no-grub" in driver,
        "the driver tells install-root not to install GRUB on the " &
        "attested layout")
  check("rm -rf \"$MNT_DIR/boot/grub\"" in driver,
        "and REMOVES the grub.cfg install-root writes anyway -- a " &
        "grub.cfg left on the ESP is an unmeasured second answer to how " &
        "the machine boots")
  check("$REPROOS_UKI" in driver and "$MNT_DIR/boot/$UKI_ESP_PATH" in driver,
        "the driver copies the assembled UKI onto the ESP")
  # The ext4 layout must be untouched: it makes no integrity claim, and
  # breaking its boot path in the name of the attested one would be a
  # regression dressed as progress.
  check("grub.cfg" in driver,
        "the uefi-ext4 layout still gets its grub.cfg")

  let recipe = readFile(RepoRoot / "recipes/reproos-image/package.nim")
  check("nim.c(" in recipe and "tools/reproos_uki.nim" in recipe,
        "the assembler is built by a typed nim.c edge rather than by a " &
        "shell invocation of a compiler")
  # Searched over the CODE, not the comments: the block comment above the
  # action explains why an objcopy pipeline was not used, and a naive
  # substring search would read that explanation as the thing it warns
  # against.
  var recipeCode: seq[string] = @[]
  for line in recipe.splitLines():
    let stripped = line.strip()
    if stripped.startsWith("#") or stripped.startsWith("##"):
      continue
    recipeCode.add line
  let recipeBody = recipeCode.join("\n")
  check("objcopy" notin recipeBody and "ukify" notin recipeBody,
        "the UKI is assembled by the typed action, not by an objcopy or " &
        "ukify pipeline")
  check("ukiAssembleArgv" in recipe,
        "the action's argv is rendered from the typed request in " &
        "repro/uki.nim, so the recipe and this gate cannot drift")

  let initDisk = readFile(RepoRoot / "recipes/reproos-iso/initramfs/init-disk")
  var unparsed: seq[string] = @[]
  for key in [VerityRootHashCmdlineKey, VerityDataDeviceCmdlineKey,
              VerityHashDeviceCmdlineKey, VerityStateVarCmdlineKey,
              VerityStateHomeCmdlineKey]:
    if (key & "=*)") notin initDisk:
      unparsed.add key
  check(unparsed.len == 0,
        "init-disk parses every key the measured command line carries" &
        (if unparsed.len > 0: " -- missing " & unparsed.join(", ") else: ""))

  # The preset's operator-facing reason has to keep up with what is true.
  # It said the command line was unmeasured; it is measured now, and a
  # reason that is no longer true is worse than no reason.
  let preset = findDiskLayoutPreset("uefi-attested")
  check(preset.isSome, "the attested layout preset is still registered")
  if preset.isSome:
    let reason = preset.get().unbuildableReason
    check("GRUB" notin reason,
          "the attested preset no longer says boot goes through GRUB")
    check("unified kernel image" in reason,
          "it says the boot path is a unified kernel image now")
    check("hash tree" in reason,
          "and it names what is still missing: the layout carries a " &
          "hash-tree volume per generation slot now, and nothing writes " &
          "the verity data image or its Merkle tree onto them")
    check(preset.get().status == dlsDeclared and reason.len > 0,
          "the attested preset is STILL refused -- a measured command " &
          "line naming volumes nothing ever writes would be worse than a " &
          "refusal")

  # And every volume the measured command line names must be one the
  # layout declares, or the boot would look for something that is not
  # there. The verity pair is named by PARTUUID and the state volumes by
  # label; ``repro/generations.nim`` owns both decisions and explains why
  # a filesystem label cannot name either half of a verity pair.
  let params = DiskLayoutParams(id: "reproos", device: "/dev/nbd0",
                                espSizeMib: 512, diskSizeGb: 32)
  let attested = buildDiskLayout("uefi-attested", params)
  var undeclared: seq[string] = @[]
  for slot in [gsA, gsB]:
    for name in [rootPartitionName(slot), hashPartitionName(slot)]:
      if name notin attested.disks[AttestedDiskName].partitions:
        undeclared.add name
  check(undeclared.len == 0,
        "both halves of both generations' verity pairs are volumes the " &
        "attested layout declares" &
        (if undeclared.len > 0: " -- missing " & undeclared.join(", ")
         else: ""))
  var missingStateLabels: seq[string] = @[]
  for label in [StateVarLabel, StateHomeLabel]:
    var found = false
    for _, p in attested.disks[AttestedDiskName].partitions:
      if p.content.kind == cfsFilesystem and p.content.label == label:
        found = true
    if not found: missingStateLabels.add label
  check(missingStateLabels.len == 0,
        "and the state volumes the command line names by label carry " &
        "those labels" &
        (if missingStateLabels.len > 0: " -- missing " &
          missingStateLabels.join(", ") else: ""))
  check(GateBootDevices.data.startsWith("PARTUUID=") and
        GateBootDevices.hash.startsWith("PARTUUID="),
        "the verity pair is named by PARTUUID rather than by filesystem " &
        "label: a Merkle tree carries no filesystem, and with two slots " &
        "staged both data carriers hold an image with the same label")

# =====================================================================
# Layer 2 — the real, pinned stub and the shipped tool.
#
# Artifact-conditional: a missing stub is a missing ARTIFACT, so it is a
# visible skip naming the remedy. A missing TOOL, once the layer is
# running, is a loud failure.
# =====================================================================

proc requireTool(gate, tool: string): string =
  ## ``followSymlinks = false`` is not a detail. Several of the tools
  ## below are ONE binary that dispatches on ``argv[0]``: every mtools
  ## command is a symlink to ``mtools``, and resolving the symlink hands
  ## the multiplexer a name it does not recognise, which it answers with
  ## its own usage text and exit 1. MEASURED: ``mmd -i esp.img ::/EFI``
  ## invoked as the resolved ``.../bin/mtools`` printed "Supported
  ## commands:" and failed the ESP build.
  let found = findExe(tool, followSymlinks = false)
  if found.len == 0:
    fail(gate & ": required tool not found on PATH: " & tool &
         ". This layer is running, so its absence is a failure, not a skip.")
  found

proc nimCcArgs(): string =
  ## The compiler the gate was told to use, carried to any nested
  ## ``nim c``. tests/nim-gate.sh exports it precisely so that a nested
  ## compile does not fall back to a bare `gcc` the hermetic PATH does
  ## not carry.
  getEnv("REPROOS_NIM_CC_ARGS")

var shippedTool = ""
  ## Set by layer 2 and reused by layer 3.

block layerRealStubAndShippedTool:
  let stubPath = resolveUkiStub()
  if stubPath.len == 0:
    skip("the real-stub layer did not run: NO pinned EFI stub was found, " &
         "so NO real unified kernel image was assembled and the shipped " &
         "assembler was NOT run. " & describeUkiStubSearch())
  else:
    let gate = "uki real-stub layer"
    check(ukiStubDigest(stubPath) == PinnedUkiStubSha256,
          "the stub was resolved BY CONTENT: " & stubPath &
          " has the pinned digest")

    let work = getTempDir() / "reproos-uki-tools-" & $getCurrentProcessId()
    removeDir(work)
    createDir(work)

    # Purpose-built payloads rather than a real kernel: this layer is
    # about the assembler and the tool, and a 12 MB kernel would make it
    # slow without making it stronger. Layer 3 uses a real one.
    let kernelPath = work / "kernel.bin"
    let initrdPath = work / "initrd.img"
    writeFile(kernelPath, repeat("K", 300_000) & "\0\0kernel-tail")
    writeFile(initrdPath, repeat("I", 90_000) & "\0initrd-tail")
    let rootHashPath = work / "roothash"
    writeFile(rootHashPath, katRootHash & "\n")

    let request = UkiAssembleRequest(
      stubPath: stubPath,
      kernelPath: kernelPath,
      initrdPath: initrdPath,
      verityRootHashPath: rootHashPath,
      verityDataDevice: GateBootDevices.data,
      verityHashDevice: GateBootDevices.hash,
      stateVarDevice: GateBootDevices.stateVar,
      stateHomeDevice: GateBootDevices.stateHome,
      extraArgs: @[],
      osReleaseVersion: "0.1.0",
      unamePath: "",
      sourceDateEpoch: PinnedEpoch,
      outputDir: work / "out")
    check(validateUkiAssembleRequest(request).len == 0,
          "the typed assembly request the recipe builds is accepted")

    # 2a. The real stub, in process, twice.
    let spec = UkiSpec(
      stubPath: stubPath,
      kernelPath: kernelPath,
      initrdPath: initrdPath,
      cmdline: katCmdline,
      osRelease: defaultOsRelease("0.1.0"),
      uname: "",
      sourceDateEpoch: PinnedEpoch)
    let realA = assembleUkiFromFiles(spec)
    let realB = assembleUkiFromFiles(spec)
    check(realA == realB,
          "t_uki_is_deterministic: two assemblies over the REAL pinned " &
          "stub are byte-identical (" & $realA.len & " bytes, sha256 " &
          ukiDigest(realA) & ")")
    check(ukiCmdline(realA) == katCmdline,
          "t_uki_cmdline_pins_verity_root_hash: the real image's " &
          ".cmdline is the composed command line")
    check(ukiSectionContent(realA, UkiLinuxSection) == readFile(kernelPath) and
          ukiSectionContent(realA, UkiInitrdSection) == readFile(initrdPath),
          "the real image's kernel and initrd sections read back byte " &
          "for byte")

    var oneChar = katCmdline
    oneChar[10] = (if oneChar[10] == 'x': 'y' else: 'x')
    var otherSpec = spec
    otherSpec.cmdline = oneChar
    let realC = assembleUkiFromFiles(otherSpec)
    check(realC.len == realA.len and ukiDigest(realC) != ukiDigest(realA),
          "t_uki_digest_changes_with_cmdline: on the REAL stub, a " &
          "one-character substitution changes the digest with the image " &
          "the same length")

    # 2b. The SHIPPED tool. Compiled here and run against the same
    #     inputs; its output must be the same bytes. Two paths, one
    #     artifact -- which is what stops the recipe's assembler and the
    #     module this gate exercises from being different programs.
    discard requireTool(gate, "nim")
    let toolBin = work / "reproos-uki"
    let compile = execCmdEx("nim c --hints:off --warnings:off " &
      nimCcArgs() & " --out:" & quoteShell(toolBin) & " " &
      quoteShell(RepoRoot / "tools/reproos_uki.nim"))
    if compile.exitCode != 0:
      stderr.writeLine(compile.output)
      fail(gate & ": the shipped assembler does not compile")
    else:
      shippedTool = toolBin
      var argv = ukiAssembleArgv(toolBin, request)
      var cmd = ""
      for a in argv:
        if cmd.len > 0: cmd.add " "
        cmd.add quoteShell(a)
      let run = execCmdEx(cmd)
      if run.exitCode != 0:
        stderr.writeLine(run.output)
        fail(gate & ": the shipped assembler failed")
      else:
        let outputs = ukiOutputPaths(request)
        let produced = readFile(outputs[0])
        check(produced == realA,
              "the shipped tools/reproos_uki.nim produces the same bytes " &
              "as the module this gate drives directly -- two paths, one " &
              "artifact")
        check(readFile(outputs[2]).strip() == ukiDigest(realA),
              "and reports the same digest")
        check(readFile(outputs[3]).strip() == katCmdline,
              "and writes the command line it composed, so a consumer " &
              "reads what was measured rather than re-deriving it")
        check("\"signed\": false" in readFile(outputs[1]),
              "and a manifest that says the image is unsigned")

        # THE ROOT HASH REALLY COMES FROM THE FILE. Change the file by one
        # character -- the change a different root closure would produce --
        # and both the command line inside the image and the image's
        # digest must move.
        var moved = katRootHash
        moved[0] = (if moved[0] == '0': '1' else: '0')
        writeFile(rootHashPath, moved & "\n")
        var secondRequest = request
        secondRequest.outputDir = work / "out2"
        var argv2 = ukiAssembleArgv(toolBin, secondRequest)
        var cmd2 = ""
        for a in argv2:
          if cmd2.len > 0: cmd2.add " "
          cmd2.add quoteShell(a)
        let run2 = execCmdEx(cmd2)
        if run2.exitCode != 0:
          stderr.writeLine(run2.output)
          fail(gate & ": the shipped assembler failed on the second run")
        else:
          let outputs2 = ukiOutputPaths(secondRequest)
          let produced2 = readFile(outputs2[0])
          check(ukiCmdline(produced2).contains(moved) and
                not ukiCmdline(produced2).contains(katRootHash),
                "t_uki_cmdline_pins_verity_root_hash: the tool reads the " &
                "root hash from the FILE the verity build writes, so a " &
                "different root closure gives a different command line")
          check(ukiDigest(produced2) != ukiDigest(produced) and
                produced2.len == produced.len,
                "t_uki_digest_changes_with_cmdline: ... and a different " &
                "image, of the same length")
        writeFile(rootHashPath, katRootHash & "\n")

        # The tool's own refusals.
        let badHash = work / "badhash"
        writeFile(badHash, "not-a-root-hash\n")
        var badRequest = request
        badRequest.verityRootHashPath = badHash
        badRequest.outputDir = work / "out3"
        var badArgv = ukiAssembleArgv(toolBin, badRequest)
        var badCmd = ""
        for a in badArgv:
          if badCmd.len > 0: badCmd.add " "
          badCmd.add quoteShell(a)
        let badRun = execCmdEx(badCmd)
        check(badRun.exitCode != 0,
              "the tool refuses a root hash that is not 64 hex digits " &
              "rather than measuring a command line nothing can verify")
        let bothRun = execCmdEx(quoteShell(toolBin) &
          " assemble --stub " & quoteShell(stubPath) &
          " --kernel " & quoteShell(kernelPath) &
          " --cmdline foo --verity-root-hash-file " &
          quoteShell(rootHashPath) &
          " --source-date-epoch 1 --out " & quoteShell(work / "x.efi"))
        check(bothRun.exitCode != 0,
              "the tool refuses --cmdline together with " &
              "--verity-root-hash-file; a command line that is partly " &
              "composed and partly literal is one nothing can re-derive")

    if getEnv("REPROOS_UKI_KEEP") != "1":
      removeDir(work)
    else:
      echo "[info] kept (REPROOS_UKI_KEEP=1): ", work

# =====================================================================
# Layer 3 — a real boot. Opt-in.
# =====================================================================

type
  BootArtifacts = object
    stub: string
    kernel: string
    ovmfCode: string
    ovmfVars: string

proc discoverBootArtifacts(): (BootArtifacts, string) =
  ## Returns the artifacts and "", or a partly-filled record and the
  ## reason it could not be completed.
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

  # The firmware. A UKI is loaded by UEFI firmware and by nothing else,
  # so this layer cannot fall back to a direct kernel boot -- doing so
  # would test the kernel rather than the image.
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

proc bootUki(qemu, ovmfCode, ovmfVars, espImage, serialLog,
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
  if getEnv(BootGateEnv) != "1":
    skip("the boot layer did not run: NO firmware loaded a unified " &
         "kernel image, NO kernel was started, and nothing here is " &
         "evidence that the image boots. Set " & BootGateEnv &
         "=1 to run it (~40s; needs qemu-system-x86_64, mkfs.vfat, " &
         "mtools, an OVMF pair, a kernel and the pinned EFI stub).")
  else:
    let gate = "uki boot layer"
    let (artifacts, why) = discoverBootArtifacts()
    if why.len > 0:
      fail(gate & ": " & why & ". This layer was asked for, so a missing " &
           "artifact is a failure, not a skip.")
    else:
      let qemu = requireTool(gate, "qemu-system-x86_64")
      let mkfsVfat = requireTool(gate, "mkfs.vfat")
      let mmd = requireTool(gate, "mmd")
      let mcopy = requireTool(gate, "mcopy")
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
         mcopy.len > 0 and cc.len > 0:
        let work = getTempDir() / "reproos-uki-boot-" &
          $getCurrentProcessId()
        removeDir(work)
        createDir(work)

        # --- the guest's userspace ---------------------------------
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
          # A cpio archive, written here rather than shelled out to,
          # because `cpio` is not a tool this gate declares and the
          # format is ten lines.
          proc newcArchive(entries: seq[(string, uint32, string)]): string =
            proc field(v: int): string = toHex(v, 8).toLowerAscii
            result = ""
            for (name, mode, body) in entries:
              var header = "070701"
              header.add field(0)                    # ino
              header.add field(int(mode))            # mode
              header.add field(0)                    # uid
              header.add field(0)                    # gid
              header.add field(1)                    # nlink
              header.add field(0)                    # mtime
              header.add field(body.len)             # filesize
              for _ in 0 ..< 4: header.add field(0)  # devmajor..rdevminor
              header.add field(name.len + 1)         # namesize
              header.add field(0)                    # check
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

          # --- the image ---------------------------------------------
          # `console=ttyS0` is what makes the guest's own transcript
          # readable; everything after it is the attested command line
          # the product would boot with.
          let bootCmdline = "console=ttyS0 panic=1 " &
            attestedKernelCmdline(katRootHash,
              GateBootDevices.data, GateBootDevices.hash,
              GateBootDevices.stateVar,
              GateBootDevices.stateHome)
          let spec = UkiSpec(
            stubPath: artifacts.stub,
            kernelPath: artifacts.kernel,
            initrdPath: initrdPath,
            cmdline: bootCmdline,
            osRelease: defaultOsRelease("0.1.0"),
            uname: "",
            sourceDateEpoch: PinnedEpoch)
          let image = assembleUkiFromFiles(spec)
          let ukiPath = work / UkiFileName
          writeFile(ukiPath, image)

          proc buildEsp(uki, path: string): bool =
            ## A real FAT32 ESP with the image at the removable-media
            ## fallback path -- the same path the image driver installs
            ## to. Each step's output is reported on failure, because
            ## "could not build the ESP" on its own diagnoses nothing.
            removeFile(path)
            var f = open(path, fmWrite)
            f.setFilePos(96 * 1024 * 1024 - 1)
            f.write('\0')
            f.close()
            # The directories come from the declared install path rather
            # than from a literal, so this helper follows the constant
            # instead of pinning a second copy of it.
            var mkdirs = ""
            var walked = ""
            for part in UkiEspFallbackPath.split('/')[0 .. ^2]:
              walked = (if walked.len == 0: part else: walked & "/" & part)
              mkdirs.add " ::/" & walked
            for (what, cmd) in [
                ("mkfs.vfat", quoteShell(mkfsVfat) & " -n ESP -F 32 " &
                  quoteShell(path)),
                ("mmd", quoteShell(mmd) & " -i " & quoteShell(path) &
                  mkdirs),
                ("mcopy", quoteShell(mcopy) & " -i " & quoteShell(path) &
                  " " & quoteShell(uki) & " ::/" & UkiEspFallbackPath)]:
              let r = execCmdEx(cmd)
              if r.exitCode != 0:
                stderr.writeLine("[esp] " & what & " exited " &
                  $r.exitCode & "\n[esp] command: " & cmd &
                  "\n[esp] output: " & r.output)
                return false
            true

          let esp = work / "esp.img"
          if not buildEsp(ukiPath, esp):
            fail(gate & ": could not build the ESP image")
          else:
            let vars = work / "vars.fd"
            copyFile(artifacts.ovmfVars, vars)
            setFilePermissions(vars, {fpUserRead, fpUserWrite})
            let log = work / "serial-clean.log"
            if bootUki(qemu, artifacts.ovmfCode, vars, esp, log,
                       "boots", 240):
              let t = transcript(log)
              check("UKI-GUEST-START" in t,
                    "t_uki_boots: firmware loaded the unified kernel " &
                    "image from the ESP, the stub started the kernel it " &
                    "carries, and the kernel ran the initrd it carries")
              check("UKI-CMDLINE=" & bootCmdline in t,
                    "t_uki_boots: /proc/cmdline in the running guest is " &
                    "EXACTLY the .cmdline section of the image -- there " &
                    "is no loader configuration file anywhere in this " &
                    "boot path")
              check("UKI-CMDLINE=" & bootCmdline in t and
                    (VerityRootHashCmdlineKey & "=" & katRootHash) in t,
                    "t_uki_boots: and the verity root hash reached the " &
                    "kernel inside the measured binary")
              check("UKI-GUEST-DONE" in t,
                    "t_uki_boots: the guest ran to completion and powered " &
                    "itself off")
            else:
              stderr.writeLine(transcript(log))

            # --- the same claim, falsified -------------------------
            # A one-character change to the command line, and nothing
            # else. The guest must report the CHANGED line and the image
            # must have a different digest. Without this, "the guest
            # printed the command line" would be consistent with the
            # guest printing a command line that came from somewhere
            # else entirely.
            var altered = bootCmdline
            let at = altered.find(katRootHash)
            if at < 0:
              fail(gate & ": the booted command line does not contain " &
                   "the root hash, so the one-character mutation this " &
                   "case rests on cannot be applied")
            altered[max(at, 0)] =
              (if altered[max(at, 0)] == '0': '1' else: '0')
            var alteredSpec = spec
            alteredSpec.cmdline = altered
            let alteredImage = assembleUkiFromFiles(alteredSpec)
            let alteredUki = work / "altered.efi"
            writeFile(alteredUki, alteredImage)
            check(alteredImage.len == image.len and
                  ukiDigest(alteredImage) != ukiDigest(image),
                  "t_uki_digest_changes_with_cmdline: on the image that " &
                  "actually boots, one changed character of the root " &
                  "hash changes the digest and nothing else about the " &
                  "image's size")
            let esp2 = work / "esp-altered.img"
            if not buildEsp(alteredUki, esp2):
              fail(gate & ": could not build the altered ESP image")
            else:
              let vars2 = work / "vars2.fd"
              copyFile(artifacts.ovmfVars, vars2)
              setFilePermissions(vars2, {fpUserRead, fpUserWrite})
              let log2 = work / "serial-altered.log"
              if bootUki(qemu, artifacts.ovmfCode, vars2, esp2, log2,
                         "altered", 240):
                let t2 = transcript(log2)
                check("UKI-CMDLINE=" & altered in t2 and
                      ("UKI-CMDLINE=" & bootCmdline) notin t2,
                      "t_uki_digest_changes_with_cmdline: the guest " &
                      "booted from the altered image reports the ALTERED " &
                      "command line, so what the kernel receives really " &
                      "is the section that changed")
              else:
                stderr.writeLine(transcript(log2))

            echo "[info] boot transcripts under ", work
            echo "[info] uki digest: ", ukiDigest(image)
            echo "[info] kernel: ", artifacts.kernel
            echo "[info] stub: ", artifacts.stub

          if getEnv("REPROOS_UKI_KEEP") == "1":
            echo "[info] kept (REPROOS_UKI_KEEP=1): ", work
          else:
            removeDir(work)

if failures > 0:
  stderr.writeLine("test_uki: " & $failures & " check(s) failed, " &
                   $passes & " passed, " & $skips & " skipped")
  quit(1)
echo "unified kernel image: PASS (" & $passes & " checks, " & $skips &
     " skipped layer(s))"
