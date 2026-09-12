## Gate: what an attested image will measure, computed before it boots —
## and checked against what a real machine reports.
##
## ## What is being claimed
##
## The boot artifact already carries the whole identity of the machine:
## the kernel, the initrd and a command line pinning the read-only root's
## dm-verity hash, all inside one PE binary. That is only useful if
## someone can say, *before any machine exists*, what a TPM will report
## when that binary boots. This gate is about that statement.
##
## A UEFI stub measures the image's own sections into PCR 11 before it
## starts the kernel: for each section, first the section NAME, then the
## section CONTENT, each as an ordinary TCG event. The value is therefore
## a pure function of the image, and the build writes it into a
## ``reproos.attested-image.v1`` document beside the image.
##
## Three registered cases:
##
##   * ``t_manifest_deterministic`` — two emissions of the same image are
##     byte-identical, and a one-character change to the command line
##     moves them. A document whose bytes wander cannot be compared, and
##     comparison is the only thing it is for.
##   * ``t_manifest_rejects_unknown_launch_shape`` — an unknown backend or
##     an unknown schema field fails the BUILD. After a document is
##     published it is too late: the only thing a verifier can do with an
##     expectation nobody can compute is reject it.
##   * ``t_pcr11_precomputation_matches_measured_boot`` — the crux. The
##     precomputed PCR 11 equals the value a real guest reads out of a
##     real TPM after a real firmware and a real stub have extended it.
##     A hash chain checked only against itself will produce a stable
##     wrong answer forever; nothing but a machine can say otherwise.
##
## ## The layers, and what each is worth
##
##   1. **The schema, calculator and recipe command** (always on, seconds,
##      no build artifact). Real PE bytes assembled here against a
##      synthetic PE32+ stub — a fixture, not a mock, since the code under
##      test is the real reader and the real renderer. PROVES the document
##      is deterministic, that every refusal fires, and that the measured
##      ORDER is the stub's rather than the file's. PROVES NOTHING about
##      any machine. The recipe command runs an argv-capture fixture using
##      the gate's declared bash/mkdir tools, including SDK paths with spaces.
##
##   2. **The shipped emitter** (artifact-conditional, ~10s). The real
##      pinned stub, a real unified kernel image, a real dm-verity image,
##      and the manifest produced by the shipped ``repro attest expect``
##      — the same command a verifier runs when it rebuilds this image and
##      compares. PROVES the product's own emitter produces the document
##      this gate describes, twice, byte for byte, and refuses the
##      documents it must refuse. Does NOT prove the value is right.
##
##   3. **A real measured boot** (opt-in, ``REPROOS_PCR_BOOT_GATE=1``,
##      ~2 min). Two transient QEMU guests, each with its own
##      swtpm-backed TPM 2.0, booting a real unified kernel image through
##      OVMF off a real FAT32 ESP. The guest's ``/init`` is a freestanding
##      ELF this gate compiles: it loads the TPM drivers, issues a raw
##      ``TPM2_PCR_Read`` on ``/dev/tpm0`` and prints the register. PROVES
##      the precomputation is the value the hardware reports. The SECOND
##      guest is what makes it more than a coincidence: one character of
##      the command line is changed, the precomputation moves, and the
##      register moves with it to the new predicted value.
##
## ## What no layer here proves
##
## No ReproOS image is built. The kernel is whichever kernel the host can
## supply and the root image is a small purpose-built one, so nothing here
## is evidence about a ReproOS closure. The TPM is a software TPM: it is a
## real TPM 2.0 implementation and it is really extended by real firmware,
## but it is not a discrete chip and no quote is signed by anything whose
## provenance chains to a vendor. The confidential-VM tiers are not
## computed at all; their arrays are emitted empty and the gate asserts
## that they are, so a reader cannot mistake absence for a value.
##
## ## Mocking
##
## No core implementation is mocked. The synthetic stub in layer 1 is a
## fixture built from the PE specification; the argv-capture executable
## records a command invocation without implementing the manifest emitter.
## Layers 2 and 3 use the real pinned stub, the real
## shipped CLI, real firmware, a real software TPM and a real QEMU.

import std/[json, macros, os, osproc, streams, strutils, tables, tempfiles, times]

import repro_attest

import "../repro/attest" as attestModule
import "../repro/uki" as ukiModule
import "../repro/verity"
import "../repro/generations"
import "./gate_layers"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  BootGateEnv = "REPROOS_PCR_BOOT_GATE"
  KeepEnv = "REPROOS_PCR_KEEP"
  GuestKernelEnv = "REPROOS_PCR_GUEST_KERNEL"
  GuestModuleDirEnv = "REPROOS_PCR_GUEST_MODULE_DIR"

  VmNamePrefix = "reproos-att-pcr-"
    ## Every guest this gate starts is named under the shared
    ## ``reproos-att-`` prefix and torn down unconditionally, so nothing
    ## it creates can be confused with the production guests that share
    ## this host.

  PinnedEpoch = 1735689600'i64
  GateSeed = "reproos-image-v1:pcr-gate-a"
  GateFingerprint = "reproos-image-v1:0123456789abcdef0123456789abcdef01234567"

  TpmModuleNames = ["rng-core", "tpm", "tpm_tis_core", "tpm_tis"]
    ## Loaded in this order: each depends on the ones before it. A kernel
    ## that carries them built in needs none of them, which is the shape
    ## the product's own kernel has.

  GuestInitSource = """
/* The guest's /init. Freestanding on purpose: raw syscalls, no libc, no
 * BusyBox, no shell -- so the guest's userspace is a function of THIS
 * FILE and cannot drift from what the gate asserts about it, and the
 * layer needs no tool beyond the C compiler the gate already has.
 *
 * It loads the TPM drivers if the kernel did not, then reads PCR 11 with
 * a raw TPM2_PCR_Read written to /dev/tpm0 on ONE file description --
 * the kernel's TPM character device discards the response if the
 * description is closed between the write and the read. */
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
#define SYS_close 3
#define SYS_nanosleep 35
#define SYS_mount 165
#define SYS_reboot 169
#define SYS_exit 60
#define SYS_finit_module 313

static unsigned long slen(const char *s) {
  unsigned long n = 0; while (s[n]) n++; return n;
}
static int con = 1;
static void say(const char *s) { sys(SYS_write, con, (long)s, slen(s), 0, 0); }
static void sayn(const char *s, long n) { sys(SYS_write, con, (long)s, n, 0, 0); }
static const char hexd[] = "0123456789abcdef";
static void sayhex(const unsigned char *p, long n) {
  static char out[8192];
  long i;
  if (n > 4000) n = 4000;
  for (i = 0; i < n; i++) { out[2*i] = hexd[p[i] >> 4]; out[2*i+1] = hexd[p[i] & 15]; }
  sayn(out, n * 2);
}
static void saydec(long v) {
  char b[24]; int i = 23; b[i--] = 0;
  if (v == 0) b[i--] = '0';
  if (v < 0) { say("-"); v = -v; }
  while (v > 0) { b[i--] = (char)('0' + (v % 10)); v /= 10; }
  say(&b[i+1]);
}
static void napms(long ms) {
  long ts[2]; ts[0] = ms / 1000; ts[1] = (ms % 1000) * 1000000L;
  sys(SYS_nanosleep, (long)ts, 0, 0, 0, 0);
}
static void loadmod(const char *path) {
  long fd = sys(SYS_open, (long)path, 0, 0, 0, 0);
  say("REPROOS-PCR-MODULE=");
  say(path);
  if (fd < 0) { say(":absent\n"); return; }
  long r = sys(SYS_finit_module, fd, (long)"", 0, 0, 0);
  sys(SYS_close, fd, 0, 0, 0, 0);
  if (r == 0) say(":loaded\n");
  else { say(":finit_module="); saydec(r); say("\n"); }
}

void _start(void) {
  long fd = sys(SYS_open, (long)"/dev/console", 1 /* O_WRONLY */, 0, 0, 0);
  if (fd >= 0) con = (int)fd;
  sys(SYS_mount, (long)"none", (long)"/proc", (long)"proc", 0, 0);
  sys(SYS_mount, (long)"none", (long)"/sys", (long)"sysfs", 0, 0);
  sys(SYS_mount, (long)"none", (long)"/dev", (long)"devtmpfs", 0, 0);
  say("REPROOS-PCR-GUEST-START\n");

  {
    long f = sys(SYS_open, (long)"/proc/cmdline", 0, 0, 0, 0);
    static char buf[8192];
    long n = f >= 0 ? sys(SYS_read, f, (long)buf, sizeof buf - 1, 0, 0) : -1;
    say("REPROOS-PCR-CMDLINE=");
    if (n > 0) {
      while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == 0)) n--;
      sayn(buf, n);
    }
    say("\n");
    if (f >= 0) sys(SYS_close, f, 0, 0, 0, 0);
  }

  loadmod("/lib/rng-core.ko");
  loadmod("/lib/tpm.ko");
  loadmod("/lib/tpm_tis_core.ko");
  loadmod("/lib/tpm_tis.ko");

  long t = -1;
  for (int i = 0; i < 100; i++) {
    t = sys(SYS_open, (long)"/dev/tpm0", 2 /* O_RDWR */, 0, 0, 0);
    if (t >= 0) break;
    napms(50);
  }
  if (t < 0) {
    say("REPROOS-PCR-TPM-DEVICE=absent\n");
  } else {
    say("REPROOS-PCR-TPM-DEVICE=present\n");
    /* TPM2_PCR_Read, SHA-256 bank, PCR 11 alone.
     *   8001      TPM_ST_NO_SESSIONS
     *   00000014  commandSize = 20
     *   0000017e  TPM_CC_PCR_Read
     *   00000001  one selection
     *   000b      TPM_ALG_SHA256
     *   03        three selection bytes
     *   000800    PCR 11 = byte 1, bit 3 */
    static const unsigned char cmd[] = {
      0x80, 0x01, 0x00, 0x00, 0x00, 0x14,
      0x00, 0x00, 0x01, 0x7e,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x0b, 0x03, 0x00, 0x08, 0x00 };
    long w = sys(SYS_write, t, (long)cmd, sizeof cmd, 0, 0);
    say("REPROOS-PCR-WRITE="); saydec(w); say("\n");
    static unsigned char resp[4096];
    long n = 0;
    for (int i = 0; i < 200; i++) {
      n = sys(SYS_read, t, (long)resp, sizeof resp, 0, 0);
      if (n > 0) break;
      napms(50);
    }
    say("REPROOS-PCR-READ=");
    if (n > 0) sayhex(resp, n); else saydec(n);
    say("\n");
    sys(SYS_close, t, 0, 0, 0, 0);
  }
  say("REPROOS-PCR-GUEST-DONE\n");
  /* LINUX_REBOOT_MAGIC1, MAGIC2, CMD_POWER_OFF */
  sys(SYS_reboot, 0xfee1deadL, 672274793L, 0x4321fedcL, 0, 0);
  sys(SYS_exit, 0, 0, 0, 0, 0);
}
"""

let GateBootDevices = attestedBootDevices(GateSeed, gsA)

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

# =====================================================================
# The synthetic stub layer 1 assembles against.
#
# A FIXTURE, not a mock: a genuine PE32+ image built from the
# specification, so the always-on layer needs nothing installed. It even
# carries a `.sbat` section, because a real stub does and `.sbat` is
# measured — a fixture without one would let a wrong calculator pass.
# =====================================================================

const
  SynthOptionalHeaderSize = 240
  SynthPeOffset = 0x40
  SynthSectionTable = SynthPeOffset + 4 + 20 + SynthOptionalHeaderSize
  SynthFileAlignment = 512
  SynthSectionAlignment = 4096
  SynthSbat = "sbat,1,SBAT Version,sbat,1,https://example.invalid\n"

proc putU16(b: var string; at, v: int) =
  b[at] = char(v and 0xFF)
  b[at + 1] = char((v shr 8) and 0xFF)

proc putU32(b: var string; at: int; v: int64) =
  for i in 0 ..< 4:
    b[at + i] = char((v shr (8 * i)) and 0xFF)

proc syntheticStub(): string =
  ## A minimal but genuine PE32+ EFI application carrying one `.sbat`.
  let headerRoom = 1536
  let firstRaw = max(headerRoom, SynthFileAlignment)
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
  putU32(result, opt + 60, headerRoom)
  putU32(result, opt + 64, 0)
  let at = SynthSectionTable
  for j in 0 ..< ".sbat".len:
    result[at + j] = ".sbat"[j]
  putU32(result, at + 8, SynthSbat.len)
  putU32(result, at + 12, SynthSectionAlignment)
  putU32(result, at + 16, SynthFileAlignment)
  putU32(result, at + 20, firstRaw)
  putU32(result, at + 36, 0x40000040)
  for j in 0 ..< SynthSbat.len:
    result[firstRaw + j] = SynthSbat[j]

let katRootHash = block:
  # A REAL verity root hash through the product's own construction, not a
  # literal: what the command line pins has to be what the verity build
  # produces.
  let spec = verityRootSpec(GateSeed)
  var data = newStringOfCap(64 * VerityDataBlockSize)
  for i in 0 ..< 64:
    let d = sha256Hex("reproos-pcr-kat:" & $i)
    for _ in 0 ..< (VerityDataBlockSize div 64):
      data.add d
  verityRootHash(spec, data)

let katCmdline = attestedKernelCmdline(katRootHash,
  GateBootDevices.data, GateBootDevices.hash,
  GateBootDevices.stateVar, GateBootDevices.stateHome)

proc synthUki(cmdline: string; kernel = "SYNTHETIC-KERNEL-PAYLOAD";
              initrd = "SYNTHETIC-INITRD-PAYLOAD"): string =
  assembleUki(syntheticStub(), ukiSections(UkiSpec(
    cmdline: cmdline,
    osRelease: defaultOsRelease("0.1.0"),
    uname: "6.12.0-reproos"), kernel, initrd), PinnedEpoch)

proc manifestFor(image: string; fingerprint = GateFingerprint;
                 verityBytes = "a-verity-protected-root-image"
                 ): AttestedImageManifest =
  attestedImageManifest(fingerprint, image,
    DigestPrefix & sha256Hex(verityBytes), katRootHash,
    @(AttestBackends))

# =====================================================================
# Layer 1 — the schema and the calculator. Always on.
# =====================================================================

block tManifestDeterministicSchema:
  let image = synthUki(katCmdline)
  let a = renderAttestedImageManifest(manifestFor(image))
  let b = renderAttestedImageManifest(manifestFor(image))
  check(a == b,
        "t_manifest_deterministic: two emissions of the same image are " &
        "byte-identical")

  # The negative half, in the form that carries the claim: a
  # SAME-LENGTH one-character substitution in the command line. The
  # image keeps its size and every other offset, so the document can
  # only have moved because the command line did.
  var altered = katCmdline
  let at = altered.find(katRootHash)
  check(at >= 0, "t_manifest_deterministic: the command line carries the " &
        "root hash, so the one-character mutation can be applied")
  if at >= 0:
    altered[at] = (if altered[at] == '0': '1' else: '0')
    let movedImage = synthUki(altered)
    check(movedImage.len == image.len,
          "t_manifest_deterministic: the mutation left the image the same " &
          "length, so nothing but the command line changed")
    let moved = renderAttestedImageManifest(manifestFor(movedImage))
    check(moved != a,
          "t_manifest_deterministic: one changed character of the root hash " &
          "moves the expected measurement -- 'identical' above is not " &
          "identical-by-not-looking")

  # The caller's environment must not reach it.
  let savedTz = getEnv("TZ")
  putEnv("TZ", "Pacific/Kiritimati")
  let underOtherTz = renderAttestedImageManifest(manifestFor(image))
  if savedTz.len > 0: putEnv("TZ", savedTz) else: delEnv("TZ")
  check(underOtherTz == a,
        "t_manifest_deterministic: the document does not depend on the " &
        "caller's timezone")

  # It is the schema the design names, it carries all three backend keys,
  # and the two the build cannot compute are visibly EMPTY rather than
  # absent -- a reader must not have to guess which.
  let doc = parseJson(a)
  check(doc["schema"].getStr == AttestedImageSchema,
        "t_manifest_deterministic: the document declares " &
        AttestedImageSchema)
  var missing: seq[string] = @[]
  for backend in KnownBackends:
    if not doc["expected"].hasKey(backend): missing.add backend
  check(missing.len == 0,
        "t_manifest_deterministic: every backend key is present" &
        (if missing.len > 0: " -- missing " & missing.join(", ") else: ""))
  check(doc["expected"][BackendTpm].len == 1 and
        doc["expected"][BackendSevSnp].len == 0 and
        doc["expected"][BackendTdx].len == 0,
        "t_manifest_deterministic: the TPM tier is computed and the " &
        "confidential-VM tiers are visibly empty rather than omitted")
  check(doc["imageOutputs"]["uki"].getStr == DigestPrefix & sha256Hex(image),
        "t_manifest_deterministic: imageOutputs.uki is the digest of the " &
        "image the measurement was taken over")

block layerCalculatorStructure:
  let image = synthUki(katCmdline)
  let measured = measureUkiPcr11(image)

  # The measured order is the STUB's, not the file's. This is the single
  # easiest way to produce a stable wrong answer, and it is invisible
  # unless the two orders are compared.
  var measuredOrder: seq[string] = @[]
  for e in measured.events: measuredOrder.add e.section
  var fileOrder: seq[string] = @[]
  for s in readPeSectionTable(image):
    if s.name in UnifiedSectionOrder: fileOrder.add s.name
  check(measuredOrder == @[".linux", ".osrel", ".cmdline", ".initrd",
                           ".uname", ".sbat"],
        "the sections are measured in the stub's order (got " &
        measuredOrder.join(", ") & ")")
  check(measuredOrder != fileOrder,
        "the measured order really differs from the file order (" &
        fileOrder.join(", ") & "), so agreeing with it is not an accident")

  # `.sbat` belongs to the stub, not to anything this repository appends.
  # A calculator that only knows about appended sections is wrong by one
  # event pair, and nothing else here would notice.
  check(".sbat" in measuredOrder and ".sbat" notin MeasuredUkiSections,
        "the stub's own .sbat section is measured even though this " &
        "repository does not append it")

  # The five sections this repository DOES append are all measured, and
  # in the order `repro/uki.nim` declares.
  var appended: seq[string] = @[]
  for s in measuredOrder:
    if s in MeasuredUkiSections: appended.add s
  var declared: seq[string] = @[]
  for s in MeasuredUkiSections: declared.add s
  check(appended == declared,
        "every section the image recipe appends is measured, in the " &
        "declared order (" & declared.join(", ") & ")")

  # The measured length is VirtualSize. `.cmdline` sits in a 512-byte raw
  # slot; digesting the padding would put bytes in the identity that are
  # not in the image.
  for e in measured.events:
    if e.section == ".cmdline":
      check(e.size == katCmdline.len and
            e.dataDigest == sha256Hex(katCmdline),
            "the command line is measured at its own length, not at the " &
            "file-aligned raw size")

  # The template is a contract, not a comment: it replays to the value
  # beside it, so a verifier never has to take the number on trust.
  let tmpl = renderEventLogTemplate(measured)
  check(replayEventLogTemplate(tmpl) == measured.pcr11,
        "the event-log template replays to the precomputed register")

block tManifestRejectsUnknownLaunchShapeSchema:
  let image = synthUki(katCmdline)
  let good = renderAttestedImageManifest(manifestFor(image))

  proc refuses(what: string; body: proc()) =
    var raised = false
    try: body()
    except CatchableError: raised = true
    check(raised, "t_manifest_rejects_unknown_launch_shape: " & what)

  refuses("an unknown backend is refused when the manifest is BUILT"):
    discard attestedImageManifest(GateFingerprint, image,
      DigestPrefix & sha256Hex("v"), katRootHash, ["sev-es"])
  # The recipe's own request validation refuses it too, so a recipe edit
  # naming a backend nobody computes stops the PLAN rather than producing
  # an image whose manifest quietly lacks the expectation its author
  # thought they had asked for.
  let badRequest = AttestExpectRequest(
    ukiPath: "build/uki/x.efi", verityImagePath: "build/verity/x.img",
    verityRootHashPath: "build/verity/x.roothash",
    configFingerprint: GateFingerprint, backends: @["sev-es"],
    outputDir: "build/attest")
  let badReason = validateAttestExpectRequest(badRequest)
  check(badReason.len > 0 and "sev-es" in badReason,
        "t_manifest_rejects_unknown_launch_shape: the image recipe's own " &
        "request validation refuses an unknown backend and names it, so a " &
        "recipe edit stops the plan rather than the emitter")
  refuses("an unknown backend key in a document is refused"):
    var doc1 = parseJson(good)
    doc1["expected"]["sev-es"] = newJArray()
    discard parseAttestedImageManifest($doc1, "<mutated>")
  refuses("an unknown field inside a launch shape is refused"):
    var doc2 = parseJson(good)
    doc2["expected"][BackendTpm][0]["pcr12"] = newJString(repeat("0", 64))
    discard parseAttestedImageManifest($doc2, "<mutated>")
  refuses("an unknown top-level field is refused"):
    var doc3 = parseJson(good)
    doc3["builtAt"] = newJString("2026-01-01T00:00:00Z")
    discard parseAttestedImageManifest($doc3, "<mutated>")
  refuses("a missing required field is refused"):
    var doc4 = parseJson(good)
    doc4["imageOutputs"].delete("verityRootHash")
    discard parseAttestedImageManifest($doc4, "<mutated>")
  refuses("a schema version this build does not implement is refused"):
    var doc5 = parseJson(good)
    doc5["schema"] = newJString("reproos.attested-image.v2")
    discard parseAttestedImageManifest($doc5, "<mutated>")
  refuses("a document that disagrees with itself is refused"):
    var doc6 = parseJson(good)
    doc6["expected"][BackendTpm][0]["pcr11"] = newJString(repeat("a", 64))
    discard parseAttestedImageManifest($doc6, "<mutated>")
  refuses("an image no single register describes -- one carrying a " &
          ".profile section -- is refused rather than measured for " &
          "profile 0 alone"):
    discard measureUkiPcr11(assembleUki(syntheticStub(), @[
      UkiSection(name: ".linux", content: "K"),
      UkiSection(name: ".profile", content: "ID=alt\n")], PinnedEpoch))

  # And the good document still parses, so the refusals are
  # discriminating rather than universal.
  check(parseAttestedImageManifest(good, "<good>").tpm.len == 1,
        "t_manifest_rejects_unknown_launch_shape: the unmutated document " &
        "is accepted, so the refusals above are about what changed")

block layerRecipeDeclarationsAgree:
  # The document's name, the artifacts it is a function of, and the argv
  # that produces it are all derived from one request. A gate that only
  # compared the emitter to itself would not notice the recipe asking for
  # a file the emitter never writes.
  let request = AttestExpectRequest(
    ukiPath: "build/uki/" & UkiFileName,
    verityImagePath: "build/verity/" & VerityDataImageFileName,
    verityRootHashPath: "build/verity/" & VerityRootHashFileName,
    configFingerprint: GateFingerprint,
    backends: @(AttestBackends),
    outputDir: "build/attest")
  check(validateAttestExpectRequest(request).len == 0,
        "the request the image recipe builds is valid")
  let outputs = attestOutputPaths(request)
  check(outputs.len == 1 and
        outputs[0] == "build/attest/" & AttestManifestFileName,
        "the edge declares exactly the one document it writes")
  let argv = attestExpectArgv("/somewhere/repro", request)
  check(argv[0 .. 2] == @["/somewhere/repro", "attest", "expect"],
        "the argv invokes the shipped verification command rather than a " &
        "second emitter")
  check("--out" in argv and argv[argv.find("--out") + 1] == outputs[0],
        "the argv writes exactly the file the edge declares as its output")
  var namedBackends: seq[string] = @[]
  for i in 0 ..< argv.len:
    if argv[i] == "--backend": namedBackends.add argv[i + 1]
  check(namedBackends == @(AttestBackends),
        "the argv asks for exactly the backends the recipe declares (" &
        namedBackends.join(", ") & ")")
  for input in attestInputPaths(request):
    check(input in argv,
          "every declared input is named on the command line (" & input & ")")
  check(MeasuredVerityImageName == VerityDataImageFileName and
        MeasuredVerityRootHashName == VerityRootHashFileName,
        "the artifacts the manifest reads are the ones the verity build " &
        "writes")

macro imageSdkCommand(root, seed: untyped; selector: static[string]): untyped =
  # Compile the recipe's actual construction and the expression passed to
  # shell(command = ...), without evaluating the unrelated image build graph.
  let recipe = parseStmt(staticRead(RepoRoot / "recipes/reproos-image/package.nim"))
  let body = newStmtList()
  body.add newLetStmt(ident"projectRoot", root)
  body.add newLetStmt(ident"identitySeed", seed)
  var buildBody: NimNode
  for node in recipe:
    if node.kind == nnkConstSection:
      let constants = node.copyNimTree()
      for definition in constants:
        if definition.kind == nnkConstDef and definition[0].kind == nnkPostfix:
          definition[0] = definition[0][1]
      body.add constants
    elif node.kind in {nnkCall, nnkCommand} and node[0].eqIdent("package") and
        node[1].eqIdent("reproosImage"):
      for section in node[^1]:
        if section.kind in {nnkCall, nnkCommand} and section[0].eqIdent("build"):
          buildBody = section[^1]
  if buildBody.isNil:
    error("image recipe has no build body")
  if selector != "attest":
    proc findBinding(node: NimNode; name: string): NimNode =
      if node.kind in {nnkLetSection, nnkVarSection} and $node[0][0] == name:
        return node[0][2]
      for child in node:
        let found = findBinding(child, name)
        if not found.isNil: return found
    proc leftLiteral(node: NimNode): string =
      if node.kind in {nnkStrLit, nnkTripleStrLit}: return node.strVal
      if node.kind == nnkInfix and node[0].eqIdent("&"):
        return leftLiteral(node[1])
    proc findAssignment(node: NimNode): NimNode =
      if leftLiteral(node).startsWith("REPRO_BIN="): return node
      for child in node:
        let found = findAssignment(child)
        if not found.isNil: return found
    for name in ["reprobuildRoot", "reproCliInput"]:
      let value = findBinding(buildBody, name)
      if value.isNil: error("image recipe lost binding: " & name)
      body.add newLetStmt(ident(name), value.copyNimTree())
    let action = findBinding(buildBody, selector)
    if action.isNil or not action[0].eqIdent("shell"):
      error("image recipe lost shell action: " & selector)
    var construction: NimNode
    for argument in action:
      if argument.kind == nnkExprEqExpr and argument[0].eqIdent("command"):
        construction = findBinding(buildBody, $argument[1])
    if construction.isNil: error("image action lost its command: " & selector)
    let assignment = findAssignment(construction)
    if assignment.isNil: error("image command lost REPRO_BIN: " & selector)
    body.add newTree(nnkInfix, ident"&", assignment.copyNimTree(),
      newLit("; \"$REPRO_BIN\""))
    return newBlockStmt(body)
  var emitting = false
  var command: NimNode
  for statement in buildBody:
    let name = if statement.kind in {nnkLetSection, nnkVarSection}:
                 $statement[0][0]
               else: ""
    if name in ["reprobuildRoot", "reproCliInput"]:
      body.add statement.copyNimTree()
    if name == "attestRequest":
      emitting = true
    if name == "buildAttestAction":
      let call = statement[0][2]
      if not call[0].eqIdent("shell"):
        error("measurement action no longer uses the shell constructor", call)
      for argument in call:
        if argument.kind == nnkExprEqExpr and argument[0].eqIdent("command"):
          command = argument[1].copyNimTree()
      break
    if emitting:
      body.add statement.copyNimTree()
  if command.isNil:
    error("measurement action has no command argument")
  body.add newTree(nnkTupleConstr, command, ident"attestRequest")
  result = newBlockStmt(body)

block layerRecipeSdkPaths:
  let work = createTempDir("reproos-attest-paths-", "")
  let savedSdk = getEnv("REPROBUILD_SRC")
  let hadSdk = existsEnv("REPROBUILD_SRC")
  let savedCapture = getEnv("REPROOS_ATTEST_ARGV_CAPTURE")
  let hadCapture = existsEnv("REPROOS_ATTEST_ARGV_CAPTURE")
  let savedCwd = getCurrentDir()
  try:
    let bash = findExe("bash")
    if bash.len == 0:
      raise newException(IOError, "measurement argv fixture requires declared bash")
    let root = work / "project with spaces"
    let actionDir = root / "recipes/reproos-image"
    createDir(actionDir)
    createDir(work / "unrelated caller")
    setCurrentDir(work / "unrelated caller")
    let capture = work / "argv"
    putEnv("REPROOS_ATTEST_ARGV_CAPTURE", capture)
    for sdkMode in ["unset", "empty", "relative", "absolute"]:
      let sdkNames = if sdkMode in ["unset", "empty"]: @["reprobuild"]
                     else: @["sdk", "sdk with spaces and 'quotes'",
                             "sdk with \"quotes\" and $cash"]
      for sdkName in sdkNames:
        let sdkRoot = work / sdkName
        let cli = sdkRoot / "build/bin/repro"
        createDir(cli.parentDir)
        writeFile(cli, "#!" & bash & "\n" &
          "printf '%s\\0' \"$0\" \"$@\" > \"$REPROOS_ATTEST_ARGV_CAPTURE\"\n")
        setFilePermissions(cli, {fpUserRead, fpUserWrite, fpUserExec})
        case sdkMode
        of "unset": delEnv("REPROBUILD_SRC")
        of "empty": putEnv("REPROBUILD_SRC", "")
        of "relative": putEnv("REPROBUILD_SRC", "../" & sdkName)
        else: putEnv("REPROBUILD_SRC", sdkRoot)
        let (command, request) = imageSdkCommand(root, GateFingerprint, "attest")
        if fileExists(capture): removeFile(capture)
        let process = startProcess(bash, workingDir = actionDir,
          args = @["-c", command], options = {poStdErrToStdOut})
        let output = process.outputStream.readAll()
        let code = process.waitForExit()
        process.close()
        let label = "measurement action SDK " & sdkMode & "=" & getEnv("REPROBUILD_SRC")
        check(code == 0, label & " launches its CLI from the action cwd: " & output)
        check(fileExists(capture), label & " reaches the argv capture executable")
        if code == 0 and fileExists(capture):
          var received = readFile(capture).split('\0')
          received.setLen(received.len - 1)
          check(received == attestExpectArgv(cli, request),
                label & " preserves the executable and every argument exactly")
        for (construction, imageCommand) in [
            ("stageInstalledRootAction", imageSdkCommand(root, GateFingerprint,
              "stageInstalledRootAction")),
            ("buildImageAction", imageSdkCommand(root, GateFingerprint,
              "buildImageAction"))]:
          if fileExists(capture): removeFile(capture)
          let imageProcess = startProcess(bash, workingDir = actionDir,
            args = @["-c", imageCommand], options = {poStdErrToStdOut})
          let imageOutput = imageProcess.outputStream.readAll()
          let imageCode = imageProcess.waitForExit()
          imageProcess.close()
          let imageLabel = construction & " SDK " & sdkMode & "=" & getEnv("REPROBUILD_SRC")
          check(imageCode == 0, imageLabel & " launches its declared CLI: " & imageOutput)
          check(fileExists(capture), imageLabel & " reaches the declared CLI fixture")
          if imageCode == 0 and fileExists(capture):
            check(readFile(capture) == cli & '\0',
                  imageLabel & " selects the exact executable without a PATH fallback")
  finally:
    setCurrentDir(savedCwd)
    if hadSdk: putEnv("REPROBUILD_SRC", savedSdk) else: delEnv("REPROBUILD_SRC")
    if hadCapture: putEnv("REPROOS_ATTEST_ARGV_CAPTURE", savedCapture)
    else: delEnv("REPROOS_ATTEST_ARGV_CAPTURE")
    removeDir(work)

# =====================================================================
# Layer 2 — the real stub and the shipped emitter.
# =====================================================================

proc requireTool(gate, tool: string): string =
  # `followSymlinks = false`, deliberately. Several of these tools ship as
  # symlinks into one multi-call binary -- `mmd` and `mcopy` are both
  # links to `mtools` -- and resolving the link hands back a program that
  # does not know which applet it was asked for.
  let path = findExe(tool, followSymlinks = false)
  if path.len == 0:
    fail(gate & ": " & tool & " not found on PATH. This layer is running, " &
         "so its absence is a failure, not a skip.")
  path

proc reproCliPath(): string =
  let explicit = getEnv("REPRO_BIN")
  if explicit.len > 0: return explicit
  let root = block:
    let configured = getEnv("REPROBUILD_SRC")
    if configured.len > 0: configured else: RepoRoot.parentDir / "reprobuild"
  root / "build" / "bin" / "repro"

proc realVerityImage(dir: string): (string, string) =
  ## A real dm-verity image and its root hash, through the product's own
  ## construction. Returns (image path, root hash).
  let spec = verityRootSpec(GateSeed)
  let dataPath = dir / VerityDataImageFileName
  let hashPath = dir / VerityHashTreeFileName
  var data = newStringOfCap(64 * VerityDataBlockSize)
  for i in 0 ..< 64:
    let d = sha256Hex("reproos-pcr-kat:" & $i)
    for _ in 0 ..< (VerityDataBlockSize div 64):
      data.add d
  writeFile(dataPath, data)
  let image = formatVerity(spec, dataPath, hashPath)
  (dataPath, image.rootHash)

proc runCli(bin: string; args: seq[string]): tuple[code: int, output: string] =
  let p = startProcess(bin, args = args, options = {poStdErrToStdOut})
  let output = p.outputStream.readAll()
  let code = p.waitForExit()
  p.close()
  (code, output)

var
  realStubPath = ""
  layer2Ran = false

block layerShippedEmitter:
  let stub = resolveUkiStub()
  let repro = reproCliPath()
  if stub.len == 0:
    skip("the shipped-emitter layer did not run: no pinned EFI stub, so " &
         "NO real unified kernel image was assembled and NOTHING here is " &
         "evidence about the shipped emitter.\n" & describeUkiStubSearch())
  elif not fileExists(repro):
    skip("the shipped-emitter layer did not run: no `repro` binary at " &
         repro & ", so the manifest was NOT produced by the shipped " &
         "command and nothing here is evidence about it. Build the " &
         "sibling toolchain, or set REPRO_BIN.")
  else:
    realStubPath = stub
    layer2Ran = true
    let gate = "shipped emitter layer"
    let work = getTempDir() / "reproos-pcr-emit-" & $getCurrentProcessId()
    removeDir(work)
    createDir(work)

    # The stub's own unified-section table, read out of the stub. This is
    # what stops the calculator's order from being a recollection: if a
    # future stub reorders or renames its table, this reddens.
    let stubBytes = readFile(stub)
    var run = ""
    for name in UnifiedSectionOrder: run.add name & "\0"
    check(run in stubBytes,
          "the measured section order is the pinned stub's own table, " &
          "found as a NUL-separated run in its read-only data")

    let kernel = "SYNTHETIC-KERNEL-PAYLOAD-FOR-THE-EMITTER-LAYER"
    let initrd = repeat("I", 4096)
    let spec = UkiSpec(stubPath: stub, cmdline: katCmdline,
                       osRelease: defaultOsRelease("0.1.0"),
                       uname: "6.12.0-reproos", sourceDateEpoch: PinnedEpoch)
    let image = assembleUki(readFile(stub),
      ukiSections(spec, kernel, initrd), PinnedEpoch)
    let ukiPath = work / UkiFileName
    writeFile(ukiPath, image)

    let (verityPath, rootHash) = realVerityImage(work)
    let rootHashPath = work / VerityRootHashFileName
    writeFile(rootHashPath, rootHash & "\n")

    proc emit(outPath: string; extra: seq[string] = @[]): tuple[code: int,
        output: string] =
      var args = @["attest", "expect",
                   "--uki", ukiPath,
                   "--verity-image", verityPath,
                   "--verity-root-hash-file", rootHashPath,
                   "--config-fingerprint", GateFingerprint]
      for b in AttestBackends:
        args.add "--backend"
        args.add b
      args.add extra
      if outPath.len > 0:
        args.add "--out"
        args.add outPath
      runCli(repro, args)

    let firstPath = work / "first.json"
    let secondPath = work / "second.json"
    let first = emit(firstPath)
    let second = emit(secondPath)
    if first.code != 0 or second.code != 0:
      fail(gate & ": `repro attest expect` exited " & $first.code & "/" &
           $second.code & ":\n" & first.output & second.output)
    else:
      let a = readFile(firstPath)
      let b = readFile(secondPath)
      check(a == b,
            "t_manifest_deterministic: two runs of the SHIPPED `repro " &
            "attest expect` over the same image are byte-identical")
      # Two paths, one document: what this gate computes in-process and
      # what the shipped command writes must be the same bytes.
      check(a == renderAttestedImageManifest(
              attestedImageManifest(GateFingerprint, image,
                DigestPrefix & sha256Hex(readFile(verityPath)), rootHash,
                @(AttestBackends))),
            "the shipped command's document is byte-identical to the one " &
            "this gate derives from the same inputs")
      # Parsed inside a guard: a document this build cannot read back is
      # exactly what several cases below exist to detect, so it has to be
      # a named red line rather than an exception that takes every check
      # after it down with it.
      var parsed: AttestedImageManifest
      var parseFailure = ""
      try:
        parsed = parseAttestedImageManifest(a, firstPath)
      except CatchableError as err:
        parseFailure = err.msg
      check(parseFailure.len == 0,
            "the document the shipped command wrote is accepted by this " &
            "build's own parser" &
            (if parseFailure.len > 0: " -- " & parseFailure else: ""))
      if parseFailure.len == 0:
        check(parsed.tpm.len == 1 and
              parsed.tpm[0].pcr11 == measureUkiPcr11(image).pcr11,
              "the shipped command's expected register is the one the " &
              "calculator derives from the image's bytes")
        check(parsed.imageOutputs.verityRootHash == rootHash,
              "the document pins the dm-verity root hash the verity build " &
              "produced")

      # --check is what a rebuilding verifier runs. It must accept the
      # document the same inputs produce and refuse a changed one.
      let recheck = emit("", @["--check", firstPath])
      check(recheck.code == 0,
            "t_manifest_deterministic: --check accepts the document the " &
            "same image produces")
      var mutated = a
      let pcrAt =
        if parseFailure.len > 0: -1
        else: mutated.find(parsed.tpm[0].pcr11)
      if pcrAt < 0:
        fail(gate & ": the document does not contain its own register")
      else:
        mutated[pcrAt] = (if mutated[pcrAt] == '0': '1' else: '0')
        let mutatedPath = work / "mutated.json"
        writeFile(mutatedPath, mutated)
        let refused = emit("", @["--check", mutatedPath])
        check(refused.code == 1 and "line " in refused.output,
              "t_manifest_deterministic: --check refuses a document whose " &
              "register was changed by one character, and names the line")

      # The documented directory convention: given the image build's
      # output directory and nothing else, the command must find the same
      # three artifacts by name and produce the same document. Nothing
      # else exercises it, and a convention no test drives is a
      # convention that drifts.
      let byDirPath = work / "by-dir.json"
      var byDirArgs = @["attest", "expect", "--image", work,
                        "--config-fingerprint", GateFingerprint]
      for b in AttestBackends:
        byDirArgs.add "--backend"
        byDirArgs.add b
      byDirArgs.add "--out"
      byDirArgs.add byDirPath
      let byDir = runCli(repro, byDirArgs)
      if byDir.code != 0:
        fail(gate & ": `repro attest expect --image <dir>` exited " &
             $byDir.code & ":\n" & byDir.output)
      else:
        check(readFile(byDirPath) == a,
              "the documented --image <dir> convention finds the same " &
              "artifacts by name and produces the same document as the " &
              "explicit flags")

      # The build refuses an unknown launch shape, and writes nothing.
      let unknownPath = work / "unknown.json"
      let unknown = emit(unknownPath, @["--backend", "sev-es"])
      check(unknown.code != 0 and not fileExists(unknownPath),
            "t_manifest_rejects_unknown_launch_shape: the SHIPPED command " &
            "refuses an unknown backend and writes no document")
      check("sev-es" in unknown.output,
            "t_manifest_rejects_unknown_launch_shape: the refusal names the " &
            "backend it did not understand")

      # An attested image's identity covers its root filesystem, so a
      # manifest without the verity outputs is refused rather than
      # emitted in a weaker form.
      let partialPath = work / "partial.json"
      let partial = runCli(repro, @["attest", "expect", "--uki", ukiPath,
        "--config-fingerprint", GateFingerprint, "--out", partialPath])
      check(partial.code != 0 and not fileExists(partialPath),
            "t_manifest_rejects_unknown_launch_shape: a manifest with no " &
            "root-image identity is refused rather than emitted")

    if getEnv(KeepEnv) != "1": removeDir(work)
    else: echo "[info] kept (" & KeepEnv & "=1): ", work

# =====================================================================
# Layer 3 — a real measured boot. Opt-in.
# =====================================================================

type
  BootArtifacts = object
    stub: string
    kernel: string
    moduleDir: string
    modulesBuiltIn: bool
    ovmfCode: string
    ovmfVars: string

proc discoverModules(kernel: string): (string, bool, string) =
  ## Returns (module directory, "the TPM drivers are built in", reason).
  let configured = getEnv(GuestModuleDirEnv)
  var dir = configured
  if dir.len == 0 and kernel == "/run/booted-system/kernel":
    for kind, path in walkDir("/run/booted-system/kernel-modules/lib/modules"):
      if kind == pcDir:
        dir = path
        break
  if dir.len == 0:
    # A kernel whose module tree we cannot find is only usable if it
    # carries the drivers itself; the guest will say which.
    return ("", false, "no module tree beside " & kernel & "; set " &
      GuestModuleDirEnv & " if its TPM drivers are modular")
  let builtin = dir / "modules.builtin"
  if fileExists(builtin) and "/tpm_tis." in readFile(builtin):
    return (dir, true, "")
  (dir, false, "")

proc discoverBootArtifacts(): (BootArtifacts, string) =
  var a: BootArtifacts
  a.stub = resolveUkiStub()
  if a.stub.len == 0:
    return (a, "no pinned EFI stub.\n" & describeUkiStubSearch())

  a.kernel = getEnv(GuestKernelEnv)
  if a.kernel.len == 0:
    let packagesRoot = block:
      let configured = getEnv("REPROBUILD_PACKAGES_ROOT")
      if configured.len > 0: configured
      else: RepoRoot.parentDir / "reprobuild-packages"
    let srcKernel = packagesRoot /
      "packages/source/kernel/.repro/output/install/usr/lib/reproos-kernel/vmlinuz"
    if fileExists(srcKernel): a.kernel = srcKernel
    elif fileExists("/run/booted-system/kernel"):
      a.kernel = "/run/booted-system/kernel"
  if a.kernel.len == 0 or not fileExists(a.kernel):
    return (a, "no kernel: set " & GuestKernelEnv & ", or build the source " &
      "kernel, or run on a host that publishes /run/booted-system/kernel")

  let (dir, builtin, why) = discoverModules(a.kernel)
  a.moduleDir = dir
  a.modulesBuiltIn = builtin
  if dir.len == 0 and why.len > 0:
    return (a, why)

  # A unified kernel image is loaded by UEFI firmware and by nothing
  # else, so this layer cannot fall back to a direct kernel boot -- and
  # the firmware must carry the TCG2 protocol, or nothing measures.
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
      "VMH_OVMF_VARS, or install a build of OVMF that carries the TCG2 " &
      "protocol")
  (a, "")

proc newcArchive(entries: seq[(string, uint32, string)]): string =
  ## A cpio archive, written here rather than shelled out to, because
  ## `cpio` is not a tool this gate declares and the format is ten lines.
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

proc pcrFromResponse(hexResponse: string): (string, string) =
  ## Decode a TPM2_PCR_Read response. Returns (digest, "") or
  ## ("", reason). The header is checked rather than the tail being
  ## sliced off blindly: a response that is an error code would otherwise
  ## be read as a register value.
  if hexResponse.len < 124:
    return ("", "the response is " & $(hexResponse.len div 2) &
      " bytes, too short to be a PCR_Read reply")
  if hexResponse[0 .. 3] != "8001":
    return ("", "the response tag is 0x" & hexResponse[0 .. 3] &
      ", not TPM_ST_NO_SESSIONS")
  let rc = hexResponse[12 .. 19]
  if rc != "00000000":
    return ("", "the TPM answered with response code 0x" & rc)
  # Byte layout, and therefore twice that in hex characters:
  #   tag(2) size(4) rc(4) pcrUpdateCounter(4)
  #   pcrSelectionOut: count(4) hashAlg(2) sizeofSelect(1) select(3)
  #   pcrValues:       count(4) size(2) digest(32)
  let valueCount = hexResponse[48 .. 55]
  if valueCount != "00000001":
    return ("", "the TPM returned 0x" & valueCount & " digests, not one")
  let digestSize = hexResponse[56 .. 59]
  if digestSize != "0020":
    return ("", "the digest is 0x" & digestSize & " bytes, not 32")
  if hexResponse.len < 60 + 64:
    return ("", "the response is truncated before the digest")
  (hexResponse[60 ..< 124], "")

block layerMeasuredBoot:
  let bootLayer = optInLayer(BootGateEnv)
  if bootLayer.isBlocked:
    fail(blockedNote(BootGateEnv,
      "bash tests/test-measurement-manifest.sh, with " & BootGateEnv & "=1"))
  elif bootLayer == lrNotRequested:
    skip("the measured-boot layer did not run: NO firmware measured " &
         "anything, NO TPM was attached, NO PCR was read, and nothing " &
         "here is evidence that the precomputation matches hardware. " &
         notRequestedNote(BootGateEnv) & " It takes ~2 min and needs " &
         "qemu-system-x86_64, " &
         "swtpm, mkfs.vfat, mtools, xz, a C compiler, an OVMF pair " &
         "carrying the TCG2 protocol, a kernel and the pinned EFI stub.")
  else:
    let gate = "measured-boot layer"
    let (artifacts, why) = discoverBootArtifacts()
    if why.len > 0:
      fail(gate & ": " & why & ". This layer was asked for, so a missing " &
           "artifact is a failure, not a skip.")
    else:
      let qemu = requireTool(gate, "qemu-system-x86_64")
      let swtpm = requireTool(gate, "swtpm")
      let mkfsVfat = requireTool(gate, "mkfs.vfat")
      let mmd = requireTool(gate, "mmd")
      let mcopy = requireTool(gate, "mcopy")
      let cc = block:
        var found = ""
        for candidate in ["clang", "cc", "gcc"]:
          let p = findExe(candidate, followSymlinks = false)
          if p.len > 0:
            found = p
            break
        if found.len == 0:
          fail(gate & ": no C compiler on PATH; the guest's /init is " &
               "compiled from source by this gate")
        found
      var xz = ""
      if not artifacts.modulesBuiltIn:
        xz = findExe("xz", followSymlinks = false)
      if qemu.len > 0 and swtpm.len > 0 and mkfsVfat.len > 0 and
         mmd.len > 0 and mcopy.len > 0 and cc.len > 0:
        let work = getTempDir() / "reproos-pcr-boot-" & $getCurrentProcessId()
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
          var entries = @[
            ("proc", 0o040755'u32 or 0o040000'u32, ""),
            ("sys", 0o040755'u32 or 0o040000'u32, ""),
            ("dev", 0o040755'u32 or 0o040000'u32, ""),
            ("lib", 0o040755'u32 or 0o040000'u32, "")]
          var moduleProblem = ""
          if not artifacts.modulesBuiltIn:
            if artifacts.moduleDir.len == 0:
              moduleProblem = "the kernel's TPM drivers are modular and no " &
                "module tree was found"
            # The kernel's own index says where each module is. Walking
            # the tree would not: on this host `kernel/` is a symlink into
            # the store, and a directory walk does not follow it.
            var moduleIndex = initTable[string, string]()
            let depPath = artifacts.moduleDir / "modules.dep"
            if not fileExists(depPath):
              moduleProblem = "no modules.dep in " & artifacts.moduleDir
            else:
              for line in lines(depPath):
                let colon = line.find(':')
                if colon <= 0: continue
                let rel = line[0 ..< colon]
                var base = rel.extractFilename
                if base.endsWith(".xz"): base = base[0 ..< base.len - 3]
                if base.endsWith(".ko"): base = base[0 ..< base.len - 3]
                moduleIndex[base] = artifacts.moduleDir / rel
            for name in TpmModuleNames:
              if moduleProblem.len > 0: break
              let found = moduleIndex.getOrDefault(name, "")
              if found.len == 0 or not fileExists(found):
                moduleProblem = "no " & name & ".ko listed in " & depPath
              elif found.endsWith(".xz"):
                if xz.len == 0:
                  moduleProblem = "the modules are xz-compressed and this " &
                    "kernel cannot decompress them itself, but xz is not on " &
                    "PATH"
                else:
                  let plain = work / (name & ".ko")
                  let r = execCmdEx(quoteShell(xz) & " -dc " &
                    quoteShell(found) & " > " & quoteShell(plain))
                  if r.exitCode != 0:
                    moduleProblem = "could not decompress " & found
                  else:
                    entries.add(("lib/" & name & ".ko", 0o100644'u32,
                                 readFile(plain)))
              else:
                entries.add(("lib/" & name & ".ko", 0o100644'u32,
                             readFile(found)))
          if moduleProblem.len > 0:
            fail(gate & ": " & moduleProblem & ". This layer was asked for, " &
                 "so a missing artifact is a failure, not a skip.")
          else:
            entries.add(("init", 0o100755'u32, readFile(initBin)))
            let initrdPath = work / "initrd.img"
            writeFile(initrdPath, newcArchive(entries))

            # --- the artifacts a manifest is a function of -----------
            let (verityPath, rootHash) = realVerityImage(work)
            let rootHashPath = work / VerityRootHashFileName
            writeFile(rootHashPath, rootHash & "\n")

            proc buildImage(cmdline: string; path: string): string =
              let spec = UkiSpec(
                stubPath: artifacts.stub, kernelPath: artifacts.kernel,
                initrdPath: initrdPath, cmdline: cmdline,
                osRelease: defaultOsRelease("0.1.0"), uname: "",
                sourceDateEpoch: PinnedEpoch)
              let image = assembleUkiFromFiles(spec)
              writeFile(path, image)
              image

            proc buildEsp(uki, path: string): bool =
              removeFile(path)
              var f = open(path, fmWrite)
              f.setFilePos(96 * 1024 * 1024 - 1)
              f.write('\0')
              f.close()
              var mkdirs = ""
              var walked = ""
              for part in UkiEspFallbackPath.split('/')[0 .. ^2]:
                walked = (if walked.len == 0: part else: walked & "/" & part)
                mkdirs.add " ::/" & walked
              for (what, cmd) in [
                  ("mkfs.vfat", quoteShell(mkfsVfat) & " -n ESP -F 32 " &
                    quoteShell(path)),
                  ("mmd", quoteShell(mmd) & " -i " & quoteShell(path) & mkdirs),
                  ("mcopy", quoteShell(mcopy) & " -i " & quoteShell(path) &
                    " " & quoteShell(uki) & " ::/" & UkiEspFallbackPath)]:
                let r = execCmdEx(cmd)
                if r.exitCode != 0:
                  stderr.writeLine("[esp] " & what & " exited " & $r.exitCode &
                    "\n[esp] command: " & cmd & "\n[esp] output: " & r.output)
                  return false
              true

            proc bootAndReadPcr(esp, caseName: string): (string, string) =
              ## One guest, with its own software TPM. Nothing this proc
              ## starts may outlive it. Returns (transcript, "") or
              ## ("", reason).
              let runDir = work / caseName
              createDir(runDir)
              let tpmState = runDir / "tpm"
              createDir(tpmState)
              let tpmSock = getTempDir() / ("reproos-att-pcr-" &
                $getCurrentProcessId() & "-" & caseName & ".sock")
              removeFile(tpmSock)
              var sw: Process
              try:
                sw = startProcess(swtpm, args = @["socket", "--tpm2",
                  "--tpmstate", "dir=" & tpmState,
                  "--log", "file=" & (runDir / "swtpm.log") & ",level=1",
                  "--ctrl", "type=unixio,path=" & tpmSock],
                  options = {poStdErrToStdOut})
              except OSError as e:
                return ("", "could not start swtpm: " & e.msg)
              var ready = false
              for _ in 0 ..< 100:
                if fileExists(tpmSock) or symlinkExists(tpmSock) or
                   dirExists(tpmSock) or execCmdEx("test -S " &
                     quoteShell(tpmSock)).exitCode == 0:
                  ready = true
                  break
                sleep(100)
              if not ready:
                if sw.running: sw.terminate()
                discard sw.waitForExit()
                sw.close()
                return ("", "swtpm never created its control socket at " &
                  tpmSock)
              let vars = runDir / "vars.fd"
              copyFile(artifacts.ovmfVars, vars)
              setFilePermissions(vars, {fpUserRead, fpUserWrite})
              let serial = runDir / "serial.log"
              let args = @[
                "-name", VmNamePrefix & caseName & "-" &
                  $getCurrentProcessId(),
                "-machine", "q35,accel=kvm:tcg", "-m", "2048", "-smp", "2",
                "-drive", "if=pflash,format=raw,readonly=on,file=" &
                  artifacts.ovmfCode,
                "-drive", "if=pflash,format=raw,file=" & vars,
                "-drive", "file=" & esp & ",format=raw,if=virtio",
                "-chardev", "socket,id=chrtpm,path=" & tpmSock,
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis,tpmdev=tpm0",
                "-nographic", "-no-reboot", "-display", "none",
                "-monitor", "none", "-serial", "file:" & serial]
              var p: Process
              var startError = ""
              try:
                p = startProcess(qemu, args = args,
                                 options = {poStdErrToStdOut})
              except OSError as e:
                startError = "could not start " & qemu & ": " & e.msg
              var transcript = ""
              if startError.len == 0:
                let deadline = epochTime() + 240.0
                while p.running and epochTime() < deadline:
                  sleep(200)
                if p.running:
                  p.terminate()
                  sleep(500)
                  if p.running: p.kill()
                  startError = "the " & caseName & " guest did not power " &
                    "off within 240s"
                discard p.waitForExit()
                p.close()
                if fileExists(serial): transcript = readFile(serial)
              # Unconditional teardown: swtpm is not a child of QEMU and
              # nothing else reaps it.
              if sw.running:
                sw.terminate()
                sleep(300)
                if sw.running: sw.kill()
              discard sw.waitForExit()
              sw.close()
              removeFile(tpmSock)
              if startError.len > 0:
                stderr.writeLine(transcript)
                return ("", startError)
              (transcript, "")

            proc registerFrom(transcript, caseName: string): (string, string) =
              let marker = "REPROOS-PCR-READ="
              let at = transcript.find(marker)
              if at < 0:
                return ("", "the " & caseName & " guest printed no " &
                  marker & " line")
              var raw = ""
              var i = at + marker.len
              while i < transcript.len and transcript[i] in
                    {'0' .. '9', 'a' .. 'f'}:
                raw.add transcript[i]
                inc i
              pcrFromResponse(raw)

            # --- the boot this gate stands on -----------------------
            let bootCmdline = "console=ttyS0 panic=1 " &
              attestedKernelCmdline(rootHash, GateBootDevices.data,
                GateBootDevices.hash, GateBootDevices.stateVar,
                GateBootDevices.stateHome)
            let ukiPath = work / UkiFileName
            let image = buildImage(bootCmdline, ukiPath)
            var expected: UkiMeasurement
            var calcFailure = ""
            try:
              expected = measureUkiPcr11(image)
            except CatchableError as err:
              calcFailure = err.msg
            check(calcFailure.len == 0,
                  "the image that is about to be booted can be measured" &
                  (if calcFailure.len > 0: " -- " & calcFailure else: ""))
            echo "[info] uki digest: ", ukiDigest(image)
            echo "[info] kernel: ", artifacts.kernel
            echo "[info] stub: ", artifacts.stub
            echo "[info] firmware: ", artifacts.ovmfCode
            echo "[info] precomputed PCR 11: ", expected.pcr11

            # The value under test is the SHIPPED emitter's, when the
            # shipped emitter is available -- so the boot checks the
            # document the build publishes, not just the library.
            var published = expected.pcr11
            var publishedFrom = "the calculator"
            let repro = reproCliPath()
            if fileExists(repro):
              let manifestPath = work / AttestManifestFileName
              var args = @["attest", "expect", "--uki", ukiPath,
                "--verity-image", verityPath,
                "--verity-root-hash-file", rootHashPath,
                "--config-fingerprint", GateFingerprint]
              for b in AttestBackends:
                args.add "--backend"
                args.add b
              args.add "--out"
              args.add manifestPath
              let r = runCli(repro, args)
              if r.code != 0:
                fail(gate & ": `repro attest expect` exited " & $r.code &
                     ":\n" & r.output)
              else:
                let parsed = parseAttestedImageManifest(
                  readFile(manifestPath), manifestPath)
                published = parsed.tpm[0].pcr11
                publishedFrom = "the manifest the shipped command wrote"
            echo "[info] the register under test comes from ", publishedFrom

            let esp = work / "esp.img"
            if not buildEsp(ukiPath, esp):
              fail(gate & ": could not build the ESP image")
            else:
              let (transcript, bootWhy) = bootAndReadPcr(esp, "measured")
              if bootWhy.len > 0:
                fail(gate & ": " & bootWhy)
              else:
                check("REPROOS-PCR-GUEST-START" in transcript,
                      "firmware loaded the unified kernel image from the " &
                      "ESP and the stub started the kernel it carries")
                check("REPROOS-PCR-CMDLINE=" & bootCmdline in transcript,
                      "/proc/cmdline in the running guest is EXACTLY the " &
                      ".cmdline section of the measured image")
                check("REPROOS-PCR-TPM-DEVICE=present" in transcript,
                      "the guest reached a real TPM 2.0 character device")
                let (observed, readWhy) = registerFrom(transcript, "measured")
                if readWhy.len > 0:
                  stderr.writeLine(transcript)
                  fail(gate & ": " & readWhy)
                else:
                  echo "[info] the guest read PCR 11 = ", observed
                  check(observed != ZeroPcr,
                        "t_pcr11_precomputation_matches_measured_boot: the " &
                        "register was really extended -- an unmeasured boot " &
                        "would leave it at zero, and comparing against an " &
                        "unextended register would prove nothing")
                  check(observed == published,
                        "t_pcr11_precomputation_matches_measured_boot: the " &
                        "register a REAL TPM reports after a REAL firmware " &
                        "and stub measured this image is EXACTLY what the " &
                        "build predicted (expected " & published &
                        ", the machine reported " & observed & ")")
                check("REPROOS-PCR-GUEST-DONE" in transcript,
                      "the guest ran to completion and powered itself off")

              # --- the same claim, falsified -------------------------
              # One character of the command line, and nothing else. The
              # precomputation must move, and the machine must move with
              # it -- to the NEW predicted value, not merely to something
              # different. Without this, "the numbers matched" would be
              # consistent with a calculator that returns a constant.
              var altered = bootCmdline
              let at = altered.find(rootHash)
              if at < 0:
                fail(gate & ": the booted command line does not carry the " &
                     "root hash, so the one-character mutation cannot be " &
                     "applied")
              else:
                altered[at] = (if altered[at] == '0': '1' else: '0')
                let alteredPath = work / "altered.efi"
                let alteredImage = buildImage(altered, alteredPath)
                var alteredExpected: UkiMeasurement
                try:
                  alteredExpected = measureUkiPcr11(alteredImage)
                except CatchableError as err:
                  fail(gate & ": the altered image cannot be measured: " &
                       err.msg)
                check(alteredImage.len == image.len and
                      alteredExpected.pcr11 != expected.pcr11,
                      "one changed character of the root hash moves the " &
                      "precomputed register with the image the same length")
                echo "[info] precomputed PCR 11 (altered): ",
                  alteredExpected.pcr11
                let esp2 = work / "esp-altered.img"
                if not buildEsp(alteredPath, esp2):
                  fail(gate & ": could not build the altered ESP image")
                else:
                  let (t2, why2) = bootAndReadPcr(esp2, "altered")
                  if why2.len > 0:
                    fail(gate & ": " & why2)
                  else:
                    check("REPROOS-PCR-CMDLINE=" & altered in t2 and
                          ("REPROOS-PCR-CMDLINE=" & bootCmdline) notin t2,
                          "the guest booted from the altered image reports " &
                          "the ALTERED command line")
                    let (observed2, why3) = registerFrom(t2, "altered")
                    if why3.len > 0:
                      stderr.writeLine(t2)
                      fail(gate & ": " & why3)
                    else:
                      echo "[info] the guest read PCR 11 (altered) = ",
                        observed2
                      check(observed2 == alteredExpected.pcr11,
                            "t_pcr11_precomputation_matches_measured_boot: " &
                            "one changed character moves the MACHINE's " &
                            "register to the newly predicted value " &
                            "(expected " & alteredExpected.pcr11 &
                            ", the machine reported " & observed2 & ")")
                      check(observed2 != expected.pcr11,
                            "t_pcr11_precomputation_matches_measured_boot: " &
                            "and away from the old one, so the agreement " &
                            "above is not a constant")

          if getEnv(KeepEnv) == "1":
            echo "[info] kept (" & KeepEnv & "=1): ", work
          else:
            removeDir(work)

if failures > 0:
  stderr.writeLine("test_measurement_manifest: " & $failures &
                   " check(s) failed, " & $passes & " passed, " & $skips &
                   " skipped")
  quit(1)
var manifestSummary = "measurement manifest: PASS (" & $passes & " checks"
if layerSummaryFragment().len > 0:
  manifestSummary.add ", " & layerSummaryFragment()
manifestSummary.add ")"
if not layer2Ran:
  manifestSummary.add " -- NO real stub or shipped emitter was exercised"
if getEnv(BootGateEnv) != "1":
  manifestSummary.add " -- NO PCR was read from a machine"
echo manifestSummary
