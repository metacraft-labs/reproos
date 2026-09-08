## The Unified Kernel Image an attestable ReproOS boots from.
##
## ## Why this module exists
##
## A read-only root with a dm-verity Merkle tree over it (``repro/verity.nim``)
## reduces the whole root filesystem to one short **root hash**. That value only
## means something if the boot path carries it *and* the boot path itself is
## covered by a measurement. Carrying it on a GRUB command line achieves
## neither: ``grub.cfg`` is a file on the ESP that anything with write access to
## the ESP can edit, and firmware measures the loader binary, not the string the
## loader chooses to pass to the kernel. An attacker who rewrites one line of
## ``grub.cfg`` boots the same signed GRUB, the same kernel and a *different*
## root hash, and every PCR still reads exactly as it did before.
##
## A **Unified Kernel Image** closes that. The kernel, the initrd, the kernel
## command line and an EFI stub are packed into ONE PE binary. Firmware loads
## that one binary; the stub reads the command line out of its own PE section
## rather than from a configuration file; and the stub measures each section it
## consumes into PCR 11 before using it. Changing one character of the command
## line changes the bytes of the PE, changes the section digest the stub
## extends, and therefore changes PCR 11. That is the property the whole
## measurement chain rests on, and it is the property this module exists to
## make true.
##
## ## What lives here and what does not
##
## Here: the section set and the order it is written in, the PE/COFF surgery
## that turns a stub plus a list of sections into a bootable image, the
## determinism rules (pinned stub, fixed section order, ``SOURCE_DATE_EPOCH``
## in the COFF timestamp), the composition of the command line from the verity
## values ``repro/verity.nim`` declares, and the readers a gate or a consumer
## uses to look back inside a finished image.
##
## Not here: the verity geometry and the root hash (``repro/verity.nim``), the
## partition table (``repro/disk_layouts.nim``), and the PCR arithmetic that
## turns the sections below into an expected PCR 11 value — that belongs to
## the measurement work that will consume this module, and nothing in this
## file computes or claims a PCR value.
##
## ## Signing is deliberately out of scope
##
## The image this module produces is **unsigned**. That is a decision, not an
## omission, and the distinction that makes it safe is worth stating exactly:
##
##   * For the **TPM tier**, signing is irrelevant. ``systemd-stub`` measures
##     each section it consumes into PCR 11 whether or not the PE carries an
##     Authenticode signature, so a remote verifier that reasons about PCR 11
##     gets the same guarantee either way. An unsigned UKI is fully attestable.
##   * For **Secure Boot**, signing is mandatory. Firmware with Secure Boot
##     enabled will refuse to load an unsigned image at all, so ReproOS cannot
##     ship a Secure-Boot-enrolled image until an ``sbsign`` step and a key
##     custody story exist. Both remain deferred.
##
## Nothing here should be read as "signing is unnecessary". It is unnecessary
## *for the measurement*, and required for the other thing.
##
## ## Why the stub is pinned by content
##
## The stub's bytes are inside the measurement twice over: they are most of the
## PE the firmware measures into PCR 4, and the stub is the code that decides
## what gets extended into PCR 11. A stub that drifted between builds would
## move every expected value with it while every input the operator can see
## stayed the same. So the stub is not "whatever ``systemd`` is on the build
## host": it is identified by ``PinnedUkiStubSha256`` and any other bytes are
## refused, naming both digests. See ``resolveUkiStub``.
##
## ## The PE surgery, precisely
##
## Reproduced from the PE/COFF specification and cross-checked against what
## ``objcopy --add-section`` and systemd's ``ukify`` produce:
##
##   * ``e_lfanew`` at offset 0x3C locates ``PE\0\0``; the 20-byte COFF header
##     follows, then the optional header (PE32+, magic 0x20B), then the section
##     table at ``e_lfanew + 24 + SizeOfOptionalHeader``.
##   * Each new section is appended after the last existing one:
##     ``PointerToRawData`` is the end of the file rounded up to
##     ``FileAlignment``, ``VirtualAddress`` is the highest
##     ``VirtualAddress + VirtualSize`` rounded up to ``SectionAlignment``.
##   * ``VirtualSize`` is the exact content length; ``SizeOfRawData`` is that
##     rounded up to ``FileAlignment``, with the padding zeroed. Reading a
##     section back therefore truncates to ``VirtualSize``.
##   * ``NumberOfSections`` and ``SizeOfImage`` are updated; ``SizeOfImage`` is
##     the last section's end rounded up to ``SectionAlignment``.
##   * The section table must still fit inside ``SizeOfHeaders``. The stub is
##     linked with room for it; a stub that is not is refused rather than
##     silently overwriting the first section's bytes.
##   * ``TimeDateStamp`` is set to ``SOURCE_DATE_EPOCH`` and the PE ``CheckSum``
##     is zeroed. Neither is consulted by EFI firmware, and both are otherwise
##     a source of bytes that are not a function of the inputs.
##
## ## No mocking
##
## Every proc here is a pure function of its arguments except the two that take
## a path: ``resolveUkiStub`` reads candidate files to digest them, and
## ``assembleUkiFromFiles`` reads its inputs and writes its output. Nothing
## executes anything.

import std/[os, strutils]

import nimcrypto/[hash, sha2]

import "./verity" as verity

# ---------------------------------------------------------------------
# What a UKI is made of.
# ---------------------------------------------------------------------

type
  UkiSection* = object
    ## One PE section of a UKI. ``name`` includes the leading dot and is
    ## at most 8 bytes, because that is all a COFF section header holds.
    name*: string
    content*: string

  UkiSpec* = object
    ## Everything one UKI is a function of. Every field is pinned by the
    ## caller; nothing here is defaulted from the environment, because a
    ## value the environment supplies is a value that moves between
    ## builds and takes the measurement with it.
    stubPath*: string        ## the EFI stub, content-pinned (see below)
    kernelPath*: string      ## the kernel image (``bzImage``/PE)
    initrdPath*: string      ## the initrd; "" emits no ``.initrd``
    cmdline*: string         ## the kernel command line, verbatim
    osRelease*: string       ## the ``.osrel`` payload
    uname*: string           ## the kernel release string; "" omits it
    sourceDateEpoch*: int64  ## written into the COFF ``TimeDateStamp``

  UkiSectionInfo* = object
    ## A section as read back out of a finished UKI.
    name*: string
    virtualSize*: int
    virtualAddress*: int
    fileOffset*: int
    rawSize*: int

const
  UkiLinuxSection* = ".linux"
  UkiOsRelSection* = ".osrel"
  UkiCmdlineSection* = ".cmdline"
  UkiInitrdSection* = ".initrd"
  UkiUnameSection* = ".uname"
    ## The five sections ReproOS emits. Named here so the assembler, the
    ## readers, the recipe and the gates cannot drift apart on a string.

  UkiSectionOrder*: array[5, string] = [
    UkiOsRelSection,
    UkiCmdlineSection,
    UkiUnameSection,
    UkiInitrdSection,
    UkiLinuxSection,
  ]
    ## The order the sections are WRITTEN to the file, smallest first and
    ## the kernel last. This is ``ukify``'s order and it is fixed rather
    ## than derived from a table walk, because two builds that emit the
    ## same sections in a different order produce different bytes and
    ## therefore a different launch measurement for an identical system.

  UkiMeasurementOrder*: array[5, string] = [
    UkiLinuxSection,
    UkiOsRelSection,
    UkiCmdlineSection,
    UkiInitrdSection,
    UkiUnameSection,
  ]
    ## The order ``systemd-stub`` EXTENDS the sections into PCR 11, which
    ## is its own fixed list and is deliberately NOT the file order above.
    ## Recorded here because the measurement work precomputes PCR 11 and the
    ## two orders being different is exactly the kind of detail that
    ## produces a calculator which agrees only with itself.

  UkiFileName* = "reproos.efi"
  UkiManifestFileName* = "reproos.efi.json"
  UkiDigestFileName* = "reproos.efi.sha256"
  UkiCmdlineFileName* = "reproos.efi.cmdline"
    ## The artifact names the image recipe emits, declared once so a
    ## consumer looks a path up instead of guessing at one.

  UkiEspFallbackPath* = "EFI/BOOT/BOOTX64.EFI"
    ## Where the UKI is installed on the ESP. The removable-media
    ## fallback path is used deliberately: it needs no NVRAM boot entry,
    ## which is what lets one built image boot on any UEFI machine and in
    ## a fresh VM with an empty variable store.

  PinnedUkiStubName* = "linuxx64.efi.stub"
  PinnedUkiStubProvider* = "systemd 258.2"
  PinnedUkiStubSha256* =
    "84f5c00168c1e0dfb1f3378bbf0a01d88ea71dcbeb18dc8af2b7718e58b24d80"
    ## The EFI stub, pinned by CONTENT. ``systemd``'s
    ## ``linuxx64.efi.stub`` is the conventional stub and the only one
    ## that implements the section measurement this image is attested by,
    ## so it is what ReproOS uses; there is no from-source stub in this
    ## project's package corpus (the source ``systemd`` recipe does not
    ## build the bootloader), which is precisely why the pin has to be a
    ## digest rather than a package name. Any other bytes are refused.

  UkiStubEnvVar* = "REPROOS_UKI_STUB"
    ## An explicit stub path. Still checked against the digest above — it
    ## selects WHICH copy is used, never WHAT is used.

  UkiStubSearchGlobs*: array[2, string] = [
    "/nix/store/*-systemd-*/lib/systemd/boot/efi/" & PinnedUkiStubName,
    "/usr/lib/systemd/boot/efi/" & PinnedUkiStubName,
  ]
    ## Where a copy of the pinned stub is looked for. A glob over a
    ## content-addressed store is safe here in a way it usually is not,
    ## because the digest decides: a candidate that is not the pinned
    ## bytes is skipped, so a host with fifty systemd versions installed
    ## still resolves to exactly one answer or to none.

# ---------------------------------------------------------------------
# Little-endian accessors. Spelled out rather than cast, because a PE is
# little-endian on every architecture and a cast would inherit the host's
# byte order.
# ---------------------------------------------------------------------

proc peU16(b: string; at: int): int =
  int(uint8(b[at])) or (int(uint8(b[at + 1])) shl 8)

proc peU32(b: string; at: int): int =
  int(uint8(b[at])) or (int(uint8(b[at + 1])) shl 8) or
    (int(uint8(b[at + 2])) shl 16) or (int(uint8(b[at + 3])) shl 24)

proc pePutU16(b: var string; at, value: int) =
  b[at] = char(value and 0xFF)
  b[at + 1] = char((value shr 8) and 0xFF)

proc pePutU32(b: var string; at: int; value: int64) =
  for i in 0 ..< 4:
    b[at + i] = char((value shr (8 * i)) and 0xFF)

proc alignUp(value, alignment: int): int =
  if alignment <= 1: value
  else: ((value + alignment - 1) div alignment) * alignment

# ---------------------------------------------------------------------
# The PE header, as far as this module needs it.
# ---------------------------------------------------------------------

type
  PeLayout* = object
    peOffset*: int
    optionalHeaderSize*: int
    sectionTableOffset*: int
    sectionCount*: int
    sectionAlignment*: int
    fileAlignment*: int
    sizeOfHeaders*: int
    sizeOfImage*: int

const
  PeSectionHeaderSize = 40
  PeCoffHeaderSize = 20
  PeSignatureSize = 4
  PeMagicPe32Plus = 0x20B

  # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ. Read-only data
  # is what every UKI payload section is: the stub reads them and the
  # firmware never executes them.
  UkiSectionCharacteristics = 0x40000040'i64

proc parsePeLayout*(image: string): PeLayout =
  ## Raises ``ValueError`` naming what is wrong. A stub that is not a
  ## PE32+ image is a configuration mistake worth failing loudly on: the
  ## alternative is a file that looks like a UKI and is not bootable.
  if image.len < 0x40:
    raise newException(ValueError, "not a PE image: only " & $image.len &
      " bytes")
  if image[0] != 'M' or image[1] != 'Z':
    raise newException(ValueError,
      "not a PE image: no MZ signature at offset 0")
  let peOffset = peU32(image, 0x3C)
  if peOffset <= 0 or peOffset + PeSignatureSize + PeCoffHeaderSize > image.len:
    raise newException(ValueError,
      "not a PE image: e_lfanew " & $peOffset & " is outside the file")
  if image[peOffset .. peOffset + 3] != "PE\0\0":
    raise newException(ValueError,
      "not a PE image: no PE signature at e_lfanew " & $peOffset)
  let coff = peOffset + PeSignatureSize
  result.peOffset = peOffset
  result.sectionCount = peU16(image, coff + 2)
  result.optionalHeaderSize = peU16(image, coff + 16)
  let opt = coff + PeCoffHeaderSize
  if opt + 68 > image.len:
    raise newException(ValueError, "PE optional header is truncated")
  if peU16(image, opt) != PeMagicPe32Plus:
    raise newException(ValueError,
      "the EFI stub is not a PE32+ image (optional header magic " &
      toHex(peU16(image, opt), 4) & "); ReproOS builds x86-64 UKIs only")
  result.sectionAlignment = peU32(image, opt + 32)
  result.fileAlignment = peU32(image, opt + 36)
  result.sizeOfImage = peU32(image, opt + 56)
  result.sizeOfHeaders = peU32(image, opt + 60)
  result.sectionTableOffset = opt + result.optionalHeaderSize
  if result.sectionTableOffset +
      result.sectionCount * PeSectionHeaderSize > image.len:
    raise newException(ValueError, "the PE section table is truncated")
  if result.fileAlignment <= 0 or result.sectionAlignment <= 0:
    raise newException(ValueError,
      "the PE declares a zero alignment (file " & $result.fileAlignment &
      ", section " & $result.sectionAlignment & ")")

proc readPeSections*(image: string): seq[UkiSectionInfo] =
  ## The section table, in file order.
  let layout = parsePeLayout(image)
  result = @[]
  for i in 0 ..< layout.sectionCount:
    let at = layout.sectionTableOffset + i * PeSectionHeaderSize
    var name = ""
    for j in 0 ..< 8:
      if image[at + j] == '\0': break
      name.add image[at + j]
    result.add UkiSectionInfo(
      name: name,
      virtualSize: peU32(image, at + 8),
      virtualAddress: peU32(image, at + 12),
      rawSize: peU32(image, at + 16),
      fileOffset: peU32(image, at + 20))

# ---------------------------------------------------------------------
# Assembly.
# ---------------------------------------------------------------------

proc validateUkiSections*(sections: openArray[UkiSection]): string =
  ## "" when the section list is emittable, otherwise the operator-facing
  ## reason.
  var seen: seq[string] = @[]
  for s in sections:
    if s.name.len == 0:
      return "a UKI section has no name"
    if s.name.len > 8:
      return "UKI section name " & s.name.escape() & " is " & $s.name.len &
        " bytes; a COFF section header holds at most 8"
    if not s.name.startsWith("."):
      return "UKI section name " & s.name.escape() & " does not start " &
        "with a dot, which is what every section the stub looks for does"
    if s.name in seen:
      return "UKI section " & s.name & " is declared twice"
    if s.content.len == 0:
      return "UKI section " & s.name & " has no content; a section that " &
        "is present and empty is worse than one that is absent, because " &
        "the stub will consume it"
    seen.add s.name
  if UkiLinuxSection notin seen:
    return "a UKI must carry " & UkiLinuxSection & "; without a kernel " &
      "there is nothing for the stub to boot"
  if UkiCmdlineSection notin seen:
    return "a UKI must carry " & UkiCmdlineSection & "; the command line " &
      "being INSIDE the measured image is the reason this format is used " &
      "at all, so an image without one is refused rather than defaulted"
  # The declared order is the whole determinism story; a caller that
  # hands sections over in some other order would produce bytes that
  # depend on its own iteration order.
  var expected: seq[string] = @[]
  for name in UkiSectionOrder:
    if name in seen: expected.add name
  var got: seq[string] = @[]
  for s in sections: got.add s.name
  if got != expected:
    return "UKI sections were handed over as " & got.join(", ") &
      " but must be written in the declared order " & expected.join(", ") &
      "; two builds that order their sections differently produce " &
      "different bytes for an identical system"
  ""

proc assembleUki*(stub: string; sections: openArray[UkiSection];
                  sourceDateEpoch: int64): string =
  ## Pack ``sections`` into ``stub`` and return the whole UKI.
  ##
  ## Pure: the same stub, the same sections and the same epoch give the
  ## same bytes on any host, which is what ``t_uki_is_deterministic``
  ## checks and what makes a precomputed launch measurement possible.
  let sectionError = validateUkiSections(sections)
  if sectionError.len > 0:
    raise newException(ValueError, "assembleUki: " & sectionError)
  let layout = parsePeLayout(stub)

  let tableEnd = layout.sectionTableOffset +
    layout.sectionCount * PeSectionHeaderSize
  let needed = sections.len * PeSectionHeaderSize
  if tableEnd + needed > layout.sizeOfHeaders:
    raise newException(ValueError,
      "assembleUki: the stub's headers have room for " &
      $((layout.sizeOfHeaders - tableEnd) div PeSectionHeaderSize) &
      " more sections and " & $sections.len & " are needed; a stub " &
      "linked without header headroom cannot carry a UKI's sections " &
      "without overwriting the first one")

  var image = stub
  var nextOffset = alignUp(image.len, layout.fileAlignment)
  var nextVirtual = 0
  for s in readPeSections(stub):
    nextVirtual = max(nextVirtual, s.virtualAddress + s.virtualSize)
  nextVirtual = alignUp(nextVirtual, layout.sectionAlignment)

  # Pad the file out to the first new section's offset before appending,
  # so a stub whose last section's raw data stops short of an alignment
  # boundary does not shift every offset below.
  if image.len < nextOffset:
    image.add newString(nextOffset - image.len)

  var headers = newSeq[string](sections.len)
  for i, s in sections:
    let rawSize = alignUp(s.content.len, layout.fileAlignment)
    var header = newString(PeSectionHeaderSize)
    for j in 0 ..< s.name.len:
      header[j] = s.name[j]
    pePutU32(header, 8, int64(s.content.len))    # VirtualSize
    pePutU32(header, 12, int64(nextVirtual))     # VirtualAddress
    pePutU32(header, 16, int64(rawSize))         # SizeOfRawData
    pePutU32(header, 20, int64(nextOffset))      # PointerToRawData
    pePutU32(header, 36, UkiSectionCharacteristics)
    headers[i] = header

    image.add s.content
    if rawSize > s.content.len:
      image.add newString(rawSize - s.content.len)
    nextOffset += rawSize
    nextVirtual = alignUp(nextVirtual + s.content.len,
                          layout.sectionAlignment)

  for i, header in headers:
    let at = layout.sectionTableOffset +
      (layout.sectionCount + i) * PeSectionHeaderSize
    for j in 0 ..< PeSectionHeaderSize:
      image[at + j] = header[j]

  let coff = layout.peOffset + PeSignatureSize
  pePutU16(image, coff + 2, layout.sectionCount + sections.len)
  # The COFF timestamp. Left alone it is the stub's own, which is stable
  # here, but a UKI is a NEW artifact and its timestamp must be a
  # function of the build's declared epoch rather than of whichever
  # toolchain produced the stub.
  pePutU32(image, coff + 4, sourceDateEpoch)
  let opt = coff + PeCoffHeaderSize
  pePutU32(image, opt + 56, int64(nextVirtual))   # SizeOfImage
  # The PE checksum is not consulted by EFI firmware and objcopy leaves
  # it stale. Zeroed rather than recomputed, so that the field is a
  # constant instead of a second thing to keep in step.
  pePutU32(image, opt + 64, 0)
  image

proc ukiSectionContent*(image: string; name: string): string =
  ## The bytes of one section of a finished UKI, or "" when it has none.
  ## Truncated to ``VirtualSize``, so the file-alignment padding the
  ## assembler wrote is not handed back as content.
  for s in readPeSections(image):
    if s.name == name:
      if s.fileOffset + s.virtualSize > image.len:
        raise newException(ValueError,
          "UKI section " & name & " claims " & $s.virtualSize &
          " bytes at offset " & $s.fileOffset & ", past the end of a " &
          $image.len & "-byte image")
      return image[s.fileOffset ..< s.fileOffset + s.virtualSize]
  ""

proc ukiCmdline*(image: string): string =
  ## The kernel command line a finished UKI carries. This is the value a
  ## verifier compares against what it expected the machine to boot with.
  ukiSectionContent(image, UkiCmdlineSection)

proc ukiDigest*(image: string): string =
  ## The image's SHA-256, lower-case hex. Not a PCR value and not a
  ## substitute for one — it is the identity of the artifact, which is
  ## what a build compares between two runs and what changes when any
  ## input, the command line included, changes.
  toLowerAscii($sha256.digest(image))

# ---------------------------------------------------------------------
# The command line, composed from the values verity.nim declares.
# ---------------------------------------------------------------------

const
  UkiBaseCmdlineArgs*: array[2, string] = ["ro", "quiet"]
    ## What every attested command line carries beyond the verity keys.
    ## ``ro`` states the intent at the mount as well as at the device;
    ## ``quiet`` is the product's existing console policy. Spelled out
    ## because the command line is measured: an argument that appears
    ## only on some builds moves the measurement for reasons an operator
    ## cannot see.

type
  AttestedBootDevices* = object
    ## The volumes an attested command line names.
    data*: string      ## the verity data image
    hash*: string      ## the Merkle tree over it
    stateVar*: string
    stateHome*: string

const AttestedBootDeviceRefs* = AttestedBootDevices(
  data: "LABEL=reproos-root",
  hash: "LABEL=reproos-roothash",
  stateVar: "LABEL=reproos-var",
  stateHome: "LABEL=reproos-home")
  ## How the attested command line names its volumes.
  ##
  ## ``LABEL=`` rather than a device path, because ``/dev/vda2`` on QEMU
  ## is ``/dev/nvme0n1p2`` on a laptop and ``/dev/sda2`` on a server,
  ## and the initrd resolves ``LABEL=`` with ``findfs`` before any udev
  ## exists. The labels are the ones ``repro/disk_layouts.nim`` declares
  ## and ``build-verity-root.sh`` writes.
  ##
  ## ONE of these does not exist yet, and saying so here is the point of
  ## naming them in one place: ``reproos-roothash`` is the volume the
  ## dm-verity Merkle tree lives on, and the attested layout does not
  ## carry one. The tree's placement — a volume of its own, or a tail
  ## offset inside the root volume — is not settled, and settling it is
  ## part of teaching the image driver to write the verity artifacts onto
  ## the partition table. Until that lands the attested layout is refused
  ## at plan time and the refusal says exactly this. What IS settled, and
  ## is what a unified kernel image is for, is that the command line
  ## naming them is inside the measured image rather than in a loader
  ## configuration file anything can edit.

proc attestedKernelCmdline*(rootHash, dataDevice, hashDevice,
                            varDevice, homeDevice: string;
                            extra: openArray[string] = []): string =
  ## The command line an attested UKI carries.
  ##
  ## Composed from ``repro/verity.nim``'s renderings rather than from a
  ## string literal here, so the keys the initrd parses, the keys the
  ## verity module declares and the keys this image measures are one
  ## declaration. The root hash is the load-bearing part: it is inside
  ## the PE, so it is inside the measurement.
  var parts: seq[string] = @[]
  parts.add verity.verityCmdlineFragment(rootHash, dataDevice, hashDevice)
  let state = verity.stateCmdlineFragment(varDevice, homeDevice)
  if state.len > 0:
    parts.add state
  for a in UkiBaseCmdlineArgs:
    parts.add a
  for a in extra:
    if a.len > 0:
      parts.add a
  parts.join(" ")

proc validateAttestedCmdline*(cmdline, rootHash: string): string =
  ## "" when the command line is one an attested image may boot with.
  ##
  ## The negative half matters more than the positive one: a command line
  ## that has lost its root hash still boots, still measures, and
  ## silently drops the integrity check — so it is refused at assembly
  ## rather than discovered at attestation time.
  if rootHash.len != 64:
    return "the verity root hash is " & $rootHash.len & " characters; a " &
      "sha256 root hash is 64 hex digits"
  for c in rootHash:
    if c notin {'0'..'9', 'a'..'f'}:
      return "the verity root hash must be lower-case hex (got " &
        rootHash.escape() & ")"
  if verity.VerityRootHashCmdlineKey & "=" & rootHash notin cmdline:
    return "the kernel command line does not carry " &
      verity.VerityRootHashCmdlineKey & "=" & rootHash & "; without it " &
      "the initrd mounts an unchecked root and the measurement covers " &
      "nothing about the root filesystem"
  if verity.VerityDataDeviceCmdlineKey & "=" notin cmdline or
     verity.VerityHashDeviceCmdlineKey & "=" notin cmdline:
    return "the kernel command line names a root hash but not both of " &
      verity.VerityDataDeviceCmdlineKey & "= and " &
      verity.VerityHashDeviceCmdlineKey & "=; the initrd refuses that " &
      "combination at boot, so it is refused here instead"
  if '\n' in cmdline or '\0' in cmdline:
    return "the kernel command line contains a newline or a NUL"
  ""

# ---------------------------------------------------------------------
# The stub, and what pins it.
# ---------------------------------------------------------------------

proc ukiStubDigest*(path: string): string =
  ## The SHA-256 of a candidate stub, or "" when it cannot be read.
  if not fileExists(path): return ""
  try: toLowerAscii($sha256.digest(readFile(path)))
  except CatchableError: ""

proc validateUkiStub*(path: string): string =
  ## "" when ``path`` is the pinned stub, otherwise the reason it is not.
  if path.len == 0:
    return "no EFI stub was given"
  if not fileExists(path):
    return "the EFI stub does not exist: " & path
  let digest = ukiStubDigest(path)
  if digest != PinnedUkiStubSha256:
    return "the EFI stub at " & path & " has sha256 " & digest &
      ", not the pinned " & PinnedUkiStubSha256 & " (" &
      PinnedUkiStubProvider & "'s " & PinnedUkiStubName & "). The stub's " &
      "bytes are inside the launch measurement, so an unpinned stub " &
      "would move every expected value while every visible input stayed " &
      "the same."
  ""

proc describeUkiStubSearch*(): string =
  ## The remediation text a failure prints, so the diagnostic names the
  ## fix rather than only the symptom.
  var lines = @[
    "No copy of the pinned EFI stub was found on this host.",
    "Wanted: " & PinnedUkiStubName & " from " & PinnedUkiStubProvider &
      ", sha256 " & PinnedUkiStubSha256 & ".",
    "Set " & UkiStubEnvVar & " to an explicit copy, or realise the one " &
      "the pinned package channel provides.",
    "Locations searched:"]
  for glob in UkiStubSearchGlobs:
    lines.add "  - " & glob
  lines.join("\n")

proc resolveUkiStub*(): string =
  ## The pinned stub's path, or "".
  ##
  ## Content decides, not the path: every candidate is digested and one
  ## that is not the pinned bytes is skipped. That is what makes a glob
  ## over a store holding fifty ``systemd`` versions resolve to exactly
  ## one answer or to none.
  let explicit = getEnv(UkiStubEnvVar)
  if explicit.len > 0:
    return (if validateUkiStub(explicit).len == 0: explicit else: "")
  for glob in UkiStubSearchGlobs:
    for candidate in walkPattern(glob):
      if ukiStubDigest(candidate) == PinnedUkiStubSha256:
        return candidate
  ""

# ---------------------------------------------------------------------
# The spec, and the file-driven assembly the recipe's action performs.
# ---------------------------------------------------------------------

proc defaultOsRelease*(version: string): string =
  ## The ``.osrel`` payload. Minimal on purpose: every key here is
  ## measured, so a field that carries a build host's name or a
  ## timestamp would make two identical systems measure differently.
  "ID=reproos\n" &
  "NAME=\"ReproOS\"\n" &
  "PRETTY_NAME=\"ReproOS " & version & "\"\n" &
  "VERSION_ID=" & version & "\n"

proc ukiSections*(spec: UkiSpec; kernel, initrd: string): seq[UkiSection] =
  ## The section list for one UKI, in ``UkiSectionOrder``.
  var byName: seq[UkiSection] = @[]
  byName.add UkiSection(name: UkiOsRelSection, content: spec.osRelease)
  byName.add UkiSection(name: UkiCmdlineSection, content: spec.cmdline)
  if spec.uname.len > 0:
    byName.add UkiSection(name: UkiUnameSection, content: spec.uname)
  if initrd.len > 0:
    byName.add UkiSection(name: UkiInitrdSection, content: initrd)
  byName.add UkiSection(name: UkiLinuxSection, content: kernel)
  result = @[]
  for name in UkiSectionOrder:
    for s in byName:
      if s.name == name:
        result.add s

proc validateUkiSpec*(spec: UkiSpec): string =
  ## "" when the spec can be assembled, otherwise the operator-facing
  ## reason. Every check here fails the BUILD; none of them is something
  ## a boot could recover from.
  if spec.stubPath.len == 0:
    return "no EFI stub was selected\n" & describeUkiStubSearch()
  let stubError = validateUkiStub(spec.stubPath)
  if stubError.len > 0:
    return stubError
  if spec.kernelPath.len == 0 or not fileExists(spec.kernelPath):
    return "the kernel image does not exist: " & spec.kernelPath
  if spec.initrdPath.len > 0 and not fileExists(spec.initrdPath):
    return "the initrd does not exist: " & spec.initrdPath
  if spec.cmdline.len == 0:
    return "the kernel command line is empty; a UKI exists to carry one " &
      "inside the measured image, so assembling one without a command " &
      "line is refused rather than defaulted"
  if '\n' in spec.cmdline or '\0' in spec.cmdline:
    return "the kernel command line contains a newline or a NUL"
  if '"' in spec.cmdline or '\\' in spec.cmdline:
    # The manifest beside the image records the command line, and its
    # renderer is a hand-written one with a fixed key order rather than
    # a general JSON encoder. Refusing here is better than emitting a
    # manifest a consumer cannot parse, or than growing an escaping rule
    # nothing exercises.
    return "the kernel command line contains a quote or a backslash, " &
      "which the manifest's renderer cannot represent"
  if spec.osRelease.len == 0:
    return "the .osrel payload is empty"
  if spec.sourceDateEpoch <= 0:
    return "SOURCE_DATE_EPOCH is not set; the COFF timestamp would " &
      "otherwise be whatever this build happened to run at, and two " &
      "builds of identical inputs would produce different images"
  ""

proc assembleUkiFromFiles*(spec: UkiSpec): string =
  ## Read the spec's inputs and return the UKI's bytes.
  let specError = validateUkiSpec(spec)
  if specError.len > 0:
    raise newException(ValueError, "assembleUkiFromFiles: " & specError)
  let stub = readFile(spec.stubPath)
  let kernel = readFile(spec.kernelPath)
  let initrd = if spec.initrdPath.len > 0: readFile(spec.initrdPath) else: ""
  assembleUki(stub, ukiSections(spec, kernel, initrd), spec.sourceDateEpoch)

# ---------------------------------------------------------------------
# The typed request the recipe's assembly action is built from.
#
# The action in ``recipes/reproos-image/package.nim`` is constructed out
# of one of these rather than out of a command string. That is what makes
# it a typed edge: the inputs it declares, the outputs it declares and
# the arguments the tool receives are all derived from the same value by
# the three procs below, so a field that is added here cannot be wired
# into two of the three and forgotten in the last.
# ---------------------------------------------------------------------

type
  UkiAssembleRequest* = object
    stubPath*: string
    kernelPath*: string
    initrdPath*: string
    verityRootHashPath*: string
      ## The file ``build_verity_root`` writes. Read at ACTION time, not
      ## at plan time: the root hash is a function of the staged tree,
      ## which does not exist until that action has run. Naming the file
      ## rather than the value is what makes the command line a function
      ## of the root closure.
    verityDataDevice*: string
    verityHashDevice*: string
    stateVarDevice*: string
    stateHomeDevice*: string
    extraArgs*: seq[string]
    osReleaseVersion*: string
    unamePath*: string
      ## The kernel package's ``kernel.release`` file. Read at action
      ## time for the same reason the root hash is: transcribing it into
      ## the recipe would be a second declaration of the kernel version,
      ## and it is measured.
    sourceDateEpoch*: int64
    outputDir*: string
      ## Relative to the action's working directory.

proc ukiOutputPaths*(request: UkiAssembleRequest): seq[string] =
  ## The four artifacts one assembly produces, in a fixed order.
  @[
    request.outputDir / UkiFileName,
    request.outputDir / UkiManifestFileName,
    request.outputDir / UkiDigestFileName,
    request.outputDir / UkiCmdlineFileName,
  ]

proc ukiAssembleArgv*(tool: string;
                      request: UkiAssembleRequest): seq[string] =
  ## The exact argv the assembly action runs.
  ##
  ## Rendered here and nowhere else, so the recipe and the gate that
  ## drives the same tool agree by construction rather than by two people
  ## typing the same flags.
  let outputs = ukiOutputPaths(request)
  result = @[tool, "assemble",
    "--stub", request.stubPath,
    "--kernel", request.kernelPath]
  if request.initrdPath.len > 0:
    result.add ["--initrd", request.initrdPath]
  result.add ["--verity-root-hash-file", request.verityRootHashPath]
  result.add ["--verity-data", request.verityDataDevice]
  result.add ["--verity-hash", request.verityHashDevice]
  if request.stateVarDevice.len > 0:
    result.add ["--state-var", request.stateVarDevice]
  if request.stateHomeDevice.len > 0:
    result.add ["--state-home", request.stateHomeDevice]
  for a in request.extraArgs:
    result.add ["--extra-arg", a]
  result.add ["--os-release-version", request.osReleaseVersion]
  if request.unamePath.len > 0:
    result.add ["--uname-file", request.unamePath]
  result.add ["--source-date-epoch", $request.sourceDateEpoch]
  result.add ["--out", outputs[0]]
  result.add ["--manifest", outputs[1]]
  result.add ["--digest-out", outputs[2]]
  result.add ["--cmdline-out", outputs[3]]

proc validateUkiAssembleRequest*(request: UkiAssembleRequest): string =
  ## "" when the request is one the action may be registered for,
  ## otherwise the operator-facing reason. Checked at PLAN time, so a
  ## request that could not produce an attestable image fails before the
  ## build starts rather than after it.
  if request.stubPath.len == 0:
    return "no EFI stub was selected\n" & describeUkiStubSearch()
  let stubError = validateUkiStub(request.stubPath)
  if stubError.len > 0:
    return stubError
  if request.kernelPath.len == 0:
    return "no kernel was named for the unified kernel image"
  if request.verityRootHashPath.len == 0:
    return "no verity root hash file was named; a unified kernel image " &
      "whose command line does not pin the root hash measures a boot " &
      "that says nothing about the root filesystem"
  if request.verityDataDevice.len == 0 or request.verityHashDevice.len == 0:
    return "the unified kernel image must name both the verity data " &
      "device and the verity hash device; the initrd refuses one " &
      "without the other, so it is refused here instead"
  if request.sourceDateEpoch <= 0:
    return "SOURCE_DATE_EPOCH is not pinned for the unified kernel image"
  if request.outputDir.len == 0:
    return "the unified kernel image has no output directory"
  ""

proc renderUkiManifest*(spec: UkiSpec; image: string): string =
  ## The manifest written beside the UKI. Hand-rendered in a fixed key
  ## order, because it is compared byte for byte by its gate and because
  ## it is a build artifact rather than a document anyone edits.
  ##
  ## It records the section sizes and the image digest and NOTHING about
  ## a PCR: the value a verifier checks is computed by the measurement
  ## work from these inputs, and a half-computed one here would be
  ## a number nobody could falsify.
  var sectionLines: seq[string] = @[]
  for info in readPeSections(image):
    var declared = false
    for name in UkiSectionOrder:
      if info.name == name: declared = true
    if not declared: continue
    sectionLines.add "    {\"name\": \"" & info.name & "\", \"size\": " &
      $info.virtualSize & "}"
  "{\n" &
  "  \"schema\": \"reproos.uki.v1\",\n" &
  "  \"digest\": \"" & ukiDigest(image) & "\",\n" &
  "  \"cmdline\": \"" & spec.cmdline & "\",\n" &
  "  \"stubSha256\": \"" & PinnedUkiStubSha256 & "\",\n" &
  "  \"stubProvider\": \"" & PinnedUkiStubProvider & "\",\n" &
  "  \"signed\": false,\n" &
  "  \"sourceDateEpoch\": " & $spec.sourceDateEpoch & ",\n" &
  "  \"sections\": [\n" & sectionLines.join(",\n") & "\n  ],\n" &
  "  \"measurementOrder\": [" &
    (block:
      var parts: seq[string] = @[]
      for name in UkiMeasurementOrder: parts.add "\"" & name & "\""
      parts.join(", ")) & "]\n" &
  "}\n"
