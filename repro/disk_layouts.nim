## ReproOS image disk-layout presets.
##
## ## Why this module exists
##
## Layout selection used to live in two places that could not be kept in
## step: a bash ``case`` with a single arm in
## ``recipes/reproos-image/scripts/build-reproos-image.sh`` and, twenty
## lines below it, a JSON heredoc that hand-wrote the disko document the
## ``repro disk apply`` driver consumes. Adding a second layout meant
## adding a second heredoc, and an unknown layout name was only rejected
## once the image build was already running as root against an attached
## NBD device.
##
## This module is the single declaration of what layouts exist. A preset
## is a *typed value* — a ``DiskLayout`` built out of the Reprobuild
## profile types (``DiskSpec`` / ``PartitionSpec`` / ``ContentSpec``) —
## and the JSON the recipe feeds to ``repro disk apply`` is rendered from
## that value. The name is resolved and validated at *plan* time, in
## ``recipes/reproos-image/package.nim``, so a typo fails before any
## privileged work starts and the error names the legal set.
##
## ## Why here rather than in ``reprobuild``
##
## The typed model is platform: ``DiskLayout``, ``ContentSpec`` and
## ``applyDiskLayout`` are Reprobuild's and are shared by every product
## that partitions a disk. *Which* layouts ReproOS images ship, what they
## are called in ``auto-config.toml``, and how big their volumes are, are
## ReproOS product decisions. They live next to ``package_sets.nim``,
## the other product-level declaration the recipe graph consumes.
##
## ## The renderer is byte-compatible with the heredoc it replaces
##
## ``renderDiskoDocument`` is a pretty-printer, not Reprobuild's
## canonical ``emitSystemHardwareJson``. That is deliberate and it is the
## only reason the refactor can be proved to be a refactor: the two
## differ in key order inside a partition object (the canonical emitter
## writes ``content`` before ``bootable``), so routing through it would
## have changed the bytes the recipe writes. The pretty-printer
## reproduces the retired heredoc exactly, which is what
## ``tests/test_disk_layout_presets.nim`` pins.
##
## The output is still typed all the way down: it parses back through
## Reprobuild's own ``parseSystemHardwareJson`` into a structurally equal
## ``SystemHardwareSpec``, which the same test asserts for every preset.

import std/[options, sha1, strutils, tables]

import repro_profile/types
import repro_profile/disk_identity

type
  DiskLayoutStatus* = enum
    ## Whether the image driver can install a preset today.
    dlsBuildable
      ## ``build-reproos-image.sh`` installs this layout end to end.
    dlsDeclared
      ## The shape is declared and renders, but the driver cannot fill
      ## it in yet. Selecting it fails at plan time with the reason.

  DiskLayoutParams* = object
    ## Everything a preset needs that is not fixed by the preset itself.
    id*: string          ## ``SystemHardwareSpec.id``
    device*: string      ## the block device the layout is applied to
    espSizeMib*: int     ## ``[disk.layout] esp_size_mib``
    diskSizeGb*: int     ## ``[disk] size_gb``

  DiskLayoutPreset* = object
    ## Registry entry. Metadata only — the partition table itself is
    ## built by ``buildDiskLayout``, because a ``DiskLayout`` depends on
    ## the per-build ``DiskLayoutParams``.
    name*: string
    summary*: string
    status*: DiskLayoutStatus
    unbuildableReason*: string
      ## Non-empty exactly when ``status == dlsDeclared``.
    minDiskSizeGb*: int
      ## Smallest ``[disk] size_gb`` whose fixed-size partitions fit.
    defaultEspSizeMib*: int

  DiskLayoutRequest* = object
    ## A layout as read out of an ``auto-config.toml``.
    name*: string
    params*: DiskLayoutParams

const
  DiskLayoutPresets*: array[2, DiskLayoutPreset] = [
    DiskLayoutPreset(
      name: "uefi-ext4",
      summary: "ESP + a single writable ext4 root; the layout every " &
        "ReproOS image has shipped with",
      status: dlsBuildable,
      unbuildableReason: "",
      minDiskSizeGb: 4,
      defaultEspSizeMib: 512),
    DiskLayoutPreset(
      name: "uefi-attested",
      summary: "ESP + a read-only root + separate /var, /home and swap; " &
        "the shape an attestable image needs",
      status: dlsDeclared,
      unbuildableReason:
        "boot now goes through a unified kernel image whose command " &
        "line pins the root hash inside the measured binary, but the " &
        "image driver still does not write the integrity-checked root " &
        "image or its hash tree onto this layout, and the layout " &
        "carries no volume for the hash tree; the result would be a " &
        "measured command line naming volumes that are not there",
      minDiskSizeGb: 16,
      defaultEspSizeMib: 512),
  ]

  DefaultDiskLayoutName* = "uefi-ext4"
  DefaultDiskSizeGb* = 8
  DefaultEspSizeMib* = 512
  MinEspSizeMib* = 128
    ## The smallest ESP the validator accepts. Named because the
    ## generated installer table below has to carry the same number and
    ## a literal in two languages is how the previous divergence
    ## started.

  AttestedRootSize* = "4G"
    ## Fixed because the verity data image is written here verbatim: the
    ## partition holds a byte-for-byte copy of an image whose hash tree
    ## was taken over exactly those bytes. A percentage size would move
    ## every time the closure moved, and with it the block count the
    ## verity table declares.
  AttestedSwapSize* = "2G"
  AttestedVarSize* = "4G"
  AttestedHomeSize* = "100%"
    ## ``/home`` absorbs the remainder, so it must stay the LAST
    ## partition: ``disk_apply`` translates ``100%`` into sgdisk's
    ## fill-the-disk form, which is only correct for the final entry.

# ---------------------------------------------------------------------
# Registry lookup.
# ---------------------------------------------------------------------

proc diskLayoutPresetNames*(): seq[string] =
  ## Declaration order, which is also the order every error message
  ## lists them in.
  result = @[]
  for p in DiskLayoutPresets:
    result.add p.name

proc findDiskLayoutPreset*(name: string): Option[DiskLayoutPreset] =
  for p in DiskLayoutPresets:
    if p.name == name:
      return some(p)
  none(DiskLayoutPreset)

proc legalDiskLayoutListing*(): string =
  var lines: seq[string] = @[]
  for p in DiskLayoutPresets:
    var line = "    " & p.name & " — " & p.summary
    if p.status == dlsDeclared:
      line.add " (declared, not yet buildable)"
    lines.add line
  lines.join("\n")

# ---------------------------------------------------------------------
# Content constructors. Thin wrappers so the preset bodies below read as
# partition tables rather than as object construction.
# ---------------------------------------------------------------------

proc fsContent(format, mountpoint, label: string;
               mountOptions: seq[string]): ContentSpec =
  ContentSpec(
    kind: cfsFilesystem,
    format: format,
    mountpoint: mountpoint,
    mountOptions: mountOptions,
    label: label,
    subvols: @[])

proc swapContent(): ContentSpec =
  ContentSpec(kind: cfsSwap, swapPriority: 0, swapDiscardPolicy: "")

proc part(kind, size: string; content: ContentSpec;
          bootable = false): PartitionSpec =
  PartitionSpec(`type`: kind, size: size, content: content,
                bootable: bootable)

proc espPartition(espSizeMib: int): PartitionSpec =
  ## Shared by both presets. ``umask=0077`` keeps the ESP unreadable to
  ## non-root, which the installed system's fstab inherits.
  part("esp", $espSizeMib & "M",
    fsContent("vfat", "/boot", "ESP", @["umask=0077"]),
    bootable = true)

# ---------------------------------------------------------------------
# The presets.
# ---------------------------------------------------------------------

proc uefiExt4Layout(p: DiskLayoutParams): DiskLayout =
  ## The shipped layout, transliterated from the heredoc it replaces.
  ## Any change here changes installed images, and
  ## ``t_disk_layout_preset_registry``'s byte-comparison case is what
  ## makes that impossible to do by accident.
  var partitions: OrderedTable[string, PartitionSpec]
  partitions["esp"] = espPartition(p.espSizeMib)
  partitions["root"] = part("linux", "100%",
    fsContent("ext4", "/", "reproos-root", @["defaults"]))
  result.disks["main"] = DiskSpec(
    device: p.device, `type`: "gpt", partitions: partitions)
  result.pools = @[]

proc uefiAttestedLayout(p: DiskLayoutParams): DiskLayout =
  ## The attestable shape: everything measured is read-only, everything
  ## writable is off the measured surface and on its own volume.
  ##
  ## What this DOES declare, today: the partition table — an ESP, a root
  ## partition mounted ``ro``, and distinct ``/var``, ``/home`` and swap
  ## volumes at the sizes above.
  ##
  ## What it does NOT yet do: install the verity data image and its hash
  ## tree onto that root partition, or carry a volume for the hash tree
  ## at all, or encrypt the state volumes. The verity image and its root
  ## hash ARE built — ``recipes/reproos-image/scripts/build-verity-root.sh``
  ## produces them from the staged tree, and ``repro/verity.nim`` declares
  ## their shape — and the root hash IS pinned on a measured kernel
  ## command line now, inside the unified kernel image ``repro/uki.nim``
  ## assembles. But the root partition below is still a plain ext4 that is
  ## merely *mounted* read-only. It is the slot the verity image goes
  ## into, not yet a measured root.
  var partitions: OrderedTable[string, PartitionSpec]
  partitions["esp"] = espPartition(p.espSizeMib)
  partitions["root"] = part("linux", AttestedRootSize,
    fsContent("ext4", "/", "reproos-root", @["ro"]))
  partitions["swap"] = part("swap", AttestedSwapSize, swapContent())
  partitions["var"] = part("linux", AttestedVarSize,
    fsContent("ext4", "/var", "reproos-var", @["defaults"]))
  partitions["home"] = part("linux", AttestedHomeSize,
    fsContent("ext4", "/home", "reproos-home", @["defaults"]))
  result.disks["main"] = DiskSpec(
    device: p.device, `type`: "gpt", partitions: partitions)
  result.pools = @[]

proc buildDiskLayout*(name: string; p: DiskLayoutParams): DiskLayout =
  ## Build the typed layout for a registered preset. Callers are
  ## expected to have run ``validateDiskLayoutRequest`` first; an
  ## unregistered name is a defect here, not a user error.
  case name
  of "uefi-ext4": uefiExt4Layout(p)
  of "uefi-attested": uefiAttestedLayout(p)
  else:
    raise newException(ValueError,
      "buildDiskLayout: '" & name & "' is not a registered layout " &
      "preset (legal: " & diskLayoutPresetNames().join(", ") & ")")

proc diskLayoutHardwareSpec*(name: string;
                             p: DiskLayoutParams): SystemHardwareSpec =
  ## Wrap the layout in the ``SystemHardwareSpec`` envelope that
  ## ``repro disk apply`` and ``repro infra install-root`` parse.
  result = SystemHardwareSpec(
    id: p.id,
    cpuArch: "x86_64",
    cpuMicrocode: "intel",
    kernelModules: @[],
    loaderDevice: p.device,
    filesystems: @[],
    graphicsDrivers: @[],
    audioCards: @[],
    disko: some(buildDiskLayout(name, p)))

# ---------------------------------------------------------------------
# Rendering.
#
# Two-space indent, objects expanded, arrays always inline. Those three
# rules reproduce the retired heredoc byte for byte; see the module
# header for why the canonical emitter could not be used directly.
# ---------------------------------------------------------------------

proc jsonStr(s: string): string =
  result = "\""
  for c in s:
    case c
    of '"': result.add "\\\""
    of '\\': result.add "\\\\"
    of '\n': result.add "\\n"
    of '\t': result.add "\\t"
    of '\r': result.add "\\r"
    else: result.add c
  result.add "\""

proc jsonStrList(items: seq[string]): string =
  var parts: seq[string] = @[]
  for it in items:
    parts.add jsonStr(it)
  "[" & parts.join(",") & "]"

proc obj(indent: int; fields: seq[(string, string)]): string =
  ## ``fields`` are already-rendered values; ``indent`` is the column
  ## the closing brace sits at.
  let inner = repeat(' ', indent + 2)
  var lines: seq[string] = @[]
  for (k, v) in fields:
    lines.add inner & jsonStr(k) & ": " & v
  "{\n" & lines.join(",\n") & "\n" & repeat(' ', indent) & "}"

proc renderContent(c: ContentSpec; indent: int): string =
  case c.kind
  of cfsFilesystem:
    if c.subvols.len > 0:
      raise newException(ValueError,
        "renderContent: btrfs subvolumes are not renderable yet — no " &
        "ReproOS layout preset declares any")
    obj(indent, @[
      ("kind", jsonStr("filesystem")),
      ("format", jsonStr(c.format)),
      ("mountpoint", jsonStr(c.mountpoint)),
      ("mountOptions", jsonStrList(c.mountOptions)),
      ("label", jsonStr(c.label)),
      ("subvols", "[]"),
    ])
  of cfsSwap:
    obj(indent, @[
      ("kind", jsonStr("swap")),
      ("priority", $c.swapPriority),
      ("discardPolicy", jsonStr(c.swapDiscardPolicy)),
    ])
  of cfsNone:
    obj(indent, @[("kind", jsonStr("none"))])
  of cfsEncrypted, cfsLvm, cfsZfs:
    # Deliberately unimplemented rather than guessed at: encrypted state
    # volumes are not built yet and LVM/ZFS have no ReproOS preset.
    # Rendering them
    # untested would put bytes nothing exercises into an image.
    raise newException(ValueError,
      "renderContent: content kind " & $c.kind & " is not renderable " &
      "yet — no ReproOS layout preset declares it")

proc renderPartition(p: PartitionSpec; indent: int): string =
  obj(indent, @[
    ("type", jsonStr(p.`type`)),
    ("size", jsonStr(p.size)),
    ("bootable", (if p.bootable: "true" else: "false")),
    ("content", renderContent(p.content, indent + 2)),
  ])

proc renderDisk(d: DiskSpec; indent: int): string =
  var partFields: seq[(string, string)] = @[]
  for name, p in d.partitions:
    partFields.add((name, renderPartition(p, indent + 4)))
  obj(indent, @[
    ("device", jsonStr(d.device)),
    ("type", jsonStr(d.`type`)),
    ("partitions", obj(indent + 2, partFields)),
  ])

proc renderLayout(l: DiskLayout; indent: int): string =
  if l.pools.len > 0:
    raise newException(ValueError,
      "renderLayout: ZFS pools are not renderable yet — no ReproOS " &
      "layout preset declares any")
  var diskFields: seq[(string, string)] = @[]
  for name, d in l.disks:
    diskFields.add((name, renderDisk(d, indent + 4)))
  obj(indent, @[
    ("disks", obj(indent + 2, diskFields)),
    ("pools", "[]"),
  ])

proc renderDiskoDocument*(h: SystemHardwareSpec): string =
  ## The exact bytes the recipe writes to ``$WORK/disko.json``.
  ## Terminated by a newline, as the heredoc was.
  if h.filesystems.len > 0:
    raise newException(ValueError,
      "renderDiskoDocument: a layout preset describes a disk to " &
      "create, never an already-mounted filesystem set")
  var fields = @[
    ("id", jsonStr(h.id)),
    ("cpuArch", jsonStr(h.cpuArch)),
    ("cpuMicrocode", jsonStr(h.cpuMicrocode)),
    ("kernelModules", jsonStrList(h.kernelModules)),
    ("loaderDevice", jsonStr(h.loaderDevice)),
    ("filesystems", "[]"),
    ("graphicsDrivers", jsonStrList(h.graphicsDrivers)),
    ("audioCards", jsonStrList(h.audioCards)),
  ]
  if h.disko.isSome:
    fields.add(("disko", renderLayout(h.disko.get(), 2)))
  obj(0, fields) & "\n"

proc renderDiskoJson*(name: string; p: DiskLayoutParams): string =
  renderDiskoDocument(diskLayoutHardwareSpec(name, p))

# ---------------------------------------------------------------------
# The identity seed, and the document that carries it.
#
# ## Why the identifiers are not in the disko document
#
# Left to themselves, every tool that creates a filesystem or a
# partition table invents its identifiers from the clock and the system
# RNG, so two builds of one image differ in their bytes. Reprobuild's
# ``repro disk apply`` can derive them all from one seed instead; what
# ReproOS decides here is what that seed is a function of.
#
# The seed travels in a document BESIDE the disko document, not inside
# it, and that placement is load-bearing in two ways:
#
#   1. The disko document is installed at ``/etc/repro/disko.json`` on
#      every machine built from an image. Filesystem UUIDs written into
#      it would tell every one of those machines to claim the same
#      UUIDs, and ``root=UUID=`` then names two devices in any box that
#      has two ReproOS disks. Pinned identifiers are a property of one
#      reproducible BUILD, not of a layout many machines share.
#   2. The image build already checks that the document it applies and
#      the document the installer emits are the same bytes. A build-only
#      field inside that document would have to be threaded through the
#      installer's compiled template too, in a language that has no
#      hash function, to keep that check meaningful.
#
# ## What the seed is a function of
#
# The auto-config the image is built from, the ordered source-package
# closure (which names the kernel), the layout preset, and the layout's
# sizing parameters. Two hosts building the same tuple derive the same
# seed and therefore the same identifiers.
#
# What it deliberately does NOT include is the target device: the same
# layout applied to ``/dev/nbd3`` instead of ``/dev/nbd0`` must produce
# the same filesystems, and the build picks whichever NBD node is free.
# ---------------------------------------------------------------------

const DiskIdentitySeedScheme* = "reproos-image-v1"
  ## Prefix of every seed, and part of the hashed material. Bumping it
  ## is how a deliberate change of the derivation announces itself:
  ## every identifier moves, and the seed says why.

proc reproosImageIdentitySeed*(autoConfigText: string;
                               sourcePackages: openArray[string];
                               request: DiskLayoutRequest): string =
  ## The identity seed for one image build. A pure function of its
  ## arguments — no clock, no host, no environment.
  var material = DiskIdentitySeedScheme & "\n"
  material.add "layout=" & request.name & "\n"
  material.add "id=" & request.params.id & "\n"
  material.add "esp-size-mib=" & $request.params.espSizeMib & "\n"
  material.add "disk-size-gb=" & $request.params.diskSizeGb & "\n"
  for pkg in sourcePackages:
    material.add "package=" & pkg & "\n"
  material.add "auto-config-bytes=" & $autoConfigText.len & "\n"
  material.add autoConfigText
  DiskIdentitySeedScheme & ":" & toLowerAscii($secureHash(material))

proc renderDiskIdentityJson*(autoConfigText: string;
                             sourcePackages: openArray[string];
                             request: DiskLayoutRequest): string =
  ## The exact bytes the driver writes beside the disko document, where
  ## ``repro disk apply`` finds them without being told.
  renderDiskIdentityDocument(DiskIdentity(
    seed: reproosImageIdentitySeed(autoConfigText, sourcePackages,
                                   request)))

# ---------------------------------------------------------------------
# The same layout, rendered as the ``hardware.nim`` profile source that
# is installed at ``/etc/repro/hardware.nim``.
#
# This is not a second description of the layout: it is the same typed
# ``DiskLayout``, printed in the ``repro_profile`` DSL's vocabulary
# instead of in JSON, because ``repro disk plan`` and ``repro infra
# install-root`` accept either form. Keeping it here is the whole point
# of the module — the installer used to hand-write this text too, and
# its copy had already drifted (no labels, ``noatime`` on the root, no
# ``umask=0077`` on the ESP).
#
# Key spellings are chosen for the parser, not for prettiness:
# ``kind:`` rather than ``type:`` (``type`` is a Nim keyword and the
# macro documents ``kind`` as the collision-free alternative), and every
# value is a string literal so that nothing depends on an identifier
# happening to be legal Nim.
# ---------------------------------------------------------------------

proc nimStrList(items: seq[string]): string =
  var parts: seq[string] = @[]
  for it in items:
    parts.add jsonStr(it)
  "@[" & parts.join(", ") & "]"

proc renderContentNim(c: ContentSpec; indent: int): string =
  let pad = repeat(' ', indent)
  case c.kind
  of cfsFilesystem:
    if c.subvols.len > 0:
      raise newException(ValueError,
        "renderContentNim: btrfs subvolumes are not renderable yet — " &
        "no ReproOS layout preset declares any")
    result.add pad & "filesystem:\n"
    result.add pad & "  format: " & jsonStr(c.format) & "\n"
    result.add pad & "  mountpoint: " & jsonStr(c.mountpoint) & "\n"
    result.add pad & "  mountOptions: " & nimStrList(c.mountOptions) & "\n"
    result.add pad & "  label: " & jsonStr(c.label) & "\n"
  of cfsSwap:
    result.add pad & "swap:\n"
    result.add pad & "  priority: " & $c.swapPriority & "\n"
    result.add pad & "  discardPolicy: " &
      jsonStr(c.swapDiscardPolicy) & "\n"
  of cfsNone:
    discard
  of cfsEncrypted, cfsLvm, cfsZfs:
    raise newException(ValueError,
      "renderContentNim: content kind " & $c.kind & " is not " &
      "renderable yet — no ReproOS layout preset declares it")

proc renderPartitionNim(name: string; p: PartitionSpec;
                        indent: int): string =
  let pad = repeat(' ', indent)
  result.add pad & jsonStr(name) & ":\n"
  result.add pad & "  kind: " & jsonStr(p.`type`) & "\n"
  result.add pad & "  size: " & jsonStr(p.size) & "\n"
  result.add pad & "  bootable: " & (if p.bootable: "true" else: "false") &
    "\n"
  if p.content.kind != cfsNone:
    result.add pad & "  content:\n"
    result.add renderContentNim(p.content, indent + 4)

proc renderLayoutNim*(l: DiskLayout; indent: int): string =
  if l.pools.len > 0:
    raise newException(ValueError,
      "renderLayoutNim: ZFS pools are not renderable yet — no ReproOS " &
      "layout preset declares any")
  let pad = repeat(' ', indent)
  result.add pad & "disks:\n"
  for diskName, d in l.disks:
    result.add pad & "  " & jsonStr(diskName) & ":\n"
    result.add pad & "    device: " & jsonStr(d.device) & "\n"
    result.add pad & "    table: " & jsonStr(d.`type`) & "\n"
    result.add pad & "    partitions:\n"
    for pName, p in d.partitions:
      result.add renderPartitionNim(pName, p, indent + 6)

proc renderHardwareNim*(name: string; p: DiskLayoutParams): string =
  ## The exact bytes written to ``/etc/repro/hardware.nim``.
  let h = diskLayoutHardwareSpec(name, p)
  result.add "# /etc/repro/hardware.nim --- generated by the ReproOS " &
    "installer\n"
  result.add "import repro_profile\n\n"
  result.add "hardware " & jsonStr(h.id) & ":\n"
  result.add "  cpu:\n"
  result.add "    arch: " & jsonStr(h.cpuArch) & "\n"
  result.add "    microcode: " & jsonStr(h.cpuMicrocode) & "\n"
  result.add "  boot:\n"
  result.add "    loaderDevice: " & jsonStr(h.loaderDevice) & "\n"
  result.add "  disko:\n"
  result.add renderLayoutNim(h.disko.get(), 4)

# ---------------------------------------------------------------------
# auto-config.toml → request.
#
# The lookup mirrors the shell ``toml_get`` in build-reproos-image.sh
# exactly — flat ``key = value`` inside ``[section]`` headers, ``#``
# comments stripped, surrounding quotes removed — so that the plan and
# the recipe read the same value out of the same file. The recipe
# re-reads it and refuses to continue if the two ever disagree.
# ---------------------------------------------------------------------

proc tomlLookup*(text, section, key: string): string =
  var current = ""
  for rawLine in text.splitLines():
    let stripped = rawLine.strip()
    if stripped.len == 0 or stripped.startsWith("#"):
      continue
    if stripped.startsWith("[") and stripped.endsWith("]"):
      current = stripped[1 ..< stripped.len - 1]
      continue
    # Strip a trailing comment the way the shell reader does -- only a
    # '#' that follows whitespace, so a '#' inside a value (a password
    # hash, say) is not a comment marker.
    var line = rawLine
    for i in 0 ..< line.len:
      if line[i] == '#' and (i == 0 or line[i - 1] in {' ', '\t'}):
        line = line[0 ..< i]
        break
    let eq = line.find('=')
    if eq < 0:
      continue
    let k = line[0 ..< eq].strip()
    var v = line[eq + 1 .. ^1].strip()
    if v.len >= 2 and ((v[0] == '"' and v[^1] == '"') or
                       (v[0] == '\'' and v[^1] == '\'')):
      v = v[1 ..< v.len - 1]
    if current == section and k == key:
      return v
  ""

proc intOr(raw: string; fallback: int): int =
  ## ``-1`` for a value that is present but not a number, so that
  ## ``validateDiskLayoutRequest`` reports it rather than the plan dying
  ## on an unhandled ``ValueError``.
  if raw.len == 0: return fallback
  try: parseInt(raw)
  except ValueError: -1

proc parseDiskLayoutRequest*(configText, id, device: string):
    DiskLayoutRequest =
  ## Read the layout selection out of an ``auto-config.toml``. Missing
  ## keys take the same defaults the recipe applies.
  let rawType = tomlLookup(configText, "disk.layout", "type")
  result.name = if rawType.len > 0: rawType else: DefaultDiskLayoutName
  result.params = DiskLayoutParams(
    id: id,
    device: device,
    espSizeMib: intOr(tomlLookup(configText, "disk.layout", "esp_size_mib"),
                      DefaultEspSizeMib),
    diskSizeGb: intOr(tomlLookup(configText, "disk", "size_gb"),
                      DefaultDiskSizeGb))

proc validateDiskLayoutRequest*(req: DiskLayoutRequest): string =
  ## Return "" when the request is buildable, otherwise the operator-
  ## facing reason. The caller turns it into a plan-time failure.
  let found = findDiskLayoutPreset(req.name)
  if found.isNone:
    return "unknown [disk.layout].type: " & jsonStr(req.name) & "\n" &
      "  legal values:\n" & legalDiskLayoutListing()
  let preset = found.get()
  if req.params.espSizeMib < MinEspSizeMib:
    return "[disk.layout].esp_size_mib must be an integer of at least " &
      $MinEspSizeMib & " (got " & $req.params.espSizeMib & ")"
  if req.params.diskSizeGb < 0:
    return "[disk] size_gb must be an integer"
  if req.params.diskSizeGb < preset.minDiskSizeGb:
    return "[disk] size_gb = " & $req.params.diskSizeGb &
      " is too small for layout " & jsonStr(preset.name) &
      ", which needs at least " & $preset.minDiskSizeGb & " GB"
  if preset.status == dlsDeclared:
    return "[disk.layout].type " & jsonStr(preset.name) &
      " is declared but not yet buildable: " & preset.unbuildableReason &
      "\n  build with " & jsonStr(DefaultDiskLayoutName) & " until then"
  ""
