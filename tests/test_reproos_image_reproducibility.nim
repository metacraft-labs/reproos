## Gate: the installed ReproOS image is reproducible — in layers, and with
## the expensive layer separated from the cheap one on purpose.
##
## ## Why this is layered, and what each layer is worth
##
## A full image build is a multi-hour, 118-source-package job that needs
## ``sudo`` and ``modprobe nbd``. Building one *twice* and comparing the
## bytes is the only thing that proves the image is reproducible — and it
## is far too expensive to be the thing that runs on every change. A gate
## that only did that would be run once, believed forever, and would
## silently stop being run.
##
## So this gate is three layers, and each one says exactly what it proves:
##
##   1. **The inputs are deterministic** (always on, seconds). Everything
##      the image is a function of — the disko document, the pinned build
##      environment of every action on the image's path, the source
##      package closure, the tool identities, the declared inputs, and the
##      scripts staged into the image — is re-derived TWICE into two clean
##      trees and compared artifact by artifact. The second derivation runs
##      under a deliberately hostile ambient environment (a different
##      ``SOURCE_DATE_EPOCH``, ``TZ``, ``LC_ALL`` and ``LANG``) and walks
##      every directory in the opposite order, because caller environment
##      and readdir order are the two things that differ between two hosts
##      building the same tree.
##
##      This PROVES that the image's inputs do not vary with the caller or
##      the filesystem. It does NOT prove that the qcow2 is byte-identical:
##      nothing here builds one.
##
##   2. **The artifact producers are pinned** (always on, seconds). Each
##      shipped script that authors an archive carries the flags that make
##      that archive a function of its inputs — a sorted entry list into
##      ``cpio``, ``--reproducible``, ``gzip -n``, a pinned GPT GUID, a
##      pinned volume modification date, a pinned FAT serial, and a hard
##      requirement for ``SOURCE_DATE_EPOCH``/``LC_ALL``/``TZ``. Each rule
##      is attributed to the ARTIFACT it protects, so a violation names the
##      artifact rather than a line number.
##
##      This PROVES the known reproducibility hazards of these tools are
##      closed in the shipped scripts. It does NOT prove the tools honour
##      the flags, and it cannot see a hazard nobody has named yet.
##
##   3. **Two builds, identical bytes** (opt-in, hours). The real thing.
##      It rebuilds the image into a clean tree and compares an ordered
##      manifest — the disko document, then the emitted configuration
##      bundle, then the qcow2 — so a mismatch names the FIRST artifact
##      that drifted instead of only reporting that the images differ.
##      It reports a visible skip, with the remedy, when it is not asked
##      for; it never reports a silent pass.
##
## And one layer that exists to prove the others can fail:
##
##   4. **Injected nondeterminism is caught** (always on, seconds). Real
##      perturbations are written into a scratch copy of the real sources
##      — a wall-clock ``SOURCE_DATE_EPOCH``, an epoch quietly made
##      inheritable, a deleted sort in the initramfs pipeline, a dropped
##      GPT GUID pin — and the SAME pipeline is run against that copy. Each
##      one must turn the gate red and must name the artifact it perturbed,
##      and only that artifact. An unperturbed copy of the same scratch
##      tree must stay green, so it is the injection and not the copying
##      that reddens.
##
## ## Why layer 3 is not the only layer
##
## Because the failures layers 1, 2 and 4 catch are the failures that
## actually happen: a pinned epoch that quietly becomes inheritable, an
## unsorted directory walk feeding an archive, a tool whose default seeds
## itself from the time of day. Those are all decided long before any
## privileged step runs, and catching them costs a second rather than an
## afternoon.
##
## ## Mocking
##
## None. Every producer reads the shipped recipes and the shipped scripts,
## renders the disko document through the shipped registry, and digests
## the bytes it wrote to disk. The injection cases perturb copies of those
## same shipped files rather than a fixture standing in for them.

import std/[algorithm, monotimes, options, os, osproc, strutils, times]

import nimcrypto/[hash, sha2]

import "../repro/disk_layouts"
import "../repro/package_sets"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  ImageRecipe = "recipes/reproos-image/package.nim"
  IsoRecipe = "recipes/reproos-iso/package.nim"
  ImageDriver = "recipes/reproos-image/scripts/build-reproos-image.sh"
  InitramfsBuilder = "recipes/reproos-iso/scripts/build-initramfs.sh"
  IsoBuilder = "recipes/reproos-iso/scripts/build-iso.sh"
  IsoGateWrapper = "tests/test-iso-reproducibility.sh"
  WorkflowRecipe = "repro/workflows.nim"
  ImageScriptsDir = "recipes/reproos-image/scripts"
  AutoConfigFixture = "tests/fixtures/auto-config-minimal.toml"

  ExpensiveGateEnv = "REPROOS_IMAGE_REPRODUCIBILITY_GATE"
    ## The opt-in for layer 3. Set it to ``1`` to authorise a real
    ## rebuild of the image; anything else reports a visible skip.

  # The artifacts the opt-in build-twice layer compares. Declared here
  # rather than beside that layer because the always-on contract case
  # checks them: the layer cannot be exercised on a machine with no
  # image, so a wrong path here would be discovered as a skip for the
  # wrong reason rather than as a failure.
  RecipeDirRel = "recipes/reproos-image"
  ImageOutputRel = RecipeDirRel / "build/reproos-installed.qcow2"
  DiskInitrdRel = RecipeDirRel / "build/reproos-disk-initramfs.img"
  StagedRootfsRel = "recipes/reproos-iso/build/de-rootfs"
  InstallerRecipe = "apps/reproos-installer/package.nim"
  InstallerBinRel = ".repro/output/install/usr/bin/reproos-installer"
    ## Where the installer's install mirror puts the config emitter the
    ## driver runs first. Kept equal to ``ReproosInstallerBinary`` in
    ## apps/reproos-installer/package.nim, which is what the image recipe
    ## hands the driver in ``REPROOS_INSTALLER_BIN``.

  AbsentRule = "REPROOS_NO_SUCH_DETERMINISM_FLAG"
    ## A token no shipped script carries. Every matcher below is asked
    ## about it, so a matcher that answered "present" to anything would
    ## fail this gate rather than pass it.

  PinnedVars = ["SOURCE_DATE_EPOCH", "LC_ALL", "TZ"]
    ## Variables the RECIPE must assign as bare literals on the action's
    ## command line. A build action inherits every variable it does not
    ## assign, so an action that leaves one of these to the caller builds
    ## a different tree on a differently-configured host.

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
# Manifests: an ordered list of named artifacts, and the first difference
# between two of them. Every layer of this gate compares through here, so
# "which artifact drifted first" has exactly one implementation.
# ---------------------------------------------------------------------------

type
  Artifact = object
    name: string
    bytes: int
    digest: string

  Manifest = seq[Artifact]

  DifferenceKind = enum
    dkNone
    dkDigest        ## same artifact, different bytes
    dkOrder         ## the manifests do not describe the same pipeline
    dkMissing       ## an artifact one run produced and the other did not

  Difference = object
    kind: DifferenceKind
    name: string
    a: Artifact
    b: Artifact

proc sha256Hex(data: string): string =
  toLowerAscii($sha256.digest(data))

proc describe(a: Artifact): string =
  "bytes=" & $a.bytes & " sha256=" & a.digest

proc materialise(m: var Manifest; runDir, name, content: string) =
  ## Write the artifact into the run's clean tree and digest what landed
  ## there, rather than digesting a string that was never written. The
  ## file stays behind so a failing run can be inspected.
  let path = runDir / name.replace('/', '~')
  writeFile(path, content)
  let onDisk = readFile(path)
  m.add Artifact(name: name, bytes: onDisk.len, digest: sha256Hex(onDisk))

proc captureFile(m: var Manifest; name, path: string) =
  if not fileExists(path):
    m.add Artifact(name: name, bytes: -1, digest: "<absent>")
    return
  let content = readFile(path)
  m.add Artifact(name: name, bytes: content.len, digest: sha256Hex(content))

proc firstDifference(a, b: Manifest): Difference =
  ## The EARLIEST artifact that differs. Order matters: the manifests are
  ## built in pipeline order, so the first difference is the first place
  ## the two runs diverged, and everything after it is a consequence.
  let shared = min(a.len, b.len)
  for i in 0 ..< shared:
    if a[i].name != b[i].name:
      return Difference(kind: dkOrder, name: a[i].name, a: a[i], b: b[i])
    if a[i].digest != b[i].digest or a[i].bytes != b[i].bytes:
      return Difference(kind: dkDigest, name: a[i].name, a: a[i], b: b[i])
  if a.len > shared:
    return Difference(kind: dkMissing, name: a[shared].name, a: a[shared])
  if b.len > shared:
    return Difference(kind: dkMissing, name: b[shared].name, b: b[shared])
  Difference(kind: dkNone)

proc report(subject: string; d: Difference; labelA, labelB: string): string =
  ## The operator-facing sentence. It names the artifact first, because
  ## "the images differ" is the one thing an operator already knows.
  case d.kind
  of dkNone:
    subject & ": no difference"
  of dkDigest:
    subject & ": first differing artifact: " & d.name & "\n" &
      "  " & labelA & ": " & describe(d.a) & "\n" &
      "  " & labelB & ": " & describe(d.b) & "\n" &
      "  later artifacts are not compared; the earliest divergence is the one to fix"
  of dkOrder:
    subject & ": the two runs describe different pipelines at the same " &
      "position: " & d.a.name & " vs " & d.b.name
  of dkMissing:
    subject & ": artifact produced by only one run: " & d.name

# ---------------------------------------------------------------------------
# Reading the shipped recipes.
#
# The recipes build their shell command as a Nim seq of string literals
# joined with spaces. Recovering the command means recovering the string
# literals, which means a scanner that knows about Nim comments, character
# literals and backslash escapes -- a naive one picks up prose out of the
# `##` documentation and reports assignments that are not there.
# ---------------------------------------------------------------------------

proc nimStringLiterals(text: string): seq[string] =
  result = @[]
  var i = 0
  while i < text.len:
    let c = text[i]
    if c == '#':
      while i < text.len and text[i] != '\n': i.inc
    elif c == '\'':
      i.inc
      while i < text.len and text[i] != '\'':
        if text[i] == '\\': i.inc
        i.inc
      i.inc
    elif c == '"':
      i.inc
      var literal = ""
      while i < text.len and text[i] != '"':
        if text[i] == '\\' and i + 1 < text.len:
          case text[i + 1]
          of '"': literal.add '"'
          of '\\': literal.add '\\'
          of 'n': literal.add '\n'
          of 't': literal.add '\t'
          else: literal.add text[i + 1]
          i.inc 2
        else:
          literal.add text[i]
          i.inc
      i.inc
      result.add literal
    else:
      i.inc

proc commandBlock(recipeText, anchor: string): string =
  ## The shell command a recipe assembles, recovered from the Nim source
  ## between ``anchor`` and the ``.join(" ")`` that closes it.
  let start = recipeText.find(anchor)
  if start < 0:
    return ""
  let stop = recipeText.find("].join(\" \")", start)
  if stop < 0:
    return ""
  nimStringLiterals(recipeText[start ..< stop]).join(" ")

proc assignmentValue(shellText, name: string): string =
  ## The value of ``name=...`` in a shell command line, or "" when the
  ## command does not assign it. Quoting and ``${...}`` nesting are
  ## honoured so that a value containing spaces is not truncated.
  let needle = name & "="
  var searchFrom = 0
  while true:
    let at = shellText.find(needle, searchFrom)
    if at < 0:
      return ""
    let boundary = at == 0 or shellText[at - 1] in {' ', '\t', '\n', ';'}
    if not boundary:
      searchFrom = at + 1
      continue
    var i = at + needle.len
    var value = ""
    var braces = 0
    var quote = '\0'
    while i < shellText.len:
      let c = shellText[i]
      if quote != '\0':
        value.add c
        if c == quote: quote = '\0'
      elif c == '"' or c == '\'':
        value.add c
        quote = c
      elif c == '{' or c == '(':
        braces.inc
        value.add c
      elif c == '}' or c == ')':
        braces.dec
        value.add c
      elif c in {' ', '\t', '\n', '\\'} and braces == 0:
        break
      else:
        value.add c
      i.inc
    return value

proc unquote(raw: string): string =
  if raw.len >= 2 and raw[0] == '"' and raw[^1] == '"': raw[1 .. ^2]
  elif raw.len >= 2 and raw[0] == '\'' and raw[^1] == '\'': raw[1 .. ^2]
  else: raw

proc braceDefault(raw: string): string =
  ## The ``D`` of ``${NAME:-D}``, or "" when the value is not that shape.
  let open = raw.find(":-")
  if open < 0: return ""
  let close = raw.rfind('}')
  if close <= open: return ""
  raw[open + 2 ..< close]

proc timeVaryingWitness(): string =
  ## What a value that is decided at build time resolves to. The gate
  ## never EXECUTES a command substitution it finds in a recipe -- it
  ## records that the value is decided when the build runs, using a
  ## reading that really does change between two runs, which is precisely
  ## the property that makes the two-run comparison detect it.
  "decided-at-build-time:" & $getMonoTime().ticks & ":" &
    formatFloat(epochTime(), ffDecimal, 6)

proc resolvePinned(name, raw: string): string =
  ## What a pinned variable is worth to THIS build.
  ##
  ##   * a bare literal          -> itself; the same on every host.
  ##   * a command substitution  -> decided when the build runs.
  ##   * anything referencing a variable, or an assignment that is simply
  ##     absent -> inherited from the caller, so it is whatever the
  ##     caller's environment says.
  let value = unquote(raw)
  if raw.len == 0:
    return "inherited-from-caller:" & getEnv(name, "<unset>")
  if value.contains("$(") or value.contains('`') or value.contains("$RANDOM"):
    return timeVaryingWitness()
  if value.contains('$'):
    return "inherited-from-caller:" & getEnv(name, braceDefault(value))
  value

proc resolveKnob(name, raw: string): string =
  ## A declared, overridable knob: its DEFAULT must be a constant, but an
  ## operator may point it somewhere else without that being a defect.
  let value = unquote(raw)
  if raw.len == 0:
    return "<unset>"
  if value.contains("$(") or value.contains('`') or value.contains("$RANDOM"):
    return timeVaryingWitness()
  let fallback = braceDefault(value)
  if fallback.len > 0:
    return fallback
  if value.contains('$'):
    return "<computed>"
  value

# ---------------------------------------------------------------------------
# Producers. Each one materialises exactly one named artifact.
# ---------------------------------------------------------------------------

type
  Enumeration = enum
    enNatural
    enReversed

  ActionEnv = object
    label: string
    recipe: string
    anchor: string
    knobs: seq[string]

const ImageCriticalActions = [
  ActionEnv(label: "reproosIso.stage_rootfs", recipe: IsoRecipe,
            anchor: "let stageRootfsCommand = @[",
            knobs: @["REPRO_LIVE_TARGET"]),
  ActionEnv(label: "reproosIso.build_iso", recipe: IsoRecipe,
            anchor: "proc buildIsoCommand(",
            knobs: @["REPRO_GRUB_VARIANT", "REPRO_LIVE_INIT"]),
  ActionEnv(label: "reproosImage.build_disk_initrd", recipe: ImageRecipe,
            anchor: "let buildDiskInitrdCommand = @[",
            knobs: @["REPRO_INITRAMFS_INIT"]),
  ActionEnv(label: "reproosImage.build_image", recipe: ImageRecipe,
            anchor: "let buildImageCommand = @[",
            knobs: @["REPROOS_DISKO_IDENTITY"]),
]

proc readSource(root, rel: string): string =
  let path = root / rel
  if not fileExists(path):
    fail("source file missing: " & rel & " (under " & root & ")")
    return ""
  readFile(path)

proc actionEnvironment(root: string; action: ActionEnv): string =
  let shellText = commandBlock(readSource(root, action.recipe), action.anchor)
  if shellText.len == 0:
    return "action " & action.label & "\n<command block not found>\n"
  var lines = @["action " & action.label]
  for name in PinnedVars:
    lines.add name & "=" & resolvePinned(name, assignmentValue(shellText, name))
  for name in action.knobs:
    lines.add name & "?=" & resolveKnob(name, assignmentValue(shellText, name))
  lines.join("\n") & "\n"

proc listFiles(dir: string; order: Enumeration): seq[string] =
  ## The raw enumeration order of a directory, optionally reversed. Two
  ## hosts do not agree on it; a producer whose output depends on it is
  ## not reproducible, and reversing is how this gate finds that out.
  result = @[]
  for kind, path in walkDir(dir):
    if kind == pcFile or kind == pcLinkToFile:
      result.add path
  if order == enReversed:
    result.reverse()

proc stagedScriptsArtifact(root: string; order: Enumeration): string =
  ## Every script the image driver installs into the built image, with
  ## its mode and its digest. Content AND mode, because a script that
  ## arrives non-executable changes the image just as surely as one whose
  ## bytes changed.
  let dir = root / ImageScriptsDir
  if not dirExists(dir):
    fail("the image recipe's script directory is missing: " & ImageScriptsDir)
    return ""
  var entries: seq[string] = @[]
  for path in listFiles(dir, order):
    let content = readFile(path)
    var mode = 0
    for permission in getFilePermissions(path):
      mode = mode or (1 shl ord(permission))
    entries.add extractFilename(path) & " " & toOct(mode, 4) & " " &
      sha256Hex(content)
  sort(entries)
  entries.join("\n") & "\n"

proc diskoArtifact(root, presetName: string; diskSizeGb: int): string =
  let configText = readSource(root, AutoConfigFixture)
  if configText.len == 0:
    return ""
  var request = parseDiskLayoutRequest(configText, "reproos-image", "/dev/nbd0")
  request.name = presetName
  if request.params.diskSizeGb < diskSizeGb:
    request.params.diskSizeGb = diskSizeGb
  renderDiskoJson(request.name, request.params)

proc declaredInputsArtifact(root: string): string =
  ## The declared inputs and outputs of the image build action, in the
  ## order the recipe lists them. They are the action's fingerprint
  ## surface: what the engine watches to decide the image is stale.
  let recipe = readSource(root, ImageRecipe)
  let start = recipe.find("let buildImageAction = shell(")
  if start < 0:
    return "<image build action not found>\n"
  let stop = recipe.find("cacheable = false)", start)
  if stop < 0:
    return "<image build action not closed>\n"
  var lines: seq[string] = @[]
  for literal in nimStringLiterals(recipe[start ..< stop]):
    if literal.contains('/') or literal.endsWith(".sh") or
       literal.endsWith(".qcow2"):
      lines.add literal
  lines.join("\n") & "\n"

proc toolIdentitiesArtifact(root: string): string =
  ## The tool identities the image action declares. Under a hermetic
  ## PATH this list IS the set of binaries the build can reach, so a
  ## change to it is a change to what the image is built with.
  let recipe = readSource(root, ImageRecipe)
  let start = recipe.find("const reproosImageRuntimeTools = @[")
  if start < 0:
    return "<runtime tool list not found>\n"
  let stop = recipe.find(']', start)
  if stop < 0:
    return "<runtime tool list not closed>\n"
  var names = nimStringLiterals(recipe[start .. stop])
  sort(names)
  names.join("\n") & "\n"

proc packageSetArtifact(): string =
  ## The source package closure, IN DECLARATION ORDER: the recipe hands it
  ## to the driver as an ordered, space-separated list, so a reordering is
  ## a change to the staging order and therefore to the image.
  ReproosGraphicalRootfsPackages.join("\n") & "\n"

proc buildInputManifest(root, runDir: string; order: Enumeration): Manifest =
  ## The whole cheap layer, in pipeline order: what the image is built
  ## FROM, before anything is built.
  createDir(runDir)
  result = @[]
  for action in ImageCriticalActions:
    result.materialise(runDir, "env/" & action.label,
                       actionEnvironment(root, action))
  result.materialise(runDir, "disko-uefi-ext4.json",
                     diskoArtifact(root, "uefi-ext4", 8))
  result.materialise(runDir, "disko-uefi-attested.json",
                     diskoArtifact(root, "uefi-attested", 16))
  result.materialise(runDir, "image-source-package-set",
                     packageSetArtifact())
  result.materialise(runDir, "image-action-tool-identities",
                     toolIdentitiesArtifact(root))
  result.materialise(runDir, "image-action-declared-inputs",
                     declaredInputsArtifact(root))
  result.materialise(runDir, "image-staged-scripts",
                     stagedScriptsArtifact(root, order))

# ---------------------------------------------------------------------------
# The artifact-producer contract: the flags that make each authored
# artifact a function of its inputs, attributed to the artifact.
# ---------------------------------------------------------------------------

type
  ProducerRule = object
    artifact: string
    script: string
    required: seq[string]
    forbidden: seq[string]

const ProducerRules = [
  ProducerRule(
    artifact: "reproos-initramfs.img",
    script: InitramfsBuilder,
    required: @[
      ": \"${SOURCE_DATE_EPOCH:?",
      "find . -print0 | LC_ALL=C sort -z",
      "cpio --null --reproducible",
      "-H newc",
      "gzip -n",
      "touch -h -d \"@$SOURCE_DATE_EPOCH\"",
      "chown -R root:root",
    ],
    forbidden: @[]),
  ProducerRule(
    artifact: "filesystem.squashfs",
    script: IsoBuilder,
    required: @["mksquashfs", "-no-xattrs", "-noappend"],
    forbidden: @["-all-time", "-mkfs-time"]),
  ProducerRule(
    artifact: "reproos.iso",
    script: IsoBuilder,
    required: @[
      ": \"${SOURCE_DATE_EPOCH:?",
      ": \"${LC_ALL:?",
      ": \"${TZ:?",
      "REPRO_GPT_DISK_GUID='",
      "--gpt_disk_guid",
      "REPRO_MODIFICATION_DATE='",
      "--modification-date=",
      "--set_all_file_dates",
      "-volid '",
      "-preparer '",
      "-appid '",
      "REPRO_FAT_SERIAL='",
      "-N 0x$REPRO_FAT_SERIAL",
    ],
    forbidden: @[]),
  ProducerRule(
    artifact: "reproos-installed.qcow2",
    script: ImageDriver,
    required: @[
      ": \"${SOURCE_DATE_EPOCH:?",
      ": \"${LC_ALL:?",
      ": \"${TZ:?",
      # The filesystems inside the image. `repro disk apply` finds the
      # identity document beside the layout document, so the driver has
      # to write it there; without it every filesystem UUID, the ext4
      # directory-hash seed, the FAT volume serial and the GPT GUIDs are
      # taken from the clock and the system RNG.
      ": \"${REPROOS_DISKO_IDENTITY:?",
      ".identity.json",
      # ...and a refusal to run an engine that would ignore it. An older
      # `repro disk apply` reads no identity document and says nothing,
      # which is a build that looks healthy and is not reproducible.
      "REPRO_DISK_USAGE=\"",
      "*--identity*)",
      # And the epoch has to survive sudo, which resets the environment:
      # the ext4 superblock's timestamps come from SOURCE_DATE_EPOCH and
      # no mkfs flag pins them, so an assignment this script merely
      # exports does not reach mkfs.
      "SOURCE_DATE_EPOCH=\"$SOURCE_DATE_EPOCH\"",
    ],
    forbidden: @[]),
]

proc codeOnly(text: string): string =
  ## Full-line comments removed, so that a hazard NAMED in a comment is
  ## not mistaken for a hazard closed in code -- and, in the other
  ## direction, so that a forbidden flag discussed in a comment does not
  ## redden a script that does not use it.
  var lines: seq[string] = @[]
  for line in text.splitLines():
    if line.strip().startsWith("#"): continue
    lines.add line
  lines.join("\n")

proc producerViolations(root: string): seq[string] =
  ## One entry per artifact whose producer is not pinned. The artifact
  ## name leads, because that is what the operator has to go and look at.
  result = @[]
  for rule in ProducerRules:
    let code = codeOnly(readSource(root, rule.script))
    var missing: seq[string] = @[]
    for needle in rule.required:
      if not code.contains(needle): missing.add needle
    var present: seq[string] = @[]
    for needle in rule.forbidden:
      if code.contains(needle): present.add needle
    if code.contains(AbsentRule):
      result.add rule.artifact & ": the rule matcher claims " & AbsentRule &
        " is present in " & rule.script & "; it matches anything"
    if missing.len > 0:
      result.add rule.artifact & " (" & rule.script &
        ") is not pinned: missing " & missing.join(", ")
    if present.len > 0:
      result.add rule.artifact & " (" & rule.script &
        ") carries a hazard: " & present.join(", ")

proc unpinnedActionVariables(root: string): seq[string] =
  ## An action on the image's path that leaves a pinned variable to the
  ## caller. A build action inherits every variable it does not assign,
  ## so this is the difference between "the image is a function of the
  ## tree" and "the image is a function of the tree and whoever ran it".
  result = @[]
  for action in ImageCriticalActions:
    let shellText = commandBlock(readSource(root, action.recipe), action.anchor)
    if shellText.len == 0:
      result.add action.label & ": its command could not be read out of " &
        action.recipe
      continue
    for name in PinnedVars:
      let raw = assignmentValue(shellText, name)
      if raw.len == 0:
        result.add action.label & " does not pin " & name &
          "; the action inherits it from whoever runs the build"
        continue
      let value = unquote(raw)
      if value.contains('$') or value.contains('`'):
        result.add action.label & " pins " & name & " to " & raw &
          ", which is not a constant; it is decided by the caller or at " &
          "build time"

# ---------------------------------------------------------------------------
# Case 1 — the image's inputs are deterministic.
# ---------------------------------------------------------------------------

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

proc compareTwoDerivations(root, workDir, subject: string): Difference =
  ## Derive the input manifest twice into two clean trees. The second
  ## derivation runs under a caller environment and a directory
  ## enumeration order chosen to be as different from the first as this
  ## gate can make them.
  removeDir(workDir)
  createDir(workDir)
  let a = buildInputManifest(root, workDir / "run-a", enNatural)
  var b: Manifest = @[]
  withHostileEnvironment(proc () =
    b = buildInputManifest(root, workDir / "run-b", enReversed))
  firstDifference(a, b)

proc caseInputsAreDeterministic(workRoot: string) =
  let d = compareTwoDerivations(RepoRoot, workRoot / "inputs",
                                "t_image_build_inputs_are_deterministic")
  if d.kind != dkNone:
    fail(report("t_image_build_inputs_are_deterministic", d,
                "first derivation", "second derivation (hostile environment)"))
    return
  pass("t_image_build_inputs_are_deterministic: every input the image is " &
       "built from re-derives identically under a different caller " &
       "environment and the opposite directory enumeration order")

# ---------------------------------------------------------------------------
# Case 2 — the artifact producers are pinned.
# ---------------------------------------------------------------------------

proc caseProducersArePinned() =
  let violations = producerViolations(RepoRoot) & unpinnedActionVariables(RepoRoot)
  if violations.len > 0:
    for v in violations:
      fail("t_image_artifact_producers_are_pinned: " & v)
    return
  pass("t_image_artifact_producers_are_pinned: every authored artifact on " &
       "the image's path pins its timestamps, its entry order and its " &
       "otherwise-random identifiers, and every action pins " &
       PinnedVars.join(", "))

# ---------------------------------------------------------------------------
# Case 2b — every variable the image recipe sets is read by something.
#
# The generalisation of a real defect: the recipe assigned
# `REPRO_QCOW2_SEED` and NOTHING read it -- not the driver, not the
# engine, not the tool that creates the filesystems. It read as a pin
# and was not one, exactly like a `${SOURCE_DATE_EPOCH:-...}` fallback,
# and while it sat there the image's filesystem identifiers were seeded
# from the clock. A variable a recipe sets and nobody reads is worse
# than an absent one, so the class is checked rather than the instance.
# ---------------------------------------------------------------------------

const EnvReadByTheToolsThemselves = [
  # Read by the binaries the driver invokes rather than by any script in
  # this repository, so their absence from the driver text is correct.
  "SOURCE_DATE_EPOCH", "LC_ALL", "LANG", "TZ", "PATH", "LD_LIBRARY_PATH",
  "HOME",
]

proc assignedNames(shellText: string): seq[string] =
  ## Every `NAME=` assignment on a shell command line, ignoring anything
  ## inside single quotes -- the recipe hands whole documents across that
  ## way and their contents are data, not assignments.
  result = @[]
  var i = 0
  var inSingle = false
  while i < shellText.len:
    let c = shellText[i]
    if c == '\'':
      inSingle = not inSingle
      i.inc
      continue
    if inSingle:
      i.inc
      continue
    let boundary = i == 0 or shellText[i - 1] in {' ', '\t', '\n', ';'}
    if boundary and c in {'A' .. 'Z', '_'}:
      var j = i
      while j < shellText.len and
            shellText[j] in {'A' .. 'Z', '0' .. '9', '_'}: j.inc
      if j > i and j < shellText.len and shellText[j] == '=':
        let name = shellText[i ..< j]
        if name notin result: result.add name
        i = j + 1
        continue
    i.inc

proc unreadRecipeVariables(root: string): seq[string] =
  ## Names the image recipe assigns on the build action's command line
  ## that nothing the recipe invokes ever reads.
  result = @[]
  let shellText = commandBlock(readSource(root, ImageRecipe),
                               "let buildImageCommand = @[")
  if shellText.len == 0:
    result.add "the image build action's command could not be read out of " &
      ImageRecipe
    return
  # Comments stripped: a variable NAMED in a comment is not a variable
  # read, and the whole point of this check is that a pin nothing
  # consumes looks exactly like one that something does.
  var readers = codeOnly(readSource(root, ImageDriver))
  let scriptsDir = root / ImageScriptsDir
  if dirExists(scriptsDir):
    for kind, path in walkDir(scriptsDir):
      if kind == pcFile or kind == pcLinkToFile:
        readers.add "\n"
        readers.add codeOnly(readFile(path))
  for name in assignedNames(shellText):
    if name in EnvReadByTheToolsThemselves: continue
    # An expansion or a re-assignment counts as a read; a bare mention
    # does not, and neither does a name that only appears because it is
    # a prefix of a longer one.
    if readers.contains("$" & name) or
       readers.contains("${" & name) or
       readers.contains(name & "="): continue
    result.add name & " is assigned by " & ImageRecipe &
      " and read by nothing it invokes: not " & ImageDriver &
      ", not any script staged from " & ImageScriptsDir &
      ". It reads as a pin and is not one; consume it or delete it."

proc caseRecipeDeclaresNoUnreadVariable() =
  let unread = unreadRecipeVariables(RepoRoot)
  if unread.len > 0:
    for u in unread:
      fail("t_image_recipe_declares_no_unread_seed: " & u)
    return
  pass("t_image_recipe_declares_no_unread_seed: every variable the image " &
       "recipe assigns on the build action's command line is read by the " &
       "driver or by a script the driver stages")

# ---------------------------------------------------------------------------
# Case 3 — the falsifiability gate.
#
# Real perturbations, written into a scratch copy of the real sources, run
# through the SAME pipeline. Each must redden, and each must name the
# artifact it perturbed and no other.
# ---------------------------------------------------------------------------

const ScratchSources = [
  ImageRecipe,
  IsoRecipe,
  ImageDriver,
  InitramfsBuilder,
  IsoBuilder,
  AutoConfigFixture,
]

proc scratchTree(dest: string) =
  removeDir(dest)
  for rel in ScratchSources:
    createDir(dest / rel.parentDir())
    copyFile(RepoRoot / rel, dest / rel)
  createDir(dest / ImageScriptsDir)
  for kind, path in walkDir(RepoRoot / ImageScriptsDir):
    if kind == pcFile or kind == pcLinkToFile:
      copyFile(path, dest / ImageScriptsDir / extractFilename(path))

proc replaceWithin(path, anchor, before, after: string): bool =
  ## Apply a replacement to the FIRST occurrence of ``before`` that falls
  ## after ``anchor``, so an injection aimed at one action does not land
  ## on an identical line belonging to another.
  let text = readFile(path)
  let start = if anchor.len == 0: 0 else: text.find(anchor)
  if start < 0: return false
  let at = text.find(before, start)
  if at < 0: return false
  writeFile(path, text[0 ..< at] & after & text[at + before.len .. ^1])
  true

type
  Injection = object
    name: string
    expect: string          ## the artifact the gate must name
    viaManifest: bool       ## caught by re-derivation, else by the contract
    apply: proc (root: string): bool {.closure.}

proc injections(): seq[Injection] =
  @[
    Injection(
      name: "a wall-clock SOURCE_DATE_EPOCH in the image action",
      expect: "env/reproosImage.build_image",
      viaManifest: true,
      apply: proc (root: string): bool =
        replaceWithin(root / ImageRecipe, "let buildImageCommand = @[",
          "SOURCE_DATE_EPOCH=1735689600",
          "SOURCE_DATE_EPOCH=$(date +%s)")),
    Injection(
      name: "the image action's epoch quietly made inheritable",
      expect: "env/reproosImage.build_image",
      viaManifest: true,
      apply: proc (root: string): bool =
        replaceWithin(root / ImageRecipe, "let buildImageCommand = @[",
          "SOURCE_DATE_EPOCH=1735689600",
          "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1735689600}")),
    Injection(
      # Two artifacts at different positions in the same manifest. The
      # gate has to name the EARLIER one: "first differing artifact" is
      # the whole claim, and a comparator that reported any differing
      # artifact would send an operator to the consequence rather than
      # to the cause. Nothing else here can catch that, because every
      # other injection perturbs exactly one artifact, which is both the
      # first and the last one to differ.
      name: "two actions unpinned at once, the earlier one must be named",
      expect: "env/reproosIso.stage_rootfs",
      viaManifest: true,
      apply: proc (root: string): bool =
        let later = replaceWithin(root / ImageRecipe,
          "let buildImageCommand = @[",
          "SOURCE_DATE_EPOCH=1735689600",
          "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1735689600}")
        let earlier = replaceWithin(root / IsoRecipe,
          "let stageRootfsCommand = @[",
          "SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC",
          "LC_ALL=C TZ=UTC")
        later and earlier),
    Injection(
      name: "the initramfs entry list no longer sorted before cpio",
      expect: "reproos-initramfs.img",
      viaManifest: false,
      apply: proc (root: string): bool =
        replaceWithin(root / InitramfsBuilder, "",
          "find . -print0 | LC_ALL=C sort -z | cpio",
          "find . -print0 | cpio")),
    Injection(
      name: "the ISO's pinned GPT disk GUID dropped",
      expect: "reproos.iso",
      viaManifest: false,
      apply: proc (root: string): bool =
        replaceWithin(root / IsoBuilder, "",
          "  --gpt_disk_guid \"$REPRO_GPT_DISK_GUID\" \\\n", "")),
    Injection(
      # A real defect this tree carried, reproduced under a different
      # name: a variable the recipe sets that reads as a pin and that
      # nothing consumes. It has to be caught as a CLASS, not as the one
      # name it happened to have.
      name: "a variable the recipe sets and nothing reads",
      expect: "REPRO_UNUSED_PIN",
      viaManifest: false,
      apply: proc (root: string): bool =
        replaceWithin(root / ImageRecipe, "let buildImageCommand = @[",
          "\"set -euo pipefail;\",",
          "\"set -euo pipefail;\",\n      \"REPRO_UNUSED_PIN=deadbeefcafebabe\",")),
  ]

proc caseInjectedNondeterminismIsCaught(workRoot: string) =
  let scratch = workRoot / "injection" / "tree"

  # Control. The scratch copy, unperturbed, must be green in BOTH halves
  # -- otherwise the injections below would be proving nothing but that
  # copying a tree breaks the gate.
  scratchTree(scratch)
  let controlDiff = compareTwoDerivations(scratch, workRoot / "injection" / "control",
                                          "control")
  let controlViolations = producerViolations(scratch) &
                          unpinnedActionVariables(scratch) &
                          unreadRecipeVariables(scratch)
  if controlDiff.kind != dkNone or controlViolations.len > 0:
    fail("t_image_reproducibility_gate_detects_injected_nondeterminism: the " &
         "UNPERTURBED scratch copy is not green, so nothing an injection " &
         "proves can be attributed to the injection: " &
         report("control", controlDiff, "run a", "run b") & " " &
         controlViolations.join("; "))
    return
  pass("t_image_reproducibility_gate_detects_injected_nondeterminism: the " &
       "unperturbed scratch copy of the shipped sources is green in both " &
       "halves, so an injection below is the only thing that can redden it")

  for injection in injections():
    scratchTree(scratch)
    if not injection.apply(scratch):
      fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
           "could not inject: " & injection.name &
           " -- the text it perturbs is no longer in the shipped source, so " &
           "this gate is no longer proving anything about it")
      continue

    if injection.viaManifest:
      let d = compareTwoDerivations(scratch,
        workRoot / "injection" / "run", "injected")
      if d.kind == dkNone:
        fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
             injection.name & " did NOT redden the gate")
        continue
      if d.name != injection.expect:
        fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
             injection.name & " reddened the gate, but the first differing " &
             "artifact it named was " & d.name & " rather than " &
             injection.expect & "; a gate that cannot say WHICH artifact " &
             "drifted is worth little more than one that says the images differ")
        continue
      # And only that artifact: everything before it compared equal, which
      # is what "first differing artifact" means.
      pass("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
           injection.name & " -> the gate fails and names " & d.name &
           " (" & describe(d.a) & " vs " & describe(d.b) & ")")
    else:
      let violations = producerViolations(scratch) &
                       unpinnedActionVariables(scratch) &
                       unreadRecipeVariables(scratch)
      if violations.len == 0:
        fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
             injection.name & " did NOT redden the gate")
        continue
      var named: seq[string] = @[]
      for v in violations:
        if v.startsWith(injection.expect): named.add v
      if named.len == 0:
        fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
             injection.name & " reddened the gate, but no violation named " &
             injection.expect & "; the violations were: " & violations.join("; "))
        continue
      if named.len != violations.len:
        fail("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
             injection.name & " reddened artifacts it did not perturb: " &
             violations.join("; "))
        continue
      pass("t_image_reproducibility_gate_detects_injected_nondeterminism: " &
           injection.name & " -> the gate fails and names " & injection.expect &
           ": " & named[0])

# ---------------------------------------------------------------------------
# Case 4 — the ISO and image gates are one contract.
#
# Two reproducibility gates that pin different epochs, or compare
# different artifact sets, are two gates that will disagree about what
# reproducible means. This case is what keeps them from drifting apart.
# ---------------------------------------------------------------------------

proc caseGatesShareOneContract() =
  let wrapper = readSource(RepoRoot, IsoGateWrapper)
  let workflows = readSource(RepoRoot, WorkflowRecipe)
  if wrapper.len == 0 or workflows.len == 0: return

  var problems: seq[string] = @[]

  let isoShell = commandBlock(readSource(RepoRoot, IsoRecipe),
                              "proc buildIsoCommand(")
  for name in PinnedVars:
    let inRecipe = unquote(assignmentValue(isoShell, name))
    let inWrapper = unquote(assignmentValue(wrapper, name))
    if inRecipe.len == 0 or inWrapper.len == 0:
      problems.add "the ISO recipe and the ISO reproducibility gate do not " &
        "both pin " & name
    elif inRecipe != inWrapper:
      problems.add "the ISO recipe pins " & name & "=" & inRecipe &
        " but the ISO reproducibility gate rebuilds with " & name & "=" &
        inWrapper & "; the rebuild is then not a repeat of the build"

  # The ISO gate must compare the initramfs BEFORE the ISO, so that it
  # names which one drifted rather than only that the media differ.
  for needle in ["reproos-initramfs.img", "reproos.iso",
                 "first differing artifact"]:
    if not wrapper.contains(needle):
      problems.add "the ISO reproducibility gate does not compare " &
        needle & "; it cannot name the first differing artifact"
  let initramfsAt = wrapper.find("ARTIFACTS=(")
  if initramfsAt >= 0:
    let order = wrapper[initramfsAt .. ^1]
    if order.find("reproos-initramfs.img") > order.find("reproos.iso"):
      problems.add "the ISO reproducibility gate compares the ISO before " &
        "the initramfs it contains, so the artifact it names first is a " &
        "consequence rather than a cause"

  # The opt-in layer cannot be exercised on a machine with no image, so
  # the paths it would use are checked here instead of being discovered
  # to be wrong the first time somebody runs it.
  let installerRecipe = readSource(RepoRoot, InstallerRecipe)
  if not installerRecipe.contains("\"" & InstallerBinRel & "\""):
    problems.add "the build-twice layer looks for the installer at " &
      InstallerBinRel & ", which is not what apps/reproos-installer/" &
      "package.nim declares; that layer would skip for the wrong reason"

  for target in ["test-iso-reproducibility", "test-image-reproducibility"]:
    if not workflows.contains("target(\"" & target & "\""):
      problems.add target & " is not a registered target"
  for binding in ["testIsoReproducibility", "testImageReproducibility"]:
    let collect = workflows.find("collect(\"test\"")
    if collect < 0 or not workflows[collect .. ^1].contains(binding):
      problems.add binding & " is not in the `test` collection, so it does " &
        "not run with the suite"

  if problems.len > 0:
    for p in problems:
      fail("t_iso_and_image_reproducibility_gates_share_one_contract: " & p)
    return
  pass("t_iso_and_image_reproducibility_gates_share_one_contract: both " &
       "gates are registered, both are in the `test` collection, both pin " &
       "the same " & PinnedVars.join("/") & ", and the ISO gate compares " &
       "the initramfs before the ISO so it names the earliest divergence")

# ---------------------------------------------------------------------------
# Case 5 — two builds, identical bytes. The expensive layer.
# ---------------------------------------------------------------------------

proc snapshotBuildArtifacts(m: var Manifest; recipeDir: string) =
  ## The image build's own intermediates, in the order the driver writes
  ## them, so the first difference points at the earliest phase that
  ## drifted rather than at the qcow2 that carries every earlier drift.
  m.captureFile("disko.json", recipeDir / "build/work/disko.json")
  let bundle = recipeDir / "build/work/configuration"
  var bundleFiles: seq[string] = @[]
  if dirExists(bundle):
    for kind, path in walkDir(bundle):
      if kind == pcFile: bundleFiles.add path
  sort(bundleFiles)
  for path in bundleFiles:
    m.captureFile("configuration/" & extractFilename(path), path)

proc expensiveSkipRemedy(reason: string): string =
  reason & "\n" &
  "  To run it: build the image, then re-run this gate with " &
  ExpensiveGateEnv & "=1.\n" &
  "  It rebuilds the image into a clean work tree and compares an ordered\n" &
  "  manifest (disko document, emitted configuration bundle, qcow2) against\n" &
  "  the build already on disk, naming the FIRST artifact that differs.\n" &
  "  It is not run by default because an image build takes hours, needs\n" &
  "  sudo and loads the nbd module."

proc caseImageBuildsTwiceIdentically(workRoot: string) =
  if getEnv(ExpensiveGateEnv) != "1":
    skip("t_reproos_image_reproducibility: not requested (" &
         ExpensiveGateEnv & " is not 1).\n" &
         expensiveSkipRemedy("  This gate has NOT compared any image bytes."))
    return

  let recipeDir = RepoRoot / RecipeDirRel
  let baseline = RepoRoot / ImageOutputRel
  for required in [baseline, RepoRoot / DiskInitrdRel,
                   RepoRoot / InstallerBinRel]:
    if not fileExists(required):
      skip("t_reproos_image_reproducibility: requested, but a required " &
           "artifact is absent: " & required & "\n" &
           expensiveSkipRemedy("  Nothing was compared."))
      return
  if not dirExists(RepoRoot / StagedRootfsRel):
    skip("t_reproos_image_reproducibility: requested, but the staged rootfs " &
         "is absent: " & (RepoRoot / StagedRootfsRel) & "\n" &
         expensiveSkipRemedy("  Nothing was compared."))
    return

  var runA: Manifest = @[]
  snapshotBuildArtifacts(runA, recipeDir)
  runA.captureFile("reproos-installed.qcow2", baseline)

  # A clean tree for the second build: the driver reuses build/work, and a
  # build that reuses a dirty tree can be accidentally reproducible.
  removeDir(recipeDir / "build/work")
  let rebuildDir = workRoot / "image-rebuild"
  createDir(rebuildDir)
  let rebuilt = rebuildDir / "reproos-installed.qcow2"

  let imageShell = commandBlock(readSource(RepoRoot, ImageRecipe),
                                "let buildImageCommand = @[")
  let epoch = unquote(assignmentValue(imageShell, "SOURCE_DATE_EPOCH"))
  let locale = unquote(assignmentValue(imageShell, "LC_ALL"))
  let zone = unquote(assignmentValue(imageShell, "TZ"))
  let identity = resolveKnob("REPROOS_DISKO_IDENTITY",
                             assignmentValue(imageShell, "REPROOS_DISKO_IDENTITY"))

  let configText = readSource(RepoRoot, AutoConfigFixture)
  let request = parseDiskLayoutRequest(configText, "reproos-image", "/dev/nbd0")
  let diskoSpec = renderDiskoJson(request.name, request.params)
    .replace("\n", "\\n")

  let command =
    "cd " & quoteShell(recipeDir) & " && " &
    "SOURCE_DATE_EPOCH=" & quoteShell(epoch) & " " &
    "LC_ALL=" & quoteShell(locale) & " TZ=" & quoteShell(zone) & " " &
    "REPROOS_DISKO_IDENTITY=" & quoteShell(identity) & " " &
    "REPRO_AUTO_CONFIG=" & quoteShell(RepoRoot / AutoConfigFixture) & " " &
    "REPROOS_INSTALLER_BIN=" & quoteShell(RepoRoot / InstallerBinRel) & " " &
    "REPROOS_STAGED_ROOTFS=" & quoteShell(RepoRoot / StagedRootfsRel) & " " &
    "REPROOS_DISK_INITRD=" & quoteShell(RepoRoot / DiskInitrdRel) & " " &
    "REPROOS_DISK_LAYOUT=" & quoteShell(request.name) & " " &
    "REPROOS_DISK_LAYOUT_ESP_MIB=" & quoteShell($request.params.espSizeMib) & " " &
    "REPROOS_DISKO_SPEC=" & quoteShell(diskoSpec) & " " &
    "bash scripts/build-reproos-image.sh " & quoteShell(rebuilt)

  echo "t_reproos_image_reproducibility: rebuilding the image (this takes hours)"
  let rebuild = execCmdEx(command)
  if rebuild.exitCode != 0:
    stderr.writeLine(rebuild.output)
    fail("t_reproos_image_reproducibility: the rebuild failed with exit " &
         $rebuild.exitCode & "; no byte comparison was made")
    return

  var runB: Manifest = @[]
  snapshotBuildArtifacts(runB, recipeDir)
  runB.captureFile("reproos-installed.qcow2", rebuilt)

  let d = firstDifference(runA, runB)
  if d.kind != dkNone:
    fail(report("t_reproos_image_reproducibility", d,
                "the build already on disk", "the rebuild into a clean tree"))
    return
  pass("t_reproos_image_reproducibility: the rebuild is byte-identical " &
       "across every compared artifact, ending with the qcow2 (" &
       describe(runA[^1]) & ")")

# ---------------------------------------------------------------------------

let workRoot = RepoRoot / "build" / "test-image-reproducibility" / "work"
removeDir(workRoot)
createDir(workRoot)

caseInputsAreDeterministic(workRoot)
caseProducersArePinned()
caseRecipeDeclaresNoUnreadVariable()
caseInjectedNondeterminismIsCaught(workRoot)
caseGatesShareOneContract()
caseImageBuildsTwiceIdentically(workRoot)

if failures > 0:
  stderr.writeLine("test_reproos_image_reproducibility: " & $failures &
                   " check(s) failed")
  quit(1)

# The summary line has to carry the skip count. A reader who greps for
# PASS must not be able to come away believing an image was compared
# when the only layer that compares one was skipped.
var summary = "image reproducibility: PASS (" & $passes & " checks"
if skips > 0:
  summary.add ", " & $skips & " SKIPPED -- no image bytes were compared"
summary.add ")"
echo summary
