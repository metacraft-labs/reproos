## The guest inode policy inside the integrity-checked root image.
##
## ## The defect this gate exists for
##
## `mkfs.ext4 -d` copies the staging tree's ownership and modes. The
## staging runs unprivileged -- it has to, because a root-owned tree under
## `build/` is one the engine can neither replace nor clean -- so every
## inode in the root image was the building user's. Measured on this
## workstation before the fix: `/etc/shadow` landed at `0640 1007:100`,
## and the from-source `/usr/bin/sudo` artifact at `0755` with NO setuid
## bit.
##
## That image boots, and it verifies against its own root hash, and it
## offers no privilege escalation at all -- `sudo` cannot raise, and
## `/etc/shadow` is readable by whoever happens to hold uid 1007 in the
## guest. Every check the project had called it healthy, because every
## check was about the hash and not about what the hash covered.
##
## The writable-root layout does not have the problem: it applies
## `tools/reproos_image_metadata.py apply` to its mounted root once the
## install is finished. The integrity-checked layout has no such moment --
## by then its root is a finished image whose bytes a measured command
## line names -- and `apply` needs uid 0 in any case.
##
## ## What was done instead, and why it is the ISO's answer
##
## The ISO has never had this problem. `mksquashfs -pf` takes ownership
## and modes as a DOCUMENT, applies them as the image is made, and chowns
## nothing. `mke2fs` has no pseudo-file, so the same document is applied
## to the finished ext4 image with `debugfs`, which rewrites inode fields
## in a file the build already owns. Unprivileged, and deterministic:
## `debugfs` writes exact fields and stamps no time.
##
## The important part is that this is not a second policy.
## `tools/reproos_image_metadata.py` has one `metadata()`, and the
## SquashFS pseudo-file, the container tar, the mounted-root `apply` and
## now the ext4 image are four carriers of it.
##
## ## The layers
##
## Layer 1 (always on, ~2s, `python3` and nothing else) reads the shipped
## builder, the shipped ISO script and the shipped recipe, and drives the
## shipped policy's SquashFS renderer over a purpose-built root. It
## PROVES NOTHING about an ext4 image.
##
## Layer 2 (opt-in, `REPROOS_ATTESTED_ROOT_METADATA_GATE=1`, ~1 min, needs
## `mkfs.ext4`, `debugfs`, `sudo` and a loop mount) runs the SHIPPED
## `build-verity-root.sh` over a purpose-built root and then reads the
## result back THROUGH THE KERNEL: the image is loop-mounted read-only and
## every assertion is made against what Linux's own ext4 driver reports.
## Nothing in the verification path is shared with the write path --
## `debugfs` writes the inodes, the kernel reads them.

import std/[algorithm, os, osproc, strutils, tables]

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  PolicyTool = "tools/reproos_image_metadata.py"
  VerityBuilder = "recipes/reproos-image/scripts/build-verity-root.sh"
  IsoBuilder = "recipes/reproos-iso/scripts/build-iso.sh"
  ImageRecipe = "recipes/reproos-image/package.nim"

  GateEnv = "REPROOS_ATTESTED_ROOT_METADATA_GATE"
  KeepEnv = "REPROOS_ATTESTED_ROOT_METADATA_KEEP"

  Layer2Tools = ["mkfs.ext4", "debugfs", "veritysetup", "python3", "sudo",
                 "mount", "umount", "stat", "find", "awk", "sha256sum"]

  # The two inodes the defect was measured on, and what the policy says
  # about them. Named here so the gate reads as the claim it makes.
  ShadowPath = "etc/shadow"
  ShadowMode = 0o640
  SudoPath = "usr/bin/sudo"
  SudoMode = 0o4755

  # The one-character change layer 1 and layer 2 both make to a COPY of
  # the policy. `metadata()` is the only place the setuid mode is
  # decided, so a carrier that does not move with it is reading something
  # else.
  SudoModeSource = "mode = 0o4755"
  SudoModeMutated = "mode = 0o4711"
  MutatedSudoMode = 0o4711

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
    fail("missing shipped file: " & rel)
    return ""
  readFile(path)

proc run(cmd: string): tuple[output: string, exitCode: int] =
  execCmdEx(cmd)

proc sh(cmd: string): bool =
  let r = run(cmd & " 2>&1")
  if r.exitCode != 0:
    stderr.writeLine("    $ " & cmd)
    stderr.writeLine(r.output.strip())
  r.exitCode == 0

# ---------------------------------------------------------------------
# Reading shipped sources for INVOCATIONS and ARGUMENTS, never mentions.
# ---------------------------------------------------------------------

proc withoutShellComments(text: string): string =
  ## Drop whole-line `#` comments and fold backslash continuations into
  ## the line they continue.
  ##
  ## Both halves matter. A comment naming a command is not the command --
  ## six checks in this area were defeated by exactly that. And a shell
  ## invocation is a LOGICAL line: the ISO's call to the policy puts the
  ## interpreter on one physical line and the operation on the next, so a
  ## line-at-a-time matcher would report it missing.
  var kept: seq[string] = @[]
  var pending = ""
  for line in text.splitLines():
    if pending.len == 0 and line.strip().startsWith("#"): continue
    if line.endsWith("\\"):
      pending.add line[0 ..< line.high] & " "
      continue
    kept.add pending & line
    pending = ""
  if pending.len > 0: kept.add pending
  kept.join("\n")

proc codeLines(text: string): seq[string] =
  ## The script's CODE: continuations folded, whole-line comments gone,
  ## and every TRAILING comment cut off too.
  ##
  ## The trailing half is not pedantry. Dropping only whole-line comments
  ## leaves `for tool in a b c; do # debugfs` satisfying a check that
  ## asks whether `debugfs` is in the tool list, and leaves a comment
  ## naming the repository-root policy satisfying a check that asks
  ## whether the script resolves it. Both were reachable in one line.
  result = @[]
  for line in withoutShellComments(text).splitLines():
    let hash = line.find('#')
    let code = if hash >= 0: line[0 ..< hash] else: line
    if code.strip().len > 0: result.add code

proc assignedValue(text, name: string): string =
  ## The right-hand side of ``name=…`` in CODE, unquoted, or "". Read as
  ## an ASSIGNMENT, because what the script resolves is what it assigns
  ## and not what a comment beside it says.
  for line in codeLines(text):
    let bare = line.strip()
    if bare.startsWith(name & "="):
      return bare[name.len + 1 .. ^1].strip().strip(chars = {'"', '\''})
  ""

proc refusesOnFailure(text, operation: string): bool =
  ## True when the invocation of ``operation`` is the CONDITION of an
  ## `if !` whose own body exits.
  ##
  ## Scoped to that construct on purpose. A scan that merely looks for
  ## the next `exit` after the invocation is satisfied by an `exit`
  ## belonging to some LATER construct -- `veritysetup format`'s `exit
  ## 69` sits a few lines below -- so turning this refusal into a warning
  ## would not be visible to it.
  var inside = false
  for line in codeLines(text):
    let bare = line.strip()
    if not inside:
      if bare.startsWith("if ! ") and "$INODE_POLICY" in bare and
         operation in bare and bare.endsWith("; then"):
        inside = true
      continue
    if bare == "fi": return false
    if bare.startsWith("exit "): return true
  false

proc invocationOffset(text, interpreter, script: string;
                      argument = ""): int =
  ## The byte offset of a line that RUNS ``script`` through
  ## ``interpreter`` with ``argument`` on it, or -1. Comments are gone
  ## before the search, and the line has to carry all three, so neither a
  ## header comment nor a variable that merely holds the path satisfies
  ## it.
  var at = 0
  for line in text.splitLines():
    let bare = line.strip()
    if not bare.startsWith("#") and
       interpreter in bare and script in bare and
       (argument.len == 0 or argument in bare):
      return at
    at += line.len + 1
  -1

proc nimListArg(text, callSite, argName: string): string =
  ## The text of ``argName = @[ ... ]`` inside the call that begins at
  ## ``callSite``, comments stripped. Read as an ARGUMENT of that call, so
  ## a list somewhere else in the file cannot satisfy it.
  let start = text.find(callSite)
  if start < 0: return ""
  # The call ends at the next line that starts a new top-level statement
  # at the same indentation; `discard target(` reliably follows every
  # registered action in this recipe.
  var stop = text.find("discard target(", start)
  if stop < 0: stop = text.len
  var body = text[start ..< stop]
  var kept: seq[string] = @[]
  for line in body.splitLines():
    let hash = line.find('#')
    kept.add(if hash >= 0: line[0 ..< hash] else: line)
  body = kept.join("\n")
  let head = body.find(argName & " = @[")
  if head < 0: return ""
  let open = body.find('[', head)
  var depth = 0
  for i in open ..< body.len:
    if body[i] == '[': depth.inc
    elif body[i] == ']':
      depth.dec
      if depth == 0: return body[open + 1 ..< i]
  ""

# ---------------------------------------------------------------------
# The purpose-built root, and the policy's own renderers over it.
# ---------------------------------------------------------------------

proc buildPolicyFixture(dir: string) =
  ## A root with the shape the policy describes and DELIBERATELY WRONG
  ## metadata: `/usr/bin/sudo` without its setuid bit, `/etc/shadow`
  ## group-readable, `/usr/bin` world-writable, everything owned by
  ## whoever is running this gate. If the policy does not run, none of
  ## those becomes the policy's answer by accident.
  ##
  ## A fixture, not a mock: the code under test is the shipped
  ## `build-verity-root.sh`, the shipped policy and the real `mkfs.ext4`.
  removeDir(dir)
  for d in ["etc", "usr/bin", "usr/share", "usr/lib", "home/repro/.config",
            "var/empty", "var/lib", "root"]:
    createDir(dir / d)
  writeFile(dir / "etc/passwd",
    "root:x:0:0::/root:/bin/sh\n" &
    "repro:x:1000:100::/home/repro:/bin/sh\n")
  writeFile(dir / "etc/shadow", "repro:!:20000::::::\n")
  setFilePermissions(dir / "etc/shadow",
    {fpUserRead, fpUserWrite, fpGroupRead})
  writeFile(dir / "usr/bin/sudo", "#!/bin/sh\necho sudo-placeholder\n")
  setFilePermissions(dir / "usr/bin/sudo",
    {fpUserRead, fpUserWrite, fpUserExec,
     fpGroupRead, fpGroupExec, fpOthersRead, fpOthersExec})
  writeFile(dir / "etc/sudoers", "root ALL=(ALL) ALL\n")
  setFilePermissions(dir / "etc/sudoers",
    {fpUserRead, fpUserWrite, fpGroupRead, fpGroupWrite})
  writeFile(dir / "etc/sudo.conf", "Plugin sudoers_policy sudoers.so\n")
  setFilePermissions(dir / "etc/sudo.conf",
    {fpUserRead, fpUserWrite, fpGroupRead, fpGroupWrite,
     fpOthersRead, fpOthersWrite})
  # World-writable on purpose: /usr/bin is a trusted directory and the
  # policy has to take those bits off.
  setFilePermissions(dir / "usr/bin",
    {fpUserRead, fpUserWrite, fpUserExec, fpGroupRead, fpGroupWrite,
     fpGroupExec, fpOthersRead, fpOthersWrite, fpOthersExec})
  writeFile(dir / "etc/os-release", "NAME=reproos-metadata-fixture\n")
  writeFile(dir / "home/repro/.config/keep", "user-owned\n")
  writeFile(dir / "usr/share/data with spaces", "quoting is not metadata\n")
  createSymlink("../../etc/passwd", dir / "usr/share/relative-link")
  createSymlink("/etc/passwd", dir / "usr/share/absolute-link")
  # Enough bytes that the Merkle tree has more than one level.
  for i in 0 ..< 8:
    var blob = newStringOfCap(256 * 1024)
    for j in 0 ..< 256 * 1024:
      blob.add chr((i * 37 + j * 11) and 0xff)
    writeFile(dir / "var/lib" / ("blob-" & $i & ".bin"), blob)

type PolicyRecord = tuple[mode: int, uid: int, gid: int]

proc renderPseudoFile(policyTool, tree, output: string): bool =
  ## The ISO's OWN document, produced by the shipped renderer.
  sh(findExe("python3") & " " & quoteShell(policyTool) & " squashfs " &
     quoteShell(tree) & " --output " & quoteShell(output))

proc parsePseudoFile(path: string): Table[string, PolicyRecord] =
  ## `mksquashfs -pf` records: `"name" m <mode> <uid> <gid>`.
  result = initTable[string, PolicyRecord]()
  for line in readFile(path).splitLines():
    if line.len == 0 or line[0] != '"': continue
    let close = line.rfind('"')
    if close <= 0: continue
    let name = line[1 ..< close].replace("\\\"", "\"").replace("\\\\", "\\")
    let fields = line[close + 1 .. ^1].strip().splitWhitespace()
    if fields.len != 4 or fields[0] != "m": continue
    result[name] = (parseOctInt(fields[1]), parseInt(fields[2]),
                    parseInt(fields[3]))

proc mutatedPolicy(work: string): string =
  ## A copy of the shipped policy with the ONE line that decides the
  ## setuid mode changed, and nothing else.
  let source = readSource(PolicyTool)
  if source.len == 0: return ""
  if source.count(SudoModeSource) != 1:
    fail("t_iso_and_image_apply_one_policy: " & PolicyTool & " does not " &
         "contain exactly one `" & SudoModeSource & "`, so the mutation " &
         "this gate relies on is no longer the single decision it was")
    return ""
  let path = work / "mutated-policy.py"
  writeFile(path, source.replace(SudoModeSource, SudoModeMutated))
  path

# =====================================================================
# Layer 1 -- always on. Shipped sources and the shipped SquashFS
# renderer. No ext4 image is made and nothing is mounted.
# =====================================================================

proc caseTheBuilderRefusesAnUnpolicedImage() =
  ## t_unpoliced_tree_is_refused, structural half.
  let builder = readSource(VerityBuilder)
  if builder.len == 0: return
  let bare = withoutShellComments(builder)

  let mkfsAt = bare.find("mkfs.ext4 -q -F")
  let applyAt = invocationOffset(bare, "python3", "$INODE_POLICY",
                                 "ext4-apply")
  let verifyAt = invocationOffset(bare, "python3", "$INODE_POLICY",
                                  "ext4-verify")
  let formatAt = bare.find("veritysetup format")

  if applyAt < 0:
    fail("t_unpoliced_tree_is_refused: " & VerityBuilder & " never RUNS " &
         "the guest inode policy over the image it makes (looked for a " &
         "line that runs python3 on $INODE_POLICY with ext4-apply, not " &
         "for a mention of the name)")
    return
  if verifyAt < 0:
    fail("t_unpoliced_tree_is_refused: " & VerityBuilder & " applies the " &
         "guest inode policy but never re-reads it out of the image. A " &
         "carrier that does not check its own work is how an image gets " &
         "hashed without the policy in it")
    return
  if mkfsAt < 0 or formatAt < 0:
    fail("t_unpoliced_tree_is_refused: could not locate the mkfs.ext4 " &
         "and veritysetup format calls in " & VerityBuilder)
    return
  if not (mkfsAt < applyAt and applyAt < verifyAt and verifyAt < formatAt):
    fail("t_unpoliced_tree_is_refused: the order in " & VerityBuilder &
         " is wrong (mkfs at " & $mkfsAt & ", apply at " & $applyAt &
         ", verify at " & $verifyAt & ", veritysetup format at " &
         $formatAt & "). The policy has to be in the image BEFORE a root " &
         "hash is taken over it, because after that nothing may write to " &
         "those bytes again")
    return
  pass("t_unpoliced_tree_is_refused: " & VerityBuilder & " applies the " &
       "guest inode policy to the image and then re-reads it out again, " &
       "and both happen after mkfs.ext4 (" & $mkfsAt & ") and before " &
       "veritysetup format (" & $formatAt & ")")

  # Both steps have to be REFUSALS: a failure must stop the script rather
  # than be reported and walked past. Read as each invocation's OWN
  # construct, so an `exit` that belongs to a later one cannot stand in.
  var permissive: seq[string] = @[]
  for operation in ["ext4-apply", "ext4-verify"]:
    if not refusesOnFailure(builder, operation):
      permissive.add operation
  if permissive.len > 0:
    fail("t_unpoliced_tree_is_refused: " & permissive.join(" and ") &
         " in " & VerityBuilder & " does not exit when it fails -- it is " &
         "reported and walked past, so an image that does not carry the " &
         "policy would still reach the hash. Read as the invocation's OWN " &
         "if/fi, not as `some exit appears further down'")
  else:
    pass("t_unpoliced_tree_is_refused: a failing ext4-apply and a failing " &
         "ext4-verify each exit from their own construct rather than " &
         "warning, so an unpoliced image cannot be hashed")

  # `debugfs` and `python3` are what the two new steps need. A build
  # action whose PATH lacks them must fail loudly at the top of the
  # script rather than at the step. Read as WORDS of the loop's list: a
  # trailing comment naming a tool is not a tool the script requires.
  var required: seq[string] = @[]
  for line in codeLines(builder):
    let loop = line.strip()
    if loop.startsWith("for tool in ") and loop.endsWith("; do"):
      required = loop["for tool in ".len ..< loop.len - "; do".len]
        .splitWhitespace()
      break
  var undeclared: seq[string] = @[]
  for tool in ["debugfs", "python3"]:
    if tool notin required: undeclared.add tool
  if undeclared.len > 0:
    fail("t_unpoliced_tree_is_refused: " & VerityBuilder & " does not " &
         "require " & undeclared.join(" or ") & " in its tool check, so a " &
         "PATH without them fails at the policy step instead of at the " &
         "top. The list it does require is: " & required.join(" "))
  else:
    pass("t_unpoliced_tree_is_refused: debugfs and python3 are WORDS of " &
         "the builder's required-tool list, so a PATH without them is a " &
         "loud failure and never a silently skipped policy")

proc caseThePolicyIsAnInputOfTheHash() =
  ## The recipe has to declare the policy as an input of the verity
  ## action: the policy is inside the image the root hash names, so a
  ## change to it changes that hash.
  let recipe = readSource(ImageRecipe)
  if recipe.len == 0: return
  let inputs = nimListArg(recipe, "let buildVerityRootAction = shell(",
                          "extraInputs")
  if inputs.len == 0:
    fail("t_unpoliced_tree_is_refused: could not read the extraInputs " &
         "argument of the verity action in " & ImageRecipe)
    return
  if ("\"" & PolicyTool & "\"") notin inputs:
    fail("t_unpoliced_tree_is_refused: the verity action does not declare " &
         PolicyTool & " as an input, so a change to the guest inode " &
         "policy would not change the root hash it is inside of. Read " &
         "out of the extraInputs ARGUMENT, not out of the file: " &
         inputs.strip())
    return
  pass("t_unpoliced_tree_is_refused: " & ImageRecipe & " declares " &
       PolicyTool & " in the extraInputs ARGUMENT of the verity action, " &
       "so the policy is an input of the root hash exactly as the tree is")

proc caseOnePolicyForBothCarriers() =
  ## t_iso_and_image_apply_one_policy, layer-1 half: the ISO and the
  ## image run the SAME file, and the ISO's document is a function of the
  ## one `metadata()` in it.
  let policy = readSource(PolicyTool)
  let iso = readSource(IsoBuilder)
  let builder = readSource(VerityBuilder)
  if policy.len == 0 or iso.len == 0 or builder.len == 0: return

  if policy.count("def metadata(") != 1:
    fail("t_iso_and_image_apply_one_policy: " & PolicyTool & " defines " &
         $policy.count("def metadata(") & " metadata() functions. One " &
         "carrier reading a second one is how the two paths drift")
    return
  # Every carrier has to read that one function IN ITS OWN BODY. Counting
  # occurrences file-wide would let a carrier stop reading it while the
  # others kept the total up.
  var carriers = 0
  for renderer in ["def squashfs(", "def archive(", "def apply(",
                   "def expected("]:
    let head = policy.find(renderer)
    if head < 0:
      fail("t_iso_and_image_apply_one_policy: " & PolicyTool & " no " &
           "longer defines " & renderer & ")")
      return
    var stop = policy.find("\n    def ", head + renderer.len)
    if stop < 0: stop = policy.len
    if "self.metadata(" notin policy[head ..< stop]:
      fail("t_iso_and_image_apply_one_policy: `" & renderer & "` in " &
           PolicyTool & " no longer reads self.metadata(), so it is a " &
           "second opinion about what the policy says rather than a " &
           "carrier of it")
      return
    carriers.inc
  pass("t_iso_and_image_apply_one_policy: " & PolicyTool & " has exactly " &
       "one metadata() and " & $carriers & " carriers that read it")

  let isoUses = invocationOffset(withoutShellComments(iso),
                                 "reproos_image_metadata.py", "squashfs")
  let imageUses = invocationOffset(withoutShellComments(builder),
                                   "$INODE_POLICY", "ext4-apply")
  if isoUses < 0 or imageUses < 0:
    fail("t_iso_and_image_apply_one_policy: the ISO (" & $isoUses & ") " &
         "and the root image (" & $imageUses & ") do not both INVOKE " &
         PolicyTool & "; one of them is carrying a second opinion")
    return
  # …and the file each of them runs has to BE the repository-root one.
  # Read out of the ISO's own invocation line and out of the builder's
  # INODE_POLICY ASSIGNMENT, with comments -- whole-line and trailing --
  # gone first. Asking only whether the path appears somewhere in the
  # file is satisfied by a comment, so a builder pointed at a private
  # copy in one line would pass while the two carriers silently drifted.
  let repoRootPolicy = "../../../" & PolicyTool
  var isoResolves = false
  for line in codeLines(iso):
    if repoRootPolicy in line and "squashfs" in line: isoResolves = true
  let builderResolves = assignedValue(builder, "INODE_POLICY")
  if not isoResolves:
    fail("t_iso_and_image_apply_one_policy: " & IsoBuilder & " does not " &
         "run " & repoRootPolicy & " on the line that invokes it (a " &
         "comment naming it is not the file it runs)")
    return
  if not builderResolves.endsWith(repoRootPolicy):
    fail("t_iso_and_image_apply_one_policy: " & VerityBuilder &
         " resolves INODE_POLICY to `" & builderResolves & "`, which is " &
         "not the repository-root " & PolicyTool & " the ISO runs. Read " &
         "out of the ASSIGNMENT: the two carriers would then be two " &
         "files, and every agreement below a coincidence")
    return
  pass("t_iso_and_image_apply_one_policy: " & IsoBuilder & " and " &
       VerityBuilder & " both invoke the same repository-root " &
       PolicyTool & ", the ISO for its pseudo-file and the image for its " &
       "inodes")

proc caseTheIsoDocumentTracksThePolicy(work: string) =
  ## The ISO's pseudo-file is a function of `metadata()` and not a
  ## constant: change the one line that decides the setuid mode in a COPY
  ## of the policy, and the document moves with it.
  let tree = work / "policy-fixture"
  buildPolicyFixture(tree)
  let shipped = work / "shipped.pseudo"
  if not renderPseudoFile(RepoRoot / PolicyTool, tree, shipped):
    fail("t_iso_and_image_apply_one_policy: the shipped SquashFS " &
         "renderer failed on the fixture root")
    return
  let records = parsePseudoFile(shipped)
  for path, wanted in {SudoPath: SudoMode, ShadowPath: ShadowMode,
                       "etc/sudoers": 0o440, "usr/bin": 0o755}.toTable:
    if path notin records:
      fail("t_iso_and_image_apply_one_policy: the ISO document says " &
           "nothing about " & path)
      return
    let got = records[path]
    if got != (wanted, 0, 0):
      fail("t_iso_and_image_apply_one_policy: the ISO document gives " &
           path & " mode " & got.mode.toOct(4) & " " & $got.uid & ":" &
           $got.gid & ", not " & wanted.toOct(4) & " 0:0")
      return
  if records.getOrDefault("home/repro").uid != 1000:
    fail("t_iso_and_image_apply_one_policy: the ISO document reassigns " &
         "the declared user's home to " &
         $records.getOrDefault("home/repro").uid & " rather than leaving " &
         "it with its passwd owner")
    return
  pass("t_iso_and_image_apply_one_policy: the shipped SquashFS renderer " &
       "gives " & SudoPath & " " & SudoMode.toOct(4) & " 0:0, " &
       ShadowPath & " " & ShadowMode.toOct(4) & " 0:0, etc/sudoers 0440 " &
       "0:0 and usr/bin 0755 0:0, and leaves home/repro to uid 1000")

  let mutated = mutatedPolicy(work)
  if mutated.len == 0: return
  let after = work / "mutated.pseudo"
  if not renderPseudoFile(mutated, tree, after):
    fail("t_iso_and_image_apply_one_policy: the mutated policy's " &
         "SquashFS renderer failed")
    return
  let moved = parsePseudoFile(after)
  if moved.getOrDefault(SudoPath).mode != MutatedSudoMode:
    fail("t_iso_and_image_apply_one_policy: changing `" & SudoModeSource &
         "` to `" & SudoModeMutated & "` in metadata() left the ISO " &
         "document saying " & moved.getOrDefault(SudoPath).mode.toOct(4) &
         " for " & SudoPath & ". The ISO's document is then not a " &
         "function of metadata(), and comparing the two carriers proves " &
         "nothing")
    return
  pass("t_iso_and_image_apply_one_policy: one changed line in " &
       "metadata() moves the ISO's own document from " &
       SudoMode.toOct(4) & " to " & MutatedSudoMode.toOct(4) & " for " &
       SudoPath & ", so the document is a function of the policy")

# =====================================================================
# Layer 2 -- opt-in. A real ext4 image, made by the SHIPPED builder, and
# read back through the KERNEL rather than through the tool that wrote
# it.
# =====================================================================

proc gateSkipRemedy(): string =
  "  Run it with " & GateEnv & "=1.\n" &
  "  It builds a purpose-built root with deliberately wrong metadata,\n" &
  "  images it with the shipped build-verity-root.sh, loop-mounts the\n" &
  "  result READ-ONLY and reads every owner and mode back out of it with\n" &
  "  the kernel's own ext4 driver. It needs mkfs.ext4, debugfs, sudo and\n" &
  "  a loop mount, and takes about a minute."

proc runVerityBuilder(tree, outDir: string; extraEnv = ""): tuple[
    output: string, exitCode: int] =
  const seed = "reproos-image-v1:root-metadata-gate"
  run(extraEnv &
      " REPROOS_STAGED_ROOTFS=" & quoteShell(tree) &
      " REPROOS_VERITY_SALT=" & "00".repeat(32) &
      " REPROOS_VERITY_UUID=3f2e1d0c-4b5a-6978-8796-a5b4c3d2e1f0" &
      " REPROOS_VERITY_FS_UUID=1a2b3c4d-5e6f-4071-8213-9455a6b7c8d9" &
      " REPROOS_VERITY_FS_HASH_SEED=9f8e7d6c-5b4a-4039-8281-716253443526" &
      " SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC" &
      " bash " & quoteShell(RepoRoot / VerityBuilder) & " " &
      quoteShell(outDir) & " 2>&1")

proc statInImage(sudo, mountPoint, rel: string): string =
  ## `<mode> <uid> <gid>` as the KERNEL reports it, not as debugfs does.
  let r = run(sudo & " stat -c '%04a %u %g' " &
              quoteShell(mountPoint / rel) & " 2>&1")
  if r.exitCode != 0: return ""
  r.output.strip()

proc runLayer2(workRoot: string) =
  if getEnv(GateEnv) != "1":
    skip("t_attested_root_ownership_and_modes: not requested (" & GateEnv &
         " is not 1).\n" &
         "  NO ext4 image was made and NOTHING was read out of one.\n" &
         gateSkipRemedy())
    skip("t_unpoliced_tree_is_refused: the behavioural half did not run " &
         "-- no image reached the builder without the policy, and the " &
         "refusal was not observed.\n" & gateSkipRemedy())
    skip("t_iso_and_image_apply_one_policy: the two carriers were not " &
         "compared at the bytes; only the ISO half ran.\n" &
         gateSkipRemedy())
    return

  var missing: seq[string] = @[]
  for tool in Layer2Tools:
    if findExe(tool).len == 0: missing.add tool
  if missing.len > 0:
    fail("t_attested_root_ownership_and_modes: requested, but these " &
         "tools are not on PATH: " & missing.join(", ") & ". This gate " &
         "does not skip for a missing tool when it was asked for: a " &
         "green run that made no image would be worse than a red one.")
    return

  let sudo = findExe("sudo")
  let work = workRoot / "root-metadata"
  removeDir(work)
  createDir(work)
  let mountPoint = work / "mnt"
  createDir(mountPoint)
  template teardown() =
    discard run(sudo & " umount " & quoteShell(mountPoint) & " 2>/dev/null")
    if getEnv(KeepEnv) != "1": removeDir(work)

  try:
    let tree = work / "installed-root"
    buildPolicyFixture(tree)
    # What the staged tree really looks like before anything runs. This
    # is the defect, measured on this host rather than recalled.
    let stagedShadow = run("stat -c '%04a %u %g' " &
                           quoteShell(tree / ShadowPath)).output.strip()
    let stagedSudo = run("stat -c '%04a %u %g' " &
                         quoteShell(tree / SudoPath)).output.strip()

    let outA = work / "verity-a"
    let built = runVerityBuilder(tree, outA)
    if built.exitCode != 0:
      fail("t_attested_root_ownership_and_modes: the shipped " &
           VerityBuilder & " failed (exit " & $built.exitCode & "): " &
           built.output.strip())
      return
    let dataImage = outA / "reproos-root.verity.img"
    if not fileExists(dataImage):
      fail("t_attested_root_ownership_and_modes: the builder produced no " &
           "root image")
      return

    # ---- THE GATE: read it back through the kernel's ext4 driver.
    if not sh(sudo & " mount -o ro,loop " & quoteShell(dataImage) & " " &
              quoteShell(mountPoint)):
      fail("t_attested_root_ownership_and_modes: the root image could " &
           "not be loop-mounted read-only, so nothing was read out of it")
      return
    let inImageShadow = statInImage(sudo, mountPoint, ShadowPath)
    let inImageSudo = statInImage(sudo, mountPoint, SudoPath)
    let inImageSudoers = statInImage(sudo, mountPoint, "etc/sudoers")
    let inImageUsrBin = statInImage(sudo, mountPoint, "usr/bin")
    let inImageHome = statInImage(sudo, mountPoint, "home/repro")
    let wantShadow = ShadowMode.toOct(4) & " 0 0"
    let wantSudo = SudoMode.toOct(4) & " 0 0"
    var wrong: seq[string] = @[]
    if inImageShadow != wantShadow:
      wrong.add ShadowPath & " is " & inImageShadow & ", want " & wantShadow
    if inImageSudo != wantSudo:
      wrong.add SudoPath & " is " & inImageSudo & ", want " & wantSudo
    if inImageSudoers != "0440 0 0":
      wrong.add "etc/sudoers is " & inImageSudoers & ", want 0440 0 0"
    if inImageUsrBin != "0755 0 0":
      wrong.add "usr/bin is " & inImageUsrBin & ", want 0755 0 0"
    if inImageHome != "0755 1000 100":
      wrong.add "home/repro is " & inImageHome & ", want 0755 1000 100"
    if wrong.len > 0:
      discard run(sudo & " umount " & quoteShell(mountPoint))
      fail("t_attested_root_ownership_and_modes: inside the image the " &
           "root hash covers, " & wrong.join("; "))
      return
    pass("t_attested_root_ownership_and_modes: the staged tree had " &
         ShadowPath & " at " & stagedShadow & " and " & SudoPath & " at " &
         stagedSudo & "; INSIDE the image, read by the kernel's own ext4 " &
         "driver off a read-only loop mount, they are " & inImageShadow &
         " and " & inImageSudo & " -- and etc/sudoers is 0440 0:0, " &
         "usr/bin lost its group- and other-write, and home/repro kept " &
         "its passwd owner")

    # ---- t_iso_and_image_apply_one_policy, at the bytes: every record
    #      of the ISO's OWN document, checked against the ext4 image.
    let pseudo = work / "iso.pseudo"
    if not renderPseudoFile(RepoRoot / PolicyTool, tree, pseudo):
      discard run(sudo & " umount " & quoteShell(mountPoint))
      fail("t_iso_and_image_apply_one_policy: the shipped SquashFS " &
           "renderer failed on the tree the image was made from")
      return
    let document = parsePseudoFile(pseudo)
    var compared = 0
    var disagreement = ""
    var names: seq[string] = @[]
    for name in document.keys: names.add name
    names.sort()
    for name in names:
      let wanted = document[name]
      let info = getFileInfo(mountPoint / name, followSymlink = false)
      let got = statInImage(sudo, mountPoint, name)
      if got.len == 0:
        disagreement = name & " is in the ISO's document and not in the " &
                       "ext4 image"
        break
      if info.kind == pcLinkToFile or info.kind == pcLinkToDir:
        # The policy never chmods a symlink -- `apply` does not, and
        # neither carrier does. Ownership still has to agree.
        let owner = got.splitWhitespace()[1 .. 2].join(" ")
        if owner != $wanted.uid & " " & $wanted.gid:
          disagreement = name & " (symlink) is owned by " & owner &
                         " in the image and " & $wanted.uid & " " &
                         $wanted.gid & " in the ISO's document"
          break
      elif got != wanted.mode.toOct(4) & " " & $wanted.uid & " " & $wanted.gid:
        disagreement = name & " is " & got & " in the image and " &
                       wanted.mode.toOct(4) & " " & $wanted.uid & " " &
                       $wanted.gid & " in the ISO's document"
        break
      compared.inc
    discard run(sudo & " umount " & quoteShell(mountPoint))
    if disagreement.len > 0:
      fail("t_iso_and_image_apply_one_policy: the two carriers disagree " &
           "-- " & disagreement)
      return
    # Anti-vacuity: the comparison has to have covered the paths that make
    # it interesting -- the setuid binary, the shadow file, a user home, a
    # symlink and a name with a space in it.
    var uncovered: seq[string] = @[]
    for name in [SudoPath, ShadowPath, "etc/sudoers", "home/repro",
                 "usr/share/relative-link", "usr/share/absolute-link",
                 "usr/share/data with spaces"]:
      if name notin document: uncovered.add name
    if uncovered.len > 0:
      fail("t_iso_and_image_apply_one_policy: the ISO's document does not " &
           "cover " & uncovered.join(", ") & ", so the comparison skipped " &
           "the paths it exists for")
      return
    if compared < 25:
      fail("t_iso_and_image_apply_one_policy: only " & $compared &
           " paths were compared, which is too few for the agreement to " &
           "mean anything")
      return
    pass("t_iso_and_image_apply_one_policy: all " & $compared & " records " &
         "of the ISO's OWN pseudo-file agree, path for path, with what " &
         "the kernel reports inside the ext4 image the root hash covers")

    # ---- determinism: the same tree and the same policy, twice.
    let outB = work / "verity-b"
    let again = runVerityBuilder(tree, outB, "TMPDIR=" &
                                 quoteShell(work / "tmp2"))
    if again.exitCode != 0:
      fail("t_attested_root_ownership_and_modes: the second run of the " &
           "builder failed: " & again.output.strip())
      return
    var firstDifference = ""
    for name in ["reproos-root.verity.img", "reproos-root.verity.hashtree",
                 "reproos-root.verity.roothash"]:
      if readFile(outA / name) != readFile(outB / name):
        firstDifference = name
        break
    if firstDifference.len > 0:
      fail("t_attested_root_ownership_and_modes: two runs over one tree " &
           "differ in " & firstDifference & ". The policy is inside the " &
           "measurement, so a carrier that is not deterministic makes " &
           "the root hash meaningless")
      return
    pass("t_attested_root_ownership_and_modes: two runs of the shipped " &
         "builder over the same tree and the same policy give a " &
         "byte-identical root image, hash tree and root hash (" &
         readFile(outA / "reproos-root.verity.roothash").strip() & ")")

    # =================================================================
    # t_unpoliced_tree_is_refused -- the behavioural half.
    # =================================================================

    # (a) An image that reached the hash the old way: plain
    #     `mkfs.ext4 -d`, nothing applied. The shipped verifier must
    #     refuse it and say which inode.
    let unpoliced = work / "unpoliced.img"
    if not sh(findExe("mkfs.ext4") & " -q -F -b 4096 -d " &
              quoteShell(tree) & " -O ^has_journal -m 0 " &
              quoteShell(unpoliced) & " 64M"):
      fail("t_unpoliced_tree_is_refused: could not build the unpoliced " &
           "control image")
      return
    let refused = run(findExe("python3") & " " &
                      quoteShell(RepoRoot / PolicyTool) & " ext4-verify " &
                      quoteShell(tree) & " --image " & quoteShell(unpoliced) &
                      " 2>&1")
    if refused.exitCode == 0:
      fail("t_unpoliced_tree_is_refused: the shipped verifier ACCEPTED " &
           "an image built by plain mkfs.ext4 -d, which is exactly the " &
           "image the defect shipped")
      return
    if "does not carry the guest inode policy" notin refused.output:
      fail("t_unpoliced_tree_is_refused: the verifier failed (exit " &
           $refused.exitCode & ") but not with the refusal: " &
           refused.output.strip())
      return
    pass("t_unpoliced_tree_is_refused: an image built by plain " &
         "mkfs.ext4 -d over the same tree is REFUSED (exit " &
         $refused.exitCode & "), naming the first inode that disagrees " &
         "-- " & refused.output.strip().splitLines()[0])

    # (b) End to end, through the SHIPPED builder: make the write half of
    #     the policy a no-op and require the BUILD to fail with no root
    #     hash. That is the property this gate exists for: a root that
    #     reaches the verity build without the policy applied must fail
    #     the build rather than be hashed.
    let shimDir = work / "shim"
    createDir(shimDir)
    writeFile(shimDir / "debugfs",
      "#!/usr/bin/env bash\n" &
      "# Reads pass through; the WRITE pass silently does nothing.\n" &
      "for a in \"$@\"; do\n" &
      "  if [ \"$a\" = \"-w\" ]; then exit 0; fi\n" &
      "done\n" &
      "exec " & findExe("debugfs") & " \"$@\"\n")
    setFilePermissions(shimDir / "debugfs",
      {fpUserRead, fpUserWrite, fpUserExec, fpGroupRead, fpGroupExec,
       fpOthersRead, fpOthersExec})
    let outC = work / "verity-c"
    let sabotaged = runVerityBuilder(tree, outC,
      "PATH=" & quoteShell(shimDir) & ":$PATH")
    if sabotaged.exitCode == 0:
      fail("t_unpoliced_tree_is_refused: with the policy's write pass " &
           "made a no-op, the shipped builder still exited 0 and took a " &
           "root hash. That is the defect: an unpoliced root gets hashed " &
           "silently")
      return
    if fileExists(outC / "reproos-root.verity.roothash"):
      fail("t_unpoliced_tree_is_refused: the builder failed (exit " &
           $sabotaged.exitCode & ") but still wrote a root hash, so an " &
           "unpoliced image was named")
      return
    if sabotaged.exitCode notin [70, 71]:
      fail("t_unpoliced_tree_is_refused: the builder failed with exit " &
           $sabotaged.exitCode & " rather than the policy's own 70/71, " &
           "so the refusal was reported as something else: " &
           sabotaged.output.strip())
      return
    pass("t_unpoliced_tree_is_refused: with the policy's write pass made " &
         "a no-op, the SHIPPED builder exits " & $sabotaged.exitCode &
         " and writes NO root hash -- the unpoliced image is refused " &
         "rather than hashed")

    # (c) A tree the policy cannot describe at all. `mkfs.ext4 -d` is
    #     perfectly happy with one, which is how the integrity-checked
    #     root was built from an unpoliced tree for as long as it has
    #     existed.
    let notARoot = work / "not-a-root"
    createDir(notARoot / "etc")
    writeFile(notARoot / "etc/os-release", "NAME=not-a-root\n")
    let outD = work / "verity-d"
    let rejected = runVerityBuilder(notARoot, outD)
    if rejected.exitCode == 0 or
       fileExists(outD / "reproos-root.verity.roothash"):
      fail("t_unpoliced_tree_is_refused: the builder hashed a tree with " &
           "no /etc/passwd and no /usr/bin/sudo, which the policy cannot " &
           "describe at all")
      return
    pass("t_unpoliced_tree_is_refused: a tree the policy cannot describe " &
         "is refused too (exit " & $rejected.exitCode & ", no root hash " &
         "written), so `it is not a root filesystem' fails the build " &
         "instead of producing a hash of one")

    # (d) A shared inode the policy describes two ways. `mkfs.ext4 -d`
    #     preserves hardlinks and an inode carries ONE owner and ONE mode,
    #     so an image made from such a tree is silently wrong at all but
    #     one of the names. The ISO sidesteps this with
    #     `mksquashfs -no-hardlinks`, which duplicates the content; an
    #     image whose size is already fixed cannot, so the build refuses.
    for kase in ["setuid alias", "home alias"]:
      let aliased = work / ("aliased-" & kase.replace(" ", "-"))
      buildPolicyFixture(aliased)
      let source = if kase == "setuid alias": aliased / SudoPath
                   else: aliased / "usr/share/shared-config"
      let alias = if kase == "setuid alias": aliased / "usr/share/sudo-alias"
                  else: aliased / "home/repro/shared-config"
      if kase != "setuid alias":
        writeFile(source, "shared between a home and the system\n")
      if not sh("ln " & quoteShell(source) & " " & quoteShell(alias)):
        fail("t_unpoliced_tree_is_refused: could not create the hardlink " &
             "for the " & kase & " case")
        return
      let outE = work / ("verity-alias-" & kase.replace(" ", "-"))
      let ambiguous = runVerityBuilder(aliased, outE)
      if ambiguous.exitCode == 0 or
         fileExists(outE / "reproos-root.verity.roothash"):
        fail("t_unpoliced_tree_is_refused: a tree whose " & kase &
             " shares one inode with a path the policy describes " &
             "differently was HASHED. The image is wrong at one of the " &
             "two names and nothing said so")
        return
      if "the policy describes differently" notin ambiguous.output:
        fail("t_unpoliced_tree_is_refused: the " & kase & " failed (exit " &
             $ambiguous.exitCode & ") but not as an aliasing refusal: " &
             ambiguous.output.strip())
        return
    pass("t_unpoliced_tree_is_refused: a hardlinked " & SudoPath &
         " and a system file hardlinked into a user home are both " &
         "REFUSED rather than resolved by picking one of the policy's " &
         "two answers -- an inode holds one owner and one mode")

    # ---- and the mutation moves BOTH carriers, not just the document.
    let mutated = mutatedPolicy(work)
    if mutated.len == 0: return
    let mutatedImage = work / "mutated.img"
    copyFile(dataImage, mutatedImage)
    if not sh(findExe("python3") & " " & quoteShell(mutated) &
              " ext4-apply " & quoteShell(tree) & " --image " &
              quoteShell(mutatedImage)):
      fail("t_iso_and_image_apply_one_policy: the mutated policy could " &
           "not be applied to a copy of the image")
      return
    if not sh(sudo & " mount -o ro,loop " & quoteShell(mutatedImage) & " " &
              quoteShell(mountPoint)):
      fail("t_iso_and_image_apply_one_policy: the mutated image could " &
           "not be mounted")
      return
    let mutatedSudo = statInImage(sudo, mountPoint, SudoPath)
    discard run(sudo & " umount " & quoteShell(mountPoint))
    if mutatedSudo != MutatedSudoMode.toOct(4) & " 0 0":
      fail("t_iso_and_image_apply_one_policy: changing `" & SudoModeSource &
           "` to `" & SudoModeMutated & "` in metadata() left " & SudoPath &
           " at " & mutatedSudo & " inside the ext4 image. The image " &
           "carrier is then not reading metadata() either, and the " &
           "agreement above is a coincidence")
      return
    pass("t_iso_and_image_apply_one_policy: the SAME one-line change to " &
         "metadata() moves the ext4 image to " & mutatedSudo & " for " &
         SudoPath & ", exactly as it moved the ISO's pseudo-file. Both " &
         "carriers read one policy")
  finally:
    teardown()

# ---------------------------------------------------------------------

when isMainModule:
  let workRoot = getEnv("REPROOS_TEST_WORK_DIR",
                        getTempDir() / "reproos-attested-root-metadata")
  createDir(workRoot)
  let layer1Work = workRoot / "layer1"
  removeDir(layer1Work)
  createDir(layer1Work)

  caseTheBuilderRefusesAnUnpolicedImage()
  caseThePolicyIsAnInputOfTheHash()
  caseOnePolicyForBothCarriers()
  caseTheIsoDocumentTracksThePolicy(layer1Work)
  if getEnv(KeepEnv) != "1":
    removeDir(layer1Work)

  runLayer2(workRoot)

  if failures > 0:
    stderr.writeLine("attested root metadata: " & $failures &
                     " check(s) failed, " & $passes & " passed, " &
                     $skips & " skipped")
    quit(1)
  echo "attested root metadata: PASS (" & $passes & " checks" &
       (if skips > 0: ", " & $skips & " SKIPPED -- no ext4 image was made"
        else: "") & ")"
