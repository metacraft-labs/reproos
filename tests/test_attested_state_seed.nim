## Gate: the first-boot state seed of an integrity-checked root.
##
## ## The defect this gate exists for
##
## On the integrity-checked layout ``/var`` and ``/home`` are separate
## volumes. The disk layout creates them EMPTY and the initramfs mounts
## them over the measured root before it hands off to init
## (``mount_state "$STATE_VAR" /var`` / ``mount_state "$STATE_HOME"
## /home``). Meanwhile the shipped configuration creates the account's
## home, ``/var/lib/reproos`` and ``/var/empty`` INSIDE that root.
##
## So the configured home was shadowed by an empty filesystem the instant
## the machine started, and nothing seeded it. The image booted, verified
## against its own root hash, had a working ``sudo`` -- and offered no
## usable session. Every check this project had passed.
##
## ## What was done, and why the mechanism is systemd's
##
## ``tools/reproos_state_seed.py`` copies the state roots into
## ``/usr/share/factory`` inside the root and writes
## ``/usr/lib/tmpfiles.d/10-reproos-state.conf``, whose lines are all
## ``C`` -- copy only when the destination is absent or an EMPTY
## directory. ``systemd-tmpfiles-setup.service`` runs them at every boot,
## ``After=local-fs.target`` and ``Before=sysinit.target``: after the
## state volumes are mounted and long before any login.
##
## Two properties come out of the mechanism rather than out of a
## convention this project would have to keep:
##
##   * the seed source is inside the measurement -- ``/usr/share/factory``
##     is part of the root the hash names, so nothing unmeasured is ever
##     installed onto the running machine; and
##   * seeding is idempotent WITHOUT a stamp file. A stamp is not an
##     answer here, because it would live on the very volume being
##     seeded: lose it and the seeder turns into a clobberer. ``C``
##     tests the destination itself, so it cannot be defeated that way.
##
## ## The layers, and what each is worth
##
## Layer 1 (always on, ~3s, ``python3`` and nothing else) reads the
## shipped configuration script, the shipped stager, the shipped
## initramfs and the shipped recipe for INVOCATIONS and ARGUMENTS, and
## drives the SHIPPED seed tool over purpose-built roots -- including
## every refusal it is supposed to make. It touches no disk and boots
## nothing.
##
## Layer 2 (opt-in, ``REPROOS_STATE_SEED_GATE=1``, ~4 min, needs sudo,
## the nbd module and the from-source systemd) is the behavioural one. It
## configures a root with the SHIPPED ``configure-installed-root.sh``,
## seeds and detaches it with the SHIPPED tool, images it with the
## SHIPPED ``build-verity-root.sh``, applies the real ``uefi-attested``
## layout to a transient qcow2 over a loopback NBD node, writes the
## verity pair onto the carriers with the SHIPPED writer, and then
## ACTIVATES THAT DISK TWICE:
##
##   * activation 1 -- ``veritysetup verify`` against the hash the
##     measured command line pins, ``veritysetup open``, the root mounted
##     READ-ONLY off ``/dev/mapper``, the real ``/var`` and ``/home``
##     partitions mounted read-write over it, and the REAL
##     ``systemd-tmpfiles`` binary the image ships run over the result;
##   * the state is then MODIFIED -- a seeded file edited, a new file
##     created, a seeded file deleted, on both volumes;
##   * everything is unmounted and the verity device closed;
##   * activation 2 -- the same disk verified, opened, mounted and seeded
##     again.
##
## Nothing the second activation does may revert any of it. The control
## for that assertion is in the gate: a naive unconditional copy is run
## over the same state afterwards and MUST clobber it, so a green
## idempotence result cannot come from an assertion that could not tell
## the difference.
##
## ## What layer 2 is NOT
##
## It is not a kernel boot. There is no ReproOS kernel or initramfs on
## this host yet, so no guest is started and no PCR is read: what is
## reproduced twice is the disk, the dm-verity activation, the mount
## topology the initramfs creates and the seeder the image runs -- not
## the firmware, the loader, or systemd as pid 1. Said plainly so nobody
## reads a boot into it.
##
## ## Mocking
##
## None. Real partitions written by the real ``repro disk apply``, real
## ``mkfs.ext4`` filesystems, a real dm-verity device, and the real
## ``systemd-tmpfiles`` from the project's own systemd. The fixture root
## is a fixture, not a mock: real files that the SHIPPED configuration
## script configures and the SHIPPED tools then describe.

import std/[algorithm, os, osproc, sets, strutils]

import "../repro/disk_layouts" as diskLayouts
import "../repro/generations" as generations
import "../repro/package_sets" as packageSets
import "../repro/uki" as ukiModule
import "../repro/verity" as verity
import "./root_policy_fixture"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  SeedTool = "tools/reproos_state_seed.py"
  InodePolicy = "tools/reproos_image_metadata.py"
  Configurer = "recipes/reproos-image/scripts/configure-installed-root.sh"
  Stager = "recipes/reproos-image/scripts/stage-installed-root.sh"
  VerityBuilder = "recipes/reproos-image/scripts/build-verity-root.sh"
  CarrierWriter = "recipes/reproos-image/scripts/write-verity-carriers.sh"
  InitDisk = "recipes/reproos-iso/initramfs/init-disk"
  ImageRecipe = "recipes/reproos-image/package.nim"
  AutoConfigFixture = "tests/fixtures/auto-config-minimal.toml"

  AttestedLayout = "uefi-attested"

  GateEnv = "REPROOS_STATE_SEED_GATE"
  KeepEnv = "REPROOS_STATE_SEED_KEEP"
  PackagesRootEnv = "REPROBUILD_PACKAGES_ROOT"

  FactoryRoot = "/usr/share/factory"
  Fragment = "/usr/lib/tmpfiles.d/10-reproos-state.conf"

  StateRoots = ["/var", "/home"]
    ## Asserted below to be exactly what the shipped tool declares and
    ## exactly what the shipped initramfs mounts, rather than trusted
    ## here.

  VmNamePrefix = "reproos-att-seed-"
    ## The dm-verity device this gate activates is named under the shared
    ## ``reproos-att-`` prefix and closed unconditionally, so nothing it
    ## creates can be confused with anything else on this host.

  Layer2Tools = ["sudo", "qemu-img", "qemu-nbd", "sgdisk", "veritysetup",
                 "mkfs.ext4", "modprobe", "dd", "blockdev", "sha256sum",
                 "mount", "umount", "blkid", "python3", "stat"]

  # The library packages the from-source `systemd-tmpfiles` resolves
  # against. `gcc`, `glibc`, `musl` and `llvm` are excluded: they carry a
  # libc newer than the one this binary and every host tool were linked
  # against, and putting it first breaks the process before it starts.
  LibcCarryingPackages = ["gcc", "glibc", "musl", "llvm"]

  FixtureTreeDirs = [
    "etc/pam.d", "etc/tmpfiles.d", "etc/systemd/system", "etc/ssh",
    "etc/dbus-1", "etc/xdg", "usr/bin", "usr/sbin", "usr/lib",
    "usr/lib/tmpfiles.d", "usr/local/bin", "usr/local/sbin",
    "usr/local/libexec", "usr/libexec", "usr/share/sddm", "var/empty",
    "var/lib/dbus", "var/lib/reproos", "var/log", "home", "root", "boot",
    "run", "tmp"]

  # What the operator does between the two activations. Named here so the
  # assertions after the second one read as the claim they make.
  OperatorEditedProfile = "# the operator edited this between boots\n"
  OperatorNewFile = "notes-written-on-the-first-boot\n"
  OperatorEditedInstallSource = "operator-rewrote-this\n"
  SeededProfileMarker = "# shipped by the factory copy\n"
  SeededKeepMarker = "shipped-config\n"

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
# Reading shipped sources for INVOCATIONS and BINDINGS, never mentions.
#
# The same three rules the sibling gates in this directory learned the
# hard way: fold continuations before matching, strip TRAILING comments
# as well as whole-line ones, and scope every scan to the construct under
# test rather than letting it run on into the next one.
# ---------------------------------------------------------------------

proc withoutShellComments(text: string): string =
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
  result = @[]
  for line in withoutShellComments(text).splitLines():
    let hash = line.find('#')
    let code = if hash >= 0: line[0 ..< hash] else: line
    if code.strip().len > 0: result.add code

proc assignments(text, name: string): seq[string] =
  ## EVERY right-hand side of ``name=…`` in CODE, unquoted, in order.
  ##
  ## All of them rather than the first, and that is the whole point. A
  ## check that reads the first assignment is defeated by leaving it
  ## exactly where it is and adding a second one below it -- the value
  ## the script actually runs with is the last one, and the check never
  ## sees it. Same shape as the old call left behind in a comment, one
  ## line further down instead of one column across.
  ##
  ## The leading =export=/=local=/=readonly=/=declare=/=typeset= keywords
  ## and their flags are stripped first, and that is not tidiness either:
  ## =export NAME=v= assigns exactly as =NAME=v= does, and a matcher
  ## anchored on the bare name never sees it. Found by mutation while
  ## hardening this proc -- and then found a SECOND time, because the
  ## first fix split on a literal space and =export<TAB>NAME=v= walked
  ## straight through it. Any run of whitespace separates them.
  result = @[]
  for line in codeLines(text):
    var bare = line.strip()
    while true:
      let cut = bare.find({' ', '\t'})
      if cut < 0: break
      let head = bare[0 ..< cut]
      if head in ["export", "local", "readonly", "declare", "typeset"] or
         (head.len > 1 and head[0] == '-'):
        bare = bare[cut + 1 .. ^1].strip()
      else:
        break
    if bare.startsWith(name & "="):
      result.add bare[name.len + 1 .. ^1].strip().strip(chars = {'"', '\''})

proc seedToolAssignmentProblem(text, script, suffix: string): string =
  ## "" when ``script`` binds STATE_SEED_TOOL exactly once, to the
  ## repository-root tool; the reason otherwise.
  let bound = assignments(text, "STATE_SEED_TOOL")
  if bound.len == 0:
    return script & " never assigns STATE_SEED_TOOL, so the path it runs " &
      "comes from somewhere this gate cannot read"
  if bound.len > 1:
    return script & " assigns STATE_SEED_TOOL " & $bound.len & " times (" &
      bound.join(", ") & "). The last one wins at run time, so two " &
      "assignments mean the path this gate reads and the path the script " &
      "executes can differ"
  if not bound[0].endsWith(suffix):
    return script & " resolves STATE_SEED_TOOL to `" & bound[0] &
      "', which is not the repository-root " & SeedTool &
      ". Read out of the ASSIGNMENT"
  ""

proc invocationLine(text, interpreter, script, argument: string): int =
  ## Index into ``codeLines(text)`` of a line that RUNS ``script`` through
  ## ``interpreter`` with ``argument`` on it, or -1. All three have to be
  ## on one logical line, so a header comment naming the tool and a
  ## variable that merely holds its path both fail to satisfy it.
  let lines = codeLines(text)
  for i, line in lines:
    if interpreter in line and script in line and argument in line:
      return i
  -1

proc refusesOnFailure(text, script, argument: string): bool =
  ## True when the invocation is the CONDITION of an ``if !`` whose OWN
  ## body exits.
  ##
  ## Scoped to that construct deliberately. A forward scan for the next
  ## ``exit`` runs past the construct under test into an unrelated one
  ## further down the file, which is exactly how a sibling gate's
  ## headline check was defeated: turning the refusal into a warning
  ## stayed green because some later block still had an ``exit`` in it.
  var inside = false
  for line in codeLines(text):
    let bare = line.strip()
    if not inside:
      if bare.startsWith("if ! ") and script in bare and argument in bare and
         bare.endsWith("; then"):
        inside = true
      continue
    if bare == "fi": return false
    if bare.startsWith("exit "): return true
  false

proc requiredTools(text: string): seq[string] =
  ## The WORDS of the script's ``for tool in … ; do`` list. Read as words
  ## so a trailing comment naming a tool is not a tool the script
  ## requires.
  for line in codeLines(text):
    let loop = line.strip()
    if loop.startsWith("for tool in ") and loop.endsWith("; do"):
      return loop["for tool in ".len ..< loop.len - "; do".len]
        .splitWhitespace()
  @[]

proc nimListArg(text, callSite, argName: string): string =
  ## The text of ``argName = @[ … ]`` inside the call beginning at
  ## ``callSite``, comments stripped, read as an ARGUMENT of that call.
  let start = text.find(callSite)
  if start < 0: return ""
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

proc withoutPythonComments(text: string): string =
  ## The Python source with every trailing ``#`` comment cut off.
  ##
  ## Not pedantry, and not hypothetical: BOTH checks below were written
  ## without it and BOTH survived their defeating mutation, because the
  ## mutation left the old call in a comment beside the new code. A
  ## substring match against a raw line is satisfied by a comment, which
  ## is the single most common way a structural check in this project has
  ## turned out not to be one.
  var kept: seq[string] = @[]
  for line in text.splitLines():
    var quote = '\0'
    var cut = -1
    for i, ch in line:
      if quote != '\0':
        if ch == quote: quote = '\0'
      elif ch == '\'' or ch == '"':
        quote = ch
      elif ch == '#':
        cut = i
        break
    kept.add(if cut >= 0: line[0 ..< cut] else: line)
  kept.join("\n")

proc pythonListLiteral(text, name: string): seq[string] =
  ## The string members of a module-level ``NAME = ( … )`` tuple in the
  ## shipped tool, read out of the BINDING rather than found anywhere in
  ## the file.
  result = @[]
  let head = text.find("\n" & name & " = (")
  if head < 0: return
  let open = text.find('(', head)
  let close = text.find(')', open)
  if close < 0: return
  for piece in text[open + 1 ..< close].split(','):
    let bare = piece.strip()
    if bare.len >= 2 and bare[0] == '"':
      result.add bare.strip(chars = {'"'})

# ---------------------------------------------------------------------
# Driving the SHIPPED tool.
# ---------------------------------------------------------------------

proc seedTool(operation, tree: string; extra = ""): tuple[
    output: string, exitCode: int] =
  run(findExe("python3") & " " & quoteShell(RepoRoot / SeedTool) & " " &
      operation & " " & quoteShell(tree) & " " & extra & " 2>&1")

proc buildStateFixture(dir: string) =
  ## A root with the shape the shipped configuration produces, and with
  ## content under BOTH state roots so that a seeder that did nothing
  ## would be visible.
  removeDir(dir)
  for d in FixtureTreeDirs:
    createDir(dir / d)
  writeFile(dir / "etc/os-release", "NAME=reproos-state-seed-fixture\n")
  writeFile(dir / "etc/machine-id", "")
  writeFile(dir / "usr/bin/hello", "#!/bin/sh\necho hello\n")
  writeRootPolicyFixture(dir)
  # /var, as the staged root really carries it: the dbus machine-id
  # symlink, the sshd privilege-separation directory, and the install
  # receipt the first-boot units read.
  createSymlink("/etc/machine-id", dir / "var/lib/dbus/machine-id")
  writeFile(dir / "var/lib/reproos/install-source", "direct-image-assembly\n")
  setFilePermissions(dir / "var/empty",
    {fpUserRead, fpUserWrite, fpUserExec, fpGroupRead, fpGroupExec,
     fpOthersRead, fpOthersExec})
  # /home, as the configuration leaves it.
  createDir(dir / "home" / PolicyFixtureUser / ".config")
  writeFile(dir / "home" / PolicyFixtureUser / ".profile", SeededProfileMarker)
  writeFile(dir / "home" / PolicyFixtureUser / ".config/keep", SeededKeepMarker)

proc fragmentLines(tree: string): seq[seq[string]] =
  result = @[]
  let path = tree / Fragment.strip(chars = {'/'})
  if not fileExists(path): return
  for line in readFile(path).splitLines():
    let bare = line.strip()
    if bare.len == 0 or bare.startsWith("#"): continue
    result.add bare.splitWhitespace()

# =====================================================================
# Layer 1 -- always on.
# =====================================================================

proc caseTheShippedScriptsRunTheSeeder() =
  ## t_attested_first_boot_seeds_state, structural half: the shipped
  ## configuration EMITS the seed and the shipped stager DETACHES the
  ## state and refuses a root that does not separate it.
  let configurer = readSource(Configurer)
  let stager = readSource(Stager)
  let recipe = readSource(ImageRecipe)
  if configurer.len == 0 or stager.len == 0 or recipe.len == 0: return

  # (a) The configuration runs the seed emitter, and the file it runs is
  #     the repository-root one. Read out of the ASSIGNMENT: a comment
  #     naming the path is not the file the script executes.
  let emitAt = invocationLine(configurer, "python3", "$STATE_SEED_TOOL",
                              "emit")
  let checkAt = invocationLine(configurer, "python3", "$STATE_SEED_TOOL",
                               "check")
  if emitAt < 0:
    fail("t_attested_first_boot_seeds_state: " & Configurer & " never RUNS " &
         "the state seed emitter (looked for a line that runs python3 on " &
         "$STATE_SEED_TOOL with `emit', not for a mention of the name). " &
         "Without it the configured home and /var content stay inside the " &
         "measured root, where the state volumes shadow them")
    return
  if checkAt < 0:
    fail("t_attested_first_boot_seeds_state: " & Configurer & " emits the " &
         "state seed and never reads it back. A carrier that does not " &
         "check its own work is how a root ships with a fragment that " &
         "seeds nothing")
    return
  let configurerBinding =
    seedToolAssignmentProblem(configurer, Configurer, "../../../" & SeedTool)
  if configurerBinding.len > 0:
    fail("t_attested_first_boot_seeds_state: " & configurerBinding)
    return
  var permissive: seq[string] = @[]
  for operation in ["emit", "check"]:
    if not refusesOnFailure(configurer, "$STATE_SEED_TOOL", operation):
      permissive.add operation
  if permissive.len > 0:
    fail("t_attested_first_boot_seeds_state: " & permissive.join(" and ") &
         " in " & Configurer & " does not exit when it fails -- it is " &
         "reported and walked past. Read as the invocation's OWN if/fi, " &
         "not as `some exit appears further down'")
    return
  pass("t_attested_first_boot_seeds_state: " & Configurer & " binds " &
       "STATE_SEED_TOOL EXACTLY ONCE, to the repository-root " & SeedTool &
       ", RUNS it to emit the seed and then to read it back, and each of " &
       "the two exits from its own construct rather than warning")

  # (b) The stager detaches the state and re-checks with --attested, both
  #     AFTER the configuration has run.
  let configureAt = invocationLine(stager, "bash", Configurer.extractFilename,
                                   "$OUT_TREE")
  let detachAt = invocationLine(stager, "python3", "$STATE_SEED_TOOL",
                                "detach")
  let attestedCheckAt = invocationLine(stager, "python3", "$STATE_SEED_TOOL",
                                       "--attested")
  if configureAt < 0 or detachAt < 0 or attestedCheckAt < 0:
    fail("t_attested_first_boot_seeds_state: " & Stager & " does not run " &
         "the configuration (" & $configureAt & "), the detach (" &
         $detachAt & ") and the attested check (" & $attestedCheckAt &
         ") as three invocations")
    return
  if not (configureAt < detachAt and detachAt < attestedCheckAt):
    fail("t_attested_first_boot_seeds_state: the order in " & Stager &
         " is wrong (configure at " & $configureAt & ", detach at " &
         $detachAt & ", attested check at " & $attestedCheckAt & "). The " &
         "state can only be separated after everything that writes it has " &
         "run, and the check has to read the finished tree")
    return
  var stagerPermissive: seq[string] = @[]
  for operation in ["detach", "--attested"]:
    if not refusesOnFailure(stager, "$STATE_SEED_TOOL", operation):
      stagerPermissive.add operation
  if stagerPermissive.len > 0:
    fail("t_attested_first_boot_seeds_state: " & stagerPermissive.join(
         " and ") & " in " & Stager & " does not exit when it fails, so a " &
         "root whose state is still shadowed would be staged anyway and " &
         "then hashed")
    return
  # The stager binds the same variable, and it was not read here until a
  # review found the configuration's own binding readable only in its
  # FIRST spelling. Both scripts run whatever the variable last held, so
  # both are read the same way.
  let stagerBinding =
    seedToolAssignmentProblem(stager, Stager, "/" & SeedTool)
  if stagerBinding.len > 0:
    fail("t_attested_first_boot_seeds_state: " & stagerBinding)
    return
  let stagerTools = requiredTools(stager)
  if "python3" notin stagerTools:
    fail("t_attested_first_boot_seeds_state: " & Stager & " does not " &
         "require python3 in its tool check, so a PATH without it fails at " &
         "the seed step instead of at the top. The list it does require " &
         "is: " & stagerTools.join(" "))
    return
  pass("t_attested_first_boot_seeds_state: " & Stager & " binds " &
       "STATE_SEED_TOOL exactly once, to the repository-root " & SeedTool &
       ", detaches the " &
       "state and re-checks it with --attested, in that order and after " &
       "the configuration, each refusing from its own construct, and " &
       "python3 is a WORD of its required-tool list")

  # (c) The seed tool is an input of the staged tree, because it decides
  #     what the tree contains.
  let inputs = nimListArg(recipe, "let stageInstalledRootAction = shell(",
                          "extraInputs")
  if inputs.len == 0:
    fail("t_attested_first_boot_seeds_state: could not read the " &
         "extraInputs argument of the staging action in " & ImageRecipe)
    return
  var undeclared: seq[string] = @[]
  for tool in [SeedTool, InodePolicy]:
    if ("\"" & tool & "\"") notin inputs: undeclared.add tool
  if undeclared.len > 0:
    fail("t_attested_first_boot_seeds_state: the staging action does not " &
         "declare " & undeclared.join(" or ") & " as an input, so a change " &
         "to what counts as state would not change the tree it produces. " &
         "Read out of the extraInputs ARGUMENT: " & inputs.strip())
    return
  pass("t_attested_first_boot_seeds_state: " & ImageRecipe & " declares " &
       SeedTool & " and " & InodePolicy & " in the extraInputs ARGUMENT of " &
       "the staging action")

proc caseTheStateRootsAreOneDeclaration() =
  ## The paths the seed tool treats as state have to be exactly the paths
  ## the initramfs mounts volumes over. Two spellings would mean a volume
  ## mounted over content nothing seeded, or a seed written into the
  ## read-only root.
  let tool = readSource(SeedTool)
  let init = readSource(InitDisk)
  if tool.len == 0 or init.len == 0: return

  let declared = pythonListLiteral(tool, "STATE_ROOTS")
  if declared.len == 0:
    fail("t_attested_first_boot_seeds_state: could not read STATE_ROOTS " &
         "out of " & SeedTool & "; it is the binding this gate compares " &
         "the initramfs against")
    return
  var mounted: seq[string] = @[]
  for line in codeLines(init):
    let bare = line.strip()
    if bare.startsWith("mount_state "):
      let fields = bare.splitWhitespace()
      if fields.len >= 3: mounted.add fields[2]
  if mounted.len == 0:
    fail("t_attested_first_boot_seeds_state: " & InitDisk & " mounts no " &
         "state volumes at all; read as `mount_state <spec> <path>' calls " &
         "in code, not as a mention")
    return
  mounted.sort()
  var wanted = declared
  wanted.sort()
  if mounted != wanted:
    fail("t_attested_first_boot_seeds_state: " & SeedTool & " calls " &
         wanted.join(" ") & " state, and " & InitDisk & " mounts volumes " &
         "over " & mounted.join(" ") & ". A path in one list and not the " &
         "other is either state nothing seeds or a seed written into the " &
         "read-only root")
    return
  if StateRoots.toHashSet != wanted.toHashSet:
    fail("t_attested_first_boot_seeds_state: this gate expects " &
         StateRoots.join(" ") & " and both shipped files now say " &
         wanted.join(" "))
    return
  pass("t_attested_first_boot_seeds_state: " & SeedTool & " and " &
       InitDisk & " name the same state roots (" & wanted.join(" ") &
       "), so what is seeded and what is mounted over are one declaration")

proc caseOneReadingOfThePasswdFile() =
  ## Who the machine's accounts are is one question with one answer. The
  ## guest inode policy needs it to leave a home to its passwd owner and
  ## the seed tool needs it to seed that home with the same owner, so
  ## there is one function and the policy reads it IN ITS OWN BODY.
  let policy = readSource(InodePolicy)
  let tool = readSource(SeedTool)
  if policy.len == 0 or tool.len == 0: return

  if policy.count("def account_homes(") != 1:
    fail("t_attested_first_boot_seeds_state: " & InodePolicy & " defines " &
         $policy.count("def account_homes(") & " account_homes() " &
         "functions; two readings of the passwd file is how the seeded " &
         "home and the policed home come to disagree about its owner")
    return
  let policyCode = withoutPythonComments(policy)
  let head = policyCode.find("def __init__(")
  if head < 0:
    fail("t_attested_first_boot_seeds_state: " & InodePolicy &
         " has no Policy.__init__ to read")
    return
  var stop = policyCode.find("\n    def ", head + 1)
  if stop < 0: stop = policyCode.len
  let initBody = policyCode[head ..< stop]
  if "account_homes(" notin initBody:
    fail("t_attested_first_boot_seeds_state: Policy.__init__ in " &
         InodePolicy & " no longer calls account_homes() in its own body, " &
         "so it is a second opinion about who the accounts are rather " &
         "than a reader of the one answer. Read with comments stripped: " &
         "the old call left behind as a comment is not a call")
    return
  # …and it must not read the passwd file itself, because a re-inlined
  # loop has to. Asked as a VALUE the body would need rather than as the
  # absence of a shape, so a differently spelled copy is caught too.
  if "/etc/passwd" in initBody:
    fail("t_attested_first_boot_seeds_state: Policy.__init__ in " &
         InodePolicy & " reads /etc/passwd itself as well as calling " &
         "account_homes(); a second reading of the passwd file is exactly " &
         "what having one function was supposed to make impossible")
    return
  let toolCode = withoutPythonComments(tool)
  var imports = false
  var calls = 0
  var ownReaders: seq[string] = @[]
  for line in toolCode.splitLines():
    let bare = line.strip()
    if bare.startsWith("from reproos_image_metadata import") and
       "account_homes" in bare:
      imports = true
    elif "account_homes(" in bare:
      calls.inc
    # A re-inlined reader has to GET the passwd file's contents, and the
    # shipped tool never does: it hands the path to guest_path() to
    # resolve the tree's own symlinks and reads nothing. So a line that
    # both names the passwd file and reads something is the copy.
    if "passwd" in bare and ("read_text(" in bare or "open(" in bare or
                             "readlines(" in bare):
      ownReaders.add bare
  if not imports:
    fail("t_attested_first_boot_seeds_state: " & SeedTool & " does not " &
         "IMPORT account_homes from " & InodePolicy & "; read as the " &
         "import statement, because a copy of the loop would satisfy any " &
         "test that only asked whether the two agree on one tree")
    return
  # …and it has to USE what it imported. An import is not a dependency:
  # the defeating change here keeps the import line exactly as it is and
  # inlines a second passwd loop beside it, which is the same shape as
  # the one on the policy's side of this check and was NOT caught until
  # this pair of assertions was added.
  if calls == 0:
    fail("t_attested_first_boot_seeds_state: " & SeedTool & " imports " &
         "account_homes and never CALLS it, so the import is decoration " &
         "and something else in that file is deciding who the accounts " &
         "are. Read with comments stripped, as call sites rather than as " &
         "the import line")
    return
  if ownReaders.len > 0:
    fail("t_attested_first_boot_seeds_state: " & SeedTool & " reads the " &
         "passwd file itself (" & ownReaders[0] & ") as well as importing " &
         "account_homes; a second reading of the passwd file is exactly " &
         "what having one function was supposed to make impossible")
    return
  pass("t_attested_first_boot_seeds_state: there is exactly one " &
       "account_homes(), Policy.__init__ calls it in its own body and " &
       "reads no passwd file of its own, and " & SeedTool & " imports it, " &
       "CALLS it (" & $calls & " sites) and reads no passwd file of its " &
       "own either -- all read with comments stripped -- so the seeded " &
       "home and the policed home cannot disagree about who owns it")

proc caseTheSeedIsCopyIfAbsent(work: string) =
  ## t_seeding_is_idempotent, structural half: every line the shipped
  ## emitter writes is a copy-if-absent, and the shipped checker REFUSES
  ## any other type.
  let tree = work / "copy-if-absent"
  buildStateFixture(tree)
  let emitted = seedTool("emit", tree)
  if emitted.exitCode != 0:
    fail("t_seeding_is_idempotent: the shipped emitter failed on the " &
         "fixture root: " & emitted.output.strip())
    return
  let lines = fragmentLines(tree)
  if lines.len == 0:
    fail("t_seeding_is_idempotent: the shipped emitter wrote no seed lines " &
         "for a root that has content under both state roots")
    return
  var wrongType: seq[string] = @[]
  for fields in lines:
    if fields[0] != "C": wrongType.add fields[0] & " " & fields[1]
  if wrongType.len > 0:
    fail("t_seeding_is_idempotent: " & Fragment & " carries " &
         wrongType.join(", ") & ". Only C copies when the destination is " &
         "absent or empty; every other tmpfiles type writes on EVERY " &
         "boot, which reverts whatever the machine or its operator put " &
         "there. A seeder that re-runs unconditionally is worse than none")
    return
  pass("t_seeding_is_idempotent: all " & $lines.len & " lines the shipped " &
       "emitter wrote are C -- copy only when the destination is absent " &
       "or an empty directory -- and there is no stamp file anywhere in " &
       "the mechanism to lose")

  # …and the checker refuses the one-character change that would make a
  # line write on every boot. `f` recreates the file with the given
  # content every time.
  let fragmentPath = tree / Fragment.strip(chars = {'/'})
  let original = readFile(fragmentPath)
  var mutated: seq[string] = @[]
  var replaced = false
  for line in original.splitLines():
    if not replaced and line.startsWith("C "):
      mutated.add "f" & line[1 .. ^1]
      replaced = true
    else:
      mutated.add line
  if not replaced:
    fail("t_seeding_is_idempotent: no C line to mutate")
    return
  writeFile(fragmentPath, mutated.join("\n"))
  let refused = seedTool("check", tree)
  writeFile(fragmentPath, original)
  if refused.exitCode == 0:
    fail("t_seeding_is_idempotent: turning a C line into an f line left " &
         "the shipped checker ACCEPTING the root. An f line rewrites its " &
         "target on every boot, so that root would destroy the operator's " &
         "file every time the machine started")
    return
  if "has to be C" notin refused.output:
    fail("t_seeding_is_idempotent: the checker failed (exit " &
         $refused.exitCode & ") but not as a line-type refusal: " &
         refused.output.strip())
    return
  pass("t_seeding_is_idempotent: changing one C to f makes the shipped " &
       "checker REFUSE the root (exit " & $refused.exitCode & "), so a " &
       "line that would rewrite state on every boot cannot ship")

  # A hand-edited fragment is refused whatever was edited, because the
  # fragment has to be a FUNCTION of the factory tree the root carries.
  # Two edits that no other refusal above would notice: a line deleted,
  # and an owner changed on a line the account-home check does not cover.
  for (label, edited) in [
      ("a deleted line", block:
        var kept: seq[string] = @[]
        var dropped = false
        for line in original.splitLines():
          if not dropped and line.startsWith("C /var"):
            dropped = true
            continue
          kept.add line
        kept.join("\n")),
      ("a changed owner", original.replace("C /var/empty 0755 0 0",
                                           "C /var/empty 0755 1000 1000"))]:
    if edited == original:
      fail("t_seeding_is_idempotent: the `" & label & "' edit changed " &
           "nothing, so it tests nothing")
      return
    writeFile(fragmentPath, edited)
    let handEdited = seedTool("check", tree)
    writeFile(fragmentPath, original)
    if handEdited.exitCode == 0:
      fail("t_seeding_is_idempotent: " & label & " in " & Fragment &
           " left the shipped checker ACCEPTING the root. The fragment is " &
           "then not a function of the factory tree the root carries, and " &
           "the machine would be seeded with whatever someone last typed")
      return
    if "not what the factory tree" notin handEdited.output:
      fail("t_seeding_is_idempotent: " & label & " failed (exit " &
           $handEdited.exitCode & ") but not as a re-derivation refusal: " &
           handEdited.output.strip().splitLines()[0])
      return
  pass("t_seeding_is_idempotent: the shipped checker RE-DERIVES the " &
       "fragment from the factory tree and refuses a hand-edited one -- a " &
       "deleted line and a changed owner are both caught, neither of " &
       "which any other refusal would have noticed")

proc caseTheSeedSourceIsMeasured(work: string) =
  ## t_seed_source_is_inside_the_measurement, structural half. Every
  ## source is under the factory root, and moving one out of the measured
  ## tree is REFUSED.
  let tree = work / "measured-source"
  buildStateFixture(tree)
  if seedTool("emit", tree).exitCode != 0:
    fail("t_seed_source_is_inside_the_measurement: the shipped emitter " &
         "failed on the fixture root")
    return
  let lines = fragmentLines(tree)
  if lines.len == 0:
    fail("t_seed_source_is_inside_the_measurement: no seed lines to read")
    return
  var outside: seq[string] = @[]
  for fields in lines:
    if fields.len != 7:
      fail("t_seed_source_is_inside_the_measurement: a seed line has " &
           $fields.len & " fields: " & fields.join(" "))
      return
    if not fields[6].startsWith(FactoryRoot & "/"): outside.add fields[6]
    if not fileExists(tree / fields[6].strip(chars = {'/'})) and
       not dirExists(tree / fields[6].strip(chars = {'/'})) and
       not symlinkExists(tree / fields[6].strip(chars = {'/'})):
      fail("t_seed_source_is_inside_the_measurement: " & fields[1] &
           " is seeded from " & fields[6] & ", which is not in the tree")
      return
  if outside.len > 0:
    fail("t_seed_source_is_inside_the_measurement: " & outside.join(", ") &
         " is not under " & FactoryRoot & ". A source the root hash does " &
         "not cover is unmeasured content installed onto the running " &
         "machine, which is the surface this layout exists to remove")
    return
  pass("t_seed_source_is_inside_the_measurement: all " & $lines.len &
       " sources are under " & FactoryRoot & " and all of them are IN the " &
       "tree, so every byte the running machine is seeded with is covered " &
       "by the root hash")

  # The refusal, exercised three ways: an unmeasured volume, a path the
  # hash does not cover, and a source that simply is not there.
  let fragmentPath = tree / Fragment.strip(chars = {'/'})
  let original = readFile(fragmentPath)
  var refusedAll = true
  for (label, replacement) in [
      ("a state volume", "/var/factory"),
      ("the ESP", "/boot/factory"),
      ("a runtime path", "/run/factory")]:
    writeFile(fragmentPath, original.replace(FactoryRoot, replacement))
    let refused = seedTool("check", tree)
    if refused.exitCode == 0:
      fail("t_seed_source_is_inside_the_measurement: moving every seed " &
           "source to " & replacement & " (" & label & ") left the shipped " &
           "checker ACCEPTING the root. Seeding from there installs bytes " &
           "the root hash does not name")
      refusedAll = false
      break
    if "inside the measured root" notin refused.output:
      fail("t_seed_source_is_inside_the_measurement: the " & label &
           " case failed (exit " & $refused.exitCode & ") but not as a " &
           "measurement refusal: " & refused.output.strip())
      refusedAll = false
      break
  writeFile(fragmentPath, original)
  if not refusedAll: return
  pass("t_seed_source_is_inside_the_measurement: moving the seed source " &
       "onto a state volume, onto the ESP or into /run is REFUSED in all " &
       "three cases, each naming the measurement as the reason")

  # And the whole factory tree really being gone is refused too, which is
  # what a root that declares a seed it cannot perform looks like.
  moveDir(tree / FactoryRoot.strip(chars = {'/'}), tree / "var/factory-moved")
  let gone = seedTool("check", tree)
  moveDir(tree / "var/factory-moved", tree / FactoryRoot.strip(chars = {'/'}))
  if gone.exitCode == 0:
    fail("t_seed_source_is_inside_the_measurement: with the factory tree " &
         "moved out from under it the shipped checker still ACCEPTED the " &
         "root, so the fragment is checked as text and never against the " &
         "bytes it names")
    return
  pass("t_seed_source_is_inside_the_measurement: a fragment whose factory " &
       "tree is not in the root is REFUSED (exit " & $gone.exitCode &
       "), so the check is against the bytes and not against the text")

proc caseTheAccountHomeIsSeeded(work: string) =
  ## The account the installer configured must have a home on the volume
  ## that gets mounted, owned by it.
  let tree = work / "account-home"
  buildStateFixture(tree)
  if seedTool("emit", tree).exitCode != 0:
    fail("t_attested_first_boot_seeds_state: the shipped emitter failed")
    return
  let guest = "/home/" & PolicyFixtureUser
  var found: seq[string] = @[]
  for fields in fragmentLines(tree):
    if fields[1] == guest: found = fields
  if found.len == 0:
    fail("t_attested_first_boot_seeds_state: nothing seeds " & guest &
         ", which is the home /etc/passwd gives the configured account. " &
         "/home is mounted empty over this root, so that account would " &
         "have no home directory and no session")
    return
  if found[3] != $PolicyFixtureUid or found[4] != $PolicyFixtureGid:
    fail("t_attested_first_boot_seeds_state: " & guest & " is seeded as " &
         found[3] & ":" & found[4] & " and /etc/passwd gives the account " &
         $PolicyFixtureUid & ":" & $PolicyFixtureGid & "; the home would " &
         "land owned by someone who cannot write to it")
    return
  pass("t_attested_first_boot_seeds_state: the account home " & guest &
       " is seeded with the uid and gid /etc/passwd gives it (" & found[3] &
       ":" & found[4] & "), read out of the line the shipped emitter wrote")

  # Removing the seeded home is refused, because that is the exact defect
  # this gate exists for: a configured account with nowhere to log in.
  removeDir(tree / FactoryRoot.strip(chars = {'/'}) / "home" /
            PolicyFixtureUser)
  let refused = seedTool("check", tree)
  if refused.exitCode == 0:
    fail("t_attested_first_boot_seeds_state: with the account home taken " &
         "out of the factory tree the shipped checker still ACCEPTED the " &
         "root -- which is precisely the image that boots, verifies, and " &
         "offers no session")
    return
  pass("t_attested_first_boot_seeds_state: a root that seeds no home for " &
       "an account /etc/passwd declares is REFUSED (exit " &
       $refused.exitCode & ")")

proc caseTheStateIsDetached(work: string) =
  ## t_seed_source_is_inside_the_measurement, the other half: nothing may
  ## be left under a state root in a tree that is about to be hashed.
  let tree = work / "detached"
  buildStateFixture(tree)
  if seedTool("emit", tree).exitCode != 0:
    fail("t_seed_source_is_inside_the_measurement: the shipped emitter " &
         "failed")
    return
  let beforeDetach = seedTool("check", tree, "--attested")
  if beforeDetach.exitCode == 0:
    fail("t_seed_source_is_inside_the_measurement: a tree whose /var and " &
         "/home are still full passed the attested check, so the check " &
         "cannot tell a separated root from an unseparated one")
    return
  if seedTool("detach", tree).exitCode != 0:
    fail("t_seed_source_is_inside_the_measurement: the shipped detach " &
         "failed on a tree it had just seeded")
    return
  for stateRoot in StateRoots:
    let path = tree / stateRoot.strip(chars = {'/'})
    if not dirExists(path):
      fail("t_seed_source_is_inside_the_measurement: detach removed the " &
           stateRoot & " mount point itself; the initramfs needs it to " &
           "mount the volume over")
      return
    var left: seq[string] = @[]
    for kind, child in walkDir(path):
      left.add child.extractFilename
    if left.len > 0:
      fail("t_seed_source_is_inside_the_measurement: " & stateRoot &
           " still holds " & left.join(", ") & " after detach")
      return
  let after = seedTool("check", tree, "--attested")
  if after.exitCode != 0:
    fail("t_seed_source_is_inside_the_measurement: the detached tree does " &
         "not pass the attested check: " & after.output.strip())
    return
  pass("t_seed_source_is_inside_the_measurement: after the shipped detach " &
       "both state roots are EMPTY mount points, the factory copy is " &
       "still inside the tree, and the attested check accepts it -- and " &
       "it did NOT accept the same tree before the detach")

  # A single leftover file has to be enough to stop it, because a single
  # leftover file is invisible to the running machine.
  writeFile(tree / "var/left-behind", "shadowed\n")
  let leftover = seedTool("check", tree, "--attested")
  removeFile(tree / "var/left-behind")
  if leftover.exitCode == 0:
    fail("t_seed_source_is_inside_the_measurement: one file left under " &
         "/var passed the attested check. It is inside the measurement, " &
         "invisible to the running machine, and nothing would ever say so")
    return
  pass("t_seed_source_is_inside_the_measurement: ONE file left under /var " &
       "is enough to be REFUSED (exit " & $leftover.exitCode & ")")

  # …and detaching a tree that was never seeded is refused rather than
  # performed, because that would delete content nothing would seed back.
  let unseeded = work / "unseeded"
  buildStateFixture(unseeded)
  let blind = seedTool("detach", unseeded)
  if blind.exitCode == 0:
    fail("t_seed_source_is_inside_the_measurement: detach emptied the " &
         "state roots of a tree that declares no seed, which deletes " &
         "content nothing would ever put back")
    return
  if not fileExists(unseeded / "var/lib/reproos/install-source"):
    fail("t_seed_source_is_inside_the_measurement: detach refused and " &
         "deleted anyway")
    return
  pass("t_seed_source_is_inside_the_measurement: detaching a tree that " &
       "carries no seed is REFUSED (exit " & $blind.exitCode & ") and " &
       "nothing is deleted")

# =====================================================================
# Layer 2 -- opt-in. A real disk, a real dm-verity activation, the real
# seeder, twice, with the state modified in between.
# =====================================================================

proc gateSkipRemedy(): string =
  "  Run it with " & GateEnv & "=1.\n" &
  "  It configures a root with the shipped configure-installed-root.sh,\n" &
  "  seeds and detaches it with the shipped tool, images it with the\n" &
  "  shipped build-verity-root.sh, applies the real " & AttestedLayout &
  " layout\n" &
  "  to a transient qcow2 over a loopback NBD node, and then ACTIVATES\n" &
  "  that disk TWICE through dm-verity -- running the real\n" &
  "  systemd-tmpfiles the image ships over the real /var and /home\n" &
  "  partitions each time, with the state modified in between. It needs\n" &
  "  sudo, the nbd module, qemu-nbd, sgdisk, veritysetup, mkfs.ext4 and\n" &
  "  the from-source systemd, and takes about four minutes."

proc findReproBinary(): string =
  for cand in [getEnv("REPRO_BIN"),
               RepoRoot / "build/bin/repro",
               RepoRoot.parentDir / "reprobuild/build/bin/repro"]:
    if cand.len > 0 and fileExists(cand):
      return cand
  findExe("repro")

proc packagesRoot(): string =
  let fromEnv = getEnv(PackagesRootEnv)
  if fromEnv.len > 0: fromEnv
  else: RepoRoot.parentDir() / "reprobuild-packages"

proc sourceInstallRoot(pkg: string): string =
  packagesRoot() / "packages" / "source" / pkg / ".repro" / "output" / "install"

proc systemdLibraryPath(): string =
  ## Where the from-source ``systemd-tmpfiles`` finds its shared
  ## libraries: every from-source install mirror on this host EXCEPT the
  ## ones that carry a libc. Putting a newer libc first breaks the
  ## process before ``main``.
  var parts = @[sourceInstallRoot("systemd") / "usr/lib/systemd"]
  let root = packagesRoot() / "packages" / "source"
  var names: seq[string] = @[]
  for kind, path in walkDir(root):
    if kind == pcDir: names.add path.extractFilename
  names.sort()
  for name in names:
    if name in LibcCarryingPackages: continue
    for sub in ["usr/lib", "usr/lib64"]:
      let dir = sourceInstallRoot(name) / sub
      if dirExists(dir): parts.add dir
  parts.join(":")

proc buildConfigBundle(dir, autoConfig: string) =
  ## The canonical bundle ``reproos-installer --emit-artifacts`` writes.
  ## The installer is a CMake target this gate does not build, so the four
  ## rendered documents beside the config are placeholders: the phase that
  ## consumes them copies them verbatim, and what is under test here is
  ## the SEED, not the renderer. Stated so nobody reads more into a green
  ## run than it says.
  createDir(dir)
  copyFile(autoConfig, dir / "auto-config.toml")
  for f in ["system.nim", "hardware.nim", "disko.json", "home.nim"]:
    writeFile(dir / f, "# emitted-artifact placeholder for the seed gate\n")

proc partitionGuidOnDisk(sudo, device: string; num: int): string =
  let r = run(sudo & " sgdisk -i " & $num & " " & device & " 2>/dev/null")
  if r.exitCode != 0: return ""
  for line in r.output.splitLines():
    if "Partition unique GUID" in line:
      let colon = line.find(':')
      if colon >= 0:
        return line[colon + 1 .. ^1].strip().toLowerAscii()
  ""

proc valueAfter(cmdline, key: string): string =
  for token in cmdline.split(' '):
    if token.startsWith(key & "="):
      return token[key.len + 1 .. ^1]
  ""

proc partitionWithLabel(sudo, device, label: string): string =
  ## The partition of THIS disk whose ext4 label matches. Scoped to the
  ## device on purpose: a `blkid -L` sweep would answer with whatever
  ## else on this host happens to carry the name.
  for num in 1 .. 8:
    let part = device & "p" & $num
    if not fileExists("/sys/class/block/" & part.extractFilename & "/dev"):
      continue
    let r = run(sudo & " blkid -o value -s LABEL " & part & " 2>/dev/null")
    if r.exitCode == 0 and r.output.strip() == label:
      return part
  ""

proc passwdOwner(tree, account: string): string =
  ## ``<uid> <gid>`` for ``account`` as the CONFIGURED tree's own
  ## ``/etc/passwd`` gives it.
  ##
  ## Read out of the tree rather than taken from the fixture constants:
  ## the shipped configuration rewrites the passwd file from the
  ## operator's config, so the fixture's idea of the account is stale by
  ## the time the seed is emitted -- and what the seed has to agree with
  ## is the configured answer, not this gate's.
  for line in readFile(tree / "etc/passwd").splitLines():
    let fields = line.split(':')
    if fields.len == 7 and fields[0] == account:
      return fields[2] & " " & fields[3]
  ""

proc statOf(sudo, path: string): string =
  let r = run(sudo & " stat -c '%04a %u %g' " & quoteShell(path) & " 2>&1")
  if r.exitCode != 0: return ""
  r.output.strip()

proc readAsRoot(sudo, path: string): string =
  let r = run(sudo & " cat " & quoteShell(path) & " 2>/dev/null")
  if r.exitCode != 0: return ""
  r.output

proc runLayer2(workRoot: string) =
  if getEnv(GateEnv) != "1":
    skip("t_attested_first_boot_seeds_state: the behavioural half did not " &
         "run (" & GateEnv & " is not 1).\n" &
         "  NO disk was written, NO dm-verity device was activated and " &
         "the seeder\n  was never run over a real /var or /home.\n" &
         gateSkipRemedy())
    skip("t_seeding_is_idempotent: nothing was activated twice and no " &
         "state was\n  modified between activations.\n" & gateSkipRemedy())
    skip("t_seed_source_is_inside_the_measurement: the seed was not read " &
         "back out of\n  an image a root hash covers.\n" & gateSkipRemedy())
    return

  var missing: seq[string] = @[]
  for tool in Layer2Tools:
    if findExe(tool).len == 0: missing.add tool
  if missing.len > 0:
    fail("t_attested_first_boot_seeds_state: requested, but these tools " &
         "are not on PATH: " & missing.join(", ") & ". This gate does not " &
         "skip for a missing tool when it was asked for: a green run that " &
         "seeded nothing would be worse than a red one.")
    return

  let tmpfilesBin = sourceInstallRoot("systemd") / "usr/bin/systemd-tmpfiles"
  let systemdTmpfilesD = sourceInstallRoot("systemd") / "usr/lib/tmpfiles.d"
  if not fileExists(tmpfilesBin) or not dirExists(systemdTmpfilesD):
    fail("t_attested_first_boot_seeds_state: requested, but the " &
         "from-source systemd is not built on this host (" & tmpfilesBin &
         "). This gate runs the REAL seeder the image ships and will not " &
         "substitute another one for it. Build it with `repro build " &
         "systemdSource` in the reprobuild-packages sibling, or point " &
         PackagesRootEnv & " at a tree that has it.")
    return
  let libraryPath = systemdLibraryPath()
  let tmpfilesEnv = "LD_LIBRARY_PATH=" & quoteShell(libraryPath) & " "
  let version = run(tmpfilesEnv & quoteShell(tmpfilesBin) & " --version 2>&1")
  if version.exitCode != 0:
    fail("t_attested_first_boot_seeds_state: the from-source " &
         "systemd-tmpfiles will not run on this host: " &
         version.output.strip())
    return
  let tmpfilesVersion = version.output.splitLines()[0].strip()

  let reproBin = findReproBinary()
  if reproBin.len == 0:
    fail("t_attested_first_boot_seeds_state: no `repro` binary; the " &
         "partition table is written by `repro disk apply` and this gate " &
         "will not substitute for it")
    return

  let sudo = findExe("sudo")
  let work = workRoot / "state-seed"
  removeDir(work)
  createDir(work)

  let configText = readSource(AutoConfigFixture)
  if configText.len == 0: return
  var request = diskLayouts.parseDiskLayoutRequest(
    configText, "reproos-state-seed-gate", "/dev/nbd0")
  request.name = AttestedLayout
  request.params.diskSizeGb = 20
  let seed = diskLayouts.reproosImageIdentitySeed(
    configText, packageSets.ReproosGraphicalRootfsPackages, request)
  if seed.len == 0:
    fail("t_attested_first_boot_seeds_state: no identity seed")
    return

  # --- the root, configured by the SHIPPED script
  let tree = work / "installed-root"
  createDir(tree)
  buildStateFixture(tree)
  # The tmpfiles fragments systemd itself ships. They are in a real
  # ReproOS root because the staged rootfs mirrors this same install
  # tree, and they are what makes /var usable -- /var/log, /var/lib,
  # /var/cache and /var/spool are systemd's own `var.conf`, and /var/tmp
  # is its `tmp.conf`. ALL of them are copied, not a chosen few: which
  # fragment declares what is systemd's business, and picking would make
  # this gate a second opinion about it.
  for kind, path in walkDir(systemdTmpfilesD):
    if kind == pcFile and path.endsWith(".conf"):
      copyFile(path, tree / "usr/lib/tmpfiles.d" / path.extractFilename)
  let bundle = work / "configuration"
  buildConfigBundle(bundle, RepoRoot / AutoConfigFixture)
  let configureCmd =
    "cd " & quoteShell(RepoRoot / "recipes/reproos-image") & " && " &
    "REPROOS_CONFIG_BUNDLE_DIR=" & quoteShell(bundle) & " " &
    "REPROOS_WORK_DIR=" & quoteShell(work / "work") & " " &
    "REPROOS_SOURCE_RECIPES_ROOT=" &
      quoteShell(work / "absent-source-mirrors") & " " &
    "bash " & quoteShell(RepoRoot / Configurer) & " " & quoteShell(tree)
  if not sh(configureCmd):
    fail("t_attested_first_boot_seeds_state: the shipped " & Configurer &
         " failed on the fixture root; nothing was seeded")
    return
  if not fileExists(tree / Fragment.strip(chars = {'/'})):
    fail("t_attested_first_boot_seeds_state: the shipped configuration " &
         "left no " & Fragment & " in the tree, so nothing declares how " &
         "the state volumes are seeded")
    return
  # The attested half the stager performs. Driven here directly because
  # `stage-installed-root.sh` also needs the compiled installer and
  # `repro infra install-root`; the always-on layer above is what asserts
  # the shipped stager is the thing that does this in production.
  if not sh(findExe("python3") & " " & quoteShell(RepoRoot / SeedTool) &
            " detach " & quoteShell(tree)):
    fail("t_attested_first_boot_seeds_state: the shipped detach failed")
    return
  if not sh(findExe("python3") & " " & quoteShell(RepoRoot / SeedTool) &
            " check " & quoteShell(tree) & " --attested"):
    fail("t_attested_first_boot_seeds_state: the configured, detached " &
         "tree does not pass the shipped attested check")
    return

  # --- the image of it, and its root hash
  let verityDir = work / "verity"
  let spec = verity.verityRootSpec(seed)
  if not sh("SOURCE_DATE_EPOCH=1735689600 LC_ALL=C TZ=UTC " &
            "REPROOS_STAGED_ROOTFS=" & quoteShell(tree) & " " &
            "REPROOS_VERITY_SALT=" & quoteShell(spec.salt) & " " &
            "REPROOS_VERITY_UUID=" & quoteShell(spec.uuid) & " " &
            "REPROOS_VERITY_FS_UUID=" &
              quoteShell(verity.verityRootFsUuid(seed)) & " " &
            "REPROOS_VERITY_FS_HASH_SEED=" &
              quoteShell(verity.verityRootFsHashSeed(seed)) & " " &
            "bash " & quoteShell(RepoRoot / VerityBuilder) & " " &
            quoteShell(verityDir)):
    fail("t_attested_first_boot_seeds_state: the shipped " & VerityBuilder &
         " failed over the configured tree")
    return
  let dataImage = verityDir / verity.VerityDataImageFileName
  let hashTree = verityDir / verity.VerityHashTreeFileName
  let rootHashFile = verityDir / verity.VerityRootHashFileName
  for f in [dataImage, hashTree, rootHashFile]:
    if not fileExists(f):
      fail("t_attested_first_boot_seeds_state: the builder produced no " &
           f.extractFilename)
      return
  let builtRootHash = readFile(rootHashFile).strip()

  # --- the command line an attested unified kernel image would carry.
  #     Every device below is read back OUT of it.
  let devices = generations.attestedBootDevices(seed, generations.gsA)
  let cmdline = ukiModule.attestedKernelCmdline(
    builtRootHash, devices.data, devices.hash,
    devices.stateVar, devices.stateHome)
  let cmdlineError = ukiModule.validateAttestedCmdline(cmdline, builtRootHash)
  if cmdlineError.len > 0:
    fail("t_attested_first_boot_seeds_state: " & cmdlineError)
    return
  let measuredHash = valueAfter(cmdline, verity.VerityRootHashCmdlineKey)
  let measuredData = valueAfter(cmdline, verity.VerityDataDeviceCmdlineKey)
  let measuredHashDev = valueAfter(cmdline, verity.VerityHashDeviceCmdlineKey)
  let measuredVar = valueAfter(cmdline, verity.VerityStateVarCmdlineKey)
  let measuredHome = valueAfter(cmdline, verity.VerityStateHomeCmdlineKey)
  if measuredHash.len != 64 or not measuredVar.startsWith("LABEL=") or
     not measuredHome.startsWith("LABEL="):
    fail("t_attested_first_boot_seeds_state: the command line does not " &
         "carry a root hash and two state-volume specifiers to read back: " &
         cmdline)
    return

  # --- a real disk, and the real apply
  let qcow2 = work / "state-seed.qcow2"
  if not sh(findExe("qemu-img") & " create -f qcow2 " & quoteShell(qcow2) &
            " " & $request.params.diskSizeGb & "G"):
    fail("t_attested_first_boot_seeds_state: qemu-img create failed")
    return
  if not sh(sudo & " modprobe nbd max_part=16"):
    fail("t_attested_first_boot_seeds_state: the nbd module could not be " &
         "loaded")
    return
  var nbdDev = ""
  for n in 0 .. 15:
    if dirExists("/sys/block/nbd" & $n) and
       not fileExists("/sys/block/nbd" & $n & "/pid"):
      nbdDev = "/dev/nbd" & $n
      break
  if nbdDev.len == 0:
    fail("t_attested_first_boot_seeds_state: no free /dev/nbdN")
    return

  let dmName = VmNamePrefix & $getCurrentProcessId()
  let rootMount = work / "mnt"
  createDir(rootMount)
  var connected = false
  var opened = false

  template teardown() =
    for point in [rootMount & "/home", rootMount & "/var", rootMount]:
      discard run(sudo & " umount " & quoteShell(point) & " 2>/dev/null")
    if opened:
      discard run(sudo & " veritysetup close " & dmName & " 2>/dev/null")
      opened = false
    if connected:
      discard run(sudo & " " & findExe("qemu-nbd") & " --disconnect " & nbdDev)
      connected = false
    if getEnv(KeepEnv) != "1":
      removeDir(work)

  if not sh(sudo & " " & findExe("qemu-nbd") & " --connect=" & nbdDev &
            " --cache=writeback -f qcow2 " & quoteShell(qcow2)):
    fail("t_attested_first_boot_seeds_state: qemu-nbd could not connect " &
         nbdDev)
    teardown()
    return
  connected = true

  try:
    discard run("sleep 2")
    let diskoPath = work / "disko.json"
    writeFile(diskoPath, diskLayouts.renderDiskoJson(
      AttestedLayout,
      diskLayouts.DiskLayoutParams(
        id: request.params.id,
        device: nbdDev,
        espSizeMib: request.params.espSizeMib,
        diskSizeGb: request.params.diskSizeGb)))
    writeFile(work / "disko.identity.json",
      diskLayouts.renderDiskIdentityJson(
        configText, packageSets.ReproosGraphicalRootfsPackages, request))
    if not sh(sudo & " env PATH=$PATH SOURCE_DATE_EPOCH=1735689600 LC_ALL=C " &
              "TZ=UTC " & quoteShell(reproBin) & " disk apply --device " &
              nbdDev & " --confirm " & quoteShell(diskoPath)):
      fail("t_attested_first_boot_seeds_state: `repro disk apply` failed " &
           "on the " & AttestedLayout & " document")
      return
    discard run(sudo & " partprobe " & nbdDev & " 2>/dev/null")
    discard run("sleep 2")

    # --- the pair, written onto the carriers by the SHIPPED writer
    if not sh("SUDO=" & quoteShell(sudo) & " " &
              "REPROOS_VERITY_CARRIER_VERIFY=1 " &
              "REPROOS_VERITY_DATA_IMAGE=" & quoteShell(dataImage) & " " &
              "REPROOS_VERITY_HASH_TREE=" & quoteShell(hashTree) & " " &
              "REPROOS_VERITY_ROOTHASH_FILE=" & quoteShell(rootHashFile) &
              " REPROOS_VERITY_DATA_DEVICE=" & quoteShell(measuredData) &
              " REPROOS_VERITY_HASH_DEVICE=" & quoteShell(measuredHashDev) &
              " bash " & quoteShell(RepoRoot / CarrierWriter) & " " & nbdDev):
      fail("t_attested_first_boot_seeds_state: the shipped " & CarrierWriter &
           " failed")
      return

    var dataPart, hashPart = ""
    for num in 1 .. 8:
      let guid = partitionGuidOnDisk(sudo, nbdDev, num)
      if guid.len == 0: continue
      if guid == measuredData["PARTUUID=".len .. ^1].toLowerAscii():
        dataPart = nbdDev & "p" & $num
      elif guid == measuredHashDev["PARTUUID=".len .. ^1].toLowerAscii():
        hashPart = nbdDev & "p" & $num
    let varPart = partitionWithLabel(sudo, nbdDev,
                                     measuredVar["LABEL=".len .. ^1])
    let homePart = partitionWithLabel(sudo, nbdDev,
                                      measuredHome["LABEL=".len .. ^1])
    if dataPart.len == 0 or hashPart.len == 0 or varPart.len == 0 or
       homePart.len == 0:
      fail("t_attested_first_boot_seeds_state: the command line's own " &
           "specifiers do not all resolve on the disk that was just " &
           "written (root -> " & dataPart & ", hash -> " & hashPart &
           ", /var -> " & varPart & ", /home -> " & homePart & ")")
      return

    # The state volumes really are EMPTY as the layout creates them.
    # Without this the whole gate could be measuring content that was
    # never seeded at all.
    if not sh(sudo & " mount " & varPart & " " & quoteShell(rootMount)):
      fail("t_attested_first_boot_seeds_state: the /var volume could not " &
           "be mounted to check that the apply leaves it empty")
      return
    var preexisting: seq[string] = @[]
    for kind, child in walkDir(rootMount):
      let name = child.extractFilename
      if name != "lost+found": preexisting.add name
    discard run(sudo & " umount " & quoteShell(rootMount))
    if preexisting.len > 0:
      fail("t_attested_first_boot_seeds_state: the freshly applied /var " &
           "volume already holds " & preexisting.join(", ") & "; this gate " &
           "would then not be measuring the seed")
      return

    # =================================================================
    # ACTIVATION 1 -- the disk brought up the way the initramfs does.
    # =================================================================
    template activate(label: string): bool =
      block:
        var ok = true
        if not sh(sudo & " veritysetup verify " & dataPart & " " & hashPart &
                  " " & measuredHash):
          fail("t_attested_first_boot_seeds_state: at " & label & " the " &
               "installed pair does not verify against the root hash the " &
               "measured command line pins (" & measuredHash & ")")
          ok = false
        elif not sh(sudo & " veritysetup open " & dataPart & " " & dmName &
                    " " & hashPart & " " & measuredHash):
          fail("t_attested_first_boot_seeds_state: at " & label &
               " veritysetup could not activate the root")
          ok = false
        else:
          opened = true
          if not sh(sudo & " mount -o ro /dev/mapper/" & dmName & " " &
                    quoteShell(rootMount)):
            fail("t_attested_first_boot_seeds_state: at " & label &
                 " the dm-verity root could not be mounted read-only")
            ok = false
        ok

    template mountState(label: string): bool =
      block:
        var ok = true
        if not sh(sudo & " mount " & varPart & " " &
                  quoteShell(rootMount / "var")):
          fail("t_attested_first_boot_seeds_state: at " & label &
               " the /var volume could not be mounted over the root")
          ok = false
        elif not sh(sudo & " mount " & homePart & " " &
                    quoteShell(rootMount / "home")):
          fail("t_attested_first_boot_seeds_state: at " & label &
               " the /home volume could not be mounted over the root")
          ok = false
        ok

    template seedNow(label: string): bool =
      block:
        let r = run(sudo & " env " & tmpfilesEnv & quoteShell(tmpfilesBin) &
                    " --root=" & quoteShell(rootMount) &
                    " --create --remove --boot --exclude-prefix=/dev 2>&1")
        # systemd's own unit treats DATAERR and CANTCREAT as success, and
        # this fixture has no `utmp` group for `var.conf` to resolve, so
        # the exit status is not the assertion. What the seeder produced
        # is, and every assertion below reads it off the mounted volumes.
        if r.output.len > 0:
          echo "    [" & label & " seeder] " &
               r.output.strip().splitLines().join("\n    ")
        true

    template deactivate() =
      discard run(sudo & " umount " & quoteShell(rootMount / "home"))
      discard run(sudo & " umount " & quoteShell(rootMount / "var"))
      discard run(sudo & " umount " & quoteShell(rootMount))
      discard run(sudo & " sync")
      discard run(sudo & " veritysetup close " & dmName)
      opened = false

    if not activate("the first activation"): return

    # The seed source is INSIDE the measurement, read out of the
    # dm-verity device rather than out of the file it was made from --
    # and the state roots in that root are EMPTY, which is what makes the
    # seeding necessary rather than decorative.
    let seededProfileInImage =
      rootMount / FactoryRoot.strip(chars = {'/'}) / "home" /
      PolicyFixtureUser / ".profile"
    if readAsRoot(sudo, seededProfileInImage) != SeededProfileMarker:
      fail("t_seed_source_is_inside_the_measurement: the factory copy of " &
           "the account home is not inside the image the root hash covers " &
           "(looked for " & seededProfileInImage & " through /dev/mapper/" &
           dmName & "). Every byte read through that device is checked " &
           "against the Merkle tree on the way out of the block layer, so " &
           "this is the seed source being covered by the measurement and " &
           "not merely being on the disk")
      deactivate()
      return
    for stateRoot in StateRoots:
      var inRoot: seq[string] = @[]
      for kind, child in walkDir(rootMount / stateRoot.strip(chars = {'/'})):
        inRoot.add child.extractFilename
      if inRoot.len > 0:
        fail("t_seed_source_is_inside_the_measurement: the measured root " &
             "still carries " & inRoot.join(", ") & " under " & stateRoot &
             ", which the state volume shadows")
        deactivate()
        return
    pass("t_seed_source_is_inside_the_measurement: read back through " &
         "/dev/mapper/" & dmName & " -- a device that checks every block " &
         "against the tree the measured command line names -- the factory " &
         "copy of the account home IS in the root, and " &
         StateRoots.join(" and ") & " in that root are empty mount points")

    if not mountState("the first activation"):
      deactivate()
      return
    discard seedNow("boot 1")

    let homeDir = rootMount / "home" / PolicyFixtureUser
    let profile = homeDir / ".profile"
    let keep = homeDir / ".config/keep"
    let installSource = rootMount / "var/lib/reproos/install-source"
    var absent: seq[string] = @[]
    if readAsRoot(sudo, profile) != SeededProfileMarker:
      absent.add ".profile"
    if readAsRoot(sudo, keep) != SeededKeepMarker:
      absent.add ".config/keep"
    if readAsRoot(sudo, installSource).strip() != "direct-image-assembly":
      absent.add "var/lib/reproos/install-source"
    if absent.len > 0:
      fail("t_attested_first_boot_seeds_state: after the first activation " &
           absent.join(", ") & " is not on the state volumes. The account " &
           "the installer configured has no home and the first-boot units " &
           "have no receipt to read")
      deactivate()
      return
    let configuredOwner = passwdOwner(tree, PolicyFixtureUser)
    if configuredOwner.len == 0:
      fail("t_attested_first_boot_seeds_state: the configured tree's " &
           "/etc/passwd has no record for " & PolicyFixtureUser)
      deactivate()
      return
    let homeOwner = statOf(sudo, homeDir)
    if homeOwner != "0755 " & configuredOwner:
      fail("t_attested_first_boot_seeds_state: the seeded home is " &
           homeOwner & " on the /home volume, and the CONFIGURED " &
           "/etc/passwd inside the measured root gives the account " &
           configuredOwner & ". A home the account cannot write to is not " &
           "a session either")
      deactivate()
      return
    let profileOwner = statOf(sudo, profile)
    if not profileOwner.endsWith(configuredOwner):
      fail("t_attested_first_boot_seeds_state: the seeded home's CONTENTS " &
           "are " & profileOwner & ", not owned by the account (" &
           configuredOwner & "). The copy reached the volume but landed " &
           "unusable")
      deactivate()
      return
    # /var usable: systemd's own factory content, which is inside the same
    # measured root, plus the ReproOS lines.
    var missingVar: seq[string] = @[]
    for rel in ["var/log", "var/lib", "var/cache", "var/spool", "var/tmp",
                "var/empty", "var/lib/dbus/machine-id"]:
      if not (dirExists(rootMount / rel) or fileExists(rootMount / rel) or
              symlinkExists(rootMount / rel)):
        missingVar.add "/" & rel
    if missingVar.len > 0:
      fail("t_attested_first_boot_seeds_state: /var is not usable after " &
           "the first activation -- " & missingVar.join(", ") & " missing")
      deactivate()
      return
    pass("t_attested_first_boot_seeds_state: on a real " & AttestedLayout &
         " disk, with the root activated through dm-verity against the " &
         "hash on its own measured command line and the real " &
         varPart & " and " & homePart & " mounted over it, " &
         tmpfilesVersion & " populated the configured account's home (" &
         homeOwner & ", contents " & profileOwner & ") and made /var " &
         "usable (log, lib, cache, spool, tmp, empty and the dbus " &
         "machine-id link)")

    # --- what the machine and its operator write between the two boots
    discard run(sudo & " tee " & quoteShell(profile) & " >/dev/null <<'EOF'\n" &
                OperatorEditedProfile & "EOF")
    discard run(sudo & " tee " & quoteShell(homeDir / "notes.txt") &
                " >/dev/null <<'EOF'\n" & OperatorNewFile & "EOF")
    discard run(sudo & " rm -f " & quoteShell(keep))
    discard run(sudo & " tee " & quoteShell(installSource) &
                " >/dev/null <<'EOF'\n" & OperatorEditedInstallSource & "EOF")
    if readAsRoot(sudo, profile) != OperatorEditedProfile or
       readAsRoot(sudo, homeDir / "notes.txt") != OperatorNewFile or
       fileExists(keep):
      fail("t_seeding_is_idempotent: the changes this gate makes between " &
           "the two activations did not land, so the second activation " &
           "would have nothing to preserve")
      deactivate()
      return

    deactivate()

    # =================================================================
    # ACTIVATION 2 -- the same disk, again.
    # =================================================================
    if not activate("the second activation"): return
    if not mountState("the second activation"):
      deactivate()
      return
    discard seedNow("boot 2")

    var reverted: seq[string] = @[]
    if readAsRoot(sudo, profile) != OperatorEditedProfile:
      reverted.add ".profile was rewritten back to the factory copy"
    if readAsRoot(sudo, homeDir / "notes.txt") != OperatorNewFile:
      reverted.add "notes.txt, written on the first boot, is gone"
    if fileExists(keep):
      reverted.add ".config/keep, deleted on the first boot, came back"
    if readAsRoot(sudo, installSource) != OperatorEditedInstallSource:
      reverted.add "var/lib/reproos/install-source was rewritten"
    if reverted.len > 0:
      fail("t_seeding_is_idempotent: the second activation REVERTED " &
           "state: " & reverted.join("; ") & ". A seeder that re-runs " &
           "unconditionally is worse than none, because it destroys the " &
           "operator's data on every reboot")
      deactivate()
      return
    pass("t_seeding_is_idempotent: the disk was activated a SECOND time " &
         "through dm-verity and seeded again by " & tmpfilesVersion &
         ", and nothing it did touched the state: the edited .profile is " &
         "still the edit, the file created on the first boot is still " &
         "there, the deleted one is still deleted, and the rewritten " &
         "/var receipt is still the rewrite")

    # The root itself was not written to by either seeding pass, which is
    # the other half of "it did not run again": a seeder that repaired the
    # root would have broken the hash.
    if not sh(sudo & " veritysetup verify " & dataPart & " " & hashPart &
              " " & measuredHash):
      fail("t_attested_first_boot_seeds_state: after two activations and " &
           "two seeding passes the root no longer verifies against " &
           measuredHash & ", so the seeder wrote into the measured root")
      deactivate()
      return
    pass("t_attested_first_boot_seeds_state: after both activations and " &
         "both seeding passes `veritysetup verify` still walks the whole " &
         "tree on " & dataPart & " / " & hashPart & " and accepts it " &
         "against the hash on the measured command line, so everything " &
         "the seeder wrote went to the state volumes and nothing went to " &
         "the root")

    # --- THE CONTROL. Without it, the idempotence result above could
    #     come from assertions that cannot tell a clobber from a no-op.
    let factoryHome =
      rootMount / FactoryRoot.strip(chars = {'/'}) / "home" / PolicyFixtureUser
    # `cp -aT src dst` merges the SOURCE DIRECTORY into the destination
    # directory. Spelled with -T rather than as `src/.`, because Nim's
    # path join swallows a trailing `.` and the copy then lands one level
    # down, changes nothing, and quietly makes this control vacuous --
    # which is how it failed the first time it was run.
    if not sh(sudo & " cp -aT " & quoteShell(factoryHome) & " " &
              quoteShell(homeDir)):
      fail("t_seeding_is_idempotent: the control copy failed, so the " &
           "assertions above are not known to be able to fail")
      deactivate()
      return
    var clobbered: seq[string] = @[]
    if readAsRoot(sudo, profile) == SeededProfileMarker:
      clobbered.add ".profile"
    if fileExists(keep): clobbered.add ".config/keep"
    if clobbered.len < 2:
      fail("t_seeding_is_idempotent: an UNCONDITIONAL copy of the same " &
           "factory tree over the same state changed only " &
           $clobbered.len & " of the two things the assertions above " &
           "check. Those assertions cannot distinguish a seeder that " &
           "re-runs from one that does not, and the result above is " &
           "worth nothing")
      deactivate()
      return
    pass("t_seeding_is_idempotent: CONTROL -- an unconditional copy of " &
         "the same factory tree over the same state DOES revert " &
         clobbered.join(" and ") & ", so the assertions above can tell a " &
         "seeder that re-runs from one that does not")

    deactivate()
  finally:
    teardown()

# ---------------------------------------------------------------------

when isMainModule:
  let workRoot = getEnv("REPROOS_TEST_WORK_DIR",
                        getTempDir() / "reproos-attested-state-seed")
  createDir(workRoot)
  let layer1Work = workRoot / "layer1"
  removeDir(layer1Work)
  createDir(layer1Work)

  caseTheShippedScriptsRunTheSeeder()
  caseTheStateRootsAreOneDeclaration()
  caseOneReadingOfThePasswdFile()
  caseTheSeedIsCopyIfAbsent(layer1Work)
  caseTheSeedSourceIsMeasured(layer1Work)
  caseTheAccountHomeIsSeeded(layer1Work)
  caseTheStateIsDetached(layer1Work)
  if getEnv(KeepEnv) != "1":
    removeDir(layer1Work)

  runLayer2(workRoot)

  if failures > 0:
    stderr.writeLine("attested state seed: " & $failures &
                     " check(s) failed, " & $passes & " passed, " &
                     $skips & " skipped")
    quit(1)
  echo "attested state seed: PASS (" & $passes & " checks" &
       (if skips > 0: ", " & $skips &
        " SKIPPED -- no disk was activated and nothing was seeded twice"
        else: "") & ")"
