## The order the attested image is built in.
##
## ## The defect this gate exists for
##
## An attested ReproOS root is a finished dm-verity image. Its bytes are
## named by a root hash that is baked into a unified kernel image
## firmware measures, so from the moment the hash is taken the root is
## no longer something a build may write to.
##
## The image driver used to write to it anyway. It took the hash, then
## mounted the root carrier and spent nine phases configuring the
## filesystem inside it -- hostname, fstab, accounts, services, desktop.
## Nothing failed: the verity data image is a valid ext4 at offset 0 of
## the carrier, so the mount succeeded, every phase succeeded, and the
## build exited 0. The image shipped with a root that no longer matched
## the root hash inside its own measured command line, and the only
## place that showed up was a verity failure at somebody else's first
## boot.
##
## Two properties fix it, and this gate is about both:
##
##   1. Every phase that mutates the root runs BEFORE the hash is taken.
##      The configuration moved into
##      ``scripts/stage-installed-root.sh``, which runs over a plain
##      directory; ``build-verity-root.sh`` then takes the hash over
##      that directory, and the driver installs the result.
##
##   2. The attested arm cannot mount a carrier writably. Not "does
##      not": CANNOT. A read-write mount that writes NOTHING AT ALL
##      already breaks the pair, because ext4 stamps the superblock's
##      mount state on mount -- so a rule keyed on "did anything get
##      written" would pass over an image that is already broken. Every
##      mount the driver performs goes through
##      ``scripts/mount-guard.sh``, which refuses a write-capable mount
##      of any partition a root hash covers.
##
## ## The layers
##
## Layer 1 (always on, ~1s, no tool beyond the Nim gate set) reads the
## shipped driver, the shipped stager, the shipped configuration script,
## the shipped mount guard and the shipped recipe, and checks the ORDER
## structurally: the configuration is not in the driver's attested arm,
## it is in the stager; the recipe's verity action consumes the stager's
## output and depends on it; the attested arm mirrors no root and
## normalises no inode policy on a mounted root; no mount in the driver
## bypasses the guard; and the strongest carrier check is pinned rather
## than inherited from the environment. It PROVES NOTHING about a disk.
##
## Layer 2 (opt-in, ``REPROOS_ATTESTED_ROOT_ORDER_GATE=1``, ~3 min,
## needs ``sudo`` and the ``nbd`` module) runs the real scripts against
## a real disk. It configures a purpose-built tree with the SHIPPED
## ``configure-installed-root.sh``, images it with the SHIPPED
## ``build-verity-root.sh``, renders the command line an attested UKI
## would carry with the SHIPPED ``repro/uki.nim``, applies the real
## ``uefi-attested`` layout to a real qcow2 over a loopback NBD node,
## writes the pair with the SHIPPED ``write-verity-carriers.sh``, and
## then:
##
##   * reads the root hash and the two device specifiers back OUT of
##     that command line, resolves the specifiers against the GPT, and
##     requires ``veritysetup verify`` to accept -- so the hash under
##     test is the one the command line pins, not one the gate carried;
##   * mounts the data carrier READ-ONLY and requires the files the
##     configuration wrote to be inside the measured image, which is the
##     ordering claim at the bytes;
##   * drives the shipped mount guard at the same carrier and requires a
##     REFUSAL; and
##   * falsifies the whole thing by bypassing the guard: a read-write
##     mount that writes nothing, unmounted immediately, must make the
##     same verification FAIL.
##
## What layer 2 does NOT prove: nothing boots. No unified kernel image
## is assembled, no firmware measures anything, no PCR is read, no
## ``veritysetup open`` happens and no dm-verity device is activated.
## The root is a purpose-built tree of a few megabytes and not the
## ReproOS package set. The guest inode policy
## (``tools/reproos_image_metadata.py``) IS carried into the image the
## shipped builder makes here -- that is what makes the fixture a root
## filesystem rather than a directory -- but nothing about it is checked
## in this gate. ``tests/test_attested_root_metadata.nim`` owns that
## claim, and reads the result back through the kernel.

import std/[os, osproc, strutils]

import "../repro/disk_layouts" as diskLayouts
import "../repro/generations" as generations
import "../repro/package_sets" as packageSets
import "../repro/uki" as ukiModule
import "../repro/verity" as verity
import "./root_policy_fixture"
import "./gate_layers"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()

  ImageDriver = "recipes/reproos-image/scripts/build-reproos-image.sh"
  Stager = "recipes/reproos-image/scripts/stage-installed-root.sh"
  Configurer = "recipes/reproos-image/scripts/configure-installed-root.sh"
  MountGuard = "recipes/reproos-image/scripts/mount-guard.sh"
  CarrierWriter = "recipes/reproos-image/scripts/write-verity-carriers.sh"
  VerityBuilder = "recipes/reproos-image/scripts/build-verity-root.sh"
  ImageRecipe = "recipes/reproos-image/package.nim"
  AutoConfigFixture = "tests/fixtures/auto-config-minimal.toml"

  AttestedLayout = "uefi-attested"

  GateEnv = "REPROOS_ATTESTED_ROOT_ORDER_GATE"
  KeepEnv = "REPROOS_ATTESTED_ROOT_ORDER_KEEP"

  AbsentRule = "REPROOS_NO_SUCH_ROOT_ORDER_TOKEN"
    ## A token no shipped file carries. Every matcher below is asked
    ## about it, so a matcher that matched anything would fail.

  CarrierVerifySwitch = "REPROOS_VERITY_CARRIER_VERIFY"

  Layer2Tools = ["sudo", "qemu-img", "qemu-nbd", "sgdisk", "veritysetup",
                 "mkfs.ext4", "modprobe", "dd", "blockdev", "sha256sum",
                 "mount", "umount"]

  # The directory skeleton the configuration expects of a root. A real
  # ReproOS root has all of it; a purpose-built one has to be given it,
  # and listing it here is what keeps layer 2 exercising the SHIPPED
  # script instead of a reduced copy of it.
  FixtureTreeDirs = [
    "etc/pam.d", "etc/tmpfiles.d", "etc/systemd/system", "etc/ssh",
    "etc/dbus-1", "etc/xdg", "usr/bin", "usr/sbin", "usr/lib",
    "usr/local/bin", "usr/local/sbin", "usr/local/libexec", "usr/libexec",
    "usr/share/sddm", "var/empty", "var/lib", "var/log", "home", "root",
    "boot", "run", "tmp"]

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

proc run(cmd: string): tuple[output: string, exitCode: int] =
  execCmdEx(cmd)

proc sh(cmd: string): bool =
  let r = run(cmd)
  if r.exitCode != 0:
    stderr.writeLine("  $ " & cmd)
    stderr.writeLine(r.output.strip())
  r.exitCode == 0

# ---------------------------------------------------------------------------
# Layer 1 — the order, read out of the shipped sources.
# ---------------------------------------------------------------------------

proc withoutNimComments(text: string): string =
  ## ``text`` with every Nim ``#`` comment removed, string literals kept.
  ##
  ## THIS IS LOAD-BEARING, not tidiness. Every check below that reads a
  ## binding is defeated by a comment if it does not do this: an earlier
  ## draft accepted
  ##   ``if isAttestedLayout: "…/de-rootfs" # build/installed-root``
  ## as evidence that the attested build hashes the staged installed
  ## root, and accepted ``deps = @[isoRootfs], # stageInstalledRootDeps``
  ## as evidence that the two actions are ordered. Both mutations change
  ## what the build does and leave the name on the page, which is the
  ## exact defect this gate was rewritten to stop answering yes to.
  var res = newStringOfCap(text.len)
  for line in text.splitLines():
    var inStr = false
    var cut = line.len
    var i = 0
    while i < line.len:
      let c = line[i]
      if c == '\\' and inStr:
        i.inc 2
        continue
      if c == '"':
        inStr = not inStr
      elif c == '#' and not inStr:
        cut = i
        break
      i.inc
    res.add line[0 ..< cut]
    res.add "\n"
  res

proc nimCallArg(text, callName, argName: string): string =
  ## The value of ``<argName> = …`` inside the ``<callName>(…)`` call.
  ##
  ## Read as an ARGUMENT of the call rather than as a substring anywhere
  ## in its span, so that a name left behind in a comment -- or sitting
  ## in a neighbouring argument -- is not mistaken for the binding.
  let clean = withoutNimComments(text)
  let callAt = clean.find(callName & "(")
  if callAt < 0: return ""
  var i = callAt + callName.len
  var depth = 0
  var stop = clean.len
  while i < clean.len:
    if clean[i] == '(': depth.inc
    elif clean[i] == ')':
      depth.dec
      if depth == 0:
        stop = i
        break
    i.inc
  let body = clean[callAt ..< stop]
  # Find `argName =` at a token boundary.
  var searchFrom = 0
  while true:
    let at = body.find(argName, searchFrom)
    if at < 0: return ""
    let beforeOk = at == 0 or body[at - 1] notin {'a'..'z', 'A'..'Z', '0'..'9', '_'}
    var j = at + argName.len
    while j < body.len and body[j] in {' ', '\t', '\n'}: j.inc
    if beforeOk and j < body.len and body[j] == '=' and
       (j + 1 >= body.len or body[j + 1] != '='):
      # Take everything up to the next top-level comma.
      var k = j + 1
      var d = 0
      var endAt = body.len
      while k < body.len:
        case body[k]
        of '(', '[', '{': d.inc
        of ')', ']', '}': d.dec
        of ',':
          if d <= 0:
            endAt = k
            break
        else: discard
        k.inc
      return body[(j + 1) ..< endAt].strip()
    searchFrom = at + argName.len

proc executesMount(line: string): bool =
  ## Does this shell line RUN a mount(8)?
  ##
  ## Keyed on the command actually invoked rather than on one spelling of
  ## it. An earlier draft looked only for the literal ``$HOST_MOUNT_BIN``,
  ## so inserting ``"$SUDO" /usr/bin/mount "$ROOT_DEV" "$MNT_DIR"`` --
  ## precisely the unguarded, write-capable mount of a hashed carrier that
  ## this whole milestone exists to make impossible -- left the gate
  ## green.
  # Quoted text is a MESSAGE, not a command. `echo "... mount failed"` and
  # `: "${REPROOS_HASHED_CARRIERS:?... refuse a write-capable mount ...}"`
  # both contain the word and run nothing, so the scan is done on the
  # unquoted remainder.
  var bare = ""
  var inD = false
  var inS = false
  for c in line.split('#')[0]:
    if c == '"' and not inS: inD = not inD
    elif c == '\'' and not inD: inS = not inS
    elif not inD and not inS: bare.add c
  for rawTok in bare.split({' ', '\t', ';', '&', '|', '(', ')', '`'}):
    let tok = rawTok.strip()
    if tok.len == 0: continue
    if tok == "mount" or tok.endsWith("/mount"):
      return true
  # The tool variables are checked on the RAW line, because a mount
  # spelled `"$SUDO" "$HOST_MOUNT_BIN" …` is quoted and would otherwise
  # be stripped above. A variable reference inside a diagnostic is rare;
  # the assignment that hands the tool to the guard is excluded by the
  # caller.
  for name in ["$HOST_MOUNT_BIN", "${HOST_MOUNT_BIN}", "$MOUNT_BIN",
               "${MOUNT_BIN}"]:
    if name in line.split('#')[0]:
      return true
  false

proc armOf(text, marker: string; fromPos: int): tuple[a, b: int] =
  ## The span of one ``case`` arm, from ``<marker>)`` to its ``;;``.
  let a = text.find(marker & ")", fromPos)
  if a < 0: return (-1, -1)
  let b = text.find(";;", a)
  if b < 0: return (a, -1)
  (a, b)

proc invokesScript(text, script, arg: string): bool =
  ## Does this text actually RUN ``script`` with ``arg``?
  ##
  ## Not "does it mention it". A mutation that deleted the invocation and
  ## left the header comment naming the script passed an earlier draft of
  ## this gate; a comment is not an edge in the build.
  for line in text.splitLines():
    let l = line.strip()
    if script in l and arg in l and l.startsWith("bash "):
      return true
  false

proc nimBinding(text, name: string): string =
  ## The right-hand side of ``let <name> =``, including the indented
  ## continuation lines that carry an ``if``/``else``.
  ##
  ## This exists because asking whether a NAME occurs in the recipe is
  ## not a check: a mutation that kept the name and changed the value
  ## passed an earlier draft of this gate. What is read here is the
  ## value.
  let lines = text.splitLines()
  var i = 0
  while i < lines.len:
    let stripped = lines[i].strip()
    if stripped.startsWith("let " & name & " =") or
       stripped.startsWith("var " & name & " =") or
       stripped.startsWith("var " & name & ":") or
       stripped.startsWith("let " & name & ":") or
       stripped.startsWith(name & " ="):
      let indent = lines[i].len - lines[i].strip(trailing = false).len
      var body = stripped
      var j = i + 1
      while j < lines.len:
        let nextIndent = lines[j].len - lines[j].strip(trailing = false).len
        if lines[j].strip().len == 0 or nextIndent <= indent:
          break
        body.add "\n" & lines[j].strip()
        j.inc
      return body
    i.inc
  ""

proc verityShellCall(recipe: string): string =
  ## The text of the ``shell(...)`` call that registers the verity
  ## action, located by the action id rather than by position.
  let idAt = recipe.find("actionId = ReproosVerityRootActionId")
  if idAt < 0: return ""
  let start = recipe.rfind("shell(", last = idAt)
  if start < 0: return ""
  let stop = recipe.find("\n    appendRegisteredActionToolIdentityRefs", idAt)
  if stop < 0: return recipe[start .. ^1]
  recipe[start ..< stop]

proc caseConfigurationRunsBeforeTheHash() =
  ## The heart of the matter, checked in four places that are
  ## deliberately independent: the driver does not do it, the stager
  ## does, the recipe wires the stager's output into the hash, and the
  ## recipe makes the hash depend on the stager.
  let driver = readSource(ImageDriver)
  let stager = readSource(Stager)
  let configurer = readSource(Configurer)
  let recipe = readSource(ImageRecipe)
  if driver.len == 0 or stager.len == 0 or configurer.len == 0 or
     recipe.len == 0:
    return

  # 1. The driver still configures a root -- but only the arm that has a
  #    writable one. Located structurally: the call must be inside the
  #    `*)` arm of the Phase 9 dispatch, so a call that escaped its arm
  #    (and would run on every layout) is red rather than green.
  let phase9 = driver.find("# Phase 9: configure the installed root")
  let phase9Case = driver.find("case \"$REPROOS_DISK_LAYOUT\" in", phase9)
  let phase9End = driver.find("\nesac", phase9Case)
  let attested = armOf(driver, AttestedLayout, phase9Case)
  let writable = driver.find("\n  *)", phase9Case)
  if phase9 < 0 or phase9Case < 0 or phase9End < 0 or attested.a < 0 or
     writable < 0 or writable > phase9End:
    fail("t_configuration_runs_before_the_hash: the driver has no Phase 9 " &
         "layout dispatch to check; the ordering claim is anchored on it")
    return
  if "configure-installed-root.sh" in driver[attested.a ..< attested.b]:
    fail("t_configuration_runs_before_the_hash: the driver's " &
         AttestedLayout & " arm runs configure-installed-root.sh. On that " &
         "layout the root is already a hashed image, so configuring it " &
         "there makes the installed root disagree with the root hash on " &
         "its own measured command line")
    return
  if not invokesScript(driver[writable ..< phase9End],
                       "configure-installed-root.sh", "$MNT_DIR"):
    fail("t_configuration_runs_before_the_hash: the writable-root arm no " &
         "longer RUNS the configuration over its mounted root; the phases " &
         "were lost rather than moved")
    return
  pass("t_configuration_runs_before_the_hash: the driver configures a root " &
       "only on the arm that has a writable one (attested arm at " &
       $attested.a & ", writable arm at " & $writable & ")")

  # 2. The stager runs it, and it runs it on a DIRECTORY -- there is no
  #    device, no mount and no nbd node anywhere in that script.
  if not invokesScript(stager, "configure-installed-root.sh", "$OUT_TREE"):
    fail("t_configuration_runs_before_the_hash: " & Stager & " does not " &
         "RUN the configuration over the tree it stages (a mention in a " &
         "comment is not an edge), so nothing configures the root before " &
         "the hash is taken")
    return
  var diskWords: seq[string] = @[]
  for word in ["qemu-nbd", "/dev/nbd", "modprobe", "veritysetup"]:
    if word in stager:
      diskWords.add word
  if diskWords.len > 0:
    fail("t_configuration_runs_before_the_hash: " & Stager & " touches a " &
         "disk (" & diskWords.join(", ") & "); it runs before any disk " &
         "exists and a reference to one means the order has drifted back")
    return
  pass("t_configuration_runs_before_the_hash: " & Stager & " runs the " &
       "configuration over a plain directory, with no device, no mount " &
       "and no verity tool in it")

  # 3. The recipe takes the hash over the STAGED tree, and 4. the hash
  #    cannot be taken before the stage has run.
  #
  # Checked at the BINDINGS rather than by asking whether names occur.
  # An earlier draft of this check did the latter and a mutation that
  # pointed the verity action back at the unconfigured tree -- while
  # keeping the identifier -- sailed through it. A presence test cannot
  # police a value.
  var wiring: seq[string] = @[]
  # Comments are stripped before ANY of the binding reads below. See
  # withoutNimComments: every one of them is defeated by a comment
  # otherwise, and two of them were.
  let cleanRecipe = withoutNimComments(recipe)
  if "ReproosStageInstalledRootActionId" notin cleanRecipe:
    wiring.add "the recipe declares no staging action"

  let sourceBinding = nimBinding(cleanRecipe, "verityStagedRootfs")
  if sourceBinding.len == 0:
    wiring.add "the verity action's source tree is not a binding this " &
      "check can read"
  else:
    let elseAt = sourceBinding.find("else:")
    let attestedBranch =
      if elseAt > 0: sourceBinding[0 ..< elseAt] else: sourceBinding
    if "isAttestedLayout" notin sourceBinding:
      wiring.add "the verity action's source tree does not depend on the " &
        "layout, so the attested build would hash whatever the ordinary " &
        "one hashes"
    elif "build/installed-root" notin attestedBranch:
      wiring.add "the attested branch of the verity action's source tree " &
        "is " & attestedBranch.strip().escape() & ", which is not the " &
        "staged installed root; the hash would be taken over a tree the " &
        "configuration never touched"

  let inputBinding = nimBinding(cleanRecipe, "verityStagedRootfsInput")
  if inputBinding.len == 0:
    wiring.add "the verity action's declared input is not a binding this " &
      "check can read"
  else:
    let elseAt = inputBinding.find("else:")
    let attestedBranch =
      if elseAt > 0: inputBinding[0 ..< elseAt] else: inputBinding
    if "ReproosInstalledRootOutput" notin attestedBranch:
      wiring.add "the attested build does not DECLARE the staged installed " &
        "root as an input of the verity action, so the graph would not " &
        "rebuild the image when the configuration changed"

  # A binding is only an input if the ACTION takes it. Reading the binding
  # and stopping there is the M2 defect wearing a different hat: deleting
  # `verityStagedRootfsInput` from the verity action's extraInputs leaves
  # the binding on the page and the declared input gone.
  let verityInputs = nimCallArg(verityShellCall(recipe), "shell", "extraInputs")
  if verityInputs.len == 0:
    wiring.add "the verity action declares no extraInputs this check can read"
  elif "verityStagedRootfsInput" notin verityInputs:
    wiring.add "the staged tree binding never reaches the verity action's " &
      "extraInputs, so the tree the hash is taken over is not a declared " &
      "input of the action that hashes it"

  let depsBinding = nimBinding(cleanRecipe, "stageInstalledRootDeps")
  if depsBinding.len == 0 or "@[]" notin depsBinding:
    wiring.add "the staging dependency list is not a binding this check " &
      "can read"
  elif "stageInstalledRootDeps = @[stageInstalledRootAction.id]" notin cleanRecipe:
    wiring.add "nothing puts the staging action into that dependency list"
  # Read as the `deps` ARGUMENT of the verity action, not as a substring
  # of its span: `deps = @[isoRootfs], # stageInstalledRootDeps` deletes
  # the ordering edge this milestone rests on and keeps the name.
  let verityDeps = nimCallArg(verityShellCall(recipe), "shell", "deps")
  if verityDeps.len == 0:
    wiring.add "the verity action declares no deps this check can read"
  elif "stageInstalledRootDeps" notin verityDeps:
    wiring.add "the verity action's deps do not include the staging " &
      "action, so the two could run in either order"

  if wiring.len > 0:
    fail("t_configuration_runs_before_the_hash: " & wiring.join("; "))
    return
  pass("t_configuration_runs_before_the_hash: the recipe takes the root " &
       "hash over the staged installed root -- checked at the bindings, " &
       "not by the presence of a name -- declares it as an input, and " &
       "orders the two actions, so the hash cannot be taken before the " &
       "configuration has run")

  # The control. If any matcher above would answer "present" to a token
  # no file carries, none of the above means anything.
  for (what, text) in [("driver", driver), ("stager", stager),
                       ("configurer", configurer), ("recipe", recipe)]:
    if AbsentRule in text:
      fail("t_configuration_runs_before_the_hash: the " & what &
           " contains the control token " & AbsentRule)
      return
  pass("t_configuration_runs_before_the_hash: the control token " &
       AbsentRule & " is in none of the four files, so the matchers " &
       "above are not answering yes to everything")

proc caseAttestedArmWritesNothingIntoTheRoot() =
  ## Three things the attested arm used to do to a mounted root, and now
  ## must not: mirror one, configure one, normalise one.
  let driver = readSource(ImageDriver)
  if driver.len == 0: return

  var offences: seq[string] = @[]
  for (phase, marker, forbidden, why) in [
      ("8", "# Phase 8: put the root and the boot path", "infra install-root",
       "mirroring a root onto a layout whose root is already an image"),
      ("11", "# Phase 11: unmount + disconnect", "reproos_image_metadata.py",
       "normalising inodes needs the root mounted writably")]:
    let start = driver.find(marker)
    let caseAt = driver.find("case \"$REPROOS_DISK_LAYOUT\" in", start)
    let endAt = driver.find("\nesac", caseAt)
    let arm = armOf(driver, AttestedLayout, caseAt)
    if start < 0 or caseAt < 0 or endAt < 0 or arm.a < 0:
      offences.add "phase " & phase & " has no layout dispatch to check"
      continue
    let armEnd = if arm.b > 0 and arm.b < endAt: arm.b else: endAt
    if forbidden in driver[arm.a ..< armEnd]:
      offences.add "phase " & phase & "'s " & AttestedLayout & " arm runs " &
        forbidden & " (" & why & ")"
  if offences.len > 0:
    fail("t_attested_arm_writes_nothing_into_the_root: " &
         offences.join("; "))
    return
  pass("t_attested_arm_writes_nothing_into_the_root: the attested arm " &
       "neither mirrors a root nor normalises one on a mounted " &
       "filesystem; both belong to the staged tree, before the hash")

proc caseEveryMountGoesThroughTheGuard() =
  ## A refusal that any line of the driver can walk around is not a
  ## refusal. The host mount binary may be invoked in exactly one place:
  ## inside the guard.
  let driver = readSource(ImageDriver)
  let guard = readSource(MountGuard)
  if driver.len == 0 or guard.len == 0: return

  # EVERY line that runs a mount(8), by whatever spelling, must be the
  # one inside mount_guarded(). Matching only `$HOST_MOUNT_BIN` was the
  # defect: `"$SUDO" /usr/bin/mount "$ROOT_DEV" "$MNT_DIR"` -- the exact
  # unguarded write-capable mount of a hashed carrier this gate exists
  # to forbid -- carries no such token and walked straight through.
  let guardedFrom = driver.find("mount_guarded()")
  var guardedFirst = 0
  var guardedLast = 0
  if guardedFrom >= 0:
    guardedFirst = driver[0 ..< guardedFrom].count('\n') + 1
    let closeAt = driver.find("\n}", guardedFrom)
    guardedLast =
      if closeAt > 0: driver[0 ..< closeAt].count('\n') + 2
      else: guardedFirst
  var strays: seq[string] = @[]
  var lineNo = 0
  for line in driver.splitLines():
    lineNo.inc
    if not executesMount(line): continue
    if "MOUNT_BIN=" in line: continue          # passing the tool to the guard
    if lineNo >= guardedFirst and lineNo <= guardedLast: continue
    strays.add "line " & $lineNo & ": " & line.strip()
  if strays.len > 0:
    fail("t_every_mount_goes_through_the_guard: the driver mounts without " &
         "the guard, so a write-capable mount of a hashed carrier would " &
         "not be refused: " & strays.join(" | "))
    return
  if guardedFrom < 0:
    fail("t_every_mount_goes_through_the_guard: the driver defines no " &
         "mount_guarded(), so there is no single place the mounts go " &
         "through and the scan above proves nothing")
    return
  if "mount-guard.sh" notin driver:
    fail("t_every_mount_goes_through_the_guard: the driver never invokes " &
         MountGuard)
    return
  # A refusal the driver reports as an ordinary mount failure is a
  # refusal nobody can act on: 78 says "an edit reintroduced the write
  # this layout exists to prevent" and 69 says "a mount would not go".
  # The driver has to hand the guard's code back.
  var folded: seq[string] = @[]
  var mountLine = 0
  for line in driver.splitLines():
    mountLine.inc
    if "mount_guarded " notin line: continue
    if "mount_guarded()" in line: continue
    if "exit 69" in line or "exit 68" in line:
      folded.add "line " & $mountLine & ": " & line.strip()
  if folded.len > 0 or "exit \"$rc\"" notin driver:
    fail("t_every_mount_goes_through_the_guard: the driver folds the " &
         "guard's exit code into a mount failure instead of propagating " &
         "it, so a refusal (78) would be reported as an ordinary mount " &
         "failure: " & (if folded.len > 0: folded.join(" | ")
                        else: "nothing in the driver re-exits with the " &
                              "code it was handed"))
    return
  # The guard's own refusal has to be keyed on write CAPABILITY, not on
  # anything having been written -- which is the whole point.
  var missing: seq[string] = @[]
  for needle in ["mount_is_readonly", "REPROOS_HASHED_CARRIERS",
                 "Partition unique GUID", "exit 78"]:
    if needle notin guard:
      missing.add needle
  if missing.len > 0:
    fail("t_every_mount_goes_through_the_guard: the guard is missing " &
         missing.join(", ") & "; it cannot decide whether a mount is " &
         "write-capable, or which partitions are hashed")
    return
  if AbsentRule in guard:
    fail("t_every_mount_goes_through_the_guard: the guard contains the " &
         "control token")
    return
  # The recipe has to tell it which partitions those are, for BOTH
  # slots. A list naming only the installed slot would let a mount of
  # the other one through the moment an apply had staged into it.
  let recipe = readSource(ImageRecipe)
  if "REPROOS_HASHED_CARRIERS" notin recipe or
     "hashedCarrierSpecs" notin recipe:
    fail("t_every_mount_goes_through_the_guard: " & ImageRecipe & " does " &
         "not hand the driver the carrier list the guard needs")
    return
  if "[generations.gsA, generations.gsB]" notin recipe:
    fail("t_every_mount_goes_through_the_guard: the carrier list is not " &
         "derived for both generation slots")
    return
  pass("t_every_mount_goes_through_the_guard: the host mount binary is " &
       "invoked in exactly one place, the guard refuses on write " &
       "CAPABILITY rather than on anything having been written, and the " &
       "recipe names the carriers of both slots")

proc caseCarrierVerifyIsPinned() =
  ## The strongest check on the attested path is the `veritysetup verify`
  ## walk over the two partitions. The writer lets a caller switch it
  ## off; this caller must not let the ambient environment do so.
  let driver = readSource(ImageDriver)
  let writer = readSource(CarrierWriter)
  if driver.len == 0 or writer.len == 0: return

  if CarrierVerifySwitch & "=1" notin driver:
    fail("t_carrier_verify_is_pinned: the driver does not pin " &
         CarrierVerifySwitch & "=1 when it runs the carrier writer, so an " &
         "exported " & CarrierVerifySwitch & "=0 would silently produce an " &
         "attested image whose installed pair was never walked")
    return
  # ...and it has to be pinned ON THE INVOCATION, inside the attested
  # arm, between the arm's opening and the `bash .../write-verity-carriers.sh`
  # that consumes it. A pin anywhere else is a variable the writer's own
  # environment does not see.
  let arm = armOf(driver, AttestedLayout,
                  driver.find("# Phase 6b:"))
  let callAt = driver.find("write-verity-carriers.sh", arm.a)
  if arm.a < 0 or callAt < 0 or (arm.b > 0 and callAt > arm.b):
    fail("t_carrier_verify_is_pinned: the driver's Phase 6b no longer " &
         "calls the carrier writer inside an " & AttestedLayout & " arm")
    return
  let pinAt = driver.find(CarrierVerifySwitch & "=1", arm.a)
  if pinAt < 0 or pinAt > callAt:
    fail("t_carrier_verify_is_pinned: " & CarrierVerifySwitch & "=1 is not " &
         "in the assignment list of the writer invocation (pin at " &
         $pinAt & ", call at " & $callAt & "), so it is not what the " &
         "writer's environment carries")
    return
  if "${" & CarrierVerifySwitch in driver:
    fail("t_carrier_verify_is_pinned: the driver reads " &
         CarrierVerifySwitch & " out of its own environment as well as " &
         "pinning it; the ambient value must not reach the writer")
    return
  if CarrierVerifySwitch notin writer:
    fail("t_carrier_verify_is_pinned: the writer no longer has the switch " &
         "this check is about, so the pin is pinning nothing")
    return
  pass("t_carrier_verify_is_pinned: " & CarrierVerifySwitch & "=1 is set on " &
       "the writer invocation itself (" & $pinAt & " < " & $callAt & "), " &
       "so the ambient environment cannot switch off the one check that " &
       "walks the installed pair")

# ---------------------------------------------------------------------------
# Layer 2 — a real disk.
# ---------------------------------------------------------------------------

proc gateSkipRemedy(prefix: string): string =
  prefix & "\n" &
  "  Run it with " & GateEnv & "=1.\n" &
  "  It configures a purpose-built root with the shipped\n" &
  "  configure-installed-root.sh, images it with the shipped\n" &
  "  build-verity-root.sh, applies the real " & AttestedLayout &
  " layout to a\n" &
  "  transient 20 GB qcow2 over a loopback NBD node, writes the pair with\n" &
  "  the shipped writer, and then verifies it against the root hash the\n" &
  "  command line pins -- and falsifies that by breaking it with a\n" &
  "  read-write mount that writes nothing. It needs sudo, the nbd module,\n" &
  "  qemu-nbd, sgdisk, veritysetup and mkfs.ext4, and takes about three\n" &
  "  minutes."

proc findReproBinary(): string =
  for cand in [getEnv("REPRO_BIN"),
               RepoRoot / "build/bin/repro",
               RepoRoot.parentDir / "reprobuild/build/bin/repro"]:
    if cand.len > 0 and fileExists(cand):
      return cand
  findExe("repro")

proc buildFixtureRoot(dir: string) =
  ## A purpose-built root with the shape the SHIPPED configuration
  ## expects, and enough bytes that the Merkle tree has more than one
  ## level. Deterministic content, because digests are compared.
  for d in FixtureTreeDirs:
    createDir(dir / d)
  writeFile(dir / "etc/os-release", "NAME=reproos-root-order-fixture\n")
  writeFile(dir / "usr/bin/hello", "#!/bin/sh\necho hello\n")
  for i in 0 ..< 16:
    var blob = newStringOfCap(256 * 1024)
    for j in 0 ..< 256 * 1024:
      blob.add chr((i * 31 + j * 7) and 0xff)
    writeFile(dir / "var/log" / ("blob-" & $i & ".bin"), blob)
  # The shipped builder carries the guest inode policy into the image and
  # refuses to hash one it could not describe.
  writeRootPolicyFixture(dir)

proc buildConfigBundle(dir, autoConfig: string) =
  ## The canonical bundle the installer emits. The installer itself is a
  ## CMake target this gate does not build, so the four rendered
  ## documents beside the config are placeholders -- Phase 9 copies them
  ## verbatim, and what is under test here is the ORDER, not the
  ## renderer. Stated so nobody reads more into a green run than it says.
  createDir(dir)
  copyFile(autoConfig, dir / "auto-config.toml")
  for f in ["system.nim", "hardware.nim", "disko.json", "home.nim"]:
    writeFile(dir / f, "# emitted-artifact placeholder for the order gate\n")

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
  ## Pull ``key=<value>`` out of a kernel command line. Everything layer
  ## 2 verifies against is read back through this, so the values under
  ## test come from the command line an attested image would carry
  ## rather than from a variable this gate happens to hold.
  for token in cmdline.split(' '):
    if token.startsWith(key & "="):
      return token[key.len + 1 .. ^1]
  ""

proc runLayer2(workRoot: string) =
  let layer = optInLayer(GateEnv)
  if layer.isBlocked:
    fail(blockedNote(GateEnv,
      "bash tests/test-attested-root-order.sh, with " & GateEnv & "=1"))
    return
  if layer == lrNotRequested:
    skip("t_attested_root_matches_its_measured_hash: " &
         notRequestedNote(GateEnv) & "\n" &
         gateSkipRemedy("  No disk was written, nothing was mounted and " &
                        "no hash was checked against a partition."))
    skip("t_readwrite_mount_of_a_hashed_carrier_is_refused: " &
         notRequestedNote(GateEnv) & "\n" &
         "  The refusal was not exercised against a real carrier, and the " &
         "zero-write\n  falsification did not run.")
    return

  var missing: seq[string] = @[]
  for tool in Layer2Tools:
    if findExe(tool).len == 0:
      missing.add tool
  if missing.len > 0:
    fail("t_attested_root_matches_its_measured_hash: requested, but these " &
         "tools are not on PATH: " & missing.join(", ") &
         ". This gate does not skip for a missing tool when it was asked " &
         "for: a green run that wrote no disk would be worse than a red one.")
    return

  let reproBin = findReproBinary()
  if reproBin.len == 0:
    fail("t_attested_root_matches_its_measured_hash: no `repro` binary; " &
         "the partition table is written by `repro disk apply` and this " &
         "gate will not substitute for it")
    return

  let sudo = findExe("sudo")
  let work = workRoot / "root-order"
  removeDir(work)
  createDir(work)

  let configText = readSource(AutoConfigFixture)
  if configText.len == 0: return
  var request = diskLayouts.parseDiskLayoutRequest(
    configText, "reproos-root-order-gate", "/dev/nbd0")
  request.name = AttestedLayout
  request.params.diskSizeGb = 20
  let seed = diskLayouts.reproosImageIdentitySeed(
    configText, packageSets.ReproosGraphicalRootfsPackages, request)
  if seed.len == 0:
    fail("t_attested_root_matches_its_measured_hash: no identity seed")
    return

  # --- the root, configured by the SHIPPED script, BEFORE any hash
  let tree = work / "installed-root"
  createDir(tree)
  buildFixtureRoot(tree)
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
    fail("t_attested_root_matches_its_measured_hash: the shipped " &
         Configurer & " failed on the fixture root; nothing was imaged")
    return
  # What it wrote, named here so the read-only check inside the image
  # below is looking for something this run actually produced.
  var configured: seq[string] = @[]
  for rel in ["etc/hostname", "etc/passwd", "etc/shadow",
              "etc/repro/auto-config.toml",
              "etc/systemd/system/reproos-health-check.service"]:
    if not fileExists(tree / rel):
      fail("t_attested_root_matches_its_measured_hash: the configuration " &
           "did not write " & rel & " into the tree, so there is nothing " &
           "to look for inside the image")
      return
    configured.add rel
  pass("t_attested_root_matches_its_measured_hash: the SHIPPED " &
       Configurer & " configured the root as a plain directory, before " &
       "any hash existed (" & $configured.len & " files checked, " &
       "including " & configured[0] & " and " & configured[^1] & ")")

  # --- the image of it, and its root hash
  let verityDir = work / "verity"
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
    fail("t_attested_root_matches_its_measured_hash: the shipped " &
         VerityBuilder & " failed over the configured tree")
    return
  let dataImage = verityDir / verity.VerityDataImageFileName
  let hashTree = verityDir / verity.VerityHashTreeFileName
  let rootHashFile = verityDir / verity.VerityRootHashFileName
  for f in [dataImage, hashTree, rootHashFile]:
    if not fileExists(f):
      fail("t_attested_root_matches_its_measured_hash: the builder " &
           "produced no " & f.extractFilename)
      return
  let builtRootHash = readFile(rootHashFile).strip()

  # --- the command line an attested unified kernel image would carry.
  #     Everything below reads its values back OUT of this string.
  let devices = generations.attestedBootDevices(seed, generations.gsA)
  let cmdline = ukiModule.attestedKernelCmdline(
    builtRootHash, devices.data, devices.hash,
    devices.stateVar, devices.stateHome)
  let cmdlineError = ukiModule.validateAttestedCmdline(cmdline, builtRootHash)
  if cmdlineError.len > 0:
    fail("t_attested_root_matches_its_measured_hash: " & cmdlineError)
    return
  let measuredHash = valueAfter(cmdline, verity.VerityRootHashCmdlineKey)
  let measuredData = valueAfter(cmdline, verity.VerityDataDeviceCmdlineKey)
  let measuredHashDev = valueAfter(cmdline, verity.VerityHashDeviceCmdlineKey)
  if measuredHash.len != 64 or not measuredData.startsWith("PARTUUID=") or
     not measuredHashDev.startsWith("PARTUUID="):
    fail("t_attested_root_matches_its_measured_hash: the command line does " &
         "not carry a hash and two PARTUUID= specifiers to read back")
    return

  # --- a real disk, and the real apply
  let qcow2 = work / "root-order.qcow2"
  if not sh(findExe("qemu-img") & " create -f qcow2 " & quoteShell(qcow2) &
            " " & $request.params.diskSizeGb & "G"):
    fail("t_attested_root_matches_its_measured_hash: qemu-img create failed")
    return
  if not sh(sudo & " modprobe nbd max_part=16"):
    fail("t_attested_root_matches_its_measured_hash: the nbd module could " &
         "not be loaded")
    return
  var nbdDev = ""
  for n in 0 .. 15:
    if dirExists("/sys/block/nbd" & $n) and
       not fileExists("/sys/block/nbd" & $n & "/pid"):
      nbdDev = "/dev/nbd" & $n
      break
  if nbdDev.len == 0:
    fail("t_attested_root_matches_its_measured_hash: no free /dev/nbdN")
    return

  var connected = false
  let mountPoint = work / "mnt"
  createDir(mountPoint)
  template teardown() =
    discard run(sudo & " umount " & quoteShell(mountPoint) & " 2>/dev/null")
    if connected:
      discard run(sudo & " " & findExe("qemu-nbd") & " --disconnect " & nbdDev)
      connected = false
    if getEnv(KeepEnv) != "1":
      removeDir(work)

  if not sh(sudo & " " & findExe("qemu-nbd") & " --connect=" & nbdDev &
            " --cache=writeback -f qcow2 " & quoteShell(qcow2)):
    fail("t_attested_root_matches_its_measured_hash: qemu-nbd could not " &
         "connect " & nbdDev)
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
      fail("t_attested_root_matches_its_measured_hash: `repro disk apply` " &
           "failed on the " & AttestedLayout & " document")
      return
    discard run(sudo & " partprobe " & nbdDev & " 2>/dev/null")
    discard run("sleep 2")

    # --- the pair, written by the SHIPPED writer
    let writeCmd =
      "SUDO=" & quoteShell(sudo) & " " &
      "REPROOS_VERITY_CARRIER_VERIFY=1 " &
      "REPROOS_VERITY_DATA_IMAGE=" & quoteShell(dataImage) & " " &
      "REPROOS_VERITY_HASH_TREE=" & quoteShell(hashTree) & " " &
      "REPROOS_VERITY_ROOTHASH_FILE=" & quoteShell(rootHashFile) & " " &
      "REPROOS_VERITY_DATA_DEVICE=" & quoteShell(measuredData) & " " &
      "REPROOS_VERITY_HASH_DEVICE=" & quoteShell(measuredHashDev) & " " &
      "bash " & quoteShell(RepoRoot / CarrierWriter) & " " & nbdDev
    if not sh(writeCmd):
      fail("t_attested_root_matches_its_measured_hash: the shipped " &
           CarrierWriter & " failed")
      return

    # --- resolve the command line's OWN specifiers against the GPT
    var dataPart, hashPart = ""
    for num in 1 .. 8:
      let guid = partitionGuidOnDisk(sudo, nbdDev, num)
      if guid.len == 0: continue
      if guid == measuredData["PARTUUID=".len .. ^1].toLowerAscii():
        dataPart = nbdDev & "p" & $num
      elif guid == measuredHashDev["PARTUUID=".len .. ^1].toLowerAscii():
        hashPart = nbdDev & "p" & $num
    if dataPart.len == 0 or hashPart.len == 0:
      fail("t_attested_root_matches_its_measured_hash: the command line's " &
           "specifiers do not resolve on the disk that was just written " &
           "(data -> " & dataPart & ", hash -> " & hashPart & ")")
      return

    # --- THE GATE. The hash is the one the command line pins.
    if not sh(sudo & " veritysetup verify " & dataPart & " " & hashPart &
              " " & measuredHash):
      fail("t_attested_root_matches_its_measured_hash: the installed pair " &
           "does not verify against the root hash the measured command " &
           "line pins (" & measuredHash & ")")
      return
    pass("t_attested_root_matches_its_measured_hash: `veritysetup verify` " &
         "walks the whole tree on " & dataPart & " / " & hashPart &
         " and accepts it against " & verity.VerityRootHashCmdlineKey &
         "=" & measuredHash & ", read back out of the command line an " &
         "attested unified kernel image would carry")

    # --- the ordering claim AT THE BYTES: the configuration is inside
    #     the measured image. Read-only, because a read-write mount here
    #     would be the very defect under test.
    if not sh(sudo & " mount -o ro " & dataPart & " " &
              quoteShell(mountPoint)):
      fail("t_attested_root_matches_its_measured_hash: the data carrier " &
           "could not be mounted read-only to inspect it")
      return
    var absent: seq[string] = @[]
    for rel in configured:
      if not fileExists(mountPoint / rel):
        absent.add rel
    let hostname = try: readFile(mountPoint / "etc/hostname").strip()
                   except CatchableError: ""
    discard run(sudo & " umount " & quoteShell(mountPoint))
    if absent.len > 0:
      fail("t_attested_root_matches_its_measured_hash: the measured image " &
           "does not contain " & absent.join(", ") & "; the configuration " &
           "did not reach the bytes the root hash covers")
      return
    if hostname != "reproos-smoke":
      fail("t_attested_root_matches_its_measured_hash: the measured " &
           "image's /etc/hostname is " & hostname.escape() & ", not the " &
           "configured one")
      return
    pass("t_attested_root_matches_its_measured_hash: all " &
         $configured.len & " configured files are INSIDE the image the " &
         "root hash covers (/etc/hostname reads " & hostname.escape() &
         "), so the configuration happened before the hash and not after " &
         "the install")

    # --- and the read-only mount left the pair verifying
    if not sh(sudo & " veritysetup verify " & dataPart & " " & hashPart &
              " " & measuredHash):
      fail("t_attested_root_matches_its_measured_hash: a READ-ONLY mount " &
           "of the carrier broke the pair, which would make the gate " &
           "below unable to distinguish anything")
      return
    pass("t_attested_root_matches_its_measured_hash: the read-only mount " &
         "left the pair verifying, so what the next case measures is the " &
         "WRITE capability and nothing else")

    # =================================================================
    # t_readwrite_mount_of_a_hashed_carrier_is_refused
    # =================================================================
    let guardEnv =
      "SUDO=" & quoteShell(sudo) & " " &
      "MOUNT_BIN=" & quoteShell(findExe("mount")) & " " &
      "SGDISK_BIN=" & quoteShell(findExe("sgdisk")) & " " &
      "REPROOS_HASHED_CARRIERS=" &
        quoteShell(measuredData & " " & measuredHashDev) & " "
    let refused = run(guardEnv & "bash " & quoteShell(RepoRoot / MountGuard) &
                      " " & dataPart & " " & quoteShell(mountPoint) & " 2>&1")
    if refused.exitCode == 0:
      discard run(sudo & " umount " & quoteShell(mountPoint))
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
           "MOUNTED " & dataPart & " read-write. That mount alone breaks " &
           "the root hash, whether or not anything is written through it")
      return
    if refused.exitCode != 78 or "REFUSED" notin refused.output:
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
           "failed (exit " & $refused.exitCode & ") but not with the " &
           "refusal: " & refused.output.strip())
      return
    let stillMounted = run("mountpoint -q " & quoteShell(mountPoint))
    if stillMounted.exitCode == 0:
      discard run(sudo & " umount " & quoteShell(mountPoint))
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
           "refused and mounted anyway")
      return
    pass("t_readwrite_mount_of_a_hashed_carrier_is_refused: the shipped " &
         "guard refuses a write-capable mount of " & dataPart & " (exit " &
         $refused.exitCode & ") and mounts nothing")

    # The guard must still be usable for the mounts a build really needs,
    # or the driver would simply route around it.
    let allowedRo = run(guardEnv & "bash " &
                        quoteShell(RepoRoot / MountGuard) & " " & dataPart &
                        " " & quoteShell(mountPoint) & " -o ro 2>&1")
    if allowedRo.exitCode != 0:
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
           "also refuses a READ-ONLY mount (exit " & $allowedRo.exitCode &
           "): " & allowedRo.output.strip() & ". A guard that refuses " &
           "everything is one the driver would be edited around")
      return
    discard run(sudo & " umount " & quoteShell(mountPoint))
    let allowedEsp = run(guardEnv & "bash " &
                         quoteShell(RepoRoot / MountGuard) & " " & nbdDev &
                         "p1 " & quoteShell(mountPoint) & " 2>&1")
    if allowedEsp.exitCode != 0:
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
           "refuses a write-capable mount of the ESP (exit " &
           $allowedEsp.exitCode & "), which no root hash covers: " &
           allowedEsp.output.strip())
      return
    discard run(sudo & " umount " & quoteShell(mountPoint))
    pass("t_readwrite_mount_of_a_hashed_carrier_is_refused: the same guard " &
         "allows the read-only mount of that carrier and the write-capable " &
         "mount of the ESP, so it is refusing the property and not the act")

    # --- FALSIFICATION, in the gate rather than by hand: bypass the
    #     guard, mount read-write, WRITE NOTHING, unmount. The pair must
    #     stop verifying. Without this, a gate keyed on modified files
    #     would pass while the image was already broken.
    if not sh(sudo & " mount " & dataPart & " " & quoteShell(mountPoint)):
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the " &
           "falsification could not mount the carrier read-write, so the " &
           "zero-write claim did not run")
      return
    let mountedFiles = run("ls " & quoteShell(mountPoint) & " | wc -l")
    discard run(sudo & " umount " & quoteShell(mountPoint))
    discard run(sudo & " sync")
    let afterZeroWrite = run(sudo & " veritysetup verify " & dataPart & " " &
                             hashPart & " " & measuredHash & " 2>&1")
    if afterZeroWrite.exitCode == 0:
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: a read-write " &
           "mount that wrote nothing left the pair VERIFYING. Either the " &
           "filesystem no longer stamps its superblock on mount or the " &
           "verification is not reading the partition -- and in both " &
           "cases the refusal above is guarding nothing")
      return
    pass("t_readwrite_mount_of_a_hashed_carrier_is_refused: FALSIFIED as " &
         "required -- bypassing the guard and mounting " & dataPart &
         " read-write, writing NOTHING (" &
         mountedFiles.output.strip() & " entries listed, none touched) " &
         "and unmounting makes the same verification fail (exit " &
         $afterZeroWrite.exitCode & "). A gate keyed on modified files " &
         "would have called this image healthy")

    # --- and the writer puts it back, which proves the failure above was
    #     the mount and not something the gate had already broken
    if not sh(writeCmd):
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the writer " &
           "could not restore the pair after the falsification")
      return
    if not sh(sudo & " veritysetup verify " & dataPart & " " & hashPart &
              " " & measuredHash):
      fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the pair " &
           "does not verify again after being rewritten")
      return

    # --- THE LAST ro/rw SPECIFIER WINS, and a guard that does not know
    #     that is not a guard.
    #
    # `mount(8)` applies the FINAL ro/rw it is given, so `-o ro,rw` mounts
    # READ-WRITE. A guard that answered "read-only" because the string
    # `ro` appeared anywhere in the options would wave these through --
    # and each of them really does mount writably and really does break
    # the pair, which is the whole failure this milestone exists to make
    # impossible. Checked against a REAL carrier, and checked by whether
    # anything ended up mounted rather than by the guard's own report:
    # a guard that refused but mounted anyway would pass an exit-code
    # test.
    for spec in ["-o ro,rw", "-o ro -o rw", "-r -o rw", "-oro,rw"]:
      let sneaky = run(guardEnv & "bash " &
                       quoteShell(RepoRoot / MountGuard) & " " & dataPart &
                       " " & quoteShell(mountPoint) & " " & spec & " 2>&1")
      let landed = run("mountpoint -q " & quoteShell(mountPoint) &
                       " && echo MOUNTED || echo no")
      if landed.output.strip() == "MOUNTED":
        let opts = run("findmnt -no OPTIONS " & quoteShell(mountPoint))
        discard run(sudo & " umount " & quoteShell(mountPoint))
        fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
             "MOUNTED the hashed carrier " & dataPart & " with `" & spec &
             "` (options: " & opts.output.strip() & "). mount(8) applies " &
             "the LAST ro/rw specifier, so this is a write-capable mount " &
             "of a partition the root hash names, and it breaks the pair. " &
             "The guard must take the last specifier rather than the " &
             "first `ro` it finds")
        return
      if sneaky.exitCode != 78:
        fail("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard " &
             "mounted nothing for `" & spec & "` but exited " &
             $sneaky.exitCode & " rather than 78, so a write-capable mount " &
             "of a hashed carrier was not reported as the refusal it is: " &
             sneaky.output.strip())
        return
    pass("t_readwrite_mount_of_a_hashed_carrier_is_refused: the guard takes " &
         "the LAST ro/rw specifier, as mount(8) does -- `-o ro,rw`, " &
         "`-o ro -o rw`, `-r -o rw` and `-oro,rw` are all refused (78) " &
         "and none of them mounted, so an `ro` anywhere in the options " &
         "cannot be used to walk a write-capable mount past it")

    pass("t_readwrite_mount_of_a_hashed_carrier_is_refused: rewriting the " &
         "carriers restores verification, so the failure above was caused " &
         "by the mount and by nothing else the gate did")
  finally:
    teardown()

# ---------------------------------------------------------------------------

when isMainModule:
  caseConfigurationRunsBeforeTheHash()
  caseAttestedArmWritesNothingIntoTheRoot()
  caseEveryMountGoesThroughTheGuard()
  caseCarrierVerifyIsPinned()

  let workRoot = getEnv("REPROOS_TEST_WORK_DIR",
                        getTempDir() / "reproos-attested-root-order")
  createDir(workRoot)
  runLayer2(workRoot)

  if failures > 0:
    stderr.writeLine("attested root order: " & $failures &
                     " check(s) failed, " & $passes & " passed, " &
                     $skips & " skipped")
    quit(1)
  var summary = "attested root order: PASS (" & $passes & " checks"
  if layerSummaryFragment().len > 0:
    summary.add ", " & layerSummaryFragment() & " -- no disk was written"
  elif skips > 0:
    summary.add ", " & $skips & " SKIPPED -- no disk was written"
  summary.add ")"
  echo summary
