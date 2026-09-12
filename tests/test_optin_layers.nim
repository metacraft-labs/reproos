## Gate: an opt-in layer the build cannot run is LOUD, and no opt-in
## variable is consumed without the action that consumes it declaring it.
##
## ## What was wrong
##
## Every expensive layer in this repository's gates is switched on by an
## environment variable. None of those variables was declared on the action
## that runs the gate, and the consequences were not what they looked like:
##
##   * The variable DID reach the gate. An action's environment is layered
##     OVER the one the build was launched with, so an undeclared name is
##     inherited rather than dropped. Measured: a sibling repository's
##     opt-in layer ran under ``repro build`` with the variable set in no
##     recipe at all, and failed for its own reason.
##   * What it did NOT do was reach the action's cache key. Where an action
##     is cacheable, that is a serve-a-stale-result hole: the same
##     repository's layer was requested with its tools pointed at a path
##     that does not exist — a configuration in which the binary run
##     directly exits 1 — and ``repro build`` returned exit 0, replaying a
##     result recorded with the layer off.
##   * And in THIS repository the variable reaches a gate that cannot use
##     it. Every gate action here gets a hermetic PATH built from the tool
##     identities it declares, and these layers need ``veritysetup``,
##     ``mkfs.ext4``, ``mkfs.vfat``, ``sgdisk``, ``mmd``, ``qemu`` — from-
##     source packages, privileged operations and real block devices, none
##     of which an always-on gate may declare. So the layer could not run
##     whatever the caller asked for, and the summary line said "skipped",
##     which is what a switched-off layer says too.
##
## ## The two registered cases
##
##   * ``t_optin_variable_is_in_the_cache_key`` — structural. Every opt-in
##     variable any gate source reads must be declared in the
##     ``optInLayers(...)`` call on the action that runs that gate. This is
##     the check that would have been red for the thirteen variables declared
##     in no recipe; it carries a negative control so that it cannot pass
##     by finding nothing.
##
##     The name says "cache key" and the check says "declared", and those
##     are the same requirement here for a reason worth stating: a declared
##     name is what ``keyedOnActionEnvironment`` mixes into the action's
##     weak fingerprint, and a name that is merely inherited is not. The
##     engine-side half of that — that a declared value changes the key and
##     a passthrough value does not — is pinned in reprobuild's own
##     ``t_declared_env_is_in_the_cache_key``; this case pins the half that
##     lives here, which is that every variable this repository consumes is
##     one the graph has an opinion about.
##
##   * ``t_unreachable_layer_is_not_a_silent_skip`` — behavioural, and the
##     negative gate. A real gate binary is compiled and run in four
##     states, and the two that must be loud are loud.
##
## ## Mocking
##
## None. The structural case reads the shipped ``repro/workflows.nim`` and
## the shipped gate sources. The behavioural case compiles a REAL shipped
## gate (``tests/test_verity_root.nim``) with the real compiler and runs
## the real binary; the only thing constructed here is the environment,
## which is the thing under test.

import std/[os, osproc, strtabs, strutils]

import "./gate_layers"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  TestsDir = RepoRoot / "tests"
  WorkflowsPath = RepoRoot / "repro" / "workflows.nim"

  SubjectGate = "tests/test_verity_root.nim"
    ## The gate the behavioural case drives. Picked because it is the
    ## cheapest gate that has an opt-in layer at all: its always-on layer
    ## is pure computation and needs no artifact.
  SubjectLayers = "REPROOS_VERITY_TOOL_GATE,REPROOS_VERITY_GUEST_GATE"
  SubjectLayer = "REPROOS_VERITY_TOOL_GATE"
  OtherLayer = "REPROOS_VERITY_GUEST_GATE"
  CommentControlLayer = "REPROOS_UKI_BOOT_GATE"
    ## The comment control's subject. A different layer from the two
    ## above only because its declaration occupies a single line, which
    ## is what makes "comment it out" a one-line edit to construct.

var
  failures = 0
  passes = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message
  passes.inc

proc check(condition: bool; what: string) =
  if condition: pass(what) else: fail(what)

# ---------------------------------------------------------------------------
# t_optin_variable_is_in_the_cache_key
# ---------------------------------------------------------------------------

proc optInVariablesIn(text: string): seq[string] =
  ## Every ``REPROOS_*_GATE`` string literal in a gate source. The suffix
  ## match is what keeps ``REPROOS_VERITY_GUEST_KEEP`` and
  ## ``REPROOS_VERITY_GATE_SECOND_RUN`` out: the first is not a layer
  ## switch and the second is a gate's private re-entrancy flag, and
  ## neither is something an action should have an opinion about.
  var i = 0
  while true:
    let start = text.find("\"REPROOS_", i)
    if start < 0: break
    let stop = text.find('"', start + 1)
    if stop < 0: break
    let name = text[start + 1 ..< stop]
    i = stop + 1
    if not name.endsWith("_GATE"): continue
    if name notin result:
      result.add(name)

proc withoutComments(text: string): string =
  ## The recipe with every Nim comment removed.
  ##
  ## NOT HOUSEKEEPING. A structural check that reads the recipe as raw text
  ## cannot tell a declaration from a mention of one, and that is not a
  ## hypothetical failure: the grep that first counted these variables
  ## reported six of them as declared, and all six hits were ``#`` comment
  ## lines. Without this, commenting out a declaration leaves every string
  ## the scan looks for exactly where it was while the action declares
  ## nothing -- a green result for a recipe that lost the declaration. Both
  ## cases below run a control that does precisely that.
  ##
  ## String-aware, because the needles live in string literals and a ``#``
  ## inside one must not end the line early.
  for line in text.splitLines():
    var inString = false
    var cut = line.len
    var i = 0
    while i < line.len:
      let c = line[i]
      if c == '\\' and inString:
        i += 2
        continue
      if c == '"':
        inString = not inString
      elif c == '#' and not inString:
        cut = i
        break
      i.inc
    result.add(line[0 ..< cut])
    result.add('\n')

proc declarationBlockFor(workflows, testFile: string): tuple[
    ok: bool; text: string; why: string] =
  ## The slice of ``repro/workflows.nim`` that declares the action running
  ## ``testFile``: from the ``extraInputs`` entry naming that file to the
  ## END OF THAT ACTION.
  ##
  ## The end matters more than the beginning. A forward scan for the next
  ## ``optInLayers(`` would happily run past this action into the NEXT
  ## one's declaration and report a variable as declared because some
  ## other gate declares it. So the scan is bounded by whichever comes
  ## first, and reaching the next action id first is a failure rather than
  ## a licence to keep looking.
  let needle = "\"" & testFile & "\","
  let at = workflows.find(needle)
  if at < 0:
    return (false, "", "no action declares " & testFile & " as an input")
  let nextAction = workflows.find("actionId = \"", at)
  let decl = workflows.find("optInLayers(", at)
  if decl < 0:
    return (false, "", "no optInLayers(...) call follows " & testFile)
  if nextAction >= 0 and nextAction < decl:
    return (false, "",
      "the next optInLayers(...) after " & testFile & " belongs to a " &
      "LATER action, so this action declares no opt-in layer at all")
  let close = workflows.find(')', decl)
  if close < 0:
    return (false, "", "unterminated optInLayers(...) after " & testFile)
  (true, workflows[decl .. close], "")

proc undeclaredVariables(workflows: string;
                         sources: openArray[tuple[file, text: string]]):
    seq[string] =
  ## Every ``(gate source, opt-in variable)`` pair the recipe has no
  ## opinion about. Returned rather than asserted so the negative control
  ## below can run the SAME procedure over a deliberately broken recipe.
  for entry in sources:
    for name in optInVariablesIn(entry.text):
      let block0 = declarationBlockFor(workflows, "tests/" & entry.file)
      if not block0.ok:
        result.add(entry.file & ":" & name & " (" & block0.why & ")")
      elif name notin block0.text:
        result.add(entry.file & ":" & name &
          " (the action declares opt-in layers, but not this one)")

proc caseEveryConsumedVariableIsDeclared() =
  let workflows = withoutComments(readFile(WorkflowsPath))
  var sources: seq[tuple[file, text: string]] = @[]
  for kind, path in walkDir(TestsDir):
    if kind != pcFile: continue
    let name = extractFilename(path)
    if not name.startsWith("test_") or not name.endsWith(".nim"): continue
    if name == "test_optin_layers.nim": continue
    sources.add((file: name, text: readFile(path)))

  var consuming = 0
  for entry in sources:
    if optInVariablesIn(entry.text).len > 0: consuming.inc
  # Without this the whole case would pass on a tree where the scanner
  # found nothing at all -- the shape that makes a structural check
  # worthless. The count is a floor, not the exact number, so adding a
  # gate does not break it.
  check(consuming >= 10,
    "t_optin_variable_is_in_the_cache_key: the scanner found opt-in " &
    "variables in " & $consuming & " gate sources (needs at least 10, " &
    "so the check below cannot pass by finding nothing)")

  let missing = undeclaredVariables(workflows, sources)
  check(missing.len == 0,
    "t_optin_variable_is_in_the_cache_key: every opt-in variable a gate " &
    "reads is declared on the action that runs it" &
    (if missing.len == 0: ""
     else: ", but these are not: " & missing.join("; ")))

  # NEGATIVE CONTROL. The same procedure, over the same sources, against a
  # recipe with ONE declaration removed. If this does not report the
  # removed variable, the positive result above is worth nothing.
  let brokenWorkflows = workflows.replace("\"" & SubjectLayer & "\", ", "")
  check(brokenWorkflows != workflows,
    "t_optin_variable_is_in_the_cache_key: the negative control really " &
    "changed the recipe text it checks against")
  let brokenMissing = undeclaredVariables(brokenWorkflows, sources)
  var namedTheRemoval = false
  for item in brokenMissing:
    if SubjectLayer in item: namedTheRemoval = true
  check(namedTheRemoval,
    "t_optin_variable_is_in_the_cache_key: removing one declaration is " &
    "detected, and the report NAMES the variable that lost it")

  # SECOND NEGATIVE CONTROL, and the one this gate would be worthless
  # without. Deleting a declaration is the honest way to lose it; the
  # cheap way is to comment it out, which leaves every string this scan
  # looks for exactly where it was. That is not a hypothetical: the
  # original count of these variables was taken with a grep, and every
  # one of the six it called "declared" was a comment line. So the same
  # procedure is run against a recipe whose declaration has been
  # COMMENTED OUT rather than removed, and it must still report it.
  let commentedDecl = "extraEnv = optInLayers(unreachable = [\"" &
    CommentControlLayer & "\"]),"
  let raw = readFile(WorkflowsPath)
  check(raw.count(commentedDecl) == 1,
    "t_optin_variable_is_in_the_cache_key: the comment control found the " &
    "one-line declaration it comments out (" & CommentControlLayer & ")")
  let commentedWorkflows = withoutComments(
    raw.replace(commentedDecl, "# " & commentedDecl))
  var namedTheComment = false
  for item in undeclaredVariables(commentedWorkflows, sources):
    if CommentControlLayer in item: namedTheComment = true
  check(namedTheComment,
    "t_optin_variable_is_in_the_cache_key: a declaration that has been " &
    "COMMENTED OUT counts as absent -- the scan reads code, not text that " &
    "merely mentions the variable")

proc caseUnreachableLayersRideNonCacheableActions() =
  ## An unreachable layer's variable is deliberately left undeclared, so
  ## that an operator's request is inherited and can be refused out loud
  ## instead of being silently replaced. That is only safe while the
  ## action cannot serve a cached result: an unkeyed input on a cacheable
  ## action is the stale-hit hole this whole gate is about. The pairing is
  ## checked here rather than asserted in a comment.
  proc offendersIn(workflows: string): tuple[checked: int;
                                             offenders: seq[string]] =
    ## Factored out so the control below can run the SAME procedure over a
    ## recipe that has been broken on purpose. ``= optInLayers(`` rather
    ## than ``optInLayers(`` matches the CALL and not the proc definition,
    ## which is not an action and has no cacheable setting of its own.
    var i = 0
    while true:
      let decl = workflows.find("= optInLayers(", i)
      if decl < 0: break
      i = decl + 1
      let close = workflows.find(')', decl)
      if close < 0: continue
      if "unreachable" notin workflows[decl .. close]: continue
      result.checked.inc
      # The action's own cacheable setting follows its extraEnv, and the
      # next action id bounds the search for the same reason as above.
      let nextAction = workflows.find("actionId = \"", close)
      let cacheable = workflows.find("cacheable = false", close)
      if cacheable < 0 or (nextAction >= 0 and nextAction < cacheable):
        result.offenders.add(workflows[decl .. close].splitLines()[0])

  # Comments are stripped first. A comment reading `cacheable = false`
  # above an action that is `cacheable = true` would otherwise satisfy
  # this scan exactly as a `#` line satisfied the grep that first counted
  # these variables; the control below constructs that arrangement.
  let workflows = withoutComments(readFile(WorkflowsPath))
  let (checked, offenders) = offendersIn(workflows)
  check(checked >= 10,
    "t_optin_variable_is_in_the_cache_key: found " & $checked &
    " actions declaring an unreachable layer (needs at least 10)")
  check(offenders.len == 0,
    "t_optin_variable_is_in_the_cache_key: every action that carries an " &
    "unreachable opt-in layer is cacheable = false, so an inherited " &
    "request can never be answered from another setting's cache entry" &
    (if offenders.len == 0: "" else: ", but these are not: " &
     offenders.join("; ")))

  # NEGATIVE CONTROL, in the shape that would otherwise defeat this scan:
  # the action really becomes cacheable, and a COMMENT is left behind
  # saying it is not. The pairing this case checks is the only reason an
  # unreachable layer may stay undeclared, so a scan a comment can satisfy
  # would leave that reasoning resting on nothing.
  let decoyed = withoutComments(readFile(WorkflowsPath).replace(
    "extraEnv = optInLayers(unreachable = [\"" & CommentControlLayer &
      "\"]),\n      cacheable = false)",
    "extraEnv = optInLayers(unreachable = [\"" & CommentControlLayer &
      "\"]),\n      # cacheable = false\n      cacheable = true)"))
  check(decoyed != workflows,
    "t_optin_variable_is_in_the_cache_key: the cacheable control really " &
    "made one action cacheable behind a comment that says otherwise")
  check(offendersIn(decoyed).offenders.len > 0,
    "t_optin_variable_is_in_the_cache_key: an action made cacheable with " &
    "a `cacheable = false` COMMENT left above it is still reported -- the " &
    "scan reads code, not text that merely resembles it")

# ---------------------------------------------------------------------------
# t_unreachable_layer_is_not_a_silent_skip
# ---------------------------------------------------------------------------

proc nimCcArgs(): string = getEnv("REPROOS_NIM_CC_ARGS")

proc runSubject(work: string; settings: openArray[(string, string)]):
    tuple[output: string; exitCode: int] =
  ## Run the compiled subject gate with EXACTLY the given values for the
  ## four contract variables and the caller's environment for everything
  ## else.
  ##
  ## The child's environment is built as a TABLE rather than by prefixing
  ## assignments to a command line, so a variable this case does not set is
  ## genuinely ABSENT in the child instead of inherited from whatever is
  ## running this gate. An inherited contract variable is precisely the
  ## condition under test, and a harness that leaked one would make the
  ## ambient arm below assert the opposite of what it says.
  var childEnv = newStringTable()
  for k, v in envPairs():
    childEnv[k] = v
  for name in [DeclaredLayersEnv, UnreachableLayersEnv, SubjectLayer,
               OtherLayer]:
    if childEnv.hasKey(name): childEnv.del(name)
  for (k, v) in settings:
    childEnv[k] = v
  execCmdEx(quoteShell(work / "subject-gate"), env = childEnv)

proc caseUnreachableIsNotASilentSkip() =
  let work = getTempDir() / "reproos-optin-layers-" & $getCurrentProcessId()
  removeDir(work)
  createDir(work)
  defer: removeDir(work)

  let compile = execCmdEx("nim c --hints:off --warnings:off " & nimCcArgs() &
    " --nimcache:" & quoteShell(work / "nimcache") &
    " --out:" & quoteShell(work / "subject-gate") & " " &
    quoteShell(RepoRoot / SubjectGate))
  if compile.exitCode != 0:
    fail("t_unreachable_layer_is_not_a_silent_skip: could not compile the " &
         "subject gate " & SubjectGate & ":\n" & compile.output)
    return

  # 1. Ambient. Nothing declared, nothing requested: an ordinary skip.
  let ambient = runSubject(work, [])
  check(ambient.exitCode == 0 and "skipped because not requested" in ambient.output,
    "t_unreachable_layer_is_not_a_silent_skip: run from a shell with " &
    "nothing requested, the gate passes and the summary says the layers " &
    "were skipped because nobody asked")
  check("UNREACHABLE" notin ambient.output,
    "t_unreachable_layer_is_not_a_silent_skip: an ambient run does NOT " &
    "claim the layers are unreachable -- from a shell they are not")

  # 2. Inside an action that declares them unreachable, nothing requested.
  #    Still green, and the summary must say something DIFFERENT from (1).
  let declaredEnv = @[(DeclaredLayersEnv, SubjectLayers),
                      (UnreachableLayersEnv, SubjectLayers)]
  let quiet = runSubject(work, declaredEnv)
  check(quiet.exitCode == 0 and "UNREACHABLE here" in quiet.output,
    "t_unreachable_layer_is_not_a_silent_skip: inside a build action that " &
    "cannot run them, an unrequested layer is reported as UNREACHABLE " &
    "rather than as not requested")
  check("skipped because not requested" notin quiet.output,
    "t_unreachable_layer_is_not_a_silent_skip: and the two states do not " &
    "both appear, so the summary line distinguishes them instead of " &
    "hedging")

  # 3. Inside that action, REQUESTED. This is the state that used to be a
  #    green skip, and it must now be a failure that names the remedy.
  let asked = runSubject(work, declaredEnv & @[(SubjectLayer, "1")])
  check(asked.exitCode != 0,
    "t_unreachable_layer_is_not_a_silent_skip: asking for a layer the " &
    "action cannot run FAILS (exit " & $asked.exitCode & ")")
  check("cannot run inside a build action" in asked.output,
    "t_unreachable_layer_is_not_a_silent_skip: the failure says the layer " &
    "cannot run here")
  check("Run it from a shell instead" in asked.output and
        "tests/test-verity-root.sh" in asked.output,
    "t_unreachable_layer_is_not_a_silent_skip: and it names the command " &
    "that WOULD run it, because installing something would not help")

  # 4. Inside an action that never declared this layer at all. That is a
  #    recipe bug, and it is loud whether or not anybody asked -- which is
  #    the only way the state all thirteen of them were in could have been
  #    seen.
  let undeclared = runSubject(work,
    [(DeclaredLayersEnv, OtherLayer), (UnreachableLayersEnv, OtherLayer)])
  check(undeclared.exitCode != 0 and "declaration bug" in undeclared.output,
    "t_unreachable_layer_is_not_a_silent_skip: a variable the action " &
    "never declared is a declaration bug, and it fails WITHOUT anyone " &
    "having requested the layer")
  check(SubjectLayer in undeclared.output and
        "repro/workflows.nim" in undeclared.output,
    "t_unreachable_layer_is_not_a_silent_skip: the declaration bug names " &
    "the variable and the file the declaration belongs in")

caseEveryConsumedVariableIsDeclared()
caseUnreachableLayersRideNonCacheableActions()
caseUnreachableIsNotASilentSkip()

if failures > 0:
  stderr.writeLine("test_optin_layers: " & $failures & " check(s) failed, " &
                   $passes & " passed")
  quit(1)
var summary = "opt-in gate layers: PASS (" & $passes & " checks"
if layerSummaryFragment().len > 0:
  summary.add ", " & layerSummaryFragment()
summary.add ")"
echo summary
