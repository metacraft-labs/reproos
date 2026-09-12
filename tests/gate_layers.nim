## Opt-in gate layers: the three states, and why two of them look alike.
##
## Several gates in this repository are built in layers. An always-on layer
## costs about a second and needs nothing but the Nim gate toolchain; an
## opt-in layer builds a real filesystem, boots a real guest, or writes a
## real partition table, and is asked for with an environment variable
## (``REPROOS_UKI_BOOT_GATE=1`` and friends).
##
## A layer that did not run can be in one of THREE states, and for a long
## time the summary line spelled the last two the same way:
##
##   1. **it ran** — requested, and executed;
##   2. **not requested** — nobody asked. Nothing was proved, and that is
##      fine, because nothing was claimed;
##   3. **unreachable here** — the layer could not have run in this process
##      no matter what the caller asked for.
##
## State 3 is the one this module exists for. A build action's ``PATH``
## carries exactly the tools the recipe declared for it, and the tools these
## layers need — ``veritysetup``, ``mkfs.ext4``, ``qemu-system-x86_64``,
## ``sgdisk``, ``swtpm``, ``mmd`` — are deliberately NOT declared. Several
## of them are from-source packages here, so declaring one would make an
## always-on gate bootstrap a package before it could run; others need
## privilege, a loopback block device or a kernel module, none of which a
## hermetic action has. So inside a build action those layers cannot run,
## and reporting them as "not requested" told the reader that the expensive
## work was merely switched off when in fact it was out of reach.
##
## THE RULE, and it is the same rule a missing TOOL already gets in
## ``tests/nim-gate.sh``: being asked for something that cannot be done is a
## DECLARATION BUG, not a skip. ``optInLayer`` returns ``lrUnreachable``
## when a layer is requested inside an action that declares it unreachable,
## and every caller turns that into a failure with the ambient command that
## WOULD run it. Nothing here makes a gate quieter; the whole point is to
## make a silent state loud.
##
## ## The contract with the recipe
##
## ``repro/workflows.nim`` declares, on each gate action:
##
##   * ``REPRO_GATE_DECLARED_LAYERS`` — every opt-in variable this action
##     knows about, comma-separated. Its PRESENCE is what tells a gate it is
##     running inside a build action rather than from a shell.
##   * ``REPRO_GATE_UNREACHABLE_LAYERS`` — the subset that cannot run inside
##     a hermetic action.
##   * for a REACHABLE layer only, that layer's own variable, carrying the
##     value the ACTION chose.
##
## The last of those is not decoration. A declared name REPLACES the
## inherited one at launch and is mixed into the action's cache key, so an
## ambient ``REPROOS_UKI_BOOT_GATE=1`` can no longer change what a build
## action does without changing the action's key — which is exactly the way
## an engine run could previously return a result computed under a different
## setting and report success.
##
## AN UNREACHABLE LAYER'S VARIABLE IS DELIBERATELY LEFT UNDECLARED, and the
## reason is the inverse of the one above. If the action declared it, the
## declared value would replace the operator's — so someone who exported
## ``REPROOS_UKI_BOOT_GATE=1`` and ran ``repro build`` would have the request
## silently discarded and be told the layer was "not requested". Leaving it
## inherited is what lets this module SEE the request and fail on it. That
## is safe only because every action carrying an unreachable layer is
## ``cacheable = false``, so no setting's result can be replayed under
## another; ``tests/test_optin_layers.nim`` checks that pairing.
##
## Run from a shell, none of the three is set, ``insideDeclaredAction()`` is
## false, and every gate behaves as it always did: the caller's variable is
## read directly and a missing tool is still a failure rather than a skip.

import std/[os, strutils]

const
  DeclaredLayersEnv* = "REPRO_GATE_DECLARED_LAYERS"
    ## Set by the recipe on every gate action that has an opt-in layer.
  UnreachableLayersEnv* = "REPRO_GATE_UNREACHABLE_LAYERS"
    ## The subset of the above that a hermetic action cannot run.

type
  LayerRequest* = enum
    lrNotRequested   ## nobody asked for it
    lrRun            ## asked for, and this process may run it
    lrUnreachable    ## asked for, and this process CANNOT run it
    lrUndeclared     ## the action running this gate never heard of it

var
  notRequestedLayers: seq[string] = @[]
  unreachableLayers: seq[string] = @[]

proc isBlocked*(request: LayerRequest): bool =
  ## The two outcomes a gate must turn into a FAILURE. Grouped behind one
  ## predicate on purpose: a call site that enumerated the failing cases by
  ## hand would eventually gain a third and forget one, and forgetting one
  ## means running a layer that should have been refused.
  request in {lrUnreachable, lrUndeclared}

proc splitNames(raw: string): seq[string] =
  for item in raw.split(','):
    let name = item.strip()
    if name.len > 0:
      result.add(name)

proc insideDeclaredAction*(): bool =
  ## True when this process runs inside a build action whose recipe
  ## declared its opt-in layer set. ``existsEnv`` rather than a non-empty
  ## test: an action with an empty declared set still made a declaration,
  ## and that is a different statement from having made none.
  existsEnv(DeclaredLayersEnv)

proc declaredLayers*(): seq[string] = splitNames(getEnv(DeclaredLayersEnv))

proc unreachableHere*(envName: string): bool =
  insideDeclaredAction() and envName in splitNames(getEnv(UnreachableLayersEnv))

proc optInLayer*(envName: string; requested: bool): LayerRequest =
  ## Classify one opt-in layer, with the caller deciding what "requested"
  ## means. Most layers are switched on with ``=1``; one carries a path
  ## instead, and a path is requested when it is non-empty.
  ##
  ## Reachability is decided BEFORE the request is read, because the two
  ## questions are independent and the unreachable-and-not-requested case is
  ## the one that has been reported dishonestly: it is not "nobody asked",
  ## it is "asking here would not have helped".
  ##
  ## AN UNDECLARED LAYER FAILS WHETHER OR NOT IT WAS ASKED FOR, and that is
  ## deliberate. It means this gate reads a variable that the action running
  ## it has no opinion about — the state every one of these layers was in
  ## before this existed. Failing only when the layer is REQUESTED would
  ## leave that state exactly as invisible as it was, because the ordinary
  ## run does not request anything. It is the same rule tests/nim-gate.sh
  ## applies to TOOLS, applied to layers: being unable to honour a contract
  ## is a declaration bug, and a declaration bug is loud.
  if insideDeclaredAction() and envName notin declaredLayers():
    return lrUndeclared
  if unreachableHere(envName):
    if requested:
      return lrUnreachable
    if envName notin unreachableLayers:
      unreachableLayers.add(envName)
    return lrNotRequested
  if requested:
    return lrRun
  if envName notin notRequestedLayers:
    notRequestedLayers.add(envName)
  lrNotRequested

proc optInLayer*(envName: string): LayerRequest =
  ## The common spelling: the layer is requested when the variable is ``1``.
  optInLayer(envName, getEnv(envName) == "1")

proc blockedNote*(envName, ambientCommand: string): string =
  ## The text a gate prints when it must refuse a layer. Two different
  ## refusals, two different texts, because they have two different
  ## remedies and printing one for the other sends the reader to the wrong
  ## file. Neither may read like a missing dependency: installing something
  ## would not fix either of them.
  if not (envName in declaredLayers()):
    "declaration bug: this gate reads " & envName & ", but the action " &
      "running it declares no opt-in layer by that name. Add it to the " &
      "optInLayers(...) call for this gate's action in repro/workflows.nim " &
      "-- as `unreachable` if a hermetic action cannot run it, which is " &
      "the usual answer. Until then nobody can tell from a green run " &
      "whether this layer was switched off or simply out of reach, and " &
      "that is the state this check exists to end."
  else:
    envName & " was requested, but this layer cannot run inside a build " &
      "action: the action's PATH carries only the tools the recipe declares " &
      "for it, and this layer's tools are deliberately not declared (they " &
      "are from-source packages here, or need privilege or a real block " &
      "device). This is a declaration mismatch, not a missing tool, and it " &
      "fails rather than skipping so that no run reports success without " &
      "having done the work.\n" &
      "  Run it from a shell instead: " & ambientCommand

proc notRequestedNote*(envName: string): string =
  ## The text a gate prints when a layer was not asked for. Under a build
  ## action that cannot run it, say so — otherwise the reader concludes the
  ## expensive work was merely switched off.
  if unreachableHere(envName):
    envName & " was not requested, and could not have run here anyway " &
      "(unreachable inside a build action)."
  else:
    envName & " was not requested."

proc layerSummaryFragment*(): string =
  ## The part of a gate's final line that accounts for its opt-in layers.
  ## Empty when the gate has no layer to account for, so a gate with all
  ## layers running prints nothing extra.
  var parts: seq[string] = @[]
  if notRequestedLayers.len > 0:
    parts.add($notRequestedLayers.len & " layer(s) skipped because not " &
      "requested (" & notRequestedLayers.join(", ") & ")")
  if unreachableLayers.len > 0:
    parts.add($unreachableLayers.len & " layer(s) UNREACHABLE here (" &
      unreachableLayers.join(", ") & ") -- run them from a shell")
  parts.join(", ")

proc layersNotRequested*(): int = notRequestedLayers.len
proc layersUnreachable*(): int = unreachableLayers.len
