## ``reproos-generation`` — the generation stager of an attested ReproOS.
##
## This is a thin, typed front end over ``repro/generations.nim``. Every
## decision that matters — which slot a generation may be written into, what
## makes a store describe itself truthfully, and why an attested instance
## cannot switch a generation under itself — lives in that module and is
## exercised directly by ``tests/test_generations.nim``. What lives here is
## argument parsing, reading the inputs off disk, and printing the report.
##
## What each subcommand does:
##
##   ``stage``          Write a generation into the slot the machine is NOT
##                      running from, point the next boot at it, and report
##                      ``reboot-required: yes``. The running generation is
##                      untouched. This is what an apply on an attested image
##                      performs instead of switching.
##   ``rollback``       Point the next boot back at the generation in the
##                      other slot. Nothing is rebuilt; the previous unified
##                      kernel image has been sitting there since it was
##                      staged, which is what makes rollback atomic.
##   ``status``         Print the store and check it against the bytes on the
##                      ESP.
##   ``activate-now``   Ask for the generation to take effect on the running
##                      system. On an attested machine this is REFUSED, and
##                      the refusal is the point: the launch measurement was
##                      taken at boot and nothing extends it, so a generation
##                      switched underneath a running system would leave every
##                      report the machine produced describing a configuration
##                      that is not executing. The command exists so that an
##                      operator or a caller can ask and be told no, with the
##                      remedy, rather than discovering a missing capability.
##
## Exit codes:
##   64 = usage
##   65 = an input is missing or unusable
##   66 = the operation is refused (this is where a live switch lands)
##   70 = the operation failed part way
##
## No mocking: every path here reads and writes real files under the ESP
## directory it is given.

import std/[os, strutils]

import "../repro/generations" as gen

proc usage(message: string) =
  if message.len > 0:
    stderr.writeLine("reproos-generation: " & message)
  stderr.writeLine("""
usage:
  reproos-generation stage --esp DIR --uki PATH [--slot a|b] [--attested]
      (--verity-root-hash HEX | --verity-root-hash-file PATH)
      --verity-data SPEC --verity-hash SPEC
  reproos-generation rollback --esp DIR [--attested]
  reproos-generation status --esp DIR
  reproos-generation activate-now --esp DIR --uki PATH [--attested]
      (--verity-root-hash HEX | --verity-root-hash-file PATH)
      --verity-data SPEC --verity-hash SPEC""")
  quit(64)

type Options = object
  esp: string
  ukiPath: string
  rootHash: string
  dataDevice: string
  hashDevice: string
  slot: gen.GenerationSlot
  slotGiven: bool
  attested: bool

proc parseOptions(args: seq[string]; start: int): Options =
  var i = start
  proc valueOf(flag: string): string =
    if i + 1 >= args.len:
      usage(flag & " needs a value")
    i.inc
    args[i]
  while i < args.len:
    let a = args[i]
    case a
    of "--esp": result.esp = valueOf(a)
    of "--uki": result.ukiPath = valueOf(a)
    of "--verity-root-hash": result.rootHash = valueOf(a)
    of "--verity-root-hash-file":
      # Read from the file the verity build writes rather than passed as a
      # value, for the same reason the assembler does it: the root hash is
      # a function of the staged tree, and a transcribed one is a second
      # declaration of it.
      let path = valueOf(a)
      if not fileExists(path):
        stderr.writeLine("reproos-generation: no verity root hash at " & path)
        quit(65)
      result.rootHash = readFile(path).strip()
    of "--verity-data": result.dataDevice = valueOf(a)
    of "--verity-hash": result.hashDevice = valueOf(a)
    of "--slot":
      let raw = valueOf(a)
      case raw
      of "a": result.slot = gen.gsA
      of "b": result.slot = gen.gsB
      else: usage("--slot takes a or b, not " & raw.escape())
      result.slotGiven = true
    of "--attested":
      # Whether this machine's boot is measured. It is what turns the
      # slot discipline from a convention into a refusal.
      result.attested = true
    else: usage("unknown flag " & a.escape())
    i.inc

proc requireEsp(opts: Options) =
  if opts.esp.len == 0:
    usage("--esp is required; it is the mounted EFI system partition")
  if not dirExists(opts.esp):
    stderr.writeLine("reproos-generation: no ESP directory at " & opts.esp)
    quit(65)

proc loadStore(opts: Options): gen.GenerationStore =
  try:
    gen.readGenerationStore(opts.esp)
  except ValueError as e:
    stderr.writeLine("reproos-generation: " & e.msg)
    quit(65)
    gen.GenerationStore()

proc stageRequest(opts: Options; slot: gen.GenerationSlot):
    gen.GenerationStageRequest =
  if opts.ukiPath.len == 0:
    usage("--uki is required")
  if opts.rootHash.len == 0:
    usage("one of --verity-root-hash or --verity-root-hash-file is required")
  if opts.dataDevice.len == 0 or opts.hashDevice.len == 0:
    usage("--verity-data and --verity-hash are both required; a generation " &
          "names both volumes of its verity pair or it names neither")
  gen.GenerationStageRequest(
    ukiPath: opts.ukiPath,
    verityRootHash: opts.rootHash,
    devices: gen.AttestedBootDevices(
      data: opts.dataDevice,
      hash: opts.hashDevice,
      stateVar: "LABEL=" & gen.StateVarLabel,
      stateHome: "LABEL=" & gen.StateHomeLabel),
    slot: slot,
    attested: opts.attested)

proc reportProblems(store: gen.GenerationStore): int =
  let problems = gen.verifyGenerationStore(store)
  for p in problems:
    stderr.writeLine("reproos-generation: " & p)
  if problems.len > 0: 70 else: 0

proc main() =
  let args = commandLineParams()
  if args.len == 0:
    usage("no subcommand")
  let sub = args[0]
  let opts = parseOptions(args, 1)
  requireEsp(opts)

  case sub
  of "status":
    let store = loadStore(opts)
    stdout.write gen.renderGenerationStatus(store)
    quit(reportProblems(store))

  of "stage":
    var store = loadStore(opts)
    # The slot is CHOSEN rather than defaulted to whatever was asked for:
    # a stage that is not told which slot goes into the one the machine is
    # not running from, which is the whole of the A/B discipline.
    let slot = if opts.slotGiven: opts.slot else: gen.nextStagingSlot(store)
    var outcome: gen.GenerationOutcome
    try:
      outcome = gen.stageGeneration(store, stageRequest(opts, slot))
    except ValueError as e:
      stderr.writeLine("reproos-generation: " & e.msg)
      quit(66)
    stdout.write gen.renderGenerationOutcome(outcome)
    quit(reportProblems(store))

  of "rollback":
    var store = loadStore(opts)
    var outcome: gen.GenerationOutcome
    try:
      outcome = gen.rollbackGeneration(store, opts.attested)
    except ValueError as e:
      stderr.writeLine("reproos-generation: " & e.msg)
      quit(66)
    stdout.write gen.renderGenerationOutcome(outcome)
    quit(reportProblems(store))

  of "activate-now":
    # The live switch. It is routed through the SAME primitive `stage`
    # uses, pointed at the slot the machine is running from — so the
    # refusal below is the only thing between this command and a machine
    # whose boot artifacts no longer describe what it is executing. That
    # is deliberate: a refusal that guards nothing is not a refusal.
    var store = loadStore(opts)
    if not store.hasCurrent:
      stderr.writeLine("reproos-generation: this ESP holds no current " &
        "generation, so there is no running generation to activate over; " &
        "use `stage`.")
      quit(66)
    var outcome: gen.GenerationOutcome
    try:
      outcome = gen.stageGeneration(store, stageRequest(opts, store.current))
    except ValueError as e:
      stderr.writeLine("reproos-generation: " & e.msg)
      quit(66)
    stdout.write gen.renderGenerationOutcome(outcome)
    quit(reportProblems(store))

  else:
    usage("unknown subcommand " & sub.escape())

main()
