## ``reproos-uki`` — the tool the UKI assembly action runs.
##
## This is a thin, typed front end over ``repro/uki.nim``. Every decision
## that matters — which sections exist, what order they are written in,
## how the command line is composed out of the verity values, what the
## PE headers say — lives in that module and is exercised directly by
## ``tests/test_uki.nim``. What lives here is argument parsing, reading
## the inputs off disk, and writing the four declared outputs.
##
## Why a tool at all, rather than a shell action calling ``objcopy``:
## the section layout, the alignment arithmetic and the command-line
## composition are the parts of a UKI that decide what a launch
## measurement covers. Expressed as a shell pipeline they would be
## unreadable, untestable except by building an image, and impossible to
## keep in step with the initrd that parses the same keys. Expressed as
## typed Nim they are checked by a gate that needs no privileged tooling.
##
## Usage:
##   reproos-uki assemble --stub PATH --kernel PATH [--initrd PATH]
##     (--cmdline TEXT | --verity-root-hash-file PATH)
##     [--verity-data DEV] [--verity-hash DEV]
##     [--state-var DEV] [--state-home DEV] [--extra-arg ARG]...
##     [--os-release-version V] [--uname TEXT | --uname-file PATH]
##     --source-date-epoch N --out PATH
##     [--manifest PATH] [--digest-out PATH] [--cmdline-out PATH]
##
## Exit codes:
##   64 = usage
##   65 = an input is missing or unusable (the stub, the kernel, the initrd)
##   66 = the spec is not one an attested image may boot with
##   70 = assembly failed

import std/[os, strutils]

import "../repro/uki" as uki

proc usage(message: string) =
  if message.len > 0:
    stderr.writeLine("reproos-uki: " & message)
  stderr.writeLine("""
usage: reproos-uki assemble --stub PATH --kernel PATH [--initrd PATH]
         (--cmdline TEXT | --verity-root-hash-file PATH)
         [--verity-data DEV] [--verity-hash DEV]
         [--state-var DEV] [--state-home DEV] [--extra-arg ARG]...
         [--os-release-version V] [--uname TEXT | --uname-file PATH]
         --source-date-epoch N --out PATH
         [--manifest PATH] [--digest-out PATH] [--cmdline-out PATH]""")
  quit(64)

proc main() =
  let args = commandLineParams()
  if args.len == 0:
    usage("no subcommand")
  if args[0] != "assemble":
    usage("unknown subcommand " & args[0].escape())

  var
    stub = ""
    kernel = ""
    initrd = ""
    cmdline = ""
    rootHashFile = ""
    verityData = ""
    verityHash = ""
    stateVar = ""
    stateHome = ""
    osReleaseVersion = "0.1.0"
    uname = ""
    sourceDateEpoch = 0'i64
    outPath = ""
    manifestPath = ""
    digestPath = ""
    cmdlinePath = ""
    extraArgs: seq[string] = @[]

  var i = 1
  proc valueOf(flag: string): string =
    if i + 1 >= args.len:
      usage(flag & " needs a value")
    i.inc
    args[i]

  while i < args.len:
    let a = args[i]
    case a
    of "--stub": stub = valueOf(a)
    of "--kernel": kernel = valueOf(a)
    of "--initrd": initrd = valueOf(a)
    of "--cmdline": cmdline = valueOf(a)
    of "--verity-root-hash-file": rootHashFile = valueOf(a)
    of "--verity-data": verityData = valueOf(a)
    of "--verity-hash": verityHash = valueOf(a)
    of "--state-var": stateVar = valueOf(a)
    of "--state-home": stateHome = valueOf(a)
    of "--extra-arg": extraArgs.add valueOf(a)
    of "--os-release-version": osReleaseVersion = valueOf(a)
    of "--uname": uname = valueOf(a)
    of "--uname-file":
      # The kernel release, read from the file the kernel package
      # publishes rather than transcribed into the recipe. A transcribed
      # release string is a second declaration of the kernel version and
      # it is measured, so it would move the launch measurement without
      # the kernel having moved.
      let path = valueOf(a)
      if not fileExists(path):
        stderr.writeLine("reproos-uki: no kernel release at " & path)
        quit(65)
      uname = readFile(path).strip()
    of "--source-date-epoch":
      let raw = valueOf(a)
      try: sourceDateEpoch = parseBiggestInt(raw)
      except ValueError: usage("--source-date-epoch is not a number: " & raw)
    of "--out": outPath = valueOf(a)
    of "--manifest": manifestPath = valueOf(a)
    of "--digest-out": digestPath = valueOf(a)
    of "--cmdline-out": cmdlinePath = valueOf(a)
    else: usage("unknown flag " & a.escape())
    i.inc

  if outPath.len == 0:
    usage("--out is required")
  if stub.len == 0:
    # Resolving here rather than defaulting in the recipe keeps ONE
    # implementation of "which stub" — the content-addressed one in
    # repro/uki.nim — instead of a second one in the caller.
    stub = uki.resolveUkiStub()
    if stub.len == 0:
      stderr.writeLine(uki.describeUkiStubSearch())
      quit(65)

  # The command line. When a verity root-hash file is given it is
  # COMPOSED from the values repro/verity.nim declares, so the string the
  # image measures and the keys the initrd parses come from one place.
  var rootHash = ""
  if rootHashFile.len > 0:
    if not fileExists(rootHashFile):
      stderr.writeLine("reproos-uki: no verity root hash at " & rootHashFile)
      quit(65)
    rootHash = readFile(rootHashFile).strip()
    if cmdline.len > 0:
      stderr.writeLine("reproos-uki: --cmdline and " &
        "--verity-root-hash-file are mutually exclusive; a command line " &
        "that is partly composed and partly literal is a command line " &
        "nothing can re-derive")
      quit(64)
    cmdline = uki.attestedKernelCmdline(rootHash, verityData, verityHash,
                                        stateVar, stateHome, extraArgs)
    let cmdlineError = uki.validateAttestedCmdline(cmdline, rootHash)
    if cmdlineError.len > 0:
      stderr.writeLine("reproos-uki: " & cmdlineError)
      quit(66)
  elif cmdline.len == 0:
    usage("one of --cmdline or --verity-root-hash-file is required")

  let spec = uki.UkiSpec(
    stubPath: stub,
    kernelPath: kernel,
    initrdPath: initrd,
    cmdline: cmdline,
    osRelease: uki.defaultOsRelease(osReleaseVersion),
    uname: uname,
    sourceDateEpoch: sourceDateEpoch)

  let specError = uki.validateUkiSpec(spec)
  if specError.len > 0:
    stderr.writeLine("reproos-uki: " & specError)
    quit(66)

  var image = ""
  try:
    image = uki.assembleUkiFromFiles(spec)
  except CatchableError as e:
    stderr.writeLine("reproos-uki: " & e.msg)
    quit(70)

  createDir(outPath.parentDir)
  writeFile(outPath, image)
  if manifestPath.len > 0:
    writeFile(manifestPath, uki.renderUkiManifest(spec, image))
  if digestPath.len > 0:
    writeFile(digestPath, uki.ukiDigest(image) & "\n")
  if cmdlinePath.len > 0:
    writeFile(cmdlinePath, cmdline & "\n")

  echo "[uki] ", outPath, " ", image.len, " bytes"
  echo "[uki] sha256 ", uki.ukiDigest(image)
  echo "[uki] cmdline ", cmdline

main()
