## ReproOS Anywhere: render the canonical storage plan for one target.
##
## The controller is Python; the storage plan is not. This is a thin CLI
## over `repro/disk_layouts.nim` -- the ONLY declaration of what a layout
## is -- so a converted machine gets the same disko document the image
## build and the installer apply, byte for byte, rather than a third
## renderer that could drift from them.
##
##   anywhere_layout <auto-config.toml> <device> <disk-size-gb>
##
## prints one JSON object: {"layout", "espSizeMib", "diskSizeGb",
## "disko"} on success, or {"error"} with exit 1 when the request is not
## buildable. <disk-size-gb> is the TARGET disk's real capacity (floored),
## measured by preflight; it replaces the image-only `[disk] size_gb`
## because an existing machine's disk is not chosen by the config.

import std/[json, os, strutils]

import "../../repro/disk_layouts" as diskLayouts

proc main(): int =
  let args = commandLineParams()
  if args.len != 3:
    stderr.writeLine("usage: anywhere_layout <auto-config.toml> <device> <disk-size-gb>")
    return 64
  let text = readFile(args[0])
  var req = diskLayouts.parseDiskLayoutRequest(text, "anywhere", args[1])
  try:
    req.params.diskSizeGb = parseInt(args[2])
  except ValueError:
    stderr.writeLine("anywhere_layout: disk size is not an integer: " & args[2])
    return 64
  let err = diskLayouts.validateDiskLayoutRequest(req)
  if err.len > 0:
    echo $(%*{"error": err})
    return 1
  echo $(%*{
    "layout": req.name,
    "espSizeMib": req.params.espSizeMib,
    "diskSizeGb": req.params.diskSizeGb,
    "device": req.params.device,
    "disko": diskLayouts.renderDiskoJson(req.name, req.params),
  })
  0

when isMainModule:
  quit(main())
