## ReproOS Anywhere: the installer's storage broker.
##
## Runs INSIDE the takeover environment, never on the controller and never
## on the source system. It is a thin, finite-vocabulary front end to
## Reprobuild's own disko port (`repro_profile/disk_apply`), the code
## `repro disk apply` runs: the full `repro` binary is a 1.4 GiB closure
## and cannot ride in a RAM-resident installer, but its applier is four
## small modules, so they are compiled in here instead of being
## re-implemented.
##
## Subcommands (each prints one JSON object on stdout):
##
##   resolve  --serial S --size-sectors N
##       Find the ONE whole disk whose kernel-reported serial is S and
##       whose size is N sectors. Refuses on zero or several matches, and
##       when the disk or any partition of it has holders or is mounted
##       or used as swap. Reports the live device node and major:minor.
##
##   destroy  --device D --serial S --size-sectors N --confirm-plan HASH
##       The point of no return, as its own step: re-resolve, then erase
##       every filesystem/RAID/LVM/partition-table signature on each
##       partition and on the disk itself (`wipefs -af`, which also
##       clears the backup GPT), and make the kernel drop the old
##       partitions. Nothing is created.
##
##   apply    <disko.json> --device D --serial S --size-sectors N
##            [--identity identity.json] --confirm-plan HASH
##       Re-runs `resolve` and refuses unless it still names D, then
##       applies the document to D (wipe, partition, format). HASH is the
##       acknowledged plan identity; it is echoed into the result so the
##       journal binds what was destroyed to what was authorised, and an
##       empty one is refused.
##
##   install-root <install-root flags>
##       Runs Reprobuild's `repro infra install-root` driver itself
##       (fstab, hostname, kernel/initrd copy, grub-install, grub.cfg)
##       with `--no-rsync`: the root was already materialised from the
##       verified payload. Flags pass through unchanged.
##
##   mount    <disko.json> --target DIR
##   unmount  <disko.json> --target DIR
##       Mount / unmount the layout under DIR, in the order the disko
##       port derives.
##
## Exit status: 0 success, 2 refused (nothing was changed), 1 failed after
## a mutation may have started.

import std/[json, options, os, osproc, strutils, tables]

import repro_profile/types
import repro_profile/emit
import repro_profile/disk_apply
import repro_profile/disk_identity
import repro_profile/disk_tools
import repro_cli_support/disk as cliDisk
import repro_cli_support/infra_install_root

const SysBlock = "/sys/block"

proc readFirst(path: string): string =
  try: readFile(path).strip() except IOError, OSError: ""

proc refuse(msg: string): int =
  echo $(%*{"ok": false, "refused": true, "error": msg})
  2

proc fail(msg: string; extra: JsonNode = newJObject()): int =
  var j = %*{"ok": false, "refused": false, "error": msg}
  for k, v in extra: j[k] = v
  echo $j
  1

proc flagValue(args: seq[string]; name: string): string =
  for i in 0 ..< args.len:
    if args[i] == name and i + 1 < args.len:
      return args[i + 1]
  ""

proc positional(args: seq[string]): seq[string] =
  var i = 0
  while i < args.len:
    if args[i].startsWith("--"):
      i += 2
    else:
      result.add args[i]
      inc i

proc mountedSources(): seq[string] =
  for line in readFile("/proc/self/mounts").splitLines():
    let f = line.splitWhitespace()
    if f.len >= 2: result.add f[0]
  for line in readFile("/proc/swaps").splitLines()[1 .. ^1]:
    let f = line.splitWhitespace()
    if f.len >= 1: result.add f[0]

proc diskBusy(name: string; mounted: seq[string]): string =
  ## "" when neither the disk nor a partition of it is held, mounted or
  ## swapped on; otherwise the reason.
  let base = SysBlock / name
  var nodes = @[name]
  for kind, p in walkDir(base):
    if kind in {pcDir, pcLinkToDir} and fileExists(p / "partition"):
      nodes.add p.extractFilename
  for n in nodes:
    let dir = if n == name: base else: base / n
    for _, h in walkDir(dir / "holders"):
      return "/dev/" & n & " is held by " & h.extractFilename
    if ("/dev/" & n) in mounted:
      return "/dev/" & n & " is mounted or used as swap"
  ""

proc resolveDisk(serial: string; sizeSectors: string):
    tuple[device, devnum, error: string] =
  if serial.len == 0:
    return ("", "", "no serial given; a disk is never selected by its name")
  var hits: seq[string] = @[]
  for kind, p in walkDir(SysBlock):
    let n = p.extractFilename
    if n.startsWith("loop") or n.startsWith("ram") or n.startsWith("zram"):
      continue
    var s = readFirst(p / "serial")
    if s.len == 0: s = readFirst(p / "device" / "serial")
    if s == serial: hits.add n
  if hits.len == 0:
    return ("", "", "no disk reports serial " & serial)
  if hits.len > 1:
    return ("", "", "serial " & serial & " is reported by " & $hits.len &
      " disks (" & hits.join(", ") & "); refusing an ambiguous identity")
  let n = hits[0]
  let size = readFirst(SysBlock / n / "size")
  if size != sizeSectors:
    return ("", "", "disk " & n & " with serial " & serial & " has " & size &
      " sectors, the plan was made for " & sizeSectors)
  let busy = diskBusy(n, mountedSources())
  if busy.len > 0:
    return ("", "", busy)
  ("/dev/" & n, readFirst(SysBlock / n / "dev"), "")

proc runFixed(cmd: string): (string, int) =
  ## Run a fixed command line built only from resolved device names.
  let (o, c) = osproc.execCmdEx(cmd)
  (o, c)

proc loadLayout(path: string): DiskLayout =
  let spec = parseSystemHardwareJson(readFile(path).strip())
  if spec.disko.isNone:
    raise newException(ValueError, path & " has no disko block")
  spec.disko.get()

proc main(): int =
  let all = commandLineParams()
  if all.len == 0:
    return refuse("usage: anywhere_disk resolve|apply|mount|unmount ...")
  let sub = all[0]
  let args = all[1 .. ^1]
  case sub
  of "resolve":
    let r = resolveDisk(flagValue(args, "--serial"),
                        flagValue(args, "--size-sectors"))
    if r.error.len > 0: return refuse(r.error)
    echo $(%*{"ok": true, "device": r.device, "devnum": r.devnum})
    0
  of "destroy":
    let device = flagValue(args, "--device")
    let planHash = flagValue(args, "--confirm-plan")
    if planHash.len != 64 or not planHash.allCharsInSet(HexDigits):
      return refuse("destroy needs --confirm-plan with the 64-hex plan identity")
    let r = resolveDisk(flagValue(args, "--serial"),
                        flagValue(args, "--size-sectors"))
    if r.error.len > 0: return refuse(r.error)
    if device.len == 0 or r.device != device:
      return refuse("serial now resolves to " & r.device &
        ", the plan named " & device)
    let name = device.extractFilename
    var ops = newJArray()
    var parts: seq[string] = @[]
    for kind, p in walkDir(SysBlock / name):
      if kind in {pcDir, pcLinkToDir} and fileExists(p / "partition"):
        parts.add "/dev/" & p.extractFilename
    for node in parts & @[device]:
      let res = wipefsAll(node)
      ops.add %*{"tool": res.tool, "cmd": res.cmd, "exit": res.exit}
      if res.exit != 0:
        return fail("wipefs " & node & " failed", %*{"operations": ops})
    let (_, rr) = runFixed("blockdev --rereadpt " & device)
    ops.add %*{"tool": "blockdev", "cmd": "blockdev --rereadpt " & device, "exit": rr}
    echo $(%*{"ok": true, "device": device, "devnum": r.devnum,
              "planHash": planHash, "operations": ops})
    0
  of "apply":
    let pos = positional(args)
    let device = flagValue(args, "--device")
    let planHash = flagValue(args, "--confirm-plan")
    if pos.len != 1 or device.len == 0:
      return refuse("apply needs <disko.json> and --device")
    if planHash.len != 64 or not planHash.allCharsInSet(HexDigits):
      return refuse("apply needs --confirm-plan with the 64-hex plan identity")
    let r = resolveDisk(flagValue(args, "--serial"),
                        flagValue(args, "--size-sectors"))
    if r.error.len > 0: return refuse(r.error)
    if r.device != device:
      return refuse("serial now resolves to " & r.device &
        ", the plan named " & device)
    var layout: DiskLayout
    try:
      layout = loadLayout(pos[0])
    except CatchableError as e:
      return refuse("cannot load " & pos[0] & ": " & e.msg)
    if layout.disks.len != 1:
      return refuse("the document describes " & $layout.disks.len &
        " disks; Anywhere converts exactly one")
    for _, d in layout.disks:
      if d.device != device:
        return refuse("the document targets " & d.device &
          ", not the resolved " & device)
    var identity = DiskIdentity()
    let idPath = flagValue(args, "--identity")
    if idPath.len > 0:
      try:
        identity = parseDiskIdentityDocument(readFile(idPath), idPath)
      except CatchableError as e:
        return refuse("identity document: " & e.msg)
    let res = applyDiskLayout(layout, initTable[string, string](), identity)
    var ops = newJArray()
    for op in res.operations:
      ops.add %*{"tool": op.tool, "cmd": op.cmd, "exit": op.exit}
    if res.failure:
      return fail("apply failed at " & res.failureStep & ": " & res.failureMsg,
        %*{"operations": ops, "planHash": planHash})
    echo $(%*{"ok": true, "device": device, "devnum": r.devnum,
              "planHash": planHash, "operations": ops})
    0
  of "install-root":
    if "--no-rsync" notin args:
      return refuse("install-root is only run with --no-rsync here")
    let loader: DiskoLoader = proc(path: string): DiskPlanOutcome =
      cliDisk.loadDiskoFromSource(path)
    let o = runInstallRoot(args, loader)
    if o.failure:
      return fail("install-root: " & o.failureMsg,
        %*{"kind": $o.failureKind, "grubExit": o.grubInstallExit})
    echo $(%*{"ok": true, "fstab": o.fstabPath, "grubCfg": o.grubCfgPath,
              "grubExit": o.grubInstallExit})
    0
  of "mount", "unmount":
    let pos = positional(args)
    let target = flagValue(args, "--target")
    if pos.len != 1 or target.len == 0:
      return refuse(sub & " needs <disko.json> and --target")
    let layout = loadLayout(pos[0])
    if sub == "mount":
      let plan = mountDiskLayout(layout, target)
      var m = newJArray()
      for (dev, mp) in plan: m.add %*[dev, mp]
      echo $(%*{"ok": true, "mounts": m})
    else:
      unmountDiskLayout(collectMountPlan(layout, target))
      echo $(%*{"ok": true})
    0
  else:
    refuse("unknown subcommand " & sub)

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    quit(fail("unexpected error: " & e.msg))
