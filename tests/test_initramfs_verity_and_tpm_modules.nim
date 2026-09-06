## Gate: the initramfs can actually activate dm-verity and reach a TPM.
##
## Two things have to be true and they are easy to get half right:
##
##   1. ``build-initramfs.sh`` must SELECT the device-mapper and TPM
##      drivers, so that a kernel which ships them as modules gets them
##      staged into the cpio, and
##   2. ``/init`` must LOAD them. A module that is present in the archive
##      and never loaded is not enablement — the root filesystem is set
##      up inside the initramfs, so a driver that arrives afterwards
##      arrives too late.
##
## Those are two lists in two different files (three, counting the
## live-boot ``init`` and the disk ``init-disk``), and nothing but this
## gate keeps them in step.
##
## ## The built-in case, which is the case that actually ships
##
## The source-built ReproOS kernel compiles dm-verity, dm-crypt and the
## TPM drivers IN (``=y``) rather than as modules — see the kernel recipe
## in the ``reprobuild-packages`` sibling and its
## ``test_kernel_config_has_attestation_knobs`` gate. So on the kernel
## that ships there is no ``dm_verity.ko`` to stage and ``modprobe
## dm_verity`` fails in exactly the way a genuinely absent driver does.
##
## That is why "contains the modules" is checked as a CAPABILITY rather
## than as a file listing: for each required driver the built initramfs
## must either carry its ``.ko`` or the paired kernel's
## ``modules.builtin`` must list it — and ``modules.builtin`` must be in
## the archive, because otherwise ``/init`` has no way to tell the two
## apart and would report a boot-critical built-in driver as missing.
##
## ## Cases
##
## Case 1 is unconditional and needs nothing built. It reads the three
## product files and asserts the selection list, the two loader lists and
## the built-in handling agree. It is falsifiable in both directions: a
## driver name that is in none of the files must be reported absent by
## the same parsers that report the real ones present.
##
## Case 2 is artifact-conditional. It runs the REAL
## ``build-initramfs.sh`` against a REAL kernel module tree and the
## source-built BusyBox, and inspects the cpio it produces. Building
## those inputs is a multi-hour job needing sudo, so when they are not
## present this reports a SKIP naming the remedy — never a pass, and no
## fixture stands in for the archive.
##
## ## Mocking
##
## None. Case 1 parses the shipped scripts themselves rather than a copy
## of their contents. Case 2 runs the shipped builder against a real
## module tree and reads the bytes it wrote.

import std/[os, osproc, sequtils, strutils]

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  IsoRecipeDir = RepoRoot / "recipes" / "reproos-iso"
  BuilderPath = IsoRecipeDir / "scripts" / "build-initramfs.sh"
  InitScripts = ["init", "init-disk"]

  RequiredSelected = [
    ## Every driver the initramfs must be able to provide. ``dm_bufio``
    ## and ``tpm_tis_core`` are dependency layers rather than things
    ## anybody names directly, and they are here because a modular
    ## kernel that staged ``dm_verity.ko`` without ``dm_bufio.ko`` would
    ## produce an initramfs whose verity activation fails at insmod time.
    "dm_mod", "dm_bufio", "dm_crypt", "dm_verity",
    "tpm", "tpm_tis_core", "tpm_tis", "tpm_crb",
  ]

  RequiredLoaded = [
    ## The subset ``/init`` must actually bring up. Same list: there is
    ## no driver here that is worth staging and not worth loading.
    "dm_mod", "dm_bufio", "dm_crypt", "dm_verity",
    "tpm", "tpm_tis_core", "tpm_tis", "tpm_crb",
  ]

  ControlModule = "dm_reproos_control_absent"
    ## A name that appears in none of the product files. If the parsers
    ## reported it present, every check below would pass against
    ## anything.

  KernelInstallEnv = "REPRO_KERNEL_INSTALL_ROOT"
  BusyboxInstallEnv = "REPRO_BUSYBOX_INSTALL_ROOT"
  PackagesRootEnv = "REPROBUILD_PACKAGES_ROOT"

var failures = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message

proc skip(message: string) =
  echo "[skip] " & message

proc readProduct(path: string): string =
  if not fileExists(path):
    fail("product file missing: " & path)
    return ""
  readFile(path)

# ---------------------------------------------------------------------------
# Parsers over the shipped scripts
# ---------------------------------------------------------------------------

proc parseRequiredModules(builder: string): seq[string] =
  ## The names inside ``REQUIRED_MODULES=( … )``, comments stripped.
  let openIdx = builder.find("REQUIRED_MODULES=(")
  if openIdx < 0:
    return @[]
  let bodyStart = openIdx + len("REQUIRED_MODULES=(")
  var body = ""
  for line in builder[bodyStart .. ^1].splitLines():
    let stripped = line.strip()
    if stripped == ")":
      break
    let hash = line.find('#')
    let content = if hash >= 0: line[0 ..< hash] else: line
    body.add(content)
    body.add(' ')
  body.splitWhitespace()

proc parseLoadedModules(initScript: string): seq[string] =
  ## The argument of every ``load_module <name>`` call.
  for line in initScript.splitLines():
    let stripped = line.strip()
    if not stripped.startsWith("load_module "):
      continue
    let fields = stripped.splitWhitespace()
    if fields.len >= 2:
      result.add(fields[1])

proc normalised(names: seq[string]): seq[string] =
  ## Kernel module names are written with either separator; the initramfs
  ## builder already resolves both, so compare on one.
  names.mapIt(it.replace('-', '_'))

proc loadModuleBody(initScript: string): string =
  ## The body of the ``load_module`` shell function.
  ##
  ## Asking whether the FILE mentions ``is_builtin`` is not the same
  ## question as whether ``load_module`` CALLS it: the helper's own
  ## definition, and the comment above it, both contain the name. Deleting
  ## just the call leaves every whole-file substring check satisfied while
  ## silently restoring the behaviour this gate exists to prevent — a
  ## built-in dm_verity reported as missing. So the check reads the body.
  let start = initScript.find("load_module() {")
  if start < 0:
    return ""
  var first = true
  for line in initScript[start .. ^1].splitLines():
    if first:
      first = false
      continue
    if line.startsWith("}"):
      break
    result.add(line)
    result.add('\n')

# ---------------------------------------------------------------------------
# Case 1 — unconditional. Selection, loading and built-in handling agree.
# ---------------------------------------------------------------------------

let builderText = readProduct(BuilderPath)

block selectionList:
  if builderText.len == 0:
    break selectionList
  let selected = normalised(parseRequiredModules(builderText))
  if selected.len == 0:
    fail("could not parse REQUIRED_MODULES out of " & BuilderPath)
    break selectionList
  var missing: seq[string]
  for m in RequiredSelected:
    if m notin selected:
      missing.add(m)
  if missing.len > 0:
    fail("build-initramfs.sh does not select: " & missing.join(", "))
    break selectionList
  if ControlModule in selected:
    fail("the control module was reported as selected; the selection " &
         "check would pass against anything")
    break selectionList
  pass("build-initramfs.sh selects every dm-verity and TPM driver (" &
       $RequiredSelected.len & " names) and rejects a control name")

for initName in InitScripts:
  block loaderList:
    let path = IsoRecipeDir / "initramfs" / initName
    let text = readProduct(path)
    if text.len == 0:
      break loaderList
    let loaded = normalised(parseLoadedModules(text))
    if loaded.len == 0:
      fail("could not parse any load_module call out of " & path)
      break loaderList
    var missing: seq[string]
    for m in RequiredLoaded:
      if m notin loaded:
        missing.add(m)
    if missing.len > 0:
      fail(initName & " never loads: " & missing.join(", ") &
           " — a module the initramfs carries and never loads is not " &
           "enablement")
      break loaderList
    if ControlModule in loaded:
      fail("the control module was reported as loaded by " & initName &
           "; the loader check would pass against anything")
      break loaderList
    pass(initName & " loads every dm-verity and TPM driver (" &
         $RequiredLoaded.len & " names) and rejects a control name")

block builtinHandling:
  # The kernel that ships compiles these drivers in, so "modprobe
  # failed" and "the driver is already here" must be distinguishable.
  if builderText.len == 0:
    break builtinHandling
  if not builderText.contains("modules.builtin"):
    fail("build-initramfs.sh does not stage modules.builtin, so /init " &
         "cannot tell a built-in driver from a missing one")
    break builtinHandling
  var bad: seq[string]
  var notConsulted: seq[string]
  for initName in InitScripts:
    let text = readProduct(IsoRecipeDir / "initramfs" / initName)
    if text.len == 0:
      break builtinHandling
    if not text.contains("modules.builtin") or
       not text.contains("is_builtin"):
      bad.add(initName)
      continue
    # The helper must be defined AND called. Only the call changes what
    # the guest does.
    let body = loadModuleBody(text)
    if body.len == 0 or not body.contains("is_builtin"):
      notConsulted.add(initName)
  if bad.len > 0:
    fail("these init scripts do not consult modules.builtin, so a " &
         "built-in dm_verity would be reported missing: " & bad.join(", "))
    break builtinHandling
  if notConsulted.len > 0:
    fail("load_module does not call is_builtin in: " &
         notConsulted.join(", ") & " — the helper is defined but never " &
         "reached, so a built-in dm_verity would still be reported missing")
    break builtinHandling
  pass("build-initramfs.sh stages modules.builtin and both init scripts " &
       "call is_builtin from load_module before declaring a driver absent")

# ---------------------------------------------------------------------------
# Case 2 — artifact-conditional. Build a real initramfs and inspect it.
# ---------------------------------------------------------------------------

proc packagesRoot(): string =
  let fromEnv = getEnv(PackagesRootEnv)
  if fromEnv.len > 0: fromEnv
  else: RepoRoot.parentDir() / "reprobuild-packages"

proc sourceInstallRoot(pkg: string): string =
  packagesRoot() / "packages" / "source" / pkg / ".repro" / "output" / "install"

proc kernelInstallRoot(): string =
  let fromEnv = getEnv(KernelInstallEnv)
  if fromEnv.len > 0: fromEnv else: sourceInstallRoot("kernel")

proc busyboxInstallRoot(): string =
  let fromEnv = getEnv(BusyboxInstallEnv)
  if fromEnv.len > 0: fromEnv else: sourceInstallRoot("busybox")

proc run(cmd: string): tuple[output: string, code: int] =
  let r = execCmdEx(cmd)
  (output: r.output, code: r.exitCode)

proc shellQuote(s: string): string =
  "'" & s.replace("'", "'\\''") & "'"

block buildRealInitramfs:
  when not defined(linux):
    skip("initramfs build requires a Linux host (cpio + kernel module tree)")
  else:
    let kernelRoot = kernelInstallRoot()
    let busyboxRoot = busyboxInstallRoot()
    let payload = kernelRoot / "usr" / "lib" / "reproos-kernel"
    let remedy =
      "Build them with `repro build kernelSource` and " &
      "`repro build busyboxSource` in the reprobuild-packages sibling " &
      "(multi-hour), or point " & KernelInstallEnv & " / " &
      BusyboxInstallEnv & " at existing install mirrors. Expected at " &
      kernelRoot & " and " & busyboxRoot & "."
    if not fileExists(payload / "vmlinuz") or
       not fileExists(payload / "kernel.release"):
      skip("no source-built kernel install mirror present. " & remedy)
      break buildRealInitramfs
    if not fileExists(busyboxRoot / "usr" / "bin" / "busybox"):
      skip("no source-built BusyBox install mirror present. " & remedy)
      break buildRealInitramfs

    let release = readFile(payload / "kernel.release").strip()
    let modRoot = kernelRoot / "usr" / "lib" / "modules" / release
    if not dirExists(modRoot):
      fail("kernel install mirror has no module tree at " & modRoot)
      break buildRealInitramfs

    let work = getTempDir() / "reproos-a3-initramfs-" & $getCurrentProcessId()
    removeDir(work)
    createDir(work)

    for initName in InitScripts:
      let extractDir = work / initName
      createDir(extractDir)
      let outImage = work / ("initramfs-" & initName & ".img")
      let cmd =
        "SOURCE_DATE_EPOCH=1577836800 " &
        KernelInstallEnv & "=" & shellQuote(kernelRoot) & " " &
        BusyboxInstallEnv & "=" & shellQuote(busyboxRoot) & " " &
        "REPRO_INITRAMFS_INIT=" & shellQuote(initName) & " " &
        "bash " & shellQuote(BuilderPath) & " " & shellQuote(outImage)
      let built = run(cmd)
      if built.code != 0:
        stderr.writeLine(built.output)
        fail("build-initramfs.sh failed for init variant " & initName)
        continue
      if not fileExists(outImage) or getFileSize(outImage) <= 0:
        fail("build-initramfs.sh produced no archive for " & initName)
        continue

      let listing = run("gzip -dc " & shellQuote(outImage) &
                        " | cpio -t --quiet 2>/dev/null")
      if listing.code != 0:
        fail("could not list the initramfs produced for " & initName)
        continue
      let entries = listing.output.splitLines().mapIt(it.strip())

      # modules.builtin must be inside the archive, or /init's built-in
      # detection has nothing to read.
      let builtinEntry = entries.filterIt(it.endsWith("modules.builtin"))
      if builtinEntry.len == 0:
        fail("the built initramfs for " & initName &
             " carries no modules.builtin")
        continue

      var builtinText = ""
      let extract = run("cd " & shellQuote(extractDir) & " && gzip -dc " &
        shellQuote(outImage) & " | cpio -id --quiet 2>/dev/null && cat " &
        shellQuote("./lib/modules/" & release & "/modules.builtin"))
      if extract.code == 0:
        builtinText = extract.output

      var unavailable: seq[string]
      for m in RequiredSelected:
        let underscore = m.replace('-', '_')
        let dash = m.replace('_', '-')
        let staged = entries.anyIt(
          it.endsWith("/" & underscore & ".ko") or
          it.endsWith("/" & dash & ".ko"))
        let builtin =
          builtinText.contains("/" & underscore & ".ko") or
          builtinText.contains("/" & dash & ".ko")
        if not staged and not builtin:
          unavailable.add(m)
      if unavailable.len > 0:
        fail("the built initramfs for " & initName & " provides neither a " &
             "module nor a built-in for: " & unavailable.join(", "))
        continue

      # The /init inside the archive is the one that runs, so assert the
      # load calls there rather than only in the source tree.
      let initInArchive = extractDir / "init"
      if not fileExists(initInArchive):
        fail("the built initramfs for " & initName & " has no /init")
        continue
      let archivedLoads = normalised(
        parseLoadedModules(readFile(initInArchive)))
      var notLoaded: seq[string]
      for m in RequiredLoaded:
        if m notin archivedLoads:
          notLoaded.add(m)
      if notLoaded.len > 0:
        fail("the /init inside the built initramfs for " & initName &
             " never loads: " & notLoaded.join(", "))
        continue

      pass("the built initramfs for " & initName & " provides every " &
           "dm-verity and TPM driver (module or built-in) and its /init " &
           "loads them")

    removeDir(work)

if failures > 0:
  stderr.writeLine("test_initramfs_verity_and_tpm_modules: " & $failures &
                   " check(s) failed")
  quit(1)
echo "initramfs verity + TPM modules: PASS"
