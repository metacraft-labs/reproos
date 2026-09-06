## Gate: a guest booted on the ReproOS kernel and initramfs really has
## dm-verity and a TPM.
##
## The kernel-config gate in the ``reprobuild-packages`` sibling proves
## the recipe RESOLVES to a configuration with dm-verity, dm-crypt and
## the TPM drivers built in, and the initramfs gate next door proves the
## initramfs SELECTS and LOADS them. Neither observes a running kernel.
## This one does: it direct-kernel-boots the bzImage the kernel recipe
## built, with an initramfs built by the product's own
## ``build-initramfs.sh``, under QEMU with a vTPM attached, and reads the
## guest's own report off the serial console.
##
## ## What it asserts
##
## From the ``init-attest-probe`` initramfs variant (see
## ``recipes/reproos-iso/initramfs/init-attest-probe``), in order:
##
##   * ``REPROOS-A3-MODULE=dm_verity:builtin`` — the running kernel's own
##     ``modules.builtin`` names it, so it is compiled in rather than
##     absent.
##   * ``REPROOS-A3-DM-CONTROL=present`` — ``/dev/mapper/control``, the
##     device-mapper ioctl endpoint through which any table, verity
##     included, is loaded.
##   * ``REPROOS-A3-VERITY-TARGET=present`` — ``/sys/module/dm_verity``,
##     which the kernel creates because dm-verity registers a module
##     parameter. It is the running kernel stating that the verity target
##     is registered.
##   * ``REPROOS-A3-TPM-DEVICE=present`` and
##     ``REPROOS-A3-TPM2-GETCAP-FAMILY=…322e3000`` — ``/dev/tpm0`` opened
##     and a real TPM2_GetCapability round trip whose response carries the
##     ASCII family indicator ``"2.0\0"``. Only a real, running,
##     responding TPM 2.0 produces those bytes.
##
## ## What it does NOT assert, and why
##
## It does not load an actual dm-verity table. Doing that needs
## ``dmsetup`` (or ``CONFIG_DM_INIT`` plus a ``dm-mod.create=`` command
## line) and a hash tree over a real backing image; the initramfs is
## BusyBox-only and BusyBox has no ``dmsetup`` applet. The strongest
## statement obtainable from inside this guest is "the target is
## registered and the ioctl endpoint is live", and that is what is
## asserted. Loading a real table belongs with the milestone that builds
## a verity-hashed root and can run ``veritysetup`` from the ReproOS
## rootfs.
##
## ## Why it is artifact-conditional
##
## It needs the source-built kernel (bzImage + module tree) and the
## source-built BusyBox. Building those is a multi-hour job. When they
## are absent this reports a SKIP naming the remedy — never a pass — and
## no fixture stands in for a boot.
##
## ## Mocking
##
## None. A real QEMU child process, a real swtpm, the real product
## initramfs builder, and the kernel the recipe built.

import std/[os, osproc, strutils]

import vm_harness

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  IsoRecipeDir = RepoRoot / "recipes" / "reproos-iso"
  BuilderPath = IsoRecipeDir / "scripts" / "build-initramfs.sh"
  ProbeInit = "init-attest-probe"

  KernelInstallEnv = "REPRO_KERNEL_INSTALL_ROOT"
  BusyboxInstallEnv = "REPRO_BUSYBOX_INSTALL_ROOT"
  PackagesRootEnv = "REPROBUILD_PACKAGES_ROOT"

  AttestationVmNamePrefix = "reproos-att-a3-"
    ## Campaign-wide naming rule from the ReproOS attestation execution
    ## plan: every VM this campaign creates is uniquely named under a
    ## ``reproos-att-<milestone>-`` prefix, so a sweep can find what the
    ## campaign leaked and nothing it does can be confused with the
    ## production guests that share this host.

var failures = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message

proc skip(message: string) =
  echo "[skip] " & message

proc packagesRoot(): string =
  let fromEnv = getEnv(PackagesRootEnv)
  if fromEnv.len > 0: fromEnv
  else: RepoRoot.parentDir() / "reprobuild-packages"

proc sourceInstallRoot(pkg: string): string =
  packagesRoot() / "packages" / "source" / pkg / ".repro" / "output" / "install"

proc envOr(name, fallback: string): string =
  let v = getEnv(name)
  if v.len > 0: v else: fallback

proc shellQuote(s: string): string =
  "'" & s.replace("'", "'\\''") & "'"

proc probeSteps(perStepTimeoutSec: int): seq[BootSmokeStep] =
  @[
    BootSmokeStep(pattern: "REPROOS-A3-PROBE-START",
                  timeoutSec: perStepTimeoutSec,
                  label: "the ReproOS kernel reached the probe initramfs"),
    BootSmokeStep(pattern: "REPROOS-A3-MODULE=dm_verity:builtin",
                  timeoutSec: perStepTimeoutSec,
                  label: "dm-verity is compiled into the running kernel"),
    BootSmokeStep(pattern: "REPROOS-A3-DM-CONTROL=present",
                  timeoutSec: perStepTimeoutSec,
                  label: "the device-mapper ioctl endpoint is live"),
    BootSmokeStep(pattern: "REPROOS-A3-VERITY-TARGET=present",
                  timeoutSec: perStepTimeoutSec,
                  label: "the running kernel registered the verity target"),
    BootSmokeStep(pattern: "REPROOS-A3-TPM-DEVICE=present",
                  timeoutSec: perStepTimeoutSec,
                  label: "/dev/tpm0 exists in the guest"),
    BootSmokeStep(pattern: r"REPROOS-A3-TPM2-GETCAP-FAMILY=[0-9a-f]*322e3000",
                  timeoutSec: perStepTimeoutSec,
                  label: "a real TPM 2.0 answered GetCapability with " &
                         "family \"2.0\""),
    BootSmokeStep(pattern: "REPROOS-A3-PROBE-DONE",
                  timeoutSec: perStepTimeoutSec,
                  label: "the probe finished rather than hanging"),
  ]

block guestProbe:
  when not defined(linux):
    skip("ReproOS kernel/TPM guest probe requires a Linux host " &
         "(QEMU direct-kernel boot + swtpm)")
  else:
    let kernelRoot = envOr(KernelInstallEnv, sourceInstallRoot("kernel"))
    let busyboxRoot = envOr(BusyboxInstallEnv, sourceInstallRoot("busybox"))
    let payload = kernelRoot / "usr" / "lib" / "reproos-kernel"
    let remedy =
      "Build them with `repro build kernelSource` and " &
      "`repro build busyboxSource` in the reprobuild-packages sibling " &
      "(multi-hour), or point " & KernelInstallEnv & " / " &
      BusyboxInstallEnv & " at existing install mirrors. Expected at " &
      kernelRoot & " and " & busyboxRoot & "."

    if not fileExists(payload / "vmlinuz") or
       not fileExists(payload / "kernel.release"):
      skip("no source-built ReproOS kernel present. " & remedy)
      break guestProbe
    if not fileExists(busyboxRoot / "usr" / "bin" / "busybox"):
      skip("no source-built BusyBox present. " & remedy)
      break guestProbe

    let work = getTempDir() / "reproos-a3-guest-" & $getCurrentProcessId()
    removeDir(work)
    createDir(work)

    let initramfs = work / "initramfs-attest-probe.img"
    let buildCmd =
      "SOURCE_DATE_EPOCH=1577836800 " &
      KernelInstallEnv & "=" & shellQuote(kernelRoot) & " " &
      BusyboxInstallEnv & "=" & shellQuote(busyboxRoot) & " " &
      "REPRO_INITRAMFS_INIT=" & shellQuote(ProbeInit) & " " &
      "bash " & shellQuote(BuilderPath) & " " & shellQuote(initramfs)
    let built = execCmdEx(buildCmd)
    if built.exitCode != 0:
      stderr.writeLine(built.output)
      fail("build-initramfs.sh failed for the " & ProbeInit & " variant")
      removeDir(work)
      break guestProbe

    echo "[info] kernel:    ", payload / "vmlinuz"
    echo "[info] initramfs: ", initramfs

    let r = runBootSmoke(BootSmokeSpec(
      caseName: "reproos-kernel-verity-tpm",
      kernelPath: payload / "vmlinuz",
      initrdPath: initramfs,
      kernelCmdline: "console=ttyS0 panic=1 loglevel=4",
      generation: 1,
      cpus: 2,
      memoryMB: 1024,
      acceleration: baAuto,
      tpmEnabled: true,
      namePrefix: AttestationVmNamePrefix,
      artifactDir: RepoRoot / "build" / "test-artifacts" / "a3-guest",
      steps: probeSteps(perStepTimeoutSec = 120)))

    if not r.ok:
      stderr.writeLine("[diag] " & r.failureMessage)
      stderr.writeLine("[diag] serial log: " & r.serialLogPath)
      stderr.writeLine(serialLogExcerpt(r.serialLogPath))
      fail("the ReproOS kernel did not report dm-verity and a working " &
           "TPM 2.0 from inside a guest")
      removeDir(work)
      break guestProbe

    if not fileExists(r.serialLogPath) or getFileSize(r.serialLogPath) <= 0:
      fail("no serial transcript was captured at " & r.serialLogPath)
      removeDir(work)
      break guestProbe

    # Nothing may be left behind on the passing path either.
    if dirExists(r.runDir):
      fail("the run directory survived a passing boot: " & r.runDir)
      removeDir(work)
      break guestProbe
    var survivors: seq[string]
    for p in qemuBootProcessesMatching(AttestationVmNamePrefix):
      if p.name == r.vmName:
        survivors.add($p.pid & ":" & p.name)
    if survivors.len > 0:
      fail("QEMU processes survived a passing boot: " & survivors.join(", "))
      removeDir(work)
      break guestProbe

    echo "[info] serial transcript: ", r.serialLogPath
    pass("a guest on the ReproOS kernel reports dm-verity built in, the " &
         "device-mapper ioctl endpoint live, and a TPM 2.0 answering " &
         "GetCapability, in " & $r.elapsedMs & " ms, leaving nothing behind")
    removeDir(work)

if failures > 0:
  stderr.writeLine("test_guest_verity_and_tpm_available: " & $failures &
                   " check(s) failed")
  quit(1)
echo "guest verity + TPM availability: PASS"
