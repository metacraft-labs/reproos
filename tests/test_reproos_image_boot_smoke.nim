## Boot gate for the installed ReproOS ``uefi-ext4`` disk image.
##
## Boots the image produced by ``recipes/reproos-image`` under OVMF and
## asserts an ordered serial sequence through to a login prompt, using
## vm-harness's ``runBootSmoke`` (``vm_harness/boot_smoke.nim``): a real
## ``qemu-system-x86_64`` child process, the same cursor-advancing
## ``SerialLineBuffer`` / ``expectLineImpl`` engine every vm-harness
## backend uses, and unconditional teardown of the process, the CoW
## overlay and the run directory.
##
## *The sequence and where it comes from.* Not invented, and not merely
## asserted to be so: it is read off a recorded ReproOS boot, checked in
## at ``tests/fixtures/reproos-boot-serial-m9r71-v4.log``. That
## transcript emits these four markers in this order —
##
##   1. ``Linux version …``            — GRUB handed off; the kernel runs
##   2. ``Welcome to ReproOS!``        — this is *our* userspace, not a
##                                       stray rescue initramfs
##   3. ``Reached target Multi-User System`` — systemd finished boot
##   4. ``<host> login:``              — getty is up on the console
##
## Step 2 is what makes the gate specific rather than "some Linux
## booted", and step 4 is the milestone's stated end state.
##
## *Why the patterns are not the plain strings above.* systemd colours
## its status output, so on the wire markers 2 and 3 arrive with SGR
## escape sequences *inside* them::
##
##   ESC[0;1;39mWelcome to ESC[0mESC[1mReproOSESC[0mESC[0;1;39m!ESC[0m
##   [ ESC[0;32m  OK  ESC[0m] Reached target ESC[0;1;39mMulti-User SystemESC[0m.
##
## Matching runs on the raw serial bytes, so a plain-substring pattern
## for either marker cannot match a real boot — it would fail the gate
## for a reason that has nothing to do with the boot. ``AnsiSgr`` below
## admits exactly the escape runs systemd interposes and nothing else,
## and ``*`` means an uncoloured console (``TERM=dumb``, a piped log)
## still matches.
##
## That is not left to inspection either: case 1 below replays the
## checked-in transcript through the same engine the live gate uses, in
## order, and asserts a control pattern that is absent from the log does
## NOT match. It runs unconditionally, so the provenance claim above is
## enforced rather than documented.
##
## *Why case 2 is artifact-conditional and case 1 is not.* There is no
## prebuilt ReproOS image in the tree and building one is a multi-hour,
## 118-source-package job needing ``sudo`` and ``modprobe nbd``. So case
## 2 runs when an image is present and reports a SKIP naming the remedy
## when it is not. A skip is reported as a skip and never as a pass, and
## no fixture stands in for the image.
##
## *Mocking.* None. Case 1 replays real recorded bytes through the real
## matching engine; case 2 boots a real image under a real QEMU. The
## harness itself is proven falsifiable in vm-harness by
## ``tests/integration/t_boot_smoke_harness_fails_on_missing_line.nim``
## and ``tests/integration/t_boot_smoke_harness_tears_down_on_failure.nim``,
## which run unconditionally there against a synthetic guest.
##
## *Fixture provenance.* ``tests/fixtures/reproos-boot-serial-m9r71-v4.log``
## is a verbatim copy of a real recorded ReproOS boot console
## (``m9r71_boot_serial_v4.log``), captured during ReproOS image
## bring-up. It is evidence, not a hand-written sample: it still carries
## the OVMF ``BdsDxe:`` banner, the Debian 6.12.86 kernel banner and the
## SGR-coloured systemd status lines this gate's patterns exist to
## tolerate.

import std/[os, strutils]

import vm_harness

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  ReferenceTranscript = "tests/fixtures/reproos-boot-serial-m9r71-v4.log"
  ImageEnvOverride = "REPROOS_IMAGE"
  RecipeImageOutput = "recipes/reproos-image/build/reproos-installed.qcow2"
  AttestationVmNamePrefix = "reproos-att-a1-"
    ## Campaign-wide naming rule from the ReproOS attestation execution
    ## plan: every VM this campaign creates is uniquely named under a
    ## ``reproos-att-<milestone>-`` prefix so that (a) a sweep can find
    ## what the campaign leaked and (b) nothing the campaign does can
    ## ever be confused with production guests sharing the same host.

var failures = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message

proc skip(message: string) =
  echo "[skip] " & message

const AnsiSgr = r"(?:\x1b\[[0-9;]*m)*"
  ## A run of zero or more SGR ("select graphic rendition") escapes —
  ## the only thing systemd interposes inside its status messages.
  ## Zero-or-more, so an uncoloured console matches the same pattern.

proc reproosImageBootSteps(perLineTimeoutSec: int): seq[BootSmokeStep] =
  @[
    BootSmokeStep(pattern: r"Linux version \d+\.\d+",
                  timeoutSec: perLineTimeoutSec,
                  label: "the bootloader handed control to the kernel"),
    BootSmokeStep(pattern: "Welcome to " & AnsiSgr & "ReproOS" &
                           AnsiSgr & "!",
                  timeoutSec: perLineTimeoutSec,
                  label: "ReproOS userspace started (not a rescue initramfs)"),
    BootSmokeStep(pattern: "Reached target " & AnsiSgr &
                           "Multi-User System",
                  timeoutSec: perLineTimeoutSec,
                  label: "systemd finished bringing the system up"),
    BootSmokeStep(pattern: r"[A-Za-z0-9_.-]+ login: ",
                  timeoutSec: perLineTimeoutSec,
                  label: "a getty login prompt is live on the console"),
  ]

proc findReproosImage(): string =
  ## ``$REPROOS_IMAGE`` first, then the recipe's engine output directory,
  ## then its in-tree ``build/`` output.
  let fromEnv = getEnv(ImageEnvOverride)
  if fromEnv.len > 0 and fileExists(fromEnv):
    return fromEnv
  # ``repro build image`` installs under a content-addressed name, so
  # glob rather than guess the hash.
  let installDir =
    RepoRoot / "recipes" / "reproos-image" / ".repro" / "output" / "install"
  if dirExists(installDir):
    var newest = ""
    for path in walkPattern(installDir / "*reproos-installed*.qcow2"):
      if newest.len == 0 or path > newest:
        newest = path
    if newest.len > 0:
      return newest
  let inTree = RepoRoot / RecipeImageOutput
  if fileExists(inTree):
    return inTree
  ""

# ---------------------------------------------------------------------------
# Case 1 — unconditional. The expected sequence matches the recorded boot.
#
# It needs no image, no QEMU and no host hypervisor, only the transcript
# this repository carries. Its job is to keep the gate's patterns and the
# evidence they were derived from from drifting apart: a pattern that
# cannot match a real ReproOS boot would otherwise sit here unnoticed for
# as long as no image is around to run case 2 against.

block replayRecordedTranscript:
  let logPath = RepoRoot / ReferenceTranscript
  if not fileExists(logPath):
    fail("reference transcript missing: " & logPath)
    break replayRecordedTranscript
  let transcript = readFile(logPath)
  if transcript.len == 0:
    fail("reference transcript is empty: " & logPath)
    break replayRecordedTranscript

  var buf = newSerialLineBuffer()
  buf.feed(transcript)
  var unmatched: seq[string]
  for step in reproosImageBootSteps(perLineTimeoutSec = 1):
    # 50 ms: the buffer is already full, so a match is immediate and a
    # miss must not cost a wall-clock second per step.
    let m = expectLineImpl(buf, step.pattern, 50, 10, nil)
    if not m.matched:
      unmatched.add(step.pattern & "  (" & step.label & ")")
  # Ordered, because expectLineImpl advances the cursor past each match:
  # asserting all four is asserting the sequence.
  if unmatched.len > 0:
    for u in unmatched:
      stderr.writeLine("[diag] absent from " & ReferenceTranscript & ": " & u)
    fail("the expected serial sequence does not match the recorded " &
         "ReproOS transcript (" & $unmatched.len & " of 4 patterns unmatched)")
    break replayRecordedTranscript

  # …and the replay is falsifiable in the other direction too: a marker
  # the recorded boot never printed must NOT match, or the check above
  # would pass against anything.
  var control = newSerialLineBuffer()
  control.feed(transcript)
  let absent = expectLineImpl(
    control, r"Reached target Nonexistent Attestation Target", 50, 10, nil)
  if absent.matched:
    fail("a control pattern absent from the recorded transcript matched; " &
         "the replay check would pass against anything")
    break replayRecordedTranscript

  pass("the expected serial sequence matches the recorded ReproOS " &
       "transcript, in order, and rejects a control pattern")

# ---------------------------------------------------------------------------
# Case 2 — artifact-conditional. A real image boots to a login prompt.

block bootInstalledImage:
  when not defined(linux):
    skip("ReproOS uefi-ext4 image boot requires a Linux host " &
         "(QEMU direct-boot backend + OVMF)")
  else:
    let image = findReproosImage()
    if image.len == 0:
      skip("ReproOS uefi-ext4 image boot: no image present. Build one " &
           "with `repro build image --tool-provisioning=from-source` " &
           "(multi-hour; needs sudo + `modprobe nbd`) or point " &
           ImageEnvOverride & "=<path-to-reproos-installed.qcow2> at an " &
           "existing one. Expected in-tree at " & RecipeImageOutput & ".")
      break bootInstalledImage

    echo "[info] booting ReproOS image: ", image
    let r = runBootSmoke(BootSmokeSpec(
      caseName: "reproos-image",
      imagePath: image,
      imageFormat: "qcow2",
      generation: 2,
      cpus: 2,
      memoryMB: 2048,
      acceleration: baAuto,
      namePrefix: AttestationVmNamePrefix,
      artifactDir: RepoRoot / "build" / "test-artifacts" / "boot-smoke",
      steps: reproosImageBootSteps(perLineTimeoutSec = 300)))

    if not r.ok:
      stderr.writeLine("[diag] " & r.failureMessage)
      stderr.writeLine("[diag] serial log: " & r.serialLogPath)
      stderr.writeLine(serialLogExcerpt(r.serialLogPath))
      fail("ReproOS uefi-ext4 image did not boot through to a login prompt")
      break bootInstalledImage
    if r.matches.len != 4:
      fail("expected 4 serial matches, got " & $r.matches.len)
      break bootInstalledImage
    if not fileExists(r.serialLogPath) or getFileSize(r.serialLogPath) <= 0:
      fail("no serial transcript was captured at " & r.serialLogPath)
      break bootInstalledImage

    # Teardown holds for the passing path too, not only the failing one
    # vm-harness's dedicated gate covers.
    if dirExists(r.runDir):
      fail("the run directory survived a passing boot: " & r.runDir)
      break bootInstalledImage
    var survivors: seq[string]
    for p in qemuBootProcessesMatching(AttestationVmNamePrefix):
      if p.name == r.vmName:
        survivors.add($p.pid & ":" & p.name)
    if survivors.len > 0:
      fail("QEMU processes survived a passing boot: " & survivors.join(", "))
      break bootInstalledImage

    echo "[info] serial transcript: ", r.serialLogPath
    pass("ReproOS uefi-ext4 image booted under OVMF through to a login " &
         "prompt in " & $r.elapsedMs & " ms, leaving nothing behind")

if failures > 0:
  stderr.writeLine("test_reproos_image_boot_smoke: " & $failures &
                   " check(s) failed")
  quit(1)
echo "reproos image boot smoke: PASS"
