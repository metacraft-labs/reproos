## Gates for "one renderer for the disko document".
##
## ReproOS used to describe the same disk in four places that did not
## agree. ``repro/disk_layouts.nim`` rendered the document the image
## build applies; ``installer_state.cpp`` hand-printed a *different*
## disko JSON (empty labels, ``noatime``, ``/dev/vda``) that shipped as
## ``/etc/repro/disko.json`` in every image, and a *different again*
## ``hardware.nim`` disko block; and both ``installer_state.cpp`` and
## ``tools/reproos-machine-config.py`` carried their own
## ``!= "uefi-ext4"`` literal, so a preset added to the registry was
## still refused by them -- which is why ``uefi-attested`` could not be
## selected through the installer at all.
##
## The fix is not "keep them in step". The registry is compiled into the
## other two languages by ``tools/gen_disk_layouts.nim``, so the C++ and
## Python sides select and substitute rather than render. These gates
## are what keeps the compilation honest.
##
## ## t_registry_addition_fails_a_stale_installer  (NEGATIVE)
##
## The generated files are checked in, because the installer has to
## build from ``apps/reproos-installer`` alone with no Nim available.
## Checked-in generated files can go stale, so this gate re-derives both
## of them from the live registry and requires the bytes on disk to
## match. Add a preset to ``repro/disk_layouts.nim`` and forget to
## regenerate, and this is red before anything else notices.
##
## It proves staleness is detected. It does NOT prove the installer
## binary in ``.repro/output`` was rebuilt from the current header --
## that is the build graph's job, and the image driver's Phase 3b check
## catches a stale *binary* at image-build time.
##
## ## t_disko_document_has_one_renderer
##
## For every registered preset and the same inputs, the installer's
## emitter and ``repro/disk_layouts.nim`` produce identical bytes --
## disko JSON *and* hardware.nim. The C++ side is not re-implemented
## here: this gate compiles the shipped
## ``apps/reproos-installer/src/disk_layouts.cpp`` with a bare ``c++``
## (no Qt, no CMake) and runs it. The matrix includes a device and an id
## containing a quote and a backslash, so the two escapers are compared
## rather than assumed equal.
##
## It runs over the whole registry, so it grows with it. It does NOT
## prove the Qt wrapper calls these functions -- the source read below
## and the artifact comparison against the real binary do that.
##
## ## t_installer_accepts_every_registered_layout
##
## The installer's validator accepts each buildable preset, and its
## message for every refused case is *byte-identical* to
## ``validateDiskLayoutRequest``'s. One registry, one wording.
##
## ## t_installer_refuses_unregistered_and_declared_layouts  (NEGATIVE)
##
## The validator refuses a name no preset carries, listing every legal
## value, and refuses a declared-but-not-yet-buildable preset quoting
## the registry's own recorded reason. Without this the unification
## could be "accept everything", which is worse than the divergence it
## replaces. The gate fails if the refusal does not contain the reason
## text the registry records, so a generic "unsupported layout" cannot
## pass.
##
## The same case matrix is then run through
## ``tools/reproos-machine-config.py``, the operator-facing validator
## that used to carry the third copy of the ``!= "uefi-ext4"`` literal,
## so all three implementations are held to one wording rather than two.
##
## ## t_installed_image_disko_matches_applied_disko
##
## Two documents leave an image build: the one ``repro disk apply``
## consumes, and the one copied to ``/etc/repro/disko.json``. They are
## the same layout from the same registry and must be the same bytes
## once the two identity parameters -- the spec id and the device node
## -- are normalised, which is exactly the check the image driver runs
## at Phase 3b before it takes ``sudo``.
##
## This gate does that comparison for real, in-process, using the C++
## renderer for the installed side and the Nim renderer for the applied
## side; and it reads the shipped driver to confirm the Phase 3b check
## is present, because an equality nobody enforces is not a gate. When
## an installer binary is available it goes further and compares against
## the bytes that binary actually writes.
##
## It does NOT open a built qcow2. No image is built here -- that is a
## multi-hour ``sudo`` + ``modprobe nbd`` job -- so the claim is about
## the documents and the driver step that compares them, not about a
## file inside an image.
##
## ## t_hardware_nim_parses_to_the_registry_layout
##
## The new ``hardware.nim`` is Nim source that ``repro disk plan`` may
## load, so "it renders" is not enough: this gate compiles each
## rendered ``hardware.nim`` through ``repro_profile``'s own
## ``hardware`` macro and requires the resulting
## ``emitSystemHardwareJson`` to equal the canonical emission of the
## registry's own ``SystemHardwareSpec``. The comparison is made with
## the canonical minified emitter, not with the ReproOS pretty-printer,
## so nothing about it depends on the pretty-printer being right.
##
## ## Mocking
##
## None. Every claim is made against shipped files: the registry module,
## the shipped ``disk_layouts.cpp`` compiled as-is, the shipped
## generated header, the shipped image driver read from disk, the
## shipped Qt binary when one is present, and ``repro_profile``'s own
## macro and emitter.

import std/[options, os, osproc, sequtils, strutils]

import repro_profile/types
import repro_profile/emit

import "../repro/disk_layouts"
import "../tools/gen_disk_layouts"

const
  RepoRoot = currentSourcePath().parentDir().parentDir()
  WorkDir = RepoRoot / "build" / "test-installer-disk-layout-parity"
  InstallerSrc = RepoRoot / "apps" / "reproos-installer" / "src"
  DiskLayoutsCpp = InstallerSrc / "disk_layouts.cpp"
  GeneratedHeader = RepoRoot / GeneratedHeaderPath
  GeneratedJson = RepoRoot / GeneratedJsonPath
  InstallerStateCpp = InstallerSrc / "installer_state.cpp"
  DriverPath = RepoRoot / "recipes" / "reproos-image" / "scripts" /
    "build-reproos-image.sh"
  FixturePath = RepoRoot / "tests" / "fixtures" / "auto-config-minimal.toml"
  GoldenBundleDisko = RepoRoot / "tests" / "golden" /
    "installer-artifacts" / "disko.json"
  GoldenBundleHardware = RepoRoot / "tests" / "golden" /
    "installer-artifacts" / "hardware.nim"

  # The plan renders the applied document with these; see
  # recipes/reproos-image/package.nim.
  PlanId = "reproos-image"
  PlanDevice = "/dev/nbd0"
  # The installer renders /etc/repro/disko.json with these; the device
  # is [install] target_device from the same config.
  InstalledId = "INSTALL"

  UnknownPresetName = "uefi-reproos-control-not-a-preset"
    ## A name no preset carries. Also used as a control: it must never
    ## appear in a generated file or in the driver.

var failures = 0

proc fail(message: string) =
  stderr.writeLine("[fail] " & message)
  failures.inc

proc pass(message: string) =
  echo "[pass] " & message

proc skip(message: string) =
  echo "[skip] " & message

proc paramsFor(id, device: string; esp: int): DiskLayoutParams =
  DiskLayoutParams(id: id, device: device, espSizeMib: esp,
                   diskSizeGb: DefaultDiskSizeGb)

# ---------------------------------------------------------------------------
# t_registry_addition_fails_a_stale_installer  (NEGATIVE)
# ---------------------------------------------------------------------------

block generatedFilesAreCurrent:
  var stale: seq[string] = @[]
  for (path, expected) in [(GeneratedHeader, renderHeader()),
                           (GeneratedJson, renderJson())]:
    if not fileExists(path):
      stale.add(path.relativePath(RepoRoot) & " (missing)")
      continue
    let onDisk = readFile(path)
    if onDisk != expected:
      stale.add(path.relativePath(RepoRoot) & " (" & $onDisk.len &
        " bytes on disk, " & $expected.len & " re-derived)")
  if stale.len > 0:
    fail("t_registry_addition_fails_a_stale_installer: the generated " &
         "installer disk-layout tables no longer match " &
         "repro/disk_layouts.nim: " & stale.join(", ") & "\n" &
         "  regenerate with: nim r tools/gen_disk_layouts.nim")
    break generatedFilesAreCurrent

  # Falsifiability of the comparison itself: the re-derived text has to
  # actually depend on the registry, or "equal" above would be vacuous.
  var missingNames: seq[string] = @[]
  let header = readFile(GeneratedHeader)
  let jsonText = readFile(GeneratedJson)
  for name in diskLayoutPresetNames():
    if name notin header: missingNames.add(name & " (header)")
    if name notin jsonText: missingNames.add(name & " (json)")
  if missingNames.len > 0:
    fail("t_registry_addition_fails_a_stale_installer: the generated " &
         "tables do not carry every registered preset: " &
         missingNames.join(", "))
    break generatedFilesAreCurrent
  if UnknownPresetName in header or UnknownPresetName in jsonText:
    fail("t_registry_addition_fails_a_stale_installer: the generated " &
         "tables contain a control name no preset declares")
    break generatedFilesAreCurrent
  pass("t_registry_addition_fails_a_stale_installer: both generated " &
       "tables re-derive byte-identically from the " &
       $DiskLayoutPresets.len & "-preset registry")

# ---------------------------------------------------------------------------
# Compile the shipped C++ registry consumer.
# ---------------------------------------------------------------------------

const HarnessSource = """
// Compiled by tests/test_installer_disk_layout_parity.nim against the
// SHIPPED apps/reproos-installer/src/disk_layouts.cpp. It exists only
// to expose that translation unit's four entry points to the gate; it
// contains no rendering and no validation of its own.
#include "disk_layouts.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static int emit(const char *path, const std::string &text) {
    FILE *out = fopen(path, "wb");
    if (out == nullptr) return 1;
    fwrite(text.data(), 1, text.size(), out);
    fclose(out);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const std::string mode = argv[1];
    if (mode == "document" && argc == 7) {
        return emit(argv[6], reproos::renderDiskoDocument(
            argv[2], argv[3], argv[4], atoi(argv[5])));
    }
    if (mode == "hardware" && argc == 7) {
        return emit(argv[6], reproos::renderHardwareNim(
            argv[2], argv[3], argv[4], atoi(argv[5])));
    }
    if (mode == "validate" && argc == 6) {
        return emit(argv[5], reproos::validateDiskLayout(
            argv[2], atoi(argv[3]), atoi(argv[4])));
    }
    if (mode == "names" && argc == 3) {
        std::string all;
        for (const reproos::DiskLayoutInfo &p : reproos::diskLayoutPresets()) {
            all += p.name;
            all += p.buildable ? "\tbuildable\n" : "\tdeclared\n";
        }
        return emit(argv[2], all);
    }
    return 2;
}
"""

var harnessBin = ""

proc resolveCxx(): string =
  ## The gate needs *a* C++17 compiler, not a specific one: all it does
  ## with it is compile the installer's shipped ``disk_layouts.cpp`` and
  ## diff what that emits against the registry's rendering.
  ##
  ## ``c++`` first, because both the gcc wrapper and the clang wrapper
  ## provide it, and because a registered build action's PATH carries
  ## only the tool identities the action declares -- here ``clang``, the
  ## identity this workspace can provision without bootstrapping a whole
  ## GCC from source. ``clang++`` / ``g++`` follow so a bare development
  ## shell that ships only one of them still runs the gate.
  for candidate in ["c++", "clang++", "g++"]:
    if findExe(candidate).len > 0:
      return candidate
  ""

let cxxExe = resolveCxx()

block buildTheCxxSide:
  if cxxExe.len == 0:
    fail("t_disko_document_has_one_renderer: a C++17 compiler (c++, " &
         "clang++ or g++) is required to compile the installer's " &
         "shipped disk-layout registry consumer.\n" &
         "  Under `repro build` this means the action does not declare " &
         "the `clang` tool identity in repro/workflows.nim.")
    break buildTheCxxSide
  if not fileExists(DiskLayoutsCpp):
    fail("t_disko_document_has_one_renderer: missing " & DiskLayoutsCpp)
    break buildTheCxxSide
  createDir(WorkDir)
  let harnessPath = WorkDir / "harness.cpp"
  writeFile(harnessPath, HarnessSource)
  let bin = WorkDir / "disk-layout-harness"
  let (output, code) = execCmdEx(
    # -O1 rather than -O0: the hardened compiler wrappers this project is
    # built with make _FORTIFY_SOURCE an error at -O0.
    quoteShell(cxxExe) & " -std=c++17 -O1 -Wall -Wextra -I" &
    quoteShell(InstallerSrc) &
    " -o " & quoteShell(bin) & " " & quoteShell(DiskLayoutsCpp) & " " &
    quoteShell(harnessPath))
  if code != 0:
    fail("t_disko_document_has_one_renderer: the shipped " &
         "disk_layouts.cpp does not compile:\n" & output)
    break buildTheCxxSide
  harnessBin = bin

proc cxx(args: seq[string]): string =
  ## Run the compiled shipped C++ and return exactly the bytes it wrote.
  let outPath = WorkDir / "cxx-out"
  removeFile(outPath)
  let quoted = args.map(quoteShell).join(" ")
  let (output, code) = execCmdEx(
    quoteShell(harnessBin) & " " & quoted & " " & quoteShell(outPath))
  if code != 0:
    raise newException(ValueError,
      "the C++ harness exited " & $code & " for [" & args.join(" ") &
      "]: " & output)
  readFile(outPath)

# ---------------------------------------------------------------------------
# t_disko_document_has_one_renderer
# ---------------------------------------------------------------------------

const RenderMatrix = [
  ("INSTALL", "/dev/vda", 512),
  ("reproos-image", "/dev/nbd0", 512),
  ("reproos-image", "/dev/nbd0", 256),
  ("machine-7", "/dev/sda", 1024),
  # A control that exercises the two escapers against each other. No
  # operator types this; the point is that if the C++ escaper ever
  # diverges from repro/disk_layouts.nim's, the divergence shows up
  # here rather than in an image.
  ("id-with-\"quote\"-and-\\backslash", "/dev/\"odd\\name", 128),
]

block bothSidesRenderTheSameBytes:
  if harnessBin.len == 0:
    break bothSidesRenderTheSameBytes
  var compared = 0
  for preset in DiskLayoutPresets:
    for (id, device, esp) in RenderMatrix:
      let p = paramsFor(id, device, esp)
      let nimDoc = renderDiskoJson(preset.name, p)
      let cxxDoc = cxx(@["document", preset.name, id, device, $esp])
      if nimDoc != cxxDoc:
        fail("t_disko_document_has_one_renderer: " & preset.name &
             " id=" & id & " device=" & device & " esp=" & $esp &
             ": the installer's disko document differs from the " &
             "registry's\n--- registry (" & $nimDoc.len & " bytes) ---\n" &
             nimDoc & "--- installer (" & $cxxDoc.len & " bytes) ---\n" &
             cxxDoc)
        break bothSidesRenderTheSameBytes
      let nimHw = renderHardwareNim(preset.name, p)
      let cxxHw = cxx(@["hardware", preset.name, id, device, $esp])
      if nimHw != cxxHw:
        fail("t_disko_document_has_one_renderer: " & preset.name &
             " id=" & id & " device=" & device & " esp=" & $esp &
             ": the installer's hardware.nim differs from the " &
             "registry's\n--- registry ---\n" & nimHw &
             "--- installer ---\n" & cxxHw)
        break bothSidesRenderTheSameBytes
      compared.inc

  # The control: an unregistered preset must render nothing at all, so
  # that "identical bytes" above cannot be satisfied by both sides
  # returning empty.
  if cxx(@["document", UnknownPresetName, "INSTALL", "/dev/vda", "512"]).len > 0:
    fail("t_disko_document_has_one_renderer: the installer rendered a " &
         "document for a name no preset declares")
    break bothSidesRenderTheSameBytes
  if renderDiskoJson(DefaultDiskLayoutName,
                     paramsFor("INSTALL", "/dev/vda", 512)).len == 0:
    fail("t_disko_document_has_one_renderer: the registry rendered an " &
         "empty document; the comparison above was vacuous")
    break bothSidesRenderTheSameBytes

  # And the registry's own list is what the installer enumerates.
  var expectedNames = ""
  for preset in DiskLayoutPresets:
    expectedNames.add preset.name & "\t" &
      (if preset.status == dlsBuildable: "buildable" else: "declared") & "\n"
  let cxxNames = cxx(@["names"])
  if cxxNames != expectedNames:
    fail("t_disko_document_has_one_renderer: the installer enumerates a " &
         "different preset set\n--- registry ---\n" & expectedNames &
         "--- installer ---\n" & cxxNames)
    break bothSidesRenderTheSameBytes

  pass("t_disko_document_has_one_renderer: " & $compared & " (preset, " &
       "id, device, esp) combination(s) render byte-identical disko " &
       "documents and hardware.nim on both sides")

block theQtWrapperUsesThem:
  ## The parity above is about disk_layouts.cpp. It would be worth
  ## nothing if installer_state.cpp had kept a private emitter beside
  ## it, which is the exact shape of the defect being removed -- so read
  ## the shipped file.
  if not fileExists(InstallerStateCpp):
    fail("t_disko_document_has_one_renderer: missing " & InstallerStateCpp)
    break theQtWrapperUsesThem
  let src = readFile(InstallerStateCpp)
  var missing: seq[string] = @[]
  for needle in ["#include \"disk_layouts.h\"", "reproos::renderDiskoDocument(",
                 "reproos::renderHardwareNim(", "reproos::validateDiskLayout("]:
    if needle notin src: missing.add(needle)
  if missing.len > 0:
    fail("t_disko_document_has_one_renderer: installer_state.cpp does " &
         "not go through the registry; missing: " & missing.join(", "))
    break theQtWrapperUsesThem
  var leftovers: seq[string] = @[]
  for needle in ["\"\\\"kernelModules\\\":[]\"", "\\\"cpuMicrocode\\\"",
                 "\\\"subvols\\\":[]", "only disk.layout.type=",
                 "m_diskoPreset"]:
    if needle in src: leftovers.add(needle)
  if leftovers.len > 0:
    fail("t_disko_document_has_one_renderer: installer_state.cpp still " &
         "carries its own renderer or its own layout literal: " &
         leftovers.join(", "))
    break theQtWrapperUsesThem
  # The stale claim, named explicitly so it cannot creep back.
  if "must match libs/repro_profile" in src or
     "emitSystemHardwareJson for the same" in src:
    fail("t_disko_document_has_one_renderer: installer_state.cpp still " &
         "claims its own output matches emitSystemHardwareJson")
    break theQtWrapperUsesThem
  pass("t_disko_document_has_one_renderer: the Qt wrapper selects from " &
       "the registry and renders nothing of its own")

# ---------------------------------------------------------------------------
# t_installer_accepts_every_registered_layout
# ---------------------------------------------------------------------------

block installerAcceptsEveryBuildablePreset:
  if harnessBin.len == 0:
    break installerAcceptsEveryBuildablePreset
  var accepted = 0
  var buildable = 0
  for preset in DiskLayoutPresets:
    if preset.status != dlsBuildable: continue
    buildable.inc
    let esp = preset.defaultEspSizeMib
    let sizeGb = preset.minDiskSizeGb
    let message = cxx(@["validate", preset.name, $esp, $sizeGb])
    if message.len > 0:
      fail("t_installer_accepts_every_registered_layout: " & preset.name &
           " is registered buildable but the installer refused it: " &
           message)
      break installerAcceptsEveryBuildablePreset
    accepted.inc
  if buildable == 0:
    fail("t_installer_accepts_every_registered_layout: no preset is " &
         "registered buildable; the acceptance claim is vacuous")
    break installerAcceptsEveryBuildablePreset
  pass("t_installer_accepts_every_registered_layout: the installer's " &
       "validator accepts all " & $accepted & " buildable preset(s)")

# ---------------------------------------------------------------------------
# t_installer_refuses_unregistered_and_declared_layouts  (NEGATIVE)
# ---------------------------------------------------------------------------

block installerRefusalsAreTheRegistrys:
  if harnessBin.len == 0:
    break installerRefusalsAreTheRegistrys

  # Every refusal the two validators can produce, compared as text. If
  # the installer ever answers "unsupported layout" where the registry
  # answers with a reason, this is where it fails.
  var cases: seq[(string, int, int)] = @[
    (UnknownPresetName, DefaultEspSizeMib, DefaultDiskSizeGb),
    ("", DefaultEspSizeMib, DefaultDiskSizeGb),
    (DefaultDiskLayoutName, MinEspSizeMib - 1, DefaultDiskSizeGb),
    (DefaultDiskLayoutName, 0, DefaultDiskSizeGb),
    (DefaultDiskLayoutName, DefaultEspSizeMib, -1),
  ]
  for preset in DiskLayoutPresets:
    cases.add((preset.name, preset.defaultEspSizeMib,
               preset.minDiskSizeGb - 1))
    cases.add((preset.name, preset.defaultEspSizeMib, preset.minDiskSizeGb))
  var compared = 0
  for (name, esp, sizeGb) in cases:
    let expected = validateDiskLayoutRequest(DiskLayoutRequest(
      name: name,
      params: DiskLayoutParams(id: InstalledId, device: "/dev/vda",
                               espSizeMib: esp, diskSizeGb: sizeGb)))
    let actual = cxx(@["validate", name, $esp, $sizeGb])
    if expected != actual:
      fail("t_installer_refuses_unregistered_and_declared_layouts: for " &
           "type=" & name & " esp=" & $esp & " size_gb=" & $sizeGb &
           " the registry says\n---\n" & expected &
           "\n---\nand the installer says\n---\n" & actual & "\n---")
      break installerRefusalsAreTheRegistrys
    compared.inc

  # The unregistered name is refused, and the refusal lists every legal
  # value -- a refusal that named none would still be "identical to the
  # registry's" if the registry had regressed too.
  let unknownMessage = cxx(
    @["validate", UnknownPresetName, $DefaultEspSizeMib, $DefaultDiskSizeGb])
  if unknownMessage.len == 0:
    fail("t_installer_refuses_unregistered_and_declared_layouts: the " &
         "installer accepted " & UnknownPresetName)
    break installerRefusalsAreTheRegistrys
  if UnknownPresetName notin unknownMessage:
    fail("t_installer_refuses_unregistered_and_declared_layouts: the " &
         "refusal does not quote the offending name")
    break installerRefusalsAreTheRegistrys
  var unlisted: seq[string] = @[]
  for name in diskLayoutPresetNames():
    if name notin unknownMessage: unlisted.add(name)
  if unlisted.len > 0:
    fail("t_installer_refuses_unregistered_and_declared_layouts: the " &
         "refusal does not name the legal value(s): " & unlisted.join(", "))
    break installerRefusalsAreTheRegistrys

  # A declared-but-not-yet-buildable preset is refused with the
  # registry's own recorded reason, not with a generic message.
  var declaredChecked = 0
  for preset in DiskLayoutPresets:
    if preset.status != dlsDeclared: continue
    let message = cxx(@["validate", preset.name, $preset.defaultEspSizeMib,
                        $preset.minDiskSizeGb])
    if message.len == 0:
      fail("t_installer_refuses_unregistered_and_declared_layouts: the " &
           "installer accepts " & preset.name & ", which the registry " &
           "records as declared but not yet buildable")
      break installerRefusalsAreTheRegistrys
    if preset.unbuildableReason notin message:
      fail("t_installer_refuses_unregistered_and_declared_layouts: " &
           preset.name & " is refused without the registry's recorded " &
           "reason:\n" & message)
      break installerRefusalsAreTheRegistrys
    if "not yet buildable" notin message:
      fail("t_installer_refuses_unregistered_and_declared_layouts: " &
           preset.name & " is refused, but not as a declared-only " &
           "layout: " & message)
      break installerRefusalsAreTheRegistrys
    declaredChecked.inc
  if declaredChecked == 0:
    skip("t_installer_refuses_unregistered_and_declared_layouts: no " &
         "preset is currently registered declared-but-not-buildable, so " &
         "the reason-quoting half of this gate had nothing to check")
  # The third validator. tools/reproos-machine-config.py is the
  # operator-facing `python3 tools/reproos-machine-config.py validate`
  # surface; it used to carry its own require_exact(..., "uefi-ext4")
  # and would have kept refusing a preset the registry accepted. It now
  # reads the same generated table, so its wording is compared here too
  # rather than trusted to stay in step.
  block:
    if findExe("python3").len == 0:
      fail("t_installer_refuses_unregistered_and_declared_layouts: " &
           "python3 is required to compare tools/" &
           "reproos-machine-config.py's refusals")
      break installerRefusalsAreTheRegistrys
    createDir(WorkDir)
    var script = """
import importlib.util, sys, json
spec = importlib.util.spec_from_file_location(
    "cfg", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
out = []
for line in open(sys.argv[2]):
    name, esp, gb = line.rstrip("\n").split("\t")
    try:
        mod.validate_disk_layout(name, int(esp), int(gb))
        out.append("")
    except mod.ConfigError as exc:
        out.append(str(exc))
open(sys.argv[3], "w").write("\x00".join(out))
"""
    let scriptPath = WorkDir / "python-validator-parity.py"
    writeFile(scriptPath, script)
    var casesText = ""
    var expectedMessages: seq[string] = @[]
    for (name, esp, sizeGb) in cases:
      casesText.add name & "\t" & $esp & "\t" & $sizeGb & "\n"
      expectedMessages.add validateDiskLayoutRequest(DiskLayoutRequest(
        name: name,
        params: DiskLayoutParams(id: InstalledId, device: "/dev/vda",
                                 espSizeMib: esp, diskSizeGb: sizeGb)))
    let casesPath = WorkDir / "python-validator-cases.tsv"
    writeFile(casesPath, casesText)
    let resultPath = WorkDir / "python-validator-result"
    let (pyOut, pyCode) = execCmdEx(
      "python3 " & quoteShell(scriptPath) & " " &
      quoteShell(RepoRoot / "tools" / "reproos-machine-config.py") & " " &
      quoteShell(casesPath) & " " & quoteShell(resultPath))
    if pyCode != 0:
      fail("t_installer_refuses_unregistered_and_declared_layouts: " &
           "tools/reproos-machine-config.py could not be exercised: " &
           pyOut)
      break installerRefusalsAreTheRegistrys
    let actualMessages = readFile(resultPath).split('\x00')
    if actualMessages.len != expectedMessages.len:
      fail("t_installer_refuses_unregistered_and_declared_layouts: the " &
           "python validator answered " & $actualMessages.len &
           " case(s), not " & $expectedMessages.len)
      break installerRefusalsAreTheRegistrys
    for i in 0 ..< expectedMessages.len:
      if actualMessages[i] != expectedMessages[i]:
        let (name, esp, sizeGb) = cases[i]
        fail("t_installer_refuses_unregistered_and_declared_layouts: " &
             "for type=" & name & " esp=" & $esp & " size_gb=" &
             $sizeGb & " the registry says\n---\n" &
             expectedMessages[i] & "\n---\nand tools/" &
             "reproos-machine-config.py says\n---\n" &
             actualMessages[i] & "\n---")
        break installerRefusalsAreTheRegistrys

  pass("t_installer_refuses_unregistered_and_declared_layouts: " &
       $compared & " refusal(s) are word-for-word the registry's in " &
       "the installer AND in tools/reproos-machine-config.py, " &
       "including " & $declaredChecked & " declared-only preset(s)")

# ---------------------------------------------------------------------------
# t_installed_image_disko_matches_applied_disko
# ---------------------------------------------------------------------------

proc installTargetDevice(configText: string): string =
  let raw = tomlLookup(configText, "install", "target_device")
  if raw.len > 0: raw else: "/dev/vda"

proc normaliseToInstalled(applied, planId, installedId, planDevice,
                          installedDevice: string): string =
  ## The two substitutions recipes/reproos-image/scripts/
  ## build-reproos-image.sh Phase 3b applies, in the same order.
  applied.replace("\"" & planId & "\"", "\"" & installedId & "\"")
         .replace(planDevice, installedDevice)

block appliedAndInstalledDocumentsAgree:
  if harnessBin.len == 0:
    break appliedAndInstalledDocumentsAgree
  if not fileExists(FixturePath):
    fail("t_installed_image_disko_matches_applied_disko: fixture " &
         "missing: " & FixturePath)
    break appliedAndInstalledDocumentsAgree
  let configText = readFile(FixturePath)
  let request = parseDiskLayoutRequest(configText, PlanId, PlanDevice)
  let refusal = validateDiskLayoutRequest(request)
  if refusal.len > 0:
    fail("t_installed_image_disko_matches_applied_disko: the shipped " &
         "fixture does not plan: " & refusal)
    break appliedAndInstalledDocumentsAgree
  let device = installTargetDevice(configText)

  # The applied side: exactly what the plan hands the driver.
  let applied = renderDiskoJson(request.name, request.params)
  # The installed side: exactly what the installer's shipped C++ emits.
  let installed = cxx(@["document", request.name, InstalledId, device,
                        $request.params.espSizeMib])
  let normalised = normaliseToInstalled(applied, PlanId, InstalledId,
                                        PlanDevice, device)
  if normalised != installed:
    fail("t_installed_image_disko_matches_applied_disko: the document " &
         "the installer writes to /etc/repro/disko.json is not the one " &
         "the image build applies\n--- applied, normalised ---\n" &
         normalised & "--- installer ---\n" & installed)
    break appliedAndInstalledDocumentsAgree
  # A control: the normalisation must really have changed something, or
  # this would be comparing a document to itself.
  if normalised == applied:
    fail("t_installed_image_disko_matches_applied_disko: normalising " &
         "the applied document changed nothing; the id/device " &
         "substitution is not exercised")
    break appliedAndInstalledDocumentsAgree
  pass("t_installed_image_disko_matches_applied_disko: the applied " &
       "document and /etc/repro/disko.json are the same " &
       $installed.len & " bytes once the spec id and device node are " &
       "normalised")

block theDriverEnforcesIt:
  ## An equality nobody checks at build time is a comment. Read the
  ## shipped driver.
  if not fileExists(DriverPath):
    fail("t_installed_image_disko_matches_applied_disko: driver " &
         "missing: " & DriverPath)
    break theDriverEnforcesIt
  let driver = readFile(DriverPath)
  var missing: seq[string] = @[]
  for needle in ["disko-as-installed.json", "$CONFIG_BUNDLE_DIR/disko.json",
                 "INSTALL_TARGET_DEVICE", "exit 66"]:
    if needle notin driver: missing.add(needle)
  if missing.len > 0:
    fail("t_installed_image_disko_matches_applied_disko: the image " &
         "driver does not compare the two disko documents; missing: " &
         missing.join(", "))
    break theDriverEnforcesIt
  if UnknownPresetName in driver:
    fail("t_installed_image_disko_matches_applied_disko: the driver " &
         "reader matched a control string that is not in the file")
    break theDriverEnforcesIt
  pass("t_installed_image_disko_matches_applied_disko: the image driver " &
       "refuses (exit 66) before qemu-img when the two documents differ")

block theRealBinaryWritesThoseBytes:
  ## Everything above compares the shipped C++ *sources*. When a built
  ## installer is present, compare the bytes the binary itself writes --
  ## that is what ends up at /etc/repro/disko.json.
  let configured = getEnv("REPROOS_INSTALLER_BIN")
  let binary =
    if configured.len > 0: configured
    else: RepoRoot / ".repro" / "output" / "install" / "usr" / "bin" /
      "reproos-installer"
  if not fileExists(binary):
    skip("t_installed_image_disko_matches_applied_disko: no installer " &
         "binary at " & binary & "; the bytes were compared at the " &
         "source level only. Build it with `repro build installer` or " &
         "set REPROOS_INSTALLER_BIN.")
    break theRealBinaryWritesThoseBytes
  createDir(WorkDir)
  let emitDir = WorkDir / "installer-artifacts"
  removeDir(emitDir)
  # This Qt build routes qCritical() to the journal unless told
  # otherwise; the gate only reads files, but force stderr so a failure
  # is diagnosable from the log.
  putEnv("QT_FORCE_STDERR_LOGGING", "1")
  let (output, code) = execCmdEx(
    quoteShell(binary) & " --config " & quoteShell(FixturePath) &
    " --emit-artifacts " & quoteShell(emitDir))
  if code != 0:
    fail("t_installed_image_disko_matches_applied_disko: the installer " &
         "binary refused the shipped fixture (exit " & $code & "): " &
         output)
    break theRealBinaryWritesThoseBytes
  let configText = readFile(FixturePath)
  let request = parseDiskLayoutRequest(configText, PlanId, PlanDevice)
  let device = installTargetDevice(configText)
  let expectedDoc = cxx(@["document", request.name, InstalledId, device,
                          $request.params.espSizeMib])
  let writtenDoc = readFile(emitDir / "disko.json")
  if writtenDoc != expectedDoc:
    fail("t_installed_image_disko_matches_applied_disko: the installer " &
         "binary wrote a disko.json the registry does not produce\n" &
         "--- registry ---\n" & expectedDoc & "--- binary ---\n" &
         writtenDoc)
    break theRealBinaryWritesThoseBytes
  let expectedHw = renderHardwareNim(request.name,
    paramsFor(InstalledId, device, request.params.espSizeMib))
  let writtenHw = readFile(emitDir / "hardware.nim")
  if writtenHw != expectedHw:
    fail("t_installed_image_disko_matches_applied_disko: the installer " &
         "binary wrote a hardware.nim the registry does not produce\n" &
         "--- registry ---\n" & expectedHw & "--- binary ---\n" & writtenHw)
    break theRealBinaryWritesThoseBytes
  # And the checked-in golden bundle is those same bytes, so the
  # artifact contract test is comparing against the registry too.
  if fileExists(GoldenBundleDisko) and readFile(GoldenBundleDisko) != writtenDoc:
    fail("t_installed_image_disko_matches_applied_disko: tests/golden/" &
         "installer-artifacts/disko.json is not what the installer emits")
    break theRealBinaryWritesThoseBytes
  if fileExists(GoldenBundleHardware) and
     readFile(GoldenBundleHardware) != writtenHw:
    fail("t_installed_image_disko_matches_applied_disko: tests/golden/" &
         "installer-artifacts/hardware.nim is not what the installer emits")
    break theRealBinaryWritesThoseBytes
  pass("t_installed_image_disko_matches_applied_disko: the built " &
       "installer writes exactly the registry's documents (" &
       $writtenDoc.len & " bytes of disko.json)")

# ---------------------------------------------------------------------------
# t_hardware_nim_parses_to_the_registry_layout
# ---------------------------------------------------------------------------

block hardwareNimRoundTrips:
  if findExe("nim").len == 0:
    fail("t_hardware_nim_parses_to_the_registry_layout: nim is required")
    break hardwareNimRoundTrips
  createDir(WorkDir)
  var checked = 0
  for preset in DiskLayoutPresets:
    let params = paramsFor(InstalledId, "/dev/vda", 512)
    let source = renderHardwareNim(preset.name, params)
    # The `hardware` macro expands into a main() that prints
    # emitSystemHardwareJson and quits, so compiling and running the
    # rendered file IS the parse.
    let moduleName = "hw" & preset.name.replace("-", "")
    let modulePath = WorkDir / (moduleName & ".nim")
    writeFile(modulePath, source)
    let binPath = WorkDir / moduleName
    # REPROOS_NIM_CC_ARGS is set by tests/nim-gate.sh and pins the C
    # compiler to one the ACTION DECLARED. Without it this nested `nim c`
    # inherits `$CC` from whoever launched `repro build` and shells out to
    # a compiler the action's hermetic PATH does not carry.
    let (compileOut, compileCode) = execCmdEx(
      "nim c --hints:off --warnings:off " & getEnv("REPROOS_NIM_CC_ARGS") &
      " -o:" & quoteShell(binPath) & " " &
      quoteShell(modulePath), workingDir = RepoRoot)
    if compileCode != 0:
      fail("t_hardware_nim_parses_to_the_registry_layout: the " &
           "hardware.nim rendered for " & preset.name & " is not " &
           "accepted by repro_profile's `hardware` macro:\n" & compileOut &
           "\n--- rendered ---\n" & source)
      break hardwareNimRoundTrips
    let (runOut, runCode) = execCmdEx(quoteShell(binPath))
    if runCode != 0:
      fail("t_hardware_nim_parses_to_the_registry_layout: running the " &
           "rendered hardware.nim for " & preset.name & " exited " &
           $runCode & ": " & runOut)
      break hardwareNimRoundTrips
    let expected = emitSystemHardwareJson(
      diskLayoutHardwareSpec(preset.name, params))
    if runOut.strip() != expected.strip():
      fail("t_hardware_nim_parses_to_the_registry_layout: " & preset.name &
           ": the parsed hardware.nim is not the registry's layout\n" &
           "--- expected ---\n" & expected & "\n--- parsed ---\n" & runOut)
      break hardwareNimRoundTrips
    checked.inc
  if checked != DiskLayoutPresets.len:
    break hardwareNimRoundTrips
  pass("t_hardware_nim_parses_to_the_registry_layout: all " & $checked &
       " rendered hardware.nim file(s) parse through repro_profile's " &
       "own macro into the registry's SystemHardwareSpec")

if failures > 0:
  stderr.writeLine("test_installer_disk_layout_parity: " & $failures &
                   " check(s) failed")
  quit(1)
echo "installer disk layout parity: PASS"
