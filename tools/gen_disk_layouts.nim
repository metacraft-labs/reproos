## Generate the installer's copy of the disk-layout registry.
##
## ## Why this exists
##
## ``repro/disk_layouts.nim`` is the single declaration of which disk
## layouts ReproOS images ship and what documents they render to. The
## installer is a Qt/C++ program that runs on the live ISO without a Nim
## toolchain, and the operator-facing ``tools/reproos-machine-config.py``
## validator is Python, so neither can call the registry. Before this
## generator they each carried a hand-written copy: the installer
## rendered its own disko JSON (empty labels, ``noatime``, ``/dev/vda``)
## and hard-rejected every ``[disk.layout].type`` but ``uefi-ext4``, and
## the Python validator hard-required the same literal.
##
## So the registry is *compiled* into those two languages instead of
## re-implemented in them:
##
##   - ``apps/reproos-installer/src/disk_layouts_generated.h`` — the
##     preset table plus, per preset, the rendered ``disko.json`` and
##     ``hardware.nim`` with the three per-install parameters left as
##     placeholders. The C++ side selects and substitutes; it renders
##     nothing.
##   - ``tools/disk_layouts_generated.json`` — the same table as data,
##     for the Python validator.
##
## Both files are checked in, because the installer must build from
## ``apps/reproos-installer`` alone with no Nim available. That is what
## makes them able to go stale, and it is exactly what
## ``t_registry_addition_fails_a_stale_installer`` gates: this generator
## has a ``--check`` mode that re-derives both files and fails if what is
## on disk differs by a single byte.
##
## Usage:
##   nim r tools/gen_disk_layouts.nim            # write both files
##   nim r tools/gen_disk_layouts.nim --check    # fail if stale

import std/[os, strutils]

import "../repro/disk_layouts"

const
  IdPlaceholder* = "@REPROOS_ID@"
  DevicePlaceholder* = "@REPROOS_DEVICE@"
  EspMibPlaceholder* = "@REPROOS_ESP_MIB@"

  EspSentinel = 424242
    ## Rendered into the templates as ``"424242M"`` and then rewritten to
    ## ``"@REPROOS_ESP_MIB@M"``. A number no preset and no config would
    ## ever carry, and the substitution below refuses to proceed unless
    ## it occurs exactly once — a preset that grew a second ESP-sized
    ## partition would stop the generator rather than silently emit a
    ## template that only parameterises one of them.

  RawDelimiter = "REPROOS_LAYOUT"
    ## C++ raw-string-literal delimiter. Asserted absent from every
    ## template before use.

  GeneratedHeaderPath* = "apps/reproos-installer/src/disk_layouts_generated.h"
  GeneratedJsonPath* = "tools/disk_layouts_generated.json"

proc placeholderParams(): DiskLayoutParams =
  DiskLayoutParams(
    id: IdPlaceholder,
    device: DevicePlaceholder,
    espSizeMib: EspSentinel,
    diskSizeGb: DefaultDiskSizeGb)

proc parameteriseEsp(rendered, what, preset: string): string =
  let sentinel = "\"" & $EspSentinel & "M\""
  let occurrences = rendered.count(sentinel)
  if occurrences != 1:
    raise newException(ValueError,
      "gen_disk_layouts: preset " & preset & "'s " & what & " mentions " &
      "the ESP size " & $occurrences & " time(s), not once; the " &
      "single-placeholder template cannot represent it. Teach this " &
      "generator the new shape rather than shipping a template that " &
      "parameterises only part of it.")
  rendered.replace(sentinel, "\"" & EspMibPlaceholder & "M\"")

proc templatesFor(name: string): tuple[document, hardware: string] =
  let p = placeholderParams()
  result.document = parameteriseEsp(
    renderDiskoJson(name, p), "disko document", name)
  result.hardware = parameteriseEsp(
    renderHardwareNim(name, p), "hardware.nim", name)

proc cxxRaw(text, preset, what: string): string =
  ## A C++ raw string literal. Raw is the only readable option here --
  ## the templates are multi-line JSON and Nim source -- so the escape
  ## hatch has to be proved unnecessary rather than assumed.
  let closing = ")" & RawDelimiter & "\""
  if closing in text:
    raise newException(ValueError,
      "gen_disk_layouts: preset " & preset & "'s " & what & " contains " &
      "the raw-string terminator " & closing)
  "R\"" & RawDelimiter & "(" & text & ")" & RawDelimiter & "\""

proc jsonQuoted(s: string): string =
  result = "\""
  for c in s:
    case c
    of '"': result.add "\\\""
    of '\\': result.add "\\\\"
    of '\n': result.add "\\n"
    of '\t': result.add "\\t"
    of '\r': result.add "\\r"
    else: result.add c
  result.add "\""

proc renderHeader*(): string =
  var s = ""
  s.add "// GENERATED FILE -- DO NOT EDIT.\n"
  s.add "//\n"
  s.add "// Produced by tools/gen_disk_layouts.nim from\n"
  s.add "// repro/disk_layouts.nim, which is the single declaration of\n"
  s.add "// which disk layouts ReproOS ships and what documents they\n"
  s.add "// render to. Regenerate with:\n"
  s.add "//\n"
  s.add "//     nim r tools/gen_disk_layouts.nim\n"
  s.add "//\n"
  s.add "// Editing this file by hand re-creates the divergence it was\n"
  s.add "// introduced to remove: the installer used to render its own\n"
  s.add "// disko JSON, and that copy disagreed with the one the image\n"
  s.add "// build applied. tests/test_installer_disk_layout_parity.nim\n"
  s.add "// re-derives this file and fails if it differs by a byte.\n"
  s.add "\n"
  s.add "#pragma once\n"
  s.add "\n"
  s.add "namespace reproos {\n"
  s.add "namespace generated {\n"
  s.add "\n"
  s.add "// One registered layout preset. `documentTemplate` and\n"
  s.add "// `hardwareTemplate` are the rendered documents with the three\n"
  s.add "// per-install parameters left as placeholders; the C++ side\n"
  s.add "// substitutes, it does not render.\n"
  s.add "struct DiskLayoutPreset {\n"
  s.add "    const char *name;\n"
  s.add "    const char *summary;\n"
  s.add "    bool buildable;\n"
  s.add "    const char *unbuildableReason;\n"
  s.add "    int minDiskSizeGb;\n"
  s.add "    int defaultEspSizeMib;\n"
  s.add "    const char *documentTemplate;\n"
  s.add "    const char *hardwareTemplate;\n"
  s.add "};\n"
  s.add "\n"
  s.add "inline constexpr const char *IdPlaceholder = " &
    jsonQuoted(IdPlaceholder) & ";\n"
  s.add "inline constexpr const char *DevicePlaceholder = " &
    jsonQuoted(DevicePlaceholder) & ";\n"
  s.add "inline constexpr const char *EspMibPlaceholder = " &
    jsonQuoted(EspMibPlaceholder) & ";\n"
  s.add "\n"
  s.add "inline constexpr const char *DefaultDiskLayoutName = " &
    jsonQuoted(DefaultDiskLayoutName) & ";\n"
  s.add "inline constexpr int DefaultDiskSizeGb = " &
    $DefaultDiskSizeGb & ";\n"
  s.add "inline constexpr int DefaultEspSizeMib = " &
    $DefaultEspSizeMib & ";\n"
  s.add "inline constexpr int MinEspSizeMib = " & $MinEspSizeMib & ";\n"
  s.add "\n"
  s.add "// The listing every \"unknown layout\" refusal prints, rendered\n"
  s.add "// by repro/disk_layouts.nim's legalDiskLayoutListing().\n"
  s.add "inline constexpr const char *LegalDiskLayoutListing =\n"
  s.add "    " & cxxRaw(legalDiskLayoutListing(), "<all>", "listing") & ";\n"
  s.add "\n"
  s.add "inline constexpr DiskLayoutPreset DiskLayoutPresets[] = {\n"
  for preset in DiskLayoutPresets:
    let t = templatesFor(preset.name)
    s.add "    {\n"
    s.add "        /* name */ " & jsonQuoted(preset.name) & ",\n"
    s.add "        /* summary */ " & jsonQuoted(preset.summary) & ",\n"
    s.add "        /* buildable */ " &
      (if preset.status == dlsBuildable: "true" else: "false") & ",\n"
    s.add "        /* unbuildableReason */ " &
      jsonQuoted(preset.unbuildableReason) & ",\n"
    s.add "        /* minDiskSizeGb */ " & $preset.minDiskSizeGb & ",\n"
    s.add "        /* defaultEspSizeMib */ " &
      $preset.defaultEspSizeMib & ",\n"
    s.add "        /* documentTemplate */\n"
    s.add "        " & cxxRaw(t.document, preset.name, "disko document") &
      ",\n"
    s.add "        /* hardwareTemplate */\n"
    s.add "        " & cxxRaw(t.hardware, preset.name, "hardware.nim") &
      ",\n"
    s.add "    },\n"
  s.add "};\n"
  s.add "\n"
  s.add "inline constexpr int DiskLayoutPresetCount =\n"
  s.add "    sizeof(DiskLayoutPresets) / sizeof(DiskLayoutPresets[0]);\n"
  s.add "\n"
  s.add "}  // namespace generated\n"
  s.add "}  // namespace reproos\n"
  s

proc renderJson*(): string =
  ## The same table as data, for tools that are neither Nim nor C++.
  ## Deliberately hand-rendered rather than std/json-marshalled so the
  ## byte layout is stable across Nim versions -- this file is compared
  ## byte for byte by the staleness gate.
  var s = ""
  s.add "{\n"
  s.add "  \"generatedBy\": \"tools/gen_disk_layouts.nim\",\n"
  s.add "  \"source\": \"repro/disk_layouts.nim\",\n"
  s.add "  \"defaultLayout\": " & jsonQuoted(DefaultDiskLayoutName) & ",\n"
  s.add "  \"defaultDiskSizeGb\": " & $DefaultDiskSizeGb & ",\n"
  s.add "  \"defaultEspSizeMib\": " & $DefaultEspSizeMib & ",\n"
  s.add "  \"minEspSizeMib\": " & $MinEspSizeMib & ",\n"
  s.add "  \"presets\": [\n"
  var rows: seq[string] = @[]
  for preset in DiskLayoutPresets:
    var r = ""
    r.add "    {\n"
    r.add "      \"name\": " & jsonQuoted(preset.name) & ",\n"
    r.add "      \"summary\": " & jsonQuoted(preset.summary) & ",\n"
    r.add "      \"buildable\": " &
      (if preset.status == dlsBuildable: "true" else: "false") & ",\n"
    r.add "      \"unbuildableReason\": " &
      jsonQuoted(preset.unbuildableReason) & ",\n"
    r.add "      \"minDiskSizeGb\": " & $preset.minDiskSizeGb & ",\n"
    r.add "      \"defaultEspSizeMib\": " & $preset.defaultEspSizeMib & "\n"
    r.add "    }"
    rows.add r
  s.add rows.join(",\n") & "\n"
  s.add "  ]\n"
  s.add "}\n"
  s

when isMainModule:
  let repoRoot = currentSourcePath().parentDir().parentDir()
  let wanted = [
    (repoRoot / GeneratedHeaderPath, renderHeader()),
    (repoRoot / GeneratedJsonPath, renderJson()),
  ]
  let check = "--check" in commandLineParams()
  var stale = 0
  for (path, text) in wanted:
    if check:
      let onDisk = if fileExists(path): readFile(path) else: ""
      if onDisk != text:
        stderr.writeLine("stale generated file: " & path)
        stderr.writeLine("  regenerate with: nim r tools/gen_disk_layouts.nim")
        stale.inc
    else:
      createDir(path.parentDir())
      writeFile(path, text)
      echo "wrote " & path & " (" & $text.len & " bytes)"
  if stale > 0:
    quit(1)
  if check:
    echo "generated installer disk-layout tables are current"
