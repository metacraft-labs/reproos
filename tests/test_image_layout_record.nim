## The layout a profile NAMES has to be the layout its image was BUILT
## with.
##
## ## The defect this gate exists for
##
## The rule that refuses a non-mock attestation tier on a layout whose
## root filesystem stays writable decided that against a string the
## PROFILE wrote. Both of its sides therefore came from one source, and
## the single failure it could not see was the profile and the image
## disagreeing: a profile saying `uefi-attested` while its image was
## built `uefi-ext4` planned, applied, booted, and ran an agent quoting a
## launch measurement of a root filesystem that is writable for the whole
## boot. Nothing failed, and a verifier accepted the quote — correctly,
## because the quote was honest about a machine that was not the one
## described.
##
## Two links close it, and this gate drives both:
##
##   1. The image build publishes a record naming the layout it resolved,
##      carrying the digest of the partition table that layout renders.
##      It refuses to publish a record whose digest is not the digest of
##      the table the build is actually applying — so the name is tied to
##      an artifact instead of to an intention.
##   2. The profile reads that record. If it also names a layout, the two
##      must agree, and a disagreement is a plan that does not exist.
##
## ## Where the expected values come from
##
## NOWHERE IN THIS FILE is a layout name written down as the answer. The
## layout an image is built with is read by running the image recipe's
## OWN resolution over the recipe's OWN fixture configuration, the way
## `recipes/reproos-image/package.nim` runs it; the layout attestation
## requires is read from Reprobuild's `AttestableImageLayouts`. A gate
## that wrote the expected layout twice would be the rule it is replacing
## with an extra step.
##
## ## Mocking
##
## None. The real presets, the real renderer, the real record schema, the
## real activity validator.

import std/[options, os, strutils, unittest]

import repro_dsl_stdlib/packages/system/attestation

import "../repro/disk_layouts" as diskLayouts
import "../repro/image_layout_record" as layoutRecord

const
  RepoRoot = currentSourcePath.parentDir.parentDir
  RecipeFixture = RepoRoot / "tests" / "fixtures" / "auto-config-minimal.toml"
    ## The configuration `recipes/reproos-image/package.nim` plans against
    ## when `REPRO_AUTO_CONFIG` names nothing else. Reading the same file
    ## the recipe reads is what makes "the layout this image is built
    ## with" a measurement rather than a restatement.

  # The id and device the recipe passes `parseDiskLayoutRequest`. They
  # are the recipe's, not this gate's opinion of them.
  RecipeSpecId = "reproos-image"
  RecipeDevice = "/dev/nbd0"

proc recipeRequest(): diskLayouts.DiskLayoutRequest =
  doAssert fileExists(RecipeFixture), RecipeFixture
  diskLayouts.parseDiskLayoutRequest(
    readFile(RecipeFixture), RecipeSpecId, RecipeDevice)

proc requestFor(name: string): diskLayouts.DiskLayoutRequest =
  ## The recipe's request with a different layout selected — the shape
  ## an image built on another preset would have resolved to.
  result = recipeRequest()
  result.name = name

let builtLayout = recipeRequest().name
  ## What the recipe's own configuration resolves to.
let attestableLayout = AttestableImageLayouts[0]
  ## What a non-mock attestation tier requires, taken from the activity's
  ## own declaration.

suite "the image publishes the layout it was built with":
  test "the two layouts this gate discriminates between really are different":
    # Without this the whole file could be green against a build whose
    # configuration already selects the attestable layout, and every
    # "disagreement" case below would be comparing a value with itself.
    check builtLayout.len > 0
    check attestableLayout.len > 0
    check builtLayout != attestableLayout
    check builtLayout notin AttestableImageLayouts
    # And both are real presets, so the partition tables below are tables
    # this product can actually render.
    check diskLayouts.findDiskLayoutPreset(builtLayout).isSome
    check diskLayouts.findDiskLayoutPreset(attestableLayout).isSome

  test "the record names the RESOLVED layout, read off the request":
    let record = parseImageLayoutRecord(
      layoutRecord.imageLayoutRecordFor(recipeRequest()))
    check record.layout == builtLayout
    # A different request gives a different record, so the renderer is
    # reading the request rather than printing a constant.
    let other = parseImageLayoutRecord(
      layoutRecord.imageLayoutRecordFor(requestFor(attestableLayout)))
    check other.layout == attestableLayout
    check other.partitionTableSha256 != record.partitionTableSha256

  test "every scalar in the record is read off the request, not transcribed":
    # The recipe's own values are what the record carries in practice,
    # and asserting them against the same literals this file would have
    # to write down pins each field against itself: a renderer that
    # printed `"reproos-image"` and `"/dev/nbd0"` would satisfy that and
    # would lose the values on any other build. Measured — it did.
    #
    # So the fields are driven with values NO part of the product uses,
    # and the record has to come back carrying them.
    var request = requestFor(attestableLayout)
    request.params.id = "some-other-image"
    request.params.device = "/dev/sdz9"
    request.params.espSizeMib = 777
    request.params.diskSizeGb = 321
    let record = parseImageLayoutRecord(
      layoutRecord.imageLayoutRecordFor(request))
    check record.layout == request.name
    check record.id == request.params.id
    check record.device == request.params.device
    check record.espSizeMib == request.params.espSizeMib
    check record.diskSizeGb == request.params.diskSizeGb
    # None of those four is what the recipe itself passes, so a record
    # built from the recipe's values could not have satisfied this.
    let recipe = recipeRequest()
    check record.id != RecipeSpecId
    check record.device != RecipeDevice
    check record.espSizeMib != recipe.params.espSizeMib
    check record.diskSizeGb != recipe.params.diskSizeGb

  test "the record's digest is the digest of the table that layout renders":
    let request = recipeRequest()
    let record = parseImageLayoutRecord(
      layoutRecord.imageLayoutRecordFor(request))
    check record.partitionTableSha256 ==
      layoutRecord.partitionTableDigest(
        diskLayouts.renderDiskoJson(request.name, request.params))

  test "THE MATCHING CASE: a record verifies against the table it describes":
    # The discriminator's positive half. A refusal that refused
    # everything would pass the negative cases below and prove nothing.
    for preset in diskLayouts.DiskLayoutPresets:
      checkpoint preset.name
      let request = requestFor(preset.name)
      let applied = diskLayouts.renderDiskoJson(request.name, request.params)
      check layoutRecord.verifyImageLayoutRecord(
        layoutRecord.imageLayoutRecordFor(request), applied).len == 0

  test "THE MUTATION: a build applying another layout's table is REFUSED":
    # Exactly the edit a typo in the recipe would make: the record still
    # says what the configuration resolved to, and the table handed to
    # the partitioner is some other preset's. Run over every ordered
    # pair, so the case covers the direction that matters (declaring the
    # attestable layout while building the writable-root one) and its
    # opposite.
    var pairs = 0
    for declared in diskLayouts.DiskLayoutPresets:
      for built in diskLayouts.DiskLayoutPresets:
        if declared.name == built.name: continue
        inc pairs
        checkpoint declared.name & " declared / " & built.name & " applied"
        let record = layoutRecord.imageLayoutRecordFor(
          requestFor(declared.name))
        let appliedRequest = requestFor(built.name)
        let applied = diskLayouts.renderDiskoJson(
          appliedRequest.name, appliedRequest.params)
        let reason = layoutRecord.verifyImageLayoutRecord(record, applied)
        checkpoint reason
        check reason.len > 0
        # Names BOTH halves: what was claimed and what the table is.
        check declared.name in reason
        check built.name in reason
    # The loop has to have run on something.
    check pairs == diskLayouts.DiskLayoutPresets.len *
      (diskLayouts.DiskLayoutPresets.len - 1)

  test "an unreadable record is refused rather than skipped":
    let applied = diskLayouts.renderDiskoJson(
      recipeRequest().name, recipeRequest().params)
    check layoutRecord.verifyImageLayoutRecord("", applied).len > 0
    check layoutRecord.verifyImageLayoutRecord("{}", applied).len > 0
    # A record of the right shape carrying a schema from a newer tool is
    # not partly understood.
    let good = layoutRecord.imageLayoutRecordFor(recipeRequest())
    let newer = good.replace(ImageLayoutRecordSchema,
      ImageLayoutRecordSchema & "9")
    check newer != good
    check layoutRecord.verifyImageLayoutRecord(newer, applied).len > 0

proc nimCode(text: string): string =
  ## ``text`` with comments removed, quote-aware. Every structural check
  ## below reads this rather than the file: a name that appears only in a
  ## comment is not a binding, and five checks in this product have now
  ## been defeated by exactly that.
  var inString = false
  var escaped = false
  for line in text.splitLines():
    var kept = ""
    inString = false
    escaped = false
    var i = 0
    while i < line.len:
      let c = line[i]
      if inString:
        if escaped: escaped = false
        elif c == '\\': escaped = true
        elif c == '"': inString = false
      elif c == '"':
        inString = true
      elif c == '#':
        break
      kept.add(c)
      inc i
    result.add(kept.strip(leading = false) & "\n")

proc squashed(text: string): string =
  ## One space for every run of whitespace, so a check can name a call
  ## the way it reads rather than the way it happens to be wrapped.
  result = ""
  var lastWasSpace = false
  for c in text:
    if c in {' ', '\t', '\n', '\r'}:
      if not lastWasSpace: result.add(' ')
      lastWasSpace = true
    else:
      result.add(c)
      lastWasSpace = false

suite "the recipe verifies the bytes it is about to apply":
  ## The cross-check in `repro/image_layout_record.nim` is only worth
  ## anything if the recipe hands it the document it is really handing
  ## the partitioner. That is one line in `package.nim`, and a line is
  ## exactly the thing a later edit replaces with a freshly rendered
  ## document that agrees with the record by construction — which is the
  ## defect this whole file is about, re-entered one level down.
  const RecipePath =
    RepoRoot / "recipes" / "reproos-image" / "package.nim"

  let recipeCode = nimCode(readFile(RecipePath))
  let recipeFlat = squashed(recipeCode)

  test "the partition table is rendered exactly ONCE in the recipe":
    # Two renders is how the verifier ends up comparing a document
    # against a different document that happens to say the same thing
    # today.
    check recipeCode.count("renderDiskoJson(") == 1
    check recipeCode.count("let diskoSpec = ") == 1
    check recipeCode.count("let diskoSpecLine = ") == 1

  test "the table and the record are rendered from the SAME request":
    # The one edit the runtime verifier exists to catch, pinned here as
    # well, because the verifier cannot run without a plan and a plan
    # costs an image build: the table has to be rendered from the
    # resolved request, not from a name somebody typed beside it.
    check ("let diskoSpec = diskLayouts.renderDiskoJson( " &
      "layoutRequest.name, layoutRequest.params)") in recipeFlat
    check "let imageLayoutRecord = layoutRecord.imageLayoutRecordFor(" &
      "layoutRequest)" in recipeFlat
    check recipeCode.count("let layoutRequest = ") == 1

  test "the verifier is handed THAT document, and the driver the same one":
    check "verifyImageLayoutRecord( imageLayoutRecord, diskoSpec)" in
      recipeFlat
    check "let diskoSpecLine = diskoSpec.replace(" in recipeFlat
    check "REPROOS_DISKO_SPEC='\" & diskoSpecLine & \"'\"," in recipeFlat
    # And the record the action publishes is the one that was verified.
    check "let imageLayoutRecordLine = imageLayoutRecord.replace(" in
      recipeFlat
    check recipeCode.count("let imageLayoutRecord = ") == 1
    check recipeCode.count("let imageLayoutRecordLine = ") == 1

  test "and a non-empty verdict stops the plan":
    check "let imageLayoutError = layoutRecord.verifyImageLayoutRecord(" in
      recipeFlat
    check recipeCode.count("imageLayoutError = ") == 1
    check "if imageLayoutError.len > 0: raise newException(ValueError," in
      recipeFlat

  test "the scan can fail — each check reddens on a one-line edit":
    # Without this the three cases above are satisfied by a scanner that
    # found nothing. Each mutation is applied to the recipe's TEXT, in
    # memory; the file on disk is never touched.
    let twoRenders = recipeCode.replace(
      "let diskoSpecLine = ",
      "let decoy = diskLayouts.renderDiskoJson(\"x\", p)\n    let diskoSpecLine = ")
    check twoRenders != recipeCode
    check nimCode(twoRenders).count("renderDiskoJson(") == 2
    let reRendered = squashed(recipeCode.replace(
      "verifyImageLayoutRecord(\n      imageLayoutRecord, diskoSpec)",
      "verifyImageLayoutRecord(\n      imageLayoutRecord, renderAgain())"))
    check "verifyImageLayoutRecord( imageLayoutRecord, diskoSpec)" notin
      reRendered
    let unguarded = squashed(recipeCode.replace(
      "if imageLayoutError.len > 0:", "if false:"))
    check "if imageLayoutError.len > 0: raise newException(ValueError," notin
      unguarded

  test "a comment is not a binding":
    # The scan reads code. A recipe that only MENTIONED the call in a
    # comment must not satisfy it — the shape that has defeated this
    # product's structural checks more than any other.
    let commentedOut = recipeCode.replace(
      "let imageLayoutError = layoutRecord.verifyImageLayoutRecord(",
      "# let imageLayoutError = layoutRecord.verifyImageLayoutRecord(")
    check commentedOut != recipeCode
    check "let imageLayoutError = layoutRecord.verifyImageLayoutRecord(" notin
      squashed(nimCode(commentedOut))

suite "the profile takes the layout from the image":
  test "a profile naming a layout its image was NOT built with fails":
    ## AT THE MOCK TIER, deliberately. At `atTpm` this case is satisfied
    ## by the WRONG refusal: taking the record's layout and letting the
    ## pre-existing tier rule reject `tpm`-on-writable-root raises an
    ## `EConfigViolation` that also names both layouts, so deleting the
    ## disagreement check outright left the case green. Measured.
    ##
    ## `mock` is accepted on every layout, so the tier rule cannot fire
    ## here at all and the only thing that can refuse is the
    ## disagreement itself.
    let record = layoutRecord.imageLayoutRecordFor(recipeRequest())
    var raised = false
    try:
      discard attestationActivity(attestationConfigForImage(
        record, tier = atMock, declaredLayout = attestableLayout))
    except EConfigViolation as err:
      raised = true
      checkpoint err.msg
      # Both sides named: what the profile declared and what the image
      # reports having been built as.
      check attestableLayout in err.msg
      check builtLayout in err.msg
      # And pinned by the disagreement's OWN wording, so the other
      # refusal in this module cannot stand in for it.
      check "it was BUILT as" in err.msg
      check "whose root filesystem is writable" notin err.msg
    check raised

  test "the same disagreement at a tier that needs evidence is ALSO refused":
    # The deployment shape that matters, kept as its own case so that the
    # one above can be the one with no second explanation.
    let record = layoutRecord.imageLayoutRecordFor(recipeRequest())
    var raised = false
    try:
      discard attestationActivity(attestationConfigForImage(
        record, tier = atTpm, declaredLayout = attestableLayout))
    except EConfigViolation as err:
      raised = true
      checkpoint err.msg
      check "it was BUILT as" in err.msg
    check raised

  test "and so does one that names nothing, because the IMAGE decides":
    # No declaration at all: the config takes the image's answer, and the
    # tier rule then decides against what was BUILT. This is the arm that
    # makes the record load-bearing rather than advisory — a profile
    # cannot reach an attestable verdict by staying quiet.
    let record = layoutRecord.imageLayoutRecordFor(recipeRequest())
    # The layout really is taken FROM THE RECORD. Checked at the mock
    # tier, where nothing refuses, so the value itself is the assertion
    # rather than the exception that follows from it.
    check attestationConfigForImage(record).imageLayout == builtLayout
    expect EConfigViolation:
      discard attestationActivity(
        attestationConfigForImage(record, tier = atTpm))

  test "THE POSITIVE CASE: agreement on an attestable image plans":
    let record = layoutRecord.imageLayoutRecordFor(
      requestFor(attestableLayout))
    let cfg = attestationConfigForImage(
      record, tier = atTpm, declaredLayout = attestableLayout)
    check cfg.imageLayout == attestableLayout
    check cfg.tier == atTpm
    let spec = attestationActivity(cfg)
    check spec.name == "attestation"
    # Silence is also allowed here, and gives the same answer.
    check attestationConfigForImage(record, tier = atTpm).imageLayout ==
      attestableLayout

  test "the mock tier is unaffected by either layout":
    # The escape hatch keeps working on both, so the record did not turn
    # into a second gate on development machines.
    for preset in diskLayouts.DiskLayoutPresets:
      checkpoint preset.name
      let record = layoutRecord.imageLayoutRecordFor(requestFor(preset.name))
      check attestationActivity(attestationConfigForImage(record)).name ==
        "attestation"

  test "a record the activity cannot read is a refusal, not a default":
    # An unreadable record must not fall back to "whatever the profile
    # said": that is the defect, re-entered through the error path.
    var raised = false
    try:
      discard attestationConfigForImage("not a document",
        tier = atTpm, declaredLayout = attestableLayout)
    except EConfigViolation as err:
      raised = true
      checkpoint err.msg
      check "cannot tell what layout" in err.msg
    check raised
