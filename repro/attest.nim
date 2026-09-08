## The measurement manifest the attested image build emits.
##
## ## What the document is
##
## An attested image is only useful if someone can say, before the machine
## exists, what a TPM will report when that image boots. The build says
## it: alongside the unified kernel image it writes a
## ``reproos.attested-image.v1`` document carrying the digests of the
## image's outputs and, per hardware backend, the launch measurement that
## backend will produce.
##
## ## Why there is no emitter here
##
## This module declares the EDGE — the typed request, its validation, the
## files it reads, the file it writes and the argv that produces it — and
## nothing else. The document itself is computed by ``repro attest
## expect``, which is also what a verifier runs when it rebuilds the image
## and compares. One implementation of the schema and of every calculator,
## exercised by both sides, is the point: a second emitter would be a
## second opinion about what an image measures, and a measurement manifest
## exists precisely to remove second opinions.
##
## ## What rides in it, and what does not
##
## The TPM tier is computed: PCR 11 is a pure function of the image's own
## sections, so it can be derived here with nothing but the bytes. The
## confidential-VM tiers are NOT: their launch digests depend on firmware
## and on per-deployment launch parameters that this recipe does not
## enumerate. Their arrays are emitted EMPTY rather than omitted, so the
## document says "this build computed no expectation for you" instead of
## leaving a reader to guess whether the key is missing or the value is.
##
## Signing is out of scope, exactly as it is for the unified kernel image
## itself: a stub measures the sections it consumes whether or not the PE
## carries an Authenticode signature, so an unsigned image is fully
## attestable on this tier and simply not loadable under Secure Boot.

import std/[os, strutils]

import repro_attest

import "./uki" as ukiModule
import "./verity" as verityModule

const
  AttestManifestFileName* = AttestedImageManifestFileName
    ## The document's name, taken from the schema's own declaration so
    ## the build and every reader agree on it.

  AttestBackends*: array[1, string] = [BackendTpm]
    ## The backends this recipe asks for. Naming them explicitly — rather
    ## than defaulting to "all" — is what makes the addition of a
    ## confidential-VM calculator a visible change to this list instead of
    ## a silent change in what the image publishes.

type
  AttestExpectRequest* = object
    ## Everything the manifest is a function of. Every path is relative to
    ## the action's working directory.
    ukiPath*: string
    verityImagePath*: string
    verityRootHashPath*: string
    configFingerprint*: string
    backends*: seq[string]
    outputDir*: string

proc attestOutputPaths*(request: AttestExpectRequest): seq[string] =
  ## The one file the edge writes.
  @[request.outputDir / AttestManifestFileName]

proc validateAttestExpectRequest*(request: AttestExpectRequest): string =
  ## Returns "" or the reason the request cannot be honoured.
  ##
  ## The unknown-backend check is here as well as in the library because
  ## this is where a recipe edit lands: a name nobody can compute must
  ## stop the PLAN, not produce an image whose manifest is missing the
  ## expectation its author thought they had asked for.
  if request.ukiPath.len == 0:
    return "attest request: no unified kernel image"
  if request.verityImagePath.len == 0:
    return "attest request: no integrity-protected root image; an " &
      "attested image's identity covers its root filesystem"
  if request.verityRootHashPath.len == 0:
    return "attest request: no dm-verity root-hash file"
  if request.configFingerprint.len == 0:
    return "attest request: no configuration fingerprint; a manifest that " &
      "does not say which configuration it describes cannot be matched to one"
  if request.outputDir.len == 0:
    return "attest request: no output directory"
  if request.backends.len == 0:
    return "attest request: no backends; an image with no expected " &
      "measurement is an image nothing can verify"
  for backend in request.backends:
    if backend notin KnownBackends:
      return "attest request: unknown launch measurement backend " &
        backend.escape() & "; this build computes " &
        KnownBackends.join(", ")
  ""

proc attestExpectArgv*(reproCli: string;
                       request: AttestExpectRequest): seq[string] =
  ## The argv the edge runs. Derived from the same request the declared
  ## inputs and outputs are derived from, so the three cannot drift.
  result = @[reproCli, "attest", "expect",
             "--uki", request.ukiPath,
             "--verity-image", request.verityImagePath,
             "--verity-root-hash-file", request.verityRootHashPath,
             "--config-fingerprint", request.configFingerprint]
  for backend in request.backends:
    result.add "--backend"
    result.add backend
  result.add "--out"
  result.add attestOutputPaths(request)[0]

proc attestInputPaths*(request: AttestExpectRequest): seq[string] =
  ## The artifacts the document is a function of. If any of these moves,
  ## the manifest must be recomputed — which is what makes them the edge's
  ## declared inputs rather than a comment.
  @[request.ukiPath, request.verityImagePath, request.verityRootHashPath]

proc expectedTpmMeasurement*(ukiImage: string): TpmExpectation =
  ## The TPM-tier expectation for an assembled unified kernel image.
  ## Re-exported here so a gate in this repository can derive the value
  ## the same way the build does without reaching into the CLI.
  tpmExpectationFor(ukiImage)

# The two constants below are asserted against the artifacts they
# describe rather than being trusted. `repro/uki.nim` decides which
# sections a ReproOS image carries and `repro/verity.nim` names the
# artifact the root image is written to; the gate checks that the sections
# this measurement covers really are the ones assembled, so the two
# modules cannot drift apart silently.
const
  MeasuredUkiSections*: array[5, string] = [
    ukiModule.UkiLinuxSection, ukiModule.UkiOsRelSection,
    ukiModule.UkiCmdlineSection, ukiModule.UkiInitrdSection,
    ukiModule.UkiUnameSection]
    ## The sections a ReproOS image appends, in the order a stub measures
    ## them. The stub's OWN sections are measured too — `.sbat` is one —
    ## so this is not the whole measured set; it is the part this
    ## repository produces.

  MeasuredVerityImageName* = verityModule.VerityDataImageFileName
  MeasuredVerityRootHashName* = verityModule.VerityRootHashFileName
