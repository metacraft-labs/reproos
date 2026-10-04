## The record an image build publishes saying which disk layout it was
## actually built with.
##
## ## Why an image has to say this out loud
##
## A profile that enables attestation has to know whether the root
## filesystem it is enabling it on is integrity-checked and read-only for
## the life of the boot, because a launch measurement of a root that goes
## on being written to says nothing about the machine an hour later.
## Until this record existed the profile answered that question itself,
## by naming a layout — so the only cross-check available compared the
## profile's belief against the profile's belief, and the single failure
## it could not see was the image having been built some other way.
##
## This module is the producing half. ``repro/disk_layouts.nim`` resolves
## the layout and renders the partition table; this renders a record that
## names the resolved layout and carries the digest of that table, and
## refuses to let the build publish a record whose digest is not the
## digest of the table the build is actually applying.
##
## ## What the digest is for, and why the record is not just a name
##
## A name beside a partition table is two declarations again. The digest
## is what ties them: the record's ``partitionTableSha256`` is taken over
## the document the NAMED layout renders, and
## ``verifyImageLayoutRecord`` compares it against the document the build
## hands the partitioner. Rendering one layout's table while publishing
## another layout's name is therefore a plan-time refusal rather than an
## image nobody can describe — and the refusal names the layout the table
## really belongs to, found by rendering every preset rather than by
## guessing.
##
## ## Why the schema is not declared here
##
## It lives in ``repro_attest/image_layout``, with the measurement
## manifest's, because it is written at one end of a repository boundary
## and read at the other. A second declaration of it would be a second
## opinion about what an image is, held by exactly the two parties the
## document exists to keep in step.
##
## ## Mocking
##
## None. Pure functions over the real presets.

import std/strutils

import nimcrypto/[hash, sha2]

import repro_attest/image_layout

import "./disk_layouts" as diskLayouts

export image_layout.ImageLayoutRecord
export image_layout.ImageLayoutRecordError
export image_layout.ImageLayoutRecordFileName
export image_layout.ImageLayoutRecordSchema
export image_layout.parseImageLayoutRecord

proc partitionTableDigest*(document: string): string =
  ## SHA-256 of a rendered partition-table document, lower-case hex.
  toLowerAscii($sha256.digest(document))

proc imageLayoutRecordFor*(request: diskLayouts.DiskLayoutRequest): string =
  ## The record for a RESOLVED layout request — the value
  ## ``parseDiskLayoutRequest`` returned and ``validateDiskLayoutRequest``
  ## accepted, not the raw text of a configuration file. The distinction
  ## matters: a configuration that names no layout takes a default, and
  ## the record has to say what the build settled on rather than what it
  ## was asked for.
  renderImageLayoutRecord(ImageLayoutRecord(
    layout: request.name,
    id: request.params.id,
    device: request.params.device,
    espSizeMib: request.params.espSizeMib,
    diskSizeGb: request.params.diskSizeGb,
    partitionTableSha256: partitionTableDigest(
      diskLayouts.renderDiskoJson(request.name, request.params))))

proc layoutOfPartitionTable*(appliedPartitionTable: string;
                             p: diskLayouts.DiskLayoutParams): string =
  ## Which preset renders ``appliedPartitionTable`` for these parameters,
  ## or "" if none does. Used only to make a refusal say what the table
  ## IS as well as what it is not — a diagnostic that named only the
  ## layout that was claimed would leave the reader to find the other
  ## half by hand.
  for preset in diskLayouts.DiskLayoutPresets:
    if diskLayouts.renderDiskoJson(preset.name, p) == appliedPartitionTable:
      return preset.name
  ""

proc verifyImageLayoutRecord*(record, appliedPartitionTable: string): string =
  ## "" when the record describes the table the build is applying,
  ## otherwise the operator-facing reason. The caller turns it into a
  ## plan-time failure, before any privileged work starts.
  ##
  ## The two arguments come from two places on purpose: the record from
  ## the resolved layout, the table from whatever the build is about to
  ## hand the partitioner. A check whose sides came from one expression
  ## would restate that expression and catch nothing.
  var parsed: ImageLayoutRecord
  try:
    parsed = parseImageLayoutRecord(record)
  except ImageLayoutRecordError as err:
    return "the image layout record is not readable: " & err.msg
  let applied = partitionTableDigest(appliedPartitionTable)
  if applied == parsed.partitionTableSha256:
    return ""
  let params = diskLayouts.DiskLayoutParams(
    id: parsed.id,
    device: parsed.device,
    espSizeMib: parsed.espSizeMib,
    diskSizeGb: parsed.diskSizeGb)
  let actual = layoutOfPartitionTable(appliedPartitionTable, params)
  result = "the image layout record says this image is being built as " &
    "\"" & parsed.layout & "\", but the partition table this build is " &
    "applying is not the one \"" & parsed.layout & "\" renders"
  if actual.len > 0 and actual != parsed.layout:
    result.add(" — it is the table \"" & actual & "\" renders")
  result.add(". A published record that names a layout the image does " &
    "not have is worse than none: it is what a profile reads to decide " &
    "whether a launch measurement of this machine means anything. " &
    "Record digest " & parsed.partitionTableSha256 & ", applied table " &
    "digest " & applied & ".")
