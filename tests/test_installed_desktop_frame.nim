import std/[os, osproc, streams, strutils]

import gui_assert/image_math
import gui_assert/ocr

proc fail(message: string) =
  stderr.writeLine(message)
  quit(1)

proc cropPanel(frame, output: string; width, height: int) =
  let ffmpeg = findExe("ffmpeg")
  if ffmpeg.len == 0:
    fail("ffmpeg is required to crop the installed desktop panel")
  let process = startProcess(
    command = ffmpeg,
    args = @[
      "-hide_banner", "-loglevel", "error", "-y",
      "-i", frame,
      "-vf", "crop=" & $width & ":" & $height & ":0:0",
      "-frames:v", "1", output,
    ],
    options = {poStdErrToStdOut})
  let processOutput = process.outputStream().readAll()
  let exitCode = process.waitForExit()
  process.close()
  if exitCode != 0 or not fileExists(output):
    fail("failed to crop the installed desktop panel: " & processOutput)

if paramCount() != 1:
  fail("usage: test_installed_desktop_frame FRAME.png")

let frame = absolutePath(paramStr(1))
if not fileExists(frame):
  fail("installed desktop frame missing: " & frame)

let imageSize = probeImageSize(frame)
if imageSize != (1280, 800):
  fail("unexpected installed desktop dimensions: " &
    $imageSize.width & "x" & $imageSize.height)

let gray = decodeGray(frame)
var rowMeans = newSeq[int](gray.height)
for y in 0 ..< gray.height:
  var rowTotal = 0
  for x in 0 ..< gray.width:
    rowTotal += int(gray.pixels[y * gray.width + x].uint8)
  rowMeans[y] = rowTotal div gray.width

var backgroundTotal = 0
for y in gray.height - 40 ..< gray.height:
  backgroundTotal += rowMeans[y]
let backgroundMean = backgroundTotal div 40
var panelEnd = -1
var backgroundRun = 0
for y in 0 ..< min(gray.height, 320):
  if abs(rowMeans[y] - backgroundMean) <= 3:
    inc backgroundRun
    if backgroundRun == 3:
      panelEnd = y - 2
      break
  else:
    backgroundRun = 0

if panelEnd < 48 or panelEnd > 140:
  fail("installed desktop readiness panel has unexpected height: " &
    $panelEnd & " (background mean " & $backgroundMean & ")")

let panelFrame = getTempDir() /
  ("reproos-installed-desktop-panel-" & $getCurrentProcessId() & ".png")
try:
  cropPanel(frame, panelFrame, gray.width, panelEnd)
  let words = runOcrEx(panelFrame, initOcrOptions(psm = 6))
  let text = concatenatedText(words).toLowerAscii()
  for expected in ["reproos", "ready"]:
    if expected notin text:
      fail("installed desktop OCR is missing '" & expected & "': " & text)

  for word in words:
    let wordBottom = word.bbox[1] + word.bbox[3]
    if wordBottom > panelEnd:
      fail("installed desktop text escapes the readiness panel: " & word.text)
finally:
  if fileExists(panelFrame):
    removeFile(panelFrame)

echo "installed desktop frame: PASS"
