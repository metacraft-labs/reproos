import std/[algorithm, os, strformat, strutils]

import gui_assert/image_math

const
  Views = [
    "welcome", "locale", "keyboard", "users", "disk", "deSelect",
    "activities", "summary", "install", "finished"
  ]
  Sizes = ["wide", "vm", "compact"]
  MinimumSsim = 0.995

proc fail(message: string) =
  stderr.writeLine(message)
  quit(1)

if paramCount() != 2:
  fail("usage: test_installer_visuals CURRENT_DIR GOLDEN_DIR")

let currentDir = absolutePath(paramStr(1))
let goldenDir = absolutePath(paramStr(2))
var expectedFiles: seq[string]

for view in Views:
  for size in Sizes:
    let filename = view & "-" & size & ".png"
    expectedFiles.add(filename)
    let current = currentDir / filename
    let golden = goldenDir / filename
    if not fileExists(current):
      fail("missing current installer frame: " & current)
    if not fileExists(golden):
      fail("missing golden installer frame: " & golden)

    let expectedSize =
      case size
      of "wide": (1280, 800)
      of "vm": (1024, 768)
      else: (960, 720)
    let actualSize = probeImageSize(current)
    if actualSize != expectedSize:
      fail(&"unexpected dimensions for {filename}: " &
           &"{actualSize.width}x{actualSize.height}")

    let score = ssimFromPaths(current, golden)
    echo &"{filename}: ssim={score:.6f}"
    if score < MinimumSsim:
      fail(&"visual regression in {filename}: SSIM {score:.6f} is below " &
           &"{MinimumSsim:.3f}")

for directory in [currentDir, goldenDir]:
  var pngFiles: seq[string]
  for path in walkFiles(directory / "*.png"):
    pngFiles.add(extractFilename(path))
  pngFiles.sort()
  expectedFiles.sort()
  if pngFiles != expectedFiles:
    fail("installer frame set differs in " & directory & ": " &
         pngFiles.join(", "))

echo "installer visual regression: PASS"
