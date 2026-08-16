import std/[os, strutils]

import gui_assert/ocr

if paramCount() != 1:
  stderr.writeLine("usage: test_installer_vm_frame FRAME.png")
  quit(2)

let frame = absolutePath(paramStr(1))
if not fileExists(frame):
  stderr.writeLine("VM frame missing: " & frame)
  quit(2)

let text = concatenatedText(runOcr(frame)).toLowerAscii()
for expected in ["reproos", "welcome", "standard configuration"]:
  if expected notin text:
    stderr.writeLine("VM frame OCR is missing '" & expected & "': " & text)
    quit(1)

echo "installer VM frame: PASS"
