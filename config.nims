import std/os

let reprobuildRoot = block:
  let configured = getEnv("REPROBUILD_SRC")
  if configured.len > 0: configured
  else: ".." / "reprobuild"

# vm-harness is a sibling repository, not a Reprobuild library: ReproOS
# drives every VM through it (`uses: "vm-harness"` in repro/workflows.nim
# for the CLI, and `import vm_harness` from tests/test_reproos_image_boot_smoke.nim
# for the Nim boot-smoke gate). Resolve it the way Reprobuild does —
# $VM_HARNESS_SRC first, then the sibling checkout — but anchor the
# fallback on this file rather than the current directory so it resolves
# identically however `nim` is invoked.
let vmHarnessRoot = block:
  let configured = getEnv("VM_HARNESS_SRC")
  if configured.len > 0: configured
  else: thisDir() / ".." / "vm-harness" / "src"
if fileExists(vmHarnessRoot / "vm_harness.nim"):
  switch("path", vmHarnessRoot)

let libsRoot = reprobuildRoot / "libs"
if dirExists(libsRoot):
  for kind, path in walkDir(libsRoot):
    if kind == pcDir and dirExists(path / "src"):
      switch("path", path / "src")

let nimcryptoRoot = libsRoot / "nimcrypto"
if fileExists(nimcryptoRoot / "nimcrypto" / "hash.nim"):
  switch("path", nimcryptoRoot)

let blake3Headers = libsRoot / "blake3" / "src" / "blake3" / "vendor"
let xxhashHeaders = libsRoot / "xxh3" / "src" / "xxh3" / "vendor"
if fileExists(blake3Headers / "blake3.h") and
    fileExists(xxhashHeaders / "xxhash.h"):
  switch("passC", "-DREPRO_VENDORED_HASH")
  switch("passC", "-I" & blake3Headers)
  switch("passC", "-I" & xxhashHeaders)
  switch("path", thisDir() / "support")
  # Provider builds import the Reprobuild hash modules directly; under
  # -d:reproVendoredHash those modules already schedule the vendored C files.
  # Interface-only runners lack that module closure and need the local shim.
  if not defined(reproVendoredHash):
    switch("import", "reproos_vendored_hash_runtime")
