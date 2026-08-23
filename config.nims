import std/os

let reprobuildRoot = block:
  let configured = getEnv("REPROBUILD_SRC")
  if configured.len > 0: configured
  else: ".." / "reprobuild"

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
