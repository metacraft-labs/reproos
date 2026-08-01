## Links the portable vendored hash implementations into generated recipe
## interface runners. These runners compile from the product repository, so
## reprobuild's own config.nims is not loaded to schedule the C sources.

import std/os

const reprobuildRoot = block:
  const configured = getEnv("REPROBUILD_SRC")
  if configured.len > 0:
    configured
  else:
    currentSourcePath().parentDir.parentDir / ".." / "reprobuild"

const blake3Root = reprobuildRoot / "libs" / "blake3" / "src" /
  "blake3" / "vendor"
const xxhashRoot = reprobuildRoot / "libs" / "xxh3" / "src" /
  "xxh3" / "vendor"

{.passC: "-DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_NO_SSE2 " &
         "-DBLAKE3_NO_SSE41 -DBLAKE3_USE_NEON=0".}
{.compile: blake3Root / "blake3.c".}
{.compile: blake3Root / "blake3_dispatch.c".}
{.compile: blake3Root / "blake3_portable.c".}
{.compile: xxhashRoot / "xxhash.c".}
