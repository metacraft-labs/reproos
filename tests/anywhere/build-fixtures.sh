#!/usr/bin/env bash
# Build the Anywhere FIXTURE artifacts into <dir>:
#   out-installer/ out-payload/ out-kexec/ bin/anywhere_layout
# They are not ReproOS; see tests/anywhere/fixture/default.nix.
#   tests/anywhere/build-fixtures.sh <dir> [<reprobuild checkout>]
set -euo pipefail
dir=$(realpath -m "${1:?usage: build-fixtures.sh <dir> [reprobuild]}")
here=$(cd "${BASH_SOURCE[0]%/*}" && pwd)
reproos=$(cd "$here/../.." && pwd)
reprobuild=$(realpath "${2:-$reproos/../reprobuild}")
mkdir -p "$dir/bin"
for a in installer payload kexec layoutTool; do
  out=$(nix-build "$here/fixture" -A "$a" --no-out-link \
    --arg reproosSrc "$reproos" --arg reprobuildSrc "$reprobuild")
  case "$a" in
    layoutTool) ln -sfn "$out/bin/anywhere_layout" "$dir/bin/anywhere_layout" ;;
    *) ln -sfn "$out" "$dir/out-$a" ;;
  esac
  # keep the outputs alive for the duration of the test run
  nix-store --add-root "$dir/gcroot-$a" --indirect -r "$out" >/dev/null
done
echo "$dir"
