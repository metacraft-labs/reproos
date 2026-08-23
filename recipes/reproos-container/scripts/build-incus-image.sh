#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: build-incus-image.sh ROOTFS PROJECTION_DIR IMAGE MANIFEST" >&2
  exit 2
fi

rootfs="$(realpath "$1")"
projection="$(realpath "$2")"
image="$(realpath -m "$3")"
manifest="$(realpath -m "$4")"
epoch="${SOURCE_DATE_EPOCH:-1735689600}"

for path in \
    "$rootfs/usr/lib/systemd/systemd" \
    "$projection/projection-report.json" \
    "$projection/artifacts/auto-config.toml"; do
  if [[ ! -e "$path" ]]; then
    echo "Incus image input missing: $path" >&2
    exit 1
  fi
done
for tool in cp python3 tar xz sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "Incus image tool missing: $tool" >&2
    exit 1
  }
done

work="$(mktemp -d -t reproos-incus-image-XXXXXX)"
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/rootfs" "$(dirname "$image")" "$(dirname "$manifest")"
cp -a "$rootfs/." "$work/rootfs/"

# Kernel, firmware, bootloader, and live-installer state have no meaning in a
# system container. Package and generation provenance remains in /etc/repro.
rm -rf \
  "$work/rootfs/boot" \
  "$work/rootfs/usr/lib/modules" \
  "$work/rootfs/lib/modules" \
  "$work/rootfs/opt/repro/reprobuild-packages/packages/source/kernel" \
  "$work/rootfs/opt/repro/reprobuild-packages/packages/source/grub"

python3 "$(dirname "$0")/project-incus-config.py" \
  --config "$projection/artifacts/auto-config.toml" \
  --artifacts-dir "$projection/artifacts" \
  --output-dir "$work/projected" \
  --rootfs "$work/rootfs"
cmp "$projection/projection-report.json" \
  "$work/projected/projection-report.json"

generation="$(python3 - "$projection/projection-report.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as source:
    generation = json.load(source).get("configuration_sha256", "")
if re.fullmatch(r"[0-9a-f]{64}", generation) is None:
    raise SystemExit("projection report has an invalid configuration_sha256")
print(generation)
PY
)"

cat >"$work/metadata.yaml" <<EOF
architecture: x86_64
creation_date: $epoch
properties:
  architecture: x86_64
  description: ReproOS source-built system container
  os: ReproOS
  release: dev
  reproos.generation: $generation
  variant: incus-system-container
templates: {}
EOF

raw="$work/reproos-incus.tar"
tar_flags=(
  --sort=name
  --mtime="@$epoch"
  --owner=0
  --group=0
  --numeric-owner
  --format=posix
  --pax-option=delete=atime,delete=ctime
)
tar "${tar_flags[@]}" \
  --exclude=rootfs/home/repro \
  -C "$work" -cf "$raw" metadata.yaml rootfs
if [[ -d "$work/rootfs/home/repro" ]]; then
  tar "${tar_flags[@]}" --owner=1000 --group=1000 \
    -C "$work" -rf "$raw" rootfs/home/repro
fi
xz -6 --threads=1 --check=crc64 -c "$raw" >"$image.tmp"
mv "$image.tmp" "$image"

sha="$(sha256sum "$image" | awk '{print $1}')"
size="$(stat -c %s "$image")"
printf '%s  %s\n' "$sha" "$(basename "$image")" \
  >"$(dirname "$image")/reproos-incus.sha256"
cat >"$manifest.tmp" <<EOF
vm=reproos-incus
snapshot=source-built
alias=reproos-incus
generation=$generation
tarball=$(basename "$image")
sha256=$sha
bytes=$size
EOF
mv "$manifest.tmp" "$manifest"
echo "[reproos-incus] OK image=$image bytes=$size sha256=$sha"
