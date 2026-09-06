#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer_bin="${REPROOS_INSTALLER_BIN:-$repo_root/.repro/output/install/usr/bin/reproos-installer}"
fixture="$repo_root/tests/fixtures/auto-config-minimal.toml"
golden="$repo_root/tests/golden/installer-artifacts"

if [[ ! -x "$installer_bin" ]]; then
  echo "installer binary missing: $installer_bin" >&2
  echo "run: repro build installer --tool-provisioning=from-source" >&2
  exit 1
fi

# Qt routes qCritical() to the journal on some builds. Every refusal
# this script asserts on is a qCritical(), so force stderr rather than
# make the assertions depend on how the host's Qt was configured.
export QT_FORCE_STDERR_LOGGING=1

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
first="$work/first"
second="$work/second"

"$installer_bin" --config "$fixture" --emit-artifacts "$first"

expected=(auto-config.toml system.nim hardware.nim disko.json home.nim)
mapfile -t actual < <(find "$first" -maxdepth 1 -type f -printf '%f\n' | sort)
mapfile -t sorted_expected < <(printf '%s\n' "${expected[@]}" | sort)
if [[ "${actual[*]}" != "${sorted_expected[*]}" ]]; then
  echo "unexpected artifact set: ${actual[*]}" >&2
  exit 1
fi

for artifact in "${expected[@]}"; do
  diff -u "$golden/$artifact" "$first/$artifact"
done

# Canonical output must be accepted as input and remain byte-identical.
"$installer_bin" --config "$first/auto-config.toml" --emit-artifacts "$second"
for artifact in "${expected[@]}"; do
  cmp "$first/$artifact" "$second/$artifact"
done

if grep -R -F "smoke-pass-changeme" "$first"; then
  echo "plaintext password leaked into installer artifacts" >&2
  exit 1
fi

cp "$fixture" "$work/unknown-key.toml"
printf '\nunsupported_key = true\n' >> "$work/unknown-key.toml"
if "$installer_bin" --config "$work/unknown-key.toml" \
    --emit-artifacts "$work/rejected" >"$work/rejected.log" 2>&1; then
  echo "configuration with an unknown key was accepted" >&2
  exit 1
fi
grep -F "unknown configuration key" "$work/rejected.log" >/dev/null

# The disk layout is decided in one place -- repro/disk_layouts.nim,
# compiled into the installer by tools/gen_disk_layouts.nim -- and the
# binary must refuse with the registry's own reason rather than with a
# validator of its own. tests/test_installer_disk_layout_parity.nim
# proves the two texts are identical; this asserts the shipped BINARY
# behaves that way, which is the thing the image driver invokes.
sed 's/^type = "uefi-ext4"/type = "uefi-reproos-not-a-preset"/' \
  "$fixture" > "$work/unknown-layout.toml"
if "$installer_bin" --config "$work/unknown-layout.toml" \
    --emit-artifacts "$work/unknown-layout-out" \
    >"$work/unknown-layout.log" 2>&1; then
  echo "an unregistered disk layout was accepted" >&2
  exit 1
fi
grep -F "unknown [disk.layout].type" "$work/unknown-layout.log" >/dev/null
# The refusal must list the legal set, not merely say no.
grep -F "uefi-ext4" "$work/unknown-layout.log" >/dev/null
grep -F "uefi-attested" "$work/unknown-layout.log" >/dev/null

# A preset the registry declares but cannot build yet is refused with
# the registry's recorded reason. Sized past the preset's minimum so
# this exercises the declared-only refusal and not the size check.
sed -e 's/^type = "uefi-ext4"/type = "uefi-attested"/' \
    -e 's/^size_gb = 8/size_gb = 32/' \
  "$fixture" > "$work/declared-layout.toml"
if "$installer_bin" --config "$work/declared-layout.toml" \
    --emit-artifacts "$work/declared-layout-out" \
    >"$work/declared-layout.log" 2>&1; then
  echo "a declared-but-not-yet-buildable disk layout was accepted" >&2
  exit 1
fi
grep -F "is declared but not yet buildable" "$work/declared-layout.log" >/dev/null
grep -F "no verity image behind it yet" "$work/declared-layout.log" >/dev/null

echo "installer artifact contract: PASS"
