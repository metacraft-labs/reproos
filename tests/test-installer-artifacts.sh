#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installer_bin="${REPROOS_INSTALLER_BIN:-$repo_root/apps/reproos-installer/.repro/output/install/usr/bin/reproos-installer}"
fixture="$repo_root/tests/fixtures/auto-config-minimal.toml"
golden="$repo_root/tests/golden/installer-artifacts"

if [[ ! -x "$installer_bin" ]]; then
  repro_bin="${REPRO_BIN:-repro}"
  "$repro_bin" build "$repo_root/apps/reproos-installer" \
    --tool-provisioning=from-source
fi
if [[ ! -x "$installer_bin" ]]; then
  echo "installer binary missing after build: $installer_bin" >&2
  exit 1
fi

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

echo "installer artifact contract: PASS"
