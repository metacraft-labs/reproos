#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repro_bin="${REPRO_BIN:-repro}"
fixture="$repo_root/tests/fixtures/auto-config-minimal.toml"
installer_bin="${REPROOS_INSTALLER_BIN:-$repo_root/apps/reproos-installer/.repro/output/install/usr/bin/reproos-installer}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
generated="$work/generated"

bash "$repo_root/tests/test-installer-artifacts.sh"
"$installer_bin" --config "$fixture" --emit-artifacts "$generated"
(
  cd "$repo_root"
  REPRO_AUTO_CONFIG="$generated/auto-config.toml" "$repro_bin" build \
    recipes/reproos-image --tool-provisioning=from-source
)
bash "$repo_root/tests/test-installed-image-health.sh"
