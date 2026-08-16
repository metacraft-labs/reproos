#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repro_bin="${REPRO_BIN:-repro}"
fixture="$repo_root/tests/fixtures/auto-config-minimal.toml"

bash "$repo_root/tests/test-installer-artifacts.sh"
(
  cd "$repo_root"
  REPRO_AUTO_CONFIG="$fixture" "$repro_bin" build \
    recipes/reproos-image --tool-provisioning=from-source
)
bash "$repo_root/tests/test-installed-image-health.sh"
