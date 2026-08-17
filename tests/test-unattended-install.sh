#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/tests/fixtures/auto-config-minimal.toml"
installer_bin="${REPROOS_INSTALLER_BIN:-$repo_root/build/reproos-installer/out/usr/bin/reproos-installer}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
generated="$work/generated"

"$installer_bin" --config "$fixture" --emit-artifacts "$generated"

# The image edge consumes this canonical fixture. Byte equality proves the
# interactive emitter produces the exact unattended input already exercised by
# the image build, without launching a nested build from inside a test edge.
cmp "$generated/auto-config.toml" "$fixture"
bash "$repo_root/tests/test-installed-image-health.sh"
