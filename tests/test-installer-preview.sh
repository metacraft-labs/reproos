#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="$repo_root/build/test-installer-preview/summary.png"

# shellcheck source=tools/installer-dev-runtime.sh
source "$repo_root/tools/installer-dev-runtime.sh"
reproos_installer_runtime_init "$repo_root"
reproos_require_installer

"$REPROOS_INSTALLER_BIN" --help | grep -q -- '--preview'

# Execute every install phase with the same forced dry-run flag used by the
# interactive preview. A failure here means preview mode is not safely usable.
"$REPROOS_INSTALLER_BIN" \
  --preview \
  --automated "$repo_root/tests/fixtures/auto-config-minimal.toml"

rm -f "$output"
QT_QPA_PLATFORM=offscreen \
QT_QUICK_BACKEND=software \
  "$REPROOS_INSTALLER_BIN" \
    --preview \
    --visual-screen summary \
    --window-size 960x720 \
    --screenshot "$output"

test -s "$output"
printf 'installer preview: PASS\nframe=%s\n' "$output"
