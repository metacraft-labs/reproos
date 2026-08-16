#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${REPROOS_IMAGE:-$repo_root/recipes/reproos-image/build/reproos-installed.qcow2}"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"

if [[ ! -s "$image" ]]; then
  echo "installed image missing: $image" >&2
  echo "run: repro build recipes/reproos-image --tool-provisioning=from-source" >&2
  exit 1
fi

"$vm_harness" boot \
  --backend auto \
  --source-image "$image" \
  --kind qcow2 \
  --expect 'REPROOS_HEALTH:PASS' \
  --timeout-sec 300
