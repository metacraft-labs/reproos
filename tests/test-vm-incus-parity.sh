#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${REPROOS_PARITY_TEST_TAG:-$$}"
project="reproos-parity-$tag"
instance="reproos-parity-$tag"
network="rp-${tag:0:12}"
output="$repo_root/build/test-vm-incus-parity-$tag"
tool="$repo_root/tools/reproos-incus.sh"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }
incus_test() { "${incus_cmd[@]}" --project "$project" "$@"; }

if ! command -v "${incus_cmd[0]}" >/dev/null ||
   ! incus_global info >/dev/null 2>&1; then
  echo "[skip] ReproOS VM/Incus parity: Incus daemon unavailable"
  exit 0
fi
if ! command -v "$vm_harness" >/dev/null; then
  echo "vm-harness is required for the VM/Incus parity gate" >&2
  exit 1
fi

mkdir -p "$output"
cleanup() {
  REPROOS_INCUS_PROJECT="$project" \
  REPROOS_INCUS_INSTANCE="$instance" \
  REPROOS_INCUS_NETWORK="$network" \
  VM_HARNESS_BIN="$vm_harness" \
    bash "$tool" destroy >/dev/null 2>&1 || true
}
trap cleanup EXIT

read -r -d '' probe <<'EOF' || true
set -eu
printf 'hostname=%s\n' "$(hostname)"
/usr/bin/busybox awk -F: '$1 == "repro" { print "user=" $3 ":" $4 ":" $5 ":" $6 ":" $7 }' /etc/passwd
groups="$(/usr/bin/busybox id -Gn repro | /usr/bin/busybox tr ' ' '\n' | /usr/bin/busybox sort | /usr/bin/busybox tr '\n' ',' | /usr/bin/busybox sed 's/,$//')"
printf 'groups=%s\n' "$groups"
for artifact in auto-config.toml home.nim system.nim; do
  set -- $(/usr/bin/busybox sha256sum "/etc/repro/$artifact")
  printf '%s=%s\n' "$artifact" "$1"
done
systemctl is-active --quiet sshd.service
EOF

if ! "$vm_harness" probe | python3 -c '
import json, sys
backends = {backend["id"]: backend for backend in json.load(sys.stdin)}
raise SystemExit(0 if backends.get("libvirt", {}).get("available") else 1)
'; then
  echo "vm-harness cannot reach the libvirt backend" >&2
  echo "LIBVIRT_DEFAULT_URI=${LIBVIRT_DEFAULT_URI:-<unset>}" >&2
  echo "PATH=$PATH" >&2
  echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-<unset>}" >&2
  command -v virsh >&2 || echo "virsh is not on PATH" >&2
  virsh --connect "${LIBVIRT_DEFAULT_URI:-qemu:///system}" list --all >&2 || true
  exit 1
fi

REPROOS_IMAGE="${REPROOS_IMAGE:-$repo_root/recipes/reproos-image/build/reproos-installed.qcow2}" \
VM_HARNESS_BIN="$vm_harness" \
  bash "$repo_root/tests/test-installed-ssh.sh" \
    /usr/bin/busybox sh -c "$probe"
cp "$repo_root/build/test-installed-ssh/command.log" "$output/vm.contract"

REPROOS_INCUS_PROJECT="$project" \
REPROOS_INCUS_INSTANCE="$instance" \
REPROOS_INCUS_NETWORK="$network" \
VM_HARNESS_BIN="$vm_harness" \
  bash "$tool" launch >/dev/null

deadline=$((SECONDS + 120))
until incus_test exec "$instance" -- test -s /run/reproos/healthy >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "ReproOS container did not reach its health marker" >&2
    exit 1
  fi
  sleep 1
done
incus_test exec "$instance" -- /usr/bin/busybox sh -c "$probe" \
  >"$output/container.contract"

python3 "$repo_root/tests/check_vm_incus_parity.py" \
  --vm "$output/vm.contract" \
  --container "$output/container.contract" \
  --report "$repo_root/recipes/reproos-container/build/projection/projection-report.json" \
  --config "$repo_root/tests/fixtures/auto-config-minimal.toml" \
  --artifacts "$repo_root/tests/golden/installer-artifacts"
