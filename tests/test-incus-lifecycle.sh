#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${REPROOS_INCUS_TEST_TAG:-$$}"
project="reproos-test-$tag"
instance="reproos-test-$tag"
network="reproos-net-$tag"
output="$repo_root/build/test-incus-$tag"
tool="$repo_root/tools/reproos-incus.sh"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }
incus_test() { "${incus_cmd[@]}" --project "$project" "$@"; }

if ! command -v "${incus_cmd[0]}" >/dev/null || \
   ! incus_global info >/dev/null 2>&1; then
  echo "[skip] ReproOS Incus lifecycle: Incus daemon unavailable"
  exit 0
fi
if ! command -v "$vm_harness" >/dev/null; then
  echo "vm-harness is required for the Incus lifecycle gate" >&2
  exit 1
fi

mkdir -p "$output"
incus_global list --project default --format csv -c n | sort >"$output/default-instances.before"
incus_global image list --project default --format csv -c f | sort >"$output/default-images.before"

capture_evidence() {
  incus_test config show "$instance" --expanded >"$output/config.yaml" 2>&1 || true
  incus_test info "$instance" --show-log >"$output/info.log" 2>&1 || true
  incus_test console "$instance" --show-log >"$output/console.log" 2>&1 || true
  incus_test exec "$instance" -- journalctl -b --no-pager >"$output/journal.log" 2>&1 || true
}
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    capture_evidence
  fi
  REPROOS_INCUS_PROJECT="$project" \
  REPROOS_INCUS_INSTANCE="$instance" \
  REPROOS_INCUS_NETWORK="$network" \
  VM_HARNESS_BIN="$vm_harness" \
    bash "$tool" destroy >/dev/null 2>&1 || true
  incus_global list --project default --format csv -c n | sort >"$output/default-instances.after"
  incus_global image list --project default --format csv -c f | sort >"$output/default-images.after"
  cmp "$output/default-instances.before" "$output/default-instances.after"
  cmp "$output/default-images.before" "$output/default-images.after"
  if incus_global project show "$project" >/dev/null 2>&1; then
    echo "isolated Incus project survived cleanup: $project" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

REPROOS_INCUS_PROJECT="$project" \
REPROOS_INCUS_INSTANCE="$instance" \
REPROOS_INCUS_NETWORK="$network" \
VM_HARNESS_BIN="$vm_harness" \
  bash "$tool" launch

deadline=$((SECONDS + 120))
until incus_test exec "$instance" -- test -s /run/reproos/healthy >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "ReproOS container did not reach its health marker" >&2
    exit 1
  fi
  sleep 1
done

incus_test exec "$instance" -- grep -Fx REPROOS_INCUS_HEALTH:PASS /run/reproos/healthy
incus_test exec "$instance" -- test "$(incus_test exec "$instance" -- hostname | tr -d '\r')" = reproos-smoke
incus_test exec "$instance" -- test -s /etc/repro/system.nim
incus_test exec "$instance" -- test -s /etc/repro/hardware.nim
incus_test exec "$instance" -- test -s /etc/repro/home.nim
incus_test exec "$instance" -- grep -Fq '"kind": "incus-system-container"' /etc/repro/realization.json
incus_test exec "$instance" -- test ! -e /boot/vmlinuz
incus_test exec "$instance" -- systemctl is-active sshd.service
incus_test exec "$instance" -- systemctl is-active reproos-incus-network.service
incus_test exec "$instance" -- systemctl is-active reproos-container-health.service

key="$output/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -f "$key"
incus_test exec "$instance" -- mkdir -p /home/repro/.ssh
incus_test file push --uid 1000 --gid 1000 --mode 0600 \
  "$key.pub" "$instance/home/repro/.ssh/authorized_keys"
incus_test exec "$instance" -- chown 1000:1000 /home/repro/.ssh

ip=""
deadline=$((SECONDS + 60))
while [[ -z "$ip" && "$SECONDS" -lt "$deadline" ]]; do
  ip="$(incus_test list "$instance" --format json | python3 -c '
import json, sys
rows = json.load(sys.stdin)
for address in rows[0].get("state", {}).get("network", {}).get("eth0", {}).get("addresses", []):
    if address.get("family") == "inet" and address.get("scope") == "global":
        print(address["address"])
        break
' 2>/dev/null || true)"
  [[ -n "$ip" ]] || sleep 1
done
if [[ -z "$ip" ]]; then
  echo "Incus container did not receive an IPv4 address" >&2
  exit 1
fi
ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
  "repro@$ip" 'test "$(hostname)" = reproos-smoke && test -s /etc/repro/system.nim'

vmh_env="${incus_cmd[*]} --project $project"
VMH_INCUS_CMD="$vmh_env" "$vm_harness" snapshot create \
  --backend incus "$instance" generation-clean >/dev/null
generation="$(incus_test exec "$instance" -- cat /etc/repro/generation | tr -d '\r')"
incus_test exec "$instance" -- sh -c 'echo mutated >/etc/repro/generation'
incus_test stop "$instance"
VMH_INCUS_CMD="$vmh_env" "$vm_harness" snapshot restore \
  --backend incus "$instance" generation-clean
incus_test start "$instance"
deadline=$((SECONDS + 60))
until incus_test exec "$instance" -- true >/dev/null 2>&1; do
  (( SECONDS < deadline )) || exit 1
  sleep 1
done
restored="$(incus_test exec "$instance" -- cat /etc/repro/generation | tr -d '\r')"
test "$restored" = "$generation"

echo "ReproOS Incus lifecycle, SSH, snapshot, and cleanup: PASS"
