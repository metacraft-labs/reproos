#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${REPROOS_INCUS_TEST_TAG:-$$}"
project="reproos-test-$tag"
instance="reproos-test-$tag"
network="ro-${tag:0:12}"
output="$repo_root/build/test-incus-$tag"
tool="$repo_root/tools/reproos-incus.sh"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }
incus_test() { "${incus_cmd[@]}" --project "$project" "$@"; }
vmh_env="${incus_cmd[*]} --project $project"
vmh_instance() {
  VMH_INCUS_CMD="$vmh_env" "$vm_harness" instance "$@" --backend incus
}
vmh_exec() {
  vmh_instance exec "$instance" -- "$@"
}
wait_for_reboot() {
  local previous_boot_id=$1
  local deadline=$((SECONDS + 120))
  local boot_id=""
  while (( SECONDS < deadline )); do
    boot_id="$(vmh_exec cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r' || true)"
    if [[ -n "$boot_id" && "$boot_id" != "$previous_boot_id" ]]; then
      vmh_instance wait "$instance"
      return 0
    fi
    sleep 1
  done
  echo "ReproOS container did not complete a distinct reboot" >&2
  return 1
}

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
"${incus_cmd[@]}" monitor --type=lifecycle >"$output/events.log" 2>&1 &
events_pid=$!
incus_global list --project default --format csv -c n | sort >"$output/default-instances.before"
incus_global image list --project default --format csv -c f | sort >"$output/default-images.before"
incus_global network list --project default --format csv -c n | sort >"$output/default-networks.before"

capture_evidence() {
  incus_test config show "$instance" --expanded >"$output/config.yaml" 2>&1 || true
  incus_test info "$instance" --show-log >"$output/info.log" 2>&1 || true
  incus_test console "$instance" --show-log >"$output/console.log" 2>&1 || true
  incus_test list "$instance" --format json >"$output/address.json" 2>&1 || true
  incus_global project show "$project" >"$output/project.yaml" 2>&1 || true
  vmh_exec journalctl -b --no-pager >"$output/journal.log" 2>&1 || true
  vmh_exec cat /etc/repro/generation >"$output/generation.txt" 2>&1 || true
}
cleanup() {
  local status=$?
  if kill -0 "$events_pid" >/dev/null 2>&1; then
    kill "$events_pid" >/dev/null 2>&1 || true
    wait "$events_pid" >/dev/null 2>&1 || true
  fi
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
  incus_global network list --project default --format csv -c n | sort >"$output/default-networks.after"
  cmp "$output/default-instances.before" "$output/default-instances.after"
  cmp "$output/default-images.before" "$output/default-images.after"
  cmp "$output/default-networks.before" "$output/default-networks.after"
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
until vmh_exec test -s /run/reproos/healthy >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "ReproOS container did not reach its health marker" >&2
    exit 1
  fi
  sleep 1
done

vmh_exec /usr/bin/busybox grep -Fx REPROOS_INCUS_HEALTH:PASS /run/reproos/healthy
test "$(vmh_exec hostname | tr -d '\r')" = reproos-smoke
vmh_exec test -s /etc/repro/system.nim
vmh_exec test -s /etc/repro/hardware.nim
vmh_exec test -s /etc/repro/home.nim
vmh_exec /usr/bin/busybox grep -Fq '"kind": "incus-system-container"' /etc/repro/realization.json
vmh_exec test ! -e /boot/vmlinuz
vmh_exec systemctl is-active sshd.service
vmh_exec systemctl is-active reproos-incus-network.service
vmh_exec systemctl is-active reproos-container-health.service

key="$output/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -f "$key"
vmh_exec mkdir -p /home/repro/.ssh
vmh_instance copy-to "$instance" "$key.pub" /tmp/repro-authorized-key
vmh_exec /usr/bin/busybox sh -c \
  'cp /tmp/repro-authorized-key /home/repro/.ssh/authorized_keys; chown -R 1000:1000 /home/repro/.ssh; chmod 0600 /home/repro/.ssh/authorized_keys'

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

VMH_INCUS_CMD="$vmh_env" "$vm_harness" snapshot create \
  --backend incus "$instance" generation-clean >/dev/null
vmh_exec touch /var/lib/reproos/snapshot-probe
vmh_instance stop "$instance"
VMH_INCUS_CMD="$vmh_env" "$vm_harness" snapshot restore \
  --backend incus "$instance" generation-clean
vmh_instance start "$instance"
vmh_exec test ! -e /var/lib/reproos/snapshot-probe

generation="$(vmh_exec /usr/sbin/reproos-generation current | tr -d '\r')"
next_generation="acceptance-$tag"
vmh_exec rm -rf /tmp/repro-next-generation
vmh_exec mkdir -p /tmp/repro-next-generation
vmh_exec cp -a /etc/repro/. /tmp/repro-next-generation/
vmh_exec chmod -R u+w /tmp/repro-next-generation
vmh_exec /usr/bin/busybox sh -c \
  "echo '$next_generation' > /tmp/repro-next-generation/generation; echo '# lifecycle-generation-$tag' >> /tmp/repro-next-generation/system.nim"
vmh_exec /usr/sbin/reproos-generation stage \
  "$next_generation" /tmp/repro-next-generation
vmh_exec /usr/sbin/reproos-generation switch "$next_generation"
test "$(vmh_exec /usr/sbin/reproos-generation current | tr -d '\r')" = "$next_generation"
vmh_exec /usr/bin/busybox grep -Fq "lifecycle-generation-$tag" /etc/repro/system.nim

boot_id="$(vmh_exec cat /proc/sys/kernel/random/boot_id | tr -d '\r')"
vmh_exec systemctl reboot >/dev/null 2>&1 || true
wait_for_reboot "$boot_id"
vmh_exec /usr/bin/busybox grep -Fx "generation=$next_generation" /run/reproos/healthy
test "$(vmh_exec /usr/sbin/reproos-generation current | tr -d '\r')" = "$next_generation"

vmh_exec /usr/sbin/reproos-generation rollback
test "$(vmh_exec /usr/sbin/reproos-generation current | tr -d '\r')" = "$generation"
boot_id="$(vmh_exec cat /proc/sys/kernel/random/boot_id | tr -d '\r')"
vmh_exec systemctl reboot >/dev/null 2>&1 || true
wait_for_reboot "$boot_id"
vmh_exec /usr/bin/busybox grep -Fx "generation=$generation" /run/reproos/healthy
if vmh_exec /usr/bin/busybox grep -Fq \
    "lifecycle-generation-$tag" /etc/repro/system.nim; then
  echo "rolled-back generation still contains the staged marker" >&2
  exit 1
fi

ssh -i "$key" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15 \
  "repro@$ip" "test \"\$(cat /etc/repro/generation)\" = '$generation'"

echo "ReproOS Incus lifecycle, SSH, generation rollback, reboot, snapshot, and cleanup: PASS"
