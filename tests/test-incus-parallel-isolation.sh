#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${REPROOS_INCUS_PARALLEL_TAG:-$$}"
tool="$repo_root/tools/reproos-incus.sh"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
output="$repo_root/build/test-incus-parallel-$tag"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }

project_for() { printf 'reproos-par-%s-%s\n' "$1" "$tag"; }
instance_for() { project_for "$1"; }
network_for() { printf 'r%s-%s\n' "$1" "${tag:0:11}"; }
storage_for() { printf 'reproos-par-%s-storage-%s\n' "$1" "$tag"; }

if ! command -v "${incus_cmd[0]}" >/dev/null ||
   ! incus_global info >/dev/null 2>&1; then
  echo "[skip] ReproOS parallel Incus isolation: Incus daemon unavailable"
  exit 0
fi
if ! command -v "$vm_harness" >/dev/null; then
  echo "vm-harness is required for the parallel Incus isolation gate" >&2
  exit 1
fi

mkdir -p "$output"

destroy_one() {
  local suffix=$1
  REPROOS_INCUS_PROJECT="$(project_for "$suffix")" \
  REPROOS_INCUS_INSTANCE="$(instance_for "$suffix")" \
  REPROOS_INCUS_NETWORK="$(network_for "$suffix")" \
  REPROOS_INCUS_STORAGE="$(storage_for "$suffix")" \
  VM_HARNESS_BIN="$vm_harness" \
    bash "$tool" destroy >"$output/destroy-$suffix.log" 2>&1
}

cleanup() {
  local failed=0 suffix
  for suffix in a b; do
    destroy_one "$suffix" || failed=1
  done
  for suffix in a b; do
    if incus_global project show "$(project_for "$suffix")" >/dev/null 2>&1 ||
       incus_global network show "$(network_for "$suffix")" >/dev/null 2>&1 ||
       incus_global storage show "$(storage_for "$suffix")" >/dev/null 2>&1; then
      echo "parallel Incus resource survived cleanup: $suffix" >&2
      failed=1
    fi
  done
  return "$failed"
}

on_exit() {
  local status=$?
  trap - EXIT
  cleanup || status=1
  exit "$status"
}
trap on_exit EXIT

launch_one() {
  local suffix=$1
  REPROOS_INCUS_PROJECT="$(project_for "$suffix")" \
  REPROOS_INCUS_INSTANCE="$(instance_for "$suffix")" \
  REPROOS_INCUS_NETWORK="$(network_for "$suffix")" \
  REPROOS_INCUS_STORAGE="$(storage_for "$suffix")" \
  VM_HARNESS_BIN="$vm_harness" \
    bash "$tool" launch >"$output/launch-$suffix.log" 2>&1
}

launch_one a &
pid_a=$!
launch_one b &
pid_b=$!
launch_failed=0
wait "$pid_a" || launch_failed=1
wait "$pid_b" || launch_failed=1
if [[ "$launch_failed" -ne 0 ]]; then
  cat "$output/launch-a.log" "$output/launch-b.log" >&2
  exit 1
fi

for suffix in a b; do
  project="$(project_for "$suffix")"
  instance="$(instance_for "$suffix")"
  network="$(network_for "$suffix")"
  storage="$(storage_for "$suffix")"
  vmh_env="${incus_cmd[*]} --project $project"

  test "$(incus_global project get "$project" user.reproos.managed)" = true
  test "$(incus_global network get "$network" user.reproos.project)" = "$project"
  test "$(incus_global storage get "$storage" user.reproos.project)" = "$project"
  test "$("${incus_cmd[@]}" --project "$project" profile device get default root pool)" = "$storage"
  test "$("${incus_cmd[@]}" --project "$project" config get "$instance" user.reproos.managed)" = true
  test "$("${incus_cmd[@]}" --project "$project" config get "$instance" user.reproos.project)" = "$project"

  VMH_INCUS_CMD="$vmh_env" "$vm_harness" instance wait \
    --backend incus "$instance"
  deadline=$((SECONDS + 120))
  until VMH_INCUS_CMD="$vmh_env" "$vm_harness" instance exec \
      --backend incus "$instance" -- test -s /run/reproos/healthy \
      >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "parallel Incus instance did not reach health: $instance" >&2
      exit 1
    fi
    sleep 1
  done
  VMH_INCUS_CMD="$vmh_env" "$vm_harness" instance exec \
    --backend incus "$instance" -- \
    /usr/bin/busybox grep -Fx REPROOS_INCUS_HEALTH:PASS /run/reproos/healthy
done

test "$(project_for a)" != "$(project_for b)"
test "$(network_for a)" != "$(network_for b)"
test "$(storage_for a)" != "$(storage_for b)"

echo "ReproOS parallel Incus lifecycle isolation: PASS"
