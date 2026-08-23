#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${REPROOS_INCUS_IMAGE:-$repo_root/recipes/reproos-container/build/reproos-incus.tar.xz}"
bundle_dir="$(dirname "$image")"
project="${REPROOS_INCUS_PROJECT:-reproos-dev}"
network="${REPROOS_INCUS_NETWORK:-reproos0}"
storage="${REPROOS_INCUS_STORAGE:-reproos-storage}"
instance="${REPROOS_INCUS_INSTANCE:-reproos-dev}"
alias="${REPROOS_INCUS_ALIAS:-reproos-incus}"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }
incus_project() { "${incus_cmd[@]}" --project "$project" "$@"; }

validate_resource_names() {
  if [[ -z "$project" || "$project" == "default" ]]; then
    echo "refusing to manage the default Incus project" >&2
    exit 2
  fi
  case "$network" in
    ""|incusbr0|lxdbr0)
      echo "refusing to manage reserved Incus bridge: ${network:-<empty>}" >&2
      exit 2
      ;;
  esac
  if [[ -z "$storage" || "$storage" == "default" ]]; then
    echo "refusing to manage the default Incus storage pool" >&2
    exit 2
  fi
}

require_managed_project() {
  local managed
  managed="$(incus_global project get "$project" user.reproos.managed 2>/dev/null || true)"
  if [[ "$managed" != "true" ]]; then
    echo "refusing to modify unowned Incus project: $project" >&2
    exit 2
  fi
}

require_managed_network() {
  local owner
  owner="$(incus_global network get "$network" user.reproos.project 2>/dev/null || true)"
  if [[ "$owner" != "$project" ]]; then
    echo "refusing to modify unowned Incus network: $network" >&2
    exit 2
  fi
}

require_managed_storage() {
  local owner
  owner="$(incus_global storage get "$storage" user.reproos.project 2>/dev/null || true)"
  if [[ "$owner" != "$project" ]]; then
    echo "refusing to modify unowned Incus storage pool: $storage" >&2
    exit 2
  fi
}

require_managed_instance() {
  local managed owner
  managed="$(incus_project config get "$instance" user.reproos.managed 2>/dev/null || true)"
  owner="$(incus_project config get "$instance" user.reproos.project 2>/dev/null || true)"
  if [[ "$managed" != "true" || "$owner" != "$project" ]]; then
    echo "refusing to modify unowned Incus instance: $instance" >&2
    exit 2
  fi
}

require_host() {
  command -v "${incus_cmd[0]}" >/dev/null || {
    echo "Incus client missing: ${incus_cmd[0]}" >&2
    exit 1
  }
  command -v "$vm_harness" >/dev/null || {
    echo "vm-harness missing: $vm_harness" >&2
    exit 1
  }
  incus_global info >/dev/null
}

setup_project() {
  if (( ${#network} > 15 )); then
    echo "Incus bridge name exceeds the Linux maximum of 15 characters: $network" >&2
    exit 2
  fi
  if ! incus_global project show "$project" >/dev/null 2>&1; then
    incus_global project create "$project" \
      -c features.images=true \
      -c features.networks=false \
      -c features.profiles=true \
      -c features.storage.volumes=true \
      -c user.reproos.managed=true
  else
    require_managed_project
  fi
  incus_project profile show default >/dev/null 2>&1 || \
    incus_project profile create default
  if ! incus_global storage show "$storage" >/dev/null 2>&1; then
    incus_global storage create "$storage" dir \
      user.reproos.project="$project"
  else
    require_managed_storage
  fi
  if ! incus_project profile device show default | grep -q '^root:'; then
    incus_project profile device add default root disk path=/ pool="$storage"
  else
    incus_project profile device set default root pool "$storage"
  fi
  if ! incus_global network show "$network" >/dev/null 2>&1; then
    incus_global network create "$network" --type=bridge \
      ipv4.address=auto ipv4.nat=true ipv6.address=none \
      user.reproos.project="$project"
  else
    require_managed_network
  fi
  local network_cidr gateway network_prefix prefix_length container_ipv4
  network_cidr="$(incus_global network get "$network" ipv4.address)"
  gateway="${network_cidr%/*}"
  network_prefix="${gateway%.*}"
  prefix_length="${network_cidr#*/}"
  container_ipv4="$network_prefix.2/$prefix_length"
  incus_project profile set default \
    environment.REPROOS_INCUS_IPV4="$container_ipv4" \
    environment.REPROOS_INCUS_GATEWAY="$gateway"
  if ! incus_project profile device show default | grep -q '^eth0:'; then
    incus_project profile device add default eth0 nic \
      network="$network" name=eth0
  fi
}

import_image() {
  if [[ ! -s "$image" || ! -s "$bundle_dir/incus-baseline.manifest" ]]; then
    echo "Incus image bundle missing; run: repro build incus-image" >&2
    exit 1
  fi
  if incus_project list "$instance" --format csv -c n | grep -Fxq "$instance"; then
    echo "container $instance is running; destroy it before replacing the image" >&2
    exit 1
  fi
  local fingerprint
  fingerprint="$(incus_project image list "$alias" --format csv -c f | head -n1)"
  if [[ -n "$fingerprint" ]]; then
    incus_project image delete "$fingerprint"
  fi
  VMH_INCUS_CMD="${incus_cmd[*]} --project $project" \
    "$vm_harness" baseline import --backend incus "$bundle_dir" >/dev/null
  incus_project image show "$alias" >/dev/null
  echo "imported $alias into Incus project $project"
}

launch() {
  setup_project
  import_image
  VMH_INCUS_CMD="${incus_cmd[*]} --project $project" \
    "$vm_harness" run --ephemeral --keep --backend incus \
      --baseline "$instance" --base-image "$alias"
  incus_project config set "$instance" user.reproos.managed true
  incus_project config set "$instance" user.reproos.project "$project"
  echo "launched $instance in Incus project $project"
}

destroy() {
  local have_project=0 have_network=0 have_storage=0
  if incus_global project show "$project" >/dev/null 2>&1; then
    have_project=1
    require_managed_project
  fi
  if incus_global network show "$network" >/dev/null 2>&1; then
    have_network=1
    require_managed_network
  fi
  if incus_global storage show "$storage" >/dev/null 2>&1; then
    have_storage=1
    require_managed_storage
  fi
  if [[ "$have_project" -eq 1 ]]; then
    if incus_project list "$instance" --format csv -c n | grep -Fxq "$instance"; then
      require_managed_instance
      VMH_INCUS_CMD="${incus_cmd[*]} --project $project" \
        "$vm_harness" ephemeral-destroy --backend incus \
          --baseline "$instance" --base-image "$alias"
    fi
    if incus_project profile device show default 2>/dev/null | grep -q '^eth0:'; then
      incus_project profile device remove default eth0
    fi
    if [[ "$have_network" -eq 1 ]]; then
      incus_global network delete "$network"
      have_network=0
    fi
    local fingerprint
    fingerprint="$(incus_project image list "$alias" --format csv -c f | head -n1)"
    if [[ -n "$fingerprint" ]]; then
      incus_project image delete "$fingerprint"
    fi
    incus_global project delete "$project"
  fi
  if [[ "$have_network" -eq 1 ]]; then
    incus_global network delete "$network"
  fi
  if [[ "$have_storage" -eq 1 ]]; then
    incus_global storage delete "$storage"
  fi
  echo "destroyed Incus project $project"
}

usage() {
  echo "usage: reproos-incus.sh {import|launch|shell|logs|destroy}" >&2
  exit 2
}

require_host
validate_resource_names
case "${1:-}" in
  import)
    setup_project
    import_image
    ;;
  launch)
    launch
    ;;
  shell)
    require_managed_project
    require_managed_instance
    incus_project exec "$instance" -- su -l repro
    ;;
  logs)
    require_managed_project
    require_managed_instance
    incus_project console "$instance" --show-log || true
    incus_project exec "$instance" -- journalctl -b --no-pager
    ;;
  destroy)
    destroy
    ;;
  *) usage ;;
esac
