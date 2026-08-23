#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${REPROOS_INCUS_IMAGE:-$repo_root/recipes/reproos-container/build/reproos-incus.tar.xz}"
bundle_dir="$(dirname "$image")"
project="${REPROOS_INCUS_PROJECT:-reproos-dev}"
network="${REPROOS_INCUS_NETWORK:-reproos0}"
instance="${REPROOS_INCUS_INSTANCE:-reproos-dev}"
alias="${REPROOS_INCUS_ALIAS:-reproos-incus}"
vm_harness="${VM_HARNESS_BIN:-vm-harness}"
read -r -a incus_cmd <<<"${VMH_INCUS_CMD:-incus}"

incus_global() { "${incus_cmd[@]}" "$@"; }
incus_project() { "${incus_cmd[@]}" --project "$project" "$@"; }

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
  if ! incus_global project show "$project" >/dev/null 2>&1; then
    incus_global project create "$project" \
      -c features.images=true \
      -c features.networks=true \
      -c features.profiles=true
  fi
  incus_project profile show default >/dev/null 2>&1 || \
    incus_project profile create default
  if ! incus_project profile device show default | grep -q '^root:'; then
    incus_project profile device add default root disk path=/ pool=default
  fi
  if ! incus_project network show "$network" >/dev/null 2>&1; then
    incus_project network create "$network" --type=bridge \
      ipv4.address=auto ipv4.nat=true ipv6.address=none
  fi
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
  echo "launched $instance in Incus project $project"
}

destroy() {
  if incus_global project show "$project" >/dev/null 2>&1; then
    if incus_project list "$instance" --format csv -c n | grep -Fxq "$instance"; then
      VMH_INCUS_CMD="${incus_cmd[*]} --project $project" \
        "$vm_harness" ephemeral-destroy --backend incus \
          --baseline "$instance" --base-image "$alias"
    fi
    if incus_project profile device show default 2>/dev/null | grep -q '^eth0:'; then
      incus_project profile device remove default eth0
    fi
    if incus_project network show "$network" >/dev/null 2>&1; then
      incus_project network delete "$network"
    fi
    local fingerprint
    fingerprint="$(incus_project image list "$alias" --format csv -c f | head -n1)"
    if [[ -n "$fingerprint" ]]; then
      incus_project image delete "$fingerprint"
    fi
    incus_global project delete "$project"
  fi
  echo "destroyed Incus project $project"
}

usage() {
  echo "usage: reproos-incus.sh {import|launch|shell|logs|destroy}" >&2
  exit 2
}

require_host
case "${1:-}" in
  import)
    setup_project
    import_image
    ;;
  launch)
    launch
    ;;
  shell)
    incus_project exec "$instance" -- su -l repro
    ;;
  logs)
    incus_project console "$instance" --show-log || true
    incus_project exec "$instance" -- journalctl -b --no-pager
    ;;
  destroy)
    destroy
    ;;
  *) usage ;;
esac
