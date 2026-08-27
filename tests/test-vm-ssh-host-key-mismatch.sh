#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state_dir=${REPROOS_VM_STATE_DIR:-$repo_root/build/e2e-unattended-vm}
known_hosts="$state_dir/ssh_known_hosts"
accepted_known_hosts="$state_dir/ssh_known_hosts.accepted"
fake_key_dir=$(mktemp -d "$state_dir/fake-host-key.XXXXXX")

restore_host_identity() {
  if test -s "$accepted_known_hosts"; then
    mv -f "$accepted_known_hosts" "$known_hosts"
  fi
  rm -rf "$fake_key_dir"
}
trap restore_host_identity EXIT

test -s "$state_dir/install-manifest.json"
test -s "$known_hosts"
cp -f "$known_hosts" "$accepted_known_hosts"
ssh-keygen -q -t ed25519 -N '' -f "$fake_key_dir/id_ed25519"
read -r fake_key_type fake_key_blob _ < "$fake_key_dir/id_ed25519.pub"
host_key_alias=$(python3 -c \
  'import json, sys; print(json.load(open(sys.argv[1]))["ssh_host_key_alias"])' \
  "$state_dir/install-manifest.json")
printf '%s %s %s\n' "$host_key_alias" "$fake_key_type" "$fake_key_blob" \
  > "$known_hosts"

if python3 "$repo_root/tools/reproos-vm.py" ssh \
    --state-dir "$state_dir" -- true \
    > "$state_dir/host-key-mismatch.log" 2>&1; then
  printf 'changed SSH host key was accepted\n' >&2
  exit 1
fi

if ! grep -Eiq \
    'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed|host key.*(changed|mismatch)' \
    "$state_dir/host-key-mismatch.log"; then
  cat "$state_dir/host-key-mismatch.log" >&2
  printf 'SSH probe failed for an unexpected VM failure\n' >&2
  exit 1
fi

printf 'changed SSH host key: rejected\n'
