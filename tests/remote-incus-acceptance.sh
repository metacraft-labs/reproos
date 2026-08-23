#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: remote-incus-acceptance.sh URL GENERATION KEY_ID WORK_DIR TAG" >&2
  exit 2
fi

base_url="$1"
generation="$2"
key_id="$3"
work_dir="$4"
tag="$5"
project="ra-${tag:0:12}"
network="rn-${tag:0:10}"
storage="rs-${tag:0:10}"
server="server"
client="client"
alias="$generation"

die() {
  echo "remote ReproOS Incus acceptance: $*" >&2
  exit 1
}

[[ "$generation" =~ ^[0-9a-f]{64}$ ]] || die "invalid generation"
[[ "$tag" =~ ^[0-9a-f]{16}$ ]] || die "invalid resource tag"
[[ "$work_dir" == "/var/tmp/reproos-incus-acceptance-$tag" ]] || \
  die "unsafe work directory"
for tool in incus python3; do
  command -v "$tool" >/dev/null || die "remote tool is missing: $tool"
done
grep -Eq '^root:[0-9]+:[1-9][0-9]*$' /etc/subuid || \
  die "root has no subordinate UID range; configure /etc/subuid and restart Incus"
grep -Eq '^root:[0-9]+:[1-9][0-9]*$' /etc/subgid || \
  die "root has no subordinate GID range; configure /etc/subgid and restart Incus"
incus info >/dev/null || die "remote Incus daemon is unavailable"

project_owned() {
  [[ "$(incus project get "$project" user.reproos.acceptance 2>/dev/null || true)" == "$tag" ]]
}

network_owned() {
  [[ "$(incus network get "$network" user.reproos.project 2>/dev/null || true)" == "$project" ]]
}

storage_owned() {
  [[ "$(incus storage get "$storage" user.reproos.project 2>/dev/null || true)" == "$project" ]]
}

cleanup() {
  set +e
  if incus project show "$project" >/dev/null 2>&1 && project_owned; then
    for instance in "$server" "$client"; do
      if [[ "$(incus --project "$project" config get "$instance" \
          user.reproos.acceptance 2>/dev/null || true)" == "$tag" ]]; then
        incus --project "$project" delete --force "$instance" >/dev/null 2>&1
      fi
    done
    while IFS= read -r fingerprint; do
      [[ -n "$fingerprint" ]] && \
        incus --project "$project" image delete "$fingerprint" >/dev/null 2>&1
    done < <(incus --project "$project" image list --format csv -c f 2>/dev/null)
    incus project delete "$project" >/dev/null 2>&1
  fi
  if incus network show "$network" >/dev/null 2>&1 && network_owned; then
    incus network delete "$network" >/dev/null 2>&1
  fi
  if incus storage show "$storage" >/dev/null 2>&1 && storage_owned; then
    incus storage delete "$storage" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

incus project create "$project" \
  -c features.images=true \
  -c features.networks=false \
  -c features.profiles=true \
  -c features.storage.volumes=true \
  -c user.reproos.acceptance="$tag"
incus storage create "$storage" dir user.reproos.project="$project"
incus --project "$project" profile show default >/dev/null 2>&1 || \
  incus --project "$project" profile create default
incus --project "$project" profile device add default root disk \
  path=/ pool="$storage"
incus network create "$network" --type=bridge \
  ipv4.address=auto ipv4.nat=true ipv6.address=none \
  user.reproos.project="$project"
incus --project "$project" profile device add default eth0 nic \
  network="$network" name=eth0

gateway_cidr="$(incus network get "$network" ipv4.address)"
gateway="${gateway_cidr%/*}"
prefix_length="${gateway_cidr#*/}"
network_prefix="${gateway%.*}"
[[ "$gateway" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
  die "Incus did not allocate an IPv4 bridge"
server_ip="$network_prefix.2"
client_ip="$network_prefix.3"

python3 "$work_dir/pull.py" pull \
  --base-url "$base_url" \
  --generation "$generation" \
  --trusted-key "$work_dir/trusted-key.pub" \
  --key-id "$key_id" \
  --project "$project" \
  --output-dir "$work_dir/download"

for spec in "$server:$server_ip" "$client:$client_ip"; do
  name="${spec%%:*}"
  address="${spec#*:}"
  incus --project "$project" init "$alias" "$name"
  incus --project "$project" config set "$name" \
    user.reproos.acceptance="$tag" \
    environment.REPROOS_INCUS_IPV4="$address/$prefix_length" \
    environment.REPROOS_INCUS_GATEWAY="$gateway"
  incus --project "$project" config device override "$name" eth0 \
    ipv4.address="$address"
  incus --project "$project" start "$name"
done

wait_healthy() {
  local instance="$1"
  local attempt
  for attempt in $(seq 1 120); do
    if incus --project "$project" exec "$instance" -- \
        /usr/bin/busybox test -s /run/reproos/healthy 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  incus --project "$project" console "$instance" --show-log >&2 || true
  return 1
}

wait_healthy "$server" || die "server did not become healthy"
wait_healthy "$client" || die "client did not become healthy"
for instance in "$server" "$client"; do
  selected="$(incus --project "$project" exec "$instance" -- \
    /usr/bin/busybox cat /etc/repro/generation)"
  [[ "$selected" == "$generation" ]] || die "$instance selected $selected"
  incus --project "$project" exec "$instance" -- \
    /usr/bin/systemctl is-active sshd.service >/dev/null || \
    die "$instance SSH service is unhealthy"
done

incus --project "$project" exec "$server" -- /usr/bin/busybox sh -c \
  'mkdir -p /run/reproos/http; printf "generation=%s\nserver=server\n" "$1" > /run/reproos/http/response; /usr/bin/busybox httpd -p 8080 -h /run/reproos/http' \
  sh "$generation"
incus --project "$project" exec "$client" -- \
  /usr/bin/busybox ping -c 1 -W 2 "$server_ip" >/dev/null || \
  die "peer address is unreachable"
response="$(incus --project "$project" exec "$client" -- \
  /usr/bin/busybox wget -T 5 -qO- "http://$server_ip:8080/response")"
expected="$(printf 'generation=%s\nserver=server' "$generation")"
[[ "$response" == "$expected" ]] || die "application response differs"
if incus --project "$project" exec "$client" -- \
    /usr/bin/busybox wget -T 2 -qO- "http://$server_ip:8081/" >/dev/null 2>&1; then
  die "undeclared application port 8081 is reachable"
fi

host_os="$(. /etc/os-release; printf '%s' "$PRETTY_NAME")"
incus_version="$(incus version | awk -F': ' '/Server version/ {print $2}')"
printf 'remote_host=%s\nincus_server=%s\ngeneration=%s\nnetwork_response=verified\n' \
  "$host_os" "$incus_version" "$generation"
