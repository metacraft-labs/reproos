#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pull_tool="$repo_root/tools/reproos-incus-publication.py"
remote_test="$repo_root/tests/remote-incus-acceptance.sh"
trusted_key="${REPROOS_INCUS_TRUSTED_KEY:-}"
base_url="${REPROOS_INCUS_PUBLICATION_URL:-}"
generation="${REPROOS_INCUS_GENERATION:-}"
key_id="${REPROOS_INCUS_SIGNING_KEY_ID:-reproos-release}"
transport="${REPROOS_INCUS_SECOND_HOST_SSH:-}"

die() {
  echo "ReproOS second-host Incus acceptance: $*" >&2
  exit 2
}

[[ -n "$transport" ]] || die \
  "set REPROOS_INCUS_SECOND_HOST_SSH to an SSH command ending in the host"
[[ -n "$base_url" ]] || die "set REPROOS_INCUS_PUBLICATION_URL"
[[ -n "$generation" ]] || die "set REPROOS_INCUS_GENERATION"
[[ "$generation" =~ ^[0-9a-f]{64}$ ]] || die "generation must be a SHA-256 digest"
[[ "$key_id" =~ ^[A-Za-z0-9][A-Za-z0-9._@+-]*$ ]] || die "invalid signing key ID"
[[ -f "$trusted_key" ]] || die "trusted public key is missing: $trusted_key"
[[ -f "$pull_tool" && -f "$remote_test" ]] || die "acceptance inputs are missing"
read -r -a ssh_command <<<"$transport"
(( ${#ssh_command[@]} > 1 )) || die "SSH transport must include a destination host"

tag="$(printf '%08x%08x' "$RANDOM" "$$")"
remote_dir="/var/tmp/reproos-incus-acceptance-$tag"
case "$remote_dir" in
  /var/tmp/reproos-incus-acceptance-[0-9a-f]*) ;;
  *) die "unsafe remote work directory" ;;
esac

remote_cleanup() {
  "${ssh_command[@]}" "rm -rf '$remote_dir'" >/dev/null 2>&1 || true
}
trap remote_cleanup EXIT

"${ssh_command[@]}" "install -d -m 0700 '$remote_dir'"
"${ssh_command[@]}" "cat > '$remote_dir/pull.py'" <"$pull_tool"
"${ssh_command[@]}" "cat > '$remote_dir/acceptance.sh'" <"$remote_test"
"${ssh_command[@]}" "cat > '$remote_dir/trusted-key.pub'" <"$trusted_key"
"${ssh_command[@]}" \
  "chmod 0700 '$remote_dir/acceptance.sh'; chmod 0600 '$remote_dir/trusted-key.pub'"

printf -v remote_command '%q ' \
  "$remote_dir/acceptance.sh" \
  "$base_url" \
  "$generation" \
  "$key_id" \
  "$remote_dir" \
  "$tag"
"${ssh_command[@]}" "$remote_command"

echo "ReproOS second-host Incus acceptance: PASS"
