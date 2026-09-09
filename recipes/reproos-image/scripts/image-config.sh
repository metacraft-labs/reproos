# shellcheck shell=bash
# image-config.sh -- the one reader of a validated auto-config.toml.
#
# Sourced, never executed. It exists because the image is now built by
# TWO actions rather than one, and both have to read the same answers
# out of the same document:
#
#   * scripts/configure-installed-root.sh, which turns a mirrored root
#     tree into the installed root -- hostname, accounts, services,
#     desktop -- and runs BEFORE the root image is made;
#   * scripts/build-reproos-image.sh, which partitions a disk and
#     installs that root onto it.
#
# Two copies of this parsing would be two answers to "what user does
# this image have", and the second answer would be the one nobody
# tested. There is one.
#
# The values are read out of the CANONICAL bundle the installer emits
# (`reproos-installer --emit-artifacts`), not out of the operator's
# hand-written file: the installer owns schema validation and
# normalisation, so everything below is already known to be well formed
# and this parser only has to find it.
#
# Usage:
#   . "$SCRIPT_DIR/image-config.sh"
#   reproos_load_image_config "$CONFIG_BUNDLE_DIR/auto-config.toml" || exit 66
#
# On success the caller's shell carries:
#   HOSTNAME_VAL USER_NAME USER_FULL_NAME USER_PWHASH USER_LOCKED
#   USER_SHELL USER_SHADOW USER_GROUPS USER_GROUPS_SPACED
#   USER_UID USER_GID USER_HOME
#   DISK_SIZE_GB DISK_TYPE ESP_SIZE_MIB DE_DEFAULT NET_IPV4
#
# `reproos_load_image_config` returns 1 (having written a diagnostic to
# stderr) when the document does not describe an image that can be
# built. Callers map that onto their own exit code, because the two
# callers have different exit-code tables.

toml_get() {
  # toml_get <file> <section> <key>
  # Returns the value for [section] key on stdout, or empty if not
  # present.  Strips surrounding quotes from string values.  Supports
  # only flat keys + [section]subsection blocks.
  awk -v section="$2" -v key="$3" '
    BEGIN { cur=""; }
    /^[[:space:]]*#/ { next; }
    /^[[:space:]]*$/ { next; }
    /^[[:space:]]*\[.*\][[:space:]]*$/ {
      gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "");
      cur=$0;
      next;
    }
    {
      line=$0;
      sub(/[[:space:]]*#.*$/, "", line);
      n=split(line, kv, "=");
      if (n<2) next;
      k=kv[1];
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", k);
      v=kv[2];
      for (i=3;i<=n;i++) v=v"="kv[i];
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v);
      gsub(/^"|"$/, "", v);
      gsub(/^'\''|'\''$/, "", v);
      if (cur == section && k == key) { print v; exit; }
    }
  ' "$1"
}

reproos_load_image_config() {
  # ``CFG`` is set here rather than taken as a local, because it is the
  # name every caller already uses for "the validated config document"
  # and later phases read it directly.
  CFG="$1"
  if [ ! -s "$CFG" ]; then
    echo "[image-config] validated config missing or empty: $CFG" >&2
    return 1
  fi

  HOSTNAME_VAL="$(toml_get "$CFG" "" "hostname")"
  USER_NAME="$(toml_get "$CFG" "user" "name")"
  USER_FULL_NAME="$(toml_get "$CFG" "user" "full_name")"
  USER_PWHASH="$(toml_get "$CFG" "user" "password_hash")"
  USER_LOCKED="$(toml_get "$CFG" "user" "locked")"
  USER_SHELL="$(toml_get "$CFG" "user" "shell")"
  DISK_SIZE_GB="$(toml_get "$CFG" "disk" "size_gb")"
  DISK_TYPE="$(toml_get "$CFG" "disk.layout" "type")"
  ESP_SIZE_MIB="$(toml_get "$CFG" "disk.layout" "esp_size_mib")"
  DE_DEFAULT="$(toml_get "$CFG" "de" "default")"
  NET_IPV4="$(toml_get "$CFG" "network" "ipv4")"

  # Defaults / validation.
  HOSTNAME_VAL="${HOSTNAME_VAL:-reproos}"
  USER_NAME="${USER_NAME:-repro}"
  USER_FULL_NAME="${USER_FULL_NAME:-$USER_NAME}"
  USER_SHELL="${USER_SHELL:-/bin/bash}"
  DISK_SIZE_GB="${DISK_SIZE_GB:-8}"
  DISK_TYPE="${DISK_TYPE:-uefi-ext4}"
  ESP_SIZE_MIB="${ESP_SIZE_MIB:-512}"
  DE_DEFAULT="${DE_DEFAULT:-sway}"
  NET_IPV4="${NET_IPV4:-dhcp}"

  case "$USER_LOCKED:$USER_PWHASH" in
    true:) USER_SHADOW='!' ;;
    :\$6\$*) USER_SHADOW="$USER_PWHASH" ;;
    *)
      echo "[image-config] [user] requires locked=true or a SHA-512 password_hash" >&2
      return 1
      ;;
  esac

  case "$DE_DEFAULT" in
    sway|kwin|mutter|plasmashell|sddm) ;;
    *) echo "[image-config] unsupported [de].default: $DE_DEFAULT" >&2
       return 1 ;;
  esac

  # Parse the TOML ``[user] groups`` array.  toml_get returns the raw
  # ``[wheel, audio, video]`` text; strip the brackets, quotes and
  # spaces so the result is a comma-separated list, and keep a
  # space-separated spelling for the ``for`` loops that iterate it.
  USER_GROUPS_RAW="$(toml_get "$CFG" "user" "groups" || true)"
  USER_GROUPS_RAW="${USER_GROUPS_RAW:-[wheel, audio, video]}"
  USER_GROUPS="$(echo "$USER_GROUPS_RAW" | sed -E 's/^\[//; s/\]$//; s/"//g; s/ //g')"
  # An explicitly EMPTY array stays empty. Defaulting it to `wheel` here
  # would silently give an account administrative rights the document
  # asked for it not to have, and this reader's job is to report what the
  # validated document says rather than to have an opinion about it.
  USER_GROUPS_SPACED="$(echo "$USER_GROUPS" | tr ',' ' ')"

  # Pinned to 1000/1000 (first non-system id per LSB); the primary
  # group matches $USER_NAME.
  USER_UID=1000
  USER_GID=1000
  USER_HOME="/home/$USER_NAME"

  return 0
}
