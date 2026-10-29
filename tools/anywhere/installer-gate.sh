#!/bin/sh
# ReproOS Anywhere installer gate: the controller's ONLY entry into the
# takeover environment (M2 confinement, MS-1 CONF/FLOW).
#
# sshd runs this as a forced command for the controller's per-plan key
# (authorized_keys: restrict,command="..."). It accepts one request from a
# fixed vocabulary in $SSH_ORIGINAL_COMMAND, validates every argument
# against a closed shape and a path allowlist, and runs nothing else: no
# shell, no interpolation, no PATH lookup outside the verified closure.
# A refused request is printed to the console -- the rescue plane -- and
# exits 126.
#
# Paths the controller may write: the installer's work area and the
# mounted target. Paths it may read back: the same, plus the installer
# identity and kernel facts it verifies.
set -f
set -u
IFS=' '

refuse() {
  # Through the kernel log, not straight to /dev/console: the kernel prints
  # each record whole, so the refusal cannot be split by the audit records
  # this very request produced.
  { echo "<4>REPROOS_ANYWHERE_GATE:REFUSED $*" > /dev/kmsg; } 2>/dev/null \
    || echo "REPROOS_ANYWHERE_GATE:REFUSED $*" > /dev/console 2>/dev/null
  echo "gate: refused: $*" >&2
  exit 126
}

# As a forced command the request is in $SSH_ORIGINAL_COMMAND; run as the
# `anywhere-gate` command (a build without the forced-command control) it is
# in the arguments. The controller always sends "anywhere-gate VERB ...".
req=${SSH_ORIGINAL_COMMAND:-$*}
req=${req#anywhere-gate }
case "$req" in
  *[!A-Za-z0-9\ /._:=+,@-]*|'') refuse "characters outside the request alphabet" ;;
esac
# shellcheck disable=SC2086 -- word splitting on the validated alphabet is the parser
set -- $req
verb=$1
shift

hex() { case "$1" in ''|*[!0-9a-f]*) refuse "$verb: not hex: $1" ;; esac; }
name() { case "$1" in ''|*[!a-z0-9]*) refuse "$verb: not a block device name: $1" ;; esac; }
octal() { case "$1" in 0[0-7][0-7][0-7]) ;; *) refuse "$verb: bad mode $1" ;; esac; }

# A path the controller may write or remove: under the work area or the
# mounted target, never containing "..". The check is made on the path as
# given AND on the path with every symlink resolved: the unpacked target
# root carries absolute symlinks, which resolve against the INSTALLER's
# root, so a string check alone would let /mnt/<link>/x land outside.
resolved() { realpath -m -- "$1" 2>/dev/null || echo /unresolvable; }
writable() {
  for p in "$1" "$(resolved "$1")"; do
    case "$p" in
      *..*) refuse "$verb: path traversal: $1" ;;
      /run/anywhere/work/*|/run/anywhere/ops/*|/mnt/*) ;;
      *) refuse "$verb: path outside the writable area: $1 (resolves to $p)" ;;
    esac
  done
}
readable() {
  for p in "$1" "$(resolved "$1")"; do
    case "$p" in
      *..*) refuse "$verb: path traversal: $1" ;;
      /run/anywhere/*|/mnt/*|/proc/cmdline|/proc/self/mounts) ;;
      *) refuse "$verb: path outside the readable area: $1 (resolves to $p)" ;;
    esac
  done
}
argc() { [ "$#" -eq "$want" ] || refuse "$verb: wants $want argument(s)"; }
# The kernel's partition naming: sda -> sda1, nvme0n1 -> nvme0n1p1.
part() { case "$1" in *[0-9]) echo "/dev/${1}p$2" ;; *) echo "/dev/$1$2" ;; esac; }
disk_serial() {
  s=$(cat "/sys/block/$1/serial" 2>/dev/null || cat "/sys/block/$1/device/serial" 2>/dev/null)
  [ -n "$s" ] || s=$(tail -c +5 "/sys/block/$1/device/vpd_pg80" 2>/dev/null | tr -d '\000')
  printf '%s' "$s" | sed 's/^ *//; s/ *$//'
}

case "$verb" in
  identity)  want=0; argc "$@"; exec cat /run/anywhere/identity ;;
  cmdline)   want=0; argc "$@"; exec cat /proc/cmdline ;;
  mounts)    want=0; argc "$@"; exec cat /proc/self/mounts ;;
  store)     want=0; argc "$@"; exec ls /nix/store ;;
  sync)      want=0; argc "$@"; exec sync ;;
  barrier)   want=1; argc "$@"; hex "$1"; exec sh -c : "anywhere-barrier-$1" ;;
  read)      want=1; argc "$@"; readable "$1"; exec cat -- "$1" ;;
  size)      want=1; argc "$@"; writable "$1"; [ -e "$1" ] || { echo 0; exit 0; }; exec stat -c %s -- "$1" ;;
  sha256)    want=1; argc "$@"; readable "$1"; exec sha256sum -- "$1" ;;
  exists)    want=1; argc "$@"; readable "$1"; [ -e "$1" ] && echo yes || echo no; exit 0 ;;
  remove)    want=1; argc "$@"; writable "$1"; exec rm -f -- "$1" ;;
  mkdir)     want=1; argc "$@"; writable "$1"; exec mkdir -p -- "$1" ;;
  put)       want=2; argc "$@"; writable "$1"; octal "$2"
             mkdir -p -- "$(dirname -- "$1")" && umask 077 && cat > "$1" && chmod "$2" -- "$1"; exit $? ;;
  append)    want=1; argc "$@"; writable "$1"
             mkdir -p -- "$(dirname -- "$1")" && exec cat >> "$1" ;;
  sysblock)  want=1; argc "$@"; name "$1"; exec readlink "/sys/block/$1" ;;
  serial)    want=1; argc "$@"; name "$1"
             printf '%s\n%s\n' "$(disk_serial "$1")" "$(cat "/sys/block/$1/size")"; exit 0 ;;
  partitions) want=1; argc "$@"; name "$1"; exec ls "/sys/block/$1" ;;
  probe)     want=1; argc "$@"; name "$1"; blkid -p "/dev/$1"; echo "rc=$?"; exit 0 ;;
  labels)    want=1; argc "$@"; name "$1"
             exec blkid -o export "$(part "$1" 1)" "$(part "$1" 2)" ;;
  unpack)    want=0; argc "$@"
             cd /mnt && zstd -dc .anywhere/rootfs.tar.zst | tar -xpf - --numeric-owner \
               && rm -rf /mnt/.anywhere && sync; exit $? ;;
  target-facts) want=0; argc "$@"
             echo "generation=$(cat /mnt/etc/repro/generation 2>/dev/null)"
             echo "os_id=$( (. /mnt/etc/os-release && echo "$ID") 2>/dev/null)"; exit 0 ;;
  boot-facts) want=1; argc "$@"; name "$1"
             [ -s /mnt/boot/EFI/BOOT/BOOTX64.EFI ] && echo efi
             grep -c "root=$(part "$1" 2)" /mnt/boot/grub/grub.cfg
             sha256sum /mnt/boot/vmlinuz /mnt/boot/initrd.img; exit 0 ;;
  disk)      # the storage broker's idempotent verbs, inline
             case "${1:-}" in resolve|mount|unmount) ;; *) refuse "disk: ${1:-} does not run inline" ;; esac
             exec anywhere_disk "$@" ;;
  op-start)  # a detached, keyed, irreversible broker operation
             op=${1:-}; hex "$op"; shift
             case "${1:-}" in destroy|apply|install-root) ;; *) refuse "op-start: verb ${1:-}" ;; esac
             base=/run/anywhere/ops/$op
             mkdir -p /run/anywhere/ops
             [ -e "$base.args" ] && { echo exists; exit 0; }
             printf '%s\n' "$*" > "$base.args"
             setsid sh -c 'anywhere_disk "$@" > "$0.out" 2> "$0.err"; echo $? > "$0.rc"' "$base" "$@" \
               < /dev/null > /dev/null 2>&1 &
             echo started; exit 0 ;;
  op-forget) # a FAILED operation may be launched again on resume
             want=1; argc "$@"; hex "$1"; base=/run/anywhere/ops/$1
             [ -e "$base.rc" ] && [ "$(cat "$base.rc")" != 0 ] || refuse "op-forget: $1 has not failed"
             exec rm -f -- "$base.args" "$base.rc" "$base.out" "$base.err" ;;
  op-poll)   want=1; argc "$@"; hex "$1"; base=/run/anywhere/ops/$1
             [ -e "$base.rc" ] || exit 0
             echo "rc=$(cat "$base.rc")"; cat "$base.out"; cat "$base.err" >&2; exit 0 ;;
  reboot)    want=0; argc "$@"; sync; ( sleep 1; sync; reboot -f ) > /dev/null 2>&1 & exit 0 ;;
  *)         refuse "unknown verb $verb" ;;
esac
