#!/bin/busybox sh
# ReproOS Anywhere takeover environment: /init.
#
# FIXTURE BUILD. The installer this init runs in is assembled from
# nixpkgs by tests/anywhere/fixture/default.nix, not from the ReproOS
# source graph; it exists so the takeover protocol can be exercised
# before a qualified source-built installer exists. The protocol it
# implements is the product's:
#
#   * the installer's SSH host key is generated HERE, at boot, and never
#     exists on the source system or on the wire;
#   * its fingerprint, the session id, the handoff nonce and this boot's
#     boot_id are announced on the serial console, which the controller
#     reads through the independent rescue plane and pins before it
#     opens SSH;
#   * only public material arrives in the session archive the controller
#     appends to this initramfs (authorized_keys and the signed handoff).
#
# Kernel command line:
#   anywhere.session=<hex>  anywhere.nonce=<hex>  anywhere.mac=<mac>
#   anywhere.net=dhcp | anywhere.net=static,<addr/prefix>,<gw>[,<dns>]

PATH=@toolPath@:/bin
export PATH
# The hardening controls this build carries (M2): gate ro-store egress.
controls="@controls@"
has() { case " $controls " in *" $1 "*) return 0 ;; esac; return 1; }

/bin/busybox mkdir -p /bin /proc /sys /dev /run /tmp /var/empty /etc/ssh
/bin/busybox --install -s /bin
ln -s /etc/anywhere/gate /bin/anywhere-gate
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts
mount -t tmpfs -o mode=0755 run /run
mount -t tmpfs tmp /tmp
[ -d /sys/firmware/efi/efivars ] && mount -t efivarfs efivarfs /sys/firmware/efi/efivars

console() { echo "$*" > /dev/console; }

for m in @modules@; do
  modprobe "$m" 2>/dev/null || true
done

arg() {
  for w in $(cat /proc/cmdline); do
    case "$w" in "$1"=*) echo "${w#*=}"; return ;; esac
  done
}
session=$(arg anywhere.session)
nonce=$(arg anywhere.nonce)
mac=$(arg anywhere.mac)
net=$(arg anywhere.net)
debug=$(arg anywhere.debug)

fatal() {
  console "REPROOS_ANYWHERE_INSTALLER:FAIL:$*"
  # Stay up: the rescue plane is how an operator reaches a failed
  # takeover, and a kernel panic would take that away too.
  while :; do sleep 3600; done
}

case "$session" in ''|*[!0-9a-f]*) fatal bad-session ;; esac
case "$nonce" in ''|*[!0-9a-f]*) fatal bad-nonce ;; esac
[ -s /etc/anywhere/session.pub ] || fatal no-session-archive
case "$(cat /etc/anywhere/session.pub)" in
  "ssh-ed25519 "*) ;; *) fatal bad-session-key ;;
esac
# Per-plan credential: only the key in this session's archive opens the
# installer, and with the gate it opens nothing but the gate.
if has gate; then
  printf 'restrict,command="/etc/anywhere/gate" %s\n' "$(head -n 1 /etc/anywhere/session.pub)" \
    > /etc/anywhere/authorized_keys
else
  head -n 1 /etc/anywhere/session.pub > /etc/anywhere/authorized_keys
fi
# Read-only verified closure: nothing in the installer may add or change
# an executable it then runs from the store.
if has ro-store; then
  mount --bind /nix/store /nix/store && mount -o remount,bind,ro /nix/store || fatal ro-store
fi
mkdir -p /mnt /run/anywhere/work

# Network: the interface is chosen by the MAC the plan pinned, never by
# name or enumeration order.
iface=""
i=0
while [ -z "$iface" ] && [ "$i" -lt 30 ]; do
  for d in /sys/class/net/*; do
    [ "$(cat "$d/address" 2>/dev/null)" = "$mac" ] && iface=${d##*/}
  done
  [ -n "$iface" ] || sleep 1
  i=$((i + 1))
done
[ -n "$iface" ] || fatal "no-interface-with-mac-$mac"
ip link set lo up
ip link set "$iface" up
case "$net" in
  dhcp)
    udhcpc -i "$iface" -n -q -t 10 -s /etc/anywhere/udhcpc-hook || fatal dhcp ;;
  static,*)
    rest=${net#static,}
    addr=${rest%%,*}; rest=${rest#*,}
    gw=${rest%%,*}; dns=""
    [ "$rest" != "$gw" ] && dns=${rest#*,}
    ip addr add "$addr" dev "$iface" || fatal static-addr
    ip route add default via "$gw" dev "$iface" || fatal static-route
    [ -n "$dns" ] && echo "nameserver $dns" > /etc/resolv.conf ;;
  *) fatal "bad-net-$net" ;;
esac

grep -q '^root:' /etc/passwd 2>/dev/null || {
  echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd
  echo 'sshd:x:74:74:sshd:/var/empty:/bin/false' >> /etc/passwd
  echo 'root:x:0:' > /etc/group
  echo 'sshd:x:74:' >> /etc/group
}
chmod 0755 /
mkdir -p /root && chmod 0700 /root

ip -o addr show > /dev/console 2>&1; ip route > /dev/console 2>&1
if has egress; then
  nft -f /etc/anywhere/egress.nft || fatal egress
fi
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key || fatal hostkey
hostkey=$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
boot_id=$(cat /proc/sys/kernel/random/boot_id)
mkdir -p /run/anywhere
printf 'session=%s\nnonce=%s\nboot_id=%s\nhostkey=%s\ncontrols=%s\n' \
  "$session" "$nonce" "$boot_id" "$hostkey" "$(echo $controls | tr ' ' ',')" > /run/anywhere/identity

cat > /etc/ssh/sshd_config <<EOF
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
HostKeyAlgorithms ssh-ed25519
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile /etc/anywhere/authorized_keys
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
MaxSessions 8
PidFile /run/sshd.pid
LogLevel INFO
SetEnv PATH=@toolPath@:/bin
EOF
chmod 0600 /etc/anywhere/authorized_keys

# Detection (M3 DET): the kernel audits every execve and every
# write-open of a disk device node, and -- with no audit daemon -- prints
# each record to the console, which the controller reads through the
# rescue plane. The rules are then locked (-e 2): changing or disabling
# them now needs a reboot, which the controller would see.
echo 0 > /proc/sys/kernel/printk_ratelimit
auditctl -D >/dev/null 2>&1
auditctl -b 16384 >/dev/null
auditctl -f 1 >/dev/null
auditctl -a always,exit -F arch=b64 -S execve -k anywhere-exec >/dev/null || fatal audit-exec
auditctl -a always,exit -F arch=b32 -S execve -k anywhere-exec >/dev/null || fatal audit-exec32
# Watch the disks that EXIST (whole disk and current partitions), plus the
# partition names the plan's target is about to get. Every audit record is
# printed synchronously on a 115200-baud console, so watching every
# conceivable disk node (150 rules) stalled a fresh installer.
serial_of() {
  s=$(cat "/sys/block/$1/serial" 2>/dev/null || cat "/sys/block/$1/device/serial" 2>/dev/null)
  [ -n "$s" ] || s=$(tail -c +5 "/sys/block/$1/device/vpd_pg80" 2>/dev/null | tr -d '\000')
  printf '%s' "$s" | sed 's/^ *//; s/ *$//'
}
want=$(sed -n 's/.*"target_serial":"\([^"]*\)".*/\1/p' /etc/anywhere/handoff.json 2>/dev/null)
i=0
while [ "$i" -lt 20 ] && ! ls /sys/block | grep -q -E '^(vd|sd|nvme)'; do sleep 0.5; i=$((i + 1)); done
target=""
for d in /sys/block/*; do
  name=${d##*/}
  case "$name" in loop*|ram*|zram*|sr*|fd*|nbd*) continue ;; esac
  auditctl -w "/dev/$name" -p w -k anywhere-disk-write >/dev/null 2>&1
  for p in "$d"/"$name"*; do
    [ -r "$p/partition" ] && auditctl -w "/dev/${p##*/}" -p w -k anywhere-disk-write >/dev/null 2>&1
  done
  [ -n "$want" ] && [ "$(serial_of "$name")" = "$want" ] && target=$name
done
[ -n "$want" ] && [ -z "$target" ] && fatal "target-serial-not-found"
if [ -n "$target" ]; then
  case "$target" in *[0-9]) sep=p ;; *) sep= ;; esac
  for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    auditctl -w "/dev/$target$sep$n" -p w -k anywhere-disk-write >/dev/null 2>&1
  done
fi
auditctl -e 2 >/dev/null || fatal audit-lock
console "REPROOS_ANYWHERE_INSTALLER:AUDIT locked rules=$(auditctl -l | wc -l)"

# The announcement the controller pins. One line, fixed vocabulary.
# kauditd prints asynchronously; let it drain so no audit record lands in
# the middle of the line (echo is a builtin, so the line itself is not
# preceded by an exec record).
sleep 2
console "REPROOS_ANYWHERE_INSTALLER:READY session=$session nonce=$nonce boot_id=$boot_id hostkey=$hostkey"
# The line reaches the UART after echo returns; starting sshd now would
# put its audit records in the middle of it. Let it drain first.
sleep 1

while :; do
  if [ "$debug" = 1 ]; then dflag=-d; else dflag=; fi
  @sshd@ -D -e $dflag -f /etc/ssh/sshd_config >/dev/console 2>&1
  console "REPROOS_ANYWHERE_INSTALLER:SSHD-EXITED"
  sleep 2
done
