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

/bin/busybox mkdir -p /bin /proc /sys /dev /run /tmp /var/empty /etc/ssh
/bin/busybox --install -s /bin
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
[ -s /etc/anywhere/authorized_keys ] || fatal no-session-archive

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
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key || fatal hostkey
hostkey=$(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)
boot_id=$(cat /proc/sys/kernel/random/boot_id)
mkdir -p /run/anywhere
printf 'session=%s\nnonce=%s\nboot_id=%s\nhostkey=%s\n' \
  "$session" "$nonce" "$boot_id" "$hostkey" > /run/anywhere/identity

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
LogLevel VERBOSE
SetEnv PATH=@toolPath@:/bin
EOF
chmod 0600 /etc/anywhere/authorized_keys

# The announcement the controller pins. One line, fixed vocabulary.
console "REPROOS_ANYWHERE_INSTALLER:READY session=$session nonce=$nonce boot_id=$boot_id hostkey=$hostkey"

while :; do
  if [ "$debug" = 1 ]; then dflag=-d; else dflag=; fi
  @sshd@ -D -e $dflag -f /etc/ssh/sshd_config >/dev/console 2>&1
  console "REPROOS_ANYWHERE_INSTALLER:SSHD-EXITED"
  sleep 2
done
