# ReproOS Anywhere inventory probe.
#
# Streamed to the source host as `sh -s` over the enrolled SSH channel; it
# is never written to the remote filesystem. It READS ONLY: it runs no
# command that creates, modifies or deletes a file, mounts nothing, loads
# no module, starts no service and seeds no privilege cache (sudo is not
# invoked here; the controller decides privilege from `id -u`).
#
# Output is one record per line:  R<TAB>section<TAB>key<TAB>value
# Values are made single-line and tab-free here; the controller still
# treats every byte as hostile (bounded, charset-checked, duplicates
# rejected). Portable to POSIX sh + busybox: no bash, no lsblk/jq/ip -j.

LC_ALL=C
export LC_ALL
# FHS first; NixOS keeps its system tools under /run/current-system.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin
export PATH

emit() {
  # $1 section, $2 key, $3 value (sanitised to one printable line)
  v=$(printf '%s' "$3" | tr '\t\r\n' '   ' | tr -cd '\040-\176')
  printf 'R\t%s\t%s\t%s\n' "$1" "$2" "$v"
}

rd() {
  # first line of a readable file, empty otherwise
  [ -r "$1" ] || return 0
  head -n 1 "$1" 2>/dev/null
}

emit probe version 1
emit probe uid "$(id -u)"
emit kernel release "$(uname -r)"
emit kernel machine "$(uname -m)"
emit kernel cmdline "$(rd /proc/cmdline)"
emit kernel kexec_load_disabled "$(rd /proc/sys/kernel/kexec_load_disabled)"
emit kernel lockdown "$(rd /sys/kernel/security/lockdown)"

if [ -r /etc/os-release ]; then
  while IFS= read -r line; do
    case "$line" in
      ID=*|ID_LIKE=*|VERSION_ID=*|PRETTY_NAME=*|NAME=*)
        k=${line%%=*}; v=${line#*=}
        v=$(printf '%s' "$v" | sed 's/^"//; s/"$//')
        emit os "$k" "$v" ;;
    esac
  done < /etc/os-release
fi

# Containers are refused by the safety contract, so evidence of one is
# collected rather than inferred.
[ -e /.dockerenv ] && emit virt container_marker dockerenv
[ -e /run/.containerenv ] && emit virt container_marker containerenv
[ -r /run/systemd/container ] && emit virt container_marker "systemd:$(rd /run/systemd/container)"
[ -d /proc/vz ] && [ ! -d /proc/bc ] && emit virt container_marker openvz
emit virt pid1 "$(rd /proc/1/comm)"
emit virt cpu_hypervisor_flag "$(grep -c '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null)"

for f in sys_vendor product_name product_uuid product_serial board_serial chassis_asset_tag; do
  emit dmi "$f" "$(rd /sys/class/dmi/id/$f)"
done
emit machine machine_id "$(rd /etc/machine-id)"
emit machine hostname "$(rd /proc/sys/kernel/hostname)"

if [ -d /sys/firmware/efi ]; then
  emit firmware mode uefi
  emit firmware efi_bits "$(rd /sys/firmware/efi/fw_platform_size)"
  sb=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
  if [ -r "$sb" ]; then
    # 4 attribute bytes then the 1-byte value
    emit firmware secure_boot "$(od -An -tu1 -j4 -N1 "$sb" 2>/dev/null | tr -d ' ')"
  else
    emit firmware secure_boot absent
  fi
else
  emit firmware mode bios
fi

emit memory mem_total_kib "$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
emit memory mem_available_kib "$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
emit cpu count "$(grep -c '^processor' /proc/cpuinfo)"

# Block devices: whole disks with their identities and topology.
for b in /sys/block/*; do
  [ -e "$b" ] || continue
  n=${b##*/}
  case "$n" in loop*|ram*|zram*|sr*|fd*|nbd*) continue ;; esac
  emit disk "$n.size_sectors" "$(rd "$b/size")"
  emit disk "$n.logical_block" "$(rd "$b/queue/logical_block_size")"
  emit disk "$n.removable" "$(rd "$b/removable")"
  emit disk "$n.ro" "$(rd "$b/ro")"
  emit disk "$n.devnum" "$(rd "$b/dev")"
  serial=$(rd "$b/serial"); [ -n "$serial" ] || serial=$(rd "$b/device/serial")
  emit disk "$n.serial" "$serial"
  emit disk "$n.wwid" "$(rd "$b/wwid")$(rd "$b/device/wwid")"
  emit disk "$n.model" "$(rd "$b/device/model")"
  emit disk "$n.dm_uuid" "$(rd "$b/dm/uuid")"
  emit disk "$n.md_level" "$(rd "$b/md/level")"
  drv=$(readlink "$b/device/driver" 2>/dev/null); emit disk "$n.driver" "${drv##*/}"
  path=$(readlink "$b" 2>/dev/null); emit disk "$n.syspath" "$path"
  s=""; for x in "$b"/slaves/*; do [ -e "$x" ] && s="$s ${x##*/}"; done
  emit disk "$n.slaves" "$s"
  h=""; for x in "$b"/holders/*; do [ -e "$x" ] && h="$h ${x##*/}"; done
  emit disk "$n.holders" "$h"
  for p in "$b"/"$n"*; do
    [ -r "$p/partition" ] || continue
    pn=${p##*/}
    emit part "$pn.disk" "$n"
    emit part "$pn.number" "$(rd "$p/partition")"
    emit part "$pn.start" "$(rd "$p/start")"
    emit part "$pn.size_sectors" "$(rd "$p/size")"
    emit part "$pn.devnum" "$(rd "$p/dev")"
    h=""; for x in "$p"/holders/*; do [ -e "$x" ] && h="$h ${x##*/}"; done
    emit part "$pn.holders" "$h"
  done
done
if [ -d /dev/disk/by-id ]; then
  for l in /dev/disk/by-id/*; do
    [ -L "$l" ] || continue
    t=$(readlink "$l"); emit byid "${l##*/}" "${t##*/}"
  done
fi
[ -r /proc/mdstat ] && emit raid mdstat "$(grep -E '^md' /proc/mdstat | tr '\n' ';')"

# Mounts and swaps, verbatim fields.
i=0
while read -r dev mnt fs opts _; do
  emit mount "$i" "$dev $mnt $fs $opts"; i=$((i + 1))
done < /proc/self/mounts
i=0
tail -n +2 /proc/swaps 2>/dev/null | while read -r dev _; do
  emit swap "$i" "$dev"; i=$((i + 1))
done

# Network: interfaces, addresses, routes, resolvers.
for d in /sys/class/net/*; do
  n=${d##*/}
  [ "$n" = lo ] && continue
  emit netif "$n.mac" "$(rd "$d/address")"
  emit netif "$n.operstate" "$(rd "$d/operstate")"
  emit netif "$n.mtu" "$(rd "$d/mtu")"
  emit netif "$n.wireless" "$([ -d "$d/wireless" ] && echo 1 || echo 0)"
  emit netif "$n.bridge" "$([ -d "$d/bridge" ] && echo 1 || echo 0)"
  drv=$(readlink "$d/device/driver" 2>/dev/null); emit netif "$n.driver" "${drv##*/}"
  [ -e "$d/device" ] && emit netif "$n.physical" 1 || emit netif "$n.physical" 0
done
if command -v ip >/dev/null 2>&1; then
  i=0
  ip -o -4 addr show 2>/dev/null | while read -r _ ifn _ addr rest; do
    case "$rest" in *dynamic*) how=dynamic ;; *) how=static ;; esac
    emit addr4 "$i" "$ifn $addr $how"; i=$((i + 1))
  done
  i=0
  ip -4 route show 2>/dev/null | while IFS= read -r r; do
    emit route4 "$i" "$r"; i=$((i + 1))
  done
fi
i=0
grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | while read -r _ ns _; do
  emit dns "$i" "$ns"; i=$((i + 1))
done
# Which tool manages addressing tells the installer what it must carry.
for u in systemd-networkd NetworkManager dhcpcd dhclient udhcpc connmand; do
  pidof "$u" >/dev/null 2>&1 && emit netmgr "$u" running
done

emit ssh connection "$SSH_CONNECTION"
emit probe complete 1
