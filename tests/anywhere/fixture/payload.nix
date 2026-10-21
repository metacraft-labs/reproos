# ReproOS Anywhere -- FIXTURE payload.
#
# The payload contract is the one the qualified source build will meet:
#
#   rootfs.tar.zst   the CONFIGURED installed root (what
#                    recipes/reproos-image/scripts/stage-installed-root.sh
#                    produces), deterministic tar, numeric root ownership
#   vmlinuz          the kernel GRUB boots
#   initrd.img       the disk initrd that mounts root= and switches to it
#   manifest.json    kind, qualification, sizes and SHA-256 of the three
#
# This fixture meets the contract with nixpkgs userspace (systemd,
# OpenSSH, BusyBox, Python) plus the REAL ReproOS first-boot pieces taken
# from recipes/reproos-image/scripts: reproos-first-boot-enroll,
# reproos-network(+hook, +wait, +unit), reproos-installed-boot-evidence,
# and the sshd / enrollment unit text configure-installed-root.sh writes.
# It is not ReproOS and says so: manifest.kind = "fixture",
# qualified = false.
{ pkgs, lib, kernel, modulesFor, reproosSrc
, autoConfig ? reproosSrc + "/tests/fixtures/auto-config-minimal.toml"
}:
let
  scripts = reproosSrc + "/recipes/reproos-image/scripts";
  sd = pkgs.systemd;
  userland = with pkgs; [
    systemd openssh busybox python3 bashInteractive coreutils util-linux
    kmod iproute2 gnugrep gawk gnused findutils dbus
  ];
  closure = pkgs.closureInfo { rootPaths = userland; };

  diskInit = pkgs.writeScript "reproos-anywhere-fixture-disk-init" ''
    #!/bin/busybox sh
    /bin/busybox mkdir -p /bin /proc /sys /dev /sysroot
    /bin/busybox --install -s /bin
    mount -t proc proc /proc
    mount -t sysfs sys /sys
    mount -t devtmpfs dev /dev
    for m in virtio_pci virtio_blk virtio_scsi sd_mod ahci nvme crc32c_generic crc32c_intel ext4 vfat; do
      modprobe "$m" 2>/dev/null || true
    done
    root=""
    for w in $(cat /proc/cmdline); do
      case "$w" in root=*) root=''${w#root=} ;; esac
    done
    i=0
    while [ ! -b "$root" ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
    mount -o ro "$root" /sysroot || { echo "disk-init: cannot mount $root"; sh; }
    umount /proc /sys
    mount --move /dev /sysroot/dev 2>/dev/null || umount /dev
    exec switch_root /sysroot /sbin/init
  '';
  diskInitrd = pkgs.makeInitrd {
    name = "reproos-anywhere-fixture-disk-initrd";
    compressor = "zstd";
    contents = [
      { object = diskInit; symlink = "/init"; }
      { object = "${pkgs.busybox}/bin/busybox"; symlink = "/bin/busybox"; }
      { object = "${modulesFor [ "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "ahci" "nvme" "crc32c_generic" "crc32c_intel" "ext4" "vfat" ]}/lib/modules"; symlink = "/lib/modules"; }
    ];
  };

  runtimeModules = modulesFor [
    "virtio_pci" "virtio_blk" "virtio_scsi" "virtio_net" "virtio_rng" "virtio_console"
    "sd_mod" "sr_mod" "ahci" "nvme" "e1000" "e1000e" "crc32c_generic" "crc32c_intel"
    "ext4" "vfat" "nls_cp437" "nls_iso8859_1" "nls_ascii" "efivarfs" "af_packet"
    "autofs4" "loop" "tun" "dm_mod"
  ];

  sshdConfig = pkgs.writeText "sshd_config" ''
    Port 22
    ListenAddress 0.0.0.0
    HostKey /etc/ssh/ssh_host_rsa_key
    HostKey /etc/ssh/ssh_host_ecdsa_key
    HostKey /etc/ssh/ssh_host_ed25519_key
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitEmptyPasswords no
    PermitRootLogin no
    AllowUsers @USER@
    PrintMotd no
    PidFile /run/sshd.pid
    Subsystem sftp /usr/libexec/sftp-server
  '';
in
pkgs.runCommand "reproos-anywhere-fixture-payload" {
  nativeBuildInputs = with pkgs; [ gnutar zstd python3 ];
} ''
  set -euo pipefail
  R=$TMPDIR/root
  mkdir -p $R/nix/store $R/usr/bin $R/usr/sbin $R/usr/lib $R/usr/libexec \
    $R/usr/local/sbin $R/etc/systemd/system/multi-user.target.wants \
    $R/etc/ssh $R/etc/repro $R/var/lib/reproos $R/var/empty $R/var/log \
    $R/proc $R/sys $R/dev $R/run $R/tmp $R/boot $R/root $R/home $R/mnt \
    $R/var/log/journal
  for p in $(cat ${closure}/store-paths); do cp -a "$p" $R/nix/store/; done
  ln -s usr/bin $R/bin; ln -s usr/sbin $R/sbin; ln -s usr/lib $R/lib
  ln -s ${sd}/lib/systemd/systemd $R/usr/sbin/init

  # The FHS paths ReproOS's own scripts and units name.
  ln -s ${pkgs.busybox}/bin/busybox $R/usr/bin/busybox
  ln -s ${pkgs.bashInteractive}/bin/bash $R/usr/bin/bash
  ln -s ${pkgs.bashInteractive}/bin/bash $R/usr/bin/sh
  ln -s ${pkgs.python3}/bin/python3 $R/usr/bin/python3
  ln -s ${pkgs.openssh}/bin/ssh-keygen $R/usr/bin/ssh-keygen
  ln -s ${pkgs.openssh}/bin/sshd $R/usr/sbin/sshd
  ln -s ${pkgs.openssh}/libexec/sftp-server $R/usr/libexec/sftp-server
  ln -s ${pkgs.coreutils}/bin/false $R/usr/bin/false
  for t in ${pkgs.coreutils}/bin/* ${pkgs.util-linux}/bin/* ${pkgs.gnugrep}/bin/* \
           ${pkgs.gawk}/bin/* ${pkgs.gnused}/bin/* ${pkgs.findutils}/bin/* \
           ${pkgs.iproute2}/bin/* ${pkgs.kmod}/bin/* ${sd}/bin/*; do
    n=$(basename "$t"); [ -e "$R/usr/bin/$n" ] || ln -s "$t" "$R/usr/bin/$n"
  done
  # Kernel modules the installed system loads after the initrd: the
  # kernel's module loader runs /sbin/modprobe against /lib/modules.
  cp -rL ${runtimeModules}/lib/modules $R/usr/lib/modules
  chmod -R u+w $R/usr/lib/modules
  ln -s ${pkgs.kmod}/bin/modprobe $R/usr/sbin/modprobe
  cp -r ${sd}/example/systemd $R/usr/lib/systemd
  chmod -R u+w $R/usr/lib/systemd
  # nixpkgs systemd searches its units under the default Nix profile and
  # its sysusers/tmpfiles under /etc (its own $out/lib copies are empty).
  mkdir -p $R/nix/var/nix/profiles/default/lib
  ln -s /usr/lib/systemd $R/nix/var/nix/profiles/default/lib/systemd
  cp -r ${sd}/example/sysusers.d ${sd}/example/tmpfiles.d $R/etc/
  chmod -R u+w $R/etc/sysusers.d $R/etc/tmpfiles.d

  cat > $R/etc/os-release <<'EOF'
  NAME="ReproOS"
  ID=reproos
  VARIANT="Anywhere fixture payload (nixpkgs userspace, NOT the source-built ReproOS)"
  VARIANT_ID=anywhere-fixture
  PRETTY_NAME="ReproOS Anywhere fixture"
  EOF
  sed -i 's/^  //' $R/etc/os-release
  printf 'root:x:0:0:root:/root:/usr/bin/bash\nsshd:x:74:74:OpenSSH privilege separation:/var/empty:/usr/bin/false\nnobody:x:65534:65534:nobody:/var/empty:/usr/bin/false\n' > $R/etc/passwd
  printf 'root:x:0:\nsshd:x:74:\nnogroup:x:65534:\n' > $R/etc/group
  printf 'root:!:20000:0:99999:7:::\nsshd:!:19000:0:99999:7:::\nnobody:!:19000:0:99999:7:::\n' > $R/etc/shadow
  printf 'root:!::\nsshd:!::\nnogroup:!::\n' > $R/etc/gshadow
  : > $R/etc/machine-id
  echo reproos > $R/etc/hostname

  # Phase 9 (configuration bundle) and the generation it is named by.
  install -m 0644 ${autoConfig} $R/etc/repro/auto-config.toml
  sha256sum $R/etc/repro/auto-config.toml | cut -d' ' -f1 > $R/etc/repro/generation
  user=$(python3 -c 'import tomllib,sys;print(tomllib.load(open(sys.argv[1],"rb"))["user"]["name"])' ${autoConfig})

  # Phase 10.4, verbatim units and scripts.
  install -m 0755 ${scripts}/reproos-udhcpc-hook ${scripts}/reproos-network \
    ${scripts}/reproos-network-wait ${scripts}/reproos-first-boot-enroll \
    ${scripts}/reproos-installed-boot-evidence $R/usr/local/sbin/
  install -m 0644 ${scripts}/reproos-network.service $R/etc/systemd/system/
  sed "s/@USER@/$user/" ${sshdConfig} > $R/etc/ssh/sshd_config
  chmod 0600 $R/etc/ssh/sshd_config
  cat > $R/etc/systemd/system/sshd.service <<'EOF'
  [Unit]
  Description=OpenSSH server
  After=network.target reproos-network.service reproos-first-boot-enroll.service
  Wants=reproos-network.service
  Requires=reproos-first-boot-enroll.service

  [Service]
  Type=simple
  RuntimeDirectory=sshd
  RuntimeDirectoryMode=0755
  ExecStartPre=/usr/bin/ssh-keygen -A
  ExecStartPre=/usr/sbin/sshd -t
  ExecStart=/usr/sbin/sshd -D -e
  Restart=on-failure
  RestartSec=2

  [Install]
  WantedBy=multi-user.target
  EOF
  cat > $R/etc/systemd/system/reproos-first-boot-enroll.service <<'EOF'
  [Unit]
  Description=Enroll ReproOS instance identity and SSH keys
  After=local-fs.target systemd-machine-id-commit.service
  Before=sddm.service sshd.service reproos-health-check.service
  ConditionPathExists=!/var/lib/reproos/enrollment.complete

  [Service]
  Type=oneshot
  ExecStart=/usr/local/sbin/reproos-first-boot-enroll
  TimeoutStartSec=120
  RemainAfterExit=yes

  [Install]
  WantedBy=multi-user.target
  EOF
  sed -i 's/^  //' $R/etc/systemd/system/sshd.service $R/etc/systemd/system/reproos-first-boot-enroll.service
  for u in reproos-network reproos-first-boot-enroll sshd; do
    ln -s /etc/systemd/system/$u.service $R/etc/systemd/system/multi-user.target.wants/$u.service
  done
  ln -s /nix/var/nix/profiles/default/lib/systemd/system/multi-user.target $R/etc/systemd/system/default.target
  echo direct-image-assembly > $R/var/lib/reproos/install-source
  # A system bus, so the installed-system checks can ask systemd about
  # unit state. nixpkgs ships dbus without units (NixOS writes them).
  printf '[Unit]\nDescription=D-Bus System Message Bus Socket\n[Socket]\nListenStream=/run/dbus/system_bus_socket\n' \
    > $R/etc/systemd/system/dbus.socket
  printf '[Unit]\nDescription=D-Bus System Message Bus\nRequires=dbus.socket\n[Service]\nExecStart=${pkgs.dbus}/bin/dbus-daemon --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only --config-file=${pkgs.dbus}/share/dbus-1/system.conf\n' \
    > $R/etc/systemd/system/dbus.service
  mkdir -p $R/etc/systemd/system/sockets.target.wants $R/etc/dbus-1
  ln -s /etc/systemd/system/dbus.socket $R/etc/systemd/system/sockets.target.wants/dbus.socket
  ln -s ${sd}/share/dbus-1/system.d $R/etc/dbus-1/system.d
  echo 'messagebus:x:4:4:D-Bus:/run/dbus:/usr/bin/false' >> $R/etc/passwd
  echo 'messagebus:x:4:' >> $R/etc/group
  echo 'messagebus:!:19000:0:99999:7:::' >> $R/etc/shadow
  echo 'messagebus:!::' >> $R/etc/gshadow
  # ReproOS writes /etc/resolv.conf from its DHCP hook; systemd-resolved
  # is not part of it, so its stub-resolv link is not either.
  rm -f $R/etc/tmpfiles.d/systemd-resolve.conf
  : > $R/etc/resolv.conf
  # nixpkgs systemd does not default services to the FHS PATH that the
  # source-built ReproOS systemd (and ReproOS's own scripts) assume.
  mkdir -p $R/etc/systemd/system.conf.d
  printf '[Manager]\nDefaultEnvironment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n' \
    > $R/etc/systemd/system.conf.d/50-anywhere-fixture-path.conf
  # Fixture only: ttyS0 is the rescue plane the tests read, not a login
  # (nixpkgs' agetty unit expects NixOS paths and fails here).
  ln -s /dev/null $R/etc/systemd/system/serial-getty@.service
  # Fixture only: the serial console is the rescue plane the tests read,
  # so service output is forwarded there.
  mkdir -p $R/etc/systemd/journald.conf.d
  printf '[Journal]\nForwardToConsole=yes\nTTYPath=/dev/ttyS0\nMaxLevelConsole=info\n' \
    > $R/etc/systemd/journald.conf.d/50-anywhere-fixture-console.conf

  mkdir -p $out
  tar --sort=name --mtime=@1735689600 --owner=0 --group=0 --numeric-owner \
    --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C $R -cf - . | zstd -q -19 -T1 > $out/rootfs.tar.zst
  cp ${kernel}/bzImage $out/vmlinuz
  cp ${diskInitrd}/initrd $out/initrd.img
  export ROOT_BYTES=$(du -sb --apparent-size $R | cut -f1)
  python3 - $out <<'EOF'
  import hashlib, json, os, sys
  out = sys.argv[1]
  files = {}
  for name in ("rootfs.tar.zst", "vmlinuz", "initrd.img"):
      p = os.path.join(out, name)
      h = hashlib.sha256(open(p, "rb").read()).hexdigest()
      files[name] = {"sha256": h, "size": os.path.getsize(p)}
  manifest = {
      "schema": "reproos-anywhere-payload/1",
      "kind": "fixture",
      "qualified": False,
      "description": "nixpkgs userspace with the real ReproOS first-boot scripts; not the source-built ReproOS rootfs",
      "rootfs_unpacked_bytes": int(os.environ["ROOT_BYTES"]),
      "configuration_generation": open(os.path.join(os.environ["TMPDIR"], "root/etc/repro/generation")).read().strip(),
      "files": files,
  }
  open(os.path.join(out, "manifest.json"), "w").write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
  EOF
''
