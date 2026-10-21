# ReproOS Anywhere -- FIXTURE artifacts for the conversion test suite.
#
# Nothing built here is ReproOS. The qualified installer and payload are
# the source-built ReproOS kernel, initramfs and rootfs (Campaign
# Completion M13), which do not exist yet. Until they do, the Anywhere
# protocol -- inventory, plan, takeover, apply, journal, reboot, installed
# verification, recovery -- is exercised against these stand-ins, and
# every receipt they produce says so (`payload.kind = "fixture"`,
# `conversionQualified = false`).
#
# Outputs (nix-build tests/anywhere/fixture -A <name>):
#   installer   kernel + initramfs of the takeover environment
#   payload     rootfs.tar.zst + vmlinuz + initrd.img + manifest.json
#   kexec       a static kexec(8) staged onto source systems that lack one
#   broker      the installer's storage broker (tools/anywhere/anywhere_disk.nim)
#
# Arguments are the sibling checkouts the broker is compiled from; the
# test driver passes them so nothing here reaches outside its inputs.
{ reproosSrc ? ../../.., reprobuildSrc ? ../../../../reprobuild
  # The takeover environment's hardening controls. Tests build variants
  # with one removed to prove each control is what its gate depends on.
, controls ? [ "gate" "ro-store" "egress" ]
  # The configuration baked into the payload (its install.target_device
  # must name the disk being converted).
, autoConfig ? reproosSrc + "/tests/fixtures/auto-config-minimal.toml"
, nixpkgs ? builtins.fetchTarball {
    # Same revision as the workspace flake lock (nixpkgs addf7cf5).
    url = "https://github.com/NixOS/nixpkgs/archive/addf7cf5f383a3101ecfba091b98d0a1263dc9b8.tar.gz";
    sha256 = "sha256-hM20uyap1a0M9d344I692r+ik4gTMyj60cQWO+hAYP8=";
  }
}:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; config = { }; overlays = [ ]; };
  inherit (pkgs) lib;

  kernel = pkgs.linuxPackages.kernel;
  noFirmware = pkgs.runCommand "no-firmware" { } "mkdir -p $out/lib/firmware";
  modulesFor = rootModules: pkgs.makeModulesClosure {
    inherit rootModules;
    kernel = kernel.modules;
    firmware = noFirmware;
    allowMissing = true;
  };
  bootModules = [
    "virtio_pci" "virtio_blk" "virtio_scsi" "virtio_net" "virtio_rng"
    "sd_mod" "sr_mod" "ahci" "ata_piix" "nvme" "e1000" "e1000e"
    "crc32c_generic" "crc32c_intel" "ext4" "vfat" "nls_cp437" "nls_iso8859_1"
    "efivarfs" "af_packet" "nf_tables" "nft_ct"
  ];
  modules = modulesFor bootModules;

  libSrc = name: builtins.path {
    name = "reprobuild-${name}";
    path = reprobuildSrc + "/libs/${name}/src";
  };
  broker = pkgs.stdenv.mkDerivation {
    name = "reproos-anywhere-broker";
    src = builtins.path { name = "anywhere-tools"; path = reproosSrc + "/tools/anywhere"; };
    nativeBuildInputs = [ pkgs.nim ];
    buildPhase = ''
      export HOME=$TMPDIR
      nim c --hints:off --warnings:off --skipParentCfg --skipProjCfg \
        --nimcache:$TMPDIR/nc -d:release \
        --path:${libSrc "repro_profile"} --path:${libSrc "repro_cli_support"} \
        -o:anywhere_disk anywhere_disk.nim
    '';
    installPhase = "install -Dm0755 anywhere_disk $out/bin/anywhere_disk";
  };

  # The controller-side storage-plan renderer: tools/anywhere/anywhere_layout.nim
  # over repro/disk_layouts.nim, the one declaration of what a layout is.
  layoutTool = pkgs.stdenv.mkDerivation {
    name = "reproos-anywhere-layout";
    src = builtins.path { name = "reproos-layout-src"; path = reproosSrc;
      filter = path: type:
        let rel = lib.removePrefix (toString reproosSrc + "/") (toString path); in
        rel == "repro" || lib.hasPrefix "repro/" rel ||
        rel == "tools" || rel == "tools/anywhere" || rel == "tools/anywhere/anywhere_layout.nim"; };
    nativeBuildInputs = [ pkgs.nim ];
    buildPhase = ''
      export HOME=$TMPDIR
      nim c --hints:off --warnings:off --skipParentCfg --skipProjCfg \
        --nimcache:$TMPDIR/nc -d:release \
        --path:${libSrc "repro_profile"} \
        --path:${builtins.path { name = "nimcrypto"; path = reprobuildSrc + "/libs/nimcrypto"; }} \
        -o:anywhere_layout tools/anywhere/anywhere_layout.nim
    '';
    installPhase = "install -Dm0755 anywhere_layout $out/bin/anywhere_layout";
  };

  installerTools = with pkgs; [
    util-linux parted gptfdisk e2fsprogs dosfstools grub2_efi kmod zstd
    gnutar coreutils openssh broker audit nftables
  ];
  # One profile on PATH; its store closure is what the initramfs carries.
  toolEnv = pkgs.buildEnv {
    name = "reproos-anywhere-installer-tools";
    paths = installerTools;
    pathsToLink = [ "/bin" "/sbin" ];
  };
  toolPath = "${toolEnv}/bin:${toolEnv}/sbin";

  installerInit = pkgs.replaceVarsWith {
    src = ./installer-init.sh;
    isExecutable = true;
    replacements = {
      inherit toolPath;
      modules = lib.concatStringsSep " " bootModules;
      controls = lib.concatStringsSep " " controls;
      sshd = "${pkgs.openssh}/bin/sshd";
    };
  };

  installerInitrd = pkgs.makeInitrd {
    name = "reproos-anywhere-installer-initrd";
    compressor = "zstd";
    contents = [
      { object = installerInit; symlink = "/init"; }
      { object = "${pkgs.busybox}/bin/busybox"; symlink = "/bin/busybox"; }
      { object = "${modules}/lib/modules"; symlink = "/lib/modules"; }
      { object = ./udhcpc-hook; symlink = "/etc/anywhere/udhcpc-hook"; }
      { object = toolEnv; symlink = "/tools"; }
      { object = ./egress.nft; symlink = "/etc/anywhere/egress.nft"; }
      # The gate's vocabulary is always present; the "gate" control decides
      # whether the session key is RESTRICTED to it (forced command).
      { object = reproosSrc + "/tools/anywhere/installer-gate.sh"; symlink = "/etc/anywhere/gate"; }
    ];
  };

  installer = pkgs.runCommand "reproos-anywhere-installer" {
    nativeBuildInputs = [ pkgs.zstd pkgs.python3 ];
  } ''
    mkdir -p $out
    cp ${kernel}/bzImage $out/vmlinuz
    cp ${installerInitrd}/initrd $out/initrd.img
    unpacked=$(zstd -dc $out/initrd.img | wc -c)
    python3 - $out "$unpacked" "${lib.concatStringsSep " " controls}" <<'EOF'
    import hashlib, json, os, sys
    out, unpacked = sys.argv[1], int(sys.argv[2])
    files = {n: {"sha256": hashlib.sha256(open(os.path.join(out, n), "rb").read()).hexdigest(),
                 "size": os.path.getsize(os.path.join(out, n))} for n in ("vmlinuz", "initrd.img")}
    m = {"schema": "reproos-anywhere-installer/1", "kind": "fixture", "qualified": False,
         "takeover_protocol": 2, "controls": sys.argv[3].split(), "initrd_unpacked_bytes": unpacked,
         "files": files}
    open(os.path.join(out, "manifest.json"), "w").write(json.dumps(m, indent=2, sort_keys=True) + "\n")
    EOF
  '';

  kexec = pkgs.runCommand "reproos-anywhere-kexec" { } ''
    install -Dm0755 ${pkgs.pkgsStatic.kexec-tools}/bin/kexec $out/bin/kexec
  '';

  payload = import ./payload.nix {
    inherit pkgs lib kernel modulesFor reproosSrc autoConfig;
  };
in
{
  inherit installer installerInitrd kexec broker payload kernel layoutTool;
}
