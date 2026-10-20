# A fresh NixOS source machine for the Anywhere distribution matrix.
#
# NixOS publishes no generic cloud qcow2, so the source image is built
# here from the pinned nixpkgs revision (the same one the other fixtures
# use): UEFI, systemd-boot, ext4 root, OpenSSH, cloud-init (NoCloud) so the
# supervisor injects the host key and operator key exactly as it does for
# the other distributions. It is a SOURCE system -- the thing converted --
# not part of ReproOS.
{ nixpkgs ? builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/addf7cf5f383a3101ecfba091b98d0a1263dc9b8.tar.gz";
    sha256 = "sha256-hM20uyap1a0M9d344I692r+ik4gTMyj60cQWO+hAYP8=";
  }
}:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; config = { }; overlays = [ ]; };
  system = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    system = "x86_64-linux";
    modules = [
      ({ modulesPath, ... }: {
        imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];
        boot.loader.systemd-boot.enable = true;
        boot.loader.efi.canTouchEfiVariables = false;
        boot.growPartition = true;
        boot.kernelParams = [ "console=ttyS0,115200" ];
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; autoResize = true; };
        fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
        networking.hostName = "";
        networking.useDHCP = false;
        networking.useNetworkd = true;
        systemd.network.networks."10-wired" = {
          matchConfig.Type = "ether";
          networkConfig.DHCP = "ipv4";
        };
        services.cloud-init.enable = true;
        services.cloud-init.network.enable = false;
        services.openssh.enable = true;
        services.openssh.settings.PermitRootLogin = "prohibit-password";
        services.openssh.settings.PasswordAuthentication = false;
        users.mutableUsers = true;
        system.stateVersion = "25.11";
      })
    ];
  };
in
import (nixpkgs + "/nixos/lib/make-disk-image.nix") {
  inherit pkgs;
  inherit (pkgs) lib;
  inherit (system) config;
  format = "qcow2";
  partitionTableType = "efi";
  diskSize = "auto";
  additionalSpace = "1024M";
  name = "nixos-anywhere-source";
}
