## Small host archive fixtures must not bootstrap the source toolchain.
import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package mksquashfs:
  provisioning:
    nixPackage "nixpkgs#squashfsTools", executablePath = "bin/mksquashfs",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash

package unsquashfs:
  provisioning:
    nixPackage "nixpkgs#squashfsTools", executablePath = "bin/unsquashfs",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
