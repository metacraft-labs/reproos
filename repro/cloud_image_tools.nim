## Tools the cloud-image conversion gate runs that have no source recipe in
## the catalog, provisioned from the same pinned nixpkgs channel as
## `measured_boot_tools.nim`. `tar` and `gzip` are deliberately not declared:
## both are from-source packages here, and naming them would make an
## always-on unit gate bootstrap them.

import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package `qemu-img`:
  ## Converts the canonical raw into qcow2 and fixed VHD
  ## (tools/reproos-cloud-image.py).
  provisioning:
    nixPackage "nixpkgs#qemu-utils", executablePath = "bin/qemu-img",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
