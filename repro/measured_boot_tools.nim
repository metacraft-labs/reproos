## The tools the opt-in measured-boot layer runs, and where they come from.
##
## `repro/workflows.nim` carries two edges over the same measurement gate:
## an always-on one whose boot layer is unreachable, and an opt-in one that
## really boots a guest with a software TPM attached and reads PCR 11 back
## out of the register. The second edge needs a system emulator, a software
## TPM and the FAT tools that build an ESP, and a build action's PATH
## carries exactly the tool identities its action declares -- so each of
## them has to be a DECLARED identity or the layer cannot run.
##
## WHY THESE FOUR ARE PINNED-NIXPKGS. This project selects
## `defaultToolProvisioning "from-source"`, under which a COMPLETED SOURCE
## MIRROR OUTRANKS THE PINNED CHANNEL -- the same ordering
## `recipes/reproos-image/package.nim` records for `gcc`, where it is the
## reason that edge compiles with `clang`. What decides whether a mirror
## exists for a given tool is the `executable <name>:` declarations INSIDE
## a source recipe, not the recipe's package name: `mtoolsSource` declares
## only `executable mtools:`, so `mmd` and `mcopy` have no mirror even
## though mtools plainly has a recipe.
##
## Checked against the corpus, none of the four names below is mirrored --
## there is no source recipe for an emulator or a software TPM at all, and
## the two FAT applets are not among mtools' declared executables. So each
## falls through to the pinned channel declared here, the same route `nim`
## and `clang` take, and the same shape `vm-harness` uses for its own
## software TPM. Nothing in THIS module can start a source build.
##
## THE TWO NAMES THE EDGE ALSO DECLARES, AND WHY THEY ARE NOT HERE:
##
##   `mkfs.vfat` is already pinned in
##   `repro_dsl_stdlib/packages/host_system_tools`, and nothing outranks
##   that: `dosfstoolsSource` declares `executable fatlabel:` plus aliases
##   for `mkfs.fat` and `fsck.fat`, and `mkfs.vfat` is not among them. A
##   second declaration of an already-provisioned name would only be a
##   second opinion about which bytes a tool is.
##
##   `xz` IS mirrored, and therefore does come FROM SOURCE. It has a
##   pinned stdlib declaration too, but `xzSource` declares
##   `executable xz:`, so under this project's default the mirror wins and
##   the pinned channel is not what the opt-in edge gets. This is stated
##   rather than engineered around because the mirror was already in this
##   recipe's closure before the edge existed -- `xz` is a declared tool
##   identity on two older actions here -- so the edge adds no source
##   build that was not already being built. It is also the one tool of
##   the six the boot layer can do without: it is needed when, and only
##   when, the guest kernel's TPM drivers are compressed modules rather
##   than built in.

import repro_project_dsl
import repro_dsl_stdlib/nixpkgs_pin

package `qemu-system-x86_64`:
  provisioning:
    nixPackage "nixpkgs#qemu", executablePath = "bin/qemu-system-x86_64",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash

package swtpm:
  ## The software TPM 2.0 the guest's `tpm-tis` device is backed by. A
  ## transient one per guest, seeded from the host random source and torn
  ## down with the guest, so the register a guest reports is a function of
  ## what the firmware and the stub measured in THAT boot and of nothing
  ## carried over from an earlier one.
  provisioning:
    nixPackage "nixpkgs#swtpm", executablePath = "bin/swtpm",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash

package mmd:
  ## `mmd` and `mcopy` are two applets of one multi-call binary, and each
  ## needs its OWN identity: a provisioning entry resolves one executable
  ## path, and resolving the link rather than the applet name hands back a
  ## program that does not know which applet it was asked for.
  provisioning:
    nixPackage "nixpkgs#mtools", executablePath = "bin/mmd",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash

package mcopy:
  provisioning:
    nixPackage "nixpkgs#mtools", executablePath = "bin/mcopy",
      nixpkgsRev = CanonicalNixpkgsRev,
      nixpkgsNarHash = CanonicalNixpkgsNarHash
