# ReproOS

ReproOS is a product repository. Changes land on `dev`; `stable` is the
published release and default branch.

Reusable package interfaces and source recipes belong in the sibling
`reprobuild-packages` repository. ReproOS owns image composition, installer
sources, boot assets, and product-specific tests.

Use Reprobuild as the only contributor command surface:

- `repro build installer`, `repro build rootfs`, `repro build iso`,
  `repro build unattended-iso`, `repro build image`,
  `repro build incus-projection`, and
  `repro build incus-image` produce the named artifacts from source.
- `repro build` produces the default artifact collection.
- `repro test` runs the complete product test collection; focused tests are
  named `test-*` build targets. Use `repro build test-iso-reproducibility`
  after changing boot media authoring or source-runtime composition, and
  `repro build test-installed-desktop` after changing the graphical session.
  `repro build test-installed-ssh` boots the installed image and verifies an
  SSH command through a loopback-only forwarded port.
  `repro build test-disk-layout-presets` checks the typed disk-layout
  registry in `repro/disk_layouts.nim`: every preset round-trips
  TOML → typed → disko JSON, the `uefi-ext4` document matches the bytes
  the recipe has always emitted, and `uefi-attested` declares the
  attestable partition shape. Run it after touching a layout preset, the
  image recipe's plan, or `build-reproos-image.sh`.
  `repro build test-installer-disk-layout-parity` checks that the disko
  document has exactly one renderer. `repro/disk_layouts.nim` is the only
  declaration of what a layout is; `tools/gen_disk_layouts.nim` compiles it
  into the installer's C++ table
  (`apps/reproos-installer/src/disk_layouts_generated.h`) and into
  `tools/disk_layouts_generated.json` for the config validator, and both
  generated files are checked in. **After changing a preset, regenerate
  them with `nim r tools/gen_disk_layouts.nim`** — this gate re-derives
  both and fails if a byte differs, compiles the shipped
  `apps/reproos-installer/src/disk_layouts.cpp` and diffs its documents
  and refusals against the registry's, and checks that the image driver
  refuses when `/etc/repro/disko.json` is not the document it applies.
  Never hand-edit a generated file, and never add a second place that
  decides which layouts are legal.
  `repro build test-image-reproducibility` is the reproducibility gate for
  the installed image, in layers. Its always-on layers cost a second and
  need nothing built: they re-derive every input the image is a function
  of — the disko document, the pinned build environment of every action on
  the image's path, the source package closure, the declared inputs and
  tool identities, and the scripts staged into the image — **twice, into
  two clean trees**, the second under a deliberately different caller
  environment (`SOURCE_DATE_EPOCH`, `TZ`, `LC_ALL`, `LANG`) and the
  opposite directory enumeration order, and they check that every shipped
  script that authors an archive carries the flags that make it a function
  of its inputs. A mismatch names the **first differing artifact**, not
  merely that something differs. The build-twice byte comparison of the
  qcow2 itself is opt-in
  (`REPROOS_IMAGE_REPRODUCIBILITY_GATE=1`) because an image build takes
  hours and needs `sudo`; it reports a visible skip naming the remedy when
  it is not asked for. Run this gate after touching the image or ISO
  recipes, the image driver, the initramfs builder, or `build-iso.sh`.
  Two rules it enforces and that are easy to get wrong: an action
  **inherits** every variable it does not assign, so `SOURCE_DATE_EPOCH`,
  `LC_ALL` and `TZ` have to be assigned as bare literals on the action's
  own command line — a `${SOURCE_DATE_EPOCH:-…}` fallback inside the
  script is not a pin; and `test-iso-reproducibility` is held to the same
  contract by this gate, so the two cannot drift.
  `repro build test-image-metadata` checks real SquashFS/tar metadata, source
  preservation, sudo privileges, and health-command exit status on Linux without
  a VM or root access. Other hosts report an explicit platform skip. Run it
  after changing image ownership policy or its packaging/health callers; see
  `docs/image-metadata.md` for the declared tool contract.
  `repro build test-source-runtime` checks source-library and exposed catalog
  links, the loader, and rewritten shebang interpreters in the staged image's
  filesystem namespace. Staging uses the same resolver for `ldconfig` and
  refuses links that still point into the host build catalog.
  Its small compiled ELF fixtures use real `patchelf`, require neither root nor
  a VM, and reject host-only, dangling, cyclic, and non-source library targets
  before modifying the image. Run it after changing source-runtime normalization.
  Other hosts report an explicit Linux platform skip; a missing declared tool
  on Linux fails. This gate does not replace source-image or guest acceptance.
  `repro build test-image-boot-smoke` asserts the installed image's serial
  boot sequence through to a login prompt via the vm-harness sibling's
  `boot_smoke` engine. Its transcript-replay case always runs; the live boot
  runs only when an image is present (`REPROOS_IMAGE`, or the recipe's
  `recipes/reproos-image/build/reproos-installed.qcow2`) and otherwise
  reports a visible skip.
  `repro build test-verity-root` is the gate for the integrity-checked
  read-only root, in layers. Its always-on layer costs about two seconds and needs
  no tool: `repro/verity.nim` builds real dm-verity Merkle trees and is
  checked against a **known answer a real `veritysetup` produced**, then
  exercised for determinism, for corruption localisation, and against
  mutations that must redden it. Two heavier layers are opt-in and report
  a visible skip naming the remedy — `REPROOS_VERITY_TOOL_GATE=1` runs
  the shipped `recipes/reproos-image/scripts/build-verity-root.sh`
  against a real `mkfs.ext4` and `veritysetup` and compares the two
  implementations byte for byte, and `REPROOS_VERITY_GUEST_GATE=1` boots
  a real guest on the product's own `init-disk` initramfs over a real
  verity image and reads the result off its serial console (writing to
  `/` fails, writing to `/var` succeeds, a flipped byte makes the read of
  its block fail while the raw device still serves it, and a root hash
  that does not match refuses to boot at all). Run it after touching
  `repro/verity.nim`, `build-verity-root.sh`, `init-disk`, or the verity
  staging in `build-initramfs.sh`. `veritysetup` and `mkfs.ext4` are
  deliberately **not** declared tool identities: `cryptsetup` and
  `e2fsprogs` are from-source packages here, so naming them would make an
  always-on gate bootstrap them.
  `repro build test-uki` is the gate for the **unified kernel image** —
  the boot artifact the attested layout uses instead of GRUB. A UKI packs
  the kernel, the initrd, the kernel command line and a pinned EFI stub
  into one PE binary, so the dm-verity root hash the command line pins is
  inside the binary firmware measures; a `grub.cfg` on the ESP is an
  editable file that nothing measures, which is why the attested layout
  does not get one. `repro/uki.nim` owns the section set, the section
  order, the PE arithmetic and the composition of the command line from
  the keys `repro/verity.nim` declares; `tools/reproos_uki.nim` is the
  assembler the recipe's action runs, built by a `nim.c` edge and invoked
  with an argv rendered from the same typed request the action's declared
  inputs and outputs come from — there is no `objcopy` pipeline, no
  `ukify` and no shell script on that path, though the spawn itself is a
  `shell` edge because that is the only way the DSL runs a binary this
  project built. The
  EFI stub is **pinned by content**: `repro/uki.nim` carries its sha256
  and refuses any other bytes, because the stub's bytes are inside the
  measurement. Run this gate after touching `repro/uki.nim`,
  `tools/reproos_uki.nim`, the UKI action in
  `recipes/reproos-image/package.nim`, or the boot-path arm of
  `build-reproos-image.sh`. Its always-on layer assembles real images
  against a synthetic PE stub it builds from the specification, so it
  needs nothing installed and runs in about a second. A second layer runs
  automatically whenever a copy of the pinned stub is present — it
  assembles against the real stub and requires the shipped assembler to
  produce the same bytes as the module — and reports a visible skip
  naming the remedy when the stub is absent. A third is opt-in
  (`REPROOS_UKI_BOOT_GATE=1`) and boots a real UKI off a FAT ESP through
  OVMF in a transient QEMU guest, asserting on the `/proc/cmdline` the
  running kernel reports. `qemu`, `dosfstools` and `mtools` are
  deliberately **not** declared identities, for the same reason
  `veritysetup` is not. **Signing is out of scope**: every image is
  unsigned. `systemd-stub` measures the sections it consumes whether or
  not the PE is signed, so an unsigned UKI is fully attestable on the TPM
  tier; Secure Boot firmware refuses to load one, so `sbsign` and a
  key-custody story remain deferred.
  `repro build test-generations` is the gate for **generation switching
  under attestation**. The launch measurement is taken once, at boot, over
  the unified kernel image firmware loaded, and nothing extends it — so an
  attested instance runs **one generation for the lifetime of a boot**.
  Applying a new configuration *stages* it: `repro/generations.nim` writes
  the new unified kernel image into the ESP slot the machine is **not**
  running from, points the next boot at it, reports `reboot-required`, and
  leaves the running generation's artifacts untouched. Rollback re-selects
  the previous pair, which has been sitting in its slot since it was
  staged. Asking for the switch to take effect on the running system is
  **refused**, and the refusal is keyed on there being a measurement to
  contradict: the same write into the same slot is accepted when nothing
  is measured. `tools/reproos_generation.nim` is the shipped stager, built
  by a `nim.c` edge, and the image driver stages the installed image
  through it as generation `a`. The ESP index is **metadata**: firmware
  loads the bytes at `EFI/BOOT/BOOTX64.EFI` and reads no index, so
  `verifyGenerationStore` checks the index against the artifacts rather
  than trusting it. A generation's verity pair is named by `PARTUUID=` and
  never by filesystem label — a dm-verity hash device carries no
  filesystem, and with two slots staged both data carriers hold an ext4
  image with the same label. Run this gate after touching
  `repro/generations.nim`, `tools/reproos_generation.nim`, the attested arm
  of `build-reproos-image.sh`, or the attested layout preset. Its always-on
  layer stages real unified kernel images against a synthetic PE stub it
  builds from the specification, so it needs nothing installed. A second
  layer runs automatically whenever a copy of the pinned EFI stub is
  present and requires the shipped stager to produce the same store bytes
  as the module. A third is opt-in (`REPROOS_GENERATION_BOOT_GATE=1`) and
  boots one real FAT32 ESP four times through OVMF — the first generation,
  the first generation's own slot *after* the second has been staged, the
  second after the reboot, and the first again after a rollback — asserting
  on the `/proc/cmdline` each guest reports. `qemu`, `dosfstools` and
  `mtools` are deliberately **not** declared identities, for the same
  reason `veritysetup` is not.
  `repro build test-attested-carriers` is the gate for the step that puts
  the integrity-checked root **onto a disk**. An attested boot resolves a
  dm-verity root hash and two volume specifiers out of a command line that
  sits inside the binary firmware measures; all three are produced and
  pinned long before anything writes a partition, so without this step an
  image boots, resolves both specifiers to volumes that really exist, and
  finds them empty. `recipes/reproos-image/scripts/write-verity-carriers.sh`
  is the step, and `build-reproos-image.sh` runs it as **Phase 6b** — on
  the attested arm only, after `repro disk apply` and *before anything is
  mounted*, because a carrier holds no filesystem and there is nothing to
  mount. Carriers are found by matching the `PARTUUID=` specifiers off the
  measured command line against the partition table that was just written
  (`sgdisk -i`, no udev in the path), never by partition number and never
  by filesystem label: a Merkle tree has no filesystem, and both root
  carriers hold an ext4 image with the same label. The write is checked
  three ways — the carrier must be big enough, the bytes are read back and
  digested (no environment switch can turn that off), and `veritysetup
  verify` re-walks the whole tree **on the partitions** against the root
  hash the UKI pins. Run this gate after touching that script, the attested
  arm of `build-reproos-image.sh`, or the carrier declarations in
  `repro/disk_layouts.nim`. Its always-on layer reads the shipped sources
  and needs nothing installed; the opt-in layer
  (`REPROOS_ATTESTED_CARRIER_GATE=1`, ~2 min, needs `sudo` and the `nbd`
  module) applies the real `uefi-attested` document to a transient qcow2
  over a loopback NBD node and checks the disk rather than the script's own
  report, with two negatives — a `PARTUUID` that is on no partition must be
  refused rather than fall back to a partition number, and one flipped byte
  on the data carrier must redden the same verification.
  `repro build test-attested-root-order` is the gate for **the order the
  attested image is built in**, and it exists because getting that order
  wrong fails silently. The root of an attested image is a finished
  dm-verity image whose bytes a measured command line names, so every step
  that configures it — hostname, fstab, accounts, services, desktop — has
  to run *before* the hash is taken. The driver used to run them after,
  against the mounted root carrier; the verity data image is a valid ext4
  at offset 0 of that carrier, so the mount succeeded, every phase
  succeeded, the build exited 0, and the image shipped with a root that no
  longer matched the root hash on its own command line. Worse, a read-write
  mount that writes **nothing at all** is already enough to break the pair,
  because ext4 stamps the superblock's mount state on mount — so "write
  less" is not a fix and only the order is. The configuration therefore
  lives in `scripts/configure-installed-root.sh` with two callers:
  `scripts/stage-installed-root.sh`, a separate action that runs it over a
  plain directory before `build-verity-root.sh` takes the hash, and
  `build-reproos-image.sh`, which runs it on the mounted root of the
  writable-root layout only. `scripts/image-config.sh` is the one reader of
  a validated `auto-config.toml`, so the two halves cannot drift into two
  ideas of what an installed ReproOS is. Every mount the driver performs
  goes through `scripts/mount-guard.sh`, which is told which partitions a
  root hash covers (both generation slots) and **refuses** a write-capable
  mount of one with exit 78 rather than relying on the driver being
  careful. Run this gate after touching any of those five scripts, the
  staging action in `recipes/reproos-image/package.nim`, or the carrier
  declarations. Its always-on layer reads the shipped sources; the opt-in
  layer (`REPROOS_ATTESTED_ROOT_ORDER_GATE=1`, ~3 min, needs `sudo` and the
  `nbd` module) configures a real root with the shipped script, images it,
  applies the real layout to a transient qcow2 over a loopback NBD node,
  writes the pair, and verifies it against the root hash read back **out of
  the command line** — then falsifies the whole thing by bypassing the
  guard with a read-write mount that writes nothing and requiring the same
  verification to fail.
  `repro build test-measurement-manifest` is the gate for **what the image
  will measure**. Before the kernel starts, the EFI stub extends TPM
  PCR 11 with the unified kernel image's own sections — for each section,
  first its name and then its content, each as an ordinary TCG event — so
  the register is a pure function of the image and the build can write it
  down. It does: `repro build measurement-manifest` emits
  `reproos.attested-image.json`, a `reproos.attested-image.v1` document
  carrying the digests of the image's outputs and the expected register.
  The document is produced by `repro attest expect`, the same command a
  verifier runs when it rebuilds this image and compares, so there is one
  implementation of the schema and of the calculator rather than two
  opinions about what an image measures; `repro/attest.nim` owns only the
  EDGE — the typed request, which artifacts the document is a function
  of, which backends it asks for and where it lands. The confidential-VM
  tiers are emitted as **empty arrays** rather than omitted, because
  "this build computed no expectation for you" and "the key is missing"
  must not look alike. An unknown backend name is refused at the BUILD,
  by both the recipe's request validation and the shipped command: after
  a document is published, the only thing a verifier can do with an
  expectation nobody can compute is reject it. Run this gate after
  touching `repro/attest.nim`, `repro/uki.nim`, or the measurement-manifest
  action in `recipes/reproos-image/package.nim`. Its always-on layer
  exercises the schema and the calculator against real PE bytes assembled
  over a synthetic stub, in about a second. A second layer runs whenever
  the pinned EFI stub and a built `repro` binary are both present: it
  emits the document twice through the shipped command and requires the
  bytes to be identical, and it checks the measured section order back
  against the pinned stub's own table so the order cannot be a
  recollection. A third is opt-in (`REPROOS_PCR_BOOT_GATE=1`) and is the
  one that makes the calculator mean anything: two transient QEMU guests,
  each with its own swtpm-backed TPM 2.0, boot a real image through OVMF,
  load the TPM drivers and read PCR 11 back with a raw `TPM2_PCR_Read`.
  The second guest boots an image whose command line differs by one
  character, and the register must move to the *newly predicted* value —
  a calculator that returns a constant would pass the first guest and
  fail the second. `qemu`, `swtpm`, `dosfstools`, `mtools` and `xz` are
  deliberately **not** declared identities, for the same reason
  `veritysetup` is not.
- `repro build incus-acceptance` runs the projection, helper, reproducibility,
  live lifecycle, and installed-VM/container parity gates. Use the focused
  `test-incus-*` and `test-vm-incus-parity` targets while iterating.
- `repro lint` enforces the project-graph structure and source-only package
  closure before review.
- `repro run installer` opens the safe local installer preview.
- `repro run installer-screenshots` captures every reviewed installer view.
- `repro run installer-vm-frame -- FRAME.png` checks a captured VM console
  through GuiAssert OCR.
- `repro run installer-vm-screenshot` builds the ISO and performs a
  readiness-gated, self-cleaning VM capture plus GuiAssert check.
- `repro run cache-backfill` publishes and verifies every source package used
  by the ISO graph; use `-- --verify-only` for a read-only cache audit.
- `repro run boot-iso` and `repro run boot-image` leave VMs open for manual
  acceptance.
- `repro run vm-install` performs a real unattended install through
  `vm-harness` into a persistent target disk; `vm-verify-installed-boot`
  detaches the ISO and verifies installed-disk boot, enrollment, health, and
  key-only SSH with persistent host-key verification. `repro run vm-installed`
  installs if necessary and starts or reuses the retained Linux/libvirt VM.
  `vm-ssh` opens an interactive terminal; `vm-exec -- COMMAND...` executes a
  command in the same instance. Use `vm-status`, `vm-logs`, `vm-stop`, and
  `vm-destroy` to inspect or stop it. Runtime destroy preserves disk and trust
  state; `vm-install -- --replace` is destructive. Automatic lease expiry and
  Hyper-V SSH lifecycle acceptance are pending. Manual lifecycle and inspection
  commands belong in `devEnv` tasks with inherited streams, not captured build
  actions. Do not duplicate a task name as a run edge.
- `repro run image-ssh -- COMMAND...` boots a self-cleaning installed VM and
  runs a command over SSH; with no command it verifies the configured hostname.
- `repro run incus-launch` imports and starts the source-built container in an
  isolated Incus project. Use `incus-shell`, `incus-logs`, and `incus-destroy`
  for inspection and cleanup; `incus-import` only refreshes the image.
- `repro run incus-publish` publishes the built image as an immutable signed
  generation. `repro run incus-pull` verifies and imports one published
  generation into a selected Incus project.
- `repro build incus-remote-acceptance` pulls an exact signed generation onto
  an SSH-accessible independent Incus daemon and verifies a two-container
  network before cleaning its owned resources.
- `repro tasks` lists interactive workflows.

Use the local installer run edge for routine design work. Reserve VM boots for
final ISO, compositor, font, installation, and boot-environment acceptance.

Keep `repro.nim` declarative and concise. Put focused graph-construction helpers
in imported `package.nim` modules, expose stable action/output constants needed
by consumers, declare all inputs and executable identities, and cover graph
composition with structural tests.

Use stable action IDs for every action. Shell actions must declare the files
they invoke directly, attach executable identities for their tools, and either
declare outputs or be explicitly non-cacheable. Keep dependency declarations
literal until the DSL can extract computed lists; `repro lint` verifies that the
ISO and image declarations remain duplicate-free and exactly match the canonical
package set.

## Adding a Nim-based gate

A registered build action's `PATH` contains **exactly** the tool identities the
action declares — not the shell's `PATH`, not coreutils, not a compiler. A gate
that assumes an ambient development shell is, from the engine's point of view,
an unregistered gate: it will fail in CI and in a clean checkout while passing
on the author's machine. Four gates were added that way before this was caught;
the shape is now fixed in one place.

To add one:

1. Write `tests/test_<name>.nim`.
2. Write `tests/test-<name>.sh` as a *tool contract* and nothing else — source
   `tests/nim-gate.sh` and call `nim_gate_run <target-name>
   tests/test_<name>.nim <extra tool identities…>`. `nim`, `mkdir` and a C
   compiler are implicit — `nim c` lowers Nim to C and shells out to one. Use
   `nim_gate_require_any` for a capability more than one command can supply (a
   C++ compiler is `c++` under both the gcc and the clang wrapper). Never
   re-implement the preamble, and never resolve the repo root with `dirname` —
   a builtin cannot be a missing tool, so the first diagnostic stays the
   accurate one.
3. Register it in `repro/workflows.nim` with `tests/nim-gate.sh` among its
   `extraInputs`, the same identities in `.withToolIdentities([…])`, and every
   one of those names in the package's `uses:` block. A `uses:` entry alone
   puts nothing on an action's `PATH`; the action has to name it too.
4. Prefer an identity with **no** sibling from-source recipe in
   `reprobuild-packages` unless you mean to build it — under this project's
   from-source provisioning a completed source mirror is authoritative, so the
   identity you name is whatever that mirror contains rather than the pinned
   nixpkgs build. `clang` is the declared C/C++ compiler for exactly this
   reason: `gcc` has a from-source recipe whose mirror here is incomplete (its
   `cc1` cannot load `libmpc`/`libmpfr`/`libgmp`), while `clang` has none and
   falls through to the pinned nixpkgs channel. `nim`, `mkdir` and `git` have
   no source recipe either.
5. Do not let the gate inherit its compiler from the caller. `repro build`
   replaces only `PATH` in an action and inherits every other variable, so a
   developer shell's `CC=gcc` reaches the action and nixpkgs' `nim.cfg`
   substitutes it — nim then shells out to a `gcc` the hermetic `PATH` does not
   carry. `tests/nim-gate.sh` pins the compiler from the declared identities and
   exports `REPROOS_NIM_CC_ARGS` for any nested `nim c` the test itself runs.

A missing tool is a **declaration bug and a loud failure**, never a skip.
Skipping would turn a broken gate into a green one, which is worse than the
failure. Skips are for missing *artifacts* (an unbuilt kernel, an unbuilt
installer binary), never for missing tools.

Two checks enforce this. `repro lint` /
`repro build test-source-composition` re-checks the structure on every run.
The engine-level acceptance gate is run directly rather than through
`repro test`, because it drives `repro build` itself:

```
bash tests/test-nim-gates-through-the-engine.sh
```

It builds every Nim gate through the engine and then, as a negative case,
removes `nim` from one target's declared identities and requires that
`repro build` fails naming the missing tool.
