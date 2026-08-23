# ReproOS

ReproOS is a product repository. Changes land on `dev`; `stable` is the
published release and default branch.

Reusable package interfaces and source recipes belong in the sibling
`reprobuild-packages` repository. ReproOS owns image composition, installer
sources, boot assets, and product-specific tests.

Use Reprobuild as the only contributor command surface:

- `repro build installer`, `repro build rootfs`, `repro build iso`,
  `repro build image`, `repro build incus-projection`, and
  `repro build incus-image` produce the named artifacts from source.
- `repro build` produces the default artifact collection.
- `repro test` runs the complete product test collection; focused tests are
  named `test-*` build targets. Use `repro build test-iso-reproducibility`
  after changing boot media authoring or source-runtime composition, and
  `repro build test-installed-desktop` after changing the graphical session.
  `repro build test-installed-ssh` boots the installed image and verifies an
  SSH command through a loopback-only forwarded port.
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
