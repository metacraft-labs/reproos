# ReproOS

ReproOS is a product repository. Changes land on `dev`; `stable` remains the
published release branch and default branch.

The reusable package interfaces and source recipes live in the sibling
`reprobuild-packages` repository. Do not copy package definitions into this
repository. ReproOS owns only the image composition, installer, boot assets,
and product-specific tests.

Use the repository's `just` commands from the repository root:

- `just installer` builds and opens the real Qt installer in safe preview
  mode. It generates the durable configuration artifacts and simulates every
  installation phase without probing the host or modifying a disk.
- `just check` validates the source package composition.
- `just build-iso` builds the bootable ISO from the federated source catalog.
- `just test-iso` boots the ISO through vm-harness and checks its serial output.
- `just boot-iso` leaves a VM open for final interactive inspection.

Use `just installer` for normal installer development. Reserve VM boots for
final ISO, compositor, font, and boot-environment acceptance.
