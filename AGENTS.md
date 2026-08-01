# ReproOS

ReproOS is a product repository. Changes land on `dev`; `stable` remains the
published release branch and default branch.

The reusable package interfaces and source recipes live in the sibling
`reprobuild-packages` repository. Do not copy package definitions into this
repository. ReproOS owns only the image composition, installer, boot assets,
and product-specific tests.

Use `repro build-iso`, `repro boot-iso`, and `repro test-iso` from the
repository root. Package builds default to the federated source catalog.

