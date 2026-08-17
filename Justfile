check:
  pwsh -NoProfile -File tests/check_source_composition.ps1

# Build and launch the installer as a regular, non-destructive desktop app.
installer:
  {{ if os() == "windows" { "pwsh -NoProfile -File tools/run-installer-preview.ps1" } else { "bash tools/run-installer-preview.sh" } }}

build-iso:
  repro build recipes/reproos-iso --tool-provisioning=from-source

build-image:
  repro build recipes/reproos-image --tool-provisioning=from-source

boot-iso:
  vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --keep

test-iso:
  vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --expect "Linux version" --timeout-sec 300
