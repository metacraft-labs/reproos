check:
  pwsh -NoProfile -File tests/check_source_composition.ps1

build-iso:
  repro build recipes/reproos-iso --tool-provisioning=from-source

build-image:
  repro build recipes/reproos-image --tool-provisioning=from-source

boot-iso:
  vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --keep

test-iso:
  vm-harness boot --backend auto --source-image recipes/reproos-iso/.repro/output/install --kind iso --expect "Linux version" --timeout-sec 300
