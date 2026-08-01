# ISO Demo Walkthrough

1. Run `repro build-iso` from the ReproOS repository root.
2. Run `repro test-iso` to boot the ISO and assert the serial kernel banner.
3. Run `repro boot-iso` for an interactive VM that remains available after
   startup.

The built ISO is published below
`recipes/reproos-iso/.repro/output/install`. vm-harness accepts that directory
and selects its newest ISO automatically.
