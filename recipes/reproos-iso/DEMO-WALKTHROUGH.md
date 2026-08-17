# ISO Demo Walkthrough

1. Run `repro build iso` from the ReproOS repository root.
2. Run `repro build test-iso` to boot the ISO and assert the serial kernel
   banner.
3. Run `repro run boot-iso` for an interactive VM that remains available after
   startup.

The ISO is written to `recipes/reproos-iso/build/reproos.iso`.
