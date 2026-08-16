# ReproOS Installer Visual Review Brief

## What You Are Reviewing

ReproOS is a reproducible, source-built desktop operating system. Its installer
is a focused Qt Quick wizard that turns a small set of choices into transparent
configuration artifacts and an installed system. It runs full-screen in a Sway
kiosk session, so the wizard itself must provide all navigation and status.

## Design Goals

- Quiet, professional system-tool design with strong information hierarchy.
- Neutral charcoal surfaces, crisp light text, green primary actions, and amber
  only for destructive warnings. Avoid a one-hue blue or purple appearance.
- Dense enough for repeated technical use without looking like a dashboard.
- Honest about available functionality; unavailable choices must not look live.
- Keyboard-accessible controls, readable contrast, and stable layouts at
  1280x800, the Hyper-V console's 1024x768, and 960x720.
- Cards are reserved for selectable repeated items. Sections and page content
  remain unframed.

## What Is Expected on Each Screenshot

The reviewer must report missing, clipped, overlapping, or placeholder content
before judging aesthetics. Any view missing a required element rates at most
4/10.

### welcome

- ReproOS is the dominant first-viewport signal.
- A concise explanation of the standard configuration path.
- Existing-configuration options are clearly unavailable, not broken controls.
- Persistent ten-step progress and Back/Continue navigation are visible.

### locale

- Locale and timezone selectors plus a hostname field.
- Current selections are legible without opening menus.
- The page explains where these settings are applied.

### keyboard

- Keyboard-layout selector and a full-width test field.
- The selected keymap and test purpose are immediately understandable.

### users

- Full name, username, password, confirmation, and administrator control.
- Password validation has reserved space and does not shift the layout.
- Secret fields are visually distinct from ordinary text fields.

### disk

- Selected disk identity/capacity, refresh action, and layout choices.
- Destructive-data warning has appropriate visual weight.
- Wipe acknowledgement is visible without scrolling at both sizes.

### deSelect

- Sway is shown as the included source-built desktop.
- The screen does not claim unavailable desktop sessions can be installed.

### activities

- Curated activity choices are scan-friendly and have stable selection states.
- The default and selected activities are distinguishable without relying only
  on color.

### summary

- Human-readable configuration summary appears before the generated source.
- The generated `system.nim` preview is readable and clearly secondary.
- Target disk and destructive consequence remain visible.

### install

- Current phase, progress, and install log are visible.
- The destructive start action is distinct and cannot be mistaken for Continue.
- Empty/pre-install state looks intentional.

### finished

- Completion is unmistakable and Reboot is the primary next action.
- The screen identifies the durable configuration files without verbose prose.

## What to Evaluate

1. Correct expected state and content
2. Alignment and consistent edges
3. Spacing and density
4. Color harmony and accessible contrast
5. Typography hierarchy
6. Visual weight and action priority
7. Professional polish
8. Compact-size adaptation and text fit

## How to Report

- Stay under 250 words per view.
- Start with `Expected elements: present` or list what is missing.
- Give specific findings with locations.
- End with the two highest-priority fixes and a 1-10 rating.

## Regression Workflow

Run `repro test-installer-visuals` after changing installer QML. The task
recaptures all 30 view/size combinations and compares them with the reviewed
goldens through GuiAssert. After completing a visual review, accept an intended
change with `bash tests/test-installer-visuals.sh --update-goldens`, inspect the
new complete set, and commit the QML and goldens together.

For a booted Hyper-V integration check, open the VM in Virtual Machine
Connection, capture it with `tools/capture-hyperv-vm.ps1`, then run
`tests/test-installer-vm-frame.sh FRAME.png`. This verifies the real console
contains the expected welcome controls through GuiAssert OCR.
