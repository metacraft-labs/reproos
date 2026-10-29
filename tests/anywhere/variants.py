"""Build takeover-environment variants with a chosen set of hardening controls.

The default installer carries every control (gate, ro-store, egress, caps). The
removal-negative gates build one variant per control with THAT control
removed, and the detection gate builds one without the gate (detection is
the defence for when confinement has already failed, so it is tested with
confinement absent).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
ALL_CONTROLS = ("gate", "ro-store", "egress", "caps")


def build_installer(controls: list[str] | tuple[str, ...]) -> Path:
    reprobuild = Path(os.environ.get("REPROBUILD_SOURCE_ROOT", REPO.parent / "reprobuild")).resolve()
    out = subprocess.run(
        ["nix-build", "--no-out-link", str(HERE / "fixture"), "-A", "installer",
         "--arg", "reproosSrc", str(REPO), "--arg", "reprobuildSrc", str(reprobuild),
         "--arg", "controls", "[ " + " ".join(json.dumps(c) for c in controls) + " ]"],
        check=True, capture_output=True, text=True).stdout.strip().splitlines()[-1]
    path = Path(out)
    got = json.loads((path / "manifest.json").read_text())["controls"]
    assert sorted(got) == sorted(controls), (got, controls)
    return path
