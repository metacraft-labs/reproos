#!/usr/bin/env python3
"""Exercise isolated Incus setup and cleanup without requiring an Incus daemon."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/reproos-incus.sh"


FAKE_INCUS = r"""#!/usr/bin/env python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with Path(os.environ["FAKE_INCUS_LOG"]).open("a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\n")

project = os.environ["REPROOS_INCUS_PROJECT"]
phase = os.environ["FAKE_INCUS_PHASE"]
if args == ["info"]:
    raise SystemExit(0)
if args == ["project", "show", project]:
    raise SystemExit(1 if phase == "import" else 0)
if args[:3] == ["--project", project, "profile"] and args[3:] == ["device", "show", "default"]:
    print("root:")
    if phase == "destroy":
        print("eth0:")
    raise SystemExit(0)
if args[:2] == ["network", "show"] and args[2:] == [os.environ["REPROOS_INCUS_NETWORK"]]:
    raise SystemExit(1 if phase == "import" else 0)
if args[:2] == ["network", "get"]:
    print("10.231.44.1/24")
    raise SystemExit(0)
if args[:3] == ["--project", project, "image"] and args[3] == "list":
    if phase == "destroy":
        print("fake-fingerprint")
    raise SystemExit(0)
raise SystemExit(0)
"""


FAKE_VM_HARNESS = """#!/usr/bin/env python3
raise SystemExit(0)
"""


def run_helper(command: str, phase: str, temp: Path) -> list[str]:
    log = temp / f"{phase}.log"
    image = temp / "reproos-incus.tar.xz"
    manifest = temp / "incus-baseline.manifest"
    image.touch()
    image.write_bytes(b"image")
    manifest.write_text("manifest\n", encoding="utf-8")

    fake_incus = temp / "incus"
    fake_vmh = temp / "vm-harness"
    fake_incus.write_text(FAKE_INCUS, encoding="utf-8")
    fake_vmh.write_text(FAKE_VM_HARNESS, encoding="utf-8")
    fake_incus.chmod(0o755)
    fake_vmh.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "FAKE_INCUS_LOG": str(log),
            "FAKE_INCUS_PHASE": phase,
            "REPROOS_INCUS_ALIAS": "test-image",
            "REPROOS_INCUS_IMAGE": str(image),
            "REPROOS_INCUS_INSTANCE": "test-instance",
            "REPROOS_INCUS_NETWORK": "test-network",
            "REPROOS_INCUS_PROJECT": "test-project",
            "VMH_INCUS_CMD": str(fake_incus),
            "VM_HARNESS_BIN": str(fake_vmh),
        }
    )
    subprocess.run(["bash", str(HELPER), command], env=env, check=True)
    return log.read_text(encoding="utf-8").splitlines()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="reproos-incus-helper-") as raw_temp:
        temp = Path(raw_temp)
        imported = run_helper("import", "import", temp)
        assert any(
            line.startswith(
                "network create test-network --type=bridge "
            )
            for line in imported
        ), imported
        assert "-c features.networks=false" in next(
            line for line in imported if line.startswith("project create ")
        )
        assert any(
            "profile set default environment.REPROOS_INCUS_IPV4=10.231.44.2/24 "
            "environment.REPROOS_INCUS_GATEWAY=10.231.44.1" in line
            for line in imported
        ), imported
        assert any("network=test-network name=eth0" in line for line in imported), imported

        destroyed = run_helper("destroy", "destroy", temp)
        expected = {
            "--project test-project profile device remove default eth0",
            "network delete test-network",
            "--project test-project image delete fake-fingerprint",
            "project delete test-project",
        }
        assert expected.issubset(set(destroyed)), destroyed
        assert all("--force" not in line for line in destroyed), destroyed

    print("ReproOS Incus helper setup and cleanup: PASS")


if __name__ == "__main__":
    main()
