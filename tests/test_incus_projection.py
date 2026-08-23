#!/usr/bin/env python3
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PROJECTOR = ROOT / "recipes/reproos-container/scripts/project-incus-config.py"
FIXTURE = ROOT / "tests/fixtures/auto-config-minimal.toml"
ARTIFACTS = ROOT / "tests/golden/installer-artifacts"


def run_projection(config: Path, output: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(PROJECTOR),
            "--config",
            str(config),
            "--artifacts-dir",
            str(ARTIFACTS),
            "--output-dir",
            str(output),
        ],
        text=True,
        capture_output=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="reproos-incus-projection-") as raw:
        work = Path(raw)
        first = work / "first"
        second = work / "second"
        assert run_projection(FIXTURE, first).returncode == 0
        assert run_projection(FIXTURE, second).returncode == 0
        assert (first / "projection-report.json").read_bytes() == (
            second / "projection-report.json"
        ).read_bytes()

        report = json.loads((first / "projection-report.json").read_text())
        assert report["realization_profile"]["kind"] == "incus-system-container"
        assert report["realization_profile"]["privilege"] == "unprivileged"
        assert report["realization_profile"]["capabilities"]["kernel"] == {
            "configurable": False,
            "provider": "host",
        }
        fields = {field["path"]: field for field in report["fields"]}
        assert fields["hostname"]["classification"] == "shared"
        assert fields["network.ipv4"]["classification"] == "container-specific"
        assert fields["disk.layout.type"]["classification"] == "ignored-with-reason"
        assert not fields["disk.layout.type"]["projected"]
        report_text = (first / "projection-report.json").read_text()
        password_hash = FIXTURE.read_text().split('password_hash = "', 1)[1].split('"', 1)[0]
        assert password_hash not in report_text
        difference_paths = {entry["path"] for entry in report["differences"]}
        assert {"hardware.boot", "services.display-manager", "install.target_device"} <= difference_paths

        unsupported = work / "unsupported.toml"
        shutil.copyfile(FIXTURE, unsupported)
        unsupported.write_text(
            unsupported.read_text().replace('ipv4 = "dhcp"', 'ipv4 = "static"')
        )
        rejected = run_projection(unsupported, work / "rejected")
        assert rejected.returncode == 2
        assert "INCUS_CONFIG_UNSUPPORTED_NETWORK_MODE" in rejected.stderr

    print("Incus configuration projection: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
