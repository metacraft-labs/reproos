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


def run_projection(
    config: Path, output: Path, rootfs: Path | None = None
) -> subprocess.CompletedProcess:
    command = [
            sys.executable,
            str(PROJECTOR),
            "--config",
            str(config),
            "--artifacts-dir",
            str(ARTIFACTS),
            "--output-dir",
            str(output),
        ]
    if rootfs is not None:
        command.extend(["--rootfs", str(rootfs)])
    return subprocess.run(
        command,
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
        assert "deterministic address" in fields["network.ipv4"]["reason"]
        assert report["realization_profile"]["capabilities"]["network"] == {
            "provider": "incus-veth",
            "guest_mode": "profile-static-with-dhcp-fallback",
        }
        assert fields["disk.layout.type"]["classification"] == "ignored-with-reason"
        assert not fields["disk.layout.type"]["projected"]
        report_text = (first / "projection-report.json").read_text()
        password_hash = FIXTURE.read_text().split('password_hash = "', 1)[1].split('"', 1)[0]
        assert password_hash not in report_text
        difference_paths = {entry["path"] for entry in report["differences"]}
        assert {"hardware.boot", "services.display-manager", "install.target_device"} <= difference_paths

        rootfs = work / "rootfs"
        (rootfs / "etc").mkdir(parents=True)
        for name in ("passwd", "group", "shadow", "gshadow"):
            (rootfs / "etc" / name).write_text("root:x:0:0:root:/root:/bin/sh\n")
        projected = run_projection(FIXTURE, work / "with-rootfs", rootfs)
        assert projected.returncode == 0, projected.stderr
        assert "sshd:x:74:74:" in (rootfs / "etc" / "passwd").read_text()
        sshd_config = (rootfs / "etc" / "ssh" / "sshd_config").read_text()
        assert "UsePAM" not in sshd_config
        network = (rootfs / "usr" / "lib" / "reproos" / "incus-network").read_text()
        assert "REPROOS_INCUS_IPV4" in network
        assert "/proc/1/environ" in network
        assert "init_environment REPROOS_INCUS_GATEWAY" in network
        assert "udhcpc" in network
        generation = report["configuration_sha256"]
        assert (rootfs / "etc" / "repro").is_symlink()
        current = rootfs / "var" / "lib" / "reproos" / "current-generation"
        assert current.readlink() == Path(f"generations/{generation}")
        generation_root = (
            rootfs / "var" / "lib" / "reproos" / "generations" / generation
        )
        assert (generation_root / "generation").read_text().strip() == generation
        assert (generation_root / "system.nim").is_file()
        generation_tool = (
            rootfs / "usr" / "sbin" / "reproos-generation"
        ).read_text()
        for command in ("stage)", "switch)", "rollback)", "current)"):
            assert command in generation_tool
        assert "mv -Tf" in generation_tool
        assert "/usr/bin/busybox find" in generation_tool
        health = (
            rootfs / "usr" / "lib" / "reproos" / "container-health"
        ).read_text()
        assert "reproos-generation current" in health
        assert "generation=%s" in health

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
