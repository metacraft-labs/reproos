#!/usr/bin/env python3
"""Install and verify ReproOS disks through vm-harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tomllib
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ISO = ROOT / "recipes/reproos-iso/build/reproos-unattended.iso"
EMBEDDED_PROFILE = ROOT / "tests/fixtures/auto-config-minimal.toml"
INSTALL_MARKER = "=== REPROOS-INSTALLER-AUTORUN-END RC=0 ==="
INSTALLED_HEALTH_MARKER = "REPROOS_HEALTH:PASS"
ENROLLMENT_LABEL = "REPROOS_ENROLL"


class VmWorkflowError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def default_disk_name() -> str:
    if platform.system() == "Windows":
        return "reproos-installed.vhdx"
    return "reproos-installed.qcow2"


def default_vm_harness() -> str:
    return os.environ.get(
        "REPROOS_VM_HARNESS_BIN",
        os.environ.get("VM_HARNESS_BIN", "vm-harness"),
    )


def run_vmh(vmh: str, args: list[str]) -> None:
    command = [vmh, *args]
    print("+ " + subprocess.list2cmdline(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise VmWorkflowError(
            f"vm-harness exited with status {completed.returncode}"
        )


def run_checked(label: str, command: list[str]) -> None:
    print("+ " + subprocess.list2cmdline(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise VmWorkflowError(
            f"{label} exited with status {completed.returncode}"
        )


def profile_hostname(profile: Path) -> str:
    value = tomllib.loads(profile.read_text(encoding="ascii")).get("hostname")
    if not isinstance(value, str) or not value:
        raise VmWorkflowError(f"machine profile has no hostname: {profile}")
    return value


def enrollment_paths(state: Path) -> dict[str, Path]:
    root = state / "enrollment"
    return {
        "root": root,
        "private_key": root / "id_ed25519",
        "public_key": root / "id_ed25519.pub",
        "media": root / "media",
        "iso": state / "reproos-enrollment.iso",
        "known_hosts": state / "ssh_known_hosts",
    }


def prepare_enrollment(args: argparse.Namespace, state: Path) -> dict[str, Path]:
    paths = enrollment_paths(state)
    required = [
        paths["private_key"],
        paths["public_key"],
        paths["media"] / "machine-id",
        paths["media"] / "authorized_keys",
        paths["iso"],
    ]
    if args.replace:
        if paths["root"].exists():
            shutil.rmtree(paths["root"])
        if paths["iso"].exists():
            paths["iso"].unlink()
        if paths["known_hosts"].exists():
            paths["known_hosts"].unlink()
    elif any(path.exists() for path in [*required, paths["known_hosts"]]):
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise VmWorkflowError(
                "incomplete enrollment state; pass --replace: " +
                ", ".join(missing)
            )
        return paths

    paths["media"].mkdir(parents=True, exist_ok=True)
    run_checked("ssh-keygen", [
        args.ssh_keygen,
        "-q", "-t", "ed25519", "-N", "",
        "-C", "reproos-vm-acceptance",
        "-f", str(paths["private_key"]),
    ])
    try:
        paths["private_key"].chmod(0o600)
    except OSError:
        pass
    public_key = paths["public_key"].read_text(encoding="ascii").strip()
    if not public_key.startswith("ssh-ed25519 "):
        raise VmWorkflowError("ssh-keygen did not produce an Ed25519 public key")
    (paths["media"] / "authorized_keys").write_text(
        public_key + "\n", encoding="ascii")
    (paths["media"] / "machine-id").write_text(
        uuid.uuid4().hex + "\n", encoding="ascii")
    run_checked("xorriso", [
        args.xorriso,
        "-as", "mkisofs", "-quiet",
        "-V", ENROLLMENT_LABEL,
        "-J", "-r",
        "-o", str(paths["iso"]),
        str(paths["media"]),
    ])
    if not paths["iso"].is_file() or paths["iso"].stat().st_size == 0:
        raise VmWorkflowError(
            f"xorriso did not produce enrollment media: {paths['iso']}"
        )
    return paths


def install(args: argparse.Namespace, passthrough: list[str]) -> None:
    state = args.state_dir.resolve()
    target = (args.target_disk or state / default_disk_name()).resolve()
    iso = args.iso.resolve()
    profile = EMBEDDED_PROFILE.resolve()
    if target.suffix.lower() not in {".qcow2", ".vhdx"}:
        raise VmWorkflowError("target disk must end in .qcow2 or .vhdx")
    for label, path in (("unattended ISO", iso), ("embedded profile", profile)):
        if not path.is_file():
            raise VmWorkflowError(f"{label} is missing: {path}")
    state.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if not args.replace:
            raise VmWorkflowError(
                f"target disk already exists: {target}; pass --replace to "
                "perform a fresh installation"
            )
        if not target.is_file():
            raise VmWorkflowError(f"refusing to replace non-file target: {target}")
        target.unlink()
    manifest_path = state / "install-manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()
    enrollment = prepare_enrollment(args, state)

    diagnostics = state / "install"
    if args.replace and diagnostics.exists():
        shutil.rmtree(diagnostics)
    diagnostics.mkdir(parents=True, exist_ok=True)
    run_vmh(args.vm_harness, [
        "install",
        "--backend", args.backend,
        "--source-image", str(iso),
        "--kind", "iso",
        "--target-disk", str(target),
        "--disk-gb", str(args.disk_gb),
        "--cpus", str(args.cpus),
        "--memory-mb", str(args.memory_mb),
        "--acceleration", args.acceleration,
        "--graphics", "vnc",
        "--video", "virtio",
        "--expect", INSTALL_MARKER,
        "--timeout-sec", str(args.timeout_sec),
        "--output-dir", str(diagnostics),
        *passthrough,
    ])
    if not target.is_file() or target.stat().st_size == 0:
        raise VmWorkflowError(f"vm-harness did not produce a target disk: {target}")

    enrollment_machine_id = (
        enrollment["media"] / "machine-id"
    ).read_text(encoding="ascii").strip()
    manifest = {
        "schema_version": 1,
        "backend_request": args.backend,
        "cpus": args.cpus,
        "disk_format": target.suffix.lower().lstrip("."),
        "disk_gb": args.disk_gb,
        "installed_disk": target.name,
        "installed_disk_sha256": sha256(target),
        "installer_iso": iso.name,
        "installer_iso_sha256": sha256(iso),
        "embedded_machine_profile": profile.name,
        "embedded_machine_profile_sha256": sha256(profile),
        "enrollment_iso": enrollment["iso"].name,
        "enrollment_iso_sha256": sha256(enrollment["iso"]),
        "enrollment_machine_id": enrollment_machine_id,
        "authorized_key_sha256": sha256(enrollment["public_key"]),
        "expected_hostname": profile_hostname(profile),
        "ssh_user": "repro",
        "ssh_host_key_alias": "reproos-" + enrollment_machine_id,
        "memory_mb": args.memory_mb,
        "required_install_marker": INSTALL_MARKER,
    }
    temporary = manifest_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(manifest_path)
    print(f"installed disk: {target}")
    print(f"enrollment media: {enrollment['iso']}")
    print(f"launch manifest: {manifest_path}")


def boot_installed(args: argparse.Namespace,
                   vmh_options: list[str],
                   guest_command: list[str],
                   diagnostics_name: str) -> None:
    state = args.state_dir.resolve()
    target = (args.target_disk or state / default_disk_name()).resolve()
    if not target.is_file():
        raise VmWorkflowError(f"installed disk is missing: {target}")
    manifest_path = state / "install-manifest.json"
    if not manifest_path.is_file():
        raise VmWorkflowError(f"install manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    enrollment = enrollment_paths(state)
    for label, path in (
        ("enrollment ISO", enrollment["iso"]),
        ("SSH private key", enrollment["private_key"]),
    ):
        if not path.is_file():
            raise VmWorkflowError(f"{label} is missing: {path}")
    expected_hostname = manifest.get("expected_hostname")
    ssh_user = manifest.get("ssh_user")
    ssh_host_key_alias = manifest.get("ssh_host_key_alias")
    if not isinstance(expected_hostname, str) or not expected_hostname:
        raise VmWorkflowError("install manifest has no expected_hostname")
    if not isinstance(ssh_user, str) or not ssh_user:
        raise VmWorkflowError("install manifest has no ssh_user")
    if not isinstance(ssh_host_key_alias, str) or not ssh_host_key_alias:
        raise VmWorkflowError("install manifest has no ssh_host_key_alias")
    media_kind = "vhdx" if target.suffix.lower() == ".vhdx" else "qcow2"
    diagnostics = state / diagnostics_name
    diagnostics.mkdir(parents=True, exist_ok=True)
    run_vmh(args.vm_harness, [
        "boot",
        "--backend", args.backend,
        "--source-image", str(target),
        "--kind", media_kind,
        "--secondary-iso", str(enrollment["iso"]),
        "--guest", "linux",
        "--cpus", str(args.cpus),
        "--memory-mb", str(args.memory_mb),
        "--acceleration", args.acceleration,
        "--graphics", "vnc",
        "--video", "virtio",
        "--expect", INSTALLED_HEALTH_MARKER,
        "--timeout-sec", str(args.timeout_sec),
        "--ssh-ready-timeout-sec", str(args.ssh_ready_timeout_sec),
        "--ssh-forward-port", "auto",
        "--ssh-user", ssh_user,
        "--ssh-private-key", str(enrollment["private_key"]),
        "--ssh-known-hosts", str(enrollment["known_hosts"]),
        "--ssh-host-key-alias", ssh_host_key_alias,
        "--output-dir", str(diagnostics),
        *vmh_options,
        "--", *guest_command,
    ])


def verify_installed_boot(args: argparse.Namespace,
                          passthrough: list[str]) -> None:
    manifest_path = args.state_dir.resolve() / "install-manifest.json"
    if not manifest_path.is_file():
        raise VmWorkflowError(f"install manifest is missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    expected_hostname = manifest.get("expected_hostname", "")
    probe = (
        "health=/var/lib/reproos/health-status; "
        "i=0; while ! grep -qx REPROOS_HEALTH:PASS \"$health\" "
        "2>/dev/null && [ $i -lt 240 ]; "
        "do sleep 1; i=$((i + 1)); done; "
        "test \"$(hostname)\" = " + shlex.quote(expected_hostname) + "; "
        "grep -qx REPROOS_HEALTH:PASS \"$health\"; "
        "test -s /var/lib/reproos/enrollment.complete; "
        "test -s /var/lib/reproos/identity.json; "
        "printf 'REPROOS_SSH_ACCEPTANCE:PASS hostname=%s\\n' "
        "\"$(hostname)\""
    )
    boot_installed(
        args,
        passthrough,
        ["/bin/sh", "-c", probe],
        "verify-installed-boot")


def ssh_installed(args: argparse.Namespace, command: list[str]) -> None:
    if command[:1] == ["--"]:
        command = command[1:]
    boot_installed(args, [], command or ["hostname"], "ssh")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "command", choices=["install", "verify-installed-boot", "ssh"])
    result.add_argument("--state-dir", type=Path, default=Path(
        os.environ.get("REPROOS_VM_STATE_DIR", ROOT / "build/reproos-vm")))
    result.add_argument("--target-disk", type=Path)
    result.add_argument("--iso", type=Path, default=Path(
        os.environ.get("REPROOS_UNATTENDED_ISO", DEFAULT_ISO)))
    result.add_argument("--vm-harness", default=default_vm_harness())
    result.add_argument("--backend", default=os.environ.get(
        "REPROOS_VM_BACKEND", "auto"))
    result.add_argument(
        "--acceleration",
        choices=["auto", "kvm", "tcg"],
        default=os.environ.get("REPROOS_VM_ACCELERATION", "auto"),
    )
    result.add_argument("--cpus", type=int, default=2)
    result.add_argument("--memory-mb", type=int, default=4096)
    result.add_argument("--disk-gb", type=int, default=12)
    result.add_argument("--timeout-sec", type=int, default=10800)
    result.add_argument(
        "--ssh-ready-timeout-sec",
        type=int,
        default=int(os.environ.get("REPROOS_VM_SSH_READY_TIMEOUT_SEC", "300")),
    )
    result.add_argument("--replace", action="store_true")
    result.add_argument("--ssh-keygen", default=os.environ.get(
        "SSH_KEYGEN_BIN", "ssh-keygen"))
    result.add_argument("--xorriso", default=os.environ.get(
        "XORRISO_BIN", "xorriso"))
    return result


def main(argv: list[str]) -> int:
    args, passthrough = parser().parse_known_args(argv)
    if passthrough[:1] == ["--"]:
        passthrough = passthrough[1:]
    try:
        for name in ("cpus", "memory_mb", "disk_gb", "timeout_sec"):
            if getattr(args, name) <= 0:
                raise VmWorkflowError(
                    "--" + name.replace("_", "-") + " must be positive"
                )
        if args.command == "install":
            install(args, passthrough)
        elif args.command == "verify-installed-boot":
            if args.replace:
                raise VmWorkflowError(
                    "--replace is valid only with the install command"
                )
            verify_installed_boot(args, passthrough)
        else:
            if args.replace:
                raise VmWorkflowError(
                    "--replace is valid only with the install command"
                )
            ssh_installed(args, passthrough)
        return 0
    except (OSError, VmWorkflowError) as error:
        print(f"reproos-vm: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
