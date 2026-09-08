#!/usr/bin/env python3
"""Live persistence gate for an already installed ReproOS test VM."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    state = Path(os.environ.get("REPROOS_VM_STATE_DIR",
                                ROOT / "build/e2e-unattended-vm")).resolve()
    if not (state / "install-manifest.json").is_file():
        raise RuntimeError("run unattended installed-disk acceptance before this gate")
    command = [sys.executable, str(ROOT / "tools/reproos-vm.py")]

    def run(operation: str, *arguments: str) -> str:
        completed = subprocess.run(
            [*command, operation, "--state-dir", str(state), *arguments],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True,
        )
        return completed.stdout

    def status() -> dict:
        return json.loads(run("status"))

    def guest(*arguments: str) -> str:
        return run("exec", "--", *arguments)

    def identity() -> dict:
        return json.loads(guest("cat", "/var/lib/reproos/identity.json"))

    def require(condition: bool, message: str) -> None:
        if not condition:
            raise RuntimeError(message)

    evidence = {"schema_version": 1, "passed": False, "transitions": []}
    try:
        run("installed")
        initial = status()
        evidence["initial"] = initial
        require(initial["state"] == "running" and initial["ownership"] == "matched",
                "initial VM ownership or readiness was not established")
        require(bool(initial["active_disk"]), "active writable disk is missing")
        initial_identity = identity()
        manifest = json.loads((state / "install-manifest.json").read_text())
        receipt = json.loads(guest("cat", "/var/lib/reproos/installation-receipt.json"))
        root_mount = json.loads(guest("findmnt", "--json", "--output",
                                      "SOURCE,TARGET,FSTYPE", "/"))
        require(initial_identity.get("machine_id") == manifest["enrollment_machine_id"],
                "guest machine identity does not match enrollment")
        require(initial_identity.get("install_source") == "unattended-installer" and
                receipt.get("install_source") == "unattended-installer",
                "guest did not identify the unattended installer as its source")
        generation = initial_identity.get("generation_id", "")
        require(isinstance(generation, str) and re.fullmatch(r"[0-9a-f]{64}", generation) is not None
                and receipt.get("configuration_generation") == generation,
                "guest generation does not match its installation receipt")
        filesystems = root_mount.get("filesystems", [])
        require(len(filesystems) == 1 and filesystems[0].get("target") == "/" and
                filesystems[0].get("fstype") in {"ext4", "btrfs", "xfs"},
                "guest root is not an installed filesystem")
        evidence["installation_receipt"] = receipt
        evidence["root_mount"] = root_mount
        trust = (state / "ssh_known_hosts").read_bytes()
        require(bool(trust), "first connection did not persist the SSH host key")
        token = uuid.uuid4().hex
        guest("/bin/sh", "-eu", "-c",
              'printf "%s\\n" "$1" > "$HOME/.reproos-vm-lifecycle"; sync',
              "vm-lifecycle", token)

        for transition, expected in [("reconnect", "running"),
                                     ("stop", "stopped"),
                                     ("destroy", "destroyed")]:
            if transition != "reconnect":
                run(transition)
            stopped = status()
            require(stopped["state"] == expected,
                    f"{transition} left unexpected state: {stopped['state']}")
            run("installed")
            current = status()
            for key in ("instance_id", "active_disk", "source_image", "nvram_path"):
                require(current[key] == initial[key],
                        f"{transition} replaced persistent {key}")
            require(current["state"] == "running" and current["ownership"] == "matched",
                    f"{transition} did not restore the owned running VM")
            require(guest("/bin/sh", "-c", 'cat "$HOME/.reproos-vm-lifecycle"').strip() == token,
                    f"{transition} lost a guest filesystem write")
            require(identity() == initial_identity,
                    f"{transition} changed enrolled machine identity")
            require((state / "ssh_known_hosts").read_bytes() == trust,
                    f"{transition} changed host-side SSH trust")
            run("verify-installed-boot")
            evidence["transitions"].append({"operation": transition, "status": current})

        evidence["identity"] = initial_identity
        evidence["known_hosts_sha256"] = hashlib.sha256(trust).hexdigest()
        evidence["passed"] = True
        print("persistent installed VM lifecycle and SSH identity: PASS")
    finally:
        try:
            # Keep disk/trust evidence, but leave no test VM running.
            run("destroy")
            evidence["cleanup"] = "runtime destroyed; persistent state retained"
        except subprocess.CalledProcessError:
            evidence["passed"] = False
            evidence["cleanup"] = "failed; inspect retained harness receipt and logs"
            raise
        finally:
            temporary = state / "lifecycle.json.tmp"
            temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
            temporary.replace(state / "lifecycle.json")


if __name__ == "__main__":
    main()
