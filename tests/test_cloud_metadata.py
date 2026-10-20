#!/usr/bin/env python3
"""Cloud Images M1: every metadata adapter reaches the one first-boot contract.

``test_cloud_first_boot_contract_across_metadata_adapters`` normalizes the
fixture for each provider, checks that the enrollment directories differ only
where the instance differs, then runs the real ``reproos-first-boot-enroll``
against each one and checks the installed identity it records.

``test_cloud_metadata_spoofing_fails_identity_checks`` feeds conflicting or
changed identity and checks that nothing is written: no key, no machine-id.

The fixtures under ``tests/fixtures/cloud-metadata/`` follow the response
shapes in each provider's documentation (see
reprobuild-pm spec/ReproOS-Cloud-Image-Provider-Matrix.md). They are not
captured from live instances; recording real responses is part of the
provider lanes (Cloud Images M3-M7).
"""

from __future__ import annotations

import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/reproos-cloud-metadata.py"
SPEC = importlib.util.spec_from_file_location("reproos_cloud_metadata", TOOL)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXTURES = ROOT / "tests/fixtures/cloud-metadata"
ENROLL = ROOT / "recipes/reproos-image/scripts/reproos-first-boot-enroll"
KEY = "ssh-ed25519 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE= cloud-test"
EXPECTED = {
    "nocloud": ("iid-reproos-nocloud-0001", "reproos-cloud-nocloud"),
    "configdrive": ("6f2b6a8e-4f0f-4a43-9f6b-1d6a1c2f0001", "reproos-cloud-configdrive"),
    "ec2": ("i-0abc1234def567890", "ip-10-0-0-5"),
    "gce": ("4520031799277581759", "reproos-cloud-gce"),
    "azure": ("02aab8a4-74ef-476e-8182-f6d2ba4166a6", "reproos-cloud-azure"),
    "oci": ("ocid1.instance.oc1.eu-frankfurt-1.anthaljr0001", "reproos-cloud-oci"),
    "hetzner": ("41234567", "reproos-cloud-hetzner"),
    "digitalocean": ("2756294", "reproos-cloud-digitalocean"),
}


def installed_root(base: Path) -> Path:
    """A root-prefixed filesystem the enroll script can run against."""
    root = base / "root"
    for d in ("etc/repro", "etc/reproos", "var/lib/reproos"):
        (root / d).mkdir(parents=True)
    (root / "etc/repro/auto-config.toml").write_bytes(
        (ROOT / "tests/fixtures/auto-config-minimal.toml").read_bytes())
    (root / "etc/repro/generation").write_text("generation-test\n")
    (root / "var/lib/reproos/install-source").write_text("cloud-image\n")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    (root / "etc/shadow").write_text("root:!:::::::\n")
    (root / "etc/group").write_text("root:x:0:\nwheel:x:10:\n")
    (root / "etc/gshadow").write_text("root:*::\nwheel:*::\n")
    return root


def run_enroll(root: Path, enrollment: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ,
               REPROOS_ROOT=str(root),
               REPROOS_ENROLLMENT_DIR=str(enrollment),
               REPROOS_SSH_HOST_KEY_FINGERPRINT="SHA256:test-host-key",
               REPROOS_TEST_MODE="1")
    return subprocess.run(["bash", str(ENROLL)], env=env, text=True,
                          capture_output=True)


class CloudFirstBootContract(unittest.TestCase):
    def test_cloud_first_boot_contract_across_metadata_adapters(self) -> None:
        self.assertEqual(sorted(EXPECTED), sorted(MODULE.NORMALIZERS))
        machine_ids = set()
        for provider, (instance_id, hostname) in EXPECTED.items():
            with self.subTest(provider=provider), \
                    tempfile.TemporaryDirectory(prefix=f"cloud-{provider}-") as raw:
                base = Path(raw)
                enrollment = base / "enroll"
                state = base / "root/var/lib/reproos"
                root = installed_root(base)
                receipt = MODULE.normalize(provider, FIXTURES / provider,
                                           enrollment, state)
                # The same contract for every provider ...
                self.assertEqual(receipt["instance_id"], instance_id)
                self.assertEqual(receipt["machine_id"],
                                 MODULE.machine_id_for(provider, instance_id))
                self.assertEqual((enrollment / "authorized_keys").read_text(), KEY + "\n")
                self.assertEqual((enrollment / "hostname").read_text().strip(), hostname)
                self.assertEqual(sorted(p.name for p in enrollment.iterdir()),
                                 ["authorized_keys", "hostname", "machine-id"])
                # ... with provider specifics only in the receipt's own field.
                self.assertTrue(set(receipt) >= {"provider_fields", "refused_keys"})
                machine_ids.add(receipt["machine_id"])

                result = run_enroll(root, enrollment)
                self.assertEqual(result.returncode, 0, result.stderr)
                identity = json.loads((state / "identity.json").read_text())
                self.assertEqual(identity["machine_id"], receipt["machine_id"])
                self.assertEqual(identity["install_source"], "cloud-image")
                self.assertEqual((root / "etc/hostname").read_text().strip(), hostname)
                self.assertEqual(
                    (root / "home/repro/.ssh/authorized_keys").read_text(), KEY + "\n")
                # A second boot re-normalizes to the same answer.
                again = MODULE.normalize(provider, FIXTURES / provider, enrollment, state)
                self.assertEqual(again["machine_id"], receipt["machine_id"])
        self.assertEqual(len(machine_ids), len(EXPECTED))

    def test_boot_path_hands_the_cloud_directory_to_enrollment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cloud-boot-") as raw:
            base = Path(raw)
            root = installed_root(base)
            # An operator's enrollment medium wins: the cloud unit does nothing.
            labels = root / "dev/disk/by-label"
            labels.mkdir(parents=True)
            (labels / "REPROOS_ENROLL").write_text("")
            self.assertIsNone(MODULE.first_boot(root, attempts=1, delay=0))
            self.assertFalse((root / "run/reproos/cloud-enrollment").exists())
            (labels / "REPROOS_ENROLL").unlink()

            # The unit's output directory is where enrollment looks next, with
            # no REPROOS_ENROLLMENT_DIR override and no optical media.
            MODULE.normalize("hetzner", FIXTURES / "hetzner",
                             root / "run/reproos/cloud-enrollment",
                             root / "var/lib/reproos")
            env = dict(os.environ, REPROOS_ROOT=str(root),
                       REPROOS_SSH_HOST_KEY_FINGERPRINT="SHA256:test-host-key",
                       REPROOS_TEST_MODE="1")
            env.pop("REPROOS_ENROLLMENT_DIR", None)
            result = subprocess.run(["bash", str(ENROLL)], env=env, text=True,
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            identity = json.loads((root / "var/lib/reproos/identity.json").read_text())
            self.assertEqual(identity["machine_id"],
                             MODULE.machine_id_for("hetzner", "41234567"))

    def test_unsupported_keys_are_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            receipt = MODULE.normalize("gce", FIXTURES / "gce",
                                       Path(raw) / "e", Path(raw) / "s")
        # The project-wide RSA key and the instance RSA key are both refused,
        # and named, rather than silently dropped.
        self.assertEqual([r["key_type"] for r in receipt["refused_keys"]],
                         ["ssh-rsa", "ssh-rsa"])

    def test_gce_block_project_keys_is_honoured(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            meta = Path(raw) / "gce"
            shutil.copytree(FIXTURES / "gce", meta)
            (meta / "instance/attributes/block-project-ssh-keys").write_text("TRUE")
            receipt = MODULE.normalize("gce", meta, Path(raw) / "e", Path(raw) / "s")
        self.assertEqual(len(receipt["refused_keys"]), 1)


class CloudMetadataSpoofing(unittest.TestCase):
    def assert_refused(self, code: str, provider: str, raw: Path,
                       state: Path | None = None) -> Path:
        out = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, out)
        enrollment = out / "enroll"
        with self.assertRaises(MODULE.MetadataError) as caught:
            MODULE.normalize(provider, raw, enrollment, state or out / "state")
        self.assertEqual(caught.exception.code, code)
        self.assertFalse((enrollment / "authorized_keys").exists())
        self.assertFalse((enrollment / "machine-id").exists())
        return out

    def copy_fixture(self, provider: str) -> Path:
        raw = Path(tempfile.mkdtemp()) / provider
        self.addCleanup(shutil.rmtree, raw.parent)
        shutil.copytree(FIXTURES / provider, raw)
        return raw

    def test_cloud_metadata_spoofing_fails_identity_checks(self) -> None:
        # 1. Conflicting provider evidence: EC2's two instance-id sources.
        raw = self.copy_fixture("ec2")
        (raw / "meta-data/instance-id").write_text("i-0ffffffffffffffff")
        self.assert_refused("conflicting-instance-identity", "ec2", raw)

        # 2. Changed instance identity after enrollment: no new key lands.
        with tempfile.TemporaryDirectory() as base:
            state = Path(base) / "state"
            first = MODULE.normalize("azure", FIXTURES / "azure",
                                     Path(base) / "enroll", state)
            moved = self.copy_fixture("azure")
            doc = json.loads((moved / "instance.json").read_text())
            doc["compute"]["vmId"] = "11111111-2222-3333-4444-555555555555"
            doc["compute"]["publicKeys"][0]["keyData"] = (
                "ssh-ed25519 QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI= attacker")
            (moved / "instance.json").write_text(json.dumps(doc))
            self.assert_refused("instance-identity-changed", "azure", moved, state)
            pinned = json.loads((state / "cloud-instance.json").read_text())
            self.assertEqual(pinned["instance_id"], first["instance_id"])
            # Same provider evidence under another provider's name is another
            # identity too.
            self.assert_refused("instance-identity-changed", "nocloud",
                                FIXTURES / "nocloud", state)

        # 3. A private key in metadata is refused outright.
        raw = self.copy_fixture("digitalocean")
        doc = json.loads((raw / "metadata/v1.json").read_text())
        doc["public_keys"].append("-----BEGIN OPENSSH PRIVATE KEY----- x")
        (raw / "metadata/v1.json").write_text(json.dumps(doc))
        self.assert_refused("private-key-in-metadata", "digitalocean", raw)

        # 4. Only unacceptable keys: refuse rather than boot unreachable.
        raw = self.copy_fixture("digitalocean")
        doc = json.loads((raw / "metadata/v1.json").read_text())
        doc["public_keys"] = ["ssh-rsa QUFB rsa-only"]
        (raw / "metadata/v1.json").write_text(json.dumps(doc))
        self.assert_refused("no-acceptable-ssh-key", "digitalocean", raw)

        # 5. A hostname that is not one.
        raw = self.copy_fixture("oci")
        doc = json.loads((raw / "opc/v2/instance.json").read_text())
        doc["hostname"] = "evil;rm -rf /"
        (raw / "opc/v2/instance.json").write_text(json.dumps(doc))
        self.assert_refused("invalid-hostname", "oci", raw)

        # 6. DMI only orders probes; a response without the provider's own
        #    marker is refused (GCE's Metadata-Flavor header).
        self.assertEqual(MODULE.detect_order("google compute engine")[0], "gce")
        self.assertEqual(sorted(MODULE.detect_order("")), sorted(MODULE.COLLECTORS))
        server = http.server.HTTPServer(("127.0.0.1", 0), _Plain)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"http://127.0.0.1:{server.server_port}/computeMetadata/v1/instance/id"
        with self.assertRaises(MODULE.MetadataError) as caught:
            MODULE.http(url, {"Metadata-Flavor": "Google"},
                        marker=("Metadata-Flavor", "Google"))
        self.assertEqual(caught.exception.code, "provider-marker-missing")
        # Positive control: the same endpoint with the marker is accepted.
        _Plain.marker = True
        self.assertEqual(MODULE.http(url, marker=("Metadata-Flavor", "Google")), b"42")


class _Plain(http.server.BaseHTTPRequestHandler):
    marker = False

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        if self.marker:
            self.send_header("Metadata-Flavor", "Google")
        self.end_headers()
        self.wfile.write(b"42")

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
