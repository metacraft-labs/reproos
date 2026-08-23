#!/usr/bin/env python3
"""Exercise signed Incus publication and pull without an Incus daemon."""

from __future__ import annotations

import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from threading import Thread


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "reproos-incus-publication.py"
GENERATION_A = "1" * 64
GENERATION_B = "2" * 64


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass


def make_bundle(root: Path, generation: str, marker: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    image = root / "reproos-incus.tar.xz"
    metadata = (
        "architecture: x86_64\n"
        "properties:\n"
        f"  reproos.generation: {generation}\n"
    ).encode("utf-8")
    with tarfile.open(image, mode="w:xz") as archive:
        info = tarfile.TarInfo("metadata.yaml")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))
        payload = marker.encode("utf-8")
        info = tarfile.TarInfo("rootfs/etc/repro-test")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    image_bytes = image.read_bytes()
    digest = hashlib.sha256(image_bytes).hexdigest()
    (root / "incus-baseline.manifest").write_text(
        "vm=reproos-incus\n"
        "snapshot=source-built\n"
        "alias=reproos-incus\n"
        f"generation={generation}\n"
        "tarball=reproos-incus.tar.xz\n"
        f"sha256={digest}\n"
        f"bytes={len(image_bytes)}\n",
        encoding="utf-8",
    )
    return root


def run_tool(*args: str, check: bool = True, env: dict[str, str] | None = None):
    completed = subprocess.run(
        [os.environ.get("PYTHON", "python3"), str(TOOL), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"publication command failed ({completed.returncode}):\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="reproos-incus-publication-") as raw:
        temp = Path(raw)
        key = temp / "release-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        publication = temp / "published"
        bundle_a = make_bundle(temp / "bundle-a", GENERATION_A, "first")

        publish_args = (
            "publish",
            "--bundle-dir",
            str(bundle_a),
            "--destination",
            str(publication),
            "--signing-key",
            str(key),
            "--key-id",
            "test-release",
        )
        run_tool(*publish_args)
        generation_dir = publication / "generations" / GENERATION_A
        initial_generation = {
            path.name: path.read_bytes() for path in generation_dir.iterdir()
        }
        run_tool(*publish_args)
        assert initial_generation == {
            path.name: path.read_bytes() for path in generation_dir.iterdir()
        }

        bundle_b = make_bundle(temp / "bundle-b", GENERATION_B, "second")
        run_tool(
            "publish",
            "--bundle-dir",
            str(bundle_b),
            "--destination",
            str(publication),
            "--signing-key",
            str(key),
            "--key-id",
            "test-release",
        )
        index = json.loads((publication / "index.json").read_text(encoding="utf-8"))
        assert index["currentGeneration"] == GENERATION_B
        assert [entry["generation"] for entry in index["generations"]] == [
            GENERATION_A,
            GENERATION_B,
        ]

        conflicting = make_bundle(temp / "conflicting", GENERATION_A, "changed")
        rejected = run_tool(
            "publish",
            "--bundle-dir",
            str(conflicting),
            "--destination",
            str(publication),
            "--signing-key",
            str(key),
            "--key-id",
            "test-release",
            check=False,
        )
        assert rejected.returncode != 0
        assert "immutable generation conflict" in rejected.stderr

        fake_log = temp / "incus.log"
        fake_incus = temp / "incus"
        fake_incus.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "log = pathlib.Path(os.environ['FAKE_INCUS_LOG'])\n"
            "with log.open('a', encoding='utf-8') as output:\n"
            "    output.write(' '.join(args) + '\\n')\n"
            "state = pathlib.Path(os.environ['FAKE_INCUS_STATE'])\n"
            "fingerprint = os.environ['FAKE_INCUS_FINGERPRINT']\n"
            "alias = os.environ['FAKE_INCUS_ALIAS']\n"
            "if args[-3:] == ['image', 'list', '--format=json']:\n"
            "    images = []\n"
            "    if state.exists():\n"
            "        aliases = [{'name': alias}] if state.read_text() == 'aliased' else []\n"
            "        images = [{'fingerprint': fingerprint, 'aliases': aliases}]\n"
            "    print(json.dumps(images))\n"
            "elif 'import' in args:\n"
            "    state.write_text('aliased', encoding='utf-8')\n"
            "elif args[-4:-2] == ['alias', 'create']:\n"
            "    state.write_text('aliased', encoding='utf-8')\n",
            encoding="utf-8",
        )
        fake_incus.chmod(0o755)
        env = os.environ.copy()
        env["FAKE_INCUS_LOG"] = str(fake_log)
        env["FAKE_INCUS_STATE"] = str(temp / "incus.state")
        env["FAKE_INCUS_FINGERPRINT"] = hashlib.sha256(
            (generation_dir / "reproos-incus.tar.xz").read_bytes()
        ).hexdigest()
        env["FAKE_INCUS_ALIAS"] = GENERATION_A

        handler = functools.partial(QuietHandler, directory=str(publication))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        pull_args = (
            "pull",
            "--base-url",
            base_url,
            "--generation",
            GENERATION_A,
            "--trusted-key",
            str(key) + ".pub",
            "--key-id",
            "test-release",
            "--project",
            "remote-test",
            "--incus-command",
            f'"{sys.executable}" "{fake_incus}"',
        )
        try:
            pulled = run_tool(*pull_args, env=env)
            result = json.loads(pulled.stdout)
            assert result["generation"] == GENERATION_A
            assert result["alias"] == GENERATION_A
            assert len(result["alias"]) <= 64
            logged = fake_log.read_text(encoding="utf-8").splitlines()
            assert logged[0] == "--project remote-test image list --format=json"
            assert logged[1].startswith("--project remote-test image import ")
            assert logged[1].endswith(
                f"--alias {GENERATION_A}"
            )

            fake_log.unlink()
            repeated = run_tool(*pull_args, env=env)
            assert json.loads(repeated.stdout)["imported"] is False
            assert fake_log.read_text(encoding="utf-8").splitlines() == [
                "--project remote-test image list --format=json"
            ]

            fake_log.unlink()
            Path(env["FAKE_INCUS_STATE"]).write_text("unaliased", encoding="utf-8")
            recovered = run_tool(*pull_args, env=env)
            assert json.loads(recovered.stdout)["imported"] is False
            assert fake_log.read_text(encoding="utf-8").splitlines() == [
                "--project remote-test image list --format=json",
                f"--project remote-test image alias create {GENERATION_A} "
                f"{env['FAKE_INCUS_FINGERPRINT']}",
            ]

            protected = [
                publication / "index.json",
                publication / "index.json.sig",
                generation_dir / "publication.json",
                generation_dir / "publication.json.sig",
                generation_dir / "reproos-incus.tar.xz",
            ]
            pristine = {path: path.read_bytes() for path in protected}
            mutations = [
                (publication / "index.json", b" \n", False),
                (publication / "index.json.sig", b"invalid signature\n", True),
                (generation_dir / "publication.json", b" \n", False),
                (generation_dir / "publication.json.sig", b"invalid signature\n", True),
                (generation_dir / "reproos-incus.tar.xz", b"tampered", False),
            ]
            for path, mutation, replace in mutations:
                fake_log.unlink(missing_ok=True)
                path.write_bytes(mutation if replace else pristine[path] + mutation)
                failed = run_tool(*pull_args, check=False, env=env)
                assert failed.returncode != 0, (path, failed.stdout, failed.stderr)
                assert not fake_log.exists(), f"Incus ran after untrusted input: {path}"
                path.write_bytes(pristine[path])

            latest = run_tool(
                "pull",
                "--base-url",
                base_url,
                "--trusted-key",
                str(key) + ".pub",
                "--key-id",
                "test-release",
                "--no-import",
            )
            assert json.loads(latest.stdout)["generation"] == GENERATION_B
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    print("ReproOS signed Incus publication: PASS")


if __name__ == "__main__":
    main()
