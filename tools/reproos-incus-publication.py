#!/usr/bin/env python3
"""Publish and pull authenticated, generation-addressed ReproOS Incus images."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urljoin
from urllib.request import urlopen
import uuid


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = ROOT / "recipes" / "reproos-container" / "build"
INDEX_SCHEMA = "org.reproos.incus.index.v1"
PUBLICATION_SCHEMA = "org.reproos.incus.publication.v1"
SIGNATURE_ALGORITHM = "openssh-signature-v1"
SIGNATURE_NAMESPACE = "reproos-incus-publication-v1"
GENERATION_RE = re.compile(r"[0-9a-f]{64}")
KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]*")


class PublicationError(Exception):
    """A publication contract or verification failure."""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def require_generation(value: object, subject: str = "generation") -> str:
    if not isinstance(value, str) or GENERATION_RE.fullmatch(value) is None:
        raise PublicationError(f"{subject} must be a lowercase SHA-256 digest")
    return value


def require_key_id(value: str) -> str:
    if KEY_ID_RE.fullmatch(value) is None:
        raise PublicationError(
            "signing key ID must contain only letters, digits, '.', '_', '@', '+', or '-'"
        )
    return value


def signer_contract(key_id: str) -> dict[str, str]:
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "keyId": require_key_id(key_id),
        "namespace": SIGNATURE_NAMESPACE,
    }


def parse_bundle_manifest(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise PublicationError(f"bundle manifest is missing: {path}")
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise PublicationError(f"invalid bundle manifest line {line_number}")
        key, value = raw.split("=", 1)
        if not key or key in values:
            raise PublicationError(f"duplicate or empty bundle manifest key: {key}")
        values[key] = value
    required = {"alias", "bytes", "generation", "sha256", "tarball"}
    missing = sorted(required - values.keys())
    if missing:
        raise PublicationError(f"bundle manifest is missing: {', '.join(missing)}")
    return values


def image_metadata_generation(path: Path) -> str:
    try:
        with tarfile.open(path, mode="r:xz") as archive:
            first = archive.next()
            if first is None or first.name != "metadata.yaml" or not first.isfile():
                raise PublicationError("Incus image must begin with metadata.yaml")
            source = archive.extractfile(first)
            if source is None:
                raise PublicationError("Incus image metadata cannot be read")
            metadata = source.read(64 * 1024).decode("utf-8")
    except (tarfile.TarError, UnicodeDecodeError, OSError) as error:
        raise PublicationError(f"invalid Incus image archive: {error}") from error
    match = re.search(
        r"^  reproos\.generation: ([0-9a-f]{64})$", metadata, re.MULTILINE
    )
    if match is None:
        raise PublicationError("Incus image metadata lacks reproos.generation")
    return match.group(1)


def normalize_public_key(value: str) -> str:
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise PublicationError("trusted key is not an OpenSSH Ed25519 public key")
    return f"{parts[0]} {parts[1]}"


def public_key_from_private(key_path: Path) -> str:
    result = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(key_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PublicationError(f"cannot read signing key: {result.stderr.strip()}")
    return normalize_public_key(result.stdout)


def sign_file(path: Path, key_path: Path) -> Path:
    signature = Path(str(path) + ".sig")
    signature.unlink(missing_ok=True)
    result = subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "sign",
            "-f",
            str(key_path),
            "-n",
            SIGNATURE_NAMESPACE,
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not signature.is_file():
        raise PublicationError(f"publication signing failed: {result.stderr.strip()}")
    return signature


def verify_signature(
    payload: bytes, signature: bytes, public_key: str, key_id: str
) -> None:
    require_key_id(key_id)
    with tempfile.TemporaryDirectory(prefix="reproos-incus-verify-") as raw:
        temp = Path(raw)
        allowed = temp / "allowed-signers"
        signature_path = temp / "signature.sig"
        allowed.write_text(
            f"{key_id} {normalize_public_key(public_key)}\n", encoding="utf-8"
        )
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                key_id,
                "-n",
                SIGNATURE_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=payload,
            check=False,
            capture_output=True,
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise PublicationError(f"publication signature verification failed: {detail}")


def validate_signer(value: object, key_id: str) -> None:
    if value != signer_contract(key_id):
        raise PublicationError("publication signer contract does not match the trusted key")


def parse_canonical_document(payload: bytes, schema: str, key_id: str) -> dict:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"publication JSON is invalid: {error}") from error
    if not isinstance(value, dict) or value.get("schemaId") != schema:
        raise PublicationError(f"unsupported publication schema; expected {schema}")
    if canonical_json(value) != payload:
        raise PublicationError("publication JSON is not in canonical form")
    validate_signer(value.get("signer"), key_id)
    return value


def publication_document(
    generation: str, image_sha256: str, image_bytes: int, key_id: str
) -> dict:
    alias = f"reproos-incus-{generation}"
    image_path = f"generations/{generation}/reproos-incus.tar.xz"
    return {
        "alias": alias,
        "architecture": "x86_64",
        "generation": generation,
        "image": {
            "bytes": image_bytes,
            "path": image_path,
            "sha256": image_sha256,
        },
        "imageType": "incus-system-container",
        "schemaId": PUBLICATION_SCHEMA,
        "signer": signer_contract(key_id),
    }


def validate_publication(value: dict, expected_generation: str, key_id: str) -> None:
    expected_keys = {
        "alias",
        "architecture",
        "generation",
        "image",
        "imageType",
        "schemaId",
        "signer",
    }
    if set(value) != expected_keys:
        raise PublicationError("publication manifest has unexpected or missing fields")
    generation = require_generation(value.get("generation"))
    if generation != expected_generation:
        raise PublicationError("publication generation does not match its index entry")
    validate_signer(value.get("signer"), key_id)
    if value.get("alias") != f"reproos-incus-{generation}":
        raise PublicationError("publication alias is not generation-addressed")
    if value.get("architecture") != "x86_64":
        raise PublicationError("unsupported Incus image architecture")
    if value.get("imageType") != "incus-system-container":
        raise PublicationError("unsupported Incus image type")
    image = value.get("image")
    if not isinstance(image, dict) or set(image) != {"bytes", "path", "sha256"}:
        raise PublicationError("publication image contract is invalid")
    expected_path = f"generations/{generation}/reproos-incus.tar.xz"
    if image.get("path") != expected_path:
        raise PublicationError("publication image path is not generation-addressed")
    if not isinstance(image.get("bytes"), int) or image["bytes"] <= 0:
        raise PublicationError("publication image size is invalid")
    require_generation(image.get("sha256"), "image SHA-256")


def publish(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir).resolve()
    destination_value = args.destination or os.environ.get(
        "REPROOS_INCUS_PUBLICATION_DIR"
    )
    signing_key_value = args.signing_key or os.environ.get(
        "REPROOS_INCUS_SIGNING_KEY"
    )
    key_id = args.key_id or os.environ.get(
        "REPROOS_INCUS_SIGNING_KEY_ID", "reproos-release"
    )
    if not destination_value:
        raise PublicationError(
            "publication destination is required (--destination or REPROOS_INCUS_PUBLICATION_DIR)"
        )
    if not signing_key_value:
        raise PublicationError(
            "signing key is required (--signing-key or REPROOS_INCUS_SIGNING_KEY)"
        )
    key_id = require_key_id(key_id)
    signing_key = Path(signing_key_value).resolve()
    if not signing_key.is_file():
        raise PublicationError(f"signing key is missing: {signing_key}")
    public_key = public_key_from_private(signing_key)

    bundle_values = parse_bundle_manifest(bundle / "incus-baseline.manifest")
    generation = require_generation(bundle_values["generation"])
    tarball = bundle_values["tarball"]
    if PurePosixPath(tarball).name != tarball:
        raise PublicationError("bundle tarball must be a file name")
    image = bundle / tarball
    if not image.is_file():
        raise PublicationError(f"Incus image is missing: {image}")
    image_sha, image_size = sha256_file(image)
    if image_sha != bundle_values["sha256"]:
        raise PublicationError("bundle manifest image SHA-256 does not match")
    try:
        declared_size = int(bundle_values["bytes"])
    except ValueError as error:
        raise PublicationError("bundle manifest image size is invalid") from error
    if image_size != declared_size:
        raise PublicationError("bundle manifest image size does not match")
    if image_metadata_generation(image) != generation:
        raise PublicationError("Incus image metadata generation does not match the bundle")

    destination = Path(destination_value).resolve()
    generations = destination / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    lock = destination / ".publish.lock"
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise PublicationError(f"another publisher holds {lock}") from error

    staging = destination / f".publish-{uuid.uuid4().hex}"
    try:
        staging.mkdir()
        staged_image = staging / "reproos-incus.tar.xz"
        shutil.copyfile(image, staged_image)
        document = publication_document(generation, image_sha, image_size, key_id)
        document_path = staging / "publication.json"
        document_path.write_bytes(canonical_json(document))
        sign_file(document_path, signing_key)

        generation_path = generations / generation
        expected_names = {
            "publication.json",
            "publication.json.sig",
            "reproos-incus.tar.xz",
        }
        if generation_path.exists():
            names = {path.name for path in generation_path.iterdir()}
            if names != expected_names:
                raise PublicationError(
                    f"immutable generation conflict: {generation_path}"
                )
            existing_payload = (generation_path / "publication.json").read_bytes()
            if existing_payload != document_path.read_bytes():
                raise PublicationError(
                    f"immutable generation conflict: {generation_path}"
                )
            existing_sha, existing_size = sha256_file(
                generation_path / "reproos-incus.tar.xz"
            )
            if (existing_sha, existing_size) != (image_sha, image_size):
                raise PublicationError(
                    f"immutable generation conflict: {generation_path}"
                )
            verify_signature(
                existing_payload,
                (generation_path / "publication.json.sig").read_bytes(),
                public_key,
                key_id,
            )
            shutil.rmtree(staging)
        else:
            os.replace(staging, generation_path)

        entries = []
        for candidate in sorted(generations.iterdir(), key=lambda path: path.name):
            if not candidate.is_dir() or GENERATION_RE.fullmatch(candidate.name) is None:
                continue
            payload = (candidate / "publication.json").read_bytes()
            signature = (candidate / "publication.json.sig").read_bytes()
            verify_signature(payload, signature, public_key, key_id)
            manifest = parse_canonical_document(
                payload, PUBLICATION_SCHEMA, key_id
            )
            validate_publication(manifest, candidate.name, key_id)
            entries.append(
                {
                    "alias": manifest["alias"],
                    "generation": candidate.name,
                    "manifest": {
                        "path": f"generations/{candidate.name}/publication.json",
                        "sha256": sha256_bytes(payload),
                    },
                }
            )

        index = {
            "currentGeneration": generation,
            "generations": entries,
            "schemaId": INDEX_SCHEMA,
            "signer": signer_contract(key_id),
        }
        temporary_index = destination / f".index-{uuid.uuid4().hex}.json"
        temporary_index.write_bytes(canonical_json(index))
        temporary_signature = sign_file(temporary_index, signing_key)
        os.replace(temporary_signature, destination / "index.json.sig")
        os.replace(temporary_index, destination / "index.json")
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        lock.rmdir()

    print(
        json.dumps(
            {
                "alias": f"reproos-incus-{generation}",
                "destination": str(destination),
                "generation": generation,
            },
            sort_keys=True,
        )
    )


def safe_relative_url(base_url: str, path: object) -> str:
    if not isinstance(path, str):
        raise PublicationError("publication path is not a string")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != path:
        raise PublicationError(f"unsafe publication path: {path}")
    base = base_url.rstrip("/") + "/"
    result = urljoin(base, path)
    if not result.startswith(base):
        raise PublicationError(f"publication path escapes its base URL: {path}")
    return result


def fetch_bytes(base_url: str, path: str, maximum: int) -> bytes:
    url = safe_relative_url(base_url, path)
    try:
        with urlopen(url, timeout=30) as response:
            payload = response.read(maximum + 1)
    except OSError as error:
        raise PublicationError(f"cannot fetch {url}: {error}") from error
    if len(payload) > maximum:
        raise PublicationError(f"publication object is too large: {path}")
    return payload


def validate_index(value: dict, key_id: str) -> None:
    if set(value) != {"currentGeneration", "generations", "schemaId", "signer"}:
        raise PublicationError("publication index has unexpected or missing fields")
    require_generation(value.get("currentGeneration"), "current generation")
    validate_signer(value.get("signer"), key_id)
    entries = value.get("generations")
    if not isinstance(entries, list) or not entries:
        raise PublicationError("publication index has no generations")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"alias", "generation", "manifest"}:
            raise PublicationError("publication index entry is invalid")
        generation = require_generation(entry.get("generation"))
        if generation in seen:
            raise PublicationError("publication index repeats a generation")
        seen.add(generation)
        if entry.get("alias") != f"reproos-incus-{generation}":
            raise PublicationError("publication index alias is not generation-addressed")
        manifest = entry.get("manifest")
        if not isinstance(manifest, dict) or set(manifest) != {"path", "sha256"}:
            raise PublicationError("publication index manifest reference is invalid")
        if manifest.get("path") != f"generations/{generation}/publication.json":
            raise PublicationError("publication manifest path is not generation-addressed")
        require_generation(manifest.get("sha256"), "manifest SHA-256")
    if value["currentGeneration"] not in seen:
        raise PublicationError("current generation is absent from the publication index")


def download_image(
    base_url: str, path: str, destination: Path, expected_sha: str, expected_size: int
) -> None:
    url = safe_relative_url(base_url, path)
    digest = hashlib.sha256()
    size = 0
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > expected_size:
                    raise PublicationError("downloaded Incus image exceeds its signed size")
                digest.update(block)
                output.write(block)
        if size != expected_size:
            raise PublicationError("downloaded Incus image size does not match")
        if digest.hexdigest() != expected_sha:
            raise PublicationError("downloaded Incus image SHA-256 does not match")
        os.replace(temporary, destination)
    except OSError as error:
        raise PublicationError(f"cannot fetch {url}: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def pull(args: argparse.Namespace) -> None:
    base_url = args.base_url or os.environ.get("REPROOS_INCUS_PUBLICATION_URL")
    trusted_key_value = args.trusted_key or os.environ.get(
        "REPROOS_INCUS_TRUSTED_KEY"
    )
    key_id = args.key_id or os.environ.get(
        "REPROOS_INCUS_SIGNING_KEY_ID", "reproos-release"
    )
    if not base_url:
        raise PublicationError(
            "publication URL is required (--base-url or REPROOS_INCUS_PUBLICATION_URL)"
        )
    if not trusted_key_value:
        raise PublicationError(
            "trusted key is required (--trusted-key or REPROOS_INCUS_TRUSTED_KEY)"
        )
    key_id = require_key_id(key_id)
    trusted_key_path = Path(trusted_key_value).resolve()
    if not trusted_key_path.is_file():
        raise PublicationError(f"trusted key is missing: {trusted_key_path}")
    trusted_key = trusted_key_path.read_text(encoding="utf-8")

    index_payload = fetch_bytes(base_url, "index.json", 8 * 1024 * 1024)
    index_signature = fetch_bytes(base_url, "index.json.sig", 1024 * 1024)
    verify_signature(index_payload, index_signature, trusted_key, key_id)
    index = parse_canonical_document(index_payload, INDEX_SCHEMA, key_id)
    validate_index(index, key_id)
    requested = args.generation or os.environ.get("REPROOS_INCUS_GENERATION")
    generation = (
        require_generation(requested) if requested else index["currentGeneration"]
    )
    selected = next(
        (entry for entry in index["generations"] if entry["generation"] == generation),
        None,
    )
    if selected is None:
        raise PublicationError(f"generation is not published: {generation}")

    manifest_path = selected["manifest"]["path"]
    manifest_payload = fetch_bytes(base_url, manifest_path, 8 * 1024 * 1024)
    if sha256_bytes(manifest_payload) != selected["manifest"]["sha256"]:
        raise PublicationError("publication manifest SHA-256 does not match the index")
    manifest_signature = fetch_bytes(
        base_url, manifest_path + ".sig", 1024 * 1024
    )
    verify_signature(manifest_payload, manifest_signature, trusted_key, key_id)
    manifest = parse_canonical_document(
        manifest_payload, PUBLICATION_SCHEMA, key_id
    )
    validate_publication(manifest, generation, key_id)

    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        temporary_context = None
    else:
        temporary_context = tempfile.TemporaryDirectory(prefix="reproos-incus-pull-")
        output_dir = Path(temporary_context.name)
    try:
        image_path = output_dir / f"reproos-incus-{generation}.tar.xz"
        download_image(
            base_url,
            manifest["image"]["path"],
            image_path,
            manifest["image"]["sha256"],
            manifest["image"]["bytes"],
        )
        if image_metadata_generation(image_path) != generation:
            raise PublicationError("downloaded Incus image generation does not match")
        if not args.no_import:
            incus_command = args.incus_command or os.environ.get(
                "VMH_INCUS_CMD", "incus"
            )
            command = shlex.split(incus_command)
            if not command:
                raise PublicationError("Incus command is empty")
            result = subprocess.run(
                command
                + [
                    "--project",
                    args.project,
                    "image",
                    "import",
                    str(image_path),
                    "--alias",
                    manifest["alias"],
                ],
                check=False,
            )
            if result.returncode != 0:
                raise PublicationError("Incus image import failed")
    finally:
        if temporary_context is not None:
            temporary_context.cleanup()

    print(
        json.dumps(
            {
                "alias": manifest["alias"],
                "generation": generation,
                "imported": not args.no_import,
                "project": args.project,
            },
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    publish_parser = commands.add_parser("publish", help="publish a signed image")
    publish_parser.add_argument("--bundle-dir", default=str(DEFAULT_BUNDLE))
    publish_parser.add_argument("--destination")
    publish_parser.add_argument("--signing-key")
    publish_parser.add_argument("--key-id")
    publish_parser.set_defaults(handler=publish)

    pull_parser = commands.add_parser("pull", help="verify and import a signed image")
    pull_parser.add_argument("--base-url")
    pull_parser.add_argument("--generation")
    pull_parser.add_argument("--trusted-key")
    pull_parser.add_argument("--key-id")
    pull_parser.add_argument("--project", default="default")
    pull_parser.add_argument("--incus-command")
    pull_parser.add_argument("--output-dir")
    pull_parser.add_argument("--no-import", action="store_true")
    pull_parser.set_defaults(handler=pull)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (PublicationError, OSError) as error:
        print(f"reproos-incus-publication: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
