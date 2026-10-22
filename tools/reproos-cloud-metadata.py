#!/usr/bin/env python3
"""Turn a cloud provider's instance metadata into ReproOS first-boot enrollment.

ReproOS has one first-boot contract: ``reproos-first-boot-enroll`` reads an
enrollment directory holding ``machine-id`` and ``authorized_keys`` (and,
optionally, ``hostname``). On a workstation or VM that directory is the
``REPROOS_ENROLL`` medium compiled by ``reproos-machine-config.py``. On a
cloud instance this tool produces the same directory from the provider's
metadata, so every provider reaches the one contract and nothing after it
knows which cloud it is on (Cloud Images M1).

Two layers, deliberately separate:

``collect``
    Fetches the provider's documents (link-local metadata service or
    config drive) into a raw directory, byte for byte. This is the only
    part that touches the network, and the only part that differs in how
    it talks to each provider.

``normalize``
    Pure: reads a raw directory and writes the enrollment directory plus
    ``cloud-instance.json``. Recorded fixtures drive it in tests, so every
    adapter is checked offline against the same expectations.

Identity rules (Cloud Images M1, ``test_cloud_metadata_spoofing_fails_identity_checks``):

* The provider is never chosen from DMI strings alone. ``detect`` only
  orders its probes by DMI; the decision is a metadata response carrying the
  provider's own marker (a response header or a labelled config drive).
* Where a provider exposes the instance id twice (EC2's ``instance-id`` and
  its identity document), the two must agree.
* ``machine-id`` is derived from (provider, instance id). Once an instance has
  enrolled, ``cloud-instance.json`` pins that pair; metadata naming another
  instance is refused and no credential is written. A disk moved or copied to
  a new instance must be re-provisioned on purpose, never silently re-keyed.

Key policy is the first-boot contract's: ed25519, ECDSA and their security-
key variants. Other key types are refused by name in the receipt, and an
instance left with no acceptable key fails rather than booting unreachable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


SCHEMA = 1
MACHINE_ID_DOMAIN = b"reproos-cloud-machine-id-v1"
ALLOWED_KEY_TYPES = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
HOSTNAME_RE = re.compile(
    r"(?=^.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)
INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
IMDS = "http://169.254.169.254"
MAX_DOCUMENT_BYTES = 1 << 20  # a metadata document is kilobytes; refuse floods


class MetadataError(Exception):
    """A refusal. ``code`` is the stable token printed after REPROOS_CLOUD:FAIL:."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


# --------------------------------------------------------------------------
# Raw-directory readers

def read_text(raw: Path, name: str, required: bool = True) -> str | None:
    path = raw / name
    if not path.is_file():
        if required:
            raise MetadataError("missing-document", name)
        return None
    return path.read_text(encoding="utf-8")


def read_json(raw: Path, name: str, required: bool = True):
    text = read_text(raw, name, required)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetadataError("malformed-document", f"{name}: {exc}") from exc


def simple_yaml(text: str) -> dict:
    """The YAML subset NoCloud meta-data and Hetzner metadata use.

    Top-level ``key: scalar`` pairs and ``key:`` followed by ``- item`` lists.
    Anything else is refused rather than guessed at: the image carries no
    YAML library, and a lenient parser here would be a spoofing surface.
    """
    result: dict = {}
    current_list: list | None = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")) and line.strip().startswith("- "):
            if current_list is None:
                raise MetadataError("malformed-document", f"orphan list item: {line!r}")
            current_list.append(unquote(line.strip()[2:].strip()))
            continue
        if line.startswith("- "):
            if current_list is None:
                raise MetadataError("malformed-document", f"orphan list item: {line!r}")
            current_list.append(unquote(line[2:].strip()))
            continue
        if ":" not in line or line.startswith((" ", "\t")):
            raise MetadataError("malformed-document", f"unsupported YAML: {line!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "":
            current_list = []
            result[key] = current_list
        else:
            current_list = None
            result[key] = unquote(value)
    return result


def unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def cloud_config_keys(user_data: str | None) -> list[str]:
    """``ssh_authorized_keys`` from a ``#cloud-config`` document, top level or
    under ``users``; any other user-data is not ours to interpret."""
    if not user_data or not user_data.startswith("#cloud-config"):
        return []
    keys: list[str] = []
    collecting = False
    indent = -1
    for line in user_data.splitlines():
        stripped = line.strip()
        here = len(line) - len(line.lstrip())
        if stripped.startswith("ssh_authorized_keys:") or stripped.startswith("- ssh_authorized_keys:"):
            collecting = True
            indent = here
            continue
        if collecting:
            if stripped.startswith("- ") and here >= indent:
                keys.append(unquote(stripped[2:].strip()))
                continue
            if stripped:
                collecting = False
    return keys


# --------------------------------------------------------------------------
# Per-provider normalization: raw directory -> (instance id, hostname, keys,
# provider-specific fields). Each returns the fields it trusts; the shared
# code below validates them identically for every provider.

def norm_nocloud(raw: Path):
    meta = simple_yaml(read_text(raw, "meta-data"))
    keys = list(meta.get("public-keys", []) or [])
    keys += cloud_config_keys(read_text(raw, "user-data", required=False))
    return meta.get("instance-id"), meta.get("local-hostname"), keys, {}


def norm_configdrive(raw: Path):
    meta = read_json(raw, "openstack/latest/meta_data.json")
    keys = list((meta.get("public_keys") or {}).values())
    return (meta.get("uuid"), meta.get("hostname"), keys,
            {"availability_zone": meta.get("availability_zone")})


def norm_ec2(raw: Path):
    instance_id = (read_text(raw, "meta-data/instance-id") or "").strip()
    document = read_json(raw, "dynamic/instance-identity/document")
    if document.get("instanceId") != instance_id:
        raise MetadataError(
            "conflicting-instance-identity",
            f"meta-data instance-id {instance_id!r} != identity document "
            f"instanceId {document.get('instanceId')!r}")
    keys = []
    for name in sorted(os.listdir(raw / "meta-data/public-keys")) if (raw / "meta-data/public-keys").is_dir() else []:
        key = read_text(raw, f"meta-data/public-keys/{name}/openssh-key", required=False)
        if key:
            keys.append(key.strip())
    hostname = (read_text(raw, "meta-data/local-hostname", required=False) or "").strip()
    return (instance_id, hostname.split(".")[0] or None, keys,
            {"region": document.get("region"), "account_id": document.get("accountId"),
             "image_id": document.get("imageId")})


def norm_gce(raw: Path):
    instance_id = (read_text(raw, "instance/id") or "").strip()
    hostname = (read_text(raw, "instance/hostname", required=False) or "").strip()
    keys: list[str] = []
    block_project = (read_text(raw, "instance/attributes/block-project-ssh-keys",
                               required=False) or "").strip().lower() == "true"
    sources = ["instance/attributes/ssh-keys"]
    if not block_project:
        sources.append("project/attributes/ssh-keys")
    for source in sources:
        for line in (read_text(raw, source, required=False) or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # "<user>:<key>"; the user name is GCE's, the account is ours.
            keys.append(line.split(":", 1)[1] if ":" in line.split(" ", 1)[0] else line)
    return (instance_id, hostname.split(".")[0] or None, keys,
            {"zone": (read_text(raw, "instance/zone", required=False) or "").strip() or None})


def norm_azure(raw: Path):
    instance = read_json(raw, "instance.json")
    compute = instance.get("compute") or {}
    keys = [k.get("keyData", "") for k in compute.get("publicKeys") or []]
    return (compute.get("vmId"), (compute.get("osProfile") or {}).get("computerName")
            or compute.get("name"), keys,
            {"location": compute.get("location"),
             "subscription_id": compute.get("subscriptionId")})


def norm_oci(raw: Path):
    instance = read_json(raw, "opc/v2/instance.json")
    metadata = instance.get("metadata") or {}
    keys = (metadata.get("ssh_authorized_keys") or "").splitlines()
    return (instance.get("id"), instance.get("hostname") or instance.get("displayName"),
            keys, {"region": instance.get("canonicalRegionName") or instance.get("region")})


def norm_hetzner(raw: Path):
    meta = simple_yaml(read_text(raw, "hetzner/v1/metadata"))
    return (meta.get("instance-id"), meta.get("hostname"),
            list(meta.get("public-keys", []) or []), {"region": meta.get("region")})


def norm_digitalocean(raw: Path):
    meta = read_json(raw, "metadata/v1.json")
    droplet = meta.get("droplet_id")
    return (str(droplet) if droplet is not None else None, meta.get("hostname"),
            list(meta.get("public_keys") or []), {"region": meta.get("region")})


NORMALIZERS = {
    "nocloud": norm_nocloud,
    "configdrive": norm_configdrive,
    "ec2": norm_ec2,
    "gce": norm_gce,
    "azure": norm_azure,
    "oci": norm_oci,
    "hetzner": norm_hetzner,
    "digitalocean": norm_digitalocean,
}


def classify_keys(candidates: list[str]) -> tuple[list[str], list[dict]]:
    accepted: list[str] = []
    refused: list[dict] = []
    for raw_key in candidates:
        key = raw_key.strip()
        if not key:
            continue
        if "PRIVATE KEY" in key:
            raise MetadataError("private-key-in-metadata")
        fields = key.split()
        if len(fields) < 2 or "\n" in key:
            refused.append({"reason": "malformed", "key_type": fields[0] if fields else ""})
            continue
        if fields[0] not in ALLOWED_KEY_TYPES:
            refused.append({"reason": "unsupported-key-type", "key_type": fields[0]})
            continue
        if key not in accepted:
            accepted.append(key)
    return accepted, refused


def machine_id_for(provider: str, instance_id: str) -> str:
    digest = hashlib.sha256(
        MACHINE_ID_DOMAIN + b"\0" + provider.encode() + b"\0" + instance_id.encode())
    return digest.hexdigest()[:32]


def documents_digest(raw: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in raw.rglob("*") if p.is_file()):
        digest.update(path.relative_to(raw).as_posix().encode() + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def normalize(provider: str, raw: Path, enroll_out: Path, state: Path) -> dict:
    if provider not in NORMALIZERS:
        raise MetadataError("unknown-provider", provider)
    instance_id, hostname, candidates, extra = NORMALIZERS[provider](raw)
    instance_id = (instance_id or "").strip()
    if not INSTANCE_ID_RE.match(instance_id):
        raise MetadataError("invalid-instance-id", repr(instance_id))
    hostname = (hostname or "").strip().lower()
    if hostname and not HOSTNAME_RE.match(hostname):
        raise MetadataError("invalid-hostname", repr(hostname))
    keys, refused = classify_keys(candidates)
    if not keys:
        raise MetadataError("no-acceptable-ssh-key",
                            f"{len(refused)} key(s) refused: {refused}")
    machine_id = machine_id_for(provider, instance_id)

    receipt_path = state / "cloud-instance.json"
    if receipt_path.is_file():
        pinned = json.loads(receipt_path.read_text())
        if (pinned.get("provider"), pinned.get("instance_id")) != (provider, instance_id):
            raise MetadataError(
                "instance-identity-changed",
                f"enrolled as {pinned.get('provider')}:{pinned.get('instance_id')}, "
                f"metadata now names {provider}:{instance_id}")

    receipt = {
        "schema_version": SCHEMA,
        "provider": provider,
        "instance_id": instance_id,
        "machine_id": machine_id,
        "hostname": hostname or None,
        "authorized_keys_sha256": hashlib.sha256(
            ("\n".join(keys) + "\n").encode()).hexdigest(),
        "refused_keys": refused,
        "documents_sha256": documents_digest(raw),
        "provider_fields": {k: v for k, v in extra.items() if v is not None},
    }
    enroll_out.mkdir(parents=True, exist_ok=True)
    (enroll_out / "machine-id").write_text(machine_id + "\n")
    (enroll_out / "authorized_keys").write_text("\n".join(keys) + "\n")
    if hostname:
        (enroll_out / "hostname").write_text(hostname + "\n")
    elif (enroll_out / "hostname").exists():
        (enroll_out / "hostname").unlink()
    state.mkdir(parents=True, exist_ok=True)
    if not receipt_path.is_file():
        tmp = receipt_path.with_suffix(".json.new")
        tmp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, receipt_path)
    return receipt


# --------------------------------------------------------------------------
# Collection (network / media). Kept thin; everything it writes is a byte
# copy of what the provider served.

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http(url: str, headers: dict | None = None, method: str = "GET",
         marker: tuple[str, str] | None = None, timeout: float = 3.0,
         data: bytes | None = None) -> bytes:
    request = urllib.request.Request(url, headers=headers or {}, method=method,
                                     data=data)
    with OPENER.open(request, timeout=timeout) as response:
        if marker and response.headers.get(marker[0]) != marker[1]:
            raise MetadataError("provider-marker-missing", f"{url}: {marker}")
        body = response.read(MAX_DOCUMENT_BYTES + 1)
        if len(body) > MAX_DOCUMENT_BYTES:
            raise MetadataError("oversized-document", f"{url}: over {MAX_DOCUMENT_BYTES} bytes")
        return body


def save(raw: Path, name: str, data: bytes) -> None:
    path = raw / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def collect_ec2(raw: Path) -> None:
    token = http(f"{IMDS}/latest/api/token", method="PUT",
                 headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"}).decode()
    h = {"X-aws-ec2-metadata-token": token}
    for name in ("instance-id", "local-hostname"):
        save(raw, f"meta-data/{name}", http(f"{IMDS}/latest/meta-data/{name}", h))
    save(raw, "dynamic/instance-identity/document",
         http(f"{IMDS}/latest/dynamic/instance-identity/document", h))
    try:
        listing = http(f"{IMDS}/latest/meta-data/public-keys/", h).decode()
    except urllib.error.HTTPError:
        listing = ""
    for line in listing.splitlines():
        index = line.split("=", 1)[0]
        save(raw, f"meta-data/public-keys/{index}/openssh-key",
             http(f"{IMDS}/latest/meta-data/public-keys/{index}/openssh-key", h))


def collect_gce(raw: Path) -> None:
    base = "http://metadata.google.internal/computeMetadata/v1"
    h = {"Metadata-Flavor": "Google"}
    marker = ("Metadata-Flavor", "Google")
    for name, required in (("instance/id", True), ("instance/hostname", False),
                           ("instance/zone", False),
                           ("instance/attributes/ssh-keys", False),
                           ("instance/attributes/block-project-ssh-keys", False),
                           ("project/attributes/ssh-keys", False)):
        try:
            save(raw, name, http(f"{base}/{name}", h, marker=marker))
        except urllib.error.HTTPError:
            if required:
                raise


def collect_azure(raw: Path) -> None:
    save(raw, "instance.json", http(
        f"{IMDS}/metadata/instance?api-version=2021-02-01",
        {"Metadata": "true"}))


def collect_oci(raw: Path) -> None:
    save(raw, "opc/v2/instance.json",
         http(f"{IMDS}/opc/v2/instance/", {"Authorization": "Bearer Oracle"}))


def collect_hetzner(raw: Path) -> None:
    save(raw, "hetzner/v1/metadata", http(f"{IMDS}/hetzner/v1/metadata"))


def collect_digitalocean(raw: Path) -> None:
    save(raw, "metadata/v1.json", http(f"{IMDS}/metadata/v1.json"))


def collect_media(raw: Path, source: Path, names: list[str]) -> None:
    for name in names:
        if (source / name).is_file():
            save(raw, name, (source / name).read_bytes())


COLLECTORS = {
    "ec2": collect_ec2,
    "gce": collect_gce,
    "azure": collect_azure,
    "oci": collect_oci,
    "hetzner": collect_hetzner,
    "digitalocean": collect_digitalocean,
}


def dmi_vendor(sysfs: Path = Path("/sys/class/dmi/id")) -> str:
    try:
        return " ".join((sysfs / f).read_text().strip().lower()
                        for f in ("sys_vendor", "product_name", "chassis_asset_tag")
                        if (sysfs / f).is_file())
    except OSError:
        return ""


def detect_order(hint: str) -> list[str]:
    """Probe order only. DMI is mutable and spoofable, so it never decides."""
    preferred = []
    for needle, provider in (("amazon", "ec2"), ("google", "gce"),
                             ("microsoft", "azure"), ("oraclecloud", "oci"),
                             ("hetzner", "hetzner"), ("digitalocean", "digitalocean")):
        if needle in hint:
            preferred.append(provider)
    rest = [p for p in COLLECTORS if p not in preferred]
    return preferred + rest


WIRESERVER = "http://168.63.129.16"
WIRESERVER_VERSION = "2012-11-30"


def azure_goal_state(xml_text: str) -> tuple[str, str, str]:
    """(incarnation, container id, role instance id) from a goal state."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise MetadataError("malformed-document", f"goal state: {exc}") from exc
    incarnation = root.findtext("Incarnation")
    container = root.find("Container")
    container_id = container.findtext("ContainerId") if container is not None else None
    instance = root.find("Container/RoleInstanceList/RoleInstance/InstanceId")
    if not incarnation or not container_id or instance is None or not instance.text:
        raise MetadataError("malformed-document", "goal state lacks incarnation, "
                            "container id or role instance id")
    return incarnation.strip(), container_id.strip(), instance.text.strip()


def azure_health_report(incarnation: str, container_id: str, instance_id: str) -> bytes:
    from xml.sax.saxutils import escape
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Health xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
        f"  <GoalStateIncarnation>{escape(incarnation)}</GoalStateIncarnation>\n"
        "  <Container>\n"
        f"    <ContainerId>{escape(container_id)}</ContainerId>\n"
        "    <RoleInstanceList>\n"
        "      <Role>\n"
        f"        <InstanceId>{escape(instance_id)}</InstanceId>\n"
        "        <Health>\n"
        "          <State>Ready</State>\n"
        "        </Health>\n"
        "      </Role>\n"
        "    </RoleInstanceList>\n"
        "  </Container>\n"
        "</Health>\n").encode()


def azure_report_ready(state: Path, base: str = WIRESERVER) -> str | None:
    """Tell Azure the instance provisioned itself (no agent does it for us).

    Without this report Azure keeps the VM in "provisioning" and fails the
    deployment (matrix section 3.3). Only an instance enrolled from Azure
    metadata reports; everything else returns None untouched.
    """
    receipt = state / "cloud-instance.json"
    if not receipt.is_file() or json.loads(receipt.read_text()).get("provider") != "azure":
        return None
    headers = {"x-ms-version": WIRESERVER_VERSION}
    goal = http(f"{base}/machine/?comp=goalstate", headers, timeout=10).decode()
    incarnation, container_id, instance_id = azure_goal_state(goal)
    http(f"{base}/machine?comp=health",
         dict(headers, **{"Content-Type": "text/xml;charset=utf-8"}),
         method="POST", timeout=10,
         data=azure_health_report(incarnation, container_id, instance_id))
    return instance_id


MEDIA_SOURCES = (("cidata", "nocloud"), ("CIDATA", "nocloud"),
                 ("config-2", "configdrive"), ("CONFIG-2", "configdrive"))
FAIL_OVER = {"provider-marker-missing"}


def first_boot(root: Path, attempts: int, delay: float) -> dict | None:
    """The boot-time path: produce ``<root>/run/reproos/cloud-enrollment``.

    A ``REPROOS_ENROLL`` medium wins: it is an operator's explicit machine
    enrollment, and this unit then does nothing. Otherwise a labelled
    NoCloud / config-drive volume is used, else the metadata services are
    probed in ``detect_order``. A service that does not answer, or answers
    without its provider's marker, is skipped; any other refusal is final.
    """
    by_label = root / "dev/disk/by-label"
    if (by_label / "REPROOS_ENROLL").exists():
        print("REPROOS_CLOUD:SKIP:machine-enrollment-media-present")
        return None
    out = root / "run/reproos/cloud-enrollment"
    state = root / "var/lib/reproos"
    # After enrollment this runs on every boot as an identity check: a disk
    # copied to another instance must not quietly keep this one's keys and
    # machine-id. normalize() refuses metadata naming another instance; the
    # directory it writes is not consumed again once enrollment is complete.
    if (state / "enrollment.complete").exists() and \
            not (state / "cloud-instance.json").exists():
        print("REPROOS_CLOUD:SKIP:enrolled-without-cloud-metadata")
        return None
    raw_base = root / "run/reproos/cloud-metadata"
    for label, provider in MEDIA_SOURCES:
        device = by_label / label
        if not device.exists():
            continue
        mountpoint = root / "run/reproos/cloud-media"
        mountpoint.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", "-o", "ro", str(device), str(mountpoint)], check=True)
        try:
            raw = raw_base / provider
            shutil.rmtree(raw, ignore_errors=True)
            names = (["meta-data", "user-data"] if provider == "nocloud"
                     else ["openstack/latest/meta_data.json"])
            collect_media(raw, mountpoint, names)
        finally:
            subprocess.run(["umount", str(mountpoint)], check=False)
        return normalize(provider, raw, out, state)
    order = detect_order(dmi_vendor(root / "sys/class/dmi/id"))
    for _ in range(max(1, attempts)):
        for provider in order:
            raw = raw_base / provider
            shutil.rmtree(raw, ignore_errors=True)
            try:
                COLLECTORS[provider](raw)
            except MetadataError as exc:
                if exc.code in FAIL_OVER:
                    continue
                raise
            except (urllib.error.URLError, OSError, ValueError):
                continue
            return normalize(provider, raw, out, state)
        time.sleep(delay)
    raise MetadataError("no-metadata-source",
                        f"no media and no metadata service answered ({' '.join(order)})")


# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    n = sub.add_parser("normalize", help="raw documents -> enrollment directory")
    n.add_argument("--provider", required=True, choices=sorted(NORMALIZERS))
    n.add_argument("--raw", required=True, type=Path)
    n.add_argument("--enroll-out", required=True, type=Path)
    n.add_argument("--state", required=True, type=Path)
    c = sub.add_parser("collect", help="fetch provider documents into --raw")
    c.add_argument("--provider", required=True,
                   choices=sorted(COLLECTORS) + ["nocloud", "configdrive"])
    c.add_argument("--raw", required=True, type=Path)
    c.add_argument("--media", type=Path,
                   help="mounted cidata / config-2 volume (nocloud, configdrive)")
    sub.add_parser("detect-order", help="print the probe order (DMI is a hint only)")
    f = sub.add_parser("first-boot", help="boot-time: media or metadata -> enrollment dir")
    f.add_argument("--root", type=Path, default=Path("/"))
    f.add_argument("--attempts", type=int, default=30)
    f.add_argument("--delay", type=float, default=2.0)
    sub.add_parser("report-ready", help="Azure: report Ready to the WireServer")
    args = parser.parse_args(argv)
    try:
        if args.command == "normalize":
            receipt = normalize(args.provider, args.raw, args.enroll_out, args.state)
            print(f"REPROOS_CLOUD:PASS:provider={receipt['provider']}"
                  f":machine_id={receipt['machine_id']}")
        elif args.command == "collect":
            if args.provider in ("nocloud", "configdrive"):
                if not args.media:
                    raise MetadataError("media-required", args.provider)
                names = (["meta-data", "user-data"] if args.provider == "nocloud"
                         else ["openstack/latest/meta_data.json"])
                collect_media(args.raw, args.media, names)
            else:
                COLLECTORS[args.provider](args.raw)
            print(f"REPROOS_CLOUD:COLLECTED:provider={args.provider}")
        elif args.command == "report-ready":
            reported = azure_report_ready(Path("/var/lib/reproos"))
            print("REPROOS_CLOUD:" + (f"READY:azure:{reported}" if reported
                                      else "SKIP:not-an-azure-instance"))
        elif args.command == "first-boot":
            receipt = first_boot(args.root, args.attempts, args.delay)
            if receipt:
                print(f"REPROOS_CLOUD:PASS:provider={receipt['provider']}"
                      f":machine_id={receipt['machine_id']}")
        else:
            print(" ".join(detect_order(dmi_vendor())))
        return 0
    except MetadataError as exc:
        print(f"REPROOS_CLOUD:FAIL:{exc.code}" + (f": {exc}" if str(exc) != exc.code else ""),
              file=sys.stderr)
        return 3
    except (urllib.error.URLError, OSError) as exc:
        print(f"REPROOS_CLOUD:FAIL:unreachable: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
