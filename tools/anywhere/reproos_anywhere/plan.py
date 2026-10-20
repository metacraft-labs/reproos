"""The conversion plan: every destructive decision, bound and signed.

A plan is a canonical record naming, for ONE machine: the enrollment it
was made for, the inventory and compatibility report it was derived
from, the configuration and its generation, the payload and installer
artifacts by digest, the target disk by serial/size/PCI path, the
storage plan's exact bytes, the network the installer and the installed
system will use, the three SSH identities (source, installer protocol,
installed), the ordered stage list, and references to -- never the
bytes of -- the secrets apply will inject. Its identity is the SHA-256
of those canonical bytes; the controller signs exactly those bytes.

Apply accepts a plan only with that identity typed back by the operator
(``--acknowledge <plan-id>``); a boolean ``--confirm`` or a hostname is
not an acknowledgement. Any drift between the plan and a fresh inventory
taken immediately before the first write refuses the apply and requires
a new plan.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
from pathlib import Path
from typing import Any

from . import canon, keys

SCHEMA = "reproos-anywhere-plan/1"
PLAN_TTL = _dt.timedelta(hours=6)

STAGES = [
    # (stage, destructive?, what it does) -- the M0 contract's ten stages
    # plus the separate non-mutating installed-health gate.
    ("stage-payload", False, "stage the takeover kernel/initrd and kexec in source RAM (tmpfs)"),
    ("takeover", False, "kexec into the takeover environment and verify its console-announced identity"),
    ("destroy", True, "erase every signature on the target disk (point of no return)"),
    ("format", True, "write the canonical partition table and filesystems"),
    ("mount", True, "mount the new layout under the installer's target prefix"),
    ("materialize", True, "stream, verify and unpack the payload root"),
    ("inject-secrets", True, "write per-instance enrollment and the installed host key"),
    ("bootloader", True, "fstab, kernel, initrd, grub-install and grub.cfg via repro infra install-root"),
    ("reboot", True, "unmount and reboot into the installed system"),
    ("final-verification", False, "installed-only health and identity proof over SSH"),
    ("retire-rescue", False, "release temporary rescue resources; the permanent rescue route stays"),
]


class PlanError(ValueError):
    pass


def generate_machine_id() -> str:
    return secrets.token_hex(16)


def build(*, enrollment: dict, enrollment_id: str, inventory_id: str, report: dict,
          report_id: str, config_text: bytes, public_manifest: dict, payload: dict,
          payload_id: str, installer: dict, installer_id: str, controller_pub: str,
          access_pub: str, installed_host_pub: str, machine_id: str,
          takeover: str = "auto", now: _dt.datetime | None = None) -> dict[str, Any]:
    if report["blocked"]:
        raise PlanError("the compatibility report is blocked; there is nothing to plan")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    enroll_expiry = _dt.datetime.strptime(enrollment["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=_dt.timezone.utc)
    expires = min(now + PLAN_TTL, enroll_expiry)
    generation = hashlib.sha256(config_text).hexdigest()
    if payload.get("configuration_generation") != generation:
        raise PlanError(
            f"payload was built for configuration generation {payload.get('configuration_generation')}, "
            f"this configuration is {generation}")
    available = report["takeover"]["available"]
    method = report["takeover"]["default"] if takeover == "auto" else takeover
    if method not in available:
        raise PlanError(f"takeover method {method!r} is not available here (available: {available})")
    layout = report["layout"]
    disko = layout["disko"]
    return {
        "schema": SCHEMA,
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "session": {"id": secrets.token_hex(8), "nonce": secrets.token_hex(16)},
        "machine": {"name": enrollment["name"], "enrollment": enrollment_id,
                    "machine_id": machine_id},
        "inventory": inventory_id,
        "compatibility": report_id,
        "configuration": {
            "generation": generation,
            "public_generation": public_manifest["configuration_generation"],
            "hostname": public_manifest["hostname"],
            "user": public_manifest["remote_access"]["user"],
        },
        "payload": {"id": payload_id, "kind": payload["kind"], "qualified": payload["qualified"],
                    "files": payload["files"], "rootfs_unpacked_bytes": payload["rootfs_unpacked_bytes"]},
        "installer": {"id": installer_id, "kind": installer["kind"], "qualified": installer["qualified"],
                      "files": installer["files"]},
        "conversion_qualified": bool(report["conversion_qualified"]),
        "takeover": method,
        "target": report["target"],
        "network": report["network"],
        "storage": {"layout": layout["layout"], "esp_size_mib": layout["espSizeMib"],
                    "device": layout["device"], "disko": disko,
                    "disko_sha256": hashlib.sha256(disko.encode()).hexdigest()},
        "identities": {
            "source_host_key": enrollment["ssh"]["host_key"],
            "installer": "console-announced ed25519 key bound to session id and nonce",
            "installed_host_key": installed_host_pub,
            "installed_access_key": access_pub,
            "controller": controller_pub,
        },
        "secrets": [
            {"name": "installed-ssh-host-key", "target": "/etc/ssh/ssh_host_ed25519_key",
             "owner": "0:0", "mode": "0600", "public": installed_host_pub},
        ],
        "stages": [{"stage": s, "destructive": d, "intent": w} for s, d, w in STAGES],
    }


# Fields that make each plan unique on purpose: the session nonce (so a
# plan cannot be replayed into another takeover), when it was made, how
# long it lives, and the per-plan machine-id and installed host key.
PER_PLAN_FIELDS = ("session", "created", "expires")


def identity(plan: dict) -> str:
    """What the operator acknowledges: unique per plan."""
    return canon.digest(plan)


def content_identity(plan: dict) -> str:
    """Everything the plan DECIDES -- target, layout bytes, artifacts,
    network, takeover, stages -- without its per-plan uniqueness. Equal
    inventory, configuration and artifacts give equal content identity."""
    body = {k: v for k, v in plan.items() if k not in PER_PLAN_FIELDS}
    body["machine"] = {k: v for k, v in plan["machine"].items() if k != "machine_id"}
    body["identities"] = {k: v for k, v in plan["identities"].items()
                          if k not in ("installed_host_key",)}
    body["secrets"] = [{k: v for k, v in sec.items() if k != "public"} for sec in plan["secrets"]]
    return canon.digest(body)


def save(plan: dict, directory: Path, controller_key: Path) -> str:
    directory.mkdir(parents=True, exist_ok=True)
    plan_id = canon.write(directory / "plan.json", plan)
    (directory / "plan.sig").write_bytes(keys.sign(controller_key, canon.encode(plan)))
    return plan_id


def load_verified(directory: Path, controller_pub: str, acknowledge: str,
                  now: _dt.datetime | None = None, *, allow_expired: bool = False) -> tuple[dict, str]:
    """``allow_expired`` is for RESUMING an apply that already started:
    once a disk is destroyed the plan must stay usable to finish or
    recover it. A fresh apply never starts after the planning window."""
    plan = canon.read(directory / "plan.json")
    plan_id = canon.digest(plan)
    if acknowledge != plan_id:
        raise PlanError(f"acknowledged identity {acknowledge!r} is not this plan's identity {plan_id}")
    if plan.get("schema") != SCHEMA:
        raise PlanError("not an Anywhere plan")
    if plan["identities"]["controller"] != controller_pub:
        raise PlanError("plan was made by a different controller key")
    if not keys.verify(controller_pub, canon.encode(plan), (directory / "plan.sig").read_bytes(),
                       directory / ".verify"):
        raise PlanError("plan signature does not verify")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    expires = _dt.datetime.strptime(plan["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    if now >= expires and not allow_expired:
        raise PlanError(f"plan expired at {plan['expires']}; make a new plan")
    return plan, plan_id
