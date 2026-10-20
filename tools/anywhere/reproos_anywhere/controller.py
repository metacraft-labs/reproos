"""ReproOS Anywhere controller: preflight, plan, apply, resume, verify.

The stages, their order and their rules come from the accepted M0 safety
contract (reprobuild-pm spec/ReproOS-Anywhere-Safety-Contract.md):

  * strict planning makes no remote write; without an independently
    enforced read-only environment, inventory is inspection-only;
  * nothing destructive runs without a signed plan whose identity the
    operator typed back, and a fresh inventory immediately before the
    first write that still matches it;
  * every stage's start is journaled durably before it executes and its
    completion after its postcondition was verified;
  * a lost completion is reconciled against the machine's actual state,
    never replayed blindly (a filesystem is not recreated because an SSH
    acknowledgement went missing);
  * success is claimed only by the installed system, identified by keys
    and values the old system and the installer cannot present.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any, Callable

from . import canon, compat, cpio, enrollment as enrollment_mod, inventory, keys
from . import plan as plan_mod
from .journal import Journal
from .rescue import RescueError, adapter as rescue_adapter
from .transport import Endpoint, HostKeyRejected, Session, TransportError, fingerprint, \
    parse_host_key, sh_quote, sha256_file

TOOLS = Path(__file__).resolve().parent.parent          # tools/anywhere
REPO = TOOLS.parent.parent                              # reproos/
PROBE = TOOLS / "probe.sh"
INSTALLER_WORK = "/run/anywhere/work"
TARGET_ROOT = "/mnt"
READY_RE = re.compile(r"REPROOS_ANYWHERE_INSTALLER:READY session=([0-9a-f]+) nonce=([0-9a-f]+) "
                      r"boot_id=([0-9a-f-]+) hostkey=(ssh-ed25519 [A-Za-z0-9+/=]+)")
FAIL_RE = re.compile(r"REPROOS_ANYWHERE_INSTALLER:FAIL:\S+")


class AnywhereError(RuntimeError):
    pass


class Refused(AnywhereError):
    """Nothing was changed; the operator must replan or fix inputs."""


# ---------------------------------------------------------------------------
# Inputs.
# ---------------------------------------------------------------------------

def _machine_config_module():
    spec = importlib.util.spec_from_file_location(
        "reproos_machine_config", REPO / "tools" / "reproos-machine-config.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Artifacts:
    """The payload and installer directories, verified against their manifests."""

    def __init__(self, payload_dir: Path, installer_dir: Path, kexec: Path):
        self.payload_dir, self.installer_dir, self.kexec = payload_dir, installer_dir, kexec
        self.payload = json.loads((payload_dir / "manifest.json").read_text())
        self.installer = json.loads((installer_dir / "manifest.json").read_text())
        for directory, manifest in ((payload_dir, self.payload), (installer_dir, self.installer)):
            for name, meta in manifest["files"].items():
                actual = sha256_file(directory / name)
                if actual != meta["sha256"]:
                    raise Refused(f"{directory / name}: sha256 {actual} is not the manifest's {meta['sha256']}")
        self.payload_id = canon.digest(self.payload)
        self.installer_id = canon.digest(self.installer)


def render_layout_with(layout_tool: Path, config_path: Path) -> Callable[[str, int], dict]:
    def render(device: str, size_gb: int) -> dict:
        proc = subprocess.run([str(layout_tool), str(config_path), device, str(size_gb)],
                              capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            raise AnywhereError(f"anywhere_layout failed: {proc.stderr.strip()}")
        return json.loads(proc.stdout)
    return render


class State:
    """Controller-side state for one machine, under ``<state>/<name>/``."""

    def __init__(self, root: Path, name: str):
        self.root = root
        self.dir = root / name
        self.work = self.dir / "work"
        self.keys = self.dir / "keys"
        for d in (self.dir, self.work, self.keys):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.controller_key = root / "controller" / "id_ed25519"
        self.controller_pub = keys.ensure_keypair(self.controller_key, "reproos-anywhere-controller")


# ---------------------------------------------------------------------------
# Preflight (M1).
# ---------------------------------------------------------------------------

def source_session(enr: dict, state: State) -> Session:
    s = enr["ssh"]
    return Session(Endpoint(s["address"], s["port"], s["user"], s["host_key"],
                            Path(s["identity_file"]), s["privilege"]), state.work)


def run_probe(session: Session) -> tuple[str, dict]:
    text = session.run("sh -s", stdin=PROBE.read_bytes(), privileged=True, timeout=120).stdout
    raw = text.decode("ascii", "replace")
    return raw, inventory.parse(raw)


def preflight(*, enrollment_path: Path, config_path: Path, artifacts: Artifacts,
              layout_tool: Path, state_root: Path, inspection: bool) -> dict:
    enr = enrollment_mod.load(enrollment_path)
    state = State(state_root, enr["name"])
    strict = enr["readonly"] is not None
    if not strict and not inspection:
        raise Refused(
            "strict preflight needs an independently enforced read-only environment "
            "(enrollment [readonly]); an ordinary SSH login writes accounting logs and access "
            "times. Re-run with --inspection to collect a diagnostic inventory that can NOT "
            "be planned against.")
    if strict and inspection:
        raise Refused("--inspection is for machines without a read-only receipt")
    rescue = rescue_adapter(enr["rescue"])
    if not rescue.reachable():
        raise Refused(f"rescue route {enr['rescue']['monitor']} is not reachable; "
                      "no conversion is planned without one")
    mc = _machine_config_module()
    config_text = config_path.read_bytes()
    config = tomllib.loads(config_text.decode())
    public = mc.validate_public(config)

    session = source_session(enr, state)
    raw, inv = run_probe(session)
    report = compat.evaluate(inv, enr, config, artifacts.payload, artifacts.installer,
                             render_layout_with(layout_tool, config_path),
                             strict_readonly=strict)
    if "target" in report:
        want = config.get("install", {}).get("target_device")
        have = f"/dev/{report['target']['kernel_name']}"
        if want != have:
            report["checks"].append({"id": "configuration-target", "verdict": "fail",
                                     "detail": f"configuration install.target_device = {want!r}, "
                                               f"the enrolled target disk is {have}"})
            report["blocked"] = True
            for k in ("target", "network", "layout"):
                report.pop(k, None)
        else:
            report["checks"].append({"id": "configuration-target", "verdict": "pass", "detail": have})
    if inspection:
        report["inspection_only"] = True
        report["blocked"] = True
        report["checks"].append({"id": "planning-environment", "verdict": "fail",
                                 "detail": "inspection-only inventory from a mutable host: the SSH "
                                           "login itself may have written logs and access times"})
    else:
        report["inspection_only"] = False
        report["planning_environment"] = enr["readonly"]
    inv_id = canon.write(state.dir / "inventory.json", inv)
    (state.dir / "probe.out").write_text(raw)
    enr_id = canon.write(state.dir / "enrollment.json", enr)
    report.update({"inventory": inv_id, "enrollment": enr_id,
                   "configuration_generation": hashlib.sha256(config_text).hexdigest(),
                   "payload": artifacts.payload_id, "installer": artifacts.installer_id})
    rep_id = canon.write(state.dir / "compatibility.json", report)
    report["id"] = rep_id
    return report


# ---------------------------------------------------------------------------
# Plan (M3).
# ---------------------------------------------------------------------------

def make_plan(*, state_root: Path, name: str, config_path: Path, artifacts: Artifacts,
              takeover: str = "auto") -> str:
    state = State(state_root, name)
    enr = canon.read(state.dir / "enrollment.json")
    report = canon.read(state.dir / "compatibility.json")
    if report.get("inspection_only"):
        raise Refused("an inspection-only inventory cannot be planned against")
    if report["blocked"]:
        raise Refused("the compatibility report is blocked: " +
                      "; ".join(f"{c['id']}: {c['detail']}" for c in report["checks"]
                                if c["verdict"] == "fail"))
    if report["payload"] != artifacts.payload_id or report["installer"] != artifacts.installer_id:
        raise Refused("artifacts changed since preflight; run preflight again")
    mc = _machine_config_module()
    config_text = config_path.read_bytes()
    if hashlib.sha256(config_text).hexdigest() != report["configuration_generation"]:
        raise Refused("configuration changed since preflight; run preflight again")
    public = mc.validate_public(tomllib.loads(config_text.decode()))
    access_pub = keys.ensure_keypair(state.keys / "access_ed25519", f"reproos-anywhere-access-{name}")
    host_key = state.keys / "installed_host_ed25519"
    if host_key.exists():
        host_key.unlink()
        Path(str(host_key) + ".pub").unlink()
    installed_pub = keys.ensure_keypair(host_key, f"root@{public['hostname']}")
    plan = plan_mod.build(
        enrollment=enr, enrollment_id=canon.digest(enr),
        inventory_id=report["inventory"], report=report, report_id=canon.digest(report),
        config_text=config_text, public_manifest=public, payload=artifacts.payload,
        payload_id=artifacts.payload_id, installer=artifacts.installer,
        installer_id=artifacts.installer_id, controller_pub=state.controller_pub,
        access_pub=access_pub, installed_host_pub=installed_pub,
        machine_id=plan_mod.generate_machine_id(), takeover=takeover)
    shutil.copyfile(config_path, state.dir / "auto-config.toml")
    plan_dir = state.dir / "plan"
    if plan_dir.exists():
        shutil.rmtree(plan_dir)
    return plan_mod.save(plan, plan_dir, state.controller_key)


# ---------------------------------------------------------------------------
# Apply (M2-M4).
# ---------------------------------------------------------------------------

class Apply:
    def __init__(self, *, state_root: Path, name: str, acknowledge: str, artifacts: Artifacts,
                 log: Callable[[str], None] = print, sinks=(), resume: bool = False,
                 max_rate: int = 0):
        self.state = State(state_root, name)
        self.log = log
        self.max_rate = max_rate        # bytes/s for payload transfer; 0 = unbounded
        self.artifacts = artifacts
        journal_path = self.state.dir / "journal.jsonl"
        self.resume = resume
        # An apply that already destroyed something must be resumable after
        # the plan's planning window closes; a fresh apply must not start late.
        self.plan, self.plan_id = plan_mod.load_verified(
            self.state.dir / "plan", self.state.controller_pub, acknowledge,
            allow_expired=resume and journal_path.exists())
        if journal_path.exists() and not resume:
            raise Refused(f"{journal_path} exists: this plan was already applied; use resume")
        if resume and not journal_path.exists():
            raise Refused("nothing to resume: no journal for this plan")
        if artifacts.payload_id != self.plan["payload"]["id"] or \
                artifacts.installer_id != self.plan["installer"]["id"]:
            raise Refused("payload or installer artifacts are not the ones the plan names")
        self.enr = canon.read(self.state.dir / "enrollment.json")
        self.journal = Journal(journal_path, self.plan_id, sinks)
        self.journal.mirrors.append(self.mirror_to_host)
        self.rescue = rescue_adapter(self.enr["rescue"])
        self.config_text = (self.state.dir / "auto-config.toml").read_bytes()
        if hashlib.sha256(self.config_text).hexdigest() != self.plan["configuration"]["generation"]:
            raise Refused("the saved configuration no longer matches the plan")
        self.target = self.plan["target"]
        self.device = self.plan["storage"]["device"]
        self.hash = self.plan_id
        self._installer: Session | None = None
        self._source: Session | None = None

    # -- host mirror -----------------------------------------------------
    HOST_JOURNAL = "/run/anywhere/journal.jsonl"
    DISK_JOURNAL = f"{TARGET_ROOT}/var/log/reproos-anywhere/journal.jsonl"

    def mirror_to_host(self, record: bytes) -> None:
        done = set(self.journal.completed())
        if "takeover" not in done or "reboot" in done:
            return
        inst = self.installer()
        targets = [self.HOST_JOURNAL]
        if "mount" in done:
            targets.append(self.DISK_JOURNAL)
        for path in targets:
            inst.run(f"mkdir -p $(dirname {path}) && cat >> {path}", stdin=record + b"\n", timeout=30)

    # -- endpoints -------------------------------------------------------
    def source(self) -> Session:
        if self._source is None:
            self._source = source_session(self.enr, self.state)
        return self._source

    def installer(self) -> Session:
        if self._installer is None:
            ev = self.journal.evidence("takeover")
            s = self.enr["ssh"]
            self._installer = Session(Endpoint(s["address"], s["port"], "root", ev["installer_host_key"],
                                               self.state.controller_key, "root"), self.state.work)
        return self._installer

    def installed(self) -> Session:
        s = self.enr["ssh"]
        return Session(Endpoint(s["address"], s["port"], self.plan["configuration"]["user"],
                                self.plan["identities"]["installed_host_key"],
                                self.state.keys / "access_ed25519", "root"), self.state.work)

    # -- driver ----------------------------------------------------------
    def run(self) -> dict:
        stages = [s["stage"] for s in self.plan["stages"]]
        if not self.resume:
            self.recheck_source()
        done = set(self.journal.completed())
        open_stage = self.journal.open_stage()
        for stage in stages:
            if stage in done:
                continue
            handler = getattr(self, "stage_" + stage.replace("-", "_"))
            if open_stage == stage:
                try:
                    finding = getattr(self, "reconcile_" + stage.replace("-", "_"))()
                except Refused as error:
                    self.journal.abort(stage, f"reconciliation refused: {str(error)[:2000]}")
                    raise
                self.journal.reconcile(stage, finding)
                self.log(f"[{stage}] reconciled: {finding['state']}")
                if finding["state"] == "done":
                    self.journal.complete(stage, finding["evidence"])
                    continue
                if finding["state"] != "redo":
                    raise AnywhereError(f"{stage}: cannot resume safely ({finding['detail']}); "
                                        f"use the rescue route {self.enr['rescue']['console_log']}")
            else:
                self.journal.start(stage, {"intent": next(s["intent"] for s in self.plan["stages"]
                                                          if s["stage"] == stage)})
            open_stage = None
            self.log(f"[{stage}] start")
            try:
                evidence = handler()
            except Refused as error:
                # A refusal changed nothing: close the stage so a later
                # resume starts it afresh instead of "reconciling" it.
                self.journal.abort(stage, str(error)[:2000])
                self.log(f"[{stage}] REFUSED: {error}")
                raise
            except Exception as error:
                self.log(f"[{stage}] FAILED: {error}")
                raise
            self.journal.complete(stage, evidence)
            self.log(f"[{stage}] complete")
        return self.journal.evidence("final-verification")

    # -- the fresh pre-write inventory -----------------------------------
    def recheck_source(self) -> None:
        raw, inv = run_probe(self.source())
        problems = []
        disk = inv["disks"].get(self.target["kernel_name"])
        if disk is None:
            problems.append(f"{self.target['kernel_name']} is gone")
        else:
            for field in ("serial", "size_sectors", "syspath", "devnum", "logical_block"):
                if disk[field] != self.target[field]:
                    problems.append(f"target {field} {disk[field]!r} != planned {self.target[field]!r}")
        mgmt = inventory.management_interface(inv)
        if mgmt is None or mgmt["mac"] != self.plan["network"]["mac"]:
            problems.append("management interface changed")
        uuid = self.enr["machine"].get("product_uuid")
        if uuid and inv["dmi"].get("product_uuid", "").lower() != uuid:
            problems.append("machine identity changed")
        if problems:
            raise Refused("the machine drifted since planning; make a new plan: " + "; ".join(problems))
        self.source_boot_id = self.source().run("cat /proc/sys/kernel/random/boot_id").stdout.decode().strip()

    # -- stage: stage-payload --------------------------------------------
    def staging_dir(self) -> str:
        return f"/dev/shm/reproos-anywhere-{self.plan['session']['id']}"

    def session_initrd(self) -> Path:
        handoff = {
            "plan": self.plan_id, "session": self.plan["session"]["id"],
            "nonce": self.plan["session"]["nonce"], "target_serial": self.target["serial"],
            "expires": self.plan["expires"],
        }
        handoff_bytes = canon.encode(handoff)
        archive = cpio.build([
            (".", 0o755, None), ("etc", 0o755, None), ("etc/anywhere", 0o755, None),
            ("etc/anywhere/authorized_keys", 0o600, (self.state.controller_pub + "\n").encode()),
            ("etc/anywhere/handoff.json", 0o644, handoff_bytes),
            ("etc/anywhere/handoff.sig", 0o644, keys.sign(self.state.controller_key, handoff_bytes)),
        ])
        base = (self.artifacts.installer_dir / "initrd.img").read_bytes()
        out = self.state.work / f"takeover-initrd-{self.plan['session']['id']}.img"
        out.write_bytes(cpio.append_to_initrd(base, archive))
        return out

    def takeover_cmdline(self) -> str:
        session, nonce = self.plan["session"]["id"], self.plan["session"]["nonce"]
        return (f"console=tty0 console=ttyS0,115200 anywhere.session={session} "
                f"anywhere.nonce={nonce} anywhere.mac={self.plan['network']['mac']} anywhere.net=dhcp")

    def stage_stage_payload(self) -> dict:
        if self.plan["takeover"] == "rescue-media":
            # Nothing goes onto the source: the management plane boots the
            # takeover image, so the source kernel never handles it.
            initrd = self.session_initrd()
            return {"method": "rescue-media", "staged_on_source": [],
                    "session_initrd": sha256_file(initrd)}
        src = self.source()
        d = self.staging_dir()
        src.run(f"umask 077 && mkdir -p {d} && df -k /dev/shm | tail -1", privileged=True)
        initrd = self.session_initrd()
        files = {
            "vmlinuz": (self.artifacts.installer_dir / "vmlinuz", self.plan["installer"]["files"]["vmlinuz"]["sha256"]),
            "initrd.img": (initrd, sha256_file(initrd)),
            "kexec": (self.artifacts.kexec, sha256_file(self.artifacts.kexec)),
        }
        evidence = {"dir": d, "files": {}}
        for name, (path, want) in files.items():
            got = src.upload(path, f"{d}/{name}", privileged=True)
            if got != want:
                raise AnywhereError(f"staged {name} has sha256 {got}, expected {want}")
            evidence["files"][name] = want
        src.run(f"chmod 0700 {d}/kexec", privileged=True)
        return evidence

    def reconcile_stage_payload(self) -> dict:
        return {"state": "redo", "detail": "staging is RAM-only and idempotent", "evidence": {}}

    # -- stage: takeover -------------------------------------------------
    def stage_takeover(self) -> dict:
        src = self.source()
        if not hasattr(self, "source_boot_id"):
            self.source_boot_id = src.run("cat /proc/sys/kernel/random/boot_id").stdout.decode().strip()
        session, nonce = self.plan["session"]["id"], self.plan["session"]["nonce"]
        cmdline = self.takeover_cmdline()
        offset = self.rescue.console_offset()
        if self.plan["takeover"] == "rescue-media":
            initrd = self.session_initrd()
            trigger = "rescue-media"
            self.rescue.boot_media(str(self.artifacts.installer_dir / "vmlinuz"), str(initrd), cmdline)
        else:
            d = self.staging_dir()
            # Re-verify what was staged immediately before executing it: the
            # stage-payload completion is evidence of what was written then,
            # not of what is there now.
            staged = self.journal.evidence("stage-payload")["files"]
            out = src.run(f"cd {d} && sha256sum vmlinuz initrd.img kexec", privileged=True).stdout.decode()
            now = {line.split()[1]: line.split()[0] for line in out.splitlines() if line.strip()}
            if now != staged:
                raise Refused(f"the staged takeover image changed on the source since it was verified "
                              f"(staged {staged}, now {now}); the source is not trustworthy for kexec "
                              f"takeover -- use --takeover rescue-media")
            src.run(f"{d}/kexec -l {d}/vmlinuz --initrd={d}/initrd.img --command-line={sh_quote(cmdline)}",
                    privileged=True)
            pid1 = src.run("cat /proc/1/comm").stdout.decode().strip()
            trigger = ("systemctl kexec" if pid1 == "systemd"
                       else f"sync; {d}/kexec -e")
            # The channel dies with the old kernel; the command is detached so
            # the controller does not mistake that for a failure.
            src.run(f"nohup sh -c {sh_quote('sleep 2; ' + trigger)} >/dev/null 2>&1 &",
                    privileged=True, check=False, timeout=30)
        self.log("[takeover] waiting for the installer's console announcement")
        m = self.rescue.wait_for_line(offset, READY_RE, timeout=300, fail=FAIL_RE)
        # Anything else that can write this console before the installer
        # does (a compromised source, on the kexec path) could print an
        # announcement too: settle, then require exactly one, for exactly
        # this session and nonce.
        time.sleep(5)
        seen = {(a.group(1), a.group(2), a.group(4))
                for a in READY_RE.finditer(self.rescue.console_since(offset))}
        if len(seen) != 1:
            raise Refused(f"{len(seen)} different installer announcements appeared on the rescue "
                          "console during takeover; refusing to pick one")
        if m.group(1) != session or m.group(2) != nonce:
            raise Refused("console announcement carries another session or nonce")
        host_key = m.group(4)
        boot_id = m.group(3)
        if boot_id == self.source_boot_id:
            raise AnywhereError("the installer reports the source system's boot id")
        self._installer = None
        inst = Session(Endpoint(self.enr["ssh"]["address"], self.enr["ssh"]["port"], "root", host_key,
                                self.state.controller_key, "root"), self.state.work)
        deadline = time.monotonic() + 120
        while not inst.reachable():
            if time.monotonic() > deadline:
                raise AnywhereError("installer announced itself but its SSH is unreachable")
            time.sleep(3)
        ident = dict(line.split("=", 1) for line in
                     inst.run("cat /run/anywhere/identity").stdout.decode().splitlines() if "=" in line)
        cmd = inst.run("cat /proc/cmdline").stdout.decode()
        if ident.get("session") != session or ident.get("nonce") != nonce or \
                ident.get("boot_id") != boot_id or ident.get("hostkey") != host_key or \
                f"anywhere.nonce={nonce}" not in cmd:
            raise AnywhereError("installer identity does not match its console announcement")
        return {"installer_host_key": host_key,
                "installer_fingerprint": fingerprint(*parse_host_key(host_key)),
                "installer_boot_id": boot_id, "source_boot_id": self.source_boot_id,
                "kexec_trigger": trigger}

    def reconcile_takeover(self) -> dict:
        offset = 0
        text = self.rescue.console_since(offset)
        found = [m for m in READY_RE.finditer(text)
                 if m.group(1) == self.plan["session"]["id"] and m.group(2) == self.plan["session"]["nonce"]]
        if not found:
            try:
                self.source().run("true", timeout=20)
                return {"state": "redo", "detail": "source still running; takeover not yet entered",
                        "evidence": {}}
            except TransportError:
                return {"state": "stuck", "detail": "neither the source nor an announced installer answers",
                        "evidence": {}}
        m = found[-1]
        inst = Session(Endpoint(self.enr["ssh"]["address"], self.enr["ssh"]["port"], "root", m.group(4),
                                self.state.controller_key, "root"), self.state.work)
        if not inst.reachable():
            return {"state": "stuck", "detail": "announced installer is unreachable", "evidence": {}}
        return {"state": "done", "detail": "installer already running",
                "evidence": {"installer_host_key": m.group(4),
                             "installer_fingerprint": fingerprint(*parse_host_key(m.group(4))),
                             "installer_boot_id": m.group(3), "source_boot_id": "unknown-after-resume",
                             "kexec_trigger": "reconciled"}}

    # -- installer-side helpers ------------------------------------------
    BROKER_OPS = "/run/anywhere/ops"
    # The irreversible operations; mount/unmount are idempotent and run inline.
    MUTATING = ("destroy", "apply", "install-root")

    def broker(self, args: str, *, timeout: float = 900) -> dict:
        """Run one storage-broker operation in the installer.

        Mutating operations run DETACHED from the SSH session, keyed by an
        operation id over the plan and the exact arguments, with their
        verdict and exit status written beside them. A dropped connection
        or a killed controller therefore never interrupts a half-written
        partition table, and a resumed controller re-attaches to the same
        operation -- running or finished -- instead of starting it again."""
        inst = self.installer()
        if args.split()[0] not in self.MUTATING:
            proc = inst.run(f"anywhere_disk {args}", check=False, timeout=600)
            return self._verdict(args, proc.stdout.decode(), proc.returncode, proc.stderr.decode())
        op = hashlib.sha256(f"{self.plan_id}\0{args}".encode()).hexdigest()[:20]
        base = f"{self.BROKER_OPS}/{op}"
        inst.run(f"mkdir -p {self.BROKER_OPS} && if [ ! -e {base}.args ]; then "
                 f"printf '%s\\n' {sh_quote(args)} > {base}.args && "
                 f"setsid sh -c {sh_quote(f'anywhere_disk {args} > {base}.out 2> {base}.err; echo $? > {base}.rc')} "
                 f"< /dev/null > /dev/null 2>&1 & fi")
        deadline = time.monotonic() + timeout
        while True:
            rc = inst.run(f"cat {base}.rc 2>/dev/null", check=False, timeout=30).stdout.decode().strip()
            if rc:
                out = inst.run(f"cat {base}.out; cat {base}.err >&2", check=False, timeout=30)
                return self._verdict(args, out.stdout.decode(), int(rc), out.stderr.decode(), op=op)
            if time.monotonic() > deadline:
                raise AnywhereError(f"broker {args.split()[0]} (operation {op}) did not finish in {timeout}s")
            time.sleep(1)

    def _verdict(self, args: str, stdout: str, rc: int, stderr: str, op: str = "") -> dict:
        try:
            result = json.loads(stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as error:
            raise AnywhereError(f"broker gave no verdict ({rc}): {stderr[-500:]}") from error
        if op:
            result["operation"] = op
        if not result.get("ok"):
            kind = Refused if result.get("refused") else AnywhereError
            raise kind(f"broker {args.split()[0]}: {result.get('error')}")
        return result

    def put_disko(self) -> str:
        inst = self.installer()
        local = self.state.work / "disko.json"
        local.write_text(self.plan["storage"]["disko"])
        inst.run(f"mkdir -p {INSTALLER_WORK}")
        got = inst.upload(local, f"{INSTALLER_WORK}/disko.json")
        if got != self.plan["storage"]["disko_sha256"]:
            raise AnywhereError("storage plan bytes changed in transit")
        return f"{INSTALLER_WORK}/disko.json"

    def check_target_path(self) -> None:
        inst = self.installer()
        name = self.target["kernel_name"]
        syspath = inst.run(f"readlink /sys/block/{name}", check=False).stdout.decode().strip()
        if syspath != self.target["syspath"]:
            raise Refused(f"in the takeover environment {name} is at {syspath!r}, the plan bound "
                          f"{self.target['syspath']!r}; a reordered or replaced disk needs a new plan")

    def prove_target(self) -> None:
        """Before ANY look at or write to the target from the installer --
        including reconciliation -- prove it is still the planned disk."""
        self.check_target_path()
        self.broker("resolve " + f"--serial {sh_quote(self.target['serial'])} "
                    f"--size-sectors {self.target['size_sectors']}")

    def target_flags(self) -> str:
        return (f"--device {self.device} --serial {sh_quote(self.target['serial'])} "
                f"--size-sectors {self.target['size_sectors']} --confirm-plan {self.hash}")

    # -- stage: destroy ---------------------------------------------------
    def stage_destroy(self) -> dict:
        self.prove_target()
        result = self.broker("destroy " + self.target_flags())
        return {"broker": result, **self.verify_erased()}

    def verify_erased(self) -> dict:
        inst = self.installer()
        name = self.target["kernel_name"]
        probe = inst.run(f"blkid -p {self.device}; echo rc=$?; ls /sys/block/{name}", check=False)
        out = probe.stdout.decode()
        if "rc=2" not in out or re.search(rf"\b{name}p?\d+\b", out.split("rc=")[1]):
            raise AnywhereError(f"target still carries signatures or partitions:\n{out}")
        return {"erased": True}

    def reconcile_destroy(self) -> dict:
        self.prove_target()
        if self.layout_state() == "formatted":
            return {"state": "done", "detail": "layout already present (format had also run)",
                    "evidence": {"reconciled": "formatted"}}
        # Re-attach to the keyed destroy operation (or run it, if the crash
        # came before it started); erasing an erased disk is harmless.
        result = self.broker("destroy " + self.target_flags())
        return {"state": "done", "detail": f"destroy operation {result['operation']}",
                "evidence": {"operation": result["operation"], **self.verify_erased()}}

    # -- stage: format ----------------------------------------------------
    def layout_state(self) -> str:
        inst = self.installer()
        out = inst.run(f"blkid -o export {self.device}1 {self.device}2", check=False).stdout.decode()
        if "LABEL=ESP" in out and "LABEL=reproos-root" in out:
            return "formatted"
        return "partial" if out.strip() else "empty"

    def stage_format(self) -> dict:
        self.prove_target()
        path = self.put_disko()
        result = self.broker(f"apply {path} " + self.target_flags())
        if self.layout_state() != "formatted":
            raise AnywhereError("format reported success but the layout labels are absent")
        return {"broker_operations": len(result["operations"]),
                "disko_sha256": self.plan["storage"]["disko_sha256"]}

    def reconcile_format(self) -> dict:
        self.prove_target()
        # Never recreate a filesystem because an acknowledgement was lost:
        # the format operation is keyed, so asking for it again re-attaches
        # to the one that ran (or is running) instead of formatting twice.
        path = self.put_disko()
        result = self.broker(f"apply {path} " + self.target_flags())
        if self.layout_state() != "formatted":
            return {"state": "stuck", "detail": "the format operation finished but the layout is absent",
                    "evidence": {}}
        return {"state": "done", "detail": f"format operation {result['operation']} already ran",
                "evidence": {"reconciled": "formatted", "operation": result["operation"]}}

    # -- stage: mount -----------------------------------------------------
    def mounted(self) -> bool:
        out = self.installer().run("cat /proc/self/mounts").stdout.decode()
        return f"{self.device}2 {TARGET_ROOT} " in out and f"{self.device}1 {TARGET_ROOT}/boot " in out

    def stage_mount(self) -> dict:
        path = self.put_disko()
        if not self.mounted():
            self.installer().run(f"mkdir -p {TARGET_ROOT}")
            self.broker(f"mount {path} --target {TARGET_ROOT}")
        if not self.mounted():
            raise AnywhereError("target layout is not mounted as planned")
        return {"root": f"{self.device}2", "esp": f"{self.device}1", "prefix": TARGET_ROOT}

    def reconcile_mount(self) -> dict:
        return {"state": "redo", "detail": "mount is idempotent", "evidence": {}}

    # -- stage: materialize -----------------------------------------------
    def upload_resumable(self, local: Path, remote: str, want: str) -> None:
        inst = self.installer()
        size = local.stat().st_size
        have = inst.run(f"stat -c %s {remote} 2>/dev/null || echo 0").stdout.decode().strip()
        have = int(have) if have.isdigit() else 0
        if have > size:
            inst.run(f"rm -f {remote}")
            have = 0
        if have < size:
            self.log(f"[materialize] sending {local.name} from byte {have} of {size}"
                     + (f" at most {self.max_rate} B/s" if self.max_rate else ""))
            inst.stream(local, have, f"cat >> {remote}", max_rate=self.max_rate)
        got = inst.run(f"sha256sum {remote}").stdout.decode().split()[0]
        if got != want:
            inst.run(f"rm -f {remote}")
            raise AnywhereError(f"{remote} has sha256 {got}, expected {want}; discarded, retry resumes from 0")

    def stage_materialize(self) -> dict:
        inst = self.installer()
        if not self.mounted():
            raise AnywhereError("target is not mounted")
        files = self.plan["payload"]["files"]
        inst.run(f"mkdir -p {TARGET_ROOT}/.anywhere {INSTALLER_WORK}")
        self.upload_resumable(self.artifacts.payload_dir / "rootfs.tar.zst",
                              f"{TARGET_ROOT}/.anywhere/rootfs.tar.zst", files["rootfs.tar.zst"]["sha256"])
        for name in ("vmlinuz", "initrd.img"):
            self.upload_resumable(self.artifacts.payload_dir / name, f"{INSTALLER_WORK}/{name}",
                                  files[name]["sha256"])
        inst.run(f"cd {TARGET_ROOT} && zstd -dc .anywhere/rootfs.tar.zst | tar -xpf - --numeric-owner "
                 f"&& rm -rf {TARGET_ROOT}/.anywhere && sync", timeout=1800)
        return self.verify_materialized()

    def verify_materialized(self) -> dict:
        inst = self.installer()
        gen = inst.run(f"cat {TARGET_ROOT}/etc/repro/generation", check=False).stdout.decode().strip()
        os_id = inst.run(f". {TARGET_ROOT}/etc/os-release && echo $ID", check=False).stdout.decode().strip()
        if gen != self.plan["configuration"]["generation"] or os_id != "reproos":
            raise AnywhereError(f"materialized root is not the planned payload (ID={os_id!r}, generation={gen!r})")
        return {"payload": self.plan["payload"]["id"], "generation": gen,
                "rootfs_sha256": self.plan["payload"]["files"]["rootfs.tar.zst"]["sha256"]}

    def reconcile_materialize(self) -> dict:
        try:
            if self.mounted():
                left = self.installer().run(f"test -e {TARGET_ROOT}/.anywhere && echo partial || echo clean").stdout.decode()
                if "clean" in left:
                    return {"state": "done", "detail": "payload unpacked", "evidence": self.verify_materialized()}
        except AnywhereError:
            pass
        return {"state": "redo", "detail": "transfer resumes from the bytes already verified on disk",
                "evidence": {}}

    # -- stage: inject-secrets --------------------------------------------
    def put_bytes(self, data: bytes, remote: str, mode: str) -> None:
        inst = self.installer()
        tmp = self.state.work / "inject.tmp"
        tmp.write_bytes(data)
        tmp.chmod(0o600)
        try:
            inst.run(f"umask 077 && mkdir -p $(dirname {remote}) && cat > {remote} && chmod {mode} {remote}",
                     stdin_file=tmp)
            got = inst.run(f"sha256sum {remote}").stdout.decode().split()[0]
        finally:
            tmp.unlink()
        if got != hashlib.sha256(data).hexdigest():
            raise AnywhereError(f"{remote}: written bytes do not verify")

    def secret_files(self) -> list[tuple[str, bytes, str]]:
        host_key = self.state.keys / "installed_host_ed25519"
        enroll = f"{TARGET_ROOT}/var/lib/reproos/anywhere-enrollment"
        access = (self.state.keys / "access_ed25519.pub").read_text()
        return [
            (f"{enroll}/machine-id", (self.plan["machine"]["machine_id"] + "\n").encode(), "0644"),
            # The machine's identity is set before its first boot: an empty
            # /etc/machine-id makes systemd bind-mount a transient one
            # read-only, and first-boot enrollment then races it.
            (f"{TARGET_ROOT}/etc/machine-id", (self.plan["machine"]["machine_id"] + "\n").encode(), "0444"),
            (f"{enroll}/authorized_keys", access.encode(), "0644"),
            (f"{TARGET_ROOT}/etc/systemd/system/reproos-first-boot-enroll.service.d/anywhere.conf",
             b"[Service]\nEnvironment=REPROOS_ENROLLMENT_DIR=/var/lib/reproos/anywhere-enrollment\n", "0644"),
            (f"{TARGET_ROOT}/etc/ssh/ssh_host_ed25519_key", host_key.read_bytes(), "0600"),
            (f"{TARGET_ROOT}/etc/ssh/ssh_host_ed25519_key.pub",
             Path(str(host_key) + ".pub").read_bytes(), "0644"),
        ]

    def stage_inject_secrets(self) -> dict:
        evidence = {}
        for remote, data, mode in self.secret_files():
            self.put_bytes(data, remote, mode)
            secret = "ssh_host_ed25519_key" in remote and not remote.endswith(".pub")
            evidence[remote[len(TARGET_ROOT):]] = "redacted" if secret else hashlib.sha256(data).hexdigest()
        evidence["installed_fingerprint"] = fingerprint(*parse_host_key(self.plan["identities"]["installed_host_key"]))
        return evidence

    def reconcile_inject_secrets(self) -> dict:
        return {"state": "redo", "detail": "rewriting the same bytes is idempotent", "evidence": {}}

    # -- stage: bootloader --------------------------------------------------
    def stage_bootloader(self) -> dict:
        inst = self.installer()
        gen = self.plan["configuration"]["generation"]
        receipt = {"schema_version": 1, "configuration_generation": gen,
                   "install_source": "anywhere", "target_device": self.device}
        anywhere_receipt = {
            "schema": "reproos-anywhere-install-receipt/1", "plan": self.plan_id,
            "payload": self.plan["payload"]["id"], "installer": self.plan["installer"]["id"],
            "session": self.plan["session"]["id"], "target_serial": self.target["serial"],
            "conversion_qualified": self.plan["conversion_qualified"],
        }
        state = f"{TARGET_ROOT}/var/lib/reproos"
        self.put_bytes(b"anywhere\n", f"{state}/install-source", "0644")
        self.put_bytes(json.dumps(receipt, sort_keys=True).encode() + b"\n",
                       f"{state}/installation-receipt.json", "0644")
        self.put_bytes(canon.encode(anywhere_receipt), f"{state}/anywhere-receipt.json", "0644")
        self.put_bytes(self.plan["storage"]["disko"].encode(), f"{TARGET_ROOT}/etc/repro/disko.json", "0644")
        disko = self.put_disko()
        result = self.broker(
            f"install-root --no-rsync --target {TARGET_ROOT} --source {TARGET_ROOT} --device {self.device} "
            f"--disko {disko} --kernel {INSTALLER_WORK}/vmlinuz --initrd {INSTALLER_WORK}/initrd.img "
            f"--hostname {sh_quote(self.plan['configuration']['hostname'])}")
        return {"install_root": result, **self.verify_bootloader()}

    def verify_bootloader(self) -> dict:
        inst = self.installer()
        files = self.plan["payload"]["files"]
        out = inst.run(f"test -s {TARGET_ROOT}/boot/EFI/BOOT/BOOTX64.EFI && echo efi; "
                       f"grep -c 'root={self.device}2' {TARGET_ROOT}/boot/grub/grub.cfg; "
                       f"sha256sum {TARGET_ROOT}/boot/vmlinuz {TARGET_ROOT}/boot/initrd.img", check=False).stdout.decode()
        if "efi" not in out or files["vmlinuz"]["sha256"] not in out or files["initrd.img"]["sha256"] not in out:
            raise AnywhereError(f"boot path incomplete:\n{out}")
        return {"efi_loader": "EFI/BOOT/BOOTX64.EFI", "kernel": files["vmlinuz"]["sha256"],
                "initrd": files["initrd.img"]["sha256"], "root": f"{self.device}2"}

    def reconcile_bootloader(self) -> dict:
        return {"state": "redo", "detail": "install-root is a bounded, repeatable operation", "evidence": {}}

    # -- stage: reboot --------------------------------------------------------
    def stage_reboot(self) -> dict:
        inst = self.installer()
        path = self.put_disko()
        inst.run("sync")
        self.broker(f"unmount {path} --target {TARGET_ROOT}")
        out = inst.run("cat /proc/self/mounts").stdout.decode()
        if f" {TARGET_ROOT} " in out:
            raise AnywhereError("target still mounted; refusing to reboot over a dirty filesystem")
        self.reboot_offset = self.rescue.console_offset()
        if self.plan["takeover"] == "rescue-media":
            # Leave rescue mode through the management plane; the machine
            # then boots from its own disk.
            inst.run("sync")
            self.rescue.restore_disk_boot()
        else:
            inst.run("nohup sh -c 'sleep 1; sync; reboot -f' >/dev/null 2>&1 &", check=False, timeout=20)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                if not inst.reachable(timeout=8):
                    break
            except HostKeyRejected:
                break
            time.sleep(2)
        else:
            raise AnywhereError("the installer is still answering after the reboot request")
        return {"rebooted_from": "installer", "console_offset": self.reboot_offset,
                "method": "management-plane disk boot" if self.plan["takeover"] == "rescue-media" else "reboot -f"}

    def reconcile_reboot(self) -> dict:
        try:
            if self.installer().reachable(timeout=8):
                return {"state": "redo", "detail": "installer still running", "evidence": {}}
        except HostKeyRejected:
            pass
        return {"state": "done", "detail": "installer gone", "evidence": {"rebooted_from": "reconciled"}}

    # -- stage: final-verification -------------------------------------------
    def stage_final_verification(self) -> dict:
        session = self.installed()
        deadline = time.monotonic() + 420
        last = ""
        while True:
            try:
                if session.reachable(timeout=10):
                    break
            except HostKeyRejected as error:
                last = f"host key rejected: {error}"
            if time.monotonic() > deadline:
                raise AnywhereError("the installed system did not answer with its enrolled identity "
                                    f"within the boot window ({last or 'no answer'})")
            time.sleep(5)
        return installed_proof(session, self.plan, self.journal)

    def reconcile_final_verification(self) -> dict:
        return {"state": "redo", "detail": "verification is read-only", "evidence": {}}

    # -- stage: retire-rescue -------------------------------------------------
    def stage_retire_rescue(self) -> dict:
        return {"temporary_rescue_resources": [],
                "permanent_rescue_route": self.enr["rescue"]["kind"],
                "note": "the QEMU serial console and monitor are the supervisor's; nothing temporary "
                        "was provisioned, so nothing is released"}

    def reconcile_retire_rescue(self) -> dict:
        return {"state": "redo", "detail": "no-op", "evidence": {}}


# ---------------------------------------------------------------------------
# Installed-system proof (M4).
# ---------------------------------------------------------------------------

# Every fact is collected even when another is missing: the proof compares
# answers; it never trusts the endpoint to fail loudly on our behalf.
PROOF_SCRIPT = r"""
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
echo "os_id=$( (. /etc/os-release && echo "$ID") 2>/dev/null)"
echo "generation=$(cat /etc/repro/generation)"
echo "identity=$(tr -d '\n' < /var/lib/reproos/identity.json)"
echo "receipt=$(cat /var/lib/reproos/anywhere-receipt.json)"
src=$(findmnt -n -o SOURCE /); echo "root_source=$src"
part=${src#/dev/}; disk=$(basename "$(readlink -f /sys/class/block/$part/..)")
echo "root_disk_serial=$(cat /sys/block/$disk/serial 2>/dev/null || cat /sys/block/$disk/device/serial)"
echo "cmdline=$(cat /proc/cmdline)"
echo "system_state=$(systemctl is-system-running 2>/dev/null)"
echo "failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
echo "default_route=$(ip -4 route show default | head -1)"
ev=$(/usr/local/sbin/reproos-installed-boot-evidence 2>&1); echo "boot_evidence_rc=$?"
echo "boot_evidence=$ev"
"""


def installed_proof(session: Session, plan: dict, journal: Journal) -> dict:
    deadline = time.monotonic() + 180
    while True:
        out = session.run("sh -s", stdin=PROOF_SCRIPT.encode(), timeout=60).stdout.decode()
        facts = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        if facts.get("system_state") not in ("starting", "initializing") or time.monotonic() > deadline:
            break
        time.sleep(5)
    problems = []
    takeover = journal.evidence("takeover")
    if facts.get("boot_id") in (takeover.get("installer_boot_id"), takeover.get("source_boot_id")):
        problems.append("boot id belongs to the installer or the source system")
    if facts.get("os_id") != "reproos":
        problems.append(f"os-release ID={facts.get('os_id')!r}")
    gen = plan["configuration"]["generation"]
    if facts.get("generation") != gen:
        problems.append(f"/etc/repro/generation {facts.get('generation')!r} != {gen}")
    try:
        identity = json.loads(facts.get("identity", ""))
    except json.JSONDecodeError:
        identity = {}
    want_fp = fingerprint(*parse_host_key(plan["identities"]["installed_host_key"]))
    for key, want in (("machine_id", plan["machine"]["machine_id"]), ("generation_id", gen),
                      ("ssh_host_key_fingerprint", want_fp), ("install_source", "anywhere")):
        if identity.get(key) != want:
            problems.append(f"identity.json {key} {identity.get(key)!r} != {want!r}")
    try:
        receipt = json.loads(facts.get("receipt", ""))
    except json.JSONDecodeError:
        receipt = {}
    if receipt.get("plan") != canon.digest(plan):
        problems.append("anywhere-receipt.json names another plan")
    if facts.get("root_disk_serial") != plan["target"]["serial"]:
        problems.append(f"/ is on a disk with serial {facts.get('root_disk_serial')!r}, "
                        f"not the planned {plan['target']['serial']!r}")
    if facts.get("root_source") != f"{plan['storage']['device']}2":
        problems.append(f"/ is {facts.get('root_source')!r}")
    if facts.get("system_state") != "running":
        problems.append(f"systemd is {facts.get('system_state')!r}; failed: {facts.get('failed_units', '').strip()}")
    if not facts.get("default_route"):
        problems.append("no default route")
    if facts.get("boot_evidence_rc") != "0" or "source=anywhere" not in facts.get("boot_evidence", ""):
        problems.append(f"reproos-installed-boot-evidence: {facts.get('boot_evidence')!r}")
    if problems:
        raise AnywhereError("installed-system proof FAILED:\n  " + "\n  ".join(problems))
    return {"verdict": "installed", "boot_id": facts["boot_id"], "machine_id": identity["machine_id"],
            "generation": gen, "host_key_fingerprint": want_fp, "root": facts["root_source"],
            "root_disk_serial": facts["root_disk_serial"], "system_state": facts["system_state"],
            "boot_evidence": facts["boot_evidence"], "conversion_qualified": plan["conversion_qualified"]}
