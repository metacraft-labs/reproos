#!/usr/bin/env python3
"""Unit layer for ReproOS Anywhere: no VM, no network, no root.

The inputs are REAL probe captures (tests/anywhere/fixtures/probe-*.out,
recorded from the e2e source VMs) and records derived from them; every
refusal predicate is exercised by altering exactly the fact it guards,
and every positive case is shown passing first, so a predicate that
always refuses fails here too.

This supplements, and does not replace, the VM gates
(e2e_reproos_anywhere_converts_linux_vm,
test_reproos_anywhere_disk_identity_mismatch, ...).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(REPO / "tools" / "anywhere"))

from reproos_anywhere import canon, compat, cpio, enrollment, inventory, keys, plan  # noqa: E402
from reproos_anywhere.journal import Journal, JournalError  # noqa: E402
from reproos_anywhere.transport import Endpoint, Session, TransportError  # noqa: E402

FIXTURES = HERE / "fixtures"
CONFIG = {"network": {"ipv4": "dhcp"}, "install": {"target_device": "/dev/vda"}}
PAYLOAD = {"kind": "fixture", "qualified": False, "rootfs_unpacked_bytes": 400 * 2**20,
           "configuration_generation": "0" * 64,
           "files": {"rootfs.tar.zst": {"sha256": "1" * 64, "size": 110 * 2**20}}}
INSTALLER = {"kind": "fixture", "qualified": False, "initrd_unpacked_bytes": 200 * 2**20,
             "files": {"vmlinuz": {"sha256": "2" * 64, "size": 12 * 2**20},
                       "initrd.img": {"sha256": "3" * 64, "size": 48 * 2**20}}}


def layout(device: str, size_gb: int) -> dict:
    return {"layout": "uefi-ext4", "espSizeMib": 512, "diskSizeGb": size_gb, "device": device,
            "disko": "{}"}


def probe(name: str) -> dict:
    return inventory.parse((FIXTURES / f"probe-{name}.out").read_text())


def enrolled_for(inv: dict, **override) -> dict:
    """The enrollment a management plane would have written for ``inv``."""
    target = inv["disks"]["vda"]
    mgmt = inventory.management_interface(inv)
    doc = {
        "schema": enrollment.SCHEMA, "name": "unit-test",
        "expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ssh": {"address": "127.0.0.1", "port": 2222, "user": "root", "privilege": "root",
                "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpZbmnZss8EKxDnHchD2GAUi9y8GBU4mVsxqnqHKzoP",
                "identity_file": "/dev/null"},
        "machine": {"product_uuid": inv["dmi"]["product_uuid"]},
        "disks": [{"serial": target["serial"], "size_sectors": target["size_sectors"], "role": "target"}],
        "network": {"mac": mgmt["mac"]},
        "rescue": {"kind": "qemu-serial", "console_log": "console.log", "monitor": "monitor.sock"},
    }
    for key, value in override.items():
        doc[key] = value
    return enrollment.normalise(doc, base=Path("/tmp"))


def evaluate(inv: dict, enr: dict, strict: bool = True) -> dict:
    return compat.evaluate(inv, enr, CONFIG, PAYLOAD, INSTALLER, layout, strict_readonly=strict)


def verdicts(report: dict) -> dict:
    return {c["id"]: c["verdict"] for c in report["checks"]}


class Canon(unittest.TestCase):
    def test_round_trip_and_identity(self):
        rec = {"b": [1, "x", None, True], "a": {"z": 0}}
        data = canon.encode(rec)
        self.assertEqual(data, b'{"a":{"z":0},"b":[1,"x",null,true]}')
        self.assertEqual(canon.decode(data), rec)
        self.assertEqual(canon.digest(rec), canon.digest(json.loads(data)))

    def test_rejects_non_canonical(self):
        for bad in (b'{"a": 1}', b'{"b":1,"a":2}', b'{"a":1,"a":1}', b'{"a":1.5}', b'{"a":"\xc3\xa9"}'):
            with self.subTest(bad=bad), self.assertRaises(canon.CanonError):
                canon.decode(bad)
        with self.assertRaises(canon.CanonError):
            canon.encode({"x": 0.5})


class Inventory(unittest.TestCase):
    def test_real_captures_parse(self):
        for name, os_id in (("debian", "debian"), ("ubuntu", "ubuntu"), ("alpine", "alpine")):
            with self.subTest(name=name):
                inv = probe(name)
                self.assertEqual(inv["os"]["id"], os_id)
                self.assertTrue(inv["disks"]["vda"]["serial"].startswith("AW-"))
                self.assertIsNotNone(inventory.management_interface(inv))
                root = inventory.root_mount(inv)
                self.assertIn("vda", inventory.lower_disks(inv, inventory.devname(root["source"])))

    def test_hostile_or_truncated_output_rejected(self):
        text = (FIXTURES / "probe-debian.out").read_text()
        lines = text.splitlines()
        cases = {
            "truncated": "\n".join(lines[:-1]),
            "duplicate": text + lines[3] + "\n",
            "unknown section": text.replace("R\tos\t", "R\tos2\t", 1),
            "not a record": text + "garbage\n",
            "bad key": text.replace("R\tdmi\tsys_vendor", "R\tdmi\tsys vendor", 1),
            "control char": text.replace("QEMU", "QE\x01MU", 1),
            "unknown disk field": text + "R\tdisk\tvda.colour\tred\n",
            "non-numeric size": text.replace("vda.size_sectors\t", "vda.size_sectors\tx", 1),
        }
        for what, bad in cases.items():
            with self.subTest(what=what), self.assertRaises(inventory.InventoryError):
                inventory.parse(bad)


class Compatibility(unittest.TestCase):
    def setUp(self):
        self.inv = probe("debian")
        self.enr = enrolled_for(self.inv)

    def test_positive_control(self):
        report = evaluate(self.inv, self.enr)
        self.assertFalse(report["blocked"], [c for c in report["checks"] if c["verdict"] == "fail"])
        v = verdicts(report)
        self.assertEqual(v["root-on-target"], "requires")
        self.assertEqual(report["target"]["serial"], self.inv["disks"]["vda"]["serial"])
        self.assertFalse(report["destructive_authorization"])
        self.assertFalse(report["conversion_qualified"])

    def assertBlockedBy(self, report: dict, check: str):
        self.assertTrue(report["blocked"])
        self.assertEqual(verdicts(report).get(check), "fail", report["checks"])
        self.assertNotIn("target", report)

    def mutate(self, fn) -> dict:
        inv = copy.deepcopy(self.inv)
        fn(inv)
        return inv

    def test_each_refusal(self):
        stack = {"name": "dm-0", "size_sectors": 100, "logical_block": 512, "removable": False,
                 "read_only": False, "devnum": "253:0", "serial": "", "wwid": "", "model": "",
                 "dm_uuid": "LVM-abc", "md_level": "", "driver": "", "syspath": "", "slaves": ["vda1"],
                 "holders": []}
        cases = {
            "distribution": lambda i: i["os"].update(id="gentoo"),
            "not-a-container": lambda i: i["virt"].update(container_marker="dockerenv"),
            "architecture": lambda i: i["kernel"].update(machine="aarch64"),
            "firmware": lambda i: i["firmware"].update(mode="bios"),
            "secure-boot": lambda i: i["firmware"].update(secure_boot="1"),
            "machine-identity": lambda i: i["dmi"].update(product_uuid="00000000-0000-0000-0000-000000000000"),
            "privilege": lambda i: i.update(uid=1000),
            "disk-serials-unique": lambda i: i["disks"].update(
                vdz={**i["disks"]["vda"], "name": "vdz"}),
            "target-stacking": lambda i: i["disks"].update({"dm-0": stack}),
            "target-controller": lambda i: i["disks"]["vda"].update(driver="usb-storage"),
            "target-not-removable": lambda i: i["disks"]["vda"].update(removable=True),
            "management-interface": lambda i: [n.update(wireless=True) for n in i["interfaces"].values()],
            "network-persistence": lambda i: [a.update(assignment="static") for a in i["ipv4"]],
            "takeover": lambda i: i["kernel"].update(kexec_load_disabled="1"),
            "memory": lambda i: i["memory"].update(total_kib=256 * 1024),
        }
        for check, fn in cases.items():
            with self.subTest(check=check):
                self.assertBlockedBy(evaluate(self.mutate(fn), self.enr), check)

    def test_md_and_luks_are_named(self):
        for uuid, level, kind in (("CRYPT-LUKS2-x", "", "luks"), ("", "raid1", "md-raid1")):
            inv = self.mutate(lambda i: i["disks"].update(md0={
                **i["disks"]["vda"], "name": "md0", "serial": "", "dm_uuid": uuid, "md_level": level,
                "slaves": ["vda1"]}))
            report = evaluate(inv, self.enr)
            self.assertIn(kind, next(c["detail"] for c in report["checks"] if c["id"] == "target-stacking"))

    def test_enrollment_mismatches(self):
        target = self.inv["disks"]["vda"]
        wrong_size = enrolled_for(self.inv, disks=[{"serial": target["serial"], "size_sectors": 1,
                                                    "role": "target"}])
        self.assertBlockedBy(evaluate(self.inv, wrong_size), f"disk:{target['serial']}")
        missing = enrolled_for(self.inv, disks=[{"serial": "NOT-THERE", "size_sectors": 1, "role": "target"}])
        self.assertTrue(evaluate(self.inv, missing)["blocked"])
        wrong_mac = enrolled_for(self.inv, network={"mac": "02:00:00:00:00:01"})
        self.assertBlockedBy(evaluate(self.inv, wrong_mac), "management-interface")

    def test_rescue_media_takes_over_when_kexec_is_off(self):
        inv = self.mutate(lambda i: i["kernel"].update(kexec_load_disabled="1"))
        rescue = {"kind": "qemu-serial", "console_log": "c", "monitor": "m",
                  "boot_command": ["boot"], "restore_command": ["restore"]}
        report = evaluate(inv, enrolled_for(self.inv, rescue=rescue))
        self.assertFalse(report["blocked"])
        self.assertEqual(report["takeover"], {"default": "rescue-media", "available": ["rescue-media"]})


class Enrollment(unittest.TestCase):
    def test_rejections(self):
        inv = probe("debian")
        good = enrolled_for(inv)
        self.assertEqual(good["machine"]["product_uuid"], inv["dmi"]["product_uuid"])
        bad = {
            "expired": {"expires": "2001-01-01T00:00:00Z"},
            "two targets": {"disks": [{"serial": "A", "size_sectors": 1, "role": "target"},
                                      {"serial": "B", "size_sectors": 1, "role": "target"}]},
            "blank serial": {"disks": [{"serial": "", "size_sectors": 1, "role": "target"}]},
            "duplicate serial": {"disks": [{"serial": "A", "size_sectors": 1, "role": "target"},
                                           {"serial": "A", "size_sectors": 1, "role": "keep"}]},
            "unknown key": {"surprise": 1},
            "rsa host key": {"ssh": {**good["ssh"], "host_key": "ssh-rsa AAAAB3"}},
            "root privilege, other user": {"ssh": {**good["ssh"], "user": "debian"}},
            "unknown rescue": {"rescue": {"kind": "ipmi", "console_log": "x", "monitor": "y"}},
            "half a rescue boot": {"rescue": {"kind": "qemu-serial", "console_log": "x", "monitor": "y",
                                              "boot_command": ["b"]}},
        }
        for what, override in bad.items():
            with self.subTest(what=what), self.assertRaises((enrollment.EnrollmentError, TransportError)):
                enrolled_for(inv, **override)


def load_cli():
    from importlib.machinery import SourceFileLoader
    return SourceFileLoader("reproos_anywhere_cli", str(REPO / "tools" / "anywhere" / "reproos-anywhere")).load_module()


class ConvertSelection(unittest.TestCase):
    """`convert DEST MACHINE`: the destination selects one enrollment, never a trust anchor."""

    def enrollment_toml(self, name: str, port: int, user: str = "root", expires: str | None = None) -> str:
        expires = expires or (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        return f'''schema = "{enrollment.SCHEMA}"
name = "{name}"
expires = "{expires}"
[ssh]
address = "192.0.2.10"
port = {port}
user = "{user}"
privilege = "{'root' if user == 'root' else 'sudo'}"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpZbmnZss8EKxDnHchD2GAUi9y8GBU4mVsxqnqHKzoP"
identity_file = "/dev/null"
[machine]
product_uuid = "0123456789abcdef0123"
[[disks]]
serial = "S1"
size_sectors = 1
role = "target"
[network]
mac = "52:54:00:00:00:01"
[rescue]
kind = "qemu-serial"
console_log = "console.log"
monitor = "monitor.sock"
'''

    def test_destination_and_machine_selection(self):
        cli = load_cli()
        self.assertEqual(cli.parse_destination("root@192.0.2.10:2222"), ("root", "192.0.2.10", 2222))
        self.assertEqual(cli.parse_destination("host.example"), (None, "host.example", None))
        self.assertEqual(cli.parse_destination("ops@[2001:db8::1]:22"), ("ops", "2001:db8::1", 22))
        self.assertEqual(cli.parse_destination("2001:db8::1"), (None, "2001:db8::1", None))
        for bad in ("root@", "host:port", "@:22"):
            with self.subTest(destination=bad), self.assertRaises(cli.c.Refused):
                cli.parse_destination(bad)
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "machines").mkdir()
            (d / "machines" / "web-1.toml").write_text("x")
            self.assertEqual(cli.select_machine("web-1", d / "machines"), d / "machines" / "web-1.toml")
            for bad in ("web-2", "../web-1", "Web 1"):
                with self.subTest(selector=bad), self.assertRaises(cli.c.Refused):
                    cli.select_machine(bad, d / "machines")
            e = d / "enrollments"
            e.mkdir()
            (e / "a.toml").write_text(self.enrollment_toml("a", 22))
            (e / "b.toml").write_text(self.enrollment_toml("b", 2222))
            (e / "old.toml").write_text(self.enrollment_toml("old", 2200, expires="2001-01-01T00:00:00Z"))
            self.assertEqual(cli.select_enrollment("root@192.0.2.10:2222", e), e / "b.toml")
            self.assertEqual(cli.select_enrollment("192.0.2.10:22", e), e / "a.toml")
            refusals = {"ambiguous": "192.0.2.10", "unknown host": "192.0.2.11:22",
                        "other user": "admin@192.0.2.10:22", "expired only": "192.0.2.10:2200"}
            for what, destination in refusals.items():
                with self.subTest(what=what), self.assertRaises(cli.c.Refused):
                    cli.select_enrollment(destination, e)


class JournalOrdering(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = self.dir / "journal.jsonl"

    def test_causal_order_enforced(self):
        j = Journal(self.path, "p" * 64)
        with self.assertRaises(JournalError):
            j.complete("destroy", {})          # completion without a start
        j.start("destroy", {})
        with self.assertRaises(JournalError):
            j.start("format", {})              # next stage before the completion
        with self.assertRaises(JournalError):
            j.complete("format", {})           # completing the wrong stage
        j.complete("destroy", {"erased": True})
        j.start("format", {})
        j.abort("format", "refused")
        j.start("format", {})                  # a refused stage restarts cleanly
        j.complete("format", {})
        self.assertEqual(Journal(self.path, "p" * 64).completed(), ["destroy", "format"])

    def test_tamper_detected(self):
        j = Journal(self.path, "p" * 64)
        j.start("destroy", {})
        j.complete("destroy", {"erased": True})
        lines = self.path.read_bytes().splitlines()
        # The chain protects every record that has a successor. The newest
        # record has none; it is protected by the off-host evidence sink
        # (see test_evidence_sink.py), never by the local mirror alone.
        cases = {
            "edited earlier record": [lines[0].replace(b'"start"', b'"note"'), lines[1]],
            "dropped record": [lines[1]],
            "reordered": [lines[1], lines[0]],
        }
        for what, body in cases.items():
            with self.subTest(what=what):
                self.path.write_bytes(b"\n".join(body) + b"\n")
                with self.assertRaises((JournalError, canon.CanonError)):
                    Journal(self.path, "p" * 64)
        self.path.write_bytes(b"\n".join(lines) + b"\n")
        with self.assertRaises(JournalError):
            Journal(self.path, "q" * 64)       # another plan's journal

    def test_sink_refusal_stops_before_local_record(self):
        def refuse(_data: bytes) -> None:
            raise RuntimeError("sink full")
        j = Journal(self.path, "p" * 64, sinks=[refuse])
        with self.assertRaises(RuntimeError):
            j.start("destroy", {})
        self.assertFalse(self.path.exists())


class PlanSignature(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.key = self.dir / "controller"
        self.pub = keys.ensure_keypair(self.key, "unit")

    def save(self, record: dict) -> str:
        return plan.save(record, self.dir / "plan", self.key)

    def record(self, **extra) -> dict:
        now = dt.datetime.now(dt.timezone.utc)
        rec = {"schema": plan.SCHEMA, "identities": {"controller": self.pub},
               "expires": (now + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), "target": {"serial": "A"}}
        rec.update(extra)
        return rec

    def test_acknowledgement_signature_and_expiry(self):
        pid = self.save(self.record())
        loaded, got = plan.load_verified(self.dir / "plan", self.pub, pid)
        self.assertEqual(got, pid)
        with self.assertRaises(plan.PlanError):
            plan.load_verified(self.dir / "plan", self.pub, "yes")            # not an identity
        with self.assertRaises(plan.PlanError):
            plan.load_verified(self.dir / "plan", self.pub, pid[:-1] + "0")   # another identity
        other = keys.ensure_keypair(self.dir / "other", "other")
        with self.assertRaises(plan.PlanError):
            plan.load_verified(self.dir / "plan", other, pid)                 # another controller
        # tampering with the plan after signing changes its identity and breaks the signature
        tampered = self.record(target={"serial": "B"})
        canon.write(self.dir / "plan" / "plan.json", tampered)
        with self.assertRaises(plan.PlanError):
            plan.load_verified(self.dir / "plan", self.pub, canon.digest(tampered))
        expired = self.record(expires="2001-01-01T00:00:00Z")
        pid = self.save(expired)
        with self.assertRaises(plan.PlanError):
            plan.load_verified(self.dir / "plan", self.pub, pid)
        plan.load_verified(self.dir / "plan", self.pub, pid, allow_expired=True)  # resume only


class PlanDeterminism(unittest.TestCase):
    """Equivalent inventory + configuration + artifacts -> one CONTENT
    identity; every meaningful input moves it; the acknowledged identity
    stays unique per plan (fresh session nonce)."""

    def build(self, inv: dict, **kw) -> dict:
        enr = enrolled_for(inv)
        report = evaluate(inv, enr)
        public = {"configuration_generation": "c" * 64, "hostname": "h",
                  "remote_access": {"user": "repro"}}
        args = dict(enrollment=enr, enrollment_id=canon.digest(enr), inventory_id=canon.digest(inv),
                    report=report, report_id=canon.digest(report), config_text=b"config",
                    public_manifest=public,
                    payload={**PAYLOAD, "configuration_generation": self.gen},
                    payload_id="p" * 64, installer=INSTALLER, installer_id="i" * 64,
                    controller_pub="ssh-ed25519 C", access_pub="ssh-ed25519 A",
                    installed_host_pub="ssh-ed25519 H", machine_id=plan.generate_machine_id())
        args.update(kw)
        return plan.build(**args)

    def setUp(self):
        import hashlib
        self.gen = hashlib.sha256(b"config").hexdigest()

    def test_content_identity(self):
        inv = probe("debian")
        payload = {**PAYLOAD, "configuration_generation": self.gen}
        a = self.build(inv, payload=payload)
        b = self.build(copy.deepcopy(inv), payload=payload,
                       installed_host_pub="ssh-ed25519 OTHER")
        self.assertNotEqual(plan.identity(a), plan.identity(b))           # fresh per plan
        self.assertEqual(plan.content_identity(a), plan.content_identity(b))
        moved = copy.deepcopy(inv)
        moved["disks"]["vda"]["syspath"] = "../devices/pci0000:00/0000:00:07.0/x/block/vda"
        c = self.build(moved, payload=payload)
        self.assertNotEqual(plan.content_identity(a), plan.content_identity(c))
        d = self.build(inv, payload=payload, payload_id="q" * 64)
        self.assertNotEqual(plan.content_identity(a), plan.content_identity(d))
        with self.assertRaises(plan.PlanError):                           # payload for another config
            self.build(inv, payload={**PAYLOAD, "configuration_generation": "0" * 64})


class TransportHardening(unittest.TestCase):
    """Every option that narrows the SSH channel, asserted one by one."""

    REQUIRED = [
        ("-F", "/dev/null"), ("-o", "StrictHostKeyChecking=yes"), ("-o", "GlobalKnownHostsFile=/dev/null"),
        ("-o", "UpdateHostKeys=no"), ("-o", "HostKeyAlgorithms=ssh-ed25519"), ("-o", "BatchMode=yes"),
        ("-o", "IdentitiesOnly=yes"), ("-o", "IdentityAgent=none"), ("-o", "ForwardAgent=no"),
        ("-o", "ForwardX11=no"), ("-o", "ClearAllForwardings=yes"), ("-o", "PermitLocalCommand=no"),
        ("-o", "ProxyCommand=none"), ("-o", "ProxyJump=none"), ("-o", "ControlMaster=no"),
    ]

    def test_argv(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        s = Session(Endpoint("127.0.0.1", 2222, "root",
                             "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGpZbmnZss8EKxDnHchD2GAUi9y8GBU4mVsxqnqHKzoP",
                             Path("/dev/null")), d)
        argv = s.argv("true")
        pairs = list(zip(argv, argv[1:]))
        for pair in self.REQUIRED:
            with self.subTest(option=pair):
                self.assertIn(pair, pairs)
        known = s.known_hosts.read_text().splitlines()
        self.assertEqual(len(known), 1)                       # exactly the pinned key
        self.assertTrue(known[0].startswith("[127.0.0.1]:2222 ssh-ed25519 "))
        with self.assertRaises(TransportError):
            Endpoint("h", 22, "root", "ssh-rsa AAAAB3", Path("/dev/null"))


class SessionArchive(unittest.TestCase):
    def test_cpio_round_trip(self):
        tool = shutil.which("cpio")
        if tool is None:
            self.fail("cpio(1) is required for this gate")
        data = cpio.build([(".", 0o755, None), ("etc", 0o755, None), ("etc/anywhere", 0o755, None),
                           ("etc/anywhere/authorized_keys", 0o600, b"ssh-ed25519 AAAA test\n")])
        self.assertEqual(len(data) % 512, 0)
        out = subprocess.run([tool, "-itv"], input=data, capture_output=True)
        listing = out.stdout.decode()
        self.assertIn("drwxr-xr-x", listing.splitlines()[0])  # the root entry fixes / modes
        self.assertIn("etc/anywhere/authorized_keys", listing)
        full = cpio.append_to_initrd(b"x" * 1001, data)
        self.assertEqual(full.index(data), 1024)


class Detection(unittest.TestCase):
    """Classification of REAL audit records captured from the installer
    console (tests/anywhere/fixtures/audit-sample.log)."""

    STORES = {"/nix/store/imad8dvhp77h0pjbckp6wvmnyhp8dpgg-coreutils-9.8",
              "/nix/store/3c6r8gh8zrqw8xmncmlj9vivz9rz6r30-util-linux-2.41.2-bin"}

    def test_classification_by_window(self):
        from reproos_anywhere.detect import Detector
        text = (FIXTURES / "audit-sample.log").read_text()
        # In a stage allowed to write disks, only the foreign exec is flagged.
        events = Detector(self.STORES).scan(text, "format")
        self.assertEqual([(e.kind, e.detail["exe"]) for e in events],
                         [("unexpected-execution", "/run/true")])
        # Outside those stages both disk write-opens are flagged too.
        kinds = sorted(e.kind for e in Detector(self.STORES).scan(text, "materialize"))
        self.assertEqual(kinds, ["unexpected-execution", "unexpected-write", "unexpected-write"])
        # An exec from a store path that was not in the verified closure.
        events = Detector({"/nix/store/3c6r8gh8zrqw8xmncmlj9vivz9rz6r30-util-linux-2.41.2-bin"}).scan(text, "format")
        self.assertIn("/nix/store/imad8dvhp77h0pjbckp6wvmnyhp8dpgg-coreutils-9.8/bin/coreutils",
                      [e.detail["exe"] for e in events])

    def test_each_record_counted_once_and_loss_fails_closed(self):
        from reproos_anywhere.detect import Detector
        text = (FIXTURES / "audit-sample.log").read_text()
        d = Detector(self.STORES)
        self.assertTrue(d.scan(text, "materialize"))
        self.assertEqual(d.scan(text, "materialize"), [])          # already attributed
        lost = d.scan("audit: audit_lost=3 audit_rate_limit=0 audit_backlog_limit=64\n", "mount")
        self.assertEqual([e.kind for e in lost], ["audit-loss"])
        change = d.scan('audit: type=1305 audit(1.0:9999): op=set audit_enabled=0 old=2 res=0\n', "mount")
        self.assertEqual([e.kind for e in change], ["audit-loss"])


class InstallerGate(unittest.TestCase):
    """The gate's refusals, run locally: validation happens before any
    action, so no installer is needed to see a request refused."""

    GATE = REPO / "tools" / "anywhere" / "installer-gate.sh"

    def run_gate(self, request: str) -> subprocess.CompletedProcess:
        env = {"PATH": os.environ.get("PATH", ""), "SSH_ORIGINAL_COMMAND": request}
        return subprocess.run(["sh", str(self.GATE)], env=env, capture_output=True, text=True)

    def test_refusals(self):
        refused = [
            "id", "anywhere-gate id", "anywhere-gate read /etc/shadow", "anywhere-gate read /mnt/../etc/shadow",
            "anywhere-gate put /etc/passwd 0644", "anywhere-gate put /mnt/x 4755", "anywhere-gate remove /",
            "anywhere-gate barrier xyz", "anywhere-gate sysblock ../../x", "anywhere-gate identity extra",
            "anywhere-gate op-start 00ff rm -rf /", "anywhere-gate disk destroy --device /dev/vda",
            "anywhere-gate read /mnt/a;id", "anywhere-gate read $(id)", "anywhere-gate read /mnt/`id`",
            "anywhere-gate op-forget 00ff",
        ]
        for request in refused:
            with self.subTest(request=request):
                p = self.run_gate(request)
                self.assertEqual(p.returncode, 126, (request, p.stdout, p.stderr))
                self.assertIn("refused", p.stderr)

    def test_symlinks_cannot_lead_outside(self):
        # The gate resolves symlinks: a link whose string is inside an allowed
        # area but whose target is not is refused. Exercised with a link under
        # a temporary directory standing in for the allowed prefix.
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "mnt").mkdir()
        (d / "mnt" / "escape").symlink_to("/etc")
        gate = (self.GATE.read_text().replace("/mnt/*", f"{d}/mnt/*"))
        g = d / "gate.sh"
        g.write_text(gate)
        env = {"PATH": os.environ.get("PATH", "")}
        for request in (f"anywhere-gate put {d}/mnt/escape/x 0644", f"anywhere-gate read {d}/mnt/escape/shadow"):
            p = subprocess.run(["sh", str(g)], env={**env, "SSH_ORIGINAL_COMMAND": request},
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 126, (request, p.stderr))
            self.assertIn("resolves to /etc", p.stderr)
        self.assertFalse(Path("/etc/x").exists())

    def test_allowed_shapes_pass_validation(self):
        # Reaching the action (which then fails here: no installer) proves
        # the request passed validation; refusal would be exit 126.
        for request in ("anywhere-gate size /mnt/.anywhere/rootfs.tar.zst", "anywhere-gate barrier 0a1b2c",
                        "anywhere-gate exists /mnt/.anywhere"):
            with self.subTest(request=request):
                self.assertNotEqual(self.run_gate(request).returncode, 126)


class EvidenceSink(unittest.TestCase):
    def setUp(self):
        import tempfile as tf
        import threading
        from reproos_anywhere.evidence import Client, Sink
        self.dir = Path(tf.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.sock = str(Path(tf.mkdtemp(dir="/tmp")) / "s")
        self.sink = Sink(self.dir / "sink", self.sock, heartbeat_window=1.5)
        threading.Thread(target=self.sink.serve_forever, daemon=True).start()
        self.addCleanup(self.sink.stop.set)
        for _ in range(50):
            if Path(self.sock).exists():
                break
            import time
            time.sleep(0.05)
        self.plan = "a" * 64
        self.client = Client(self.sock, self.plan)

    def alerts(self) -> list[str]:
        p = self.dir / "sink" / "alerts.jsonl"
        return [json.loads(x)["kind"] for x in p.read_text().splitlines()] if p.exists() else []

    def test_append_only_chain_and_denials(self):
        import time
        j = Journal(self.dir / "journal.jsonl", self.plan, sinks=[self.client.append])
        j.start("destroy", {})
        j.complete("destroy", {"erased": True})
        # A forked history (the same seq again) is refused and alerted.
        forged = dict(j.records[-1], evidence={"erased": False})
        with self.assertRaises(Exception):
            self.client.append(canon.encode(forged))
        for op in ("read", "list", "delete"):
            self.assertFalse(self.client.request({"op": op, "stream": self.plan})["ok"])
        j.note("after", {"append": "still works"})
        kinds = self.alerts()
        self.assertIn("chain-fork", kinds)
        self.assertEqual(kinds.count("denied-operation"), 3)
        # Heartbeat loss on an open stream; a closed stream is silent.
        time.sleep(3.5)
        self.assertIn("heartbeat-lost", self.alerts())
        self.client.close()
        n = len(self.alerts())
        time.sleep(2.5)
        self.assertEqual(len(self.alerts()), n)


class FailureBundle(unittest.TestCase):
    def test_bundle_carries_evidence_and_no_credentials(self):
        import tarfile
        from reproos_anywhere import recovery
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "plan").mkdir()
        rec = {"schema": plan.SCHEMA, "machine": {"name": "m"}}
        canon.write(d / "plan" / "plan.json", rec)
        canon.write(d / "enrollment.json", {"rescue": {"console_log": str(d / "console.log")}})
        (d / "console.log").write_text("console")
        Journal(d / "journal.jsonl", canon.digest(rec)).note("x", {})
        (d / "keys").mkdir()
        (d / "keys" / "session_x").write_text("-----BEGIN OPENSSH PRIVATE KEY-----")
        out = d / "b.tar.gz"
        recovery.bundle(d, out)
        with tarfile.open(out) as t:
            names = t.getnames()
        self.assertIn("journal.jsonl", names)
        self.assertNotIn("keys/session_x", names)
        (d / "console.log").write_text("leaked -----BEGIN OPENSSH PRIVATE KEY-----")
        with self.assertRaises(recovery.RecoveryError):
            recovery.bundle(d, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
