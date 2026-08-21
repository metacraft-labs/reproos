#!/usr/bin/env python3
"""Regression tests for the ReproOS source-package cache backfill workflow."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKFILL = ROOT / "tools/cache_reproos_packages.py"
ALPHA_KEY = "a" * 64
BETA_KEY = "b" * 64


FAKE_REPRO = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

cwd = Path.cwd()
args = sys.argv[1:]
state_path = Path(os.environ["FAKE_CACHE_STATE"])
log_path = Path(os.environ["FAKE_REPRO_LOG"])
graph_log_path = Path(os.environ["FAKE_GRAPH_LOG"])
alpha_key = "a" * 64
beta_key = "b" * 64

if args[:2] == ["graph", "iso"]:
    expected_source_root = os.environ["FAKE_EXPECTED_SOURCE_ROOT"]
    if os.environ.get("REPRO_FROM_SOURCE_ROOT") != expected_source_root:
        print("wrong source root", file=sys.stderr)
        raise SystemExit(3)
    if "REPRO_LOCK_PATH" in os.environ or "REPRO_LOCK_PINS" in os.environ:
        print("ambient lock leaked into graph", file=sys.stderr)
        raise SystemExit(3)
    with graph_log_path.open("a", encoding="utf-8") as stream:
        stream.write("iso\n")
    print(json.dumps({
        "graph": {"actions": [{"toolIdentityRefs": ["beta", "ignored", "alpha"]}]}
    }))
    raise SystemExit(0)

if args and args[0] == "graph":
    with graph_log_path.open("a", encoding="utf-8") as stream:
        stream.write(cwd.name + "\n")
    key = alpha_key if cwd.name == "alpha" else beta_key
    print(json.dumps({
        "actions": [{
            "publishToBinaryCache": True,
            "binaryCacheKey": key,
        }]
    }))
    raise SystemExit(0)

if args[:2] == ["cache", "lookup"]:
    entries = set(json.loads(state_path.read_text()))
    key = args[2]
    if key in entries:
        print(f"hit {key}")
        raise SystemExit(0)
    print(f"miss {key}")
    raise SystemExit(1)

if args and args[0] == "build":
    key = alpha_key if cwd.name == "alpha" else beta_key
    entries = set(json.loads(state_path.read_text()))
    entries.add(key)
    state_path.write_text(json.dumps(sorted(entries)))
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(cwd.name + "\n")
    report_arg = next(value for value in args if value.startswith("--write-report="))
    report_path = Path(report_arg.split("=", 1)[1])
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({
        "unrelatedFingerprint": "c" * 64,
        "actions": [{"reason": f"published {key}"}],
    }))
    raise SystemExit(0)

print("unsupported fake repro command", args, file=sys.stderr)
raise SystemExit(2)
'''


class CacheBackfillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.packages_root = self.root / "reprobuild-packages"
        for package in ["alpha", "beta"]:
            package_dir = self.packages_root / "packages" / "source" / package
            package_dir.mkdir(parents=True)
            (package_dir / "repro.nim").write_text("discard\n", encoding="utf-8")
        self.repro = self.root / "repro"
        self.repro.write_text(textwrap.dedent(FAKE_REPRO), encoding="utf-8")
        self.repro.chmod(self.repro.stat().st_mode | stat.S_IXUSR)
        self.state = self.root / "cache-state.json"
        self.log = self.root / "repro.log"
        self.graph_log = self.root / "graph.log"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_backfill(self, *extra: str) -> subprocess.CompletedProcess[str]:
        report = self.root / "report.json"
        env = os.environ.copy()
        env["FAKE_CACHE_STATE"] = str(self.state)
        env["FAKE_REPRO_LOG"] = str(self.log)
        env["FAKE_GRAPH_LOG"] = str(self.graph_log)
        env["FAKE_EXPECTED_SOURCE_ROOT"] = str(
            self.packages_root / "packages" / "source"
        )
        env["REPRO_LOCK_PATH"] = str(self.root / "ambient.lock")
        env["REPRO_LOCK_PINS"] = "ambient=pins"
        return subprocess.run(
            [
                sys.executable,
                str(BACKFILL),
                "--repro",
                str(self.repro),
                "--packages-root",
                str(self.packages_root),
                "--report",
                str(report),
                *extra,
            ],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_publishes_only_missing_entries_and_verifies_every_key(self) -> None:
        self.state.write_text(json.dumps([BETA_KEY]), encoding="utf-8")
        result = self.run_backfill()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads((self.root / "report.json").read_text(encoding="utf-8"))
        self.assertTrue(report["complete"])
        self.assertEqual(report["sourcePackageCount"], 2)
        self.assertEqual(report["cacheEntryCount"], 2)
        self.assertEqual(report["hitBeforeCount"], 1)
        self.assertEqual(report["publishedPackageCount"], 1)
        self.assertEqual(report["verifiedEntryCount"], 2)
        self.assertEqual(report["ignoredToolIdentityRefs"], ["ignored"])
        self.assertEqual(report["packages"][0]["reportedPublicationKeys"], [ALPHA_KEY])
        self.assertEqual(self.log.read_text(encoding="utf-8"), "alpha\n")

    def test_verify_only_reports_a_missing_entry_without_building(self) -> None:
        self.state.write_text("[]", encoding="utf-8")
        result = self.run_backfill("--verify-only", "--package", "alpha")
        self.assertEqual(result.returncode, 1)
        report = json.loads((self.root / "report.json").read_text(encoding="utf-8"))
        self.assertFalse(report["complete"])
        self.assertEqual(report["sourcePackageCount"], 1)
        self.assertEqual(report["packages"][0]["status"], "missing")
        self.assertFalse(self.log.exists())

    def test_resume_skips_completed_package_graphs_for_matching_inputs(self) -> None:
        self.state.write_text(json.dumps([ALPHA_KEY, BETA_KEY]), encoding="utf-8")
        first = self.run_backfill("--verify-only")
        self.assertEqual(first.returncode, 0, first.stderr)

        self.graph_log.unlink()
        resumed = self.run_backfill("--verify-only", "--resume")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        report = json.loads((self.root / "report.json").read_text(encoding="utf-8"))
        self.assertTrue(report["complete"])
        self.assertEqual(report["schemaVersion"], 2)
        self.assertTrue(all(item["resumed"] for item in report["packages"]))
        self.assertEqual(self.graph_log.read_text(encoding="utf-8"), "iso\n")

    def test_resume_rejects_a_changed_source_catalog(self) -> None:
        self.state.write_text(json.dumps([ALPHA_KEY, BETA_KEY]), encoding="utf-8")
        first = self.run_backfill("--verify-only")
        self.assertEqual(first.returncode, 0, first.stderr)

        alpha_recipe = self.packages_root / "packages" / "source" / "alpha" / "repro.nim"
        alpha_recipe.write_text("discard\n# changed\n", encoding="utf-8")
        resumed = self.run_backfill("--verify-only", "--resume")
        self.assertEqual(resumed.returncode, 1)
        self.assertIn("resume report inputs changed: source catalog", resumed.stderr)


if __name__ == "__main__":
    unittest.main()
