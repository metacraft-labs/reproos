#!/usr/bin/env python3
"""Publish and verify the source package closure used by the ReproOS ISO."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_URL = "https://repro-cache.metacraft-labs.com"
CACHE_KEY_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


class BackfillError(RuntimeError):
    """A cache backfill prerequisite or command failed."""


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def command_failure(command: list[str], result: subprocess.CompletedProcess[str]) -> str:
    detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
    return f"{' '.join(command)} exited {result.returncode}: {detail}"


def resolve_repro(explicit: str) -> str:
    candidates = [
        explicit,
        os.environ.get("REPROBUILD_REPRO", ""),
        shutil.which("repro") or "",
        str(ROOT.parent / "reprobuild" / "build" / "bin" / "repro"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    raise BackfillError(
        "repro CLI not found; pass --repro or set REPROBUILD_REPRO"
    )


def resolve_packages_root(explicit: str) -> Path:
    candidates = [
        explicit,
        os.environ.get("REPROBUILD_PACKAGES_ROOT", ""),
        str(ROOT.parent / "reprobuild-packages"),
    ]
    for candidate in candidates:
        path = Path(candidate).expanduser() if candidate else None
        if path is not None and (path / "packages" / "source").is_dir():
            return path.resolve()
    raise BackfillError(
        "reprobuild-packages checkout not found; pass --packages-root or set "
        "REPROBUILD_PACKAGES_ROOT"
    )


def graph_actions(document: dict[str, Any]) -> list[dict[str, Any]]:
    graph = document.get("graph", document)
    actions = graph.get("actions", []) if isinstance(graph, dict) else []
    if not isinstance(actions, list):
        raise BackfillError("repro graph returned an invalid actions field")
    return [action for action in actions if isinstance(action, dict)]


def load_graph(
    repro: str,
    cwd: Path,
    target: str,
    env: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    command = [repro, "graph"]
    if target:
        command.append(target)
    command.extend(["--tool-provisioning=from-source", "--format=json"])
    result = run_command(command, cwd=cwd, env=env, timeout=timeout)
    if result.returncode != 0:
        raise BackfillError(command_failure(command, result))
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BackfillError(f"repro graph returned invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise BackfillError("repro graph returned a non-object JSON document")
    return document


def discover_iso_packages(
    repro: str,
    packages_root: Path,
    env: dict[str, str],
    timeout: int,
) -> tuple[list[str], list[str]]:
    graph = load_graph(repro, ROOT, "iso", env, timeout)
    refs = sorted(
        {
            ref
            for action in graph_actions(graph)
            for ref in action.get("toolIdentityRefs", [])
            if isinstance(ref, str) and ref
        }
    )
    source_root = packages_root / "packages" / "source"
    packages = [name for name in refs if (source_root / name / "repro.nim").is_file()]
    ignored = [name for name in refs if name not in packages]
    if not packages:
        raise BackfillError("the source-only ISO graph contains no source package recipes")
    return packages, ignored


def package_cache_keys(
    repro: str,
    package_dir: Path,
    env: dict[str, str],
    timeout: int,
) -> list[str]:
    graph = load_graph(repro, package_dir, "", env, timeout)
    keys = sorted(
        {
            action.get("binaryCacheKey", "")
            for action in graph_actions(graph)
            if action.get("publishToBinaryCache") is True
            and isinstance(action.get("binaryCacheKey"), str)
            and CACHE_KEY_RE.fullmatch(action["binaryCacheKey"])
        }
    )
    if not keys:
        raise BackfillError(
            f"{package_dir.name} has no materialized binary-cache publication action"
        )
    return keys


def cache_lookup(
    repro: str,
    key: str,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> tuple[bool, str]:
    command = [repro, "cache", "lookup", key]
    result = run_command(command, cwd=cwd, env=env, timeout=timeout)
    output = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part)
    if result.returncode == 0 and re.search(rf"\bhit\s+{re.escape(key)}\b", output):
        return True, ""
    if result.returncode == 0:
        return False, output or "cache lookup did not report a hit"
    return False, command_failure(command, result)


def publish_package(
    repro: str,
    package_dir: Path,
    report_path: Path,
    env: dict[str, str],
    timeout: int,
) -> tuple[bool, str, list[str]]:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        repro,
        "build",
        "--daemon=off",
        "--tool-provisioning=from-source",
        "--publish-materialized",
        "--publish-cache-hits",
        f"--write-report={report_path}",
        "--progress=line",
        "--log=summary",
        "--no-runquota",
    ]
    result = run_command(command, cwd=package_dir, env=env, timeout=timeout)
    if result.returncode != 0:
        return False, command_failure(command, result), []

    reported_keys: set[str] = set()
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            actions = report.get("actions", []) if isinstance(report, dict) else []
            for action in actions:
                if not isinstance(action, dict):
                    continue
                reason = action.get("reason", "")
                if isinstance(reason, str):
                    reported_keys.update(CACHE_KEY_RE.findall(reason))
        except (OSError, json.JSONDecodeError) as error:
            return False, f"unable to read build report {report_path}: {error}", []
    return True, "", sorted(reported_keys)


def provider_worker_env(env: dict[str, str]) -> dict[str, str]:
    """Give each audit worker a reusable, non-overlapping provider cache."""
    result = env.copy()
    result["REPRO_PROVIDER_NIMCACHE_SESSION"] = (
        f"reproos-cache-backfill-{os.getpid()}-{threading.get_ident()}"
    )
    return result


def process_package(
    package: str,
    *,
    repro: str,
    packages_root: Path,
    report_path: Path,
    env: dict[str, str],
    verify_only: bool,
    graph_timeout: int,
    build_timeout: int,
    lookup_timeout: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    item: dict[str, Any] = {
        "package": package,
        "cacheKeys": [],
        "missingBefore": [],
        "missingAfter": [],
        "reportedPublicationKeys": [],
        "status": "pending",
        "resumed": False,
        "elapsedSeconds": 0.0,
        "error": "",
    }
    counts = {
        "cacheEntryCount": 0,
        "hitBeforeCount": 0,
        "publishedPackageCount": 0,
        "verifiedEntryCount": 0,
    }
    package_dir = packages_root / "packages" / "source" / package
    worker_env = provider_worker_env(env)
    started = time.monotonic()
    try:
        keys = package_cache_keys(repro, package_dir, worker_env, graph_timeout)
        item["cacheKeys"] = keys
        counts["cacheEntryCount"] = len(keys)

        missing: list[str] = []
        lookup_errors: list[str] = []
        for key in keys:
            hit, detail = cache_lookup(
                repro, key, package_dir, worker_env, lookup_timeout
            )
            if hit:
                counts["hitBeforeCount"] += 1
            else:
                missing.append(key)
                if detail:
                    lookup_errors.append(detail)
        item["missingBefore"] = missing

        if missing and verify_only:
            item["status"] = "missing"
            item["missingAfter"] = missing
            item["error"] = "; ".join(lookup_errors)
        elif missing:
            package_report = (
                report_path.parent / "cache-backfill-packages" / f"{package}.json"
            )
            ok, detail, reported_keys = publish_package(
                repro,
                package_dir,
                package_report,
                worker_env,
                build_timeout,
            )
            item["reportedPublicationKeys"] = reported_keys
            if not ok:
                raise BackfillError(detail)
            counts["publishedPackageCount"] = 1

            missing_after: list[str] = []
            for key in keys:
                hit = False
                detail = ""
                for attempt in range(5):
                    hit, detail = cache_lookup(
                        repro, key, package_dir, worker_env, lookup_timeout
                    )
                    if hit:
                        break
                    if attempt < 4:
                        time.sleep(1)
                if hit:
                    counts["verifiedEntryCount"] += 1
                else:
                    missing_after.append(key)
                    if detail:
                        item["error"] = detail
            item["missingAfter"] = missing_after
            item["status"] = "published" if not missing_after else "failed"
        else:
            counts["verifiedEntryCount"] = len(keys)
            item["status"] = "hit"
    except (BackfillError, OSError, subprocess.SubprocessError) as error:
        item["status"] = "failed"
        item["error"] = str(error)
    finally:
        item["elapsedSeconds"] = round(time.monotonic() - started, 3)
    return item, counts


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_catalog_fingerprint(packages_root: Path) -> str:
    digest = hashlib.sha256()
    source_root = packages_root / "packages" / "source"
    for recipe in sorted(source_root.glob("*/repro.nim")):
        relative = recipe.relative_to(source_root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(file_fingerprint(recipe).encode("ascii"))
    return digest.hexdigest()


def load_resume_items(
    path: Path,
    *,
    cache_url: str,
    cache_scope: str,
    packages_root: Path,
    repro_fingerprint: str,
    catalog_fingerprint: str,
) -> tuple[dict[str, dict[str, Any]], bool]:
    if not path.is_file():
        return {}, False
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BackfillError(f"unable to read resume report {path}: {error}") from error
    if not isinstance(previous, dict):
        raise BackfillError(f"resume report {path} is not a JSON object")

    expected = {
        "target": "iso",
        "cacheUrl": cache_url,
        "cacheScope": cache_scope,
        "reprobuildPackagesRoot": str(packages_root),
    }
    mismatches = [
        name for name, value in expected.items() if previous.get(name) != value
    ]
    if mismatches:
        raise BackfillError(
            "resume report does not match the current run: " + ", ".join(mismatches)
        )

    legacy = previous.get("schemaVersion") == 1
    if not legacy:
        fingerprint_mismatches = []
        if previous.get("reproFingerprint") != repro_fingerprint:
            fingerprint_mismatches.append("repro executable")
        if previous.get("sourceCatalogFingerprint") != catalog_fingerprint:
            fingerprint_mismatches.append("source catalog")
        if fingerprint_mismatches:
            raise BackfillError(
                "resume report inputs changed: " + ", ".join(fingerprint_mismatches)
            )

    items: dict[str, dict[str, Any]] = {}
    for item in previous.get("packages", []):
        if not isinstance(item, dict) or item.get("status") not in {"hit", "published"}:
            continue
        package = item.get("package")
        keys = item.get("cacheKeys")
        missing_after = item.get("missingAfter")
        if (
            isinstance(package, str)
            and isinstance(keys, list)
            and keys
            and all(isinstance(key, str) and CACHE_KEY_RE.fullmatch(key) for key in keys)
            and missing_after == []
        ):
            items[package] = item
    return items, legacy


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repro", default="", help="path to the repro CLI")
    parser.add_argument(
        "--packages-root",
        default="",
        help="path to the reprobuild-packages checkout",
    )
    parser.add_argument("--cache-url", default=DEFAULT_CACHE_URL)
    parser.add_argument("--cache-scope", default="release")
    parser.add_argument(
        "--report",
        default="build/evidence/reproos-cache-backfill-report.json",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="limit work to a named package; may be repeated",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="check the cache without publishing missing entries",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="reuse completed packages from a matching report",
    )
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--graph-timeout-sec", type=int, default=900)
    parser.add_argument("--build-timeout-sec", type=int, default=14400)
    parser.add_argument("--lookup-timeout-sec", type=int, default=60)
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="verify or publish this many package graphs concurrently",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = ROOT / report_path

    try:
        if args.jobs < 1:
            raise BackfillError("--jobs must be at least 1")
        if args.fail_fast and args.jobs != 1:
            raise BackfillError("--fail-fast requires --jobs=1")
        repro = resolve_repro(args.repro)
        packages_root = resolve_packages_root(args.packages_root)
        env = os.environ.copy()
        env.update(
            {
                "REPROBUILD_REPRO": repro,
                "REPROBUILD_PACKAGES_ROOT": str(packages_root),
                "REPRO_BINARY_CACHE_URL": args.cache_url,
                "REPRO_BINARY_CACHE_SCOPE": args.cache_scope,
                "REPRO_DAEMON": "off",
                "REPROBUILD_NO_RUNQUOTA": "1",
                "REPRO_FROM_SOURCE_ROOT": str(packages_root / "packages" / "source"),
            }
        )
        env.pop("REPRO_LOCK_PATH", None)
        env.pop("REPRO_LOCK_PINS", None)
        packages, ignored_refs = discover_iso_packages(
            repro, packages_root, env, args.graph_timeout_sec
        )
        if args.package:
            requested = set(args.package)
            unknown = sorted(requested.difference(packages))
            if unknown:
                raise BackfillError(
                    "requested packages are not in the source-only ISO graph: "
                    + ", ".join(unknown)
                )
            packages = [name for name in packages if name in requested]
        repro_fingerprint = file_fingerprint(Path(repro))
        catalog_fingerprint = source_catalog_fingerprint(packages_root)
        resume_items: dict[str, dict[str, Any]] = {}
        if args.resume:
            resume_items, legacy_resume = load_resume_items(
                report_path,
                cache_url=args.cache_url,
                cache_scope=args.cache_scope,
                packages_root=packages_root,
                repro_fingerprint=repro_fingerprint,
                catalog_fingerprint=catalog_fingerprint,
            )
            if legacy_resume:
                print(
                    "cache backfill: warning: resuming a schema-1 report without "
                    "input fingerprints",
                    file=sys.stderr,
                )
    except (BackfillError, OSError, subprocess.SubprocessError) as error:
        print(f"cache backfill: {error}", file=sys.stderr)
        return 1

    report: dict[str, Any] = {
        "schemaVersion": 2,
        "target": "iso",
        "cacheUrl": args.cache_url,
        "cacheScope": args.cache_scope,
        "verifyOnly": args.verify_only,
        "reprobuildPackagesRoot": str(packages_root),
        "reproFingerprint": repro_fingerprint,
        "sourceCatalogFingerprint": catalog_fingerprint,
        "ignoredToolIdentityRefs": ignored_refs,
        "sourcePackageCount": len(packages),
        "cacheEntryCount": 0,
        "hitBeforeCount": 0,
        "publishedPackageCount": 0,
        "verifiedEntryCount": 0,
        "complete": False,
        "packages": [],
    }
    package_reports = report["packages"]
    assert isinstance(package_reports, list)

    completed: dict[int, dict[str, Any]] = {}

    def record(index: int, item: dict[str, Any], counts: dict[str, int]) -> None:
        completed[index] = item
        for name, count in counts.items():
            report[name] += count
        package_reports[:] = [completed[i] for i in sorted(completed)]
        write_report(report_path, report)

    pending: list[tuple[int, str]] = []
    for index, package in enumerate(packages, start=1):
        resumed = resume_items.get(package)
        if resumed is None:
            pending.append((index, package))
            continue
        print(f"[{index}/{len(packages)}] {package} (resumed)", flush=True)
        item = dict(resumed)
        item["resumed"] = True
        keys = item["cacheKeys"]
        missing_before = item.get("missingBefore", [])
        record(
            index,
            item,
            {
                "cacheEntryCount": len(keys),
                "hitBeforeCount": len(keys) - len(missing_before),
                "publishedPackageCount": int(item["status"] == "published"),
                "verifiedEntryCount": len(keys),
            },
        )

    package_args = {
        "repro": repro,
        "packages_root": packages_root,
        "report_path": report_path,
        "env": env,
        "verify_only": args.verify_only,
        "graph_timeout": args.graph_timeout_sec,
        "build_timeout": args.build_timeout_sec,
        "lookup_timeout": args.lookup_timeout_sec,
    }
    if args.jobs == 1:
        for index, package in pending:
            print(f"[{index}/{len(packages)}] {package}", flush=True)
            item, counts = process_package(package, **package_args)
            record(index, item, counts)
            if item["status"] in {"failed", "missing"} and args.fail_fast:
                break
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = {}
            for index, package in pending:
                print(f"[{index}/{len(packages)}] {package} (scheduled)", flush=True)
                future = executor.submit(process_package, package, **package_args)
                futures[future] = (index, package)
            for future in as_completed(futures):
                index, package = futures[future]
                item, counts = future.result()
                print(
                    f"[{index}/{len(packages)}] {package} ({item['status']})",
                    flush=True,
                )
                record(index, item, counts)

    report["complete"] = (
        len(package_reports) == len(packages)
        and all(item["status"] in {"hit", "published"} for item in package_reports)
        and report["verifiedEntryCount"] == report["cacheEntryCount"]
    )
    write_report(report_path, report)
    print(
        "cache backfill: "
        f"{report['verifiedEntryCount']}/{report['cacheEntryCount']} entries verified "
        f"across {len(package_reports)}/{len(packages)} packages; "
        f"report: {report_path}",
        flush=True,
    )
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
