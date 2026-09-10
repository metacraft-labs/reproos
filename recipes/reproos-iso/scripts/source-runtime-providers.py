#!/usr/bin/env python3
"""Resolve runtime providers inside an image, never through the host root."""

from __future__ import annotations

import argparse
from collections import deque
import os
from pathlib import Path
import stat
import sys


class ImagePathError(ValueError):
    pass


def resolve_image_path(stage: Path, image_path: str) -> Path:
    if not image_path.startswith("/"):
        raise ImagePathError(f"image path is not absolute: {image_path}")
    pending = deque(image_path.split("/")[1:])
    parts: list[str] = []
    links = 0
    while pending:
        part = pending.popleft()
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        candidate = stage.joinpath(*parts, part)
        try:
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode):
                links += 1
                if links > 40:
                    raise ImagePathError(f"image symlink chain exceeds 40 links: {image_path}")
                target = os.readlink(candidate)
                if target.startswith("/"):
                    parts.clear()
                pending.extendleft(reversed(target.split("/")))
                continue
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ImagePathError(f"image path component is not a directory: {image_path}")
        except OSError as error:
            raise ImagePathError(f"unresolved image path: {image_path}: {error.strerror}") from error
        parts.append(part)
    return stage.joinpath(*parts)


def runtime_file(stage: Path, image_path: str, source: Path | None = None,
                 executable: bool = False) -> Path:
    target = resolve_image_path(stage, image_path)
    if source is not None and not target.is_relative_to(source):
        raise ImagePathError(f"library target is outside source mirror: {image_path}")
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ImagePathError(f"runtime target is not a regular file: {image_path}")
    if executable and not info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise ImagePathError(f"runtime target is not executable: {image_path}")
    return target


def provider_records(stage: Path, source: Path):
    def failed_walk(error: OSError):
        raise error

    paths: list[Path] = []
    for directory, dirs, files in os.walk(source, followlinks=False, onerror=failed_walk):
        for name in files + [name for name in dirs if (Path(directory) / name).is_symlink()]:
            if ".so" in name:
                paths.append(Path(directory) / name)
    for path in sorted(paths):
        image_path = "/" + path.relative_to(stage).as_posix()
        error = ""
        try:
            runtime_file(stage, image_path, source=source)
        except (ImagePathError, OSError) as failure:
            error = str(failure)
        yield path.name, image_path, error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path)
    parser.add_argument("source", type=Path)
    parser.add_argument("--check", help="check one image path instead of indexing libraries")
    parser.add_argument("--source-only", action="store_true")
    parser.add_argument("--executable", action="store_true")
    args = parser.parse_args()
    if not args.check and (args.source_only or args.executable):
        parser.error("--source-only and --executable require --check")
    try:
        stage = args.stage.resolve(strict=True)
        source = args.source.resolve(strict=True)
        if stage == Path(stage.anchor) or source == stage or not source.is_relative_to(stage):
            raise ImagePathError("source mirror must be inside a non-root staging directory")
        if not stage.is_dir() or not source.is_dir():
            raise ImagePathError("staging root and source mirror must be directories")
        if args.check:
            runtime_file(stage, args.check, source=source if args.source_only else None,
                         executable=args.executable)
        else:
            # NUL-framed triples preserve whitespace in paths and diagnostics.
            for record in provider_records(stage, source):
                for field in record:
                    sys.stdout.buffer.write(os.fsencode(field) + b"\0")
        return 0
    except (ImagePathError, OSError) as error:
        print(f"[source-runtime-providers] {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
