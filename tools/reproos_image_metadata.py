#!/usr/bin/env python3
"""Guest inode policy; never change the source package/staging tree."""

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile


def guest_path(root, name):
    """Resolve guest symlinks, including absolute links, without leaving root."""
    pending = name.split("/")
    parts = []
    hops = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError(f"guest path escapes root: {name}")
            parts.pop()
            continue
        path = root.joinpath(*parts, part)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            hops += 1
            if hops > 40:
                raise ValueError(f"guest symlink loop: {name}")
            target = os.readlink(path)
            if target.startswith("/"):
                parts = []
            pending = target.split("/") + pending
        else:
            parts.append(part)
    return root.joinpath(*parts)


class Policy:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or not self.root.is_dir() or self.root == Path("/"):
            raise ValueError("expected a private image root directory, not / or a symlink")
        self.sudo = guest_path(self.root, "/usr/bin/sudo")
        sudo_mode = self.sudo.lstat().st_mode
        if not stat.S_ISREG(sudo_mode) or not sudo_mode & 0o111:
            raise ValueError("guest /usr/bin/sudo must resolve to a regular executable")
        self.config_modes = {
            guest_path(self.root, "/etc/sudo.conf"): 0o644,
            guest_path(self.root, "/etc/sudoers"): 0o440,
        }
        if any(not path.is_file() for path in self.config_modes):
            raise ValueError("sudo configuration must resolve to regular guest files")
        self.trusted_dirs = set(guest_path(self.root, "/usr/bin").parents)
        self.trusted_dirs.add(guest_path(self.root, "/usr/bin"))
        for path in (self.sudo, *self.config_modes):
            self.trusted_dirs.update(path.parents)
        self.homes = {}
        for line in guest_path(self.root, "/etc/passwd").read_text().splitlines():
            fields = line.split(":")
            if len(fields) != 7:
                raise ValueError("invalid guest passwd record")
            name, _, uid, gid, _, home, _ = fields
            if 1000 <= int(uid) < 65534 and home == f"/home/{name}":
                if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]*", name) or int(gid) < 0:
                    raise ValueError("invalid guest home owner")
                if not stat.S_ISDIR((self.root / "home").lstat().st_mode):
                    raise ValueError("guest /home must be a real directory")
                path = self.root / home.lstrip("/")
                if path.is_symlink():
                    raise ValueError(f"user home must not be a symlink: {home}")
                self.homes[home.lstrip("/")] = (int(uid), int(gid))
        if any(path.is_relative_to(self.root / home)
               for path in (self.sudo, *self.config_modes) for home in self.homes):
            raise ValueError("sudo and its configuration must not reside in a user home")

    def entries(self, skip=()):
        def walk(path):
            name = path.relative_to(self.root).as_posix()
            if name in skip:
                return
            yield path
            if stat.S_ISDIR(path.lstat().st_mode):
                for child in sorted(path.iterdir()):
                    yield from walk(child)
        yield from walk(self.root)

    def metadata(self, path):
        info = path.lstat()
        name = path.relative_to(self.root).as_posix()
        mode = stat.S_IMODE(info.st_mode) & ~0o6000
        uid, gid = 0, 0
        for home, owner in self.homes.items():
            if name == home or name.startswith(home + "/"):
                uid, gid = owner
                break
        if path == self.root or name == "var/empty":
            mode = 0o755
        if path == self.sudo:
            mode = 0o4755
        elif path in self.trusted_dirs and not stat.S_ISLNK(info.st_mode):
            mode &= ~0o022
        if path in self.config_modes:
            mode = self.config_modes[path]
        return uid, gid, mode

    def squashfs(self, output):
        self.check_output(output)
        with open(output, "w", encoding="utf-8", newline="\n") as stream:
            for path in self.entries():
                name = path.relative_to(self.root).as_posix()
                if name == ".":
                    name = "/"
                if any(ord(c) < 32 for c in name):
                    raise ValueError(f"unsupported control character in guest path: {name!r}")
                name = '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'
                uid, gid, mode = self.metadata(path)
                stream.write(f"{name} m {mode:04o} {uid} {gid}\n")

    def archive(self, output, metadata, epoch):
        self.check_output(output)
        with tarfile.open(output, "w", format=tarfile.PAX_FORMAT) as archive:
            paths = [(Path(metadata), "metadata.yaml")] if metadata else []
            paths.extend((path, "rootfs" if path == self.root else
                          "rootfs/" + path.relative_to(self.root).as_posix())
                         for path in self.entries())
            for path, name in paths:
                entry = archive.gettarinfo(str(path), arcname=name)
                if name == "metadata.yaml":
                    entry.uid, entry.gid, entry.mode = 0, 0, 0o644
                else:
                    entry.uid, entry.gid, entry.mode = self.metadata(path)
                entry.uname = entry.gname = ""
                entry.mtime = epoch
                entry.pax_headers = {}
                # Do not propagate a privileged inode to a hardlinked alias.
                if stat.S_ISREG(path.lstat().st_mode):
                    entry.type, entry.linkname = tarfile.REGTYPE, ""
                    entry.size = path.lstat().st_size
                    with path.open("rb") as source:
                        archive.addfile(entry, source)
                else:
                    archive.addfile(entry)

    def check_output(self, output):
        if Path(output).resolve().is_relative_to(self.root.resolve()):
            raise ValueError("archive output must be outside the source tree")

    def apply(self, skip=()):
        if os.geteuid() != 0:
            raise PermissionError("applying image metadata requires root")
        root = self.root.resolve()
        # st_dev alone misses bind mounts on the same filesystem. Reject those
        # from Linux's mount table too, before changing even the root inode.
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            fields = line.split(" - ", 1)[0].split()
            mount = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
            if mount == root or not mount.is_relative_to(root):
                continue
            if not any(mount.is_relative_to(root / name) for name in skip):
                raise ValueError(f"unexpected mounted image descendant: {mount}")
        paths = list(self.entries(skip))
        device = self.root.lstat().st_dev
        for path in paths:
            if path.lstat().st_dev != device:
                raise ValueError(f"unexpected image filesystem boundary: {path}")
        for path in paths:
            uid, gid, mode = self.metadata(path)
            info = path.lstat()
            # A copied tree can still share an inode with a package cache.
            # Replace multiply-linked files before changing ownership or mode.
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                fd, temporary = tempfile.mkstemp(prefix=".image-metadata-", dir=path.parent)
                try:
                    with os.fdopen(fd, "wb") as target, path.open("rb") as source:
                        shutil.copyfileobj(source, target)
                    os.utime(temporary, ns=(info.st_atime_ns, info.st_mtime_ns))
                    os.replace(temporary, path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            elif stat.S_ISLNK(info.st_mode) and info.st_nlink > 1:
                target = os.readlink(path)
                path.unlink()
                path.symlink_to(target)
            os.chown(path, uid, gid, follow_symlinks=False)
            if not stat.S_ISLNK(info.st_mode):
                os.chmod(path, mode, follow_symlinks=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("squashfs", "tar", "apply"))
    parser.add_argument("root")
    parser.add_argument("--output")
    parser.add_argument("--metadata")
    parser.add_argument("--skip", action="append", default=[])
    args = parser.parse_args()
    policy = Policy(args.root)
    if args.operation == "apply":
        policy.apply(args.skip)
    elif not args.output:
        parser.error("--output is required for archive metadata")
    elif args.operation == "squashfs":
        policy.squashfs(args.output)
    else:
        policy.archive(args.output, args.metadata, int(os.environ["SOURCE_DATE_EPOCH"]))


if __name__ == "__main__":
    main()
