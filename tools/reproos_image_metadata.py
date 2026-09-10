#!/usr/bin/env python3
"""Guest inode policy; never change the source package/staging tree."""

import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
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

    def expected(self):
        """The policy as a map: guest path -> (uid, gid, permission bits).

        The permission bits are ``None`` for a symlink, because a symlink's
        mode is not policy -- ``apply`` never chmods one, and every carrier
        below follows it. ``.`` is the root inode.

        This is the ONE description every carrier is checked against, so a
        carrier cannot hold a second opinion about what the policy says.
        """
        table = {}
        for path in self.entries():
            name = path.relative_to(self.root).as_posix()
            uid, gid, mode = self.metadata(path)
            link = stat.S_ISLNK(path.lstat().st_mode)
            table[name] = (uid, gid, None if link else mode)
        return table

    def squashfs(self, output):
        self.check_output(output)
        with open(output, "w", encoding="utf-8", newline="\n") as stream:
            for path in self.entries():
                name = path.relative_to(self.root).as_posix()
                if name == ".":
                    # Existing root inode modes require mksquashfs -root-mode;
                    # pseudo records only override descendants of that inode.
                    continue
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


class Ext4Image:
    """Carry the policy into a finished ext4 image, without root.

    ``mkfs.ext4 -d`` copies the staging tree's ownership and modes, which
    on an unprivileged build are the building user's -- so a raw-ext4 root
    ships ``/etc/shadow`` owned by whoever holds that uid and
    ``/usr/bin/sudo`` with no setuid bit. The ISO does not have this
    problem: ``mksquashfs -pf`` sets ownership and modes as the image is
    made. ``mke2fs`` has no pseudo-file, so the equivalent is done here,
    afterwards, by rewriting the inodes of the image itself with
    ``debugfs``.

    Three properties make that a legitimate answer rather than a
    workaround:

      * it needs no privilege -- the image is an ordinary file the build
        already owns, and nothing chowns anything on the host;
      * it is deterministic -- ``debugfs`` writes exact inode fields and
        stamps no time, so the same tree and the same policy give the same
        bytes, which matters because these bytes are inside the
        measurement; and
      * the policy is ``Policy.expected()``, the same table the SquashFS
        pseudo-file and the container tar are written from.

    Everything is addressed by INODE NUMBER (``<12>``) rather than by
    path, so no guest filename ever has to survive ``debugfs``'s argument
    splitting.
    """

    LostFound = "lost+found"

    def __init__(self, image):
        self.image = str(image)
        if not Path(self.image).is_file():
            raise ValueError(f"not a filesystem image: {self.image}")
        self.debugfs = shutil.which("debugfs")
        if not self.debugfs:
            raise ValueError("debugfs is required to carry the guest inode "
                             "policy into an ext4 image and is not on PATH")

    def _debugfs(self, commands, write=False):
        """Run a command script and return stdout, refusing any diagnostic.

        ``debugfs`` reports a failed command on stderr and still exits 0, so
        the exit status alone would let a silently skipped ``sif`` through.
        Every stderr line is therefore accounted for: the banner, and one
        echo per command. Anything else is an error.
        """
        with tempfile.TemporaryDirectory(prefix=".image-metadata-") as scratch:
            script = Path(scratch) / "commands"
            script.write_text("".join(c + "\n" for c in commands),
                              encoding="utf-8")
            argv = [self.debugfs]
            if write:
                argv.append("-w")
            argv += ["-f", str(script), self.image]
            done = subprocess.run(argv, capture_output=True, text=True)
        if done.returncode != 0:
            raise ValueError(f"debugfs failed on {self.image}: "
                             f"{done.stderr.strip()}")
        noise = re.compile(r"^debugfs (\d|$)|^debugfs: +(sif|ls -l) ")
        for line in done.stderr.splitlines():
            if line.strip() and not noise.match(line):
                raise ValueError(f"debugfs refused a command on {self.image}: "
                                 f"{line.strip()}")
        return done.stdout

    def walk(self):
        """guest path -> (inode, uid, gid, full i_mode), read out of the image.

        The walk is driven by the IMAGE rather than by the staging tree, so
        an entry the image holds and the tree does not is found rather than
        skipped.
        """
        found = {}
        pending = [(2, ".")]
        while pending:
            output = self._debugfs("ls -l <%d>" % ino for ino, _ in pending)
            index, base, following = -1, None, []
            for line in output.splitlines():
                fields = line.split(None, 8)
                if len(fields) < 9:
                    continue
                name = fields[8]
                # Every listing opens with its own `.` entry, which is what
                # separates one directory's block of output from the next.
                if name == ".":
                    index += 1
                    if index >= len(pending):
                        raise ValueError("debugfs listed more directories "
                                         "than were asked for")
                    base = pending[index][1]
                    if base == ".":
                        found["."] = (int(fields[0]), int(fields[3]),
                                      int(fields[4]), int(fields[1], 8))
                    continue
                if name == "..":
                    continue
                if base is None:
                    raise ValueError("debugfs listed an entry outside any "
                                     "directory")
                inode, mode = int(fields[0]), int(fields[1], 8)
                path = name if base == "." else base + "/" + name
                if path in found:
                    raise ValueError(f"guest path listed twice: {path}")
                found[path] = (inode, int(fields[3]), int(fields[4]), mode)
                if stat.S_ISDIR(mode):
                    following.append((inode, path))
            if index + 1 != len(pending):
                raise ValueError("debugfs listed fewer directories than were "
                                 "asked for")
            pending = following
        return found

    def differences(self, policy):
        """Every place the image disagrees with the policy, in walk order.

        Returns ``(inode, path, wanted, found, kind)`` tuples, where
        ``wanted`` and ``found`` are ``(uid, gid, permission bits)`` and
        ``kind`` is the inode's file-type bits.
        """
        want = policy.expected()
        found = self.walk()
        extra = sorted(set(found) - set(want) - {self.LostFound})
        if extra:
            raise ValueError("the image holds paths the staged tree does "
                             "not, so the policy does not describe it: " +
                             ", ".join(extra[:8]))
        missing = sorted(set(want) - set(found))
        if missing:
            raise ValueError("the image is missing staged paths, so the "
                             "policy does not describe it: " +
                             ", ".join(missing[:8]))
        if self.LostFound in found:
            _, uid, gid, mode = found[self.LostFound]
            if (uid, gid) != (0, 0):
                raise ValueError(f"mke2fs left {self.LostFound} owned by "
                                 f"{uid}:{gid} rather than 0:0")
            want = dict(want)
            want[self.LostFound] = (0, 0, stat.S_IMODE(mode))
        self._refuse_ambiguous_inodes(found, want)
        report = []
        for path, (inode, uid, gid, mode) in found.items():
            wuid, wgid, wmode = want[path]
            have = (uid, gid, None if stat.S_ISLNK(mode) else
                    stat.S_IMODE(mode))
            if have != (wuid, wgid, wmode):
                report.append((inode, path, (wuid, wgid, wmode), have,
                               mode & ~0o7777))
        return report

    @staticmethod
    def _refuse_ambiguous_inodes(found, want):
        """Refuse a shared inode the policy describes two ways.

        ``mkfs.ext4 -d`` preserves hardlinks, and an inode carries ONE
        owner and ONE mode. The ISO sidesteps this with
        ``mksquashfs -no-hardlinks``, which duplicates the content; an
        image whose size is already fixed cannot, so an aliased inode the
        policy disagrees about is refused rather than resolved by picking
        one of the two answers. A privileged mode reached through a second
        name is refused for the same reason even when both names agree:
        setuid must not arrive anywhere the policy did not put it.
        """
        aliases = {}
        for path, (inode, _, _, _) in found.items():
            aliases.setdefault(inode, []).append(path)
        for inode, paths in sorted(aliases.items()):
            if len(paths) < 2:
                continue
            paths = sorted(paths)
            answers = {want[p] for p in paths}
            if len(answers) > 1:
                raise ValueError(
                    f"inode {inode} is reached by {len(paths)} guest paths "
                    f"the policy describes differently ({', '.join(paths[:4])}"
                    f"): an inode holds one owner and one mode, so the image "
                    f"would be silently wrong at all but one of them")
            mode = next(iter(answers))[2]
            if mode is not None and mode & (stat.S_ISUID | stat.S_ISGID):
                raise ValueError(
                    f"inode {inode} carries mode {mode:04o} and is reached by "
                    f"{len(paths)} guest paths ({', '.join(paths[:4])}): a "
                    f"setuid or setgid inode must not be reachable under a "
                    f"second name")

    def apply(self, policy):
        """Rewrite the image's inodes until they are the policy."""
        commands = []
        for inode, _, wanted, found, kind in self.differences(policy):
            uid, gid, mode = wanted
            if uid != found[0]:
                commands.append("sif <%d> uid %d" % (inode, uid))
            if gid != found[1]:
                commands.append("sif <%d> gid %d" % (inode, gid))
            if mode is not None and mode != found[2]:
                # `sif mode` replaces the WHOLE i_mode, so the file type
                # has to be carried over or the inode becomes untyped.
                commands.append("sif <%d> mode 0%o" % (inode, kind | mode))
        if commands:
            self._debugfs(commands, write=True)
        # A carrier that does not check its own work is how an image gets
        # hashed without the policy in it.
        left = self.differences(policy)
        if left:
            inode, path, wanted, found, _ = left[0]
            raise ValueError(
                f"the guest inode policy did not land in {self.image}: "
                f"{path} (inode {inode}) is {self.render(found)} and the "
                f"policy says {self.render(wanted)}")
        return len(commands)

    def verify(self, policy):
        """Refuse an image that is not already the policy."""
        report = self.differences(policy)
        if report:
            inode, path, wanted, found, _ = report[0]
            raise ValueError(
                f"{self.image} does not carry the guest inode policy: "
                f"{path} (inode {inode}) is {self.render(found)} and the "
                f"policy says {self.render(wanted)} ({len(report)} "
                f"path(s) disagree)")

    @staticmethod
    def render(triple):
        uid, gid, mode = triple
        return f"{'link' if mode is None else format(mode, '04o')} {uid}:{gid}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("squashfs", "tar", "apply",
                                              "ext4-apply", "ext4-verify"))
    parser.add_argument("root")
    parser.add_argument("--output")
    parser.add_argument("--image")
    parser.add_argument("--metadata")
    parser.add_argument("--skip", action="append", default=[])
    args = parser.parse_args()
    if args.operation in ("ext4-apply", "ext4-verify"):
        if not args.image:
            parser.error("--image is required for ext4 metadata")
        # A diagnostic, not a traceback. Whoever reads this is holding an
        # image that must not be hashed, and needs to be told which inode
        # and what the policy wanted -- including when the refusal is that
        # the tree is not a root filesystem the policy can describe.
        try:
            policy = Policy(args.root)
            image = Ext4Image(args.image)
            if args.operation == "ext4-verify":
                image.verify(policy)
                print("[image-metadata] %s carries the guest inode policy"
                      % args.image)
            else:
                print("[image-metadata] %d inode field(s) rewritten in %s"
                      % (image.apply(policy), args.image))
        except (ValueError, OSError) as error:
            raise SystemExit("reproos_image_metadata.py %s: %s"
                             % (args.operation, error))
        return
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
