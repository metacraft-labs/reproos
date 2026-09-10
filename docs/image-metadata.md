# Image Metadata

`tools/reproos_image_metadata.py` owns the guest inode policy at the packaging
boundary. Package install mirrors and the shared `de-rootfs` stage remain
unprivileged build inputs; never recursively chown or chmod them as root.

- ISO: `build-iso.sh` emits SquashFS pseudo metadata with `-all-root`,
  `-root-mode 0755`, and
  `-pseudo-override`. The override is required for declared user-home owners.
  `-no-hardlinks` prevents sudo's privileged mode from reaching another alias.
- Writable installed QCOW2: `build-reproos-image.sh` applies the same policy to
  its private mounted destination, after account/configuration installation.
  The FAT ESP is excluded; other mounted descendants and device boundaries are
  refused before any inode changes. Multiply-linked files are detached before changes;
  symlinks are never followed during ownership changes. Chown precedes chmod.
- Container: the deterministic tar writer assigns the same numeric owners and
  modes without changing the staged files. It supports the configured home
  name, not just `/home/repro`, and archives hardlinked files independently.
- Integrity-checked read-only root: `build-verity-root.sh` applies the same
  policy to the finished ext4 image with `debugfs`, addressing every inode by
  NUMBER so no guest filename has to survive argument splitting, and then
  re-reads the whole image and refuses to take a root hash over one that does
  not carry the policy. `mke2fs` has no pseudo-file, and the tree cannot be
  chowned — `apply` needs uid 0, and a root-owned tree under `build/` is one
  the engine can neither replace nor clean. Rewriting inode fields needs no
  privilege and stamps no time, so the same tree and the same policy give the
  same bytes; that matters because these bytes are inside the launch
  measurement. `mkfs.ext4 -d` preserves hardlinks and an inode carries one
  owner and one mode, so a shared inode the policy describes two ways — or any
  setuid inode reachable under a second name — is REFUSED rather than resolved
  by picking one of the two answers. The ISO duplicates the content instead
  (`-no-hardlinks`); an image whose size is already fixed cannot.

Everything defaults to `0:0`. Normal users' declared `/home/NAME` trees retain
their passwd UID/GID and non-privilege mode bits, including live's `0700` home. Incoming
setuid/setgid bits are removed; only the regular executable reached by guest
`/usr/bin/sudo` receives `04755`. Absolute guest links are resolved inside the
image, not against the build host. Escapes, cycles, missing sudo targets, and
sudo targets inside a user home are errors. Archive metadata excludes xattrs.
These are offline packaging operations over an exclusively owned destination,
not a concurrent or hostile-filesystem editing API.

The staged sudoers policy grants passwordless commands to `sudo` (live) and
`wheel` (the supported installed administrative profile). Installed health
checks assert root-owned configuration, root-setuid sudo, and `sudo -n id -u`
executed as the configured non-root user. An empty `enrollment.complete` remains
a valid completion marker.
The source sudo plugin directory is linked at its compiled `/usr/libexec/sudo`
path, and the sudo PAM service uses the image's common account/session policy
instead of falling back to the deliberately denying `other` service.

Run `repro build test-image-metadata` on Linux for small real SquashFS/tar fixtures,
source/cache preservation, guest symlink resolution, destination policy, and
health-command exit-status checks. It needs no VM or root access. Other hosts
report an explicit platform skip before fixture setup; the graph does not select
the Linux archive tools there. Python, Bash and pinned host `mksquashfs` /
`unsquashfs` are action tool identities; no source archive-tool bootstrap is
required. Run `repro build test-image-reproducibility` and `repro lint` as well.
The destination test observes chown calls without requiring root; archive tests
read actual numeric ownership from the generated filesystems.

Run `repro build test-attested-root-metadata` for the raw-ext4 carrier. Its
always-on layer needs only `python3`; `REPROOS_ATTESTED_ROOT_METADATA_GATE=1`
images a purpose-built root with the shipped builder and reads every owner and
mode back out of it through a read-only loop mount, so nothing in the
verification path is shared with the `debugfs` that wrote them. Existing VM
disks and receipts are not migrated or modified; acceptance needs newly
authored media.

Upstream format references: [SquashFS 4.7.5 usage](https://github.com/plougher/squashfs-tools/blob/master/Documentation/4.7.5/USAGE-MKSQUASHFS.md)
and [pseudo filename parser](https://github.com/plougher/squashfs-tools/blob/4.7.5/squashfs-tools/pseudo.c).
