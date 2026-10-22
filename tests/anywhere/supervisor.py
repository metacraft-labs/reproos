#!/usr/bin/env python3
"""Test supervisor: the independent management plane for Anywhere fixtures.

It plays the role a cloud provider or a datacenter operator plays for a
real machine: it CREATES the source machine from a fresh, digest-pinned
distribution image, and therefore knows -- without asking the machine --
its SSH host key (which it generates and injects through cloud-init), its
DMI product UUID, its disk serials and sizes and its MAC address. It
writes those into the enrollment the controller trusts, and it provides
the rescue plane: the serial console captured to a file and the QEMU
monitor on a UNIX socket.

Machines run as unprivileged QEMU/KVM guests with user-mode networking
and a loopback-only forwarded SSH port. Nothing here needs root, and
nothing touches the host's disks, bootloader or /etc: every write is to
a qcow2 overlay under the run directory, which `destroy` deletes.

    supervisor.py image  <distro>                 fetch + verify a base image
    supervisor.py create <distro> <dir> [--readonly] [--port N]
    supervisor.py start  <dir> [--readonly]
    supervisor.py stop   <dir>
    supervisor.py destroy <dir>
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
DISTROS = json.loads((HERE / "distros.json").read_text())
FIRMWARE = Path(os.environ.get("ANYWHERE_OVMF_DIR", "/run/current-system/sw/share/qemu"))
IMAGE_CACHE = Path(os.environ.get("ANYWHERE_IMAGE_CACHE", HERE / ".images"))
# Bounded guests: the host serves CI, so every fixture is capped.
CPUS, MEMORY_MIB, DISK_GIB = 2, 2048, 12


def sha_file(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_image(distro: str) -> Path:
    spec = DISTROS[distro]
    if "nix_build" in spec:
        # Built from the pinned nixpkgs revision the expression names.
        out = subprocess.run(["nix-build", "--no-out-link", str(HERE / spec["nix_build"])],
                             check=True, capture_output=True, text=True).stdout.strip()
        return Path(out) / spec["file"]
    IMAGE_CACHE.mkdir(parents=True, exist_ok=True)
    path = IMAGE_CACHE / spec["file"]
    if path.exists() and sha_file(path, spec["algo"]) == spec["digest"]:
        return path
    tmp = path.with_suffix(".part")
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(tmp), spec["url"]], check=True)
    got = sha_file(tmp, spec["algo"])
    if got != spec["digest"]:
        tmp.unlink()
        raise SystemExit(f"{distro}: {spec['url']} has {spec['algo']} {got}, pinned {spec['digest']}")
    tmp.rename(path)
    return path


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def iso_seed(directory: Path, files: dict[str, str]) -> Path:
    """A NoCloud seed: an ISO 9660 volume labelled "cidata" (the form every
    cloud-init build reads from a CD-ROM, Alpine's included)."""
    seed = directory / "seed.img"
    for name, text in files.items():
        (directory / name).write_text(text)
    subprocess.run(["xorriso", "-as", "genisoimage", "-quiet", "-output", str(seed), "-volid", "cidata",
                    "-joliet", "-rock", *[str(directory / n) for n in files]], check=True,
                   stderr=subprocess.DEVNULL)
    return seed


def short_socket_path() -> str:
    """A UNIX socket path must stay under 108 bytes; TMPDIR can be long."""
    for base in (os.environ.get("XDG_RUNTIME_DIR", ""), "/tmp"):
        if base and os.path.isdir(base) and os.access(base, os.W_OK):
            path = str(Path(tempfile.mkdtemp(prefix="aw-", dir=base)) / "monitor.sock")
            if len(path.encode()) < 108:
                return path
    raise SystemExit("no directory short enough for a QEMU monitor socket (needs < 108 bytes)")


def create(distro: str, run: Path, port: int | None, *, firmware: str = "uefi",
           extra_disks: tuple[int, ...] = (), runcmd: tuple[str, ...] = (),
           network_config: str | None = None, target: str = "boot", mac: str | None = None,
           controller: str = "virtio-blk") -> dict:
    """``firmware`` uefi|bios; ``extra_disks`` sizes (GiB) attached behind
    the target before first boot; ``runcmd`` extra first-boot commands;
    ``network_config`` a cloud-init v2 network document; ``target`` "boot"
    or "extra-0" -- which disk the enrollment names as the target."""
    spec = DISTROS[distro]
    base = fetch_image(distro)
    run.mkdir(parents=True, exist_ok=False)
    keys = run / "keys"
    keys.mkdir(mode=0o700)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"anywhere-host-{distro}",
                    "-f", str(keys / "host_ed25519")], check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "anywhere-operator",
                    "-f", str(keys / "operator_ed25519")], check=True)
    host_priv = (keys / "host_ed25519").read_text()
    host_pub = (keys / "host_ed25519.pub").read_text().strip()
    op_pub = (keys / "operator_ed25519.pub").read_text().strip()
    machine = {
        "distro": distro, "uuid": str(uuid.uuid4()),
        "serial": "AW-" + uuid.uuid4().hex[:12].upper(),
        "mac": mac or "52:54:00:%02x:%02x:%02x" % tuple(os.urandom(3)),
        "port": port or free_port(), "disk_gib": DISK_GIB,
        # A UNIX socket path is limited to 107 bytes, which a run directory
        # deep in a worktree exceeds; the monitor lives in a short one.
        "monitor": short_socket_path(),
        "firmware": firmware,
        "arch": spec.get("arch", "x86_64"),
        "controller": controller,
        "target": target,
    }
    extra_runcmd = "".join(f"  - [sh, -c, {json.dumps(cmd)}]\n" for cmd in runcmd)
    indent = "\n".join("      " + line for line in host_priv.splitlines())
    indent2 = "\n".join("      " + line for line in host_priv.splitlines())
    user_data = f"""#cloud-config
disable_root: false
ssh_pwauth: false
ssh_deletekeys: true
ssh_keys:
  ed25519_private: |
{indent}
  ed25519_public: {host_pub}
users:
  - name: root
    ssh_authorized_keys:
      - {op_pub}
# Some cloud-init builds (Alpine's) skip the ssh module's host-key
# handling, so the key is also written as a plain file.
write_files:
  - path: /etc/ssh/ssh_host_ed25519_key
    permissions: "0600"
    owner: root:root
    content: |
{indent2}
  - path: /etc/ssh/ssh_host_ed25519_key.pub
    permissions: "0644"
    owner: root:root
    content: "{host_pub}\n"
runcmd:
{extra_runcmd}  - [sh, -c, "sed -i 's/^root:![^:]*:/root:*:/' /etc/shadow; sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config; (systemctl restart ssh || systemctl restart sshd || rc-service sshd restart) 2>/dev/null; true"]
"""
    seed = {"user-data": user_data,
            "meta-data": f"instance-id: {machine['uuid']}\nlocal-hostname: src-{distro}\n"}
    if network_config:
        seed["network-config"] = network_config
    iso_seed(run, seed)
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", spec.get("format", "qcow2"),
                    "-b", str(base), str(run / "disk.qcow2"), f"{DISK_GIB}G"], check=True)
    vars_fd = run / "OVMF_VARS.fd"
    shutil.copyfile(FIRMWARE / ("edk2-arm-vars.fd" if machine["arch"] == "aarch64" else "edk2-i386-vars.fd"),
                    vars_fd)
    vars_fd.chmod(0o600)
    (run / "machine.json").write_text(json.dumps(machine, indent=2))
    for gib in extra_disks:
        add_disk(run, "after", gib)
    start(run, readonly=False)
    wait_ssh(run, timeout=spec.get("first_boot_timeout", 300) + 120 * bool(runcmd))
    write_enrollment(run, readonly=False)
    return machine


PLANNING_KINDS = {
    # Guest writes are impossible: the drive is read-only below the guest.
    "readonly": ("qemu-drive-readonly", ",readonly=on"),
    # Guest writes land in a throwaway overlay QEMU discards at exit; the
    # machine's disk is never written. For distributions whose boot cannot
    # run from a read-only device (Arch's btrfs root, NixOS's stage-1 fsck).
    "snapshot": ("qemu-snapshot", ",snapshot=on"),
}


def planning_kind(m: dict) -> str:
    """The strongest planning environment both the distribution and the
    disk controller can boot from."""
    kinds = {DISTROS[m["distro"]].get("planning", "readonly"),
             CONTROLLERS[m.get("controller", "virtio-blk")][1]}
    return "snapshot" if "snapshot" in kinds else "readonly"


def qemu_argv(run: Path, readonly: bool) -> list[str]:
    m = json.loads((run / "machine.json").read_text())
    ro = PLANNING_KINDS[planning_kind(m)][1] if readonly else ""
    if m.get("arch", "x86_64") == "aarch64":
        return aarch64_argv(run, m, ro)
    return [
        "qemu-system-x86_64", "-name", f"anywhere-{m['distro']}",
        "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", str(CPUS), "-m", str(MEMORY_MIB),
        "-uuid", m["uuid"],
        *firmware_args(run, m),
        # Explicit PCI slots: the kernel names virtio disks in slot order,
        # so a disk added "before" the target really renames the target.
        "-drive", f"file={run / m.get('disk_file', 'disk.qcow2')},if=none,id=d0,format=qcow2{ro}",
        # The target sits behind a hot-plug capable root port so a test can
        # replace the drive under a running machine (pcie.0 itself is not).
        "-device", "pcie-root-port,id=rp6,bus=pcie.0,addr=0x6,chassis=6",
        *target_device_args(m),
        *extra_disk_args(run, m, ro),
        # The cloud-init seed rides on the chipset's AHCI controller, so it
        # is /dev/sr0 and never takes a /dev/vd* name from a real disk.
        "-drive", f"file={run / 'seed.img'},if=none,id=seed,format=raw,readonly=on",
        "-device", "ide-cd,drive=seed,bus=ide.2",
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{m['port']}-:22",
        "-device", f"virtio-net-pci,netdev=n0,mac={m['mac']}",
        "-display", "none",
        # Append-only: the console is the rescue plane's record, and a
        # power cycle must not truncate what was read before it.
        "-chardev", f"file,id=console,path={run / 'console.log'},append=on",
        "-serial", "chardev:console",
        "-monitor", f"unix:{m['monitor']},server,nowait",
        "-pidfile", str(run / "qemu.pid"), "-daemonize",
        *rescue_args(m),
    ]


def aarch64_argv(run: Path, m: dict, ro: str) -> list[str]:
    """An emulated arm64 source machine (TCG: this host has no arm64 KVM).

    It exists to show what Anywhere does with a source it cannot convert,
    so it carries only the target disk on virtio-blk, the seed on a
    virtio-scsi CD-ROM and the PL011 console; it is slow and never a
    conversion target."""
    if m.get("controller", "virtio-blk") != "virtio-blk" or m.get("extra_disks") or m.get("rescue_boot"):
        raise SystemExit("aarch64 sources support only the plain virtio-blk shape")
    return [
        "qemu-system-aarch64", "-name", f"anywhere-{m['distro']}",
        "-machine", "virt,accel=tcg", "-cpu", "max", "-smp", str(CPUS), "-m", str(MEMORY_MIB),
        "-uuid", m["uuid"],
        "-drive", f"if=pflash,format=raw,readonly=on,file={FIRMWARE / 'edk2-aarch64-code.fd'}",
        "-drive", f"if=pflash,format=raw,file={run / 'OVMF_VARS.fd'}",
        "-drive", f"file={run / m.get('disk_file', 'disk.qcow2')},if=none,id=d0,format=qcow2{ro}",
        "-device", f"virtio-blk-pci,drive=d0,id=target,serial={m['serial']},bootindex=1",
        "-device", "virtio-scsi-pci,id=scsi0",
        "-drive", f"file={run / 'seed.img'},if=none,id=seed,format=raw,readonly=on",
        "-device", "scsi-cd,drive=seed,bus=scsi0.0",
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{m['port']}-:22",
        "-device", f"virtio-net-pci,netdev=n0,mac={m['mac']}",
        "-display", "none",
        "-chardev", f"file,id=console,path={run / 'console.log'},append=on",
        "-serial", "chardev:console",
        "-monitor", f"unix:{m['monitor']},server,nowait",
        "-pidfile", str(run / "qemu.pid"), "-daemonize",
    ]


def rescue_args(m: dict) -> list[str]:
    r = m.get("rescue_boot")
    if not r:
        return []
    return ["-kernel", r["kernel"], "-initrd", r["initrd"], "-append", r["cmdline"]]


def rescue_boot(run: Path, kernel: str, initrd: str, cmdline: str) -> None:
    """The provider-rescue analogue: power off, boot the given media."""
    m = json.loads((run / "machine.json").read_text())
    media = run / "rescue-media"
    media.mkdir(exist_ok=True)
    shutil.copyfile(kernel, media / "vmlinuz")
    shutil.copyfile(initrd, media / "initrd.img")
    m["rescue_boot"] = {"kernel": str(media / "vmlinuz"), "initrd": str(media / "initrd.img"),
                        "cmdline": cmdline}
    (run / "machine.json").write_text(json.dumps(m, indent=2))
    stop(run, graceful_timeout=60)
    start(run, readonly=False)


def normal_boot(run: Path) -> None:
    """Leave rescue mode: power off, boot from the machine's own disk."""
    m = json.loads((run / "machine.json").read_text())
    m.pop("rescue_boot", None)
    (run / "machine.json").write_text(json.dumps(m, indent=2))
    stop(run, graceful_timeout=5)
    start(run, readonly=False)


CONTROLLERS = {
    # name -> (kernel name of the target, planning environment it supports)
    "virtio-blk": ("vda", "readonly"),
    "virtio-scsi": ("sda", "snapshot"),   # the source fscks its ESP and fails read-only
    "ahci": ("sda", "snapshot"),       # ide-hd cannot be attached read-only
    "nvme": ("nvme0n1", "snapshot"),
}


def target_device_args(m: dict) -> list[str]:
    serial, ctl = m["serial"], m.get("controller", "virtio-blk")
    if ctl == "virtio-blk":
        return ["-device", f"virtio-blk-pci,drive=d0,id=target,serial={serial},bootindex=1,bus=rp6"]
    if ctl == "virtio-scsi":
        return ["-device", "virtio-scsi-pci,id=scsi0,bus=rp6",
                "-device", f"scsi-hd,drive=d0,id=target,serial={serial},bootindex=1,bus=scsi0.0"]
    if ctl == "ahci":
        return ["-device", f"ide-hd,drive=d0,id=target,serial={serial},bootindex=1,bus=ide.0"]
    if ctl == "nvme":
        return ["-device", f"nvme,drive=d0,id=target,serial={serial},bootindex=1,bus=rp6"]
    raise SystemExit(f"unknown controller {ctl}")


def firmware_args(run: Path, m: dict) -> list[str]:
    if m.get("firmware", "uefi") == "bios":
        return []                     # QEMU's default SeaBIOS
    return ["-drive", f"if=pflash,format=raw,readonly=on,file={FIRMWARE / 'edk2-x86_64-code.fd'}",
            "-drive", f"if=pflash,format=raw,file={run / 'OVMF_VARS.fd'}"]


def extra_disk_args(run: Path, m: dict, ro: str) -> list[str]:
    """Linux enumerates every device on the root bus before any device
    behind a root port, and root ports in slot order. The target sits behind
    the port at slot 6, so a "before" disk goes on the root bus itself and an
    "after" disk behind its own port at a later slot."""
    args = []
    for i, d in enumerate(m.get("extra_disks", [])):
        drive = f"file={run / d['file']},if=none,id=x{i},format=qcow2{ro}"
        if d["slot"] == "before":
            args += ["-drive", drive, "-device",
                     f"virtio-blk-pci,drive=x{i},serial={d['serial']},bus=pcie.0,addr={0x4 + i:#x}"]
        else:
            port = f"rpx{i}"
            args += ["-device", f"pcie-root-port,id={port},bus=pcie.0,addr={0x10 + i:#x},chassis={16 + i}",
                     "-drive", drive, "-device", f"virtio-blk-pci,drive=x{i},serial={d['serial']},bus={port}"]
    return args


def add_disk(run: Path, slot: str, gib: int, serial: str | None = None) -> dict:
    """Attach another disk (takes effect at the next start)."""
    m = json.loads((run / "machine.json").read_text())
    serial = serial or "AW-" + uuid.uuid4().hex[:12].upper()
    name = f"extra-{len(m.get('extra_disks', []))}.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(run / name), f"{gib}G"], check=True)
    m.setdefault("extra_disks", []).append({"file": name, "serial": serial, "gib": gib, "slot": slot})
    (run / "machine.json").write_text(json.dumps(m, indent=2))
    return m


def replace_target(run: Path) -> dict:
    """Swap the target for a blank disk of the same capacity and a new
    serial -- a replaced drive, as a datacenter would do it."""
    m = json.loads((run / "machine.json").read_text())
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(run / "replacement.qcow2"),
                    f"{m['disk_gib']}G"], check=True)
    m["disk_file"], m["serial"] = "replacement.qcow2", "AW-" + uuid.uuid4().hex[:12].upper()
    (run / "machine.json").write_text(json.dumps(m, indent=2))
    return m


def hot_replace_target(run: Path) -> dict:
    """Unplug the running machine's target drive and plug in a blank one of
    the same capacity with a new serial (the machine keeps running)."""
    m = json.loads((run / "machine.json").read_text())
    serial = "AW-" + uuid.uuid4().hex[:12].upper()
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(run / "hotswap.qcow2"),
                    f"{m['disk_gib']}G"], check=True)
    monitor(run, "device_del target")
    time.sleep(3)
    monitor(run, f"drive_add 0 if=none,id=hs0,file={run / 'hotswap.qcow2'},format=qcow2")
    monitor(run, f"device_add virtio-blk-pci,drive=hs0,id=target2,serial={serial},bus=rp6")
    time.sleep(3)
    return {"old_serial": m["serial"], "new_serial": serial}


def start(run: Path, readonly: bool) -> None:
    stop(run)
    subprocess.run(qemu_argv(run, readonly), check=True)
    (run / "mode").write_text("readonly" if readonly else "writable")


def monitor(run: Path, command: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(json.loads((run / "machine.json").read_text())["monitor"])
        s.recv(4096)
        s.sendall(command.encode() + b"\n")
        time.sleep(0.5)


def stop(run: Path, graceful_timeout: float = 90) -> None:
    """ACPI power-down first, so the guest's filesystems are clean (a
    read-only planning boot cannot replay a dirty ext4 journal); kill
    only if the guest ignores it."""
    pidfile = run / "qemu.pid"
    if not pidfile.exists():
        return
    try:
        pid = int(pidfile.read_text().strip())
        try:
            monitor(run, "system_powerdown")
            deadline = time.monotonic() + graceful_timeout
            while time.monotonic() < deadline:
                os.kill(pid, 0)
                time.sleep(1)
        except (OSError, socket.timeout):
            pass
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            os.kill(pid, 0)
            time.sleep(0.2)
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, ValueError):
        pass
    pidfile.unlink(missing_ok=True)


def destroy(run: Path) -> None:
    stop(run)
    try:
        sock = Path(json.loads((run / "machine.json").read_text())["monitor"])
        shutil.rmtree(sock.parent, ignore_errors=True)
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        pass
    shutil.rmtree(run, ignore_errors=True)


def ssh_argv(run: Path, user: str = "root") -> list[str]:
    m = json.loads((run / "machine.json").read_text())
    host_pub = (run / "keys" / "host_ed25519.pub").read_text().split()
    kh = run / "known_hosts"
    kh.write_text(f"[127.0.0.1]:{m['port']} {host_pub[0]} {host_pub[1]}\n")
    return ["ssh", "-F", "/dev/null", "-o", f"UserKnownHostsFile={kh}", "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            "-i", str(run / "keys" / "operator_ed25519"), "-p", str(m["port"]), f"{user}@127.0.0.1"]


def wait_ssh(run: Path, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if subprocess.run(ssh_argv(run) + ["true"], capture_output=True).returncode == 0:
            return
        time.sleep(3)
    raise SystemExit(f"{run}: SSH with the injected host key did not come up in {timeout}s")


def write_enrollment(run: Path, readonly: bool) -> Path:
    m = json.loads((run / "machine.json").read_text())
    host_pub = " ".join((run / "keys" / "host_ed25519.pub").read_text().split()[:2])
    expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    sectors = m["disk_gib"] * 1024 * 1024 * 1024 // 512
    on_extra = m.get("target", "boot") != "boot"
    target_extra = int(m["target"].split("-")[1]) if on_extra else -1
    extra = "".join(f'\n[[disks]]\nserial = "{d["serial"]}"\nsize_sectors = {d["gib"] * 2097152}\n'
                    f'role = "{"target" if i == target_extra else "keep"}"\n'
                    for i, d in enumerate(m.get("extra_disks", [])))
    text = f'''schema = "reproos-anywhere-enrollment/1"
name = "{m['distro']}-{m['serial'][-6:].lower()}"
expires = "{expires}"

[ssh]
address = "127.0.0.1"
port = {m['port']}
user = "root"
privilege = "root"
host_key = "{host_pub}"
identity_file = "keys/operator_ed25519"

[machine]
product_uuid = "{m['uuid']}"

[[disks]]
serial = "{m['serial']}"
size_sectors = {sectors}
role = "{'keep' if on_extra else 'target'}"

{extra}
[network]
mac = "{m['mac']}"

[rescue]
kind = "qemu-serial"
console_log = "console.log"
monitor = "{m['monitor']}"
boot_command = ["{sys.executable}", "{Path(__file__).resolve()}", "rescue-boot", "{run}"]
restore_command = ["{sys.executable}", "{Path(__file__).resolve()}", "normal-boot", "{run}"]
'''
    if readonly:
        kind = PLANNING_KINDS[planning_kind(m)][0]
        text += f'\n[readonly]\nkind = "{kind}"\nissued_by = "anywhere-test-supervisor"\n'
    path = run / ("enrollment-readonly.toml" if readonly else "enrollment.toml")
    path.write_text(text)
    return path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("image").add_argument("distro", choices=sorted(DISTROS))
    c = sub.add_parser("create")
    c.add_argument("distro", choices=sorted(DISTROS))
    c.add_argument("dir")
    c.add_argument("--port", type=int)
    c.add_argument("--controller", default="virtio-blk", choices=sorted(CONTROLLERS))
    s = sub.add_parser("start")
    s.add_argument("dir")
    s.add_argument("--readonly", action="store_true")
    for name in ("stop", "destroy", "ssh", "normal-boot"):
        sub.add_parser(name).add_argument("dir")
    rb = sub.add_parser("rescue-boot")
    for a in ("dir", "kernel", "initrd", "cmdline"):
        rb.add_argument(a)
    args = p.parse_args()
    if args.cmd == "image":
        print(fetch_image(args.distro))
    elif args.cmd == "create":
        print(json.dumps(create(args.distro, Path(args.dir).resolve(), args.port,
                                controller=args.controller), indent=2))
    elif args.cmd == "start":
        run = Path(args.dir).resolve()
        start(run, args.readonly)
        wait_ssh(run, 240)
        print(write_enrollment(run, args.readonly))
    elif args.cmd == "stop":
        stop(Path(args.dir).resolve())
    elif args.cmd == "destroy":
        destroy(Path(args.dir).resolve())
    elif args.cmd == "rescue-boot":
        rescue_boot(Path(args.dir).resolve(), args.kernel, args.initrd, args.cmdline)
    elif args.cmd == "normal-boot":
        normal_boot(Path(args.dir).resolve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
