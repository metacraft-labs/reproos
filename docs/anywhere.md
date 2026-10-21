# ReproOS Anywhere

`tools/anywhere/reproos-anywhere` converts an existing Linux machine into
ReproOS over SSH: it inventories the machine without writing to it, plans
the conversion as a signed record, takes the machine over into a
RAM-resident installer, writes the canonical ReproOS storage layout and
root, reboots, and proves over SSH that the **installed** system — not the
old one, not the installer — answers.

The safety rules it implements are the accepted Anywhere M0 contract
(`reprobuild-pm/spec/ReproOS-Anywhere-Safety-Contract.md`). The planning
status, the evidence behind every claim below and the open gaps are in
`reprobuild-pm/milestones/ReproOS-Anywhere.milestones.org`.

> **No conversion is qualified yet.** The payload a conversion installs
> must be the source-built ReproOS root (Campaign Completion M13), which
> does not exist. Every test conversion today installs the labelled
> FIXTURE payload from `tests/anywhere/fixture/` and every report, plan and
> receipt says `conversion_qualified: false`. Never point this tool at a
> machine you are not prepared to lose.

## The commands

```console
reproos-anywhere preflight --enrollment machine.toml --config auto-config.toml
reproos-anywhere plan      --name <machine> --config auto-config.toml [--takeover auto|kexec|rescue-media]
reproos-anywhere apply     --name <machine> --acknowledge <plan-id>
reproos-anywhere resume    --name <machine> --acknowledge <plan-id>
reproos-anywhere status    --name <machine>
reproos-anywhere logs      --name <machine>             # journal + rescue console tail
reproos-anywhere ssh       --name <machine> [COMMAND]   # the INSTALLED system, pinned key
reproos-anywhere abort     --name <machine>             # roll back; only before destroy
reproos-anywhere recover   --name <machine> --acknowledge <plan-id> [--rematerialize]
reproos-anywhere bundle    --name <machine> --output FILE.tar.gz
reproos-anywhere contain   --name <machine> --evidence DIR  # compromise: freeze, capture memory, power off, revoke
reproos-anywhere investigate --name <machine>           # read-only report from the evidence
reproos-anywhere replan    --name <machine>             # after containment: new plan, fresh keys, rescue-media
```

Each is also `repro run anywhere-<command> -- ...`.

Common options: `--state DIR` (controller state, one directory per
machine), `--payload DIR`, `--installer DIR`, `--kexec FILE`,
`--layout-tool FILE`. Exit status: 0 success, 2 refused (nothing changed),
3 blocked compatibility report, 1 failure.

### Enrollment: what you know without asking the machine

The enrollment (TOML, schema `reproos-anywhere-enrollment/1`) is written by
whoever controls the machine's management plane — the provider, the
datacenter operator, or `tests/anywhere/supervisor.py` for test VMs. It
names the exact SSH host key (no trust on first use), the DMI product UUID,
every disk by serial and size with exactly one `role = "target"`, the
management interface's MAC, the rescue route (serial console and
monitor; optionally `boot_command`/`restore_command` for rescue-media
boot) and an expiry. A machine whose answers disagree with its enrollment
is refused.

### Preflight

Strict preflight requires `[readonly]` in the enrollment: an environment,
enforced *below* the machine, in which planning cannot write its disk
(`qemu-drive-readonly`, or `qemu-snapshot` where the distribution cannot
boot from a read-only device). Without one, an SSH login itself writes
logs and access times, so preflight refuses; `--inspection` collects the
same report for diagnosis, marks it inspection-only and makes it
unplannable.

The probe (`tools/anywhere/probe.sh`) is streamed over the pinned SSH
channel and never copied to the machine. Its output is treated as hostile
input: bounded, fixed vocabulary, duplicates rejected. Every compatibility
predicate is a closed set (`tools/anywhere/reproos_anywhere/compat.py`): an
unsupported distribution, BIOS firmware, Secure Boot, LVM/RAID/LUKS on the
target, a wireless, bridged or static management network, too little RAM
or disk, or no takeover path all block the report.

### Plan and acknowledgement

`plan` binds the enrollment, inventory, compatibility report,
configuration generation, payload and installer digests, the target disk
by serial/size/PCI path, the exact storage-plan bytes (rendered by
`repro/disk_layouts.nim`, the same renderer the image build and the
installer use), the takeover method, and the SSH identities, and signs
the canonical bytes with the controller key. `apply` runs only with that
identity typed back. Immediately before the first write it takes a fresh
inventory and refuses on any drift.

### Apply

| Stage | What happens | Resume |
|---|---|---|
| stage-payload | kexec path: takeover kernel/initrd and a static `kexec` into source RAM (`/dev/shm`); rescue-media path: nothing on the source | idempotent |
| takeover | kexec, or rescue-media boot through the management plane; the installer generates its own SSH key and announces it with the session nonce on the serial console, where the controller reads and pins it | reconciled from the console |
| destroy | in the installer: re-prove the disk (PCI path + serial + size), then erase every signature | reconciled, identity re-proved first |
| format | canonical partition table and filesystems via Reprobuild's disko port | never re-formats a present layout |
| mount | the layout under `/mnt` | idempotent |
| materialize | payload streamed, SHA-256 checked, unpacked | resumes from the verified bytes |
| inject-secrets | machine-id, enrollment, the controller-generated installed host key | rewrite is idempotent |
| bootloader | install receipt, then Reprobuild's `repro infra install-root` driver (fstab, grub-install, grub.cfg) | bounded rerun |
| reboot | unmount, reboot (kexec path) or leave rescue mode (rescue-media) | reconciled |
| final-verification | the installed-only proof below | read-only |
| retire-rescue | releases temporary rescue resources; the permanent route stays | no-op |

Every stage's start is journaled durably before it runs and its
completion after its postcondition is verified (`journal.jsonl`, a
SHA-256 hash chain). A refused stage is closed with an abort record. After
takeover each record is also mirrored to the installer and, once the
target is mounted, to `/var/log/reproos-anywhere/journal.jsonl` on the
installed disk; the mirror is best-effort and never authoritative.

The irreversible storage operations (destroy, format, install-root) run
detached from the SSH session in the installer, keyed by the plan and
their exact arguments. A dropped connection or a killed controller does
not interrupt them, and `resume` re-attaches to the same operation instead
of running it twice. `--max-rate BYTES_PER_SECOND` bounds the payload
transfer; an interrupted transfer resumes from the bytes already on the
target and is verified by digest before it is unpacked.

### The takeover environment's boundary

The controller reaches the installer only with a **per-plan session key**
carried in the session archive, and that key is restricted
(`restrict,command=`) to the installer gate,
`tools/anywhere/installer-gate.sh`: a fixed vocabulary of requests
(`identity`, `put PATH MODE`, `sha256 PATH`, `op-start ID destroy ...`,
`unpack`, ...) whose every argument is checked against a closed alphabet
and a path allowlist (the work area and the mounted target). Anything else
is refused with exit 126 and a `REPROOS_ANYWHERE_GATE:REFUSED` line on the
console. The installer also mounts its executable closure (`/nix/store`)
read-only and drops every connection it did not receive except DHCP
(`tests/anywhere/fixture/egress.nft`). It reports the controls it runs
with, and takeover refuses an installer whose controls differ from its
manifest.

Detection: the installer's kernel audits every `execve` and every
write-open of a disk device, prints the records to the console (the
rescue plane) and locks the rules (`auditctl -e 2`). Before and after each
stage the controller places a barrier (a uniquely tagged exec whose own
record must reach the console) and attributes everything up to it: an
execution from outside the closure verified at takeover, a disk write
outside destroy/format/mount/bootloader, or an audit configuration change
halts the apply. `resume` then refuses until `--clear-detection`.

Evidence: `--evidence-sink SOCKET` sends every journal record, alert and
heartbeat to `tools/anywhere/reproos-anywhere-sink serve`, an append-only
sink that refuses (and records) read, list and delete, refuses a record
that does not continue its own copy of the chain, and raises
`heartbeat-lost` when an apply stops without closing its stream.
`reproos-anywhere-sink audit` compares a controller's local journal with
the sink's copy; the sink is the authority. Run the sink under its own
account on its own host: the tests prove the protocol boundary, not
account separation.

### What counts as success

The installed system must answer on the pinned **installed** host key,
with the planned machine-id and configuration generation in
`/var/lib/reproos/identity.json`, root on the planned serial, a boot id
that is neither the source's nor the installer's, `systemctl
is-system-running` = `running`, a default route, and ReproOS's own
`reproos-installed-boot-evidence` accepting the receipt
(`source=anywhere`). The old system and the installer cannot produce those
answers: they hold different host keys.

### Compromise

`contain` is the response to a detection that looks like compromise: the
rescue plane freezes the machine, its memory is captured into the evidence
directory, it is powered off, and the plan and every credential it issued
(session, installed host and access keys) are revoked. `investigate`
reports from the controller's evidence alone. `replan` then issues a new
signed plan for the same target and payload with fresh credentials and
rescue-media takeover (the source system no longer exists); applying it
restores the machine under a new installed identity, and the revoked one
is refused.

### Supported systems

[anywhere-compatibility.md](anywhere-compatibility.md) is generated from
gate evidence by `tests/anywhere/compat_matrix.py`; a combination is
listed only if a gate converted it.

## Tests

```console
tests/anywhere/build-fixtures.sh DIR                  # fixture installer, payload, kexec, layout tool
python3 tests/anywhere/test_anywhere_unit.py           # no VM
python3 tests/anywhere/e2e_convert.py --artifacts DIR debian ubuntu fedora arch alpine nixos
python3 tests/anywhere/test_disk_identity_mismatch.py --artifacts DIR
python3 tests/anywhere/test_negatives.py --artifacts DIR
python3 tests/anywhere/test_resume.py --artifacts DIR
python3 tests/anywhere/test_detection.py --artifacts DIR
python3 tests/anywhere/test_confinement.py --artifacts DIR
python3 tests/anywhere/test_recovery.py --artifacts DIR
python3 tests/anywhere/test_preflight_refusals.py --artifacts DIR
python3 tests/anywhere/test_compromise_drill.py --artifacts DIR
python3 tests/anywhere/e2e_convert.py --artifacts DIR --controller nvme debian
```

`tests/anywhere/run-vm-gates.sh <gate>` (e2e, controllers, diskid, negatives, resume, detection,
confinement, recovery, refusals, drill) builds the
fixtures and runs one gate; the same gates are registered as `repro build`
targets and in the `test` collection.

The VM tests run unprivileged QEMU/KVM guests (2 vCPU, 2 GiB, 12 GiB disk
each) with user-mode networking and loopback-only SSH, created from the
digest-pinned images in `tests/anywhere/distros.json`, and delete them when
done. They need KVM, `qemu-system-x86_64`, `qemu-img`, OVMF
(`ANYWHERE_OVMF_DIR`), OpenSSH, `xorriso`, `cpio` and Nix for the fixtures.
