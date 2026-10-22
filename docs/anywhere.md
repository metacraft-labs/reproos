# ReproOS Anywhere

`tools/anywhere/reproos-anywhere` converts an existing Linux machine into
ReproOS over SSH: it inventories the machine without writing to it, plans
the conversion as a signed record, takes the machine over into a
RAM-resident installer, writes the canonical ReproOS storage layout and
root, reboots, and proves over SSH that the **installed** system — not the
old one, not the installer — answers.

The safety rules it implements are the accepted Anywhere M0 contract,
`spec/ReproOS-Anywhere-Safety-Contract.md` in the (private)
`reprobuild-pm` repository. The planning status, the evidence behind every
claim below and the open gaps are in that repository's
`milestones/ReproOS-Anywhere.milestones.org`.

**Requirements on the operator's machine:** `python3` (3.11 or later),
OpenSSH (`ssh`, `ssh-keygen`) and `cpio`; the release artifacts (payload,
installer, `kexec`, layout tool); and, per machine, the enrollment its
management plane wrote and a machine configuration.

> **No conversion is qualified yet.** The payload a conversion installs
> must be the source-built ReproOS root (Campaign Completion M13), which
> does not exist. Every test conversion today installs the labelled
> FIXTURE payload from `tests/anywhere/fixture/` and every report, plan and
> receipt says `conversion_qualified: false`. Never point this tool at a
> machine you are not prepared to lose.

## The commands

### The short form

For one enrolled machine and one machine configuration:

```console
# 1. management plane: boot the machine into its read-only planning environment
reproos-anywhere convert root@203.0.113.7:22 web-1 $ARTIFACTS        # preflight + plan; prints the plan
# 2. read the plan; management plane: boot the machine normally
reproos-anywhere convert root@203.0.113.7:22 web-1 $ARTIFACTS --acknowledge <plan-id>   # apply it
```

`$ARTIFACTS` stands for `--payload DIR --installer DIR --kexec FILE
--layout-tool FILE`, the release artifacts; give them to **every** command
that plans or runs a conversion, the second `convert` included, because the
plan binds their digests and apply refuses different ones. `--state DIR`
(default `./anywhere-state`) holds the controller's state, one directory per
machine; use the same one throughout.

`web-1` selects `machines/web-1.toml` (`--machines DIR`, default
`./machines`; a path to a `.toml` file also works). The destination selects
the one enrollment in `--enrollments DIR` (default `./enrollments`) whose
`[ssh]` address, port and user match it, and is refused if none or more
than one does. It is never a trust anchor: the host key, the disks and the
rescue route still come from that enrollment.

The first command needs the machine in its read-only planning environment
(see Preflight). It ends by printing the plan: the target disk by serial
and device, the hostname and user the installed system will have, the
takeover method, when the plan expires, where the full plan is
(`STATE/<name>/plan/plan.json`), and the identity to acknowledge. Nothing
destructive has happened. Check the disk serial against what you expect
to lose, then boot the machine normally through its management plane.

The second command applies the plan. It is refused, before anything is
written, if the management plane still has the target disk attached
read-only or as a throwaway snapshot (a conversion applied there would not
survive the next power cycle), or if the plan on record was not made with
the same machine configuration. If the plan was already started it resumes
it; if it already completed, it says so and prints the result recorded
then without touching the machine. It finishes by naming the follow-up
commands.

A plan expires 6 hours after it is made (sooner if the enrollment expires
first). An expired plan cannot be applied: run the first command again for
a new one. A plan that was already started can still be resumed after it
expires.

`--takeover auto|kexec|rescue-media` (first command only; `auto` prefers
kexec) chooses how the installer is started. `--max-rate`,
`--evidence-sink` and `--events FILE` (second command) are described under
Apply.

### The long form, one step at a time

`<name>` is the `name` in the machine's enrollment (in the short form it is
printed as "plan for <name>"); it is NOT the machine configuration's name.

```console
reproos-anywhere preflight --enrollment enrollments/<name>.toml --config machines/web-1.toml
reproos-anywhere plan      --name <name> --config machines/web-1.toml [--takeover auto|kexec|rescue-media]
reproos-anywhere apply     --name <name> --acknowledge <plan-id> [--events FILE]
reproos-anywhere resume    --name <name> --acknowledge <plan-id> [--reformat] [--clear-detection]
reproos-anywhere status    --name <name>
reproos-anywhere logs      --name <name> [--lines N]  # journal + rescue console tail
reproos-anywhere ssh       --name <name> [COMMAND]    # the INSTALLED system, pinned key
reproos-anywhere abort     --name <name>              # roll back; only before destroy
reproos-anywhere recover   --name <name> --acknowledge <plan-id> [--rematerialize]
reproos-anywhere bundle    --name <name> --output FILE.tar.gz
reproos-anywhere contain   --name <name> --evidence DIR  # compromise: freeze, capture memory, power off, revoke
reproos-anywhere investigate --name <name>            # read-only report from the evidence
reproos-anywhere replan    --name <name>              # after containment: new plan, fresh keys, rescue-media
```

`preflight` and `plan` take the same artifacts and `--state` as above.
`convert`, `preflight`, `plan`, `apply`, `resume`, `recover`, `status`,
`logs`, `ssh`, `abort` and `bundle` are also Reprobuild run tasks; run them
from a ReproOS checkout, with the tool's arguments after `--`:

```console
repro run anywhere-convert -- root@203.0.113.7:22 web-1 --state /srv/anywhere $ARTIFACTS
```

`contain`, `investigate` and `replan` are not registered as run tasks;
run them from `tools/anywhere/reproos-anywhere`.

Exit status: 0 success, 2 refused (nothing changed), 3 blocked
compatibility report, 1 failure, 64 a usage error.

### Enrollment: what you know without asking the machine

The enrollment (TOML, schema `reproos-anywhere-enrollment/1`) is written by
whoever controls the machine's management plane — the provider, the
datacenter operator, or `tests/anywhere/supervisor.py` for test VMs. It
names the exact SSH host key (no trust on first use), the DMI product UUID,
every disk by serial and size with exactly one `role = "target"`, the
management interface's MAC, the rescue route (serial console and
monitor; `boot_command`/`restore_command` for rescue-media boot, which are
optional for a conversion but required to restore a machine after
compromise or to `recover`) and an expiry. A machine whose answers disagree with its enrollment
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
completion after its postcondition is verified
(`STATE/<name>/journal.jsonl`, a SHA-256 hash chain). A refused stage is
closed with a record whose event is `abort` (this is not the `abort`
command). After takeover each record is also mirrored to the installer
and, while the target is mounted, to
`/var/log/reproos-anywhere/journal.jsonl` on the installed disk; that
mirror therefore holds only the records written between mount and reboot,
is best-effort and is never authoritative.

`--events FILE` appends one JSON line per journal record and, at the end, a
verdict (`installed`, `refused` or `failed`) carrying the plan identity and
the paths of the journal, the plan and the rescue console, for automation
that watches a conversion.

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

Deciding what to do after a detection halt: read the alert (`logs`, and
`investigate`, which reads only the controller's state and changes
nothing). If it is explained by something you did, resume with
`--clear-detection`. If it is not explained, treat it as compromise: run
`contain` (below), not `resume`.

Evidence: `--evidence-sink SOCKET` sends every journal record, alert and
heartbeat to `tools/anywhere/reproos-anywhere-sink serve`, an append-only
sink that refuses (and records) read, list and delete, refuses a record
that does not continue its own copy of the chain, and raises
`heartbeat-lost` when an apply stops without closing its stream.
`reproos-anywhere-sink audit` compares a controller's local journal with
the sink's copy; the sink is the authority:

```console
tools/anywhere/reproos-anywhere-sink serve --dir SINK_DIR --socket /run/anywhere-sink.sock [--heartbeat-window 30]
tools/anywhere/reproos-anywhere-sink audit --dir SINK_DIR --journal STATE/<name>/journal.jsonl --plan <plan-id>
```

The sink listens on a local UNIX socket. Run it under its own account,
ideally on its own host with the socket forwarded to the controller
(`ssh -L /path/local.sock:/run/anywhere-sink.sock sinkhost`): the tests
prove the protocol boundary, not account separation.

### Recovery

Which command depends on how far the journal got (`status` shows it):

| Situation | Command | What it does |
|---|---|---|
| Before `destroy` has **started** | `abort` | Rolls back to the source system. Kexec path: power-cycles the machine out of the RAM-resident installer, which boots the source from its untouched disk, and removes the staging directory from `/dev/shm`. Rescue-media path: leaves rescue mode. Then it waits for the source to answer on its **enrolled** host key and refuses if a ReproOS system answers instead. |
| After `destroy` started, before the reboot; the controller or the link died | `resume` | Continues from the journal: an open stage is reconciled (identity re-proved, detached storage operations re-attached, the transfer resumed from the verified bytes) and the rest run. |
| A stage failed after `destroy` and the half-written install should be redone | `resume --reformat` | Formats the target again (operator-confirmed; the source is already gone) and reruns every stage from format on. |
| The installed system did not pass the proof after the reboot | `recover` | Boots the installer through the rescue plane under a new session, repairs the installed root (bootloader, identity) and runs the installed-only proof again. Never re-creates storage. Needs a rescue route that can boot media. |
| The installed root itself is damaged, or the payload never finished unpacking | `recover --rematerialize` | As `recover`, but unpacks the payload again over the installed root first. Data written on the installed system since is overwritten. |

`abort` is refused once `destroy` has started: from then on the source's
storage may already be gone. `bundle --output FILE.tar.gz` writes what
someone else needs to investigate a failure (plan, journal, reports,
inventory, enrollment, detection state, the last 32 MiB of the rescue
console) and no key; attach it to an issue.

### What counts as success

The installed system must answer on the pinned **installed** host key,
with the planned machine-id and configuration generation in
`/var/lib/reproos/identity.json`, root on the planned serial, a boot id
that is neither the source's nor the installer's, `systemctl
is-system-running` = `running`, a default route, and ReproOS's own
`reproos-installed-boot-evidence` accepting the receipt
(`source=anywhere`). The old system and the installer cannot produce those
answers: they hold different host keys.

Reaching the installed system: `ssh --name <name>` logs in as the user the
machine configuration names (root login is disabled), with the access key
`STATE/<name>/keys/access_ed25519` and the installed host key from the plan
(`identities.installed_host_key` in `plan.json`). Plain `ssh` works with
the same two. ReproOS's own check is `/usr/local/sbin/reproos-installed-boot-evidence`
(not on the user's `PATH`). The fixture payload has no `sudo`, so on a
fixture conversion there is no route to root on the installed system; the
final verification does not check one.

### Compromise

The sequence, for a detection that looks like compromise:

1. `contain --name <name> --evidence DIR`. It does not ask for
   confirmation. The rescue plane freezes the machine, its memory is
   captured into `DIR`, it is powered off, and the plan and every
   credential it issued (session, installed host and access keys) are
   revoked. After this, `resume` and `apply` of that plan are refused.
2. `investigate --name <name>`: a read-only report built from the
   controller's state directory alone (journal, detections, completed
   stages, whether storage was destroyed); it sends nothing to the machine.
   Keep `DIR` and a `bundle` with it.
3. `replan --name <name>`: a new signed plan for the same target and
   payload with fresh credentials and rescue-media takeover (the source
   system no longer exists), linked to the revoked plan. It needs an
   enrollment whose rescue route can boot media (`boot_command` and
   `restore_command`); without one it is refused, and the machine has to be
   restored through the provider's console.
4. `apply --name <name> --acknowledge <new-plan-id>`: restores the machine
   under a new installed host key. The controller pins only the new key, so
   anything still presenting the revoked one is refused.

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

`tests/anywhere/run-vm-gates.sh <gate>` (e2e, controllers, convert, diskid, negatives, resume,
detection, confinement, recovery, refusals, drill) builds the
fixtures and runs one gate; the same gates are registered as `repro build`
targets and in the `test` collection.

The VM tests run unprivileged QEMU/KVM guests (2 vCPU, 2 GiB, 12 GiB disk
each) with user-mode networking and loopback-only SSH, created from the
digest-pinned images in `tests/anywhere/distros.json`, and delete them when
done. The refusal gate also boots one emulated arm64 Debian (TCG, slow) to
show an aarch64 source is refused. They need KVM, `qemu-system-x86_64`,
`qemu-system-aarch64`, `qemu-img`, OVMF
(`ANYWHERE_OVMF_DIR`), OpenSSH, `xorriso`, `cpio` and Nix for the fixtures.
