#!/usr/bin/env bash
# configure-installed-root.sh -- turn a mirrored root tree into the
# INSTALLED root: the configuration bundle, the accounts, the network
# and SSH services, the graphical session, and the post-boot health
# gate.
#
# WHY THIS IS ITS OWN SCRIPT, AND WHY THAT IS A CORRECTNESS PROPERTY
# RATHER THAN TIDINESS.
#
# On the ordinary writable-root layout these phases can run against a
# mounted filesystem, because nothing has made a claim about that
# filesystem's bytes yet.
#
# On the integrity-checked layout they cannot. There the root is a
# finished image: `build-verity-root.sh` makes a read-only ext4 image
# of the root tree and the dm-verity Merkle tree over it, and the ROOT
# HASH of that pair is baked into a unified kernel image that firmware
# measures. From that moment the bytes of the root are named by the
# measurement, and any later write to them -- any write at all -- makes
# the installed root disagree with the hash inside its own measured
# command line. The disagreement is silent at build time and fatal at
# first boot.
#
# It is worse than "do not write much". A read-WRITE mount that writes
# nothing of its own already breaks the pair, because ext4 updates the
# superblock's mount state on mount. So there is no version of these
# phases that can safely run after the hash is taken, and the only fix
# is the order: configure the tree FIRST, then make the image of it.
#
# Hence one script with two callers:
#
#   * scripts/stage-installed-root.sh runs it on a plain directory,
#     BEFORE the root image and its hash exist. That directory is what
#     `build-verity-root.sh` then takes the hash over.
#   * scripts/build-reproos-image.sh runs it on the mounted root of the
#     writable-root layout, which has no hash to invalidate.
#
# One implementation, so the two layouts cannot drift into two
# different ideas of what an installed ReproOS is.
#
# Usage:
#   configure-installed-root.sh <root-tree>
#
# Required environment:
#   REPROOS_CONFIG_BUNDLE_DIR   the canonical artifact bundle
#                               `reproos-installer --emit-artifacts`
#                               wrote (auto-config.toml, system.nim,
#                               hardware.nim, disko.json, home.nim)
#   REPROOS_WORK_DIR            a scratch directory the caller owns
#   REPROOS_SOURCE_RECIPES_ROOT the HOST path of the from-source package
#                               install mirrors
#
# Optional environment:
#   REPROOS_TARGET_SOURCE_RECIPES_ROOT  where those mirrors are visible
#                               inside the guest (default
#                               /opt/repro/reprobuild-packages/packages/source)
#   REPROOS_PATCHELF_BIN        patchelf, for the libseat interpreter
#                               checks; the phase degrades to a report
#                               without it
#   SUDO                        how to escalate. Defaults to
#                               /usr/bin/env -- i.e. NO escalation --
#                               because a plain directory the build user
#                               owns needs none, and the caller that
#                               does need it (a mounted root) passes its
#                               own resolved sudo path. Ownership is not
#                               decided here in either case:
#                               tools/reproos_image_metadata.py owns the
#                               guest inode policy and normalises the
#                               whole tree afterwards.
#
# Exit codes (the caller's own table has to leave these free):
#   64 = bad invocation
#   66 = the validated config does not describe a buildable image
#   71 = config emit failed
#   72 = dbus wiring failed
#   73 = sddm theme install failed
#   74 = sddm path shims / instrumentation failed
#   75 = seatd install failed
#   76 = post-boot health gate install failed

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <root-tree>" >&2
  exit 64
fi
ROOT_TREE="$1"
if [ ! -d "$ROOT_TREE" ]; then
  echo "[configure-installed-root] not a directory: $ROOT_TREE" >&2
  exit 64
fi

SCRIPT_DIR_SELF="$(cd "$(dirname "$0")" && pwd)"

: "${REPROOS_CONFIG_BUNDLE_DIR:?REPROOS_CONFIG_BUNDLE_DIR must name the bundle the installer emitted}"
: "${REPROOS_WORK_DIR:?REPROOS_WORK_DIR must name a scratch directory}"
: "${REPROOS_SOURCE_RECIPES_ROOT:?REPROOS_SOURCE_RECIPES_ROOT must name the host from-source package root}"

CONFIG_BUNDLE_DIR="$REPROOS_CONFIG_BUNDLE_DIR"
WORK="$REPROOS_WORK_DIR"
SOURCE_RECIPES_ROOT="$REPROOS_SOURCE_RECIPES_ROOT"
TARGET_SOURCE_RECIPES_ROOT="${REPROOS_TARGET_SOURCE_RECIPES_ROOT:-/opt/repro/reprobuild-packages/packages/source}"
PATCHELF_BIN="${REPROOS_PATCHELF_BIN:-$(command -v patchelf 2>/dev/null || true)}"
mkdir -p "$WORK"

# `env` rather than the empty string: every phase below spells the
# escalation as `"$SUDO" <command>`, so an unset value has to be a
# command that runs its arguments unchanged rather than nothing.
SUDO="${SUDO:-/usr/bin/env}"

# shellcheck source=recipes/reproos-image/scripts/image-config.sh
. "$SCRIPT_DIR_SELF/image-config.sh"
reproos_load_image_config "$CONFIG_BUNDLE_DIR/auto-config.toml" || exit 66

echo "[configure-installed-root] root tree: $ROOT_TREE"
echo "[configure-installed-root] hostname=$HOSTNAME_VAL user=$USER_NAME de=$DE_DEFAULT"

# ---------------------------------------------------------------
# Phase 9: write etc/repro/{system,hardware}.nim from TOML.
# The validated installer emitter is the single renderer for both
# interactive and unattended paths. Copy the complete replay bundle
# into the installed root after install-root has mirrored the stage.
# ---------------------------------------------------------------
echo "[configure-installed-root] Phase 9: install canonical configuration bundle"
"$SUDO" mkdir -p "$ROOT_TREE/etc/repro"
for artifact in auto-config.toml system.nim hardware.nim disko.json home.nim; do
  if [ ! -s "$CONFIG_BUNDLE_DIR/$artifact" ]; then
    echo "[configure-installed-root] missing generated artifact: $artifact" >&2
    exit 71
  fi
  "$SUDO" cp "$CONFIG_BUNDLE_DIR/$artifact" "$ROOT_TREE/etc/repro/$artifact"
  "$SUDO" chmod 0644 "$ROOT_TREE/etc/repro/$artifact"
done
CONFIGURATION_SHA256="$(sha256sum "$CFG" | awk '{print $1}')"
printf '%s\n' "$CONFIGURATION_SHA256" > "$WORK/configuration-generation"
"$SUDO" install -m 0644 "$WORK/configuration-generation" \
  "$ROOT_TREE/etc/repro/generation"

# ---------------------------------------------------------------
# Phase 10: write /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow
# user entries + create home directory.
#
# M9.R.56.3 — the M9.R.50 emit only wrote /etc/shadow, so at first
# boot the account had a hashed password on file but no /etc/passwd
# entry (no uid, no home, no shell), and no /etc/group membership.
# ``login: repro`` then failed with ``no such user`` and the system
# fell back to the emergency shell (which prompts for root password
# — root has ``*`` in shadow so no login possible).  We now emit
# all four files.  The uid/gid are pinned to 1000/1000 (first
# non-system id per LSB); the primary group matches ``$USER_NAME``;
# secondary groups come from the TOML ``[user] groups`` array (falls
# back to wheel+audio+video, matching M9.R.50 fixture defaults).
# ---------------------------------------------------------------

echo "[configure-installed-root] Phase 10: emit passwd + shadow + group + gshadow + home for $USER_NAME (uid=$USER_UID gid=$USER_GID groups='$USER_GROUPS_SPACED')"

"$SUDO" bash -c "
  set -euo pipefail

  # --- /etc/shadow --- (root + user entries).  Preserve any prior
  # rows (e.g. from the stage-de-rootfs Debian base + ``live`` user).
  # M9.R.56.6: also remove any row whose uid collides with the
  # target uid; the stage-de-rootfs baseline ships a ``live`` user
  # at uid=1000 which collides with the auto-config ``repro`` user
  # at uid=1000 --- with both entries present nss lookups for uid
  # 1000 resolve non-deterministically (typically to ``live``) and
  # SDDM's autologin=User=repro fails to find a match.
  if [ ! -f '$ROOT_TREE/etc/shadow' ]; then
    echo 'root:*:19000:0:99999:7:::' > '$ROOT_TREE/etc/shadow'
  fi
  awk -v u='$USER_NAME' -F: '\$1 != u' '$ROOT_TREE/etc/shadow' > '$ROOT_TREE/etc/shadow.new'
  echo '$USER_NAME:$USER_SHADOW:19000:0:99999:7:::' >> '$ROOT_TREE/etc/shadow.new'
  mv '$ROOT_TREE/etc/shadow.new' '$ROOT_TREE/etc/shadow'
  chmod 0640 '$ROOT_TREE/etc/shadow'
  chown root:root '$ROOT_TREE/etc/shadow' 2>/dev/null || true

  # --- /etc/passwd --- (user entry with $USER_HOME + $USER_SHELL).
  if [ ! -f '$ROOT_TREE/etc/passwd' ]; then
    echo 'root:x:0:0:root:/root:/bin/bash' > '$ROOT_TREE/etc/passwd'
  fi
  # Drop any row matching either the target USER_NAME OR the target USER_UID
  # (M9.R.56.6 UID-collision cleanup) --- the stage baseline live user shares
  # uid=1000 with our repro user and shadows autologin.
  awk -v u='$USER_NAME' -v uid='$USER_UID' -F: '\$1 != u && \$3 != uid' '$ROOT_TREE/etc/passwd' > '$ROOT_TREE/etc/passwd.new'
  echo '$USER_NAME:x:$USER_UID:$USER_GID:$USER_FULL_NAME:$USER_HOME:$USER_SHELL' >> '$ROOT_TREE/etc/passwd.new'
  mv '$ROOT_TREE/etc/passwd.new' '$ROOT_TREE/etc/passwd'
  chmod 0644 '$ROOT_TREE/etc/passwd'

  # Also drop the ``live`` shadow row (matches the ``live`` passwd row we
  # removed above; nss keeps them in lock-step, and dpkg-triggered
  # tools scan shadow via getent).
  awk -v u='$USER_NAME' -F: '\$1 != u && \$1 != \"live\"' '$ROOT_TREE/etc/shadow' > '$ROOT_TREE/etc/shadow.new2'
  echo '$USER_NAME:$USER_SHADOW:19000:0:99999:7:::' >> '$ROOT_TREE/etc/shadow.new2'
  mv '$ROOT_TREE/etc/shadow.new2' '$ROOT_TREE/etc/shadow'
  chmod 0640 '$ROOT_TREE/etc/shadow'
  chown root:root '$ROOT_TREE/etc/shadow' 2>/dev/null || true

  # --- /etc/group --- (primary group + secondary group memberships).
  # Primary group: $USER_NAME with gid $USER_GID.
  if [ ! -f '$ROOT_TREE/etc/group' ]; then
    echo 'root:x:0:' > '$ROOT_TREE/etc/group'
  fi
  # Remove live-media aliases, colliding primary groups, and stale target/live
  # memberships before applying the configured group set.
  awk -v g='$USER_NAME' -v gid='$USER_GID' -v u='$USER_NAME' -F: '
    BEGIN { OFS=\":\" }
    \$1 != g && \$1 != \"live\" && \$3 != gid {
      kept=\"\"
      count=split(\$4, members, \",\")
      for (i=1; i<=count; i++) {
        if (members[i] == \"\" || members[i] == u || members[i] == \"live\") continue
        kept=(kept == \"\" ? members[i] : kept \",\" members[i])
      }
      \$4=kept
      print
    }
  ' '$ROOT_TREE/etc/group' > '$ROOT_TREE/etc/group.new'
  echo '$USER_NAME:x:$USER_GID:' >> '$ROOT_TREE/etc/group.new'
  # Add user to each secondary group (append user to member list;
  # create group with gid+100 if it doesn't exist).
  next_gid=1001
  for g in $USER_GROUPS_SPACED; do
    [ -z \"\$g\" ] && continue
    if grep -qE \"^\$g:\" '$ROOT_TREE/etc/group.new'; then
      # Group exists: append user to member list if not already there.
      awk -v g=\"\$g\" -v u='$USER_NAME' -F: 'BEGIN{OFS=\":\"} { if (\$1==g) { if (\$4==\"\") { \$4=u } else if (index(\$4,u)==0) { \$4=\$4\",\"u } } print }' '$ROOT_TREE/etc/group.new' > '$ROOT_TREE/etc/group.new2'
      mv '$ROOT_TREE/etc/group.new2' '$ROOT_TREE/etc/group.new'
    else
      # Group missing: create with the next genuinely unused gid.
      while awk -F: -v gid=\"\$next_gid\" '
        \$3 == gid { found=1 }
        END { exit(found ? 0 : 1) }
      ' '$ROOT_TREE/etc/group.new'; do
        next_gid=\$((next_gid+1))
      done
      echo \"\$g:x:\$next_gid:$USER_NAME\" >> '$ROOT_TREE/etc/group.new'
      next_gid=\$((next_gid+1))
    fi
  done
  mv '$ROOT_TREE/etc/group.new' '$ROOT_TREE/etc/group'
  chmod 0644 '$ROOT_TREE/etc/group'

  # --- /etc/gshadow --- (shadow-group entries; NSS wants matching).
  if [ ! -f '$ROOT_TREE/etc/gshadow' ]; then
    echo 'root:*::' > '$ROOT_TREE/etc/gshadow'
  fi
  awk -v g='$USER_NAME' -v u='$USER_NAME' -F: '
    BEGIN { OFS=\":\" }
    \$1 != g && \$1 != \"live\" {
      kept=\"\"
      count=split(\$4, members, \",\")
      for (i=1; i<=count; i++) {
        if (members[i] == \"\" || members[i] == u || members[i] == \"live\") continue
        kept=(kept == \"\" ? members[i] : kept \",\" members[i])
      }
      \$4=kept
      print
    }
  ' '$ROOT_TREE/etc/gshadow' > '$ROOT_TREE/etc/gshadow.new'
  echo '$USER_NAME:!::' >> '$ROOT_TREE/etc/gshadow.new'
  for g in $USER_GROUPS_SPACED; do
    [ -z \"\$g\" ] && continue
    awk -v g=\"\$g\" -F: '\$1 != g' '$ROOT_TREE/etc/gshadow.new' > '$ROOT_TREE/etc/gshadow.new2'
    mv '$ROOT_TREE/etc/gshadow.new2' '$ROOT_TREE/etc/gshadow.new'
    echo \"\$g:!::$USER_NAME\" >> '$ROOT_TREE/etc/gshadow.new'
  done
  mv '$ROOT_TREE/etc/gshadow.new' '$ROOT_TREE/etc/gshadow'
  chmod 0640 '$ROOT_TREE/etc/gshadow'

  # --- /home/\$USER_NAME --- (chown uid:gid so first login has a
  # writeable home).
  mkdir -p '$ROOT_TREE$USER_HOME'
  if ! chown $USER_UID:$USER_GID '$ROOT_TREE$USER_HOME' 2>/dev/null; then
    # A caller with no escalation cannot set an arbitrary owner. That
    # is not silently acceptable: it is exactly the reason the guest
    # inode policy (tools/reproos_image_metadata.py) exists and has to
    # run over this tree, and a caller that cannot escalate cannot run
    # that either. Refuse when we ARE privileged -- then a failure is a
    # real one -- and say so loudly when we are not, so the caller's
    # own gate can decide.
    if [ \"\$(id -u)\" -eq 0 ]; then
      echo '[configure-installed-root] chown of $USER_HOME failed as root' >&2
      exit 1
    fi
    echo '[configure-installed-root] UNPRIVILEGED: $USER_HOME keeps the' \\
         'building user as its owner; the guest inode policy has not been' \\
         'applied to this tree' >&2
  fi
  chmod 0755 '$ROOT_TREE$USER_HOME'
" || { echo "[configure-installed-root] passwd/shadow/group emit failed" >&2; exit 71; }

# Make sure the hostname file matches the TOML value (install-root
# already wrote one but the TOML may differ from the default).
"$SUDO" bash -c "echo '$HOSTNAME_VAL' > '$ROOT_TREE/etc/hostname'" || true

# ---------------------------------------------------------------
# Phase 10.4: configure source-built DHCP and OpenSSH. The image uses
# BusyBox udhcpc for lease management and the OpenSSH installation
# staged from reprobuild-packages; no distro networking or SSH package
# is required at runtime.
# ---------------------------------------------------------------
echo "[configure-installed-root] Phase 10.4: configure DHCP + OpenSSH"

SSHD_CONFIG="$WORK/sshd_config"
SSHD_UNIT="$WORK/sshd.service"

cat > "$SSHD_CONFIG" <<SSHD_CONFIG_EOF
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers $USER_NAME
PrintMotd no
PidFile /run/sshd.pid
Subsystem sftp /usr/libexec/sftp-server
SSHD_CONFIG_EOF

cat > "$SSHD_UNIT" <<'SSHD_UNIT_EOF'
[Unit]
Description=OpenSSH server
After=network.target reproos-network.service reproos-first-boot-enroll.service
Wants=reproos-network.service
Requires=reproos-first-boot-enroll.service

[Service]
Type=simple
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
ExecStartPre=/usr/bin/ssh-keygen -A
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D -e
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
SSHD_UNIT_EOF

"$SUDO" mkdir -p \
  "$ROOT_TREE/usr/local/sbin" \
  "$ROOT_TREE/etc/ssh" \
  "$ROOT_TREE/etc/systemd/system/multi-user.target.wants" \
  "$ROOT_TREE/var/empty"
"$SUDO" install -m 0755 \
  "$SCRIPT_DIR_SELF/reproos-udhcpc-hook" \
  "$SCRIPT_DIR_SELF/reproos-network" \
  "$SCRIPT_DIR_SELF/reproos-network-wait" \
  "$ROOT_TREE/usr/local/sbin/"
"$SUDO" install -m 0644 "$SCRIPT_DIR_SELF/reproos-network.service" \
  "$ROOT_TREE/etc/systemd/system/reproos-network.service"
"$SUDO" cp "$SSHD_CONFIG" "$ROOT_TREE/etc/ssh/sshd_config"
"$SUDO" cp "$SSHD_UNIT" "$ROOT_TREE/etc/systemd/system/sshd.service"
"$SUDO" chmod 0644 \
  "$ROOT_TREE/etc/systemd/system/reproos-network.service" \
  "$ROOT_TREE/etc/systemd/system/sshd.service"
"$SUDO" chmod 0600 "$ROOT_TREE/etc/ssh/sshd_config"
"$SUDO" chmod 0755 "$ROOT_TREE/var/empty"

"$SUDO" install -m 0755 "$SCRIPT_DIR_SELF/reproos-first-boot-enroll" \
  "$ROOT_TREE/usr/local/sbin/reproos-first-boot-enroll"
"$SUDO" bash -c "cat > '$ROOT_TREE/etc/systemd/system/reproos-first-boot-enroll.service'" <<'ENROLL_UNIT_EOF'
[Unit]
Description=Enroll ReproOS instance identity and SSH keys
After=local-fs.target
Before=sddm.service sshd.service reproos-health-check.service
ConditionPathExists=!/var/lib/reproos/enrollment.complete

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/reproos-first-boot-enroll
TimeoutStartSec=120
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
ENROLL_UNIT_EOF
"$SUDO" chmod 0644 \
  "$ROOT_TREE/etc/systemd/system/reproos-first-boot-enroll.service"
"$SUDO" mkdir -p "$ROOT_TREE/var/lib/reproos"
printf '%s\n' 'direct-image-assembly' > "$WORK/install-source"
"$SUDO" install -m 0644 "$WORK/install-source" \
  "$ROOT_TREE/var/lib/reproos/install-source"

"$SUDO" bash -c "
  set -euo pipefail
  grep -q '^sshd:' '$ROOT_TREE/etc/group' || \
    echo 'sshd:x:74:' >> '$ROOT_TREE/etc/group'
  grep -q '^sshd:' '$ROOT_TREE/etc/gshadow' || \
    echo 'sshd:!::' >> '$ROOT_TREE/etc/gshadow'
  grep -q '^sshd:' '$ROOT_TREE/etc/passwd' || \
    echo 'sshd:x:74:74:OpenSSH privilege separation:/var/empty:/usr/bin/false' \
      >> '$ROOT_TREE/etc/passwd'
  grep -q '^sshd:' '$ROOT_TREE/etc/shadow' || \
    echo 'sshd:!:19000:0:99999:7:::' >> '$ROOT_TREE/etc/shadow'
  ln -sfn /etc/systemd/system/reproos-network.service \
    '$ROOT_TREE/etc/systemd/system/multi-user.target.wants/reproos-network.service'
  ln -sfn /etc/systemd/system/reproos-first-boot-enroll.service \
    '$ROOT_TREE/etc/systemd/system/multi-user.target.wants/reproos-first-boot-enroll.service'
  ln -sfn /etc/systemd/system/sshd.service \
    '$ROOT_TREE/etc/systemd/system/multi-user.target.wants/sshd.service'
" || { echo "[configure-installed-root] DHCP + OpenSSH configuration failed" >&2; exit 71; }

# ---------------------------------------------------------------
# Phase 10.5: wire the default systemd target + display-manager +
# SDDM autologin for the installed system.
#
# M9.R.56.4 — the stage-de-rootfs.sh baseline sets
# ``default.target -> multi-user.target`` (console mode) and
# writes an SDDM autologin config for the LIVE ISO (User=live,
# Session=reproos-installer), then overlays those into the staged
# tree.  On the INSTALLED disk we need the graphical target + a
# per-user SDDM autologin per ``[de] default`` + ``[user] name``
# from auto-config.toml.
#
# ``[de] default`` values (validated at Phase 1):
#   sway         -> Session=sway
#   kwin         -> Session=plasma (kwin_wayland runs under plasma)
#   mutter       -> Session=gnome
#   plasmashell  -> Session=plasma
#   sddm         -> Session=sway (fallback -- SDDM is not itself a
#                    session; treat as "graphical with default sway")
# ---------------------------------------------------------------

case "$DE_DEFAULT" in
  sway)         SDDM_SESSION="sway" ;;
  kwin)         SDDM_SESSION="plasma" ;;
  mutter)       SDDM_SESSION="gnome" ;;
  plasmashell)  SDDM_SESSION="plasma" ;;
  sddm)         SDDM_SESSION="sway" ;;
  *)            SDDM_SESSION="sway" ;;
esac

echo "[configure-installed-root] Phase 10.5: wire graphical target + sddm autologin (session=$SDDM_SESSION user=$USER_NAME)"

"$SUDO" bash -c "
  set -euo pipefail

  # Swap default.target to graphical.target (from-source-built
  # graphical.target is present at /usr/lib/systemd/system/).
  mkdir -p '$ROOT_TREE/etc/systemd/system'
  if [ -e '$ROOT_TREE/usr/lib/systemd/system/graphical.target' ] \\
      || [ -e '$ROOT_TREE/lib/systemd/system/graphical.target' ]; then
    ln -sfn /usr/lib/systemd/system/graphical.target \\
      '$ROOT_TREE/etc/systemd/system/default.target'
  else
    echo '[configure-installed-root] warning: graphical.target not found in installed rootfs -- staying at multi-user.target' >&2
  fi

  # Wire display-manager.service to sddm (from-source-built sddm.service
  # was installed to /usr/lib/systemd/system/sddm.service by the
  # from-source sddm recipe's install-mirror overlay).
  if [ -e '$ROOT_TREE/usr/lib/systemd/system/sddm.service' ] \\
      || [ -e '$ROOT_TREE/lib/systemd/system/sddm.service' ]; then
    ln -sfn /usr/lib/systemd/system/sddm.service \\
      '$ROOT_TREE/etc/systemd/system/display-manager.service'
    # Enable at graphical.target.
    mkdir -p '$ROOT_TREE/etc/systemd/system/graphical.target.wants'
    ln -sfn /usr/lib/systemd/system/sddm.service \\
      '$ROOT_TREE/etc/systemd/system/graphical.target.wants/sddm.service'
  else
    echo '[configure-installed-root] warning: sddm.service not found in installed rootfs' >&2
  fi

  # SDDM autologin config: point at the per-TOML user + session,
  # replacing the stage-de-rootfs.sh live-ISO default (User=live,
  # Session=reproos-installer).
  mkdir -p '$ROOT_TREE/etc/sddm.conf.d'
  cat > '$ROOT_TREE/etc/sddm.conf.d/00-autologin.conf' <<SDDM_EOF
[Autologin]
User=$USER_NAME
Session=$SDDM_SESSION
Relogin=true

[General]
HaltCommand=/usr/bin/systemctl poweroff
RebootCommand=/usr/bin/systemctl reboot
SDDM_EOF

  # Disable the reproos-installer-autorun.service unit -- it only
  # belongs on the LIVE ISO where the installer needs to run.
  rm -f '$ROOT_TREE/etc/systemd/system/multi-user.target.wants/reproos-installer-autorun.service' \\
        '$ROOT_TREE/etc/systemd/system/graphical.target.wants/reproos-installer-autorun.service' \\
        2>/dev/null || true

  # M9.R.56.6: strip the live-ISO tty1 autologin drop-in --- the
  # installed disk should not auto-login as root on the text
  # console (the graphical session via SDDM/autologin is where
  # the user lands).  Without this the getty@tty1 unit is racing
  # with sddm.service both trying to own vt1 depending on which
  # gets ahead in unit ordering.
  rm -rf '$ROOT_TREE/etc/systemd/system/getty@tty1.service.d' 2>/dev/null || true
" || { echo "[configure-installed-root] display-manager wiring failed" >&2; exit 71; }

# ---------------------------------------------------------------
# Phase 10.6: close dbus.service boot-blockers so the D-Bus system
# bus can start (M9.R.56.4 + M9.R.56.5).
#
# Post-M9.R.56.3 the from-source dbus binary + libdbus + system.conf
# are present at the expected FHS paths, but three latent bugs from
# the Debian base rootfs + the install-mirror layout still prevent
# dbus.service from reaching notify-ready:
#
#   Blocker 1 (runtime dir):  the Debian dbus.service unit lacks
#     ``RuntimeDirectory=dbus``.  dbus-daemon fails with
#     ``Failed to bind socket "/run/dbus/system_bus_socket": No
#     such file or directory`` because /run/dbus doesn't exist and
#     nothing creates it at unit start.  Fix: drop-in override that
#     adds ``RuntimeDirectory=dbus`` (systemd creates
#     /run/dbus/ with mode 0755 before ExecStart).
#
#   Blocker 2 (Debian gdm.conf):  the Debian base rootfs ships
#     /etc/dbus-1/system.d/gdm.conf with ``<policy user="gdm">``.
#     dbus-daemon parses every *.conf in system.d/ at startup and
#     rejects the whole config file when the user is undefined
#     (``Unknown username "gdm" in message bus configuration
#     file``).  We use SDDM not GDM so removing gdm.conf is the
#     correct cleanup; a future GDM-first config can drop it back
#     in via the polkit / dconf split we already ship for KDE.
#
#   Blocker 3 (dbus-daemon-launch-helper):  the from-source dbus
#     ships /usr/libexec/dbus-daemon-launch-helper (a setuid helper
#     the daemon exec()'s for privileged bus-activation), but
#     stage-de-rootfs.sh's ``link_base_recipe_binaries`` only
#     shadow-links ``usr/{bin,sbin}`` from-source binaries, NOT
#     ``usr/libexec/``.  Add a shadow-link at
#     /usr/libexec/dbus-daemon-launch-helper -> install-mirror.
#
# Blocker 4 (falsified):  the LIBDBUS_PRIVATE_1.16.0 warning
# printed at exec time by ld.so is a NON-FATAL diagnostic caused
# by Debian's /etc/ld.so.cache holding a stale entry for the older
# Debian /lib/x86_64-linux-gnu/libdbus-1.so.3 (verified by
# LD_DEBUG=libs: after the warning ld.so falls through to the
# from-source libdbus at
# /opt/repro/reprobuild/.../install/usr/lib/libdbus-1.so.3 via
# dbus-daemon's RUNPATH and completes the load).  The daemon
# succeeds after the warning; the warning is a v2 cleanup.
# ---------------------------------------------------------------

# Everything from this point writes target-side links. Use the canonical
# in-image mirror location, independent of the host checkout path.
SOURCE_RECIPES_ROOT="$TARGET_SOURCE_RECIPES_ROOT"

echo "[configure-installed-root] Phase 10.6: wire dbus RuntimeDirectory + strip gdm.conf + shadow-link libexec helper + replace ExecStart"

"$SUDO" bash -c "
  set -euo pipefail

  # Blocker 1 --- drop-in override adding RuntimeDirectory=dbus.
  mkdir -p '$ROOT_TREE/etc/systemd/system/dbus.service.d'
  cat > '$ROOT_TREE/etc/systemd/system/dbus.service.d/10-runtime-dir.conf' <<'DBUS_DROPIN_EOF'
[Service]
RuntimeDirectory=dbus
RuntimeDirectoryMode=0755
DBUS_DROPIN_EOF

  # Blocker 2 --- remove Debian's gdm.conf (references undefined gdm user).
  rm -f '$ROOT_TREE/etc/dbus-1/system.d/gdm.conf'

  # Blocker 3 --- shadow-link the setuid dbus-daemon-launch-helper from
  # the from-source install-mirror so ExecStart's fork() finds it at
  # /usr/libexec/dbus-daemon-launch-helper.
  mkdir -p '$ROOT_TREE/usr/libexec'
  ln -sfn '$SOURCE_RECIPES_ROOT/dbus/.repro/output/install/usr/libexec/dbus-daemon-launch-helper' \\
    '$ROOT_TREE/usr/libexec/dbus-daemon-launch-helper'

  # Blocker 5 (M9.R.56.5) --- the from-source dbus 1.16.0 recipe does
  # NOT enable the meson systemd option (\`\`-Dsystemd=enabled\`\`), so
  # dbus-daemon is compiled without libsystemd support and rejects
  # \`\`--systemd-activation\`\` with \`\`Failed to start message bus: dbus
  # was compiled without systemd support\`\`.  Falsified by injecting a
  # diag unit that runs dbus-daemon manually: variant without
  # \`\`--systemd-activation\`\` runs fine (test1=RUNNING); variant with
  # \`\`--systemd-activation\`\` exits with the compile-support error
  # (test3 stderr).  Also confirmed via readelf: from-source
  # \`\`libdbus-1.so.3.38.3\`\` has NO NEEDED entry for libsystemd.so.0.
  #
  # Fix at v1: override the ExecStart to drop \`\`--systemd-activation\`\`
  # + \`\`--address=systemd:\`\` and switch Type=notify -> Type=simple so
  # systemd doesn't wait for a sd_notify() dbus-daemon can't emit.
  # dbus-daemon then listens on the default /run/dbus/system_bus_socket
  # (which matches dbus.socket's ListenStream anyway).  Type=simple
  # means the unit is Active as soon as the process is running; the
  # Debian unit's TriggeredBy=dbus.socket already gives the correct
  # ordering.  Once the from-source dbus recipe is rebuilt with
  # \`\`-Dsystemd=enabled\`\` we can drop the ExecStart override; the
  # RuntimeDirectory drop-in stays.
  cat > '$ROOT_TREE/etc/systemd/system/dbus.service.d/20-no-systemd-activation.conf' <<'DBUS_EXEC_EOF'
[Service]
Type=simple
ExecStart=
ExecStart=/usr/bin/dbus-daemon --system --nofork --nopidfile --syslog-only
DBUS_EXEC_EOF
" || { echo "[configure-installed-root] Phase 10.6 dbus wiring failed" >&2; exit 72; }

# ---------------------------------------------------------------
# Phase 10.7 (M9.R.56.7): install a minimal SDDM theme.
#
# The from-source sddm recipe install-mirror ships ONLY the sddm
# binary + libexec helpers; NO themes.  The Debian sddm dpkg
# entry ships /usr/share/sddm/{faces,scripts,flags,translations-qt6}
# but NO themes/ directory.  SDDM's default ``Theme=`` in
# /etc/sddm.conf.d and the greeter's fallback path both expect
# /usr/share/sddm/themes/<name>/Main.qml.  Without one, SDDM's
# greeter renders a blank/black QQuickWindow --- verified in
# M9.R.56.6 boot smoke where all 6 t={0..165}s screendumps are
# 1280x800 grayscale mean=0.
#
# The minimal theme below is a bare-bones QML that just fills
# the window in a solid gray with the "reproos" text --- enough
# to prove the greeter renders SOMETHING, so that on subsequent
# iterations (M9.R.56.8+) we know if SDDM's autologin is firing
# (screen goes to sway session) or falling back to greeter (screen
# stays at gray+text).  A full theme lands with the sddm recipe
# rework in M9.R.57+.
# ---------------------------------------------------------------

echo "[configure-installed-root] Phase 10.7: install minimal SDDM theme /usr/share/sddm/themes/reproos"

"$SUDO" bash -c "
  set -euo pipefail
  mkdir -p '$ROOT_TREE/usr/share/sddm/themes/reproos'
  cat > '$ROOT_TREE/usr/share/sddm/themes/reproos/metadata.desktop' <<'THEME_META_EOF'
[SddmGreeterTheme]
Name=reproos
Description=ReproOS minimal SDDM theme
Author=reprobuild
Copyright=(c) 2026 Metacraft Labs
License=MIT
Type=sddm-theme
Version=1.0
Website=https://github.com/metacraft-labs/reprobuild
Screenshot=
MainScript=Main.qml
ConfigFile=theme.conf
Theme-Id=reproos
Theme-API=2.0

THEME_META_EOF
  cat > '$ROOT_TREE/usr/share/sddm/themes/reproos/Main.qml' <<'THEME_QML_EOF'
import QtQuick 2.15

Rectangle {
  id: root
  width: 1920
  height: 1080
  color: '#1a1a2e'
  Text {
    anchors.centerIn: parent
    color: 'white'
    font.pixelSize: 48
    text: 'reproos'
  }
  Text {
    anchors.horizontalCenter: parent.horizontalCenter
    anchors.top: parent.verticalCenter
    anchors.topMargin: 60
    color: '#aaaaaa'
    font.pixelSize: 18
    text: 'M9.R.56.7 minimal greeter'
  }
}
THEME_QML_EOF
  cat > '$ROOT_TREE/usr/share/sddm/themes/reproos/theme.conf' <<'THEME_CONF_EOF'
[General]
background=
type=color
color=#1a1a2e
THEME_CONF_EOF

  # Wire /etc/sddm.conf to select the reproos theme.  We layer
  # over the existing /etc/sddm.conf.d/ dir (already contains
  # 00-autologin.conf from Phase 10.5) so the [Autologin] section
  # stays intact.
  cat > '$ROOT_TREE/etc/sddm.conf.d/05-theme.conf' <<'SDDM_THEME_EOF'
[Theme]
Current=reproos
SDDM_THEME_EOF
" || { echo "[configure-installed-root] Phase 10.7 sddm theme install failed" >&2; exit 73; }

# ---------------------------------------------------------------
# Phase 10.8 (M9.R.56.8.1): fix compiled-in /usr/local paths in
# the from-source sddm binary + install strace instrumentation
# for the sddm session-launch chain.
#
# ## Diagnosis (Phase A — static, per feedback_mcr_no_speculation)
#
# The from-source sddm 0.21 recipe (recipes/packages/source/sddm/
# repro.nim) does NOT set ``CMAKE_INSTALL_PREFIX`` in its
# ``cmakeFlags:`` block, so CMake defaults to
# ``/usr/local``.  The prefix bakes into the generated
# ``src/common/Constants.h`` (Constants.h.in is templated with
# ``@CMAKE_INSTALL_FULL_LIBEXECDIR@`` etc.), which the sddm
# daemon then references via ``QStringLiteral`` at every session-
# launch and theme-load site:
#
#   #define LIBEXEC_INSTALL_DIR     "/usr/local/libexec"
#   #define DATA_INSTALL_DIR        "/usr/local/share/sddm"
#   #define SESSION_COMMAND         "/usr/local/share/sddm/scripts/Xsession"
#   #define WAYLAND_SESSION_COMMAND "/usr/local/share/sddm/scripts/wayland-session"
#   #define SYSTEM_CONFIG_DIR       "/usr/local/lib/sddm/sddm.conf.d"
#
# Real files ship at:
#   /usr/libexec/sddm-helper                       (from-source install-mirror)
#   /usr/libexec/sddm-helper-start-wayland          (from-source install-mirror)
#   /usr/libexec/sddm-helper-start-x11user          (from-source install-mirror)
#   /usr/share/sddm/scripts/{wayland-session,Xsession,Xsetup,Xstop} (Debian dpkg)
#   /usr/share/sddm/{faces,flags,translations-qt6} (Debian dpkg)
#   /usr/share/sddm/themes/reproos/Main.qml         (Phase 10.7)
#
# Consequences the M9.R.56.7 evidence hit:
#   * Autologin succeeds via PAM (sddm-autologin PAM stack is
#     complete) but the ``sddm-helper`` exec at
#     ``/usr/local/libexec/sddm-helper`` errors ENOENT --- the
#     user session never spawns.
#   * Greeter mode (non-autologin) loads the ``Theme.ThemeDir``
#     default ``/usr/local/share/sddm/themes`` which does not
#     exist; the QQuickWindow falls back to a blank/black surface.
#     This exactly matches the M9.R.56.7 mean-grayscale=0 PPM.
#   * Wayland compositor spawn also fails --- the daemon exec()s
#     ``/usr/local/share/sddm/scripts/wayland-session <sway.desktop-Exec>``
#     but the wayland-session script is not at that path.
#
# Cascade class: install-prefix baked into a compile-time
# constant.  The proper fix is to rebuild sddm with the correct
# CMake flags, which is still outstanding; the image-time fix used
# here is shadow-link symlinks in the same pattern as
# Phase 10.6 Blocker 3 (the
# dbus-daemon-launch-helper shim) --- ``/usr/local/libexec ->
# /usr/libexec`` and ``/usr/local/share/sddm -> /usr/share/sddm``.
#
# The ``[Theme] ThemeDir`` / ``[X11] SessionCommand`` /
# ``[Wayland] SessionCommand`` config overrides layered under
# /etc/sddm.conf.d/10-paths.conf are belt-and-suspenders: they
# route the Config-file overridable paths at /usr/share instead of
# /usr/local, so if a future refactor moves sddm to a proper
# CMAKE_INSTALL_PREFIX=/usr build the shim symlinks become
# no-ops and the config overrides pin the correct paths.
#
# ## Instrumentation
#
# We wrap sddm's ExecStart with strace -f piping to
# /var/log/m9r56_diag/sddm-strace.log and dump the sddm
# journal to /var/log/m9r56_diag/sddm-journal.txt via a
# one-shot post-boot unit.  A future M9.R.56.9 can inspect the
# diag files by mounting the resulting qcow2 nbd.
# ---------------------------------------------------------------

echo "[configure-installed-root] Phase 10.8: shim compiled-in /usr/local sddm paths + install strace instrumentation"

"$SUDO" bash -c "
  set -euo pipefail

  # --- Path shims for compiled-in Constants.h defines ---
  # M9.R.56.8.2: point directly at the from-source install-mirror
  # under /opt/repro/reprobuild.  stage-de-rootfs.sh's
  # ``link_base_recipe_binaries`` shadow-links only ``usr/{bin,
  # sbin}`` from the install-mirror --- ``usr/libexec/`` is NOT
  # shadow-linked (same finding as Phase 10.6 Blocker 3 for
  # dbus-daemon-launch-helper).  We therefore link
  # /usr/local/libexec/<helper> DIRECTLY at
  # /opt/repro/reprobuild-packages/packages/source/sddm/.repro/output/install/usr/libexec/<helper>
  # rather than via /usr/libexec/<helper> (which does not exist
  # on the installed disk).
  #
  # This matches Phase 10.6 Blocker 3's dbus-daemon-launch-helper
  # shim exactly.  A future stage-de-rootfs.sh pass that shadow-
  # links usr/libexec/ from every from-source install-mirror
  # would let this collapse to ``ln -sfn /usr/libexec/<helper>``
  # (a single-hop symlink), but that broader shadow-link rework
  # belongs in M9.R.57+ with the sddm-recipe CMAKE_INSTALL_PREFIX
  # fix.
  mkdir -p '$ROOT_TREE/usr/local/libexec'
  SDDM_INSTALL_LIBEXEC='$SOURCE_RECIPES_ROOT/sddm/.repro/output/install/usr/libexec'
  for helper in sddm-helper sddm-helper-start-wayland sddm-helper-start-x11user; do
    ln -sfn \"\$SDDM_INSTALL_LIBEXEC/\$helper\" \"$ROOT_TREE/usr/local/libexec/\$helper\"
  done

  # Also shadow-link /usr/libexec/<helper> so any code path that
  # references /usr/libexec/sddm-helper directly (e.g. the
  # /etc/sddm.conf.d/10-paths.conf overrides below, or a rebuilt
  # sddm binary with CMAKE_INSTALL_PREFIX=/usr) resolves too.
  mkdir -p '$ROOT_TREE/usr/libexec'
  for helper in sddm-helper sddm-helper-start-wayland sddm-helper-start-x11user; do
    ln -sfn \"\$SDDM_INSTALL_LIBEXEC/\$helper\" \"$ROOT_TREE/usr/libexec/\$helper\"
  done

  # /usr/local/share/sddm -> /usr/share/sddm as a full dir
  # symlink so the daemon finds themes, faces, scripts, and
  # translations at their compiled-in DATA_INSTALL_DIR.
  mkdir -p '$ROOT_TREE/usr/local/share'
  ln -sfn /usr/share/sddm '$ROOT_TREE/usr/local/share/sddm'

  # M9.R.56.8.3: shim /usr/local/bin/sddm-greeter-qt6.  sddm's
  # daemon.Greeter.cpp computes the greeter argv as
  # ``QStringLiteral(BIN_INSTALL_DIR \"/sddm-greeter%1\").arg(suffix)``
  # which bakes to ``/usr/local/bin/sddm-greeter-qt6``.  Point at
  # the from-source install-mirror greeter binary directly (the
  # image's /usr/bin/sddm-greeter-qt6 is already a shadow-link
  # to the same install-mirror path via stage-de-rootfs.sh's
  # link_base_recipe_binaries, so pointing at the install-mirror
  # is equivalent and avoids a two-hop symlink).
  mkdir -p '$ROOT_TREE/usr/local/bin'
  ln -sfn '$SOURCE_RECIPES_ROOT/sddm/.repro/output/install/usr/bin/sddm-greeter-qt6' \\
    '$ROOT_TREE/usr/local/bin/sddm-greeter-qt6'
  ln -sfn '$SOURCE_RECIPES_ROOT/sddm/.repro/output/install/usr/bin/sddm' \\
    '$ROOT_TREE/usr/local/bin/sddm'

  # M9.R.56.8.3: shim /lib/security -> from-source pam's install-
  # mirror.  libpam.so.0 from the pam recipe (linked by
  # sddm-helper via RUNPATH) has compiled-in module search path
  # /lib/security/ (verified via ``strings libpam.so.0``).  The
  # from-source pam recipe installs modules at
  # /opt/repro/reprobuild-packages/packages/source/pam/.repro/output/install/usr/lib/security/
  # but that path is not shadow-linked into /lib/security/ by
  # stage-de-rootfs.sh.  Debian's PAMs at
  # /usr/lib/x86_64-linux-gnu/security/ are ABI-compatible but
  # linked against Debian's libpam.so.0.85.1 (older), so we
  # point at the from-source install-mirror to keep the ABI
  # matched with the sddm-helper's linked libpam.
  #
  # We link the whole /lib/security dir at the pam install-
  # mirror's usr/lib/security subtree.
  mkdir -p '$ROOT_TREE/lib'
  ln -sfn '$SOURCE_RECIPES_ROOT/pam/.repro/output/install/usr/lib/security' \\
    '$ROOT_TREE/lib/security'

  # M9.R.56.8.4: strip pam_selinux.so references from the sddm
  # PAM config files.  The from-source pam recipe does NOT
  # build pam_selinux.so (it's a separate libselinux-dependent
  # module).  The Debian sddm-autologin + sddm-greeter PAM config
  # references pam_selinux.so with control ``[success=ok
  # ignore=ignore module_unknown=ignore default=bad]``; the
  # ``module_unknown=ignore`` semantic SHOULD skip a missing
  # module, but the actual libpam-1.5 pam_start()
  # implementation treats a file-not-found dlopen error
  # differently from a module_unknown case: it silently falls
  # through to /etc/pam.d/other for the affected phase.
  # /etc/pam.d/other's @include common-auth uses pam_unix.so
  # nullok --- with autologin (no password supplied), pam_unix
  # returns PAM_AUTH_ERR, and sddm-helper logs the resulting
  # ``PAM_PERM_DENIED`` as ``Permission denied`` (verified in
  # /var/log/sddm.log from the M9.R.56.8.3 boot smoke).
  #
  # Fix: use sed to comment out every ``pam_selinux.so`` line
  # in the two sddm PAM configs.  We use ONLY sed --- no
  # rewriting the file --- so any future Debian sddm dpkg
  # update to the PAM config gets picked up (except the
  # pam_selinux comment).  ReproOS does not ship SELinux;
  # stripping the module is safe.
  #
  # A future M9.R.57+ can either (a) build pam_selinux from
  # libselinux via a proper from-source module or (b) patch
  # pam_start()'s file-not-found path to honour
  # module_unknown=ignore.
  for f in '$ROOT_TREE/etc/pam.d/sddm' '$ROOT_TREE/etc/pam.d/sddm-autologin' '$ROOT_TREE/etc/pam.d/sddm-greeter'; do
    [ -f \"\$f\" ] || continue
    sed -i 's|^\\(.*pam_selinux.so.*\\)\$|# M9.R.56.8.4 stripped: \\1|' \"\$f\"
  done

  # M9.R.56.8.5: replace the sddm-autologin + sddm-greeter PAM
  # config files with MINIMAL configs that only reference the
  # from-source PAM modules we know are available.  Empirical
  # evidence from the M9.R.56.8.4 boot smoke (/var/log/sddm.log):
  #
  #   [PAM] Authenticating...
  #   [PAM] authenticate: Permission denied
  #
  # even AFTER stripping pam_selinux.so and confirming pam_nologin
  # + pam_permit + pam_keyinit + pam_limits + pam_loginuid +
  # pam_env dlopen successfully.  libpam1.6.1's pam_dispatch.c
  # returns PAM_PERM_DENIED (== PAM_MUST_FAIL_CODE) when
  # \`\`no modules loaded for '<service>' service\`\`.  That means
  # the config file parse failed silently somewhere in the
  # @include common-* chain --- either a common-* file references
  # a module the from-source pam recipe doesnt ship (pam_cap.so,
  # pam_deny.so's specific path, pam_unix.so's Debian
  # multiarch quirk...) OR the from-source pam has a config-
  # parse regression against Debians @include semantics.
  #
  # The minimal configs below drop every @include and reference
  # ONLY: pam_nologin, pam_permit, pam_limits, pam_loginuid,
  # pam_keyinit, pam_env, pam_unix --- all confirmed present at
  # /lib/security/ from the from-source pam recipe install-
  # mirror shim.
  #
  # A future M9.R.57+ can (a) diff the from-source pam parser
  # against Debians libpam to find the include divergence, or
  # (b) reintroduce the @include chain once the pam recipe is
  # aligned with Debians module set.
  cat > '$ROOT_TREE/etc/pam.d/sddm-autologin' <<'PAM_AUTOLOGIN_EOF'
#%PAM-1.0
# M9.R.56.8.5 minimal PAM stack for sddm autologin.
# Bypasses the common-* @include chain that fails config parse
# silently on the from-source pam recipe.
# M9.R.56.8.6 adds pam_systemd.so (Debian binary; ABI-compatible
# with the from-source libpam.so.0) to create /run/user/<uid>
# and set XDG_RUNTIME_DIR --- without this, sway aborts at
# startup with ``XDG_RUNTIME_DIR is not set in the environment.
# Aborting.`` (verified in /home/repro/.local/share/sddm/
# wayland-session.log from the M9.R.56.8.5 boot smoke).
auth       required   pam_permit.so
account    required   pam_permit.so
password   required   pam_permit.so
session    required   pam_permit.so
session    optional   pam_keyinit.so force revoke
session    optional   pam_limits.so
session    optional   pam_loginuid.so
session    optional   pam_env.so
session    optional   /usr/lib/x86_64-linux-gnu/security/pam_systemd.so
PAM_AUTOLOGIN_EOF
  cat > '$ROOT_TREE/etc/pam.d/sddm-greeter' <<'PAM_GREETER_EOF'
#%PAM-1.0
# M9.R.56.8.5 minimal PAM stack for sddm greeter session (runs
# as the unprivileged sddm user; no autologin, no password
# required, just enough scaffolding to hand off to the greeter).
auth       required   pam_permit.so
account    required   pam_permit.so
password   required   pam_permit.so
session    required   pam_permit.so
session    optional   pam_keyinit.so force revoke
session    optional   pam_limits.so
session    optional   pam_loginuid.so
session    optional   pam_env.so
session    optional   /usr/lib/x86_64-linux-gnu/security/pam_systemd.so
PAM_GREETER_EOF

  # M9.R.71.3: replace /etc/pam.d/other with a portable pam_deny-only
  # fallback stack.
  #
  # Phase A evidence (recipes/reproos-image/run-evidence/m9r71/
  # m9r71_phaseA_pam_audit.txt):  the from-source Linux-PAM 1.6.1
  # recipe does NOT recognize Debian's @include directive as a
  # module-type keyword.  Only \`include\` and \`substack\` are
  # recognized upstream; @include is a Debian-patched extension.
  # sddm-helper links against the from-source libpam via RUNPATH,
  # so parsing /etc/pam.d/other (which Debian ships with four
  # @include common-* lines) produces four syslog LOG_ERR entries
  # per session start:
  #
  #   PAM (other) illegal module type: @include
  #   PAM pam_parse: expecting return value; [...common-auth]
  #   PAM (other) no module name supplied
  #
  # The libpam parser recovers by registering MUST_FAIL handlers
  # for the affected lines and returning PAM_SUCCESS, so the
  # sddm-autologin PAM chain is not functionally broken (the
  # MUST_FAIL handlers only apply to the \`other\` fallback service,
  # which sddm-autologin does not invoke).  But the log spam is
  # ugly and the file is semantically broken.
  #
  # This rewrite replaces the Debian @include chain with an
  # explicit pam_deny.so-only stack that preserves Debian's
  # original security intent (services with no explicit config
  # get DENIED) using portable directives that both the
  # from-source and Debian libpam parsers accept.
  cat > '$ROOT_TREE/etc/pam.d/other' <<'PAM_OTHER_EOF'
#%PAM-1.0
# M9.R.71.3 replacement for Debian's @include-based fallback.
# The from-source Linux-PAM 1.6.1 does not recognize @include
# (a Debian-patched extension); use portable pam_deny.so on
# every phase so any service without its own explicit config
# is denied outright.  Original Debian intent preserved.
auth       required   pam_deny.so
account    required   pam_deny.so
password   required   pam_deny.so
session    required   pam_deny.so
PAM_OTHER_EOF

  # M9.R.71.3: capture sway compositor stderr durably so a crash
  # cause is diagnosable.
  #
  # Phase B evidence: sddm-helper's UserSession.cpp:355-380 opens
  # \$HOME/.local/share/sddm/wayland-session.log with dup2 to
  # STDERR_FILENO before fork(exec sway).  On the qcow2 after
  # M9.R.70's boot smoke, /home/repro/.local/share/sddm/ is
  # completely absent — sway's stderr is being lost.
  #
  # The wrapper /usr/local/bin/repro-sway-diag:
  #   1. redirects stderr to /var/log/m9r71_sway.log (world-writable
  #      via tmpfiles.d so the setuid'd session process can append)
  #   2. echoes a launch marker line + env dump BEFORE exec'ing sway
  #   3. sync(1)s after the header so the log survives an abort()
  #      that happens before sway's own stdio buffer flushes
  # And point sddm's [Wayland] SessionCommand at the wrapper via
  # /etc/sddm.conf.d/20-sway-diag.conf.
  #
  # The wrapper source lives at
  # recipes/reproos-image/scripts/repro-sway-diag to avoid the
  # nested-quoting hazards of embedding a shell script inside
  # this build script's bash -c wrapper.
  mkdir -p '$ROOT_TREE/usr/local/bin'
  install -m 0755 '$SCRIPT_DIR_SELF/repro-sway-diag' '$ROOT_TREE/usr/local/bin/repro-sway-diag'
  sed -i 's|@REPRO_SOURCE_RECIPES_ROOT@|$SOURCE_RECIPES_ROOT|g' \
    '$ROOT_TREE/usr/local/bin/repro-sway-diag'

  # Keep the installed session independent of Debian's optional sway
  # companion packages.  swaybar is built beside sway in the from-source
  # output and gives the smoke test a stable, visible readiness signal.
  ln -sfn '$SOURCE_RECIPES_ROOT/sway/.repro/output/install/usr/bin/swaybar' \
    '$ROOT_TREE/usr/bin/swaybar'
  ln -sfn '$SOURCE_RECIPES_ROOT/sway/.repro/output/install/usr/bin/swaynag' \
    '$ROOT_TREE/usr/bin/swaynag'
  ln -sfn '$SOURCE_RECIPES_ROOT/qt6-declarative/.repro/output/install/usr/bin/qml' \
    '$ROOT_TREE/usr/bin/qml'
  ln -sfn '$SOURCE_RECIPES_ROOT/qt6-declarative/.repro/output/install/usr/qml' \
    '$ROOT_TREE/usr/qml'
  mkdir -p '$ROOT_TREE/etc/sway'
  install -m 0644 '$SCRIPT_DIR_SELF/reproos-sway.conf' \
    '$ROOT_TREE/etc/sway/config'
  mkdir -p '$ROOT_TREE/usr/share/reproos'
  install -m 0644 '$SCRIPT_DIR_SELF/reproos-desktop.qml' \
    '$ROOT_TREE/usr/share/reproos/reproos-desktop.qml'

  # systemd invokes module helpers through /sbin, while the from-source kmod
  # recipe installs its applets under /usr/bin.  Expose modprobe at the
  # conventional system path so early module units do not fail with ENOENT.
  mkdir -p '$ROOT_TREE/usr/sbin'
  ln -sfn '$SOURCE_RECIPES_ROOT/kmod/.repro/output/install/usr/bin/modprobe' \
    '$ROOT_TREE/usr/sbin/modprobe'

  # The source fontconfig build uses prefix=/usr, so its compiled default
  # configuration path is /usr/etc/fonts rather than Debian's /etc/fonts.
  # Keep both locations available to source and distribution consumers.
  mkdir -p '$ROOT_TREE/usr/etc' '$ROOT_TREE/etc'
  if [ ! -e '$ROOT_TREE/usr/etc/fonts' ] && [ ! -L '$ROOT_TREE/usr/etc/fonts' ]; then
    ln -s '$SOURCE_RECIPES_ROOT/fontconfig/.repro/output/install/usr/etc/fonts' \
      '$ROOT_TREE/usr/etc/fonts'
  fi
  if [ ! -e '$ROOT_TREE/etc/fonts' ] && [ ! -L '$ROOT_TREE/etc/fonts' ]; then
    ln -s '$SOURCE_RECIPES_ROOT/fontconfig/.repro/output/install/usr/etc/fonts' \
      '$ROOT_TREE/etc/fonts'
  fi

  # Ensure /var/log/m9r71_sway.log is world-writable (repro user
  # will append after setuid) — create it at boot via tmpfiles.d.
  # 0666 is safe because it's a diagnostic log only; nothing
  # security-sensitive is written.
  cat > '$ROOT_TREE/etc/tmpfiles.d/m9r71-sway-log.conf' <<'SWAY_LOG_TMPFILES_EOF'
# M9.R.71.3 durable sway diagnostic log.  0666 so setuid'd
# session processes can append across respawns.
f /var/log/m9r71_sway.log 0666 root root -
SWAY_LOG_TMPFILES_EOF

  # Point sddm's Wayland SessionCommand at our diagnostic wrapper.
  # This overrides the M9.R.56.8's 10-paths.conf setting.
  cat > '$ROOT_TREE/etc/sddm.conf.d/20-sway-diag.conf' <<'SDDM_SWAY_DIAG_EOF'
# M9.R.71.3 route the wayland session through our diagnostic
# wrapper so sway stderr is durably captured to
# /var/log/m9r71_sway.log across sddm respawn cycles.
[Wayland]
SessionCommand=/usr/local/bin/repro-sway-diag
SDDM_SWAY_DIAG_EOF

  # Also extend the M9.R.56.8 diag-capture unit to snarf the sway
  # log into the same directory the boot-smoke driver pulls from.
  mkdir -p '$ROOT_TREE/etc/systemd/system/m9r56-diag.service.d'
  cat > '$ROOT_TREE/etc/systemd/system/m9r56-diag.service.d/10-m9r71-sway-log.conf' <<'DIAG_EXTEND_EOF'
[Service]
ExecStart=/bin/sh -c 'cp /var/log/m9r71_sway.log /var/log/m9r56_diag/m9r71_sway.log 2>&1 || true'
ExecStart=/bin/sh -c 'journalctl --no-pager _COMM=sway > /var/log/m9r56_diag/journal-sway.txt 2>&1 || true'
DIAG_EXTEND_EOF

  # M9.R.71.4: disable the live-ISO installer autostart script on
  # the INSTALLED system.  /etc/profile.d/zz-reproos-installer-
  # autostart.sh runs the reproos installer on the tty1 shell
  # login whenever /etc/reproos/auto-config.toml is present.  On
  # the live ISO that's the intended flow; on the installed qcow2
  # it's a bug because the autologin session runs on VT 1 too and
  # the installer body executes on every sddm-helper spawn,
  # polluting the sway diagnostic log and delaying sway launch by
  # ~5 seconds per attempt.
  #
  # Fix shape: rename /etc/reproos/auto-config.toml so the
  # installer autostart script's presence check fails, short-
  # circuiting the installer block.  Keep the .toml file
  # available under an alternate name for manual re-run + a
  # comment marker so future audit can trace the rename.
  if [ -f '$ROOT_TREE/etc/reproos/auto-config.toml' ]; then
    mv '$ROOT_TREE/etc/reproos/auto-config.toml' \
       '$ROOT_TREE/etc/reproos/auto-config.toml.M9R71-disabled-post-install'
  fi

  # M9.R.56.8.7: create /run/user/1000 out-of-band + export
  # XDG_RUNTIME_DIR in the sway session environment.
  #
  # Phase B evidence after M9.R.56.8.6 (system journal +
  # wayland-session.log):
  #
  #   systemd-logind: Failed to start user service
  #   'user-runtime-dir@1000.service': Failed to execute program
  #   org.freedesktop.systemd1: Permission denied
  #
  #   wayland-session.log: XDG_RUNTIME_DIR is not set in the
  #   environment. Aborting.
  #
  # Root cause: pam_systemd.so calls systemd-logind over dbus
  # to CreateSession(); logind then tries to start
  # user-runtime-dir@1000.service by activating org.freedesktop.
  # systemd1 over the system bus.  The bus service file
  # /usr/share/dbus-1/system-services/org.freedesktop.systemd1.service
  # has ``Exec=/bin/false SystemdService=dbus-org.freedesktop.
  # systemd1.service``, which means dbus MUST use
  # ``--systemd-activation`` to route the request to systemd.
  # But the M9.R.56.5 fix stripped ``--systemd-activation`` from
  # dbus.services ExecStart (because the from-source dbus
  # recipe was compiled without libsystemd support), so dbus
  # falls back to executing /bin/false which returns immediately
  # with the systemd-logind Permission denied error.  Net result:
  # /run/user/1000 is never created; XDG_RUNTIME_DIR is never
  # set; sway aborts at startup.
  #
  # Fix: bypass systemd-logind entirely for the runtime-dir
  # creation.  A tmpfiles.d entry creates /run/user/1000 owned
  # by uid 1000 gid 1000 at boot, and a systemd-tmpfiles
  # --create call reruns it after the graphical.target reaches.
  # We ALSO drop /etc/environment.d/50-xdg-runtime-dir.conf
  # exporting XDG_RUNTIME_DIR=/run/user/1000 so sway inherits
  # the variable via /bin/bash --login (the wayland-session
  # script sources /etc/profile which reads
  # /etc/environment.d/).
  #
  # This is a v1 shim.  A future M9.R.57+ rebuild of dbus with
  # ``-Dsystemd=enabled`` restores the standard flow and the
  # tmpfiles.d + environment.d shims become no-ops (systemd-
  # logind then handles /run/user/<uid> normally).
  mkdir -p '$ROOT_TREE/etc/tmpfiles.d'
  cat > '$ROOT_TREE/etc/tmpfiles.d/m9r56-8-xdg-runtime.conf' <<'TMPFILES_EOF'
# M9.R.56.8.7 --- create /run/user/1000 for the autologin repro
# user to bypass systemd-logind's user-runtime-dir@.service (which
# fails because dbus can't systemd-activate org.freedesktop.systemd1).
d /run/user 0755 root root -
d /run/user/1000 0700 1000 1000 -
TMPFILES_EOF

  mkdir -p '$ROOT_TREE/etc/environment.d'
  cat > '$ROOT_TREE/etc/environment.d/50-xdg-runtime-dir.conf' <<'ENVD_EOF'
# M9.R.56.8.7 --- export XDG_RUNTIME_DIR to /run/user/1000
# (the tmpfiles.d entry above creates the dir).  The wayland-
# session script sources /etc/profile which reads
# /etc/environment.d/ via pam_env.so, so sway inherits this.
XDG_RUNTIME_DIR=/run/user/1000
ENVD_EOF

  # Also add to /etc/environment (single-line, older-style) as
  # a belt-and-suspenders fallback for shells that don't process
  # /etc/environment.d/.
  if ! grep -q '^XDG_RUNTIME_DIR=' '$ROOT_TREE/etc/environment' 2>/dev/null; then
    echo 'XDG_RUNTIME_DIR=/run/user/1000' >> '$ROOT_TREE/etc/environment'
  fi

  # /usr/local/lib/sddm/sddm.conf.d -> /etc/sddm.conf.d so the
  # daemon's SYSTEM_CONFIG_DIR probe finds any drop-ins.
  mkdir -p '$ROOT_TREE/usr/local/lib/sddm' '$ROOT_TREE/usr/lib/sddm'
  ln -sfn /etc/sddm.conf.d '$ROOT_TREE/usr/local/lib/sddm/sddm.conf.d'
  ln -sfn /etc/sddm.conf.d '$ROOT_TREE/usr/lib/sddm/sddm.conf.d'

  # --- Config-file overrides (belt-and-suspenders) ---
  # If a future sddm rebuild moves to CMAKE_INSTALL_PREFIX=/usr
  # the shim symlinks above become no-ops; the config overrides
  # continue to pin the paths.  Every key here mirrors a
  # Configuration.h Entry whose default embeds LIBEXEC_INSTALL_DIR
  # or DATA_INSTALL_DIR.
  cat > '$ROOT_TREE/etc/sddm.conf.d/10-paths.conf' <<'SDDM_PATHS_EOF'
[Theme]
ThemeDir=/usr/share/sddm/themes
FacesDir=/usr/share/sddm/faces

[X11]
SessionCommand=/usr/share/sddm/scripts/Xsession
DisplayCommand=/usr/share/sddm/scripts/Xsetup
DisplayStopCommand=/usr/share/sddm/scripts/Xstop
SessionDir=/usr/share/xsessions

[Wayland]
SessionCommand=/usr/share/sddm/scripts/wayland-session
SessionDir=/usr/share/wayland-sessions
SDDM_PATHS_EOF

  # --- Instrumentation: strace sddm's ExecStart ---
  # Diag files land in /var/log/m9r56_diag/ so a
  # post-boot qemu-nbd inspection can pull them.  strace
  # follows forks to capture sddm-helper spawn behaviour +
  # session command exec + PAM helper invocations.
  mkdir -p '$ROOT_TREE/var/log/m9r56_diag'
  mkdir -p '$ROOT_TREE/etc/systemd/system/sddm.service.d'
  cat > '$ROOT_TREE/etc/systemd/system/sddm.service.d/50-strace.conf' <<'SDDM_STRACE_EOF'
[Service]
# M9.R.56.8: wrap sddm with strace -f so the sddm ->
# sddm-helper -> sway spawn chain is captured.  The
# --absolute-timestamps + -f flags follow every child and
# tag every syscall with wall-clock time.  Output goes to
# /var/log/m9r56_diag/sddm-strace.log for post-boot
# extraction.  We trace only the syscalls that reveal the
# session-launch path (execve, openat, connect, dup2,
# setuid, setgid, fork, clone, wait4, kill, exit, exit_group).
ExecStart=
ExecStart=/usr/bin/strace -f -tt -o /var/log/m9r56_diag/sddm-strace.log -e trace=execve,openat,connect,dup2,setuid,setgid,fork,clone,wait4,kill,exit,exit_group /usr/bin/sddm
SDDM_STRACE_EOF

  # --- Instrumentation: post-boot journal capture ---
  # A one-shot unit that runs after graphical.target and
  # dumps the sddm.service + sddm-autologin PAM logs to
  # /var/log/m9r56_diag/sddm-journal.txt.  Runs with a
  # 30 s delay so sddm has time to emit any startup errors.
  cat > '$ROOT_TREE/etc/systemd/system/m9r56-diag.service' <<'M9R56_DIAG_EOF'
[Unit]
Description=M9.R.56.8 diagnostic journal capture
After=graphical.target
Wants=graphical.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/mkdir -p /var/log/m9r56_diag
ExecStartPre=/bin/sh -c 'sleep 30'
ExecStart=/bin/sh -c 'journalctl --no-pager -u sddm.service > /var/log/m9r56_diag/sddm-journal.txt 2>&1 || true'
ExecStart=/bin/sh -c 'journalctl --no-pager _PID=1 > /var/log/m9r56_diag/systemd-pid1.txt 2>&1 || true'
ExecStart=/bin/sh -c 'ls -la /var/log/m9r56_diag/ > /var/log/m9r56_diag/ls.txt 2>&1'
ExecStart=/bin/sh -c 'systemctl status sddm.service --no-pager > /var/log/m9r56_diag/sddm-status.txt 2>&1 || true'
ExecStart=/bin/sh -c 'systemctl list-units --failed --no-pager > /var/log/m9r56_diag/failed-units.txt 2>&1 || true'
ExecStart=/bin/sh -c 'ps auxf > /var/log/m9r56_diag/ps.txt 2>&1'
ExecStart=/bin/sh -c 'ls -laR /run/user > /var/log/m9r56_diag/run-user.txt 2>&1 || true'

[Install]
WantedBy=graphical.target
M9R56_DIAG_EOF
  mkdir -p '$ROOT_TREE/etc/systemd/system/graphical.target.wants'
  ln -sfn /etc/systemd/system/m9r56-diag.service \
    '$ROOT_TREE/etc/systemd/system/graphical.target.wants/m9r56-diag.service'
" || { echo "[configure-installed-root] Phase 10.8 sddm path shims + instrumentation failed" >&2; exit 74; }

# ---------------------------------------------------------------
# Phase 10.9: install + enable the seatd system service so libseat's
# seatd backend can mediate DRM + tty access without going through
# systemd-logind.  Rationale (M9.R.58.2):
#
# M9.R.57 closed the wlroots compile-time gate but sway still fails
# to start a session at runtime with:
#
#   [wlr] [libseat] [logind.c:621] Could not get primary session for user: No data available
#   [wlr] [libseat] [common/terminal.c:162] Could not open target tty: Permission denied
#   [wlr] backend/backend.c:399 Failed to start a DRM session
#
# Root cause (see recipes/reproos-image/run-evidence/m9r58/
# m9r58_phaseA_pam_audit.txt): pam_systemd IS invoked in the sddm-
# autologin PAM stack (M9.R.56.8.6), IS reaching dbus, but its
# CreateSession() side effect ``/run/systemd/users/1000`` is never
# created.  logind's CreateSession call to PID-1 systemd's
# StartTransientUnit needs dbus --systemd-activation, which the
# from-source dbus recipe was compiled without (per M9.R.56.5).
# libseat then falls through to the builtin backend which needs
# cap_sys_admin or video-group ownership on tty0 (uid 1000 has
# neither).
#
# Fix: enable libseat's ``seatd`` backend and ship the seatd daemon
# as a system service (Shape 5 in the Phase A audit).  seatd runs
# as root, listens on /run/seatd.sock, and hands out fd's for
# /dev/dri/* and /dev/tty* to libseat clients that connect + prove
# group membership (via the seatd socket group).  This bypasses
# logind entirely.  Requires:
#
#   1. libseat rebuilt with libseat-seatd=enabled + server=enabled
#      (M9.R.58.2 flipped these in recipes/packages/source/libseat/
#      repro.nim).
#   2. seatd daemon binary shadow-linked into /usr/bin/seatd (via
#      stage-de-rootfs.sh's normal link_base_recipe_binaries pass).
#   3. This phase: /etc/systemd/system/seatd.service + a
#      graphical.target.wants symlink so seatd starts BEFORE sddm.
#   4. This phase: add the ``repro`` user to the ``seat`` group so
#      the wayland-session process can open /run/seatd.sock.
# ---------------------------------------------------------------
echo "[configure-installed-root] Phase 10.9: install + enable seatd system service (libseat seatd backend)"

"$SUDO" bash -c "
  set -euo pipefail

  # Shadow-link the seatd daemon binary from the libseat install-
  # mirror.  stage-de-rootfs.sh's link_base_recipe_binaries only
  # walks /usr/bin + /usr/sbin of each install-mirror, but the
  # libseat recipe installs seatd + seatd-launch under
  # <install>/usr/bin, so those should already be linked.  Belt-
  # and-suspenders: force-link them here in case the recipe layout
  # changes.
  LIBSEAT_INSTALL='$SOURCE_RECIPES_ROOT/libseat/.repro/output/install/usr/bin'
  LIBSEAT_INSTALL_HOST='$ROOT_TREE$SOURCE_RECIPES_ROOT/libseat/.repro/output/install/usr/bin'
  if [ -x \"\$LIBSEAT_INSTALL_HOST/seatd\" ]; then
    ln -sfn \"\$LIBSEAT_INSTALL/seatd\" '$ROOT_TREE/usr/bin/seatd'
  else
    echo '[configure-installed-root] warning: seatd binary not at expected install-mirror path' >&2
  fi
  if [ -x \"\$LIBSEAT_INSTALL_HOST/seatd-launch\" ]; then
    ln -sfn \"\$LIBSEAT_INSTALL/seatd-launch\" '$ROOT_TREE/usr/bin/seatd-launch'
  fi

  # M9.R.69.3 — patchelf the on-disk copies of seatd + seatd-launch +
  # libseat.so.1 to prepend the glibc lib dir (extracted from the
  # ELF interpreter path) to DT_RUNPATH.  Without this, ld-linux
  # falls through the recipe RUNPATH (which meson populated with
  # only meson + systemd + clingo + gcc-lib dirs, no glibc), reads
  # /etc/ld.so.cache, and picks up the Debian base-rootfs glibc as
  # libc.so.6.  A Nix 2.40 ld-linux + Debian 2.41 libc pair AVs
  # seatd inside __libc_start_main with 'segfault at 2 ip 0x2' -
  # the exact class M9.R.58.3 characterised.  _m9r58_swap.sh applied
  # this patchelf on the qcow2 but never landed the fix into the
  # reproducible build path; M9.R.68 clean-rebuild regressed it.
  # This phase lands the fix inside build-reproos-image.sh so
  # every future clean rebuild patches the RPATH deterministically.
  PATCHELF='$PATCHELF_BIN'
  if [ -n \"\$PATCHELF\" ]; then
    LIBSEAT_INSTALL_ROOT='$ROOT_TREE$SOURCE_RECIPES_ROOT/libseat/.repro/output/install'
    for target in \\
      \"\$LIBSEAT_INSTALL_ROOT/usr/bin/seatd\" \\
      \"\$LIBSEAT_INSTALL_ROOT/usr/bin/seatd-launch\" \\
      \"\$LIBSEAT_INSTALL_ROOT/usr/lib/libseat.so.1\"; do
      if [ ! -f \"\$target\" ]; then
        echo \"[configure-installed-root] warning: patchelf target not present: \$target\" >&2
        continue
      fi
      ip=\$(\"\$PATCHELF\" --print-interpreter \"\$target\" 2>/dev/null || true)
      glibc_libdir=\"\"
      if [ -n \"\$ip\" ]; then
        # /repro/store/<hash>-glibc-<ver>/lib/ld-linux-x86-64.so.2
        # -> /repro/store/<hash>-glibc-<ver>/lib
        glibc_libdir=\"\${ip%/ld-linux-x86-64.so.2}\"
      fi
      # Libraries (libseat.so.1) don't have an interpreter but link the same
      # glibc as the executables through their meson-recorded RPATH origin.
      # Fall back to extracting the glibc lib dir from seatd's interpreter.
      if [ -z \"\$glibc_libdir\" ]; then
        SEATD_BIN=\"\$LIBSEAT_INSTALL_ROOT/usr/bin/seatd\"
        if [ -f \"\$SEATD_BIN\" ]; then
          seatd_ip=\$(\"\$PATCHELF\" --print-interpreter \"\$SEATD_BIN\" 2>/dev/null || true)
          if [ -n \"\$seatd_ip\" ]; then
            glibc_libdir=\"\${seatd_ip%/ld-linux-x86-64.so.2}\"
          fi
        fi
      fi
      if [ -z \"\$glibc_libdir\" ]; then
        echo \"[configure-installed-root] warning: could not determine glibc lib dir for \$target - skipping patchelf\" >&2
        continue
      fi
      rp=\$(\"\$PATCHELF\" --print-rpath \"\$target\" 2>/dev/null || true)
      if [ -z \"\$rp\" ]; then
        new_rp=\"\$glibc_libdir\"
      else
        case \":\$rp:\" in
          *\":\$glibc_libdir:\"*)
            # Already contains the glibc lib dir — nothing to do.
            continue ;;
          *)
            new_rp=\"\$glibc_libdir:\$rp\" ;;
        esac
      fi
      \"\$PATCHELF\" --set-rpath \"\$new_rp\" \"\$target\"
      echo \"[configure-installed-root] patchelf --set-rpath: prepended \$glibc_libdir to \$target\"
    done
  else
    echo '[configure-installed-root] warning: patchelf not found on PATH - libseat RPATH glibc-lib-dir prepend SKIPPED. seatd will crash at ip=0x2 on boot per M9.R.58.3.' >&2
  fi

  # Create the ``seat`` group used by seatd's socket ownership.
  # Uses a fixed high GID (985) so successive image builds are
  # reproducible.  Idempotent: skip if the group already exists.
  if ! grep -q '^seat:' '$ROOT_TREE/etc/group' 2>/dev/null; then
    echo 'seat:x:985:repro' >> '$ROOT_TREE/etc/group'
  fi

  # Systemd unit for the seatd daemon.  Runs as root (needs
  # CAP_SYS_ADMIN to open /dev/tty0 etc.), sets socket ownership
  # to the ``seat`` group so unprivileged wayland-session
  # processes can connect.
  cat > '$ROOT_TREE/etc/systemd/system/seatd.service' <<'SEATD_UNIT_EOF'
[Unit]
Description=Seat management daemon
Documentation=man:seatd(1)
DefaultDependencies=no
After=systemd-user-sessions.service
# Must be up BEFORE sddm.service since sddm-helper's wayland-session
# spawns sway (via libseat) which connects to /run/seatd.sock.
Before=sddm.service

[Service]
Type=simple
ExecStart=/usr/bin/seatd -g seat
Restart=always
RestartSec=1

[Install]
WantedBy=graphical.target
SEATD_UNIT_EOF

  # Enable the unit in graphical.target so it starts on boot.
  mkdir -p '$ROOT_TREE/etc/systemd/system/graphical.target.wants'
  ln -sfn /etc/systemd/system/seatd.service \\
    '$ROOT_TREE/etc/systemd/system/graphical.target.wants/seatd.service'
" || { echo "[configure-installed-root] Phase 10.9 seatd install failed" >&2; exit 75; }

# ---------------------------------------------------------------
# Phase 10.10: install the post-boot acceptance check. Its serial
# sentinel is the VM harness contract for an installed, graphical,
# replayable system rather than merely a kernel-booted image.
# ---------------------------------------------------------------
echo "[configure-installed-root] Phase 10.10: install post-boot health gate"
"$SUDO" bash -c "
  set -euo pipefail
  install -m 0755 '$SCRIPT_DIR_SELF/reproos-health-check' \
    '$ROOT_TREE/usr/local/sbin/reproos-health-check'
  cat > '$ROOT_TREE/etc/systemd/system/reproos-health-check.service' <<'HEALTH_UNIT_EOF'
[Unit]
Description=ReproOS post-installation acceptance check
After=sddm.service seatd.service reproos-first-boot-enroll.service reproos-network.service
Requires=reproos-first-boot-enroll.service reproos-network.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/reproos-health-check
TimeoutStartSec=180
RemainAfterExit=yes

[Install]
WantedBy=graphical.target
HEALTH_UNIT_EOF
  mkdir -p '$ROOT_TREE/etc/systemd/system/graphical.target.wants'
  ln -sfn /etc/systemd/system/reproos-health-check.service \
    '$ROOT_TREE/etc/systemd/system/graphical.target.wants/reproos-health-check.service'
" || { echo "[configure-installed-root] Phase 10.10 health gate install failed" >&2; exit 76; }

echo "[configure-installed-root] OK $ROOT_TREE"
exit 0
