#!/usr/bin/env python3
"""Validate the source-only composition of the ReproOS build graph."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_RECIPE = ROOT / "repro.nim"
INSTALLER_RECIPE = ROOT / "apps/reproos-installer/package.nim"
ISO_RECIPE = ROOT / "recipes/reproos-iso/package.nim"
IMAGE_RECIPE = ROOT / "recipes/reproos-image/package.nim"
WORKFLOW_RECIPE = ROOT / "repro/workflows.nim"
PACKAGE_SETS = ROOT / "repro/package_sets.nim"
STAGE_ROOTFS_SCRIPT = ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh"
NORMALIZE_RUNTIME_SCRIPT = (
    ROOT / "recipes/reproos-iso/scripts/normalize-source-runtime.sh"
)
CONTRIBUTOR_GUIDE = ROOT / "AGENTS.md"
README = ROOT / "README.md"


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require_contains(path: Path, values: list[str], subject: str) -> None:
    content = source(path)
    for value in values:
        if value not in content:
            raise AssertionError(f"{subject} is missing: {value}")


def build_dependencies(path: Path) -> list[str]:
    match = re.search(
        r"^  buildDeps:\r?\n(?P<body>.*?)(?=^  [A-Za-z][A-Za-z0-9]*:)",
        source(path),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"buildDeps block missing in {path}")
    return re.findall(r'"([^"]+)"', match.group("body"))


def uses_dependencies(path: Path) -> list[str]:
    match = re.search(
        r"^  uses:\r?\n(?P<body>.*?)(?=^  [A-Za-z][A-Za-z0-9]*:)",
        source(path),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"uses block missing in {path}")
    return re.findall(r'"([^"]+)"', match.group("body"))


def canonical_rootfs_packages() -> list[str]:
    match = re.search(
        r"ReproosGraphicalRootfsPackages\*\s*=\s*@\[(?P<body>.*?)^\]",
        source(PACKAGE_SETS),
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError("canonical graphical rootfs package set is missing")
    return re.findall(r'"([^"]+)"', match.group("body"))


def require_unique(values: list[str], subject: str) -> None:
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        raise AssertionError(f"{subject} contains duplicates: {', '.join(duplicates)}")


def shell_call_blocks(path: Path) -> list[tuple[str, str]]:
    """Return (binding, call text) pairs for balanced ``shell(...)`` calls."""
    content = source(path)
    calls: list[tuple[str, str]] = []
    for match in re.finditer(r"\blet\s+(\w+)\s*=\s*shell\(", content):
        depth = 1
        quote = ""
        escaped = False
        cursor = match.end()
        while cursor < len(content) and depth > 0:
            char = content[cursor]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
            elif char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth != 0:
            raise AssertionError(f"unbalanced shell call for {match.group(1)} in {path}")
        calls.append((match.group(1), content[match.start():cursor]))
    return calls


def require_shell_action_contracts(path: Path) -> None:
    content = source(path)
    for binding, call in shell_call_blocks(path):
        if "actionId =" not in call:
            raise AssertionError(f"shell action {binding} in {path} has no stable actionId")
        if "extraOutputs =" not in call and "cacheable = false" not in call:
            raise AssertionError(
                f"shell action {binding} in {path} has neither outputs nor cache disabled"
            )
        has_fluent_identities = re.search(
            rf"\blet\s+{re.escape(binding)}\s*=\s*shell\(.*?\)"
            r"\.withToolIdentities\(",
            content,
            flags=re.DOTALL,
        )
        has_explicit_identities = (
            f"appendRegisteredActionToolIdentityRefs({binding}.id" in content
        )
        if not has_fluent_identities and not has_explicit_identities:
            raise AssertionError(
                f"shell action {binding} in {path} has no executable identities"
            )


def main() -> None:
    modules = [
        ROOT_RECIPE,
        INSTALLER_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        WORKFLOW_RECIPE,
        PACKAGE_SETS,
    ]
    for path in modules:
        if not path.is_file():
            raise AssertionError(f"canonical Reprobuild module missing: {path}")

    package_modules = [
        ROOT_RECIPE,
        INSTALLER_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        WORKFLOW_RECIPE,
    ]
    for path in package_modules:
        if 'defaultToolProvisioning "from-source"' not in source(path):
            raise AssertionError(f"package does not default to from-source tools: {path}")
    if "shell(" in source(ROOT_RECIPE) or "command =" in source(ROOT_RECIPE):
        raise AssertionError("root repro.nim must remain a composition manifest")
    for path in [ISO_RECIPE, IMAGE_RECIPE, WORKFLOW_RECIPE]:
        require_shell_action_contracts(path)
    require_contains(
        ISO_RECIPE,
        ['"xorriso"', '"mtools"', '"squashfs-tools"'],
        "ISO source authoring tool interface",
    )

    obsolete = [
        ROOT / "Justfile",
        ROOT / "apps/reproos-installer/repro.nim",
        ROOT / "recipes/reproos-iso/repro.nim",
        ROOT / "recipes/reproos-image/repro.nim",
    ]
    for path in obsolete:
        if path.exists():
            raise AssertionError(f"obsolete parallel contributor interface remains: {path}")

    require_contains(
        ROOT_RECIPE,
        [
            "installerPackage.buildReproosInstallerPackage()",
            "isoPackage.buildReproosIsoPackage()",
            "imagePackage.buildReproosImagePackage()",
            "workflows.buildReproosWorkflowsPackage()",
            'collect("default"',
        ],
        "root graph",
    )

    require_contains(
        INSTALLER_RECIPE,
        [
            'ReproosInstallerReadyActionId* = "install-mirror-reproosInstaller"',
            '".repro/output/install/usr/bin/reproos-installer"',
            "BuildActionDef(id: ReproosInstallerReadyActionId)",
        ],
        "finalized installer package contract",
    )
    require_contains(
        IMAGE_RECIPE,
        [
            'let reproCliInput = reprobuildRoot / "build" / "bin" / "repro"',
            '"REPRO_BIN=\\\"" & reproCliInput & "\\\""',
            "reproCliInput,",
        ],
        "pinned image assembly CLI",
    )

    require_contains(
        ROOT / "tests/test-installed-desktop-screenshot.sh",
        ['--screenshot-delay-sec "${REPROOS_SCREENSHOT_DELAY_SEC:-20}"'],
        "installed desktop graphical settle gate",
    )
    installer_consumers = [
        WORKFLOW_RECIPE,
        ISO_RECIPE,
        IMAGE_RECIPE,
        ROOT / "tools/installer-dev-runtime.sh",
        ROOT / "tests/test-installer-artifacts.sh",
        ROOT / "tests/test-unattended-install.sh",
        ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh",
    ]
    for path in installer_consumers:
        content = source(path)
        if "ReproosInstallerInstallActionId" in content:
            raise AssertionError(f"installer consumer bypasses finalization: {path}")
        if "build/reproos-installer/out/usr/bin/reproos-installer" in content:
            raise AssertionError(f"installer consumer uses raw CMake output: {path}")

    for path in modules[1:]:
        content = source(path)
        if "devEnv:" in content:
            raise AssertionError(f"package module duplicates workflows through devEnv: {path}")
        if re.search(r"M9\.[A-Za-z0-9.]+", content) or "historical" in content.lower():
            raise AssertionError(f"package module contains milestone archaeology: {path}")

    iso_dependencies = build_dependencies(ISO_RECIPE)
    image_dependencies = build_dependencies(IMAGE_RECIPE)
    canonical_dependencies = canonical_rootfs_packages()
    require_unique(iso_dependencies, "ISO buildDeps")
    require_unique(image_dependencies, "image buildDeps")
    require_unique(canonical_dependencies, "canonical rootfs package set")
    if iso_dependencies != image_dependencies:
        raise AssertionError("ISO and image source package closures differ")
    if iso_dependencies != canonical_dependencies:
        raise AssertionError("buildDeps blocks differ from the canonical rootfs package set")
    if "reproos-installer" in iso_dependencies:
        raise AssertionError("the installer must be an action dependency, not a source package")

    workflow_dependencies = uses_dependencies(WORKFLOW_RECIPE)
    require_unique(workflow_dependencies, "workflow uses")
    if "vm-harness" not in workflow_dependencies:
        raise AssertionError(
            "workflow uses must select the federated vm-harness producer"
        )

    workflow_content = source(WORKFLOW_RECIPE)
    if workflow_content.count("withHostVmRuntime(") != 4:
        raise AssertionError(
            "all direct VM workflows must select the available libvirt runtime"
        )
    require_contains(
        WORKFLOW_RECIPE,
        [
            'export LIBVIRT_DEFAULT_URI=qemu:///session',
            '"boot-iso"',
            '"test-iso"',
            '"boot-image"',
        ],
        "host VM runtime fallback",
    )

    require_contains(
        WORKFLOW_RECIPE,
        [
            *[f'target("{name}"' for name in [
                "test-source-composition",
                "test-installer-preview",
                "test-installer-visuals",
                "test-installer-artifacts",
                "test-cache-backfill",
                "test-iso",
                "test-image-health",
                "test-installed-desktop",
                "test-unattended-install",
            ]],
            *[f'run("{name}"' for name in [
                "installer",
                "installer-screenshots",
                "installer-accept-goldens",
                "installer-vm-screenshot",
                "cache-backfill",
                "boot-iso",
                "boot-image",
            ]],
            'collect("lint"',
        ],
        "workflow module",
    )

    require_contains(
        WORKFLOW_RECIPE,
        [
            "tools/capture-installer-screens.sh",
            "tools/run-installer-preview.sh",
            "tools/installer-dev-runtime.sh",
            "tests/test-installer-preview.sh",
            "tests/test-installer-visuals.sh",
            "tests/test_installer_visuals.nim",
            "tests/test-installer-vm-screenshot.sh",
            "tests/test-installer-vm-frame.sh",
            "tests/test_installer_vm_frame.nim",
            "tests/test-installer-artifacts.sh",
            "tests/test_cache_reproos_packages.py",
            "tools/cache_reproos_packages.py",
            "tests/test-installed-image-health.sh",
            "tests/test-installed-desktop-screenshot.sh",
            "tests/test-installed-desktop-frame.sh",
            "tests/test_installed_desktop_frame.nim",
            "tests/test-unattended-install.sh",
            "tests/fixtures/auto-config-minimal.toml",
        ],
        "declared workflow inputs",
    )

    require_contains(
        CONTRIBUTOR_GUIDE,
        ["repro lint", "stable action IDs", "executable identities"],
        "contributor graph-quality policy",
    )
    require_contains(README, ["repro lint"], "README quality command")

    iso_content = source(ISO_RECIPE)
    if re.search(r"vendor/(vmlinuz|initrd)", iso_content):
        raise AssertionError("ISO recipe still references a vendored kernel or initramfs")
    for value in [
        "reprobuild-packages/packages/source/kernel",
        "reproos-initramfs.img",
        "REPRO_BUSYBOX_INSTALL_ROOT",
        "REPRO_LIVE_TARGET=graphical",
        'ReproosIsoRootfsActionId* = "reproosIso.stage_rootfs"',
        'extraOutputs = @["build/de-rootfs"]',
        'deps = @[stageRootfsAction.id]',
        'target("rootfs", stageRootfsAction)',
        "setRegisteredActionDependencyPolicy(stageRootfsAction.id",
        "automaticMonitorPolicy(@[rootfsOutputAbs])",
        "setRegisteredActionDependencyPolicy(buildIsoAction.id",
        "automaticMonitorPolicy(@[initramfsOutputAbs, isoOutputAbs])",
        "reproCliInput",
    ]:
        if value not in iso_content:
            raise AssertionError(f"ISO recipe is missing source-build input: {value}")

    image_content = source(IMAGE_RECIPE)
    for value in [
        'import "../reproos-iso/package" as isoPackage',
        'ReproosDiskInitrdActionId* = "reproosImage.build_disk_initrd"',
        'target("disk-initramfs", buildDiskInitrdAction)',
        "isoPackage.ReproosIsoRootfsActionId",
        "isoPackage.ReproosIsoRootfsOutput",
        "ReproosDiskInitrdOutput",
        "cacheable = false",
        'let imageBuildDirAbs = projectRoot / "recipes/reproos-image/build"',
        "setRegisteredActionDependencyPolicy(buildImageAction.id",
        "automaticMonitorPolicy(@[imageBuildDirAbs])",
    ]:
        if value not in image_content:
            raise AssertionError(
                f"image recipe is missing output dependency exclusion: {value}"
            )

    image_script = source(
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh"
    )
    for value in [
        "REPROOS_STAGED_ROOTFS",
        "REPROOS_DISK_INITRD",
        '--kernel "$SOURCE_KERNEL"',
        '--initrd "$DISK_INITRD"',
    ]:
        if value not in image_script:
            raise AssertionError(f"image driver is missing graph input: {value}")
    for legacy in ["REPRO_FORCE_RESTAGE", "stage-de-rootfs.sh \"$STAGE_DIR\""]:
        if legacy in image_script:
            raise AssertionError(f"image driver retains private stage cache: {legacy}")

    active_sources = [
        ISO_RECIPE,
        IMAGE_RECIPE,
        STAGE_ROOTFS_SCRIPT,
        ROOT / "recipes/reproos-iso/scripts/build-initramfs.sh",
        ROOT / "recipes/reproos-image/scripts/build-reproos-image.sh",
    ]
    for path in active_sources:
        content = source(path)
        for legacy in [
            "$REPO_ROOT/recipes/packages/source",
            "/opt/repro/reprobuild/recipes/packages/source",
        ]:
            if legacy in content:
                raise AssertionError(f"legacy source root remains in {path}: {legacy}")

    stage_path = active_sources[2]
    stage_content = source(stage_path)
    stage_requirements = [
        "stage filesystem is case-insensitive",
        'case_probe_lower_inode="$(stat -c %i "$case_probe_dir/lower")"',
        'ln -sfn "$modprobe_target" "$STAGE_DIR/usr/sbin/modprobe"',
        'ln -sfn "$busybox_target" "$STAGE_DIR/usr/bin/hostname"',
        "required source BusyBox hostname applet missing",
        "usr/lib/x86_64-linux-gnu/security",
        "REPRO_RUNTIME_SOURCE_ROOT:-/opt/repro/reprobuild-packages/packages/source",
        "rewrote $rewritten_source_links build-root source links",
        "required source D-Bus configuration missing",
        "org.freedesktop.login1.service",
        "usr/lib/security/pam_systemd.so",
        "usr/libexec/sddm-helper",
        "auth required pam_permit.so",
        "session include common-session",
        "etc/pam.d/systemd-user",
        "required source graphics runtime data missing",
        "usr/lib/dri/virtio_gpu_dri.so",
        "FONTCONFIG_PATH=/usr/etc/fonts",
        "LIBGL_DRIVERS_PATH=/usr/lib/dri",
        "export QT_QUICK_BACKEND=software",
        "export WLR_RENDERER=pixman",
        'qtpkg_prefix="/opt/repro/reprobuild-packages/packages/source/${repro_qt_pkg}/.repro/output/install/usr"',
        "${qtpkg_prefix}/plugins/platforms",
        "Environment=LANG=C.UTF-8",
        "packages/source/gcc/.repro/output/install/usr/lib64",
        "required source repro runtime library directory missing",
        '--set-rpath "$repro_runtime_rpath" "$STAGE_DIR/usr/bin/repro"',
        '/usr/bin/reproos-installer-launcher.sh "$@"',
        "link_entry sway swaymsg",
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        'if [ "$(id -u)" -eq 0 ] && [ "$(tty)" = "/dev/tty1" ]',
        "source glibc C.UTF-8 locale generation failed",
        "--no-archive",
        "usr/lib/locale/C.utf8/LC_CTYPE",
        "usr/lib/locale/C.utf8/LC_MESSAGES/SYS_LC_MESSAGES",
        'I18NPATH="$SOURCE_GLIBC_LOCALEDATA"',
        '"$SRC_RECIPES_ROOT/glibc/src/version.h"',
        'localedef_runner="$(realpath -m "$STAGE_DIR/tmp/reproos-localedef")"',
        'SOURCE_GLIBC_LOADER_RUNNER="$(realpath -m "$SOURCE_GLIBC_LOADER_STAGED")"',
        'SOURCE_GLIBC_RUNTIME_DIR_RUNNER="$(realpath -m "$SOURCE_GLIBC_RUNTIME_DIR_STAGED")"',
        '"$patchelf_bin" --force-rpath',
        '"$localedef_runner"',
        'SOURCE_RUNTIME_REPRO_BIN="${REPRO_CLI_BIN:-${REPROBUILD_SRC:-$REPO_ROOT/../reprobuild}/build/bin/repro}"',
        'resolve_staged_image_path "/sbin/ldconfig"',
        'ldconfig_runner="$(realpath -m "$STAGE_DIR/tmp/reproos-ldconfig")"',
        "source ldconfig must be dynamically linked for observable cache generation",
        '"$ldconfig_runner" -r "$STAGE_DIR"',
        '"$STAGE_DIR$SOURCE_GLIBC_LOADER"',
        '"$SOURCE_GLIBC_VERSION"',
        '"$ISO_SRC_MIRROR_ROOT"/*) continue',
        'resolve_staged_image_path "$image_link"',
    ]
    for value in stage_requirements:
        if value not in stage_content:
            raise AssertionError(f"ISO staging is missing runtime surface: {value}")
    for obsolete_invocation in [
        '"$busybox_src" --list',
        '"$SOURCE_GLIBC_LOADER_STAGED" --version',
    ]:
        if obsolete_invocation in stage_content:
            raise AssertionError(
                "ISO staging executes an image-owned validation helper: "
                f"{obsolete_invocation}"
            )

    for package in ["pam", "kbd"]:
        if re.search(
            rf"BASE_USERSPACE_RECIPES=\(.*?^  {re.escape(package)}$.*?^\)",
            stage_content,
            flags=re.MULTILINE | re.DOTALL,
        ) is None:
            raise AssertionError(f"source {package} is not in base userspace staging")
    for package in ["clingo", "qt6-wayland"]:
        if package not in iso_dependencies:
            raise AssertionError(f"source {package} is not in the bootable package closure")
    if "required source loadkeys binary missing" not in stage_content:
        raise AssertionError("source kbd runtime validation is missing")

    require_contains(
        NORMALIZE_RUNTIME_SCRIPT,
        [
            "SOURCE_GLIBC_VERSION [EXTRA_ELF ...]",
            'source_glibc_version="$4"',
            "stage_path_is_executable",
            'staged_path="$stage_dir$link_target"',
            'if ! stage_path_is_executable "$target"',
            'run_patchelf_mutation "$elf" set-interpreter',
            '[ "$old_interpreter" != "$source_glibc_loader" ]',
            "patchelf failed for ${elf#$stage_dir}",
        ],
        "source runtime normalization",
    )
    if '"$source_glibc_loader_staged" --version' in source(
        NORMALIZE_RUNTIME_SCRIPT
    ):
        raise AssertionError("runtime normalization executes the image-owned loader")
    base_rootfs_content = source(
        ROOT / "recipes/reproos-iso/scripts/build-base-rootfs.sh"
    )
    if re.search(r"(^|\s)chown\s", base_rootfs_content):
        raise AssertionError("base rootfs staging must remain unprivileged")
    for ownership_flag in ["--numeric-owner", "--owner=0", "--group=0"]:
        if ownership_flag not in base_rootfs_content:
            raise AssertionError(
                f"base rootfs staging is missing deterministic ownership: {ownership_flag}"
            )
    require_contains(
        ROOT / "recipes/reproos-iso/scripts/build-iso.sh",
        ['-p "home/live m 0700 1000 1002"'],
        "SquashFS staging",
    )
    require_contains(
        ROOT / "apps/reproos-installer/qml/main.qml",
        ['import "components"', "color: Theme.canvas", 'id: "deSelect"', 'id: "finished"'],
        "installer chrome",
    )

    desktop_content = source(ROOT / "apps/reproos-installer/qml/screens/DeSelect.qml")
    if 'title: "Sway"' not in desktop_content:
        raise AssertionError("installer does not expose the source-built Sway desktop")
    for desktop in ["KDE Plasma", "GNOME", "Hyprland"]:
        if desktop in desktop_content:
            raise AssertionError(f"installer advertises unavailable desktop: {desktop}")

    require_contains(
        ROOT / "apps/reproos-installer/qml/screens/Activities.qml",
        ["installerState.activeActivities = []"],
        "installer activity screen",
    )

    print(f"Validated {len(iso_dependencies)} source packages in both bootable targets.")


if __name__ == "__main__":
    main()
