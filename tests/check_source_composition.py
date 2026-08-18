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
        ['"xorriso"', '"mtools"'],
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

    require_contains(
        WORKFLOW_RECIPE,
        [
            *[f'target("{name}"' for name in [
                "test-source-composition",
                "test-installer-preview",
                "test-installer-visuals",
                "test-installer-artifacts",
                "test-iso",
                "test-image-health",
                "test-unattended-install",
            ]],
            *[f'run("{name}"' for name in [
                "installer",
                "installer-screenshots",
                "installer-accept-goldens",
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
            "tests/test-installer-artifacts.sh",
            "tests/test-installed-image-health.sh",
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
    ]:
        if value not in iso_content:
            raise AssertionError(f"ISO recipe is missing source-build input: {value}")

    active_sources = [
        ISO_RECIPE,
        IMAGE_RECIPE,
        ROOT / "recipes/reproos-iso/scripts/stage-de-rootfs.sh",
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
        'I18NPATH="$SOURCE_GLIBC_LOCALEDATA"',
        'SOURCE_RUNTIME_REPRO_BIN="${REPRO_CLI_BIN:-${REPROBUILD_SRC:-$REPO_ROOT/../reprobuild}/build/bin/repro}"',
        'resolve_staged_image_path "/sbin/ldconfig"',
        '"$STAGE_DIR$SOURCE_GLIBC_LOADER"',
        '"$ISO_SRC_MIRROR_ROOT"/*) continue',
        'resolve_staged_image_path "$image_link"',
    ]
    for value in stage_requirements:
        if value not in stage_content:
            raise AssertionError(f"ISO staging is missing runtime surface: {value}")

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
        ROOT / "recipes/reproos-iso/scripts/normalize-source-runtime.sh",
        [
            "stage_path_is_executable",
            'staged_path="$stage_dir$link_target"',
            'if ! stage_path_is_executable "$target"',
        ],
        "source runtime normalization",
    )
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
