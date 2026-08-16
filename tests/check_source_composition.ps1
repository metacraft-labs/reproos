$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$isoRecipe = Join-Path $root 'recipes/reproos-iso/repro.nim'
$imageRecipe = Join-Path $root 'recipes/reproos-image/repro.nim'

function Get-BuildDependencies([string] $Path) {
    $source = Get-Content -LiteralPath $Path -Raw
    $match = [regex]::Match(
        $source,
        '(?ms)^  buildDeps:\r?\n(?<body>.*?)(?=^  [A-Za-z][A-Za-z0-9]*:)')
    if (-not $match.Success) {
        throw "buildDeps block missing in $Path"
    }
    return [regex]::Matches($match.Groups['body'].Value, '"([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique
}

$isoDependencies = @(Get-BuildDependencies $isoRecipe)
$imageDependencies = @(Get-BuildDependencies $imageRecipe)
$difference = Compare-Object $imageDependencies $isoDependencies
if ($difference) {
    $rendered = $difference | Out-String
    throw "ISO and image source package closures differ:`n$rendered"
}

$isoSource = Get-Content -LiteralPath $isoRecipe -Raw
if ($isoSource -match 'vendor/(vmlinuz|initrd)') {
    throw 'ISO recipe still references a vendored kernel or initramfs.'
}
foreach ($required in @(
    'reprobuild-packages/packages/source/kernel',
    'reproos-initramfs.img',
    'REPRO_BUSYBOX_INSTALL_ROOT',
    'REPRO_LIVE_TARGET=graphical')) {
    if (-not $isoSource.Contains($required)) {
        throw "ISO recipe is missing source-build input: $required"
    }
}

$activeSources = @(
    $isoRecipe,
    $imageRecipe,
    (Join-Path $root 'recipes/reproos-iso/scripts/stage-de-rootfs.sh'),
    (Join-Path $root 'recipes/reproos-iso/scripts/build-initramfs.sh'),
    (Join-Path $root 'recipes/reproos-image/scripts/build-reproos-image.sh'))
foreach ($path in $activeSources) {
    $source = Get-Content -LiteralPath $path -Raw
    if ($source.Contains('$REPO_ROOT/recipes/packages/source')) {
        throw "legacy in-tree source root remains in $path"
    }
    if ($source.Contains('/opt/repro/reprobuild/recipes/packages/source')) {
        throw "legacy runtime package mirror remains in $path"
    }
}

$stageSource = Get-Content -LiteralPath $activeSources[2] -Raw
foreach ($requiredRuntimeSurface in @(
    'ln -sfn "$modprobe_target" "$STAGE_DIR/usr/sbin/modprobe"',
    'ln -sfn "$busybox_target" "$STAGE_DIR/usr/bin/hostname"',
    'required source BusyBox hostname applet missing',
    'usr/lib/x86_64-linux-gnu/security',
    'REPRO_RUNTIME_SOURCE_ROOT:-/opt/repro/reprobuild-packages/packages/source',
    'rewrote $rewritten_source_links build-root source links',
    'required source D-Bus configuration missing',
    'org.freedesktop.login1.service',
    'usr/lib/security/pam_systemd.so',
    'usr/libexec/sddm-helper',
    'auth required pam_permit.so',
    'session include common-session',
    'etc/pam.d/systemd-user',
    'required source graphics runtime data missing',
    'usr/lib/dri/virtio_gpu_dri.so',
    'FONTCONFIG_PATH=/usr/etc/fonts',
    'LIBGL_DRIVERS_PATH=/usr/lib/dri',
    'export QT_QUICK_BACKEND=software',
    'export WLR_RENDERER=pixman',
    'qtpkg_prefix="/opt/repro/reprobuild-packages/packages/source/${repro_qt_pkg}/.repro/output/install/usr"',
    '${qtpkg_prefix}/plugins/platforms',
    'Environment=LANG=C.UTF-8',
    'packages/source/gcc/.repro/output/install/usr/lib64',
    'required source repro runtime library directory missing',
    '--set-rpath "$repro_runtime_rpath" "$STAGE_DIR/usr/bin/repro"',
    '/usr/bin/reproos-installer-launcher.sh "$@"',
    'link_entry sway swaymsg',
    'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'if [ "$(id -u)" -eq 0 ] && [ "$(tty)" = "/dev/tty1" ]',
    'source glibc C.UTF-8 locale generation failed',
    'resolve_staged_image_path "/sbin/ldconfig"',
    '"$STAGE_DIR$SOURCE_GLIBC_LOADER"',
    '"$ISO_SRC_MIRROR_ROOT"/*) continue',
    'resolve_staged_image_path "$image_link"')) {
    if (-not $stageSource.Contains($requiredRuntimeSurface)) {
        throw "ISO staging is missing runtime surface: $requiredRuntimeSurface"
    }
}
if ($stageSource -notmatch '(?ms)BASE_USERSPACE_RECIPES=\(.*?^  pam$.*?^\)') {
    throw 'Source PAM is not part of the base userspace staging set.'
}
if ($stageSource -notmatch '(?ms)BASE_USERSPACE_RECIPES=\(.*?^  kbd$.*?^\)') {
    throw 'Source kbd is not part of the base userspace staging set.'
}
if ($isoDependencies -notcontains 'clingo') {
    throw 'Source clingo is not part of the bootable package closure.'
}
if ($isoDependencies -notcontains 'qt6-wayland') {
    throw 'Source qt6-wayland is not part of the bootable package closure.'
}
if (-not $stageSource.Contains('required source loadkeys binary missing')) {
    throw 'Source kbd runtime validation is missing.'
}

$normalizerSource = Get-Content -LiteralPath (
    Join-Path $root 'recipes/reproos-iso/scripts/normalize-source-runtime.sh') -Raw
foreach ($requiredNormalizerSurface in @(
    'stage_path_is_executable',
    'staged_path="$stage_dir$link_target"',
    'if ! stage_path_is_executable "$target"')) {
    if (-not $normalizerSource.Contains($requiredNormalizerSurface)) {
        throw "Source runtime normalization is missing: $requiredNormalizerSurface"
    }
}

$baseRootfsSource = Get-Content -LiteralPath (
    Join-Path $root 'recipes/reproos-iso/scripts/build-base-rootfs.sh') -Raw
if (-not $baseRootfsSource.Contains('chown -R 1000:1002 "$ROOTFS_DIR/home/live"')) {
    throw 'Live user home ownership is not staged.'
}

$buildIsoSource = Get-Content -LiteralPath (
    Join-Path $root 'recipes/reproos-iso/scripts/build-iso.sh') -Raw
if (-not $buildIsoSource.Contains('-p "home/live m 0700 1000 1002"')) {
    throw 'Live user home ownership is not encoded in the SquashFS image.'
}

$installerQml = Get-Content -LiteralPath (
    Join-Path $root 'apps/reproos-installer/qml/main.qml') -Raw
foreach ($requiredInstallerSurface in @(
    'import "components"',
    'color: Theme.canvas',
    'id: "deSelect"',
    'id: "finished"')) {
    if (-not $installerQml.Contains($requiredInstallerSurface)) {
        throw "Installer chrome is missing: $requiredInstallerSurface"
    }
}

$desktopScreen = Get-Content -LiteralPath (
    Join-Path $root 'apps/reproos-installer/qml/screens/DeSelect.qml') -Raw
if (-not $desktopScreen.Contains('title: "Sway"')) {
    throw 'Installer does not expose the source-built Sway desktop.'
}
foreach ($unavailableDesktop in @('KDE Plasma', 'GNOME', 'Hyprland')) {
    if ($desktopScreen.Contains($unavailableDesktop)) {
        throw "Installer advertises unavailable desktop: $unavailableDesktop"
    }
}

$activitiesScreen = Get-Content -LiteralPath (
    Join-Path $root 'apps/reproos-installer/qml/screens/Activities.qml') -Raw
if (-not $activitiesScreen.Contains('installerState.activeActivities = []')) {
    throw 'Installer activity screen does not preserve the validated base profile.'
}
Write-Host "Validated $($isoDependencies.Count) source packages in both bootable targets."
