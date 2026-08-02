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
    'usr/lib/x86_64-linux-gnu/security',
    'REPRO_RUNTIME_SOURCE_ROOT:-/opt/repro/reprobuild-packages/packages/source',
    'rewrote $rewritten_source_links build-root source links',
    'required source D-Bus configuration missing',
    '"$ISO_SRC_MIRROR_ROOT"/*) continue',
    'resolve_staged_image_path "$image_link"')) {
    if (-not $stageSource.Contains($requiredRuntimeSurface)) {
        throw "ISO staging is missing runtime surface: $requiredRuntimeSurface"
    }
}
if ($stageSource -notmatch '(?ms)BASE_USERSPACE_RECIPES=\(.*?^  pam$.*?^\)') {
    throw 'Source PAM is not part of the base userspace staging set.'
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

Write-Host "Validated $($isoDependencies.Count) source packages in both bootable targets."
