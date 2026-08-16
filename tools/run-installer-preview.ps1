[CmdletBinding()]
param(
  [string]$Distro = $(if ($env:REPROOS_WSL_DISTRO) { $env:REPROOS_WSL_DISTRO } else { "repro-ubuntu" }),
  [string]$DependencyRoot = $(if ($env:REPROOS_WSL_BUILD_ROOT) { $env:REPROOS_WSL_BUILD_ROOT } else { "/root/repro-e2e" }),
  [string]$Screen = "welcome",
  [string]$Size = "1180x760",
  [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ($repoRoot -notmatch '^([A-Za-z]):\\(.*)$') {
  throw "The WSL launcher requires a drive-qualified workspace path; got '$repoRoot'."
}
$drive = $Matches[1].ToLowerInvariant()
$tail = $Matches[2] -replace '\\', '/'
$linuxRepo = "/mnt/$drive/$tail"

$noBuildArg = if ($NoBuild) { " --no-build" } else { "" }
$command = @"
set -e
export REPRO_BIN='$DependencyRoot/reprobuild/build/bin/repro'
export REPROBUILD_SOURCE_ROOT='$DependencyRoot/reprobuild'
export REPROBUILD_SRC='$DependencyRoot/reprobuild'
export REPROBUILD_PACKAGES_ROOT='$DependencyRoot/reprobuild-packages'
export REPRO_FROM_SOURCE_ROOT='$DependencyRoot/reprobuild-packages/packages/source'
export REPROBUILD_NIX_DAEMON_BIN='$DependencyRoot/reprobuild/tools/reprobuild-nix-daemon/reprobuild-nix-daemon'
export RUNQUOTAD_BIN='$DependencyRoot/runquota/build/bin/runquotad'
export REPRO_MONITOR_SHIM_LIB='$DependencyRoot/reprobuild/build/lib/librepro_monitor_shim.so'
export REPROBUILD_USE_SYSTEM_HASH_LIBS=1
export BLAKE3_PREFIX=/usr/local XXHASH_PREFIX=/usr/local CLINGO_PREFIX=/usr/local
export PATH=/root/.nix-profile/bin:/nix/var/nix/profiles/default/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd '$linuxRepo'
exec bash tools/run-installer-preview.sh --screen '$Screen' --size '$Size'$noBuildArg
"@

Write-Host "Launching ReproOS installer preview from $repoRoot"
& wsl.exe -d $Distro -u root -- bash -lc $command
exit $LASTEXITCODE
