param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^repro-test-boot-')]
  [string]$VmName,

  [Parameter(Mandatory = $true)]
  [string]$Output
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ReproOsWindowCapture {
  [StructLayout(LayoutKind.Sequential)]
  public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")]
  public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
  [DllImport("user32.dll")]
  public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint flags);
}
'@
Add-Type -AssemblyName System.Drawing

$process = Get-Process vmconnect -ErrorAction SilentlyContinue |
  Where-Object MainWindowTitle -Like "$VmName*" |
  Select-Object -First 1
if (-not $process) {
  throw "No open Virtual Machine Connection window found for $VmName"
}

$rect = New-Object ReproOsWindowCapture+RECT
if (-not [ReproOsWindowCapture]::GetWindowRect(
    $process.MainWindowHandle, [ref]$rect)) {
  throw "GetWindowRect failed for $VmName"
}

$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
$bitmap = New-Object Drawing.Bitmap $width, $height
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$deviceContext = $graphics.GetHdc()
try {
  if (-not [ReproOsWindowCapture]::PrintWindow(
      $process.MainWindowHandle, $deviceContext, 2)) {
    throw "PrintWindow failed for $VmName"
  }
} finally {
  $graphics.ReleaseHdc($deviceContext)
  $graphics.Dispose()
}

$absoluteOutput = [IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($absoluteOutput)) |
  Out-Null
try {
  $bitmap.Save($absoluteOutput, [Drawing.Imaging.ImageFormat]::Png)
} finally {
  $bitmap.Dispose()
}

Write-Output $absoluteOutput
