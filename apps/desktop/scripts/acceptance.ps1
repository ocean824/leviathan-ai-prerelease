param([string]$InstallRoot = (Join-Path $env:TEMP "LeviathanAI-PKG001-$PID"))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$bundle = Join-Path $repo 'apps\desktop\src-tauri\target\release\bundle'
$evidence = Join-Path $repo 'infra\packaging'
$installer = Get-ChildItem (Join-Path $bundle 'nsis') -Filter '*-setup.exe' -File |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $installer) { throw 'NSIS installer not found; run build.ps1 first' }
$hash = (Get-FileHash -Algorithm SHA256 $installer.FullName).Hash.ToLowerInvariant()
$checksum = [IO.File]::ReadAllText((Join-Path $bundle 'SHA256SUMS.txt'))
if (-not $checksum.StartsWith($hash)) { throw 'Installer checksum mismatch' }

if (Test-Path $InstallRoot) { throw "Install root already exists: $InstallRoot" }
$install = Start-Process -FilePath $installer.FullName -ArgumentList @('/S', "/D=$InstallRoot") -Wait -PassThru
if ($install.ExitCode -ne 0) { throw "Silent install failed: exit $($install.ExitCode)" }
$appPath = Join-Path $InstallRoot 'leviathan-desktop-shell.exe'
if (-not (Test-Path $appPath)) { throw "Installed executable not found: $appPath" }

$isolatedLocalAppData = Join-Path $env:TEMP "LeviathanAI-PKG001-Data-$PID"
if (Test-Path $isolatedLocalAppData) { throw "Isolated data root already exists: $isolatedLocalAppData" }
New-Item -ItemType Directory -Path $isolatedLocalAppData | Out-Null
$originalLocalAppData = $env:LOCALAPPDATA
$env:LOCALAPPDATA = $isolatedLocalAppData

function Assert-RejectedRequest {
    param([string]$Uri, [string]$Method = 'GET', [hashtable]$Headers = @{}, [string]$ContentType = 'application/x-www-form-urlencoded', [string]$HostOverride = '')
    try {
        if ($HostOverride) {
            $request = [System.Net.HttpWebRequest]::Create($Uri)
            $request.Host = $HostOverride
            $response = $request.GetResponse()
            $status = [int]$response.StatusCode
            $response.Dispose()
            throw "Unexpected accepted $Method request: HTTP $status $Uri"
        } elseif ($Method -eq 'POST') {
            $response = Invoke-WebRequest -Uri $Uri -Method POST -Headers $Headers -Body '' -ContentType $ContentType -UseBasicParsing -TimeoutSec 5
        } else {
            $response = Invoke-WebRequest -Uri $Uri -Method GET -Headers $Headers -UseBasicParsing -TimeoutSec 5
        }
        throw "Unexpected accepted $Method request: HTTP $($response.StatusCode) $Uri"
    } catch [System.Net.WebException] {
        $status = [int]$_.Exception.Response.StatusCode
        if ($status -notin @(403, 421)) { throw "Unexpected rejection status $status for $Method $Uri" }
        return $status
    }
}

try {
$log = Join-Path $env:LOCALAPPDATA 'LeviathanAI\desktop-sidecar.log'
$logOffset = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
$app = Start-Process -FilePath $appPath -PassThru
$port = $null
$health = $null
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    if (Test-Path $log) {
        $bytes = [IO.File]::ReadAllBytes($log)
        if ($bytes.Length -gt $logOffset) {
            $newText = [Text.Encoding]::UTF8.GetString($bytes, [int]$logOffset, $bytes.Length - [int]$logOffset)
            $matchesFound = [regex]::Matches($newText, 'LEVIATHAN_READY port=(\d+)')
            if ($matchesFound.Count -gt 0) {
                $port = [int]$matchesFound[$matchesFound.Count - 1].Groups[1].Value
                try {
                    $health = Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/health" -UseBasicParsing -TimeoutSec 2
                    break
                } catch { }
            }
        }
    }
}
if (-not $health -or $health.StatusCode -ne 200) { throw "Health check failed; see $log" }
$terminal = Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -UseBasicParsing -TimeoutSec 5
if ($terminal.StatusCode -ne 200 -or $terminal.Content -notmatch '<div id="root"></div>') {
    throw 'Terminal HTML failed to load'
}
$riskUri = "http://127.0.0.1:$port/api/risk/status"
$killUri = "http://127.0.0.1:$port/api/omega/kill"
$missingCapabilityStatus = Assert-RejectedRequest -Uri $riskUri
$wrongCapabilityStatus = Assert-RejectedRequest -Uri $riskUri -Headers @{ 'X-Leviathan-Capability' = ('0' * 64) }
$foreignOriginStatus = Assert-RejectedRequest -Uri $killUri -Method POST -Headers @{ Origin = 'https://untrusted.example' }
$missingOriginStatus = Assert-RejectedRequest -Uri $killUri -Method POST
$foreignHostStatus = Assert-RejectedRequest -Uri $riskUri -HostOverride "localhost:$port"

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class DesktopCapture {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window, out RECT rect);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window, int command);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr window, IntPtr after, int x, int y, int width, int height, uint flags);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr window, IntPtr target, uint flags);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string windowClass, string title);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
'@
$deadline = (Get-Date).AddSeconds(10)
do {
    $app.Refresh()
    if ($app.MainWindowHandle -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
} while ((Get-Date) -lt $deadline)
if ($app.MainWindowHandle -eq [IntPtr]::Zero) { throw 'Desktop window did not open' }
$secondApp = Start-Process -FilePath $appPath -PassThru
if (-not $secondApp.WaitForExit(5000)) { throw 'Second shell launch did not exit after focusing the existing instance' }
if ($app.HasExited) { throw 'Original shell exited during duplicate launch' }
$sidecarCountAfterDuplicate = @(Get-CimInstance Win32_Process -Filter "Name = 'leviathan-desktop.exe'" |
    Where-Object { $_.ExecutablePath -like "$InstallRoot*" }).Count
if ($sidecarCountAfterDuplicate -ne 1) { throw "Duplicate launch left $sidecarCountAfterDuplicate sidecars" }
[DesktopCapture]::ShowWindow($app.MainWindowHandle, 9) | Out-Null
if (-not [DesktopCapture]::SetWindowPos($app.MainWindowHandle, [IntPtr](-1), 0, 0, 0, 0, 0x0043)) {
    throw 'Could not bring desktop window above other windows for screenshot'
}
[DesktopCapture]::SetForegroundWindow($app.MainWindowHandle) | Out-Null
Start-Sleep -Seconds 2
$rect = [DesktopCapture+RECT]::new()
if (-not [DesktopCapture]::GetWindowRect($app.MainWindowHandle, [ref]$rect)) { throw 'Could not read window bounds' }
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
if ($width -lt 200 -or $height -lt 200) { throw 'Window bounds are invalid' }
$bitmap = [Drawing.Bitmap]::new($width, $height)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$screenshot = Join-Path $evidence 'acceptance-window.png'
try {
    $deviceContext = $graphics.GetHdc()
    try {
        if (-not [DesktopCapture]::PrintWindow($app.MainWindowHandle, $deviceContext, 2)) {
            throw 'PrintWindow failed to capture the desktop window'
        }
    } finally { $graphics.ReleaseHdc($deviceContext) }
    $bitmap.Save($screenshot, [Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose(); $bitmap.Dispose()
    [DesktopCapture]::SetWindowPos($app.MainWindowHandle, [IntPtr](-2), 0, 0, 0, 0, 0x0043) | Out-Null
}

$sidecar = Get-CimInstance Win32_Process -Filter "Name = 'leviathan-desktop.exe'" |
    Where-Object { $_.ExecutablePath -like "$InstallRoot*" } | Select-Object -First 1
if (-not $sidecar) { throw 'Installed sidecar process was not found for crash test' }
$beforeCrashLogSize = (Get-Item $log).Length
Stop-Process -Id $sidecar.ProcessId -Force
$dialog = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(10)
do {
    $dialog = [DesktopCapture]::FindWindow('#32770', 'Leviathan AI')
    if ($dialog -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
} while ((Get-Date) -lt $deadline)
if ($dialog -eq [IntPtr]::Zero) { throw 'Sidecar crash did not show a restart prompt' }
if (-not [DesktopCapture]::PostMessage($dialog, 0x0111, [IntPtr]6, [IntPtr]::Zero)) {
    throw 'Could not accept the restart prompt'
}
$restartPort = $null
$restartHealth = $null
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $bytes = [IO.File]::ReadAllBytes($log)
    if ($bytes.Length -le $beforeCrashLogSize) { continue }
    $newText = [Text.Encoding]::UTF8.GetString($bytes, [int]$beforeCrashLogSize, $bytes.Length - [int]$beforeCrashLogSize)
    $matchesFound = [regex]::Matches($newText, 'LEVIATHAN_READY port=(\d+)')
    if ($matchesFound.Count -gt 0) {
        $restartPort = [int]$matchesFound[$matchesFound.Count - 1].Groups[1].Value
        try {
            $restartHealth = Invoke-WebRequest -Uri "http://127.0.0.1:$restartPort/api/health" -UseBasicParsing -TimeoutSec 2
            break
        } catch { }
    }
}
if (-not $restartHealth -or $restartHealth.StatusCode -ne 200) { throw 'Sidecar did not restart after prompt' }

if (-not $app.CloseMainWindow()) { throw 'Window refused a normal close request' }
if (-not $app.WaitForExit(10000)) { throw 'Desktop process remained after close' }
Start-Sleep -Seconds 1
$orphans = @(Get-CimInstance Win32_Process -Filter "Name = 'leviathan-desktop.exe'" |
    Where-Object { $_.ExecutablePath -like "$InstallRoot*" })
if ($orphans.Count -gt 0) { throw "Orphan sidecar processes: $($orphans.ProcessId -join ',')" }

$closeDuringSpawnTrials = 0
for ($trial = 0; $trial -lt 4; $trial++) {
    $quickApp = Start-Process -FilePath $appPath -PassThru
    $quickDeadline = (Get-Date).AddSeconds(10)
    do {
        $quickApp.Refresh()
        if ($quickApp.MainWindowHandle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 50
    } while ((Get-Date) -lt $quickDeadline)
    if ($quickApp.MainWindowHandle -eq [IntPtr]::Zero) { throw "Quick-close trial $trial did not open a window" }
    if (-not $quickApp.CloseMainWindow()) { throw "Quick-close trial $trial refused close" }
    if (-not $quickApp.WaitForExit(10000)) { throw "Quick-close trial $trial shell remained running" }
    Start-Sleep -Milliseconds 300
    $quickOrphans = @(Get-CimInstance Win32_Process -Filter "Name = 'leviathan-desktop.exe'" |
        Where-Object { $_.ExecutablePath -like "$InstallRoot*" })
    if ($quickOrphans.Count -gt 0) { throw "Quick-close trial $trial orphaned sidecar" }
    $closeDuringSpawnTrials++
}

$installedSidecars = @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Filter 'leviathan-desktop.exe' -File)
if ($installedSidecars.Count -ne 1) { throw "Expected one installed sidecar, found $($installedSidecars.Count)" }
$python = Join-Path $repo 'apps\desktop\.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { throw "Build Python environment missing: $python" }
$haltOutput = Join-Path $evidence 'halt-acceptance.json'
$haltLog = Join-Path $evidence 'halt-acceptance.log'
& $python (Join-Path $repo 'apps\desktop\scripts\halt-acceptance.py') `
    --sidecar $installedSidecars[0].FullName --local-app-data $isolatedLocalAppData `
    --output $haltOutput | Tee-Object -FilePath $haltLog
if ($LASTEXITCODE -ne 0) { throw "Installed sidecar halt acceptance failed: exit $LASTEXITCODE" }
$haltEvidence = Get-Content -LiteralPath $haltOutput -Raw | ConvertFrom-Json
if (@($haltEvidence.observations).Count -ne 5) { throw 'Halt acceptance ledger is incomplete' }

$uninstaller = Join-Path $InstallRoot 'uninstall.exe'
if (-not (Test-Path $uninstaller)) { throw "Uninstaller missing: $uninstaller" }
$uninstall = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru
if ($uninstall.ExitCode -ne 0) { throw "Silent uninstall failed: exit $($uninstall.ExitCode)" }
Start-Sleep -Seconds 2
if (Test-Path $appPath) { throw 'Program files remained after uninstall' }
$dataRoot = Join-Path $env:LOCALAPPDATA 'LeviathanAI'
if (-not (Test-Path $dataRoot)) { throw 'User data was removed during uninstall' }

$result = [ordered]@{
    installer = $installer.FullName
    sha256 = $hash
    installRoot = $InstallRoot
    installExit = $install.ExitCode
    appPid = $app.Id
    port = $port
    healthStatus = $health.StatusCode
    healthBody = $health.Content
    terminalStatus = $terminal.StatusCode
    terminalHasRoot = $true
    missingCapabilityStatus = $missingCapabilityStatus
    wrongCapabilityStatus = $wrongCapabilityStatus
    foreignOriginStatus = $foreignOriginStatus
    missingOriginStatus = $missingOriginStatus
    foreignHostStatus = $foreignHostStatus
    duplicateLaunchExit = $secondApp.ExitCode
    sidecarsAfterDuplicate = $sidecarCountAfterDuplicate
    screenshot = $screenshot
    restartPromptSeen = $true
    restartPort = $restartPort
    restartHealthStatus = $restartHealth.StatusCode
    sidecarOrphansAfterClose = $orphans.Count
    closeDuringSpawnTrials = $closeDuringSpawnTrials
    haltAcceptance = $haltOutput
    haltObservations = $haltEvidence.observations
    uninstallExit = $uninstall.ExitCode
    programFilesRemoved = $true
    userDataRetained = $true
}
$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'acceptance.json') -Encoding UTF8
$result | ConvertTo-Json -Depth 4
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
}
