param(
    [Parameter(Mandatory = $true)]
    [string]$LicenseWorkerConfig,
    [switch]$SkipNpmCi,
    [switch]$SkipTerminal,
    [switch]$SkipSidecar,
    [switch]$CI
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$desktop = Join-Path $repo 'apps\desktop'
$tauri = Join-Path $desktop 'src-tauri'
$packaging = Join-Path $repo 'infra\packaging'
New-Item -ItemType Directory -Force -Path $packaging | Out-Null
$log = Join-Path $packaging 'build.log'
$nativeLog = Join-Path $packaging 'build-native.log'
Start-Transcript -Path $log -Append | Out-Null
function Resolve-LicenseWorkerConfig {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'License Worker config path must be absolute' }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw 'License Worker config file is missing' }
    $item = Get-Item -LiteralPath $fullPath -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'License Worker config file is invalid'
    }
    try {
        $config = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'License Worker config JSON is invalid'
    }
    if ($config -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'License Worker config is invalid'
    }
    $properties = @($config.PSObject.Properties)
    if ($properties.Count -ne 1 -or $properties[0].Name -cne 'origin' -or
        $properties[0].Value -isnot [string]) {
        throw 'License Worker config is invalid'
    }
    $origin = [string]$properties[0].Value
    $uri = $null
    if (-not [Uri]::TryCreate($origin, [UriKind]::Absolute, [ref]$uri)) {
        throw 'License Worker origin is invalid'
    }
    $canonicalOrigin = $uri.GetLeftPart([UriPartial]::Authority)
    $isExactOrigin = [string]::Equals($origin, $canonicalOrigin, [StringComparison]::Ordinal) -and
        $uri.UserInfo.Length -eq 0 -and $uri.AbsolutePath -eq '/' -and
        $uri.Query.Length -eq 0 -and $uri.Fragment.Length -eq 0
    $isHttps = $uri.Scheme -ceq 'https' -and $uri.Host.Length -gt 0
    $loopbackMatch = [regex]::Match($origin, '^http://(?:localhost|127\.0\.0\.1):([0-9]{1,5})$')
    $port = 0
    $isLoopback = $uri.Scheme -ceq 'http' -and $loopbackMatch.Success -and
        [int]::TryParse($loopbackMatch.Groups[1].Value, [ref]$port) -and
        $port -ge 1 -and $port -le 65535 -and
        ($uri.Host -ceq 'localhost' -or $uri.Host -ceq '127.0.0.1')
    if (-not $isExactOrigin -or -not ($isHttps -or $isLoopback)) {
        throw 'License Worker origin is invalid'
    }
    return $fullPath
}

function Invoke-WithLicenseWorkerConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath, [Parameter(Mandatory = $true)][scriptblock]$Action)
    $name = 'LEVIATHAN_LICENSE_WORKER_CONFIG'
    $previous = [Environment]::GetEnvironmentVariable($name, 'Process')
    try {
        [Environment]::SetEnvironmentVariable($name, $ConfigPath, 'Process')
        & $Action
    } finally {
        [Environment]::SetEnvironmentVariable($name, $previous, 'Process')
    }
}

function Invoke-NativeLogged {
    param([scriptblock]$Action, [string]$Failure)
    $previousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 wraps native stderr as ErrorRecord on 2>&1.
        $ErrorActionPreference = 'Continue'
        & $Action 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $nativeLog -Append
        $nativeExit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($nativeExit -ne 0) { throw "$Failure (exit $nativeExit)" }
}
try {
    $licenseWorkerConfigPath = Resolve-LicenseWorkerConfig -Path $LicenseWorkerConfig
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    $env:CARGO_BUILD_JOBS = '1'
    $env:CARGO_INCREMENTAL = '0'
    $env:CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG = '0'
    $env:UV_PROJECT_ENVIRONMENT = Join-Path $desktop '.venv'
    $env:PYTHONUNBUFFERED = '1'
    $temporary = Join-Path $desktop '.tmp'
    New-Item -ItemType Directory -Force -Path $temporary | Out-Null
    $env:TEMP = $temporary
    $env:TMP = $temporary

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo.exe is not installed' }
    if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) { throw 'rustc.exe is not installed' }
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'uv.exe is not installed' }
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'npm is not installed' }
    Write-Host "Cargo: $(cargo --version)"
    Write-Host "Rust: $(rustc --version)"
    Write-Host "Node: $(node --version)"
    Write-Host "npm: $(npm --version)"
    Write-Host "uv: $(uv --version)"
    Write-Host 'Pinned Tauri CLI: 2.12.0; pinned PyInstaller: 6.22.3'

    $vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
    if ($CI) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'MSVC vswhere.exe is missing' }
        $vsInstallation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -ne 0 -or -not $vsInstallation) { throw 'MSVC C++ build tools were not found by vswhere' }
        $vcvars = Join-Path $vsInstallation 'VC\Auxiliary\Build\vcvars64.bat'
    }
    if (-not (Test-Path -LiteralPath $vcvars -PathType Leaf)) { throw "MSVC vcvars64.bat is missing: $vcvars" }
    $vcEnvironment = & cmd.exe /d /s /c "`"$vcvars`" >nul && set"
    if ($LASTEXITCODE -ne 0) { throw 'vcvars64.bat failed; MSVC/Windows SDK install is incomplete' }
    foreach ($line in $vcEnvironment) {
        if ($line -match '^([^=][^=]*)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
    $link = Get-Command link.exe -ErrorAction SilentlyContinue
    if (-not $link) { throw 'MSVC link.exe is unavailable after vcvars64.bat' }
    Write-Host "Linker: $($link.Source)"

    $lock = Join-Path $repo 'infra\risk\risk_governance.lock.yaml'
    $lockHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $lock).Hash.ToLowerInvariant()
    Write-Host "Risk lock SHA-256: $lockHash"
    $generated = Join-Path $desktop 'sidecar\generated'
    New-Item -ItemType Directory -Force -Path $generated | Out-Null
    [IO.File]::WriteAllText((Join-Path $generated 'build_constants.py'), "RISK_LOCK_SHA256 = '$lockHash'`n", [Text.UTF8Encoding]::new($false))

    Write-Host 'Step 1/3: terminal'
    if ($SkipTerminal) {
        if (-not (Test-Path (Join-Path $repo 'apps\terminal\dist\index.html'))) { throw 'Terminal output missing' }
        Write-Host 'Reusing existing terminal output'
    } else {
        Push-Location (Join-Path $repo 'apps\terminal')
        try {
            if (-not $SkipNpmCi -or -not (Test-Path 'node_modules')) {
                Invoke-NativeLogged { npm ci --no-audit --no-fund } 'npm ci failed'
            }
            Invoke-NativeLogged { npm run build } 'terminal build failed'
        } finally { Pop-Location }
    }

    Write-Host 'Step 2/3: PyInstaller one-folder sidecar'
    if ($SkipSidecar) {
        if (-not (Test-Path (Join-Path $desktop 'sidecar\dist\leviathan-desktop\leviathan-desktop.exe'))) { throw 'Sidecar output missing' }
        Write-Host 'Reusing existing PyInstaller output'
    } else {
        Push-Location $repo
        try {
            Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api --with 'pyinstaller==6.22.3' pyinstaller --noconfirm --clean --distpath (Join-Path $desktop 'sidecar\dist') --workpath (Join-Path $desktop 'sidecar\build') (Join-Path $desktop 'sidecar\leviathan_desktop.spec') } 'PyInstaller build failed'
        } finally { Pop-Location }
    }

    $source = Join-Path $desktop 'sidecar\dist\leviathan-desktop'
    $staged = Join-Path $tauri 'resources\sidecar'
    $stagedFull = [IO.Path]::GetFullPath($staged)
    $desktopFull = [IO.Path]::GetFullPath($desktop).TrimEnd('\') + '\'
    if (-not $stagedFull.StartsWith($desktopFull, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe staged sidecar path' }
    if (Test-Path $staged) { Remove-Item -LiteralPath $staged -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $staged | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $staged -Recurse -Force
    if (-not (Test-Path (Join-Path $staged 'leviathan-desktop.exe'))) { throw 'Staged sidecar executable is missing' }
    $inventoryScript = Join-Path $packaging 'release_manifest.py'
    Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api python $inventoryScript sidecar --repo $repo } 'Fresh staged-sidecar BOM failed'

    $icon = Join-Path $tauri 'icons\icon.ico'
    if (-not (Test-Path $icon)) {
        Add-Type -AssemblyName System.Drawing
        New-Item -ItemType Directory -Force -Path (Split-Path $icon) | Out-Null
        $bitmap = [Drawing.Bitmap]::new(64, 64)
        $graphics = [Drawing.Graphics]::FromImage($bitmap)
        $graphics.Clear([Drawing.Color]::FromArgb(12, 24, 50))
        $font = [Drawing.Font]::new('Arial', 42, [Drawing.FontStyle]::Bold)
        $brush = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(77, 214, 235))
        $graphics.DrawString('L', $font, $brush, 8, 1)
        $stream = [IO.File]::Create($icon)
        try { [Drawing.Icon]::FromHandle($bitmap.GetHicon()).Save($stream) } finally {
            $stream.Dispose(); $brush.Dispose(); $font.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
        }
    }

    Write-Host 'Step 3/3: building Tauri NSIS installer'
    $feedPath = Join-Path $repo 'infra\release\feed.json'
    $publicKeyPath = Join-Path $repo 'infra\release\updater.pub'
    if (-not (Test-Path -LiteralPath $feedPath -PathType Leaf)) { throw 'Updater feed config is missing' }
    if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) { throw 'Updater public key is missing' }
    $feedConfig = Get-Content -LiteralPath $feedPath -Raw | ConvertFrom-Json
    if (-not $feedConfig.base.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase) -or
        -not $feedConfig.endpoint.StartsWith('/v1/updates/desktop/', [StringComparison]::Ordinal)) {
        throw 'Updater feed endpoint is invalid'
    }
    $keyLines = @(Get-Content -LiteralPath $publicKeyPath | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
    if ($keyLines.Count -ne 2 -or $keyLines[0] -notmatch '^untrusted comment: minisign public key:' -or
        $keyLines[1] -notmatch '^[A-Za-z0-9+/=]+$') {
        throw 'Updater public key file is invalid'
    }
    $publicKey = $keyLines -join "`n"
    $endpoint = $feedConfig.base.TrimEnd('/') + $feedConfig.endpoint
    $signingEnabled = -not [string]::IsNullOrWhiteSpace($env:TAURI_SIGNING_PRIVATE_KEY)
    if ($CI) {
        $signingEnabled = $false
        Write-Host 'CI build: updater artifact signing and updater bundles are disabled'
    }
    $configOverride = @{
        bundle = @{ createUpdaterArtifacts = $signingEnabled }
        plugins = @{
            updater = @{
                pubkey = $publicKey
                endpoints = @($endpoint)
                windows = @{ installMode = 'passive' }
            }
        }
    }
    $overridePath = Join-Path $temporary 'tauri-updater-config.json'
    [IO.File]::WriteAllText(
        $overridePath,
        ($configOverride | ConvertTo-Json -Depth 12),
        [Text.UTF8Encoding]::new($false)
    )
    Push-Location $desktop
    try {
        Invoke-WithLicenseWorkerConfig -ConfigPath $licenseWorkerConfigPath -Action {
            Invoke-NativeLogged { npx --yes '@tauri-apps/cli@2.12.0' build --bundles nsis --config $overridePath } 'Tauri/NSIS/updater build failed'
        }
    } finally { Pop-Location }

    $bundle = Join-Path $tauri 'target\release\bundle'
    $installer = Get-ChildItem -LiteralPath (Join-Path $bundle 'nsis') -Filter '*-setup.exe' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $installer) { throw "NSIS installer missing under $bundle" }
    $installerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installer.FullName).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $bundle 'SHA256SUMS.txt'), "$installerHash  $($installer.Name)`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Installer: $($installer.FullName)"
    Write-Host "Installer SHA-256: $installerHash"

    $shellConfig = Get-Content -LiteralPath (Join-Path $tauri 'tauri.conf.json') -Raw | ConvertFrom-Json
    $version = [string]$shellConfig.version
    $signature = $null
    if ($signingEnabled) {
        $updaterArtifact = Get-ChildItem -LiteralPath $bundle -Recurse -Filter '*.nsis.zip' -File |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $updaterArtifact) { throw 'Signed Tauri updater artifact is missing' }
        $signatureFile = Get-Item -LiteralPath ($updaterArtifact.FullName + '.sig') -ErrorAction Stop
        $signature = $signatureFile.FullName
    } else {
        Write-Host 'UNSIGNED UPDATE ARTIFACT'
    }
    $feedManifest = Join-Path $repo 'infra\release\feed_manifest.py'
    $priorManifest = Join-Path $bundle 'latest.json'
    if (Test-Path -LiteralPath $priorManifest -PathType Leaf) {
        Copy-Item -LiteralPath $priorManifest -Destination (Join-Path $temporary 'prior-latest.json') -Force
        $priorManifest = Join-Path $temporary 'prior-latest.json'
    } else {
        $priorManifest = $null
    }
    $pubDate = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    if ($signingEnabled) {
        Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api python $feedManifest --bundle-dir $bundle --feed $feedPath --version $version --notes 'Leviathan AI desktop update' --pub-date $pubDate --signature-file $signature --require-signature --prior-latest $priorManifest } 'Signed update feed manifest failed'
    } elseif ($priorManifest) {
        Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api python $feedManifest --bundle-dir $bundle --feed $feedPath --version $version --notes 'Leviathan AI desktop update' --pub-date $pubDate --prior-latest $priorManifest } 'Unsigned update feed manifest failed'
    } else {
        Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api python $feedManifest --bundle-dir $bundle --feed $feedPath --version $version --notes 'Leviathan AI desktop update' --pub-date $pubDate } 'Unsigned update feed manifest failed'
    }

    $nsisScript = Join-Path $tauri 'target\release\nsis\x64\installer.nsi'
    if (-not (Test-Path -LiteralPath $nsisScript -PathType Leaf)) { throw 'Generated NSIS script is missing' }
    $nsisText = [IO.File]::ReadAllText($nsisScript)
    $webviewMatches = [regex]::Matches($nsisText, '(?m)^!define WEBVIEW2INSTALLERPATH "([^"\r\n]+)"[ \t]*\r?$')
    if ($webviewMatches.Count -ne 1) { throw 'Generated NSIS WebView2 input is missing or ambiguous' }
    $webviewPath = [IO.Path]::GetFullPath($webviewMatches[0].Groups[1].Value)
    $cacheRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'tauri\x64')).TrimEnd('\') + '\'
    if (-not $webviewPath.StartsWith($cacheRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($webviewPath) -ne 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe') {
        throw 'Generated NSIS WebView2 input is outside the expected cache'
    }
    $webview = Get-Item -LiteralPath $webviewPath -ErrorAction Stop
    if ($webview.PSIsContainer -or ($webview.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Generated NSIS WebView2 input is not a regular file'
    }
    $webviewHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $webview.FullName).Hash.ToLowerInvariant()
    Invoke-NativeLogged { uv run --locked --no-dev --package leviathan-api python $inventoryScript release --repo $repo --webview $webview.FullName } 'Release inventory and manifest failed'
    $release = Get-Content -LiteralPath (Join-Path $bundle 'release-manifest.json') -Raw | ConvertFrom-Json
    if ($release.webview.installerCacheSha256 -ne $webviewHash -or
        $release.webview.installerCacheBytes -ne $webview.Length -or
        $release.installer.sha256 -ne $installerHash) {
        throw 'Release manifest hashes do not match the generated NSIS inputs'
    }
    Write-Host "SBOM: $(Join-Path $bundle 'leviathan-sidecar.cdx.json')"
    Write-Host 'Build complete (unsigned; certificate remains an open requirement).'
} finally {
    Stop-Transcript | Out-Null
}
