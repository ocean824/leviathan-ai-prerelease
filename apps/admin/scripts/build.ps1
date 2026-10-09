param(
    [Parameter(Mandatory = $true)][string]$WorkerOrigin,
    [Parameter(Mandatory = $true)][string]$FeedOrigin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-HttpsOrigin([string]$Value, [string]$Name) {
    $parsed = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or $parsed.UserInfo -or $parsed.Query -or $parsed.Fragment -or
        $parsed.AbsolutePath -ne '/') {
        throw "$Name must be a configured HTTPS origin without credentials, path, query, or fragment."
    }
    return $parsed.GetLeftPart([UriPartial]::Authority)
}

$worker = Assert-HttpsOrigin $WorkerOrigin 'WorkerOrigin'
$feed = Assert-HttpsOrigin $FeedOrigin 'FeedOrigin'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$admin = Join-Path $repo 'apps\admin'
$ui = Join-Path $admin 'ui'
$tauri = Join-Path $admin 'src-tauri'
$publicKeyPath = Join-Path $repo 'infra\release\updater.pub'

if (-not (Test-Path -LiteralPath $publicKeyPath -PathType Leaf)) {
    throw 'Release build blocked: canonical infra/release/updater.pub is not integrated.'
}
if (-not $env:TAURI_SIGNING_PRIVATE_KEY) {
    throw 'Release build blocked: coordinator signing key was not injected.'
}
$keyLines = @(Get-Content -LiteralPath $publicKeyPath -Encoding utf8)
if ($keyLines.Count -ne 2 -or $keyLines[0] -notmatch '^untrusted comment: minisign public key: [a-f0-9]{16}$' -or
    $keyLines[1] -notmatch '^RW[A-Za-z0-9+/]{42,50}$') {
    throw 'Release build blocked: updater public-key file is malformed.'
}

$configPath = Join-Path $tauri 'tauri.conf.json'
$config = Get-Content -LiteralPath $configPath -Raw -Encoding utf8 | ConvertFrom-Json
$config.app.security.csp = "default-src 'self'; connect-src 'self' $worker; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
$config.plugins.updater.pubkey = $keyLines -join "`n"
$config.plugins.updater.endpoints = @("$feed/v1/updates/admin/{{target}}/{{arch}}/{{current_version}}")
$temporaryConfig = Join-Path ([IO.Path]::GetTempPath()) ("admin-tauri-" + [Guid]::NewGuid().ToString('N') + '.json')
try {
    [IO.File]::WriteAllText($temporaryConfig, ($config | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
    $env:VITE_ADMIN_WORKER_ORIGIN = $worker
    $env:CARGO_BUILD_JOBS = '1'

    Push-Location $ui
    try {
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "Admin UI build failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }

    Push-Location $admin
    try {
        npx --yes '@tauri-apps/cli@2.12.0' build --bundles nsis --config $temporaryConfig
        if ($LASTEXITCODE -ne 0) { throw "Admin Tauri/NSIS build failed (exit $LASTEXITCODE)." }
    } finally { Pop-Location }
} finally {
    if (Test-Path -LiteralPath $temporaryConfig) { Remove-Item -LiteralPath $temporaryConfig -Force }
}
