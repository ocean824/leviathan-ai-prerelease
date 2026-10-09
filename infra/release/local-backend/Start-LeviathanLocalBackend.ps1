[CmdletBinding()]
param(
    [switch]$Stop,
    [ValidateRange(1024, 65535)][int]$LicensingPort = 8787,
    [ValidateRange(1024, 65535)][int]$ReleaseFeedPort = 8788,
    [ValidateRange(5, 120)][int]$HealthTimeoutSeconds = 30,
    [string]$SecretsModulePath = 'C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\factory\tools\secrets\Xyra.Secrets.psm1'
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'LocalBackend.Common.psm1'
Import-Module -Name $commonPath -Force -ErrorAction Stop
$runtimeDirectory = Join-Path $env:LOCALAPPDATA 'Leviathan\local-backend'
$environmentPath = Join-Path $runtimeDirectory 'licensing.env'
$statePath = Join-Path $runtimeDirectory 'backend-state.json'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$licensingDirectory = Join-Path $repoRoot 'workers\licensing'
$releaseFeedDirectory = Join-Path $repoRoot 'workers\release-feed'
$children = New-Object System.Collections.Generic.List[object]
$secretModule = $null
$environmentWritten = $false

function Remove-LbRuntimeFiles {
    foreach ($path in @($environmentPath, $statePath)) {
        if (Test-Path -LiteralPath $path) {
            try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop } catch { }
        }
    }
}

function Stop-LbProcessTree {
    param([Parameter(Mandatory)]$Record)
    try { $process = Get-Process -Id ([int]$Record.process_id) -ErrorAction Stop } catch { return }
    try {
        if ([long]$process.StartTime.ToUniversalTime().Ticks -ne [long]$Record.started_utc_ticks) { return }
    } catch { return }
    $taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    if (Test-Path -LiteralPath $taskkill) {
        $null = & $taskkill /PID ([string]$Record.process_id) /T /F 2>$null
    } else {
        try { Stop-Process -Id ([int]$Record.process_id) -Force -ErrorAction SilentlyContinue } catch { }
    }
}

function Save-LbState {
    $records = @()
    foreach ($child in $children) {
        $records += [pscustomobject]@{
            name = [string]$child.name
            process_id = [int]$child.process.Id
            started_utc_ticks = [long]$child.process.StartTime.ToUniversalTime().Ticks
        }
    }
    $state = [pscustomobject]@{ schema_version = 1; processes = $records }
    Write-LbPrivateEnvFile -Path $statePath -Content (ConvertTo-Json -InputObject $state -Compress -Depth 4)
}

function Start-LbWrangler {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Directory,
        [Parameter(Mandatory)][int]$Port, [string]$EnvFile)
    $arguments = 'wrangler dev --ip 127.0.0.1 --port ' + $Port
    if (-not [string]::IsNullOrEmpty($EnvFile)) {
        if (-not (Test-LbSafeEnvFilePath -Path $EnvFile)) { throw 'LOCAL_BACKEND_INVALID_ENV_PATH' }
        $arguments += ' --env-file "' + $EnvFile + '"'
    }
    $command = 'npx ' + $arguments + ' 1>NUL 2>NUL'
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $env:ComSpec
    $startInfo.Arguments = '/d /s /c "' + $command + '"'
    $startInfo.WorkingDirectory = $Directory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'LOCAL_BACKEND_PROCESS_START_FAILED' }
    $children.Add([pscustomobject]@{ name = $Name; process = $process })
    Save-LbState
}

function Test-LbReadyResponse {
    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)][ValidateSet('licensing', 'release-feed')][string]$Worker)
    $code = Get-LbJsonErrorCode -Content ([string]$Response.Content)
    if ($Worker -eq 'licensing') {
        return (($Response.StatusCode -eq 401 -and $code -eq 'UNAUTHENTICATED') -or
            ($Response.StatusCode -eq 503 -and $code -eq 'NOT_CONFIGURED'))
    }
    $feedHeader = ''
    try { $feedHeader = [string]$Response.Headers['X-Leviathan-Feed'] } catch { }
    return (($Response.StatusCode -eq 204 -and $feedHeader -eq 'no-newer') -or
        ($Response.StatusCode -eq 503 -and $code -eq 'FEED_INVALID'))
}

function Wait-LbWorkerReady {
    param([Parameter(Mandatory)][ValidateSet('licensing', 'release-feed')][string]$Worker,
        [Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][int]$TimeoutSeconds)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    if ($Worker -eq 'licensing') {
        $uri = [uri]('http://127.0.0.1:' + $Port + '/v1/admin/license')
    } else {
        $uri = [uri]('http://127.0.0.1:' + $Port + '/v1/updates/desktop/windows-x86_64/x86_64/0.1.0')
    }
    while ([DateTime]::UtcNow -lt $deadline) {
        foreach ($child in $children) {
            if ($child.process.HasExited) { throw 'LOCAL_BACKEND_WORKER_EXITED' }
        }
        $response = Get-LbHttpResponse -Uri $uri -TimeoutSeconds 2
        if (Test-LbReadyResponse -Response $response -Worker $Worker) { return }
        Start-Sleep -Milliseconds 300
    }
    throw 'LOCAL_BACKEND_HEALTH_TIMEOUT'
}

if ($Stop) {
    $stopFailed = $false
    if (Test-Path -LiteralPath $statePath) {
        try {
            Assert-LbUserOnlyAcl -Path $statePath
            $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json -ErrorAction Stop
            foreach ($record in @($state.processes)) { Stop-LbProcessTree -Record $record }
        } catch { $stopFailed = $true }
    }
    Remove-LbRuntimeFiles
    if ($stopFailed) {
        [Console]::Error.WriteLine('LOCAL_BACKEND_STOP_INCOMPLETE')
        exit 1
    }
    [Console]::WriteLine('LOCAL_BACKEND_STOPPED')
    exit 0
}

try {
    if (Test-Path -LiteralPath $statePath) { throw 'LOCAL_BACKEND_ALREADY_RUNNING' }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'LOCAL_BACKEND_LOCALAPPDATA_UNAVAILABLE' }
    if (-not (Test-Path -LiteralPath $licensingDirectory) -or -not (Test-Path -LiteralPath $releaseFeedDirectory)) {
        throw 'LOCAL_BACKEND_WORKER_DIRECTORY_MISSING'
    }
    $null = New-Item -ItemType Directory -Path $runtimeDirectory -Force
    Set-LbUserOnlyAcl -Path $runtimeDirectory -Directory

    $secretModule = Import-Module -Name $SecretsModulePath -Force -PassThru -ErrorAction Stop
    $core = @{}
    $specifications = @(
        @{ Binding = 'DATABASE_URL'; Name = 'LEVIATHAN_LICENSING_DATABASE_URL'; Scope = 'leviathan-ai'; Environment = 'live'; Transform = 'identity' },
        @{ Binding = 'LICENSE_SIGNING_PRIVATE_KEY_PKCS8'; Name = 'LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8'; Scope = 'leviathan-ai'; Environment = 'development'; Transform = 'pkcs8' },
        @{ Binding = 'LICENSE_VERIFY_PUBLIC_KEY_JWK'; Name = 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_JWK'; Scope = 'leviathan-ai'; Environment = 'development'; Transform = 'jwk' },
        @{ Binding = 'ADMIN_TOTP_ENCRYPTION_KEY'; Name = 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY'; Scope = 'leviathan-ai'; Environment = 'development'; Transform = 'identity' },
        @{ Binding = 'INTERNAL_SERVICE_TOKEN'; Name = 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN'; Scope = 'leviathan-ai'; Environment = 'development'; Transform = 'identity' }
    )
    foreach ($spec in $specifications) {
        $secure = $null
        try {
            $secure = Get-XyraSecret -Name $spec.Name -Scope $spec.Scope -Environment $spec.Environment
            if ($secure -isnot [Security.SecureString]) { throw 'INVALID' }
            $plain = ConvertTo-LbPlainText -SecureValue $secure
            switch ($spec.Transform) {
                'pkcs8' { $plain = ConvertTo-LbPrivateKeyBase64 -Pem $plain }
                'jwk' { $plain = ConvertTo-LbCompactJwk -Json $plain }
            }
            $core[$spec.Binding] = $plain
        } catch {
            throw 'LOCAL_BACKEND_REQUIRED_SECRET_UNAVAILABLE'
        } finally {
            if ($null -ne $secure) { $secure.Dispose() }
        }
    }

    $stripeTestKey = $null
    $stripeSecure = $null
    try {
        $stripeSecure = Get-XyraSecret -Name 'STRIPE_TEST_SECRET_KEY' -Scope 'factory-admin' -Environment 'test'
        if ($stripeSecure -is [Security.SecureString]) { $stripeTestKey = ConvertTo-LbPlainText -SecureValue $stripeSecure }
    } catch {
        $stripeTestKey = $null
    } finally {
        if ($null -ne $stripeSecure) { $stripeSecure.Dispose() }
    }

    $bindings = New-LbLocalBindings -CoreSecrets $core -StripeTestKey $stripeTestKey
$signup = if ($bindings.Contains('STRIPE_SECRET_KEY')) { 'configured-with-test-key' } else { 'disabled-no-test-key' }
    $content = ConvertTo-LbEnvFileText -Bindings $bindings
    Write-LbPrivateEnvFile -Path $environmentPath -Content $content
    $environmentWritten = $true
    $content = $null
    foreach ($key in @($core.Keys)) { $core[$key] = '' }
    $stripeTestKey = $null
    $bindings.Clear()

    Start-LbWrangler -Name 'licensing' -Directory $licensingDirectory -Port $LicensingPort -EnvFile $environmentPath
    Start-LbWrangler -Name 'release-feed' -Directory $releaseFeedDirectory -Port $ReleaseFeedPort
    Wait-LbWorkerReady -Worker licensing -Port $LicensingPort -TimeoutSeconds $HealthTimeoutSeconds
    Wait-LbWorkerReady -Worker release-feed -Port $ReleaseFeedPort -TimeoutSeconds $HealthTimeoutSeconds
    [Console]::WriteLine(('LOCAL_BACKEND_READY licensing=127.0.0.1:{0} release_feed=127.0.0.1:{1} signup={2}' -f $LicensingPort, $ReleaseFeedPort, $signup))
    while ($true) {
        foreach ($child in $children) {
            if ($child.process.HasExited) { throw 'LOCAL_BACKEND_WORKER_EXITED' }
        }
        Start-Sleep -Seconds 1
    }
} catch {
    [Console]::Error.WriteLine('LOCAL_BACKEND_START_FAILED')
    exit 1
} finally {
    if ($null -ne $secretModule) { Remove-Module -ModuleInfo $secretModule -Force -ErrorAction SilentlyContinue }
    foreach ($child in $children) {
        Stop-LbProcessTree -Record ([pscustomobject]@{
            process_id = [int]$child.process.Id
            started_utc_ticks = [long]$child.process.StartTime.ToUniversalTime().Ticks
        })
        $child.process.Dispose()
    }
    if ($environmentWritten) { Remove-LbRuntimeFiles }
}




