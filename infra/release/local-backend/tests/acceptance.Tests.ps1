$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('release-local-backend-acceptance-' + [Guid]::NewGuid().ToString('N'))
$localBackendRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repoRoot = (Resolve-Path (Join-Path $localBackendRoot '..\..\..')).Path
$startPath = Join-Path $localBackendRoot 'Start-LeviathanLocalBackend.ps1'
$bootstrapPath = Join-Path $localBackendRoot 'Bootstrap-LeviathanOwner.ps1'
$smokePath = Join-Path $localBackendRoot 'Test-LeviathanLocalBackend.ps1'
$commonPath = Join-Path $localBackendRoot 'LocalBackend.Common.psm1'
$failures = New-Object System.Collections.Generic.List[string]
$checks = 0
$runningStarts = New-Object System.Collections.Generic.List[Diagnostics.Process]
$savedEnvironment = @{}
$fakeDbUrl = 'postgresql://synthetic.invalid/test-only-db-canary'
$fakePassword = 'FAKE_ONLY_OWNER_PASSWORD_CANARY'
$fakeInternalToken = 'FAKE_ONLY_INTERNAL_TOKEN_CANARY'

function Assert-Case {
    param([bool]$Condition, [string]$Name)
    $script:checks += 1
    if (-not $Condition) { $script:failures.Add($Name) }
}

function Save-TestEnvironment {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $script:savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
}

function Set-TestEnvironment {
    param([string]$Name, [AllowNull()][string]$Value)
    [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
}

function Write-TestText {
    param([string]$Path, [string]$Text)
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Get-TestText {
    param([string[]]$Paths, [string[]]$Values = @())
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
            try {
                $reader = New-Object IO.StreamReader($stream)
                try { $parts.Add($reader.ReadToEnd()) } finally { $reader.Dispose() }
            } finally { $stream.Dispose() }
        }
    }
    foreach ($value in $Values) {
        if ($null -ne $value) { $parts.Add($value) }
    }
    return ($parts -join "`n")
}

function Start-TestChild {
    param([string]$ScriptPath, [string]$Arguments = '')
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $PSHOME 'powershell.exe'
    $info.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $ScriptPath + '" ' + $Arguments
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'ACCEPTANCE_CHILD_START_FAILED' }
    $script:runningStarts.Add($process)
    return $process
}

function Invoke-TestChild {
    param([string]$ScriptPath, [string]$Arguments = '', [int]$TimeoutSeconds = 30)
    $process = Start-TestChild -ScriptPath $ScriptPath -Arguments $Arguments
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { }
        return [pscustomobject]@{ ExitCode = 124; Output = '' }
    }
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = [int]$process.ExitCode
        Output = [string]($stdout.Result + $stderr.Result)
    }
}

function Test-UserOnlyAcl {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    return ($acl.AreAccessRulesProtected -and $owner -eq $sid -and $rules.Count -eq 1 -and
        $rules[0].IdentityReference.Value -eq $sid -and
        $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        $rules[0].FileSystemRights -eq [Security.AccessControl.FileSystemRights]::FullControl)
}

function Wait-TestReady {
    param([Diagnostics.Process]$Process, [string]$OutputPath, [int]$Seconds = 25)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Test-Path -LiteralPath $script:statePath -PathType Leaf) -and (Test-Path -LiteralPath $script:httpLog -PathType Leaf)) {
            $requests = @([IO.File]::ReadAllLines($script:httpLog))
            if ($requests.Count -ge 2 -and $requests[-2] -eq '127.0.0.1:18787/v1/admin/license' -and
                $requests[-1] -eq '127.0.0.1:18888/v1/updates/desktop/windows-x86_64/x86_64/0.1.0' -and
                -not $Process.HasExited) { return $true }
        }
        if ($Process.HasExited) { return $false }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Stop-TestRuntime {
    param([string]$LocalAppData, [string]$FakeModulePath, [string]$StopOutputPath)
    Set-TestEnvironment 'LOCALAPPDATA' $LocalAppData
    $quotedModule = $FakeModulePath.Replace('"', '\"')
    $wrapperPath = Join-Path $testRoot 'stop-wrapper.ps1'
    $wrapper = @'
$ErrorActionPreference = 'Stop'
& $env:LB_START_SCRIPT -Stop -SecretsModulePath $env:LB_FAKE_MODULE *> $env:LB_STOP_OUTPUT
'@
    Write-TestText -Path $wrapperPath -Text $wrapper
    return Invoke-TestChild -ScriptPath $wrapperPath
}

function New-StartWrapper {
    param([string]$Tag)
    $wrapperPath = Join-Path $testRoot ($Tag + '-start-wrapper.ps1')
    $wrapper = @'
$ErrorActionPreference = 'Stop'
$env:LOCALAPPDATA = $env:LB_TEST_LOCALAPPDATA
function global:Invoke-WebRequest {
    [CmdletBinding()]
    param([uri]$Uri, [string]$Method, [switch]$UseBasicParsing, [int]$TimeoutSec)
    if ($Uri.Host -cne '127.0.0.1') { throw 'NETWORK_DISABLED' }
    Add-Content -LiteralPath $env:LB_HTTP_LOG -Value ($Uri.Host + ':' + $Uri.Port + $Uri.AbsolutePath)
    if ($Uri.AbsolutePath -eq '/v1/admin/license') {
        return [pscustomobject]@{ StatusCode = 401; Headers = @{}; Content = '{"error":{"code":"UNAUTHENTICATED"}}' }
    }
    return [pscustomobject]@{ StatusCode = 204; Headers = @{ 'X-Leviathan-Feed' = 'no-newer' }; Content = '' }
}
Start-Transcript -Path $env:LB_TRANSCRIPT -Force | Out-Null
try {
    & $env:LB_START_SCRIPT -LicensingPort ([int]$env:LB_LICENSING_PORT) `
        -ReleaseFeedPort ([int]$env:LB_FEED_PORT) -HealthTimeoutSeconds 5 `
        -SecretsModulePath $env:LB_FAKE_MODULE *> $env:LB_START_OUTPUT
} finally {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}
'@
    Write-TestText -Path $wrapperPath -Text $wrapper
    return $wrapperPath
}

function New-BootstrapWrapper {
    param([string]$Tag, [bool]$RejectPrompt)
    $wrapperPath = Join-Path $testRoot ($Tag + '-bootstrap-wrapper.ps1')
    $promptBehavior = if ($RejectPrompt) {
        "function global:Read-Host { throw 'PROMPT_FORBIDDEN_ON_EXISTING_OWNER' }"
    } else {
        @'
function global:Read-Host {
    [CmdletBinding()]
    param([string]$Prompt, [switch]$AsSecureString)
    if (-not $AsSecureString) { throw 'SECURE_PROMPT_REQUIRED' }
    Add-Content -LiteralPath $env:LB_PROMPT_LOG -Value 'SECURE_PROMPT'
    return ConvertTo-SecureString 'FAKE_ONLY_OWNER_PASSWORD_CANARY' -AsPlainText -Force
}
'@
    }
    $wrapper = @'
$ErrorActionPreference = 'Stop'
$env:LOCALAPPDATA = $env:LB_TEST_LOCALAPPDATA
__PROMPT_BEHAVIOR__
Start-Transcript -Path $env:LB_BOOTSTRAP_TRANSCRIPT -Force | Out-Null
try {
    & $env:LB_BOOTSTRAP_SCRIPT -OwnerEmail 'owner@example.test' -NodeExecutable $env:LB_FAKE_NODE *> $env:LB_BOOTSTRAP_OUTPUT
} finally {
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
}
'@
    $wrapper = $wrapper.Replace('__PROMPT_BEHAVIOR__', $promptBehavior)
    Write-TestText -Path $wrapperPath -Text $wrapper
    return $wrapperPath
}

function Read-TestEnvValue {
    param([string]$Path, [string]$Name)
    $prefix = $Name + '='
    $lines = [IO.File]::ReadAllLines($Path)
    $matches = @($lines | Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) })
    if ($matches.Count -ne 1) { return $null }
    return $matches[0].Substring($prefix.Length)
}

function Assert-NoCanaries {
    param([string[]]$Paths, [string[]]$Values = @(), [string]$Name)
    $text = Get-TestText -Paths $Paths -Values $Values
    $clear = -not ($text.Contains($script:fakeDbUrl) -or $text.Contains($script:fakePassword) -or
        $text.Contains($script:fakeInternalToken))
    Assert-Case $clear $Name
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$binDirectory = Join-Path $testRoot 'bin'
New-Item -ItemType Directory -Path $binDirectory -Force | Out-Null
$script:localAppData = Join-Path $testRoot 'AppData'
$script:runtimeDirectory = Join-Path $script:localAppData 'Leviathan\local-backend'
$script:environmentPath = Join-Path $script:runtimeDirectory 'licensing.env'
$script:statePath = Join-Path $script:runtimeDirectory 'backend-state.json'
$script:fakeModulePath = Join-Path $testRoot 'Fake.Xyra.Secrets.psm1'
$script:fakeNodePath = Join-Path $binDirectory 'fake-node.cmd'
$script:fakeNpxPath = Join-Path $binDirectory 'npx.cmd'
$script:secretLog = Join-Path $testRoot 'secret-module.log'
$script:nodeLog = Join-Path $testRoot 'node-children.log'
$script:npxLog = Join-Path $testRoot 'wrangler-arguments.log'
$script:httpLog = Join-Path $testRoot 'http-requests.log'
$script:promptLog = Join-Path $testRoot 'prompt.log'
$script:fakePem = [Convert]::ToBase64String([byte[]](0..63))
$script:fakeJwk = '{"kty":"EC","crv":"P-256","x":"' + ('A' * 43) + '","y":"' + ('B' * 43) + '"}'
$script:fakeTotp = [Convert]::ToBase64String([byte[]](0..31))
$fakeModule = @'
Add-Content -LiteralPath $env:LB_SECRET_MODULE_LOG -Value 'MODULE_IMPORTED'
function Get-XyraSecret {
    param([string]$Name, [string]$Scope, [string]$Environment)
    Add-Content -LiteralPath $env:LB_SECRET_MODULE_LOG -Value ('REQUEST_' + $Name)
    switch ($Name) {
        'LEVIATHAN_LICENSING_DATABASE_URL' { $value = 'postgresql://synthetic.invalid/test-only-db-canary' }
        'LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8' { $value = '-----BEGIN PRIVATE KEY-----' + '__PEM__' + "`n-----END PRIVATE KEY-----" }
        'LEVIATHAN_LICENSING_SIGNING_PUBLIC_JWK' { $value = '__JWK__' }
        'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY' { $value = '__TOTP__' }
        'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN' { $value = 'FAKE_ONLY_INTERNAL_TOKEN_CANARY' }
        'STRIPE_TEST_SECRET_KEY' { throw 'SECRET_NOT_CONFIGURED' }
        default { throw 'SECRET_NOT_CONFIGURED' }
    }
    return ConvertTo-SecureString -String $value -AsPlainText -Force
}
Export-ModuleMember -Function Get-XyraSecret
'@
$fakeModule = $fakeModule.Replace('__PEM__', $script:fakePem).Replace('__JWK__', $script:fakeJwk).Replace('__TOTP__', $script:fakeTotp)
Write-TestText -Path $script:fakeModulePath -Text $fakeModule

$fakeNpx = @'
@echo off
>>"%LB_NPX_LOG%" echo %*
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 180"
'@
[IO.File]::WriteAllText($script:fakeNpxPath, $fakeNpx.Replace("`n", "`r`n"), [Text.Encoding]::ASCII)

$fakeNode = @'
@echo off
if /i "%~1"=="--input-type=module" goto preflight
if /i "%~1"=="--input-type" if /i "%~2"=="module" goto preflight
if /i "%~1"=="scripts/apply_migrations.mjs" goto migration
if /i "%~1"=="scripts/bootstrap_owner.mjs" goto bootstrap
exit /b 91
:preflight
call :record PREFLIGHT
echo %DATABASE_URL%
echo %OWNER_PASSWORD%
exit /b %LB_PREFLIGHT_EXIT%
:migration
call :record MIGRATION
echo %DATABASE_URL%
echo %OWNER_PASSWORD%
exit /b 0
:bootstrap
call :record BOOTSTRAP
echo %DATABASE_URL%
echo %OWNER_PASSWORD%
exit /b 0
:record
set caps=absent
if defined CAPS_APPROVED set caps=other
if /i "%CAPS_APPROVED%"=="true" set caps=true
set pass=absent
if defined OWNER_PASSWORD set pass=present
set database=absent
if defined DATABASE_URL set database=present
>>"%LB_NODE_LOG%" echo %~1,caps=%caps%,password=%pass%,database=%database%
exit /b 0
'@
[IO.File]::WriteAllText($script:fakeNodePath, $fakeNode.Replace("`n", "`r`n"), [Text.Encoding]::ASCII)

$environmentNames = @(
    'LOCALAPPDATA', 'PATH', 'ComSpec', 'LB_TEST_LOCALAPPDATA', 'LB_START_SCRIPT',
    'LB_BOOTSTRAP_SCRIPT', 'LB_FAKE_MODULE', 'LB_FAKE_NODE', 'LB_SECRET_MODULE_LOG',
    'LB_NODE_LOG', 'LB_NPX_LOG', 'LB_HTTP_LOG', 'LB_PROMPT_LOG', 'LB_PREFLIGHT_EXIT',
    'LB_LICENSING_PORT', 'LB_FEED_PORT', 'LB_START_OUTPUT', 'LB_TRANSCRIPT',
    'LB_BOOTSTRAP_OUTPUT', 'LB_BOOTSTRAP_TRANSCRIPT', 'LB_STOP_OUTPUT', 'CAPS_APPROVED',
    'DATABASE_URL', 'OWNER_PASSWORD', 'OWNER_EMAIL'
)
Save-TestEnvironment -Names $environmentNames

try {
    $env:PATH = $binDirectory + ';' + $savedEnvironment['PATH']
    $env:LOCALAPPDATA = $script:localAppData
    $env:LB_TEST_LOCALAPPDATA = $script:localAppData
    $env:LB_START_SCRIPT = $startPath
    $env:LB_BOOTSTRAP_SCRIPT = $bootstrapPath
    $env:LB_FAKE_MODULE = $script:fakeModulePath
    $env:LB_FAKE_NODE = $script:fakeNodePath
    $env:LB_SECRET_MODULE_LOG = $script:secretLog
    $env:LB_NODE_LOG = $script:nodeLog
    $env:LB_NPX_LOG = $script:npxLog
    $env:LB_HTTP_LOG = $script:httpLog
    $env:LB_PROMPT_LOG = $script:promptLog
    $env:LB_LICENSING_PORT = '18787'
    $env:LB_FEED_PORT = '18888'
    $env:CAPS_APPROVED = 'PARENT_SENTINEL'
    $env:DATABASE_URL = 'PARENT_DATABASE_SENTINEL'
    $env:OWNER_PASSWORD = 'PARENT_PASSWORD_SENTINEL'
    $env:OWNER_EMAIL = 'PARENT_EMAIL_SENTINEL'

    # Start is the only code path allowed to load the vault module; it is injected with a fake.
    $startOneOutput = Join-Path $testRoot 'start-one.output.log'
    $startOneTranscript = Join-Path $testRoot 'start-one.transcript.log'
    $env:LB_START_OUTPUT = $startOneOutput
    $env:LB_TRANSCRIPT = $startOneTranscript
    $wrapperOne = New-StartWrapper -Tag 'start-one'
    $startOne = Start-TestChild -ScriptPath $wrapperOne
    $startedOne = Wait-TestReady -Process $startOne -OutputPath $startOneOutput
    Assert-Case $startedOne 'start uses fake secrets and reaches local-only readiness'

    if ($startedOne) {
        Assert-Case (Test-Path -LiteralPath $script:environmentPath -PathType Leaf) 'start writes the protected licensing env file'
        Assert-Case (Test-UserOnlyAcl -Path $script:runtimeDirectory) 'runtime directory ACL is current-user-only with inheritance disabled'
        Assert-Case (Test-UserOnlyAcl -Path $script:environmentPath) 'licensing env ACL is current-user-only with inheritance disabled'
        $webhookOne = Read-TestEnvValue -Path $script:environmentPath -Name 'STRIPE_WEBHOOK_SECRET'
        Assert-Case ($webhookOne -match '^whsec_[A-Za-z0-9_-]{43}$') 'local webhook placeholder has generated format'
        Assert-Case ((Read-TestEnvValue -Path $script:environmentPath -Name 'STRIPE_PRICE_ID') -ceq 'price_LOCALPLACEHOLDER0') 'local price binding is a non-real placeholder'
        Assert-Case ((Read-TestEnvValue -Path $script:environmentPath -Name 'CAPS_APPROVED') -ceq 'false') 'Worker env file does not approve CAPS'
        $wranglerText = [IO.File]::ReadAllText($script:npxLog)
        Assert-Case ($wranglerText -match 'wrangler dev --ip 127\.0\.0\.1 --port 18787 --env-file' -and
            $wranglerText -match 'wrangler dev --ip 127\.0\.0\.1 --port 18888' -and
            $wranglerText -notmatch '--ip 0\.0\.0\.0|--host 0\.0\.0\.0|--ip 0\.0\.0\.0') 'both Workers bind only to IPv4 loopback'
        $httpLines = @(Get-Content -LiteralPath $script:httpLog -ErrorAction SilentlyContinue)
        Assert-Case ($httpLines.Count -eq 2 -and @($httpLines | Where-Object { $_ -notmatch '^127\.0\.0\.1:' }).Count -eq 0) 'start readiness is exercised only through mocked loopback HTTP'
        Assert-NoCanaries -Paths @($startOneOutput, $startOneTranscript, $script:npxLog, $script:httpLog) -Name 'start output, transcript and process logs contain no fake DB/token values'
    }

    # Active-owner preflight must return before the SecureString prompt and before either write child.
    $preflightOutput = Join-Path $testRoot 'preflight-positive.output.log'
    $preflightTranscript = Join-Path $testRoot 'preflight-positive.transcript.log'
    $preflightWrapper = New-BootstrapWrapper -Tag 'preflight-positive' -RejectPrompt $true
    $env:LB_PREFLIGHT_EXIT = '10'
    $env:LB_PREFLIGHT_EXIT = '10'
    $env:LB_BOOTSTRAP_OUTPUT = $preflightOutput
    $env:LB_BOOTSTRAP_TRANSCRIPT = $preflightTranscript
    $nodeBeforePreflight = if (Test-Path $script:nodeLog) { @(Get-Content $script:nodeLog).Count } else { 0 }
    $preflightResult = Invoke-TestChild -ScriptPath $preflightWrapper
    $preflightChildren = @(if (Test-Path $script:nodeLog) { Get-Content $script:nodeLog | Select-Object -Skip $nodeBeforePreflight })
    $preflightText = Get-TestText -Paths @($preflightOutput) -Values @($preflightResult.Output)
    Assert-Case ($preflightResult.ExitCode -eq 0 -and $preflightText -match 'Owner already bootstrapped') 'active-owner preflight reports existing owner and succeeds'
    Assert-NoCanaries -Paths @($preflightOutput, $preflightTranscript) -Values @($preflightResult.Output) -Name 'active-owner preflight output/transcript contains no fake credentials'
    Assert-Case (-not (Test-Path -LiteralPath $script:promptLog) -and $preflightChildren.Count -eq 1 -and $preflightChildren[0] -match '^PREFLIGHT,') 'active-owner preflight prompts for no password and starts no migration/bootstrap child'
    Assert-Case ($preflightChildren.Count -eq 1 -and $preflightChildren[0] -match 'caps=absent,password=absent,database=present') 'preflight child receives DB only, not CAPS or password'

    # Empty-owner flow uses only synthetic child processes; CAPS approval is scoped to bootstrap.
    $bootstrapOutput = Join-Path $testRoot 'bootstrap.output.log'
    $bootstrapTranscript = Join-Path $testRoot 'bootstrap.transcript.log'
    $bootstrapWrapper = New-BootstrapWrapper -Tag 'bootstrap-normal' -RejectPrompt $false
    $env:LB_PREFLIGHT_EXIT = '0'
    $env:LB_BOOTSTRAP_OUTPUT = $bootstrapOutput
    $env:LB_BOOTSTRAP_TRANSCRIPT = $bootstrapTranscript
    $nodeBeforeBootstrap = if (Test-Path -LiteralPath $script:nodeLog) { @(Get-Content $script:nodeLog).Count } else { 0 }
    $bootstrapResult = Invoke-TestChild -ScriptPath $bootstrapWrapper
    $bootstrapChildren = @(if (Test-Path -LiteralPath $script:nodeLog) { Get-Content $script:nodeLog | Select-Object -Skip $nodeBeforeBootstrap })
    Assert-Case ($bootstrapResult.ExitCode -eq 0 -and (Get-TestText -Paths @($bootstrapOutput) -Values @($bootstrapResult.Output)) -match 'LOCAL_BACKEND_OWNER_BOOTSTRAPPED') 'fake owner bootstrap completes successfully'
    Assert-Case ($bootstrapChildren.Count -eq 3 -and $bootstrapChildren[0] -match '^PREFLIGHT,' -and
        $bootstrapChildren[1] -match '^MIGRATION,' -and $bootstrapChildren[2] -match '^BOOTSTRAP,') 'preflight, migrations and bootstrap run in order'
    Assert-Case ($bootstrapChildren.Count -eq 3 -and $bootstrapChildren[0] -match 'caps=absent,password=absent,database=present' -and
        $bootstrapChildren[1] -match 'caps=absent,password=absent,database=present' -and
        $bootstrapChildren[2] -match 'caps=true,password=present,database=present') 'CAPS_APPROVED is absent from migrations and true only in bootstrap child'
    Assert-Case ($env:CAPS_APPROVED -ceq 'PARENT_SENTINEL' -and $env:DATABASE_URL -ceq 'PARENT_DATABASE_SENTINEL' -and
        $env:OWNER_PASSWORD -ceq 'PARENT_PASSWORD_SENTINEL') 'bootstrap never mutates parent credential environment'
    Assert-Case ((Get-TestText -Paths @($bootstrapOutput, $bootstrapTranscript, $script:nodeLog, $script:promptLog) -Values @($bootstrapResult.Output)) -notmatch 'PARENT_SENTINEL|PARENT_DATABASE_SENTINEL|PARENT_PASSWORD_SENTINEL') 'bootstrap output/logs do not expose inherited credential sentinels'
    Assert-NoCanaries -Paths @($bootstrapOutput, $bootstrapTranscript, $script:nodeLog, $script:promptLog) -Values @($bootstrapResult.Output) -Name 'bootstrap output, child log and transcript contain no fake DB URL, password or token'

    # Smoke test is read-only and its HTTP client is replaced by the local fake above.
    $smokeOutput = Join-Path $testRoot 'smoke.output.log'
    $smokeWrapper = Join-Path $testRoot 'smoke-wrapper.ps1'
    $smokeWrapperContent = @'
$ErrorActionPreference = 'Stop'
function global:Invoke-WebRequest {
    [CmdletBinding()]
    param([uri]$Uri, [string]$Method, [switch]$UseBasicParsing, [int]$TimeoutSec)
    if ($Uri.Host -cne '127.0.0.1') { throw 'NETWORK_DISABLED' }
    Add-Content -LiteralPath $env:LB_HTTP_LOG -Value ($Uri.Host + ':' + $Uri.Port + $Uri.AbsolutePath)
    if ($Uri.AbsolutePath -eq '/v1/admin/license') {
        return [pscustomobject]@{ StatusCode = 401; Headers = @{}; Content = '{"error":{"code":"UNAUTHENTICATED"}}' }
    }
    return [pscustomobject]@{ StatusCode = 204; Headers = @{ 'X-Leviathan-Feed' = 'no-newer' }; Content = '' }
}
& $env:LB_SMOKE_SCRIPT -LicensingPort 18787 -ReleaseFeedPort 18888 *> $env:LB_SMOKE_OUTPUT
'@
    Write-TestText -Path $smokeWrapper -Text $smokeWrapperContent
    $env:LB_SMOKE_SCRIPT = $smokePath
    $env:LB_SMOKE_OUTPUT = $smokeOutput
    $httpBeforeSmoke = @(Get-Content $script:httpLog -ErrorAction SilentlyContinue).Count
    $moduleBeforeSmoke = @(Get-Content $script:secretLog -ErrorAction SilentlyContinue).Count
    $smokeResult = Invoke-TestChild -ScriptPath $smokeWrapper
    $smokeText = Get-TestText -Paths @($smokeOutput) -Values @($smokeResult.Output)
    $httpAfterSmoke = @(Get-Content $script:httpLog -ErrorAction SilentlyContinue)
    Assert-Case ($smokeResult.ExitCode -eq 0 -and $smokeText -match 'LICENSING_HEALTH_OK' -and $smokeText -match 'RELEASE_FEED_HEALTH_OK') 'read-only smoke accepts the two synthetic local health responses'
    Assert-Case ($httpAfterSmoke.Count - $httpBeforeSmoke -eq 2 -and @($httpAfterSmoke | Select-Object -Skip $httpBeforeSmoke | Where-Object { $_ -notmatch '^127\.0\.0\.1:' }).Count -eq 0) 'smoke invokes only mocked loopback endpoints'
    Assert-Case (@(Get-Content $script:secretLog -ErrorAction SilentlyContinue).Count -eq $moduleBeforeSmoke) 'smoke test never imports or calls the secrets module'

    # A second fake start proves a new non-vault webhook placeholder is generated each time.
    if ($startedOne) {
        $stopOutputOne = Join-Path $testRoot 'stop-one.output.log'
        $env:LB_STOP_OUTPUT = $stopOutputOne
        $stopOne = Stop-TestRuntime -LocalAppData $script:localAppData -FakeModulePath $script:fakeModulePath -StopOutputPath $stopOutputOne
        $startOne.WaitForExit(10000) | Out-Null
        Assert-Case ($stopOne.ExitCode -eq 0 -and (Get-TestText -Paths @($stopOutputOne) -Values @($stopOne.Output)) -match 'LOCAL_BACKEND_STOPPED') 'stop returns success on fake processes'
        Assert-Case (-not (Test-Path -LiteralPath $script:environmentPath) -and -not (Test-Path -LiteralPath $script:statePath)) 'stop removes licensing.env and private process state'
        Assert-NoCanaries -Paths @($stopOutputOne) -Name 'stop output contains no fake credentials'

        $startTwoOutput = Join-Path $testRoot 'start-two.output.log'
        $startTwoTranscript = Join-Path $testRoot 'start-two.transcript.log'
        $env:LB_START_OUTPUT = $startTwoOutput
        $env:LB_TRANSCRIPT = $startTwoTranscript
        $wrapperTwo = New-StartWrapper -Tag 'start-two'
        $startTwo = Start-TestChild -ScriptPath $wrapperTwo
        $startedTwo = Wait-TestReady -Process $startTwo -OutputPath $startTwoOutput
        Assert-Case $startedTwo 'second fake start reaches readiness'
        if ($startedTwo) {
            $webhookTwo = Read-TestEnvValue -Path $script:environmentPath -Name 'STRIPE_WEBHOOK_SECRET'
            Assert-Case ($webhookTwo -match '^whsec_[A-Za-z0-9_-]{43}$' -and $webhookTwo -cne $webhookOne) 'webhook placeholder is freshly randomized on each start'
            Assert-NoCanaries -Paths @($startTwoOutput, $startTwoTranscript, $script:npxLog, $script:httpLog) -Name 'second start output and logs remain secret-free'
            $stopOutputTwo = Join-Path $testRoot 'stop-two.output.log'
            $env:LB_STOP_OUTPUT = $stopOutputTwo
            $stopTwo = Stop-TestRuntime -LocalAppData $script:localAppData -FakeModulePath $script:fakeModulePath -StopOutputPath $stopOutputTwo
            $startTwo.WaitForExit(10000) | Out-Null
            Assert-Case ($stopTwo.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $script:environmentPath)) 'second stop also deletes licensing.env'
        }
    }

    # Abnormal start failure after env creation must also remove the private file.
    $abnormalAppData = Join-Path $testRoot 'AbnormalAppData'
    $env:LB_TEST_LOCALAPPDATA = $abnormalAppData
    $env:LOCALAPPDATA = $abnormalAppData
    $env:ComSpec = Join-Path $testRoot 'missing-comspec.exe'
    $abnormalOutput = Join-Path $testRoot 'abnormal.output.log'
    $abnormalResult = Invoke-TestChild -ScriptPath $startPath -Arguments ('-SecretsModulePath "{0}" -HealthTimeoutSeconds 5' -f $script:fakeModulePath)
    $abnormalEnv = Join-Path $abnormalAppData 'Leviathan\local-backend\licensing.env'
    Assert-Case ($abnormalResult.ExitCode -ne 0) 'abnormal startup reports failure after the fake process start is denied'
    Assert-Case (-not (Test-Path -LiteralPath $abnormalEnv)) 'abnormal startup removes env file after fake secret injection'
    Assert-NoCanaries -Values @($abnormalResult.Output) -Name 'abnormal start output contains no fake secret values'

    # No script other than Start may import or invoke the real vault module.
    $nonStartScripts = @($bootstrapPath, $smokePath)
    $nonStartVaultUse = @($nonStartScripts | Where-Object {
        $text = [IO.File]::ReadAllText($_)
        $text -match 'Xyra\.Secrets\.psm1|Get-XyraSecret|SecretsModulePath'
    })
    $moduleImports = @(Get-Content $script:secretLog -ErrorAction SilentlyContinue | Where-Object { $_ -ceq 'MODULE_IMPORTED' })
    Assert-Case ($nonStartVaultUse.Count -eq 0 -and $moduleImports.Count -ge 2) 'only Start imports the injected fake module; Bootstrap and smoke never reach vault module'

    if ($failures.Count -gt 0) {
        [Console]::Error.WriteLine(('RELEASE_LOCAL_BACKEND_ACCEPTANCE_FAILED count={0} cases={1}' -f $failures.Count, ($failures -join ',')))
        exit 1
    }
    [Console]::WriteLine(('RELEASE_LOCAL_BACKEND_ACCEPTANCE_PASSED checks={0}' -f $checks))
    exit 0
} catch {
    [Console]::Error.WriteLine(('RELEASE_LOCAL_BACKEND_ACCEPTANCE_ERROR type={0} line={1} stack={2}' -f $_.Exception.GetType().Name, $_.InvocationInfo.ScriptLineNumber, $_.ScriptStackTrace))
    exit 1
} finally {
    foreach ($process in $runningStarts) {
        try {
            if (-not $process.HasExited) { $process.Kill() }
            $process.Dispose()
        } catch { }
    }
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
