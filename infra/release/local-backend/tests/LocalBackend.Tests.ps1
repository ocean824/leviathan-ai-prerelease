$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('local-backend-selftest-' + [Guid]::NewGuid().ToString('N'))
$modulePath = Join-Path $PSScriptRoot '..\LocalBackend.Common.psm1'
$startPath = Join-Path $PSScriptRoot '..\Start-LeviathanLocalBackend.ps1'
$bootstrapPath = Join-Path $PSScriptRoot '..\Bootstrap-LeviathanOwner.ps1'
$testPath = Join-Path $PSScriptRoot '..\Test-LeviathanLocalBackend.ps1'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..')).Path
$failures = New-Object System.Collections.Generic.List[string]
$checks = 0

function Assert-LbTest {
    param([bool]$Condition, [string]$Name)
    $script:checks += 1
    if (-not $Condition) { $script:failures.Add($Name) }
}

function Invoke-LbChildPowerShell {
    param([string[]]$Arguments)
    $exe = Join-Path $PSHOME 'powershell.exe'
    $quoted = foreach ($argument in $Arguments) { '"' + ([string]$argument).Replace('"', '\"') + '"' }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $exe
    $info.Arguments = '-NoProfile -NonInteractive ' + ($quoted -join ' ')
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = [int]$process.ExitCode; Output = [string]($stdout.Result + $stderr.Result) }
    } finally { $process.Dispose() }
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
Import-Module -Name $modulePath -Force
$fakePemBytes = [byte[]](0..63)
$fakePemBody = [Convert]::ToBase64String($fakePemBytes)
$fakeJwk = '{"kty":"EC","crv":"P-256","x":"' + ('A' * 43) + '","y":"' + ('B' * 43) + '"}'
$fakeModule = @'
function Get-XyraSecret {
    param([string]$Name, [string]$Scope, [string]$Environment)
    switch ($Name) {
        'LEVIATHAN_LICENSING_DATABASE_URL' { $value = 'postgresql://fake.invalid/TEST_ONLY_DB_CANARY' }
        'LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8' { $value = '-----BEGIN PRIVATE KEY-----' + '__FAKE_PEM__' + "`n-----END PRIVATE KEY-----" }
        'LEVIATHAN_LICENSING_SIGNING_PUBLIC_JWK' { $value = '__FAKE_JWK__' }
        'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY' { $value = '__FAKE_TOTP__' }
        'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN' { $value = 'TEST_ONLY_INTERNAL_TOKEN_CANARY' }
        'STRIPE_TEST_SECRET_KEY' { throw 'SECRET_NOT_CONFIGURED' }
        default { throw 'SECRET_NOT_CONFIGURED' }
    }
    return ConvertTo-SecureString -String $value -AsPlainText -Force
}
Export-ModuleMember -Function Get-XyraSecret
'@
$fakeModule = $fakeModule.Replace('__FAKE_PEM__', $fakePemBody).Replace('__FAKE_JWK__', $fakeJwk)
$fakeModule = $fakeModule.Replace('__FAKE_TOTP__', [Convert]::ToBase64String([byte[]](0..31)))
$fakeModulePath = Join-Path $testRoot 'Fake.Xyra.Secrets.psm1'
Set-Content -LiteralPath $fakeModulePath -Value $fakeModule -Encoding utf8

try {
    $convertedPem = ConvertTo-LbPrivateKeyBase64 -Pem ('-----BEGIN PRIVATE KEY-----' + "`n" + $fakePemBody + "`n-----END PRIVATE KEY-----")
    Assert-LbTest ($convertedPem -ceq $fakePemBody) 'PKCS8 PEM becomes single-line base64 DER'
    $convertedJwk = ConvertTo-LbCompactJwk -Json $fakeJwk
    Assert-LbTest ($convertedJwk -notmatch '[\r\n]' -and $convertedJwk -match '"crv":"P-256"') 'public JWK is compact JSON'
    $privateJwkRejected = $false
    try { $null = ConvertTo-LbCompactJwk -Json ($fakeJwk.TrimEnd('}') + ',"d":"PRIVATE_CANARY"}') } catch { $privateJwkRejected = $true }
    Assert-LbTest $privateJwkRejected 'private material in public JWK is rejected'

    $core = @{
        DATABASE_URL = 'postgresql://fake.invalid/TEST_ONLY_DB_CANARY'
        LICENSE_SIGNING_PRIVATE_KEY_PKCS8 = $convertedPem
        LICENSE_VERIFY_PUBLIC_KEY_JWK = $convertedJwk
        ADMIN_TOTP_ENCRYPTION_KEY = [Convert]::ToBase64String([byte[]](0..31))
        INTERNAL_SERVICE_TOKEN = 'TEST_ONLY_INTERNAL_TOKEN_CANARY'
    }
    $bindings = New-LbLocalBindings -CoreSecrets $core -StripeTestKey $null
    Assert-LbTest (-not $bindings.Contains('STRIPE_SECRET_KEY')) 'absent Stripe test key disables signup binding'
    Assert-LbTest ($bindings.STRIPE_WEBHOOK_SECRET -match '^whsec_[A-Za-z0-9_-]{43}$') 'webhook placeholder is random-format local value'
    Assert-LbTest ($bindings.STRIPE_PRICE_ID -ceq 'price_LOCALPLACEHOLDER0') 'local Stripe price placeholder matches contract'
    Assert-LbTest ($bindings.SIGNUP_SUCCESS_URL -ceq 'https://127.0.0.1/signup/success') 'success redirect is loopback HTTPS'
    $bindings2 = New-LbLocalBindings -CoreSecrets $core -StripeTestKey 'sk_test_FAKE_ONLY_KEY'
    Assert-LbTest ($bindings2.STRIPE_WEBHOOK_SECRET -cne $bindings.STRIPE_WEBHOOK_SECRET) 'webhook placeholder rotates per start'
    Assert-LbTest ($bindings2.STRIPE_SECRET_KEY -ceq 'sk_test_FAKE_ONLY_KEY') 'test-only Stripe key maps to Worker binding'
    $liveStripeRejected = $false
    try { $null = New-LbLocalBindings -CoreSecrets $core -StripeTestKey 'sk_live_FAKE_ONLY_KEY' } catch { $liveStripeRejected = $true }
    Assert-LbTest $liveStripeRejected 'live Stripe key is rejected'
    $linebreakRejected = $false
    try { $null = ConvertTo-LbEnvScalar -Name 'DATABASE_URL' -Value "postgresql://fake`nCANARY" } catch { $linebreakRejected = $true }
    Assert-LbTest $linebreakRejected 'line breaks in .env values are rejected'
    Assert-LbTest (Test-LbSafeEnvFilePath -Path 'C:\Users\test\AppData\Local\Leviathan\local-backend\licensing.env') 'ordinary licensing.env path with n characters is accepted'
    Assert-LbTest (-not (Test-LbSafeEnvFilePath -Path "C:\temp\bad`n.env") -and -not (Test-LbSafeEnvFilePath -Path 'C:\temp\bad".env')) 'unsafe env file path separators are rejected'
    $commentRejected = $false
    try { $null = ConvertTo-LbEnvScalar -Name 'DATABASE_URL' -Value 'postgresql://fake.invalid/#CANARY' } catch { $commentRejected = $true }
    Assert-LbTest $commentRejected '.env comment injection is rejected'

    $appData = Join-Path $testRoot 'AppData'
    $env:LOCALAPPDATA = $appData
    $runtime = Join-Path $appData 'Leviathan\local-backend'
    $envPath = Join-Path $runtime 'licensing.env'
    $envText = ConvertTo-LbEnvFileText -Bindings $bindings
    Write-LbPrivateEnvFile -Path $envPath -Content $envText
    Assert-LbTest (Test-Path -LiteralPath $envPath) 'private environment file was created'
    Assert-LbTest ((Get-LbEnvValue -Path $envPath -Name 'DATABASE_URL') -ceq $core.DATABASE_URL) 'database URL can be read for child environment only'
    Assert-LbTest ((Get-Content -Raw -LiteralPath $envPath) -notmatch '[\r]') '.env file uses stable LF line endings'
    Assert-LbTest ((Get-Content -Raw -LiteralPath $envPath) -match 'LICENSE_SIGNING_PRIVATE_KEY_PKCS8=[A-Za-z0-9+/]+=*') 'private key binding is one-line base64'
    Assert-LbTest ((Get-Content -Raw -LiteralPath $envPath) -notmatch 'BEGIN PRIVATE KEY') 'PEM armor is not passed to the Worker'
    Assert-LbTest ((Get-Content -Raw -LiteralPath $envPath) -notmatch 'STRIPE_SECRET_KEY=') 'optional Stripe binding is absent'
    Assert-LbTest ((Get-Acl -LiteralPath $runtime).AreAccessRulesProtected) 'runtime directory disables inherited ACLs'
    Assert-LbTest ((Get-Acl -LiteralPath $envPath).AreAccessRulesProtected) 'environment file disables inherited ACLs'
    Assert-LbTest ((Get-Acl -LiteralPath $runtime).Access.Count -eq 1) 'runtime directory has one ACL principal'
    Assert-LbTest ((Get-Acl -LiteralPath $envPath).Access.Count -eq 1) 'environment file has one ACL principal'

    $scriptContent = Get-Content -Raw -LiteralPath $startPath
    $bootstrapContent = Get-Content -Raw -LiteralPath $bootstrapPath
    $smokeContent = Get-Content -Raw -LiteralPath $testPath
    Assert-LbTest ($scriptContent -match '--ip 127\.0\.0\.1' -and $smokeContent -match 'http://127\.0\.0\.1:') 'Worker binds and smoke calls are loopback-only'
    Assert-LbTest ($scriptContent -match 'Xyra\.Secrets\.psm1' -and $bootstrapContent -notmatch 'Xyra\.Secrets|Get-XyraSecret' -and $smokeContent -notmatch 'Xyra\.Secrets|Get-XyraSecret') 'only the start script imports the vault module'
    $bootstrapTokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($bootstrapPath, [ref]$bootstrapTokens, [ref]$parseErrors)
    $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    Assert-LbTest (($parameterNames -contains 'OwnerEmail') -and ($parameterNames -notcontains 'OwnerPassword') -and ($parameterNames -notcontains 'Password')) 'owner password is prompt-only, never a parameter'
    Assert-LbTest ($bootstrapContent -match 'Read-Host .*AsSecureString' -and $bootstrapContent -match 'EnvironmentVariables\[' -and $bootstrapContent -notmatch 'StartInfo\.Arguments.*OWNER_PASSWORD') 'password is child environment only, not command line'
    Assert-LbTest ($bootstrapContent.IndexOf('Invoke-LbNodeChild', [StringComparison]::Ordinal) -lt $bootstrapContent.IndexOf('Read-Host', [StringComparison]::Ordinal) -and $bootstrapContent -match "owner_exists") 'active-owner preflight is before the password prompt'

    # A synthetic node command reports an existing owner. Success must return
    # before prompting or invoking migrations/bootstrap, with no CAPS grant.
    $preflightLog = Join-Path $testRoot 'preflight-calls.txt'
    $fakeNode = Join-Path $testRoot 'fake-node.cmd'
    @('@echo off', 'echo PREFLIGHT>>"%LOCAL_BACKEND_FAKE_LOG%"', 'if defined CAPS_APPROVED echo CAPS_SET>>"%LOCAL_BACKEND_FAKE_LOG%"', 'exit /b 10') |
        Set-Content -LiteralPath $fakeNode -Encoding ASCII
    $oldFakeLog = $env:LOCAL_BACKEND_FAKE_LOG
    $env:LOCAL_BACKEND_FAKE_LOG = $preflightLog
    $preflightInvocation = Invoke-LbChildPowerShell -Arguments @('-File', $bootstrapPath, '-NodeExecutable', $fakeNode, '-OwnerEmail', 'owner@example.test')
    $env:LOCAL_BACKEND_FAKE_LOG = $oldFakeLog
    $preflightCalls = @(Get-Content -LiteralPath $preflightLog -ErrorAction SilentlyContinue)
    Assert-LbTest ($preflightInvocation.ExitCode -eq 0 -and $preflightInvocation.Output -match 'Owner already bootstrapped') 'existing owner preflight exits successfully before prompting'
    Assert-LbTest ($preflightCalls.Count -eq 1 -and $preflightCalls[0] -ceq 'PREFLIGHT') 'existing owner path calls no migration or bootstrap child'
    Assert-LbTest ($preflightInvocation.Output -notmatch 'TEST_ONLY_DB_CANARY|INTERNAL_TOKEN_CANARY|PRIVATE_KEY|FAKE_ONLY_KEY') 'preflight output contains no secret values'

    # The stop path uses only synthetic state and a local sleeping process. It never calls a Worker or vault.
    $stopDirectory = Join-Path $runtime 'stop-probe'
    $null = New-Item -ItemType Directory -Path $stopDirectory -Force
    Set-LbUserOnlyAcl -Path $stopDirectory -Directory
    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = Join-Path $PSHOME 'powershell.exe'
    $processInfo.Arguments = '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 90"'
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $sleepProcess = New-Object Diagnostics.Process
    $sleepProcess.StartInfo = $processInfo
    $null = $sleepProcess.Start()
    Start-Sleep -Milliseconds 250
    $state = [pscustomobject]@{ schema_version = 1; processes = @([pscustomobject]@{
        name = 'synthetic'; process_id = $sleepProcess.Id; started_utc_ticks = $sleepProcess.StartTime.ToUniversalTime().Ticks
    }) }
    $statePath = Join-Path $runtime 'backend-state.json'
    Write-LbPrivateEnvFile -Path $statePath -Content (ConvertTo-Json -InputObject $state -Compress -Depth 4)
    $stopInvocation = Invoke-LbChildPowerShell -Arguments @('-File', $startPath, '-Stop', '-SecretsModulePath', (Join-Path $testRoot 'missing-module.psm1'))
    Assert-LbTest ($stopInvocation.ExitCode -eq 0 -and $stopInvocation.Output -match 'LOCAL_BACKEND_STOPPED') 'stop path succeeds without importing secrets module'
    Assert-LbTest (-not (Test-Path -LiteralPath $envPath) -and -not (Test-Path -LiteralPath $statePath)) 'stop removes env and process state files'
    $sleepProcess.Refresh()
    Assert-LbTest $sleepProcess.HasExited 'stop terminates the tracked local process tree'
    Assert-LbTest ($stopInvocation.Output -notmatch 'TEST_ONLY_DB_CANARY|INTERNAL_TOKEN_CANARY') 'stop output contains no fake secret values'

    # A fake vault plus an unavailable command shell forces startup to fail after env creation but before any process/network.
    $startEnv = Join-Path $runtime 'startup-probe'
    $oldComSpec = $env:ComSpec
    $env:LOCALAPPDATA = $startEnv
    $env:ComSpec = Join-Path $testRoot 'missing-cmd.exe'
    $startupInvocation = Invoke-LbChildPowerShell -Arguments @('-File', $startPath, '-SecretsModulePath', $fakeModulePath, '-HealthTimeoutSeconds', '5')
    Assert-LbTest ($startupInvocation.ExitCode -ne 0 -and $startupInvocation.Output -match 'LOCAL_BACKEND_START_FAILED') 'fake-secret startup reports only generic failure'
    Assert-LbTest (-not (Test-Path -LiteralPath (Join-Path $startEnv 'Leviathan\local-backend\licensing.env'))) 'abnormal startup removes the private env file'
    Assert-LbTest ($startupInvocation.Output -notmatch 'TEST_ONLY_DB_CANARY|INTERNAL_TOKEN_CANARY|PRIVATE_KEY|FAKE_ONLY_KEY') 'startup output contains no fake secret values'
    $env:ComSpec = $oldComSpec
    $env:LOCALAPPDATA = $appData

    if ($failures.Count -gt 0) {
        [Console]::Error.WriteLine(('LOCAL_BACKEND_SELFTEST_FAILED count={0} cases={1}' -f $failures.Count, ($failures -join ',')))
        exit 1
    }
    [Console]::WriteLine(('LOCAL_BACKEND_SELFTEST_PASSED checks={0}' -f $checks))
    exit 0
} finally {
    if ($null -ne $sleepProcess -and -not $sleepProcess.HasExited) { $sleepProcess.Kill() }
    if ($null -ne $sleepProcess) { $sleepProcess.Dispose() }
    Remove-Module -Name LocalBackend.Common -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue }
}


