[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$MasterRoot,
    [string]$WranglerJsPath,
    [string]$NodeExePath,
    [string]$StripeTestPriceId,
    [ValidateSet('Test', 'Live')][string]$StripeMode = 'Test',
    [string]$StripeLivePriceId,
    [string]$XyraModulePath,
    [string[]]$ProviderIds = @('DATABENTO', 'MASSIVE', 'FRED', 'BEA', 'EIA', 'UNUSUAL_WHALES'),
    [switch]$InitializeLiveKeys,
    [switch]$RotateLiveKeys
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectScope = 'leviathan-ai'
$projectEnvironment = 'live'
$licensingWorker = 'leviathan-licensing-worker'
$releaseWorker = 'leviathan-release-feed'
$gatewayWorker = 'leviathan-data-gateway'
$releaseBucket = 'leviathan-release-feed'
$licensingOrigin = "https://$licensingWorker.ocean824.workers.dev"
$releaseOrigin = "https://$releaseWorker.ocean824.workers.dev"
$gatewayOrigin = "https://$gatewayWorker.ocean824.workers.dev"
$providerBindings = @{
    DATABENTO = 'PROVIDER__DATABENTO__API_KEY'
    MASSIVE = 'PROVIDER__MASSIVE__API_KEY'
    FRED = 'PROVIDER__FRED__API_KEY'
    BEA = 'PROVIDER__BEA__API_KEY'
    EIA = 'PROVIDER__EIA__API_KEY'
    UNUSUAL_WHALES = 'PROVIDER__UNUSUAL_WHALES__API_KEY'
}

function Write-Plan {
    Write-Output 'Plan only; no secrets read.'
    Write-Output 'Live key initialization writes four values and a final commit marker; rotation requires -RotateLiveKeys -InitializeLiveKeys.'
    Write-Output "R2 bucket: $releaseBucket"
    Write-Output "Deploy order: $licensingWorker, $gatewayWorker, $releaseWorker"
    Write-Output "Stripe mode: $StripeMode (Test is default; Live requires -StripeMode Live explicitly)"
    Write-Output 'Licensing secrets: DATABASE_URL, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, LICENSE_SIGNING_PRIVATE_KEY_PKCS8, ADMIN_TOTP_ENCRYPTION_KEY, INTERNAL_SERVICE_TOKEN'
    Write-Output 'Licensing vars: STRIPE_MODE, STRIPE_PRICE_ID, LICENSE_SIGNING_KEY_ID, LICENSE_VERIFY_PUBLIC_KEY_JWK, SIGNUP_SUCCESS_URL, SIGNUP_CANCEL_URL, ADMIN_SESSION_TTL_S, USER_SESSION_TTL_S, CAPS_APPROVED'
    foreach ($providerId in $ProviderIds) {
        if (-not $providerBindings.ContainsKey($providerId)) { throw 'PROVIDER_ID_INVALID' }
        Write-Output "Data gateway secret: $($providerBindings[$providerId])"
    }
}

function ConvertTo-SecureStringFromChars([char[]]$Chars) {
    $secure = [Security.SecureString]::new()
    foreach ($character in $Chars) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return $secure
}

function Convert-SecureStringToChars([Security.SecureString]$Value) {
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        $chars = New-Object char[] $Value.Length
        [Runtime.InteropServices.Marshal]::Copy($pointer, $chars, 0, $chars.Length)
        return ,$chars
    } finally {
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function New-SecretChars([byte[]]$Bytes, [switch]$UrlSafe) {
    $encoded = [Convert]::ToBase64String($Bytes)
    if ($UrlSafe) { $encoded = $encoded.TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    return $encoded.ToCharArray()
}

function Test-RegisteredSecret([string]$Name) {
    $value = $null
    try {
        $value = Get-XyraSecretStatus -Name $Name -Scope $projectScope -Environment $projectEnvironment
        return $true
    } catch {
        if ($_.Exception.Message -eq 'SECRET_NOT_CONFIGURED') { return $false }
        throw 'SECRET_REGISTRY_UNAVAILABLE'
    } finally {
        if ($null -ne $value -and $value -is [IDisposable]) { $value.Dispose() }
    }
}

function Set-GeneratedSecret([string]$Name, [char[]]$Chars, [switch]$Replace) {
    $secure = ConvertTo-SecureStringFromChars $Chars
    try { Set-XyraSecret -Name $Name -Scope $projectScope -Environment $projectEnvironment -Value $secure -Replace:$Replace }
    finally {
        $secure.Dispose()
        [Array]::Clear($Chars, 0, $Chars.Length)
    }
}

function New-SigningKeyPairBundle {
    $ecdsa = [Security.Cryptography.ECDsaCng]::new(256)
    $pkcs8 = $null
    try {
        $pkcs8 = $ecdsa.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $parameters = $ecdsa.ExportParameters($false)
        $x = [Convert]::ToBase64String($parameters.Q.X).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $y = [Convert]::ToBase64String($parameters.Q.Y).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return (@{ schema_version = 1; private_key_pkcs8 = [Convert]::ToBase64String($pkcs8);
            public_jwk = @{ crv = 'P-256'; kty = 'EC'; x = $x; y = $y } } | ConvertTo-Json -Compress -Depth 4)
    } finally {
        if ($null -ne $pkcs8) { [Array]::Clear($pkcs8, 0, $pkcs8.Length) }
        $ecdsa.Dispose()
    }
}

function Get-LiveRuntimeKeyNames {
    return @('LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8', 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK', 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY', 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN')
}

function Read-LiveRuntimeKeysetValues {
    $values = @{}
    foreach ($name in Get-LiveRuntimeKeyNames) {
        if (-not (Test-RegisteredSecret $name)) { continue }
        $secure = $null; $chars = $null
        try {
            $secure = Get-XyraSecret -Name $name -Scope $projectScope -Environment $projectEnvironment
            $chars = Convert-SecureStringToChars $secure
            $values[$name] = [string]::new($chars)
        } finally {
            if ($null -ne $secure) { $secure.Dispose() }
            if ($null -ne $chars -and $chars.Length -gt 0) { [Array]::Clear($chars, 0, $chars.Length) }
        }
    }
    return $values
}

function Read-LiveRuntimeKeysetMarker {
    $name = 'LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT'
    if (-not (Test-RegisteredSecret $name)) { return $null }
    $secure = $null; $chars = $null
    try {
        $secure = Get-XyraSecret -Name $name -Scope $projectScope -Environment $projectEnvironment
        $chars = Convert-SecureStringToChars $secure
        return [string]::new($chars)
    } finally {
        if ($null -ne $secure) { $secure.Dispose() }
        if ($null -ne $chars -and $chars.Length -gt 0) { [Array]::Clear($chars, 0, $chars.Length) }
    }
}

function Test-LiveRuntimeKeysetValues {
    param([hashtable]$Values)
    $privateName = 'LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8'
    $publicName = 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK'
    $totpName = 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY'
    $tokenName = 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN'
    foreach ($name in @($privateName, $publicName, $totpName, $tokenName)) { if (-not $Values.ContainsKey($name)) { return $false } }
    if (-not (Test-LiveSigningKeyPair -PrivateKeyPkcs8 ([string]$Values[$privateName]) -PublicJwkJson ([string]$Values[$publicName]))) { return $false }
    $totp = $null
    try { $totp = [Convert]::FromBase64String([string]$Values[$totpName]); if ($totp.Length -ne 32) { return $false } }
    catch { return $false }
    finally { if ($null -ne $totp) { [Array]::Clear($totp, 0, $totp.Length) } }
    return [string]$Values[$tokenName] -cmatch '^[A-Za-z0-9_-]{43}$'
}

function New-LiveRuntimeKeysetCandidate {
    $values = @{}
    $bundle = (New-SigningKeyPairBundle) | ConvertFrom-Json -ErrorAction Stop
    $values['LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8'] = [string]$bundle.private_key_pkcs8
    $values['LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK'] = $bundle.public_jwk | ConvertTo-Json -Compress -Depth 4
    foreach ($name in @('LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY', 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN')) {
        $random = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($random)
            $chars = if ($name.EndsWith('TOTP_ENCRYPTION_KEY')) { New-SecretChars $random } else { New-SecretChars $random -UrlSafe }
            try { $values[$name] = [string]::new($chars) }
            finally { [Array]::Clear($chars, 0, $chars.Length) }
        } finally { $rng.Dispose(); [Array]::Clear($random, 0, $random.Length) }
    }
    return $values
}

function Commit-LiveRuntimeKeysetValue([string]$Name, [string]$Value, [bool]$Replace) {
    $chars = $Value.ToCharArray()
    Set-GeneratedSecret $Name $chars -Replace:$Replace
}

function Initialize-LiveRuntimeKeys {
    $registration = Invoke-AtomicLiveRuntimeKeyRegistration `
        -ReadValues { Read-LiveRuntimeKeysetValues } `
        -ReadMarker { Read-LiveRuntimeKeysetMarker } `
        -Generate { New-LiveRuntimeKeysetCandidate } `
        -ValidateValues { param($values) Test-LiveRuntimeKeysetValues $values } `
        -Commit { param($name, $value, $replace) Commit-LiveRuntimeKeysetValue $name $value ([bool]$replace) } `
        -Rotate:$RotateLiveKeys
    if ($registration -eq 'EXISTING_VALID_KEYSET') { Write-Output 'A valid committed live licensing key set already exists; no key was changed.' }
    else { Write-Output 'A complete live licensing key set was committed; its marker verifies all four values.' }
}

function ConvertTo-WindowsArgument([string]$Value) {
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ([int][char]$character -eq 92) { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(([string][char]92 * (2 * $slashes + 1)))
            [void]$builder.Append('"')
        } else {
            [void]$builder.Append(([string][char]92 * $slashes))
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    [void]$builder.Append(([string][char]92 * (2 * $slashes)))
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Start-WranglerProcess([string[]]$Arguments, [Security.SecureString]$ApiToken, [Security.SecureString]$StdinSecret) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $NodeExePath
    $start.WorkingDirectory = $projectRoot
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    $commandArguments = @((Resolve-Path -LiteralPath $WranglerJsPath).Path) + $Arguments
    $start.Arguments = ($commandArguments | ForEach-Object { ConvertTo-WindowsArgument ([string]$_) }) -join ' '
    $apiChars = Convert-SecureStringToChars $ApiToken
    $apiText = [string]::new($apiChars)
    [Array]::Clear($apiChars, 0, $apiChars.Length)
    $start.EnvironmentVariables['CLOUDFLARE_API_TOKEN'] = $apiText
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'WRANGLER_START_FAILED' }
        [void]$start.EnvironmentVariables.Remove('CLOUDFLARE_API_TOKEN')
        $apiText = $null
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if ($null -ne $StdinSecret) {
            $secretChars = Convert-SecureStringToChars $StdinSecret
            try { $process.StandardInput.Write($secretChars, 0, $secretChars.Length); $process.StandardInput.WriteLine(); $process.StandardInput.Flush() }
            finally { [Array]::Clear($secretChars, 0, $secretChars.Length) }
        }
        $process.StandardInput.Close()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        [void]$stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'WRANGLER_COMMAND_FAILED' }
        return $stdout
    } catch { throw 'WRANGLER_COMMAND_FAILED' }
    finally {
        $apiText = $null
        [void]$start.EnvironmentVariables.Remove('CLOUDFLARE_API_TOKEN')
        $process.Dispose()
    }
}

function Get-ProjectSecret([string]$Name) {
    try { return Get-XyraSecret -Name $Name -Scope $projectScope -Environment $projectEnvironment }
    catch { throw 'REQUIRED_SECRET_UNAVAILABLE' }
}

function Invoke-SecretPutValue([string]$WorkerName, [string]$BindingName, [Security.SecureString]$Secret, [Security.SecureString]$ApiToken) {
    [void](Start-WranglerProcess @('secret', 'put', $BindingName, '--name', $WorkerName) $ApiToken $Secret)
    Write-Output "Configured secret binding: $WorkerName/$BindingName"
}

function Invoke-SecretPut([string]$WorkerName, [string]$BindingName, [string]$RegistryName, [Security.SecureString]$ApiToken) {
    $secret = Get-ProjectSecret $RegistryName
    try { Invoke-SecretPutValue $WorkerName $BindingName $secret $ApiToken }
    finally { $secret.Dispose() }
}

function ConvertFrom-SecureStringText([Security.SecureString]$Value) {
    $chars = Convert-SecureStringToChars $Value
    try { return [string]::new($chars) }
    finally { [Array]::Clear($chars, 0, $chars.Length) }
}

function ConvertTo-FormField([string]$Name, [string]$Value) {
    return [Uri]::EscapeDataString($Name) + '=' + [Uri]::EscapeDataString($Value)
}

function Invoke-StripeWebhookEnsure([string]$Mode, [Security.SecureString]$ApiSecret, [string]$SecretRegistryName) {
    $apiKey = ConvertFrom-SecureStringText $ApiSecret
    $url = "$licensingOrigin/v1/signup/webhook"
    $marker = "Leviathan licensing $Mode webhook"
    $events = @('checkout.session.completed','invoice.paid','customer.subscription.updated','customer.subscription.deleted')
    $headers = @{ Authorization = "Bearer $apiKey" }
    $found = @()
    try {
        $cursor = $null
        do {
            $uri = 'https://api.stripe.com/v1/webhook_endpoints?limit=100' + $(if ($cursor) { '&starting_after=' + [Uri]::EscapeDataString($cursor) } else { '' })
            $page = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 30 -ErrorAction Stop
            foreach ($item in @($page.data)) { if ($item.url -ceq $url) { $found += $item } }
            $cursor = if ($page.has_more -and @($page.data).Count -gt 0) { [string]$page.data[-1].id } else { $null }
        } while ($cursor)
        $managed = @($found | Where-Object { $_.description -ceq $marker })
        if ($managed.Count -gt 1) { throw 'STRIPE_WEBHOOK_AMBIGUOUS' }
        $chosen = if ($managed.Count -eq 1) { $managed[0] } elseif ($found.Count -eq 1) { $found[0] } else { $null }
        $hasSecret = Test-RegisteredSecret $SecretRegistryName
        if ($null -ne $chosen -and $hasSecret) {
            $fields = @((ConvertTo-FormField 'url' $url),(ConvertTo-FormField 'description' $marker))
            foreach ($event in $events) { $fields += ConvertTo-FormField 'enabled_events[]' $event }
            $body = $fields -join '&'
            $updated = Invoke-RestMethod -Method Post -Uri "https://api.stripe.com/v1/webhook_endpoints/$($chosen.id)" `
                -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body -TimeoutSec 30 -ErrorAction Stop
            foreach ($duplicate in @($found | Where-Object { $_.id -ne $updated.id })) {
                [void](Invoke-RestMethod -Method Delete -Uri "https://api.stripe.com/v1/webhook_endpoints/$($duplicate.id)" `
                    -Headers $headers -TimeoutSec 30 -ErrorAction Stop)
            }
            return Get-XyraSecret -Name $SecretRegistryName -Scope $projectScope -Environment $projectEnvironment
        }
        $fields = @((ConvertTo-FormField 'url' $url),(ConvertTo-FormField 'description' $marker))
        foreach ($event in $events) { $fields += ConvertTo-FormField 'enabled_events[]' $event }
        $createBody = $fields -join '&'
        $created = Invoke-RestMethod -Method Post -Uri 'https://api.stripe.com/v1/webhook_endpoints' `
            -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $createBody -TimeoutSec 30 -ErrorAction Stop
        if ($created.url -cne $url -or [string]$created.id -notmatch '^we_[A-Za-z0-9]+$' -or [string]$created.secret -notmatch '^whsec_[A-Za-z0-9_-]{8,}$') {
            try { [void](Invoke-RestMethod -Method Delete -Uri "https://api.stripe.com/v1/webhook_endpoints/$($created.id)" -Headers $headers -TimeoutSec 30 -ErrorAction Stop) } catch { }
            throw 'STRIPE_WEBHOOK_CREATE_INVALID'
        }
        $secretChars = ([string]$created.secret).ToCharArray()
        $secureWebhook = ConvertTo-SecureStringFromChars $secretChars
        try {
            try { Set-XyraSecret -Name $SecretRegistryName -Scope $projectScope -Environment $projectEnvironment -Value $secureWebhook }
            catch {
                try { [void](Invoke-RestMethod -Method Delete -Uri "https://api.stripe.com/v1/webhook_endpoints/$($created.id)" -Headers $headers -TimeoutSec 30 -ErrorAction Stop) } catch { }
                throw 'STRIPE_WEBHOOK_VAULT_WRITE_FAILED'
            }
        } finally { $secureWebhook.Dispose() }
        foreach ($duplicate in @($found | Where-Object { $_.id -ne $created.id })) {
            [void](Invoke-RestMethod -Method Delete -Uri "https://api.stripe.com/v1/webhook_endpoints/$($duplicate.id)" `
                -Headers $headers -TimeoutSec 30 -ErrorAction Stop)
        }
        return Get-XyraSecret -Name $SecretRegistryName -Scope $projectScope -Environment $projectEnvironment
    } catch {
        $message = $_.Exception.Message
        if ($message -like 'STRIPE_WEBHOOK_*') { throw $message }
        throw 'STRIPE_WEBHOOK_CONFIG_FAILED'
    } finally { $apiKey = $null; $headers.Clear() }
}

function Assert-StripeModeCredentialPair([string]$Mode, [Security.SecureString]$ApiKey, [string]$PublishableName, [string]$PublishableScope, [string]$PublishableEnvironment) {
    $prefix = if ($Mode -eq 'Test') { 'test' } else { 'live' }
    $secretText = ConvertFrom-SecureStringText $ApiKey
    $publishable = $null
    $publishableChars = $null
    try {
        $publishable = Get-XyraSecret -Name $PublishableName -Scope $PublishableScope -Environment $PublishableEnvironment
        $publishableChars = Convert-SecureStringToChars $publishable
        $publishableText = [string]::new($publishableChars)
        if ($secretText -notmatch "^sk_$prefix_[A-Za-z0-9_]+$" -or $publishableText -notmatch "^pk_$prefix_[A-Za-z0-9_]+$") {
            throw 'STRIPE_MODE_KEY_MISMATCH'
        }
    } catch {
        if ($_.Exception.Message -eq 'STRIPE_MODE_KEY_MISMATCH') { throw }
        throw 'STRIPE_MODE_KEY_UNAVAILABLE'
    } finally {
        $secretText = $null
        if ($null -ne $publishable) { $publishable.Dispose() }
        if ($null -ne $publishableChars -and $publishableChars.Length -gt 0) { [Array]::Clear($publishableChars, 0, $publishableChars.Length) }
    }
}

function Invoke-Deploy([string]$WorkerDirectory, [string[]]$Vars, [Security.SecureString]$ApiToken) {
    $args = @('deploy', '--config', (Join-Path $WorkerDirectory 'wrangler.toml'))
    foreach ($variable in $Vars) { $args += @('--var', $variable) }
    [void](Start-WranglerProcess $args $ApiToken $null)
    Write-Output "Deployed Worker: $(Split-Path -Leaf $WorkerDirectory)"
}

function Invoke-R2BucketEnsure([Security.SecureString]$ApiToken) {
    $listing = Start-WranglerProcess @('r2', 'bucket', 'list', '--json') $ApiToken $null
    try { $buckets = $listing | ConvertFrom-Json } catch { throw 'R2_BUCKET_LIST_INVALID' }
    if (@($buckets | Where-Object { $_.name -eq $releaseBucket }).Count -gt 0) {
        Write-Output "R2 bucket exists: $releaseBucket"
        return
    }
    [void](Start-WranglerProcess @('r2', 'bucket', 'create', $releaseBucket) $ApiToken $null)
    Write-Output "Created R2 bucket: $releaseBucket"
}

function Invoke-Smoke([string]$Url, [int[]]$AcceptedStatuses, [switch]$AllowManifestBody) {
    $status = 0
    $content = ''
    try {
        $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 20 -UseBasicParsing
        $status = [int]$response.StatusCode
        $content = [string]$response.Content
    } catch {
        $failedResponse = $_.Exception.Response
        if ($null -eq $failedResponse) { throw 'SMOKE_CHECK_FAILED' }
        $status = [int]$failedResponse.StatusCode
    }
    if ($AcceptedStatuses -notcontains $status) { throw 'SMOKE_CHECK_FAILED' }
    if ($status -eq 200 -and $AllowManifestBody) {
        try { $null = $content | ConvertFrom-Json } catch { throw 'SMOKE_CHECK_FAILED' }
    }
    Write-Output "Smoke check passed: $Url ($status)"
}

if ($WhatIfPreference) { Write-Plan; return }
if ($ProviderIds | Where-Object { -not $providerBindings.ContainsKey($_) }) { throw 'PROVIDER_ID_INVALID' }
if ($StripeMode -eq 'Test') {
    if (-not $StripeTestPriceId -or $StripeTestPriceId -notmatch '^price_[A-Za-z0-9]+$') { throw 'STRIPE_PRICE_ID_INVALID' }
    $stripePriceId = $StripeTestPriceId
    $stripeApiRegistry = 'LEVIATHAN_LICENSING_STRIPE_TEST_SECRET_KEY'
    $stripeWebhookRegistry = 'LEVIATHAN_LICENSING_STRIPE_TEST_WEBHOOK_SECRET'
    $stripePublishableVaultName = 'STRIPE_TEST_PUBLISHABLE_KEY'
    $stripePublishableScope = 'factory-admin'; $stripePublishableEnvironment = 'test'
} else {
    if (-not $StripeLivePriceId -or $StripeLivePriceId -notmatch '^price_[A-Za-z0-9]+$') { throw 'STRIPE_LIVE_PRICE_ID_REQUIRED' }
    $stripePriceId = $StripeLivePriceId
    $stripeApiRegistry = 'STRIPE_LIVE_SECRET_KEY'
    $stripeWebhookRegistry = 'LEVIATHAN_LICENSING_STRIPE_LIVE_WEBHOOK_SECRET'
    $stripePublishableVaultName = 'STRIPE_LIVE_PUBLISHABLE_KEY'
    $stripePublishableScope = 'factory-admin'; $stripePublishableEnvironment = 'live'
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$module = if ($XyraModulePath) { $XyraModulePath } else { Join-Path (Resolve-Path $MasterRoot).Path 'factory\tools\secrets\Xyra.Secrets.psm1' }
if (-not (Test-Path -LiteralPath $module -PathType Leaf)) { throw 'XYRA_SECRETS_MODULE_UNAVAILABLE' }
Import-Module -Name $module -Force
Import-Module -Name (Join-Path $PSScriptRoot 'SigningKeyPair.psm1') -Force

if ($RotateLiveKeys -and -not $InitializeLiveKeys) { throw 'ROTATE_REQUIRES_INITIALIZE_LIVE_KEYS' }
if ($InitializeLiveKeys) { Initialize-LiveRuntimeKeys; return }
$liveRuntimeKeyValues = Read-LiveRuntimeKeysetValues
$liveRuntimeKeysetMarker = Read-LiveRuntimeKeysetMarker
if (-not (Test-LiveRuntimeKeysetCommit -Values $liveRuntimeKeyValues -Marker $liveRuntimeKeysetMarker -ValidateValues { param($values) Test-LiveRuntimeKeysetValues $values })) { throw 'LIVE_RUNTIME_KEYSET_UNCOMMITTED: initialize or repair the complete key set before deployment.' }
if (-not (Test-Path -LiteralPath $WranglerJsPath -PathType Leaf) -or -not (Test-Path -LiteralPath $NodeExePath -PathType Leaf)) {
    throw 'PINNED_WRANGLER_RUNTIME_REQUIRED'
}

$apiToken = $null
$stripeApiSecret = $null
$stripeWebhookSecret = $null
try {
    $apiToken = Get-XyraSecret -Name 'CLOUDFLARE_MASTER_API_TOKEN' -Scope 'factory-admin' -Environment 'administration'
    Invoke-R2BucketEnsure $apiToken

    $licensingDirectory = Join-Path $projectRoot 'workers\licensing'
    $gatewayDirectory = Join-Path $projectRoot 'workers\data-gateway'
    $releaseDirectory = Join-Path $projectRoot 'workers\release-feed'

    $privateKeyChars = ([string]$liveRuntimeKeyValues['LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8']).ToCharArray()
    $privateKeySecure = ConvertTo-SecureStringFromChars $privateKeyChars
    [Array]::Clear($privateKeyChars, 0, $privateKeyChars.Length)
    $jwk = [string]$liveRuntimeKeyValues['LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK']
    $licensingVars = @(
        "STRIPE_MODE:$($StripeMode.ToLowerInvariant())",
        "STRIPE_PRICE_ID:$stripePriceId",
        'LICENSE_SIGNING_KEY_ID:leviathan-live-2026-10',
        "LICENSE_VERIFY_PUBLIC_KEY_JWK:$jwk",
        "SIGNUP_SUCCESS_URL:$licensingOrigin/v1/signup/success",
        "SIGNUP_CANCEL_URL:$licensingOrigin/v1/signup/cancel",
        'ADMIN_SESSION_TTL_S:900', 'USER_SESSION_TTL_S:900', 'CAPS_APPROVED:true'
    )
    Invoke-Deploy $licensingDirectory $licensingVars $apiToken

    $stripeApiSecret = if ($StripeMode -eq 'Test') {
        Get-ProjectSecret $stripeApiRegistry
    } else {
        Get-XyraSecret -Name $stripeApiRegistry -Scope 'factory-admin' -Environment 'live'
    }
    $stripeWebhookSecret = $null
    Assert-StripeModeCredentialPair $StripeMode $stripeApiSecret $stripePublishableVaultName $stripePublishableScope $stripePublishableEnvironment
    $stripeWebhookSecret = Invoke-StripeWebhookEnsure $StripeMode $stripeApiSecret $stripeWebhookRegistry

    Invoke-SecretPut $licensingWorker 'DATABASE_URL' $apiToken
    $totpChars = ([string]$liveRuntimeKeyValues['LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY']).ToCharArray()
    $tokenChars = ([string]$liveRuntimeKeyValues['LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN']).ToCharArray()
    $totpSecure = ConvertTo-SecureStringFromChars $totpChars
    $internalTokenSecure = ConvertTo-SecureStringFromChars $tokenChars
    try {
        Invoke-SecretPutValue $licensingWorker 'ADMIN_TOTP_ENCRYPTION_KEY' $totpSecure $apiToken
        Invoke-SecretPutValue $licensingWorker 'INTERNAL_SERVICE_TOKEN' $internalTokenSecure $apiToken
    } finally {
        $totpSecure.Dispose(); $internalTokenSecure.Dispose()
        [Array]::Clear($totpChars, 0, $totpChars.Length); [Array]::Clear($tokenChars, 0, $tokenChars.Length)
    }
    Invoke-SecretPutValue $licensingWorker 'STRIPE_SECRET_KEY' $stripeApiSecret $apiToken
    $stripeApiSecret.Dispose(); $stripeApiSecret = $null
    Invoke-SecretPutValue $licensingWorker 'STRIPE_WEBHOOK_SECRET' $stripeWebhookSecret $apiToken
    $stripeWebhookSecret.Dispose(); $stripeWebhookSecret = $null
    Invoke-SecretPutValue $licensingWorker 'LICENSE_SIGNING_PRIVATE_KEY_PKCS8' $privateKeySecure $apiToken
    $privateKeySecure.Dispose(); $privateKeySecure = $null
    $jwk = $null
    Invoke-Deploy $licensingDirectory $licensingVars $apiToken

    foreach ($providerId in $ProviderIds) {
        $binding = $providerBindings[$providerId]
        $registryName = "LEVIATHAN_DATA_GATEWAY_${providerId}_API_KEY"
        Invoke-SecretPut $gatewayWorker $binding $registryName $apiToken
    }
    Invoke-Deploy $gatewayDirectory @() $apiToken
    Invoke-Deploy $releaseDirectory @() $apiToken
} finally {
    if ($null -ne $apiToken) { $apiToken.Dispose() }
    if ($null -ne $privateKeySecure) { $privateKeySecure.Dispose() }
    if ($null -ne $stripeApiSecret) { $stripeApiSecret.Dispose() }
    if ($null -ne $stripeWebhookSecret) { $stripeWebhookSecret.Dispose() }
}

Invoke-Smoke "$licensingOrigin/health" @(200)
Invoke-Smoke "$gatewayOrigin/health" @(200)
Invoke-Smoke "$releaseOrigin/health" @(200)
Invoke-Smoke "$releaseOrigin/v1/updates/desktop/windows/x86_64/0.0.0" @(200, 204) -AllowManifestBody
Invoke-Smoke "$releaseOrigin/latest.json" @(200, 404) -AllowManifestBody
Invoke-Smoke "$licensingOrigin/v1/signup/success" @(200)
Invoke-Smoke "$licensingOrigin/v1/signup/cancel" @(200)
Invoke-Smoke "$licensingOrigin/v1/admin/license" @(401, 403)



