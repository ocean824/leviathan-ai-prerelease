Set-StrictMode -Version 2.0

function ConvertTo-LbPlainText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Security.SecureString]$SecureValue)
    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function ConvertTo-LbPrivateKeyBase64 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Pem)
    $body = $Pem -replace '-----BEGIN PRIVATE KEY-----', '' -replace '-----END PRIVATE KEY-----', ''
    $body = $body -replace '\s', ''
    try {
        if ($body.Length -lt 16 -or $body -notmatch '^[A-Za-z0-9+/]+={0,2}$') {
            throw 'INVALID'
        }
        $bytes = [Convert]::FromBase64String($body)
        if ($bytes.Length -lt 32) { throw 'INVALID' }
        return [Convert]::ToBase64String($bytes)
    } catch {
        throw 'LOCAL_BACKEND_INVALID_SIGNING_KEY'
    }
}

function ConvertTo-LbCompactJwk {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Json)
    try {
        $jwk = ConvertFrom-Json -InputObject $Json -ErrorAction Stop
        if ($jwk.kty -ne 'EC' -or $jwk.crv -ne 'P-256' -or
            [string]::IsNullOrWhiteSpace([string]$jwk.x) -or
            [string]::IsNullOrWhiteSpace([string]$jwk.y) -or
            (@($jwk.PSObject.Properties.Name) -contains 'd')) {
            throw 'INVALID'
        }
        return ConvertTo-Json -InputObject $jwk -Compress -Depth 10
    } catch {
        throw 'LOCAL_BACKEND_INVALID_PUBLIC_JWK'
    }
}

function ConvertTo-LbEnvScalar {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value)
    if ($Value.Length -eq 0 -or $Value -match '[\x00\r\n#]' -or $Value -ne $Value.Trim()) {
        throw 'LOCAL_BACKEND_INVALID_BINDING'
    }
    return ($Name + '=' + $Value)
}

function Test-LbSafeEnvFilePath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    return ($Path.IndexOf('"') -lt 0 -and $Path.IndexOf([char]0) -lt 0 -and
        $Path.IndexOf([char]10) -lt 0 -and $Path.IndexOf([char]13) -lt 0)
}

function New-LbLocalBindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$CoreSecrets,
        [AllowNull()][string]$StripeTestKey
    )
    $required = @(
        'DATABASE_URL', 'LICENSE_SIGNING_PRIVATE_KEY_PKCS8',
        'LICENSE_VERIFY_PUBLIC_KEY_JWK', 'ADMIN_TOTP_ENCRYPTION_KEY',
        'INTERNAL_SERVICE_TOKEN'
    )
    foreach ($name in $required) {
        if (-not $CoreSecrets.Contains($name) -or [string]::IsNullOrEmpty([string]$CoreSecrets[$name])) {
            throw 'LOCAL_BACKEND_REQUIRED_SECRET_MISSING'
        }
    }
    if ([string]$CoreSecrets['DATABASE_URL'] -notmatch '^postgres(?:ql)?://') {
        throw 'LOCAL_BACKEND_INVALID_DATABASE_URL'
    }
    try {
        $totpKey = [Convert]::FromBase64String([string]$CoreSecrets['ADMIN_TOTP_ENCRYPTION_KEY'])
        if ($totpKey.Length -ne 32) { throw 'INVALID' }
    } catch {
        throw 'LOCAL_BACKEND_INVALID_TOTP_KEY'
    }
    $bindings = [ordered]@{
        DATABASE_URL = [string]$CoreSecrets['DATABASE_URL']
        STRIPE_WEBHOOK_SECRET = ''
        STRIPE_PRICE_ID = 'price_LOCALPLACEHOLDER0'
        SIGNUP_SUCCESS_URL = 'https://127.0.0.1/signup/success'
        SIGNUP_CANCEL_URL = 'https://127.0.0.1/signup/cancel'
        ADMIN_SESSION_TTL_S = '900'
        USER_SESSION_TTL_S = '900'
        CAPS_APPROVED = 'false'
        LICENSE_SIGNING_KEY_ID = 'local-dev-es256-v1'
        LICENSE_SIGNING_PRIVATE_KEY_PKCS8 = [string]$CoreSecrets['LICENSE_SIGNING_PRIVATE_KEY_PKCS8']
        LICENSE_VERIFY_PUBLIC_KEY_JWK = [string]$CoreSecrets['LICENSE_VERIFY_PUBLIC_KEY_JWK']
        INTERNAL_SERVICE_TOKEN = [string]$CoreSecrets['INTERNAL_SERVICE_TOKEN']
        ADMIN_TOTP_ENCRYPTION_KEY = [string]$CoreSecrets['ADMIN_TOTP_ENCRYPTION_KEY']
    }
    $random = New-Object byte[] 32
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $bindings['STRIPE_WEBHOOK_SECRET'] = 'whsec_' + [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [Array]::Clear($random, 0, $random.Length)
    if (-not [string]::IsNullOrWhiteSpace($StripeTestKey)) {
        if ($StripeTestKey -notmatch '^sk_test_[A-Za-z0-9_]+$') {
            throw 'LOCAL_BACKEND_TEST_STRIPE_KEY_INVALID'
        }
        $bindings['STRIPE_SECRET_KEY'] = $StripeTestKey
    }
    foreach ($key in @($bindings.Keys)) {
        $bindings[$key] = (ConvertTo-LbEnvScalar -Name $key -Value ([string]$bindings[$key])).Substring($key.Length + 1)
    }
    return $bindings
}

function ConvertTo-LbEnvFileText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Bindings)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($name in $Bindings.Keys) {
        if ([string]$name -notmatch '^[A-Z][A-Z0-9_]{1,79}$') { throw 'LOCAL_BACKEND_INVALID_BINDING_NAME' }
        $lines.Add((ConvertTo-LbEnvScalar -Name ([string]$name) -Value ([string]$Bindings[$name])))
    }
    return (($lines -join "`n") + "`n")
}

function Set-LbUserOnlyAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($Directory) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    } else {
        $acl = New-Object Security.AccessControl.FileSecurity
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl',
            [Security.AccessControl.AccessControlType]::Allow)
    }
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $null = $acl.AddAccessRule($rule)
    if ($Directory) { [IO.Directory]::SetAccessControl($Path, $acl) }
    else { [IO.File]::SetAccessControl($Path, $acl) }
    Assert-LbUserOnlyAcl -Path $Path
}

function Assert-LbUserOnlyAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (-not $acl.AreAccessRulesProtected -or $owner -ne $sid -or $rules.Count -ne 1 -or
        $rules[0].IdentityReference.Value -ne $sid -or
        $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw 'LOCAL_BACKEND_ACL_DENIED'
    }
}

function Write-LbPrivateEnvFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Content)
    $directory = [IO.Path]::GetDirectoryName($Path)
    if (-not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }
    Set-LbUserOnlyAcl -Path $directory -Directory
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
    Set-LbUserOnlyAcl -Path $Path
}

function Get-LbEnvValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    Assert-LbUserOnlyAcl -Path $Path
    $matches = @([IO.File]::ReadAllLines($Path) | Where-Object { $_ -match ('^' + [regex]::Escape($Name) + '=') })
    if ($matches.Count -ne 1) { throw 'LOCAL_BACKEND_DATABASE_URL_UNAVAILABLE' }
    $value = $matches[0].Substring($Name.Length + 1)
    if ([string]::IsNullOrWhiteSpace($value) -or $value -notmatch '^postgres(?:ql)?://') {
        throw 'LOCAL_BACKEND_DATABASE_URL_UNAVAILABLE'
    }
    return $value
}

function Get-LbHttpResponse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri]$Uri, [ValidateRange(1, 10)][int]$TimeoutSeconds = 2)
    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Get -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Headers = $response.Headers; Content = [string]$response.Content }
    } catch {
        $webResponse = $_.Exception.Response
        if ($null -eq $webResponse) {
            return [pscustomobject]@{ StatusCode = 0; Headers = @{}; Content = '' }
        }
        $content = ''
        try {
            $reader = New-Object IO.StreamReader($webResponse.GetResponseStream())
            try { $content = $reader.ReadToEnd() } finally { $reader.Dispose() }
        } catch { $content = '' }
        return [pscustomobject]@{ StatusCode = [int]$webResponse.StatusCode; Headers = $webResponse.Headers; Content = $content }
    }
}

function Get-LbJsonErrorCode {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Content)
    try {
        $body = ConvertFrom-Json -InputObject $Content -ErrorAction Stop
        return [string]$body.error.code
    } catch { return '' }
}

Export-ModuleMember -Function ConvertTo-LbPlainText, ConvertTo-LbPrivateKeyBase64, ConvertTo-LbCompactJwk,
    Test-LbSafeEnvFilePath, New-LbLocalBindings, ConvertTo-LbEnvFileText, Set-LbUserOnlyAcl, Assert-LbUserOnlyAcl,
    Write-LbPrivateEnvFile, Get-LbEnvValue, Get-LbHttpResponse, Get-LbJsonErrorCode



