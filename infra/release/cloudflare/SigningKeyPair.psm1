function Test-LiveSigningKeyPair {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PrivateKeyPkcs8, [Parameter(Mandatory = $true)][string]$PublicJwkJson)
    $privateBytes = $null; $cngKey = $null; $ecdsa = $null
    try {
        $jwk = $PublicJwkJson | ConvertFrom-Json -ErrorAction Stop
        if ($jwk.kty -cne 'EC' -or $jwk.crv -cne 'P-256' -or [string]$jwk.x -cnotmatch '^[A-Za-z0-9_-]{43}$' -or [string]$jwk.y -cnotmatch '^[A-Za-z0-9_-]{43}$') { return $false }
        $privateBytes = [Convert]::FromBase64String($PrivateKeyPkcs8)
        $cngKey = [Security.Cryptography.CngKey]::Import($privateBytes, [Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $ecdsa = [Security.Cryptography.ECDsaCng]::new($cngKey)
        $public = $ecdsa.ExportParameters($false)
        $x = [Convert]::ToBase64String($public.Q.X).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $y = [Convert]::ToBase64String($public.Q.Y).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        return $x -ceq [string]$jwk.x -and $y -ceq [string]$jwk.y
    } catch { return $false }
    finally {
        if ($null -ne $privateBytes) { [Array]::Clear($privateBytes, 0, $privateBytes.Length) }
        if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        if ($null -ne $cngKey) { $cngKey.Dispose() }
    }
}

function Get-LiveRuntimeKeysetNames {
    return @('LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8', 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK', 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY', 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN')
}

function Get-LiveRuntimeKeysetDigest {
    param([Parameter(Mandatory = $true)][hashtable]$Values, [Parameter(Mandatory = $true)][string]$KeysetId)
    $canonical = [Text.StringBuilder]::new()
    [void]$canonical.Append($KeysetId.Length).Append(':').Append($KeysetId)
    foreach ($name in Get-LiveRuntimeKeysetNames) {
        if (-not $Values.ContainsKey($name)) { throw 'LIVE_RUNTIME_KEYSET_INCOMPLETE' }
        $value = [string]$Values[$name]
        [void]$canonical.Append($name.Length).Append(':').Append($name).Append($value.Length).Append(':').Append($value)
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($canonical.ToString())
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $sha.Dispose() }
}

function Test-LiveRuntimeKeysetCommit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Values,
        [AllowNull()][string]$Marker,
        [Parameter(Mandatory = $true)][scriptblock]$ValidateValues
    )
    if ($null -eq $Marker -or -not (& $ValidateValues $Values)) { return $false }
    foreach ($name in Get-LiveRuntimeKeysetNames) { if (-not $Values.ContainsKey($name) -or [string]::IsNullOrEmpty([string]$Values[$name])) { return $false } }
    try {
        $parsed = $Marker | ConvertFrom-Json -ErrorAction Stop
        if ($parsed.schema_version -ne 1 -or [string]$parsed.keyset_id -notmatch '^[0-9a-f]{32}$' -or [string]$parsed.digest -notmatch '^[0-9a-f]{64}$') { return $false }
        $digest = Get-LiveRuntimeKeysetDigest -Values $Values -KeysetId ([string]$parsed.keyset_id)
        return [string]$parsed.digest -ceq $digest
    } catch { return $false }
}

function New-LiveRuntimeKeysetCommitMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Values)
    $keysetId = [Guid]::NewGuid().ToString('N')
    $digest = Get-LiveRuntimeKeysetDigest -Values $Values -KeysetId $keysetId
    return (@{ schema_version = 1; keyset_id = $keysetId; digest = $digest } | ConvertTo-Json -Compress)
}

function Invoke-AtomicLiveRuntimeKeyRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ReadValues,
        [Parameter(Mandatory = $true)][scriptblock]$ReadMarker,
        [Parameter(Mandatory = $true)][scriptblock]$Generate,
        [Parameter(Mandatory = $true)][scriptblock]$ValidateValues,
        [Parameter(Mandatory = $true)][scriptblock]$Commit,
        [switch]$Rotate
    )
    $values = & $ReadValues
    $marker = & $ReadMarker
    if ((Test-LiveRuntimeKeysetCommit -Values $values -Marker $marker -ValidateValues $ValidateValues) -and -not $Rotate) { return 'EXISTING_VALID_KEYSET' }
    $candidate = & $Generate
    if ($null -eq $candidate -or -not (& $ValidateValues $candidate)) { throw 'LIVE_RUNTIME_KEYSET_GENERATION_INVALID' }
    $names = @(Get-LiveRuntimeKeysetNames)
    foreach ($name in $names) { if (-not $candidate.ContainsKey($name)) { throw 'LIVE_RUNTIME_KEYSET_GENERATION_INVALID' } }
    $newMarker = New-LiveRuntimeKeysetCommitMarker -Values $candidate
    foreach ($name in $names) { & $Commit $name ([string]$candidate[$name]) $true }
    & $Commit 'LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT' $newMarker $true
    $committedValues = & $ReadValues
    $committedMarker = & $ReadMarker
    if (-not (Test-LiveRuntimeKeysetCommit -Values $committedValues -Marker $committedMarker -ValidateValues $ValidateValues)) {
        throw 'LIVE_RUNTIME_KEYSET_COMMIT_UNVERIFIED: retry initialization; no key may be deployed until the marker validates.'
    }
    foreach ($name in $names) { if ([string]$committedValues[$name] -cne [string]$candidate[$name]) { throw 'LIVE_RUNTIME_KEYSET_COMMIT_UNVERIFIED: retry initialization; no key may be deployed until the marker validates.' } }
    return 'CREATED_VALID_KEYSET'
}

Export-ModuleMember -Function Test-LiveSigningKeyPair, Get-LiveRuntimeKeysetNames, Get-LiveRuntimeKeysetDigest, Test-LiveRuntimeKeysetCommit, New-LiveRuntimeKeysetCommitMarker, Invoke-AtomicLiveRuntimeKeyRegistration
