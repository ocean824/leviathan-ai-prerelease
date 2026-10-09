$modulePath = Join-Path $PSScriptRoot '..\cloudflare\SigningKeyPair.psm1'
Import-Module $modulePath -Force

Describe 'atomic live runtime keyset registration' {
    BeforeEach {
        $global:cfKeysetStore = @{}
        $global:cfKeysetCandidate = @{
            LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8 = 'synthetic-private-key'
            LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK = '{"kty":"EC","crv":"P-256"}'
            LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY = 'synthetic-totp-key'
            LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN = 'synthetic-internal-token'
        }
        $global:cfKeysetWrites = 0
        $global:cfKeysetWriteOrder = @{}
        $global:cfKeysetFailAt = $null
        $global:cfKeysetRead = {
            $values = @{}
            foreach ($name in (Get-LiveRuntimeKeysetNames)) {
                if ($global:cfKeysetStore.ContainsKey($name)) { $values[$name] = $global:cfKeysetStore[$name] }
            }
            return $values
        }
        $global:cfKeysetMarker = {
            if ($global:cfKeysetStore.ContainsKey('LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT')) {
                return $global:cfKeysetStore['LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT']
            }
            return $null
        }
        $global:cfKeysetValidate = {
            param($values)
            foreach ($name in (Get-LiveRuntimeKeysetNames)) { if (-not $values.ContainsKey($name)) { return $false } }
            return $true
        }
        $global:cfKeysetGenerate = { return $global:cfKeysetCandidate }
        $global:cfKeysetCommit = {
            param($name, $value, $replace)
            $global:cfKeysetWrites++
            $global:cfKeysetWriteOrder[$global:cfKeysetWrites] = $name
            if ($global:cfKeysetFailAt -eq $name) { throw 'injected write failure' }
            if ($global:cfKeysetStore.ContainsKey($name) -and -not $replace) { throw 'replace required' }
            $global:cfKeysetStore[$name] = $value
        }
    }

    It 'writes the four values before the marker and treats a valid matching commit as idempotent' {
        $first = Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit
        $first | Should Be 'CREATED_VALID_KEYSET'
        $global:cfKeysetWrites | Should Be 5
        $global:cfKeysetWriteOrder[1] | Should Be 'LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8'
        $global:cfKeysetWriteOrder[2] | Should Be 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK'
        $global:cfKeysetWriteOrder[3] | Should Be 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY'
        $global:cfKeysetWriteOrder[4] | Should Be 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN'
        $global:cfKeysetWriteOrder[5] | Should Be 'LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT'
        $second = Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit
        $second | Should Be 'EXISTING_VALID_KEYSET'
        $global:cfKeysetWrites | Should Be 5
    }

    It 'rejects uncommitted partial writes and retry converges after each value or marker failure' {
        foreach ($failure in @('LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8', 'LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK', 'LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY', 'LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN', 'LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT')) {
            $global:cfKeysetStore = @{}
            $global:cfKeysetWrites = 0
            $global:cfKeysetWriteOrder = @{}
            $global:cfKeysetFailAt = $failure
            { Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit } | Should Throw
            $partial = & $global:cfKeysetRead
            (Test-LiveRuntimeKeysetCommit -Values $partial -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $false
            $global:cfKeysetFailAt = $null
            (Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit) | Should Be 'CREATED_VALID_KEYSET'
            (Test-LiveRuntimeKeysetCommit -Values (& $global:cfKeysetRead) -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $true
        }
    }

    It 'does not overwrite a committed set unless rotation is explicit' {
        Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit | Out-Null
        $global:cfKeysetCandidate = @{
            LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8 = 'rotated-private-key'
            LEVIATHAN_LICENSING_SIGNING_PUBLIC_KEY_JWK = '{"kty":"EC","crv":"P-256","kid":"rotated"}'
            LEVIATHAN_LICENSING_ADMIN_TOTP_ENCRYPTION_KEY = 'rotated-totp-key'
            LEVIATHAN_LICENSING_INTERNAL_SERVICE_TOKEN = 'rotated-internal-token'
        }
        $before = $global:cfKeysetWrites
        (Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit) | Should Be 'EXISTING_VALID_KEYSET'
        $global:cfKeysetWrites | Should Be $before
        (Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit -Rotate) | Should Be 'CREATED_VALID_KEYSET'
        $global:cfKeysetWrites | Should Be ($before + 5)
        (Test-LiveRuntimeKeysetCommit -Values (& $global:cfKeysetRead) -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $true
    }

    It 'repairs an uncommitted partial or mismatched marker set without treating it as deployable' {
        $global:cfKeysetStore['LEVIATHAN_LICENSING_SIGNING_PRIVATE_KEY_PKCS8'] = 'stale-private-key'
        $global:cfKeysetStore['LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT'] = '{"schema_version":1,"keyset_id":"00000000000000000000000000000000","digest":"0000000000000000000000000000000000000000000000000000000000000000"}'
        (Test-LiveRuntimeKeysetCommit -Values (& $global:cfKeysetRead) -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $false
        (Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $global:cfKeysetCommit) | Should Be 'CREATED_VALID_KEYSET'
        (Test-LiveRuntimeKeysetCommit -Values (& $global:cfKeysetRead) -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $true
    }

    It 'treats a marker write whose acknowledgement fails as a committed idempotent retry' {
        $global:cfKeysetMarkerAckLost = $false
        $ackLostCommit = {
            param($name, $value, $replace)
            $global:cfKeysetWrites++
            $global:cfKeysetStore[$name] = $value
            if ($name -eq 'LEVIATHAN_LICENSING_LIVE_KEYSET_COMMIT' -and -not $global:cfKeysetMarkerAckLost) {
                $global:cfKeysetMarkerAckLost = $true
                throw 'synthetic lost marker acknowledgement'
            }
        }
        { Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $ackLostCommit } | Should Throw
        (Test-LiveRuntimeKeysetCommit -Values (& $global:cfKeysetRead) -Marker (& $global:cfKeysetMarker) -ValidateValues $global:cfKeysetValidate) | Should Be $true
        $writes = $global:cfKeysetWrites
        (Invoke-AtomicLiveRuntimeKeyRegistration $global:cfKeysetRead $global:cfKeysetMarker $global:cfKeysetGenerate $global:cfKeysetValidate $ackLostCommit) | Should Be 'EXISTING_VALID_KEYSET'
        $global:cfKeysetWrites | Should Be $writes
    }
    It 'rejects a signing key and JWK that are not a matching pair' {
        $ecdsa = [Security.Cryptography.ECDsaCng]::new(256)
        $privateBytes = $null
        try {
            $privateBytes = $ecdsa.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $public = $ecdsa.ExportParameters($false)
            $x = [Convert]::ToBase64String($public.Q.X).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $y = [Convert]::ToBase64String($public.Q.Y).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $jwk = @{ kty = 'EC'; crv = 'P-256'; x = $x; y = $y } | ConvertTo-Json -Compress
            $private = [Convert]::ToBase64String($privateBytes)
            (Test-LiveSigningKeyPair -PrivateKeyPkcs8 $private -PublicJwkJson $jwk) | Should Be $true
            $wrongJwk = @{ kty = 'EC'; crv = 'P-256'; x = $x; y = ('A' + $y.Substring(1)) } | ConvertTo-Json -Compress
            (Test-LiveSigningKeyPair -PrivateKeyPkcs8 $private -PublicJwkJson $wrongJwk) | Should Be $false
        } finally {
            if ($null -ne $privateBytes) { [Array]::Clear($privateBytes, 0, $privateBytes.Length) }
            if ($null -ne $ecdsa) { $ecdsa.Dispose() }
        }
    }
}



