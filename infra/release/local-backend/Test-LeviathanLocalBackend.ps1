[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)][int]$LicensingPort = 8787,
    [ValidateRange(1024, 65535)][int]$ReleaseFeedPort = 8788,
    [ValidateRange(1, 10)][int]$TimeoutSeconds = 3
)

$ErrorActionPreference = 'Stop'
Import-Module -Name (Join-Path $PSScriptRoot 'LocalBackend.Common.psm1') -Force -ErrorAction Stop

try {
    $licenseUri = [uri]('http://127.0.0.1:' + $LicensingPort + '/v1/admin/license')
    $license = Get-LbHttpResponse -Uri $licenseUri -TimeoutSeconds $TimeoutSeconds
    $licenseCode = Get-LbJsonErrorCode -Content ([string]$license.Content)
    if ($license.StatusCode -eq 401 -and $licenseCode -eq 'UNAUTHENTICATED') {
        [Console]::WriteLine('LICENSING_HEALTH_OK status=401 code=UNAUTHENTICATED')
    } elseif ($license.StatusCode -eq 503 -and $licenseCode -eq 'NOT_CONFIGURED') {
        [Console]::WriteLine('LICENSING_HEALTH_OK status=503 code=NOT_CONFIGURED')
    } else {
        throw 'LOCAL_BACKEND_LICENSING_HEALTH_FAILED'
    }

    $feedUri = [uri]('http://127.0.0.1:' + $ReleaseFeedPort + '/v1/updates/desktop/windows-x86_64/x86_64/0.1.0')
    $feed = Get-LbHttpResponse -Uri $feedUri -TimeoutSeconds $TimeoutSeconds
    $feedHeader = ''
    try { $feedHeader = [string]$feed.Headers['X-Leviathan-Feed'] } catch { }
    if ($feed.StatusCode -eq 204 -and $feedHeader -eq 'no-newer') {
        [Console]::WriteLine('RELEASE_FEED_HEALTH_OK status=204 state=no-newer')
    } elseif ($feed.StatusCode -eq 503 -and (Get-LbJsonErrorCode -Content ([string]$feed.Content)) -eq 'FEED_INVALID') {
        [Console]::WriteLine('RELEASE_FEED_HEALTH_OK status=503 state=FEED_INVALID')
    } else {
        throw 'LOCAL_BACKEND_RELEASE_FEED_HEALTH_FAILED'
    }
    exit 0
} catch {
    [Console]::Error.WriteLine('LOCAL_BACKEND_SMOKE_FAILED')
    exit 1
} finally {
    Remove-Module -Name LocalBackend.Common -Force -ErrorAction SilentlyContinue
}
