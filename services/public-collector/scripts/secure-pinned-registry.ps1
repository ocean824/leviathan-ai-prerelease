param(
  [string]$RegistryPath = (Join-Path $PSScriptRoot "..\templates\PINNED.json")
)
$ErrorActionPreference = "Stop"

$resolved = (Resolve-Path -LiteralPath $RegistryPath -ErrorAction Stop).Path
$registryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\templates") -ErrorAction Stop).Path
if (-not $resolved.StartsWith(($registryRoot.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
  throw "Registry path must remain inside services/public-collector/templates."
}

$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$reset = & icacls.exe $resolved /reset
if ($LASTEXITCODE -ne 0) {
  throw "Could not reset inherited PINNED.json ACL: $reset"
}
$userEntry = "*{0}:F" -f $userSid.Value
$restricted = & icacls.exe $resolved /inheritance:r /grant:r $userEntry "*S-1-5-18:F" "*S-1-5-32-544:F"
if ($LASTEXITCODE -ne 0) {
  throw "Could not apply restrictive PINNED.json ACL: $restricted"
}
Write-Output "Restricted PINNED.json to the current user, SYSTEM, and local Administrators."
