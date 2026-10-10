$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$source = Join-Path $repoRoot 'infra\release\cloudflare\Deploy-LeviathanWorkers.ps1'
$tests = Join-Path $PSScriptRoot 'Deploy-LeviathanWorkers.Cycle3.Acceptance.Tests.ps1'
$original = [IO.File]::ReadAllText($source)
$mutants = @(
    @{ Name = 'append-newline-to-secret-stdin'; TestName = 'passes exactly the UTF-8 secret bytes*'; Old = '.GetBytes($secretChars)'; New = '.GetBytes(([string]$secretChars) + "`n")' },
    @{ Name = 'break-wrangler-r2-text-parser'; TestName = 'leaves an already listed bucket alone'; Old = "'(?m)^\s*name:\s+(\S+)\s*$'"; New = "'(?m)^\s*bucket:\s+(\S+)\s*$'" },
    @{ Name = 'skip-stripe-mode-validation'; TestName = 'rejects a cross-mode secret*'; Old = 'if ($secretText -notmatch "^sk_${prefix}_[A-Za-z0-9_]+$" -or $publishableText -notmatch "^pk_${prefix}_[A-Za-z0-9_]+$") {'; New = 'if ($false) {' },
    @{ Name = 'misroute-database-registry-name'; TestName = 'reads the requested DATABASE_URL*'; Old = "'LEVIATHAN_LICENSING_DATABASE_URL'"; New = "'LEVIATHAN_LICENSING_DATABASE_URL_MUTANT'" },
    @{ Name = 'skip-stderr-redaction'; TestName = 'bounds and redacts stderr*'; Old = 'foreach ($pattern in $patterns) { $safe = [regex]::Replace($safe, $pattern, ''[REDACTED]'') }'; New = 'foreach ($pattern in $patterns) { $safe = $safe }' },
    @{ Name = 'remove-pre-try-finally-initialization'; TestName = 'preserves the original deployment error*'; Old = '$privateKeySecure = $null'; New = '' }
)
if ($env:CF_DEPLOY_MUTANT_FILTER) {
    $selectedNames = @($env:CF_DEPLOY_MUTANT_FILTER -split ',')
    $mutants = @($mutants | Where-Object { $_.Name -in $selectedNames })
    if ($mutants.Count -eq 0) { throw 'CF_DEPLOY_MUTANT_FILTER selected no mutants.' }
}
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('cfdeploy-cycle3-mutants-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$savedPath = $env:CF_DEPLOY_SOURCE_PATH
$caught = 0
try {
    foreach ($mutant in $mutants) {
        if (-not $original.Contains($mutant.Old)) { throw "Mutant source pattern missing: $($mutant.Name)" }
        $mutantDir = Join-Path $scratch $mutant.Name
        New-Item -ItemType Directory -Path $mutantDir | Out-Null
        $mutantPath = Join-Path $mutantDir 'Deploy-LeviathanWorkers.ps1'
        $changed = $original.Replace($mutant.Old, $mutant.New)
        [IO.File]::WriteAllText($mutantPath, $changed, [Text.UTF8Encoding]::new($false))
        $env:CF_DEPLOY_SOURCE_PATH = $mutantPath
        $result = Invoke-Pester -Script $tests -PassThru 6> $null
        if ($result.FailedCount -lt 1) { throw "Mutant survived acceptance: $($mutant.Name)" }
        $caught++
        Write-Output "$($mutant.Name): CAUGHT ($($result.FailedCount) acceptance failure(s))"
    }
} finally {
    if ($null -eq $savedPath) { Remove-Item Env:\CF_DEPLOY_SOURCE_PATH -ErrorAction SilentlyContinue }
    else { $env:CF_DEPLOY_SOURCE_PATH = $savedPath }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
if ($caught -ne $mutants.Count) { throw 'Not every CF-DEPLOY cycle-3 mutant was caught.' }
