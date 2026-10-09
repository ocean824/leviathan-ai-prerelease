$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$admin = Join-Path $repo 'apps\admin'
$ui = Join-Path $admin 'ui'
$acceptance = Join-Path $admin 'qa\test_admin_app_acceptance.py'

Push-Location $ui
try {
    npx vitest run --maxWorkers=1 --no-file-parallelism
    if ($LASTEXITCODE -ne 0) { throw "Vitest failed (exit $LASTEXITCODE)." }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "UI build failed (exit $LASTEXITCODE)." }
    npm run lint
    if ($LASTEXITCODE -ne 0) { throw "UI lint failed (exit $LASTEXITCODE)." }
} finally { Pop-Location }

if (-not (Test-Path -LiteralPath $acceptance -PathType Leaf)) {
    throw 'Independent ADMIN-APP acceptance file is missing.'
}
Push-Location $repo
try {
    uv run --locked --offline python -m pytest apps/admin/qa/test_admin_app_acceptance.py -q
    if ($LASTEXITCODE -ne 0) { throw "Independent acceptance failed (exit $LASTEXITCODE)." }
} finally { Pop-Location }
