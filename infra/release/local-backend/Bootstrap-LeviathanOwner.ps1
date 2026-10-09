[CmdletBinding()]
param(
    [ValidatePattern('^[^\s@]+@[^\s@]+\.[^\s@]+$')]
    [string]$OwnerEmail = 'ocean824@gmail.com',
    [string]$NodeExecutable = 'node.exe'
)

$ErrorActionPreference = 'Stop'
$commonPath = Join-Path $PSScriptRoot 'LocalBackend.Common.psm1'
Import-Module -Name $commonPath -Force -ErrorAction Stop
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$licensingDirectory = Join-Path $repoRoot 'workers\licensing'
$environmentPath = Join-Path $env:LOCALAPPDATA 'Leviathan\local-backend\licensing.env'
$childTimeoutMilliseconds = 120000

function Invoke-LbNodeChild {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][System.Collections.IDictionary]$ChildEnvironment
    )

    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $extension = [IO.Path]::GetExtension($Executable)
    if ($extension -ieq '.cmd' -or $extension -ieq '.bat') {
        $commandShell = $env:ComSpec
        if ([string]::IsNullOrWhiteSpace($commandShell) -or -not (Test-Path -LiteralPath $commandShell)) {
            return 125
        }
        $command = '"' + $Executable + '" ' + $Arguments + ' >NUL 2>&1'
        $processInfo.FileName = $commandShell
        $processInfo.Arguments = '/d /s /c "' + $command + '"'
    } else {
        $processInfo.FileName = $Executable
        $processInfo.Arguments = $Arguments
    }
    $processInfo.WorkingDirectory = $WorkingDirectory
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.CreateNoWindow = $true

    # Never let credentials already present in the parent shell leak into a child.
    foreach ($name in @('DATABASE_URL', 'OWNER_EMAIL', 'OWNER_PASSWORD', 'CAPS_APPROVED')) {
        $processInfo.EnvironmentVariables.Remove($name)
    }
    foreach ($key in $ChildEnvironment.Keys) {
        $processInfo.EnvironmentVariables[[string]$key] = [string]$ChildEnvironment[$key]
    }

    $process = New-Object Diagnostics.Process
    $process.StartInfo = $processInfo
    try {
        if (-not $process.Start()) { return 125 }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($childTimeoutMilliseconds)) {
            try { $process.Kill() } catch { }
            return 124
        }
        $process.WaitForExit()
        # Consume and discard all child output; it may contain connection details.
        $null = $stdoutTask.Result
        $null = $stderrTask.Result
        return [int]$process.ExitCode
    } catch {
        return 125
    } finally {
        $process.Dispose()
    }
}

$passwordSecure = $null
$passwordText = $null
$childEnvironment = $null
try {
    if (-not (Test-Path -LiteralPath $environmentPath -PathType Leaf)) {
        throw 'LOCAL_BACKEND_ENVIRONMENT_NOT_FOUND'
    }
    $databaseUrl = Get-LbEnvValue -Path $environmentPath -Name 'DATABASE_URL'

    # The preflight is deliberately before Read-Host. Missing table means the
    # approved empty database has not been migrated yet; other errors fail closed.
    $preflightCode = "import { Pool } from '@neondatabase/serverless'; const pool=new Pool({connectionString:process.env.DATABASE_URL}); try { const r=await pool.query('SELECT EXISTS (SELECT 1 FROM licensing_users WHERE lower(email)=lower(`$1) AND owner=TRUE AND active=TRUE) AS owner_exists',[process.env.OWNER_EMAIL]); if(r.rows[0]?.owner_exists) process.exitCode=10; } catch (error) { process.exitCode=error?.code==='42P01'?0:20; } finally { await pool.end(); }"
    $preflightEnvironment = @{ DATABASE_URL = $databaseUrl; OWNER_EMAIL = $OwnerEmail }
    $preflightArguments = '--input-type=module -e "' + $preflightCode + '"'
    $preflightExitCode = Invoke-LbNodeChild -Executable $NodeExecutable -Arguments $preflightArguments `
        -WorkingDirectory $licensingDirectory -ChildEnvironment $preflightEnvironment
    $preflightEnvironment.Clear()
    if ($preflightExitCode -eq 10) {
        Write-Output 'Owner already bootstrapped'
        exit 0
    }
    if ($preflightExitCode -ne 0) {
        throw 'LOCAL_BACKEND_OWNER_PREFLIGHT_FAILED'
    }

    $passwordSecure = Read-Host -Prompt 'Owner password' -AsSecureString
    if ($null -eq $passwordSecure -or $passwordSecure.Length -lt 12) {
        throw 'LOCAL_BACKEND_OWNER_PASSWORD_INVALID'
    }
    $passwordText = ConvertTo-LbPlainText -SecureValue $passwordSecure

    $migrationEnvironment = @{ DATABASE_URL = $databaseUrl }
    $migrationExitCode = Invoke-LbNodeChild -Executable $NodeExecutable `
        -Arguments 'scripts/apply_migrations.mjs' -WorkingDirectory $licensingDirectory `
        -ChildEnvironment $migrationEnvironment
    $migrationEnvironment.Clear()
    if ($migrationExitCode -ne 0) {
        throw 'LOCAL_BACKEND_MIGRATIONS_FAILED'
    }

    Write-Output 'OWNER_BOOTSTRAP_GATE=opened-for-single-run'
    $childEnvironment = @{
        DATABASE_URL = $databaseUrl
        OWNER_EMAIL = $OwnerEmail
        OWNER_PASSWORD = $passwordText
        CAPS_APPROVED = 'true'
    }
    $bootstrapExitCode = Invoke-LbNodeChild -Executable $NodeExecutable `
        -Arguments 'scripts/bootstrap_owner.mjs' -WorkingDirectory $licensingDirectory `
        -ChildEnvironment $childEnvironment
    if ($bootstrapExitCode -ne 0) {
        throw 'LOCAL_BACKEND_OWNER_BOOTSTRAP_FAILED'
    }
    Write-Output 'LOCAL_BACKEND_OWNER_BOOTSTRAPPED'
    exit 0
} catch {
    Write-Error -Message 'LOCAL_BACKEND_OWNER_BOOTSTRAP_FAILED' -ErrorAction Continue
    exit 1
} finally {
    if ($null -ne $preflightEnvironment) { $preflightEnvironment.Clear() }
    if ($null -ne $migrationEnvironment) { $migrationEnvironment.Clear() }
    if ($null -ne $childEnvironment) { $childEnvironment.Clear() }
    if ($null -ne $passwordSecure) { $passwordSecure.Dispose() }
    $passwordText = $null
    $databaseUrl = $null
    Remove-Module -Name LocalBackend.Common -Force -ErrorAction SilentlyContinue
}
