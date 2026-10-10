$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$runbookPath = if ($env:CF_DEPLOY_SOURCE_PATH) {
    $env:CF_DEPLOY_SOURCE_PATH
} else {
    Join-Path $PSScriptRoot '..\..\..\infra\release\cloudflare\Deploy-LeviathanWorkers.ps1'
}
$runbookPath = (Resolve-Path -LiteralPath $runbookPath).Path
$null = . $runbookPath -MasterRoot $env:TEMP -StripeTestPriceId 'price_acceptance' -WhatIf
$realStartWrangler = (Get-Item Function:\Start-WranglerProcess).ScriptBlock

function New-AcceptanceSecureString([string]$Text) {
    $value = New-Object Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $value.AppendChar($character) }
    $value.MakeReadOnly()
    return $value
}

function New-AcceptanceChild([string]$OutputPath, [string]$Mode) {
    $typeName = 'CFDeployAcceptanceChild' + [guid]::NewGuid().ToString('N')
    if ($Mode -eq 'HashStdin') {
        $body = @'
using System;
using System.IO;
using System.Security.Cryptography;
public static class __TYPE__ {
    public static int Main() {
        using (var input = Console.OpenStandardInput())
        using (var memory = new MemoryStream()) {
            input.CopyTo(memory);
            var bytes = memory.ToArray();
            using (var sha = SHA256.Create()) {
                Console.Out.WriteLine(bytes.Length.ToString() + ":" + BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant());
            }
        }
        return 0;
    }
}
'@
    } else {
        $body = @'
using System;
public static class __TYPE__ {
    public static int Main() {
        Console.Error.WriteLine(new string('x', 1500) + " SAFE_TAIL cfat_acceptance_fake_token sk_test_acceptance_fake whsec_acceptance_fake postgres://fixture:password@db.invalid/name 0123456789abcdef0123456789abcdef");
        return 7;
    }
}
'@
    }
    $body = $body.Replace('__TYPE__', $typeName)
    Add-Type -TypeDefinition $body -Language CSharp -OutputAssembly $OutputPath -OutputType ConsoleApplication
}

function Get-XyraSecret {
    param([string]$Name, [string]$Scope, [string]$Environment)
    $script:acceptanceSecretReadName = $Name
    return New-AcceptanceSecureString $script:acceptanceSecretText
}

Describe 'CF-DEPLOY-001 cycle-3 independent acceptance' {
    Context 'Wrangler child input and diagnostics' {
        It 'passes exactly the UTF-8 secret bytes, without BOM or trailing newline' {
            $temp = Join-Path ([IO.Path]::GetTempPath()) ('cfdeploy-accept-stdin-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $temp | Out-Null
            $exe = Join-Path $temp 'fake-node.exe'
            $js = Join-Path $temp 'fake-wrangler.js'
            Set-Content -LiteralPath $js -Value '// inert fake child marker' -Encoding ASCII
            New-AcceptanceChild $exe 'HashStdin'
            $script:NodeExePath = $exe
            $script:WranglerJsPath = $js
            $script:projectRoot = $temp
            $apiToken = New-AcceptanceSecureString 'cfat_acceptance_api_token'
            $secretText = 'db://user:fixture-password@database.invalid/leviathan'
            $secret = New-AcceptanceSecureString $secretText
            try {
                $actual = (& $realStartWrangler @('secret', 'put', 'DATABASE_URL') $apiToken $secret).Trim()
                $expectedBytes = [Text.UTF8Encoding]::new($false).GetBytes($secretText)
                $sha = [Security.Cryptography.SHA256]::Create()
                try {
                    $expected = $expectedBytes.Length.ToString() + ':' + [BitConverter]::ToString($sha.ComputeHash($expectedBytes)).Replace('-', '').ToLowerInvariant()
                } finally { [Array]::Clear($expectedBytes, 0, $expectedBytes.Length); $sha.Dispose() }
                $actual | Should Be $expected
            } finally {
                $apiToken.Dispose(); $secret.Dispose()
                Remove-Item -LiteralPath $temp -Recurse -Force
            }
        }

        It 'bounds and redacts stderr in the thrown error and captured output' {
            $temp = Join-Path ([IO.Path]::GetTempPath()) ('cfdeploy-accept-stderr-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $temp | Out-Null
            $exe = Join-Path $temp 'fake-node.exe'
            $js = Join-Path $temp 'fake-wrangler.js'
            Set-Content -LiteralPath $js -Value '// inert fake child marker' -Encoding ASCII
            New-AcceptanceChild $exe 'Stderr'
            $script:NodeExePath = $exe
            $script:WranglerJsPath = $js
            $script:projectRoot = $temp
            $apiToken = New-AcceptanceSecureString 'cfat_acceptance_fake_token'
            $caught = $null
            $captured = @()
            try {
                try { $captured = @(& $realStartWrangler @('deploy') $apiToken $null 2>&1) }
                catch { $caught = $_.Exception.Message }
                ($null -ne $caught) | Should Be $true
                $caught | Should Match 'SAFE_TAIL'
                ($caught.Length -le 1250) | Should Be $true
                $allOutput = (@($captured | ForEach-Object { [string]$_ }) -join "`n") + "`n" + $caught
                foreach ($secretShape in @('cfat_acceptance_fake_token', 'sk_test_acceptance_fake', 'whsec_acceptance_fake', 'postgres://', '0123456789abcdef0123456789abcdef')) {
                    $allOutput.Contains($secretShape) | Should Be $false
                }
            } finally { $apiToken.Dispose(); Remove-Item -LiteralPath $temp -Recurse -Force }
        }
    }

    Context 'R2 Wrangler 4.x text output' {
        BeforeEach {
            $script:wranglerCalls = New-Object System.Collections.ArrayList
            function Start-WranglerProcess {
                param([string[]]$Arguments, [Security.SecureString]$ApiToken, [Security.SecureString]$StdinSecret)
                [void]$script:wranglerCalls.Add(($Arguments -join ' '))
                if ($Arguments -contains 'list') { return [string]$script:r2Listing }
                return ''
            }
            $script:r2ApiToken = New-AcceptanceSecureString 'cfat_acceptance_r2_token'
        }

        It 'creates the bucket for an empty listing' {
            $script:r2Listing = ''
            Invoke-R2BucketEnsure $script:r2ApiToken | Out-Null
            ($script:wranglerCalls -join '|') | Should Be 'r2 bucket list|r2 bucket create leviathan-release-feed'
        }

        It 'leaves an already listed bucket alone' {
            $script:r2Listing = "name: leviathan-release-feed`nname: archive"
            Invoke-R2BucketEnsure $script:r2ApiToken | Out-Null
            $script:wranglerCalls.Count | Should Be 1
        }

        It 'creates the bucket when only other bucket names are listed' {
            $script:r2Listing = "name: archive`nname: snapshots"
            Invoke-R2BucketEnsure $script:r2ApiToken | Out-Null
            ($script:wranglerCalls -join '|') | Should Be 'r2 bucket list|r2 bucket create leviathan-release-feed'
        }

        It 'parses CRLF output when the bucket is present' {
            $script:r2Listing = "name: archive`r`nname: leviathan-release-feed`r`n"
            Invoke-R2BucketEnsure $script:r2ApiToken | Out-Null
            $script:wranglerCalls.Count | Should Be 1
        }
    }

    Context 'Stripe mode under StrictMode' {
        It 'accepts a matched test-mode secret and publishable key' {
            $script:acceptanceSecretText = 'pk_test_acceptance123'
            $apiKey = New-AcceptanceSecureString 'sk_test_acceptance123'
            try {
                Set-StrictMode -Version Latest
                { Assert-StripeModeCredentialPair -Mode Test -ApiKey $apiKey -PublishableName 'STRIPE_TEST_PUBLISHABLE_KEY' -PublishableScope 'fake' -PublishableEnvironment 'test' } | Should Not Throw
            } finally { $apiKey.Dispose() }
        }

        It 'rejects a cross-mode secret and publishable key pair' {
            $script:acceptanceSecretText = 'pk_live_acceptance123'
            $apiKey = New-AcceptanceSecureString 'sk_test_acceptance123'
            $caught = $null
            try { Assert-StripeModeCredentialPair -Mode Test -ApiKey $apiKey -PublishableName 'STRIPE_TEST_PUBLISHABLE_KEY' -PublishableScope 'fake' -PublishableEnvironment 'test' }
            catch { $caught = $_.Exception.Message }
            finally { $apiKey.Dispose() }
            $caught | Should Be 'STRIPE_MODE_KEY_MISMATCH'
        }
    }

    It 'reads the requested DATABASE_URL registry entry during secret put' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($runbookPath, [ref]$tokens, [ref]$errors)
        $calls = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-SecretPut' }, $true)
        $databaseCall = @($calls | Where-Object { $_.Extent.Text -match "'DATABASE_URL'" }) | Select-Object -First 1
        ($null -ne $databaseCall -and (@($databaseCall.CommandElements | ForEach-Object { $_.Extent.Text }) -join ' ') -eq "Invoke-SecretPut `$licensingWorker 'DATABASE_URL' 'LEVIATHAN_LICENSING_DATABASE_URL' `$apiToken") | Should Be $true
        $script:acceptanceSecretText = 'db-url-fixture-only'
        $script:acceptanceSecretReadName = $null
        $script:secretPutValueCall = $null
        function Invoke-SecretPutValue {
            param([string]$WorkerName, [string]$BindingName, [Security.SecureString]$Secret, [Security.SecureString]$ApiToken)
            $script:secretPutValueCall = "$WorkerName/$BindingName"
        }
        $apiToken = New-AcceptanceSecureString 'cfat_acceptance_api_token'
        try {
            Invoke-SecretPut 'leviathan-licensing-worker' 'DATABASE_URL' 'LEVIATHAN_LICENSING_DATABASE_URL' $apiToken
            $script:acceptanceSecretReadName | Should Be 'LEVIATHAN_LICENSING_DATABASE_URL'
            $script:secretPutValueCall | Should Be 'leviathan-licensing-worker/DATABASE_URL'
        } finally { $apiToken.Dispose() }
    }

    It 'preserves the original deployment error through the actual finally block under StrictMode' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($runbookPath, [ref]$tokens, [ref]$errors)
        $deploymentTry = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally -and $node.Finally.Extent.Text.Contains('$privateKeySecure.Dispose()') }, $true) | Select-Object -Last 1
        ($null -ne $deploymentTry) | Should Be $true
        $privateKeyInit = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$privateKeySecure' -and $node.Right.Extent.Text -eq '$null' }, $true) | Where-Object { $_.Extent.StartOffset -lt $deploymentTry.Extent.StartOffset } | Select-Object -Last 1
        $setup = '$apiToken = $null; $stripeApiSecret = $null; $stripeWebhookSecret = $null;'
        if ($null -ne $privateKeyInit) { $setup += $privateKeyInit.Extent.Text + ';' }
        $program = "Set-StrictMode -Version Latest; $setup try { throw 'PRIMARY_DEPLOYMENT_FAILURE' } finally $($deploymentTry.Finally.Extent.Text)"
        $caught = $null
        try { & ([scriptblock]::Create($program)) } catch { $caught = $_.Exception.Message }
        $caught | Should Be 'PRIMARY_DEPLOYMENT_FAILURE'
    }
}
