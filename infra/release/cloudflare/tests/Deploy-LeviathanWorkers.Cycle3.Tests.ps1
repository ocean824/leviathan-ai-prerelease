$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$runbookPath = Join-Path $PSScriptRoot '..\Deploy-LeviathanWorkers.ps1'
$null = . $runbookPath -MasterRoot $env:TEMP -StripeTestPriceId 'price_fixture' -WhatIf
$realStartWrangler = (Get-Item Function:\Start-WranglerProcess).ScriptBlock

function New-FixtureSecureString([string]$Text) {
    $secure = New-Object Security.SecureString
    foreach ($character in $Text.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return $secure
}

function New-FixtureChild([string]$OutputPath) {
    $type = @"
using System;
using System.IO;
using System.Security.Cryptography;
public static class WranglerStdinProbe {
    public static int Main() {
        using (var stream = Console.OpenStandardInput())
        using (var memory = new MemoryStream()) {
            stream.CopyTo(memory);
            var bytes = memory.ToArray();
            using (var sha = SHA256.Create()) {
                Console.Out.WriteLine(bytes.Length.ToString() + ":" + BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant());
            }
        }
        return 0;
    }
}
"@
    Add-Type -TypeDefinition $type -Language CSharp -OutputAssembly $OutputPath -OutputType ConsoleApplication
}

Describe 'CF-DEPLOY-001 cycle 3 runbook regressions' {
    It 'initializes the private-key SecureString before entering the deployment try/finally' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $runbookPath).Path, [ref]$tokens, [ref]$errors)
        $errors.Count | Should Be 0
        $tryNode = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $node.Finally -and $node.Finally.Extent.Text.Contains('$privateKeySecure.Dispose()') }, $true) | Select-Object -First 1
        $init = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$privateKeySecure' -and $node.Right.Extent.Text -eq '$null' }, $true) | Where-Object { $null -ne $tryNode -and $_.Extent.StartOffset -lt $tryNode.Extent.StartOffset } | Select-Object -Last 1
        ($null -ne $init -and $null -ne $tryNode -and $init.Extent.StartOffset -lt $tryNode.Extent.StartOffset) | Should Be $true
    }

    Context 'R2 bucket listing uses Wrangler text output' {
        BeforeEach {
            $script:wranglerCalls = New-Object System.Collections.ArrayList
            function Start-WranglerProcess {
                param([string[]]$Arguments, [Security.SecureString]$ApiToken, [Security.SecureString]$StdinSecret)
                [void]$script:wranglerCalls.Add(($Arguments -join ' '))
                if ($Arguments -contains 'list') { return [string]$script:r2Listing }
                return ''
            }
            $script:apiFixture = New-FixtureSecureString 'cfat_fixture_api_token'
        }

        It 'creates the bucket when the listing is empty' {
            $script:r2Listing = ''
            Invoke-R2BucketEnsure $script:apiFixture | Out-Null
            ($script:wranglerCalls -join '|') | Should Be 'r2 bucket list|r2 bucket create leviathan-release-feed'
        }

        It 'does not create the bucket when its name appears in the text listing' {
            $script:r2Listing = "name: leviathan-release-feed`nname: another-bucket"
            Invoke-R2BucketEnsure $script:apiFixture | Out-Null
            $script:wranglerCalls.Count | Should Be 1
        }

        It 'creates the bucket when the listing contains only other buckets' {
            $script:r2Listing = "name: another-bucket`nname: archive"
            Invoke-R2BucketEnsure $script:apiFixture | Out-Null
            ($script:wranglerCalls -join '|') | Should Be 'r2 bucket list|r2 bucket create leviathan-release-feed'
        }
    }

    It 'expands the Stripe mode prefix under StrictMode for test credentials' {
        $script:stripePublishableFixture = New-FixtureSecureString 'pk_test_fixture123'
        function Get-XyraSecret {
            param([string]$Name, [string]$Scope, [string]$Environment)
            return $script:stripePublishableFixture
        }
        $apiKey = New-FixtureSecureString 'sk_test_fixture123'
        try {
            Set-StrictMode -Version Latest
            { Assert-StripeModeCredentialPair -Mode Test -ApiKey $apiKey -PublishableName 'STRIPE_TEST_PUBLISHABLE_KEY' -PublishableScope 'fixture' -PublishableEnvironment 'test' } | Should Not Throw
        } finally { $apiKey.Dispose(); $script:stripePublishableFixture.Dispose() }
    }

    It 'passes the licensing database registry name in the third Invoke-SecretPut argument' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $runbookPath).Path, [ref]$tokens, [ref]$errors)
        $calls = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-SecretPut' }, $true)
        $databaseCall = @($calls | Where-Object { $_.Extent.Text -match "'DATABASE_URL'" }) | Select-Object -First 1
        ($null -ne $databaseCall -and @($databaseCall.CommandElements | ForEach-Object { $_.Extent.Text }) -join ' ' -eq "Invoke-SecretPut `$licensingWorker 'DATABASE_URL' 'LEVIATHAN_LICENSING_DATABASE_URL' `$apiToken") | Should Be $true
    }

    It 'hands the child process exactly the UTF-8 secret bytes with no BOM or newline' {
        $temp = Join-Path ([IO.Path]::GetTempPath()) ('cfdeploy-stdin-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temp | Out-Null
        $exe = Join-Path $temp 'stdin-probe.exe'
        $dummyJs = Join-Path $temp 'wrangler.js'
        Set-Content -LiteralPath $dummyJs -Value '// fake child input probe' -Encoding ASCII
        New-FixtureChild -OutputPath $exe
        $script:NodeExePath = $exe
        $script:WranglerJsPath = $dummyJs
        $script:projectRoot = $temp
        $apiToken = New-FixtureSecureString 'cfat_fake_api_token'
        $secretText = 'postgres://fixture:password@db.invalid/test'
        $secret = New-FixtureSecureString $secretText
        try {
            $output = & $realStartWrangler @('secret', 'put', 'DATABASE_URL') $apiToken $secret
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes($secretText)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $expected = $bytes.Length.ToString() + ':' + [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
            finally { [Array]::Clear($bytes, 0, $bytes.Length); $sha.Dispose() }
            $output.Trim() | Should Be $expected
        } finally {
            $apiToken.Dispose(); $secret.Dispose()
            Remove-Item -LiteralPath $temp -Recurse -Force
        }
    }

    It 'includes a safe stderr tail while redacting token-shaped diagnostic values' {
        $temp = Join-Path ([IO.Path]::GetTempPath()) ('cfdeploy-stderr-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temp | Out-Null
        $exe = Join-Path $temp 'stderr-probe.exe'
        $dummyJs = Join-Path $temp 'wrangler.js'
        $type = @"
using System;
public static class WranglerStderrProbe {
    public static int Main() {
        Console.Error.WriteLine(new string('x', 1500) + " safe diagnostic cfat_fixture_api_token cfat_fixturetoken sk_test_fixture pk_live_fixture whsec_fixture postgres://user:pass@host/db 0123456789abcdef0123456789abcdef AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA= account_1234567890abcdef1234567890abcdef");
        return 7;
    }
}
"@
        Add-Type -TypeDefinition $type -Language CSharp -OutputAssembly $exe -OutputType ConsoleApplication
        Set-Content -LiteralPath $dummyJs -Value '// fake diagnostic child' -Encoding ASCII
        $script:NodeExePath = $exe; $script:WranglerJsPath = $dummyJs; $script:projectRoot = $temp
        $apiToken = New-FixtureSecureString 'cfat_fixture_api_token'
        $caught = $null
        try { $null = & $realStartWrangler @('deploy') $apiToken $null } catch { $caught = $_.Exception.Message }
        try {
            $null -ne $caught | Should Be $true
            $caught | Should Match 'safe diagnostic'
            ($caught.Length -le 1250) | Should Be $true
            foreach ($secretShape in @('cfat_fixture_api_token', 'cfat_fixturetoken', 'sk_test_fixture', 'pk_live_fixture', 'whsec_fixture', 'postgres://', '0123456789abcdef0123456789abcdef', 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=', 'account_1234567890abcdef1234567890abcdef')) {
                $caught.Contains($secretShape) | Should Be $false
            }
        } finally { $apiToken.Dispose(); Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}
