Import-Module (Join-Path $PSScriptRoot '..\..\..\workers\site\src\site-facts.psm1') -Force
$script:deploy = Get-Content (Join-Path $PSScriptRoot '..\cloudflare\Deploy-LeviathanWorkers.ps1') -Raw

Describe 'Leviathan site facts and deploy smoke checks' {
    It 'blocks incomplete required facts with SITE_FACTS_INCOMPLETE' {
        $config = Get-Content (Join-Path $PSScriptRoot '..\..\..\workers\site\site.config.json') -Raw | ConvertFrom-Json
        $missing = @(Get-SiteMissingFacts -Config $config)
        ($missing -contains 'company.legal_name') | Should Be $true
        ($missing -contains 'company.formation_state') | Should Be $true
        ($missing -contains 'company.mailing_address') | Should Be $true
        ($missing -contains 'company.support_email') | Should Be $true
        ($missing -contains 'company.regulatory_status') | Should Be $true
        ($missing -contains 'company.web_backend_host') | Should Be $false
        ($missing -contains 'company.domain') | Should Be $true
        ($missing -contains 'company.effective_date') | Should Be $true
        ($missing -contains 'retention.account_deletion_days') | Should Be $true
        ($missing -contains 'retention.legal_retention_years') | Should Be $true
        ($missing -contains 'refund_policy') | Should Be $true
        $message = ''
        try { Assert-SiteFactsComplete -ConfigPath (Join-Path $PSScriptRoot '..\..\..\workers\site\site.config.json') }
        catch { $message = $_.Exception.Message }
        $message | Should Match '^SITE_FACTS_INCOMPLETE:'
    }

    It 'accepts complete facts after explicit legal-name confirmation' {
        $config = [pscustomobject]@{ company = [pscustomobject]@{
            legal_name = [pscustomobject]@{ value = 'Lossless Holdings, LLC'; owner_confirmation_required = $false }
            formation_state = 'Delaware'; mailing_address = '1 Example Street'; support_email = 'support@example.test'
            regulatory_status = 'Not registered as a broker-dealer or investment adviser'; domain = 'example.test'; effective_date = '2026-10-09'
            web_backend_host = 'Cloudflare Containers'
        }; retention = [pscustomobject]@{ account_deletion_days = '30'; legal_retention_years = '7' }; refund_policy = 'Refunds are available within 30 days.'; billing = [pscustomobject]@{ cancellation_method = 'email' } }
        $missing = @(Get-SiteMissingFacts -Config $config)
        $missing.Count | Should Be 0
    }

    It 'rejects malformed email, date and workers.dev domains' {
        $config = [pscustomobject]@{
            company = [pscustomobject]@{
                legal_name = [pscustomobject]@{ value = 'Lossless Holdings, LLC'; owner_confirmation_required = $false }
                formation_state = 'Delaware'; mailing_address = '1 Example Street'; support_email = 'not-an-email'
                regulatory_status = 'Owner supplied regulatory sentence.'; domain = 'example.workers.dev'; effective_date = 'soon'
                web_backend_host = 'Cloudflare (Workers and Containers)'
            }
            retention = [pscustomobject]@{ account_deletion_days = '30'; legal_retention_years = '7' }
            refund_policy = 'Refunds are described here.'
            billing = [pscustomobject]@{ cancellation_method = 'portal' }
        }
        $missing = @(Get-SiteMissingFacts -Config $config)
        ($missing -contains 'company.support_email') | Should Be $true
        ($missing -contains 'company.domain') | Should Be $true
        ($missing -contains 'company.effective_date') | Should Be $true
    }

    It 'rejects mailto support addresses and out-of-range retention periods' {
        $config = [pscustomobject]@{
            company = [pscustomobject]@{
                legal_name = [pscustomobject]@{ value = 'Lossless Holdings, LLC'; owner_confirmation_required = $false }
                formation_state = 'Delaware'; mailing_address = '1 Example Street'; support_email = 'mailto:support@example.test'
                regulatory_status = 'Owner supplied regulatory sentence.'; domain = 'example.test'; effective_date = '2026-10-09'
                web_backend_host = 'Cloudflare (Workers and Containers)'
            }
            retention = [pscustomobject]@{ account_deletion_days = '0'; legal_retention_years = '100' }
            refund_policy = 'Refunds are described here.'
            billing = [pscustomobject]@{ cancellation_method = 'email' }
        }
        $missing = @(Get-SiteMissingFacts -Config $config)
        foreach ($name in @('company.support_email', 'retention.account_deletion_days', 'retention.legal_retention_years')) {
            ($missing -contains $name) | Should Be $true
        }
    }

    It 'accepts only the configured email or portal cancellation methods' {
        $config = Get-Content (Join-Path $PSScriptRoot '..\..\..\workers\site\site.config.json') -Raw | ConvertFrom-Json
        $config.billing.cancellation_method = 'portal'
        $missing = @(Get-SiteMissingFacts -Config $config)
        ($missing -contains 'billing.cancellation_method') | Should Be $false
        $config.billing.cancellation_method = 'other'
        $missing = @(Get-SiteMissingFacts -Config $config)
        ($missing -contains 'billing.cancellation_method') | Should Be $true
    }

    It 'includes the fourth no-secret Worker only with the opt-in switch and gates it independently' {
        $deploy | Should Match '\$siteWorker\s*=\s*''leviathan-site'''
        $deploy | Should Match 'Assert-SiteFactsComplete'
        $deploy | Should Match '\[switch\]\$IncludeSite'
        $deploy | Should Match 'if \(\$IncludeSite\)'
        $deploy | Should Match 'Invoke-Deploy \$siteDirectory @\(\) \$apiToken'
        $deploy | Should Match 'siteOrigin.*ExpectedTitle'
    }

    It 'contains an HTTP 200 and exact title smoke check for each required page' {
        foreach ($path in @('/', '/app', '/privacy', '/terms', '/contact', '/risk-disclosure', '/data-deletion', '/security', '/cookies', '/subprocessors')) {
            $deploy | Should Match ([regex]::Escape("Path = '$path'"))
        }
        $deploy | Should Match 'Invoke-Smoke.*\$siteOrigin.*@\(200\).*ExpectedTitle'
    }
}


