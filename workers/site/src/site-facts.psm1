function Get-SitePathValue {
    param([object]$Object, [string]$Path)
    $value = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $value -or $null -eq $value.PSObject.Properties[$part]) { return $null }
        $value = $value.PSObject.Properties[$part].Value
    }
    return $value
}

function Get-SiteMissingFacts {
    param([Parameter(Mandatory = $true)][object]$Config)
    $required = @(
        @{ Name = 'company.legal_name'; Value = Get-SitePathValue $Config 'company.legal_name.value'; Confirm = [bool](Get-SitePathValue $Config 'company.legal_name.owner_confirmation_required') },
        @{ Name = 'company.formation_state'; Value = Get-SitePathValue $Config 'company.formation_state' },
        @{ Name = 'company.mailing_address'; Value = Get-SitePathValue $Config 'company.mailing_address' },
        @{ Name = 'company.support_email'; Value = Get-SitePathValue $Config 'company.support_email' },
        @{ Name = 'company.regulatory_status'; Value = Get-SitePathValue $Config 'company.regulatory_status' },
        @{ Name = 'company.web_backend_host'; Value = Get-SitePathValue $Config 'company.web_backend_host' },
        @{ Name = 'company.domain'; Value = Get-SitePathValue $Config 'company.domain' },
        @{ Name = 'company.effective_date'; Value = Get-SitePathValue $Config 'company.effective_date' }
    )
    $placeholders = '^(tbd|todo|n/?a|none|unknown|pending|xxx+|\?+|-+)$'
    @($required | Where-Object {
        $value = [string]$_.Value
        $invalid = -not $value -or $value.Trim() -match $placeholders -or $value -match '^\[REQUIRED:'
        if (-not $invalid -and $_.Name -eq 'company.support_email') { $invalid = $value -match '(?i)^mailto:' -or $value -notmatch '^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$' }
        if (-not $invalid -and $_.Name -eq 'company.effective_date') { $parsed = [datetime]::MinValue; $invalid = $value -notmatch '^\d{4}-\d{2}-\d{2}$' -or -not [datetime]::TryParseExact($value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed) }
        if (-not $invalid -and $_.Name -eq 'company.domain') { $invalid = $value -notmatch '^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$' -or $value -match '(?i)\.workers\.dev$' }
        $invalid -or $_.Confirm
    } | ForEach-Object { $_.Name })
    foreach ($fact in @(
        @{ Name = 'retention.account_deletion_days'; Value = Get-SitePathValue $Config 'retention.account_deletion_days' },
        @{ Name = 'retention.legal_retention_years'; Value = Get-SitePathValue $Config 'retention.legal_retention_years' },
        @{ Name = 'refund_policy'; Value = Get-SitePathValue $Config 'refund_policy' },
        @{ Name = 'billing.cancellation_method'; Value = Get-SitePathValue $Config 'billing.cancellation_method' }
    )) {
        $value = [string]$fact.Value
        $invalid = -not $value -or $value -match '^\[REQUIRED:' -or $value -match $placeholders
        if ($fact.Name -eq 'retention.account_deletion_days') { $invalid = $value -notmatch '^[1-9][0-9]{0,2}$' }
        if ($fact.Name -eq 'retention.legal_retention_years') { $invalid = $value -notmatch '^[1-9][0-9]?$' }
        if ($fact.Name -eq 'billing.cancellation_method') { $invalid = $value -notin @('email', 'portal') }
        if ($invalid) { $fact.Name }
    }
}

function Assert-SiteFactsComplete {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $missing = @(Get-SiteMissingFacts -Config $config)
    if ($missing.Count -gt 0) { throw "SITE_FACTS_INCOMPLETE: $($missing -join ', ')" }
}

Export-ModuleMember -Function Get-SiteMissingFacts, Assert-SiteFactsComplete
