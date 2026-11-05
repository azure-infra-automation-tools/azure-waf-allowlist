#Requires -Version 7.2
#Requires -Modules Az.Accounts

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$WafPolicyName,
    [Parameter(Mandatory)][string]$ServiceTagLocation,
    [string[]]$ServiceTagNames = @('LogicApps','PowerPlatformPlex','PowerPlatformInfra'),
    [string[]]$CustomIpAddresses = @(),
    [string]$RuleName = 'BlockNonTrustedSources',
    [ValidateRange(1,100)][int]$RulePriority = 10,
    [ValidateSet('Enabled','Disabled')][string]$RuleState = 'Enabled',
    [ValidateSet('Block','Log')][string]$RuleAction = 'Block',
    [string]$ServiceTagApiVersion = '2024-05-01',
    [string]$WafPolicyApiVersion = '2026-01-01',
    [switch]$UseManagedIdentity,
    [switch]$IncludeIPv6,
    [switch]$FailOnMissingServiceTag,
    [switch]$ExportArtifacts,
    [string]$ExportDirectory = '.',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Invoke-ArmJson {
    param([ValidateSet('GET','PUT')][string]$Method,[string]$Path,[object]$Body)
    $p = @{ Method=$Method; Path=$Path; ErrorAction='Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $p.Payload = ($Body | ConvertTo-Json -Depth 100 -Compress)
    }
    $r = Invoke-AzRestMethod @p
    if ($r.StatusCode -lt 200 -or $r.StatusCode -ge 300) {
        throw "ARM request failed: $Method $Path`nHTTP $($r.StatusCode)`n$($r.Content)"
    }
    if ([string]::IsNullOrWhiteSpace($r.Content)) { return $null }
    return ($r.Content | ConvertFrom-Json -Depth 100)
}

function Convert-ToCidr([string]$Value) {
    $v = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { throw 'IP/CIDR cannot be empty.' }
    $parts = $v.Split('/',2)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0],[ref]$ip)) { throw "Invalid IP/CIDR: $Value" }
    if ($parts.Count -eq 2) {
        $prefix = 0
        if (-not [int]::TryParse($parts[1],[ref]$prefix)) { throw "Invalid CIDR: $Value" }
        $max = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ($prefix -lt 0 -or $prefix -gt $max) { throw "Invalid CIDR prefix: $Value" }
        return $v
    }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { return "$v/32" }
    return "$v/128"
}

function Test-IsIPv6([string]$Cidr) {
    $ip = [System.Net.IPAddress]::Parse($Cidr.Split('/',2)[0])
    return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
}

if (-not (Get-Module -ListAvailable Az.Accounts)) {
    throw 'Az.Accounts is required. Install-Module Az.Accounts -Scope CurrentUser'
}
Import-Module Az.Accounts -ErrorAction Stop

$ctx = Get-AzContext -ErrorAction SilentlyContinue
if ($UseManagedIdentity) {
    Connect-AzAccount -Identity -Subscription $SubscriptionId | Out-Null
} elseif ($null -eq $ctx -or $null -eq $ctx.Account) {
    Connect-AzAccount -Subscription $SubscriptionId | Out-Null
} elseif ($ctx.Subscription.Id -ne $SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$location = [Uri]::EscapeDataString($ServiceTagLocation)
$tagPath = "/subscriptions/$SubscriptionId/providers/Microsoft.Network/locations/$location/serviceTags?api-version=$ServiceTagApiVersion"
Write-Step 'Retrieving Azure Service Tags'
$tagData = Invoke-ArmJson -Method GET -Path $tagPath

$resolved = [System.Collections.Generic.List[string]]::new()
$matched = [System.Collections.Generic.List[string]]::new()
$missing = [System.Collections.Generic.List[string]]::new()
foreach ($requested in $ServiceTagNames) {
    $name = $requested.Trim()
    $hits = @($tagData.values | Where-Object { $_.name -ieq $name })
    if ($hits.Count -eq 0 -and -not $name.Contains('.')) {
        $escaped = [regex]::Escape($name)
        $hits = @($tagData.values | Where-Object { $_.name -imatch "^$escaped\." })
    }
    if ($hits.Count -eq 0) { $missing.Add($name); continue }
    foreach ($hit in $hits) {
        $matched.Add([string]$hit.name)
        foreach ($prefix0 in @($hit.properties.addressPrefixes)) {
            $prefix = Convert-ToCidr ([string]$prefix0)
            if (-not $IncludeIPv6 -and (Test-IsIPv6 $prefix)) { continue }
            $resolved.Add($prefix)
        }
    }
}
if ($missing.Count -gt 0) {
    $msg = 'Service Tags not found: ' + (($missing | Sort-Object -Unique) -join ', ')
    if ($FailOnMissingServiceTag) { throw $msg } else { Write-Warning $msg }
}

$custom = @()
foreach ($item in $CustomIpAddresses) {
    if ([string]::IsNullOrWhiteSpace($item)) { continue }
    $cidr = Convert-ToCidr $item
    if (-not $IncludeIPv6 -and (Test-IsIPv6 $cidr)) { Write-Warning "Skipping IPv6 prefix: $cidr"; continue }
    $custom += $cidr
}
$allow = @($resolved + $custom | Sort-Object -Unique)
if ($allow.Count -eq 0) { throw 'Final trusted IP list is empty.' }

$rg = [Uri]::EscapeDataString($ResourceGroupName)
$policy = [Uri]::EscapeDataString($WafPolicyName)
$wafPath = "/subscriptions/$SubscriptionId/resourceGroups/$rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/$policy?api-version=$WafPolicyApiVersion"
Write-Step 'Reading existing WAF policy'
$current = Invoke-ArmJson -Method GET -Path $wafPath
$existingRules = @($current.properties.customRules)

$conflict = @($existingRules | Where-Object { $_.name -ine $RuleName -and [int]$_.priority -eq $RulePriority })
if ($conflict.Count -gt 0) { throw "Priority $RulePriority is already used by $($conflict[0].name)." }

# Intentionally use a negated IPMatch + Block rule. Trusted sources do not match this
# custom rule and therefore continue to the managed WAF rules.
$newRule = [ordered]@{
    name=$RuleName; priority=$RulePriority; ruleType='MatchRule'; action=$RuleAction; state=$RuleState
    matchConditions=@([ordered]@{
        matchVariables=@([ordered]@{ variableName='RemoteAddr' })
        operator='IPMatch'
        negationConditon=$true
        matchValues=@($allow)
        transforms=@()
    })
}
$rules = @($existingRules | Where-Object { $_.name -ine $RuleName }) + @($newRule)
$rules = @($rules | Sort-Object { [int]$_.priority })
$props = [ordered]@{
    customRules=$rules
    policySettings=$current.properties.policySettings
    managedRules=$current.properties.managedRules
}
if ($null -ne $current.properties.tier) { $props.tier=$current.properties.tier }
$body = [ordered]@{ location=$current.location; properties=$props }
if ($null -ne $current.tags) { $body.tags=$current.tags }

if ($ExportArtifacts) {
    New-Item -Path $ExportDirectory -ItemType Directory -Force | Out-Null
    [ordered]@{
        generatedAtUtc=[DateTime]::UtcNow.ToString('o')
        requestedTags=$ServiceTagNames
        matchedTags=@($matched | Sort-Object -Unique)
        missingTags=@($missing | Sort-Object -Unique)
        customPrefixes=$custom
        allowedPrefixes=$allow
    } | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $ExportDirectory 'waf-allowlist.json') -Encoding utf8
    $body | ConvertTo-Json -Depth 100 | Set-Content (Join-Path $ExportDirectory 'waf-policy-request.json') -Encoding utf8
}

Write-Host "Resolved $($allow.Count) unique trusted prefixes." -ForegroundColor Yellow
$target = "WAF Policy '$WafPolicyName'"
$action = "Replace rule '$RuleName' with a negated IP allowlist and action '$RuleAction'"
if (-not $PSCmdlet.ShouldProcess($target,$action)) { return }
if (-not $Force) {
    if ((Read-Host 'Type YES to update the WAF policy') -cne 'YES') { Write-Warning 'Cancelled.'; return }
}
Write-Step 'Updating WAF policy'
$null = Invoke-ArmJson -Method PUT -Path $wafPath -Body $body
Write-Step 'Verifying update'
$verify = Invoke-ArmJson -Method GET -Path $wafPath
$vr = @($verify.properties.customRules | Where-Object { $_.name -ieq $RuleName })
if ($vr.Count -ne 1) { throw "Verification failed: rule '$RuleName' was not found." }
Write-Host "Success. Rule '$RuleName' contains $(@($vr[0].matchConditions[0].matchValues).Count) trusted prefixes." -ForegroundColor Green
