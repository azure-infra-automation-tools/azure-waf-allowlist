# Azure Service Tag -> Application Gateway WAF allowlist

This package synchronizes Azure Service Tag address prefixes plus custom IP/CIDR ranges into an existing Azure Application Gateway WAF Policy.

## Files

- `Sync-PowerAutomateWafAllowlist.ps1` - automation script
- `README.md` - usage notes

## Design

The script resolves the requested Azure Service Tags, merges their prefixes with custom IPs, then reads the current WAF policy and replaces only the custom rule identified by `RuleName`.

The generated custom rule uses `RemoteAddr` + `IPMatch` + `negationConditon = true` with action `Block` by default. In other words, traffic not in the trusted address list matches this rule and is blocked. Trusted traffic does not match this rule, so it can continue through the WAF policy's remaining custom rules and managed rules. The script does not add a separate `Allow` rule or a catch-all block rule.

```text
Azure Service Tag Discovery API
        │
        │ Get current IP prefixes
        ▼
┌───────────────────────────┐
│ Resolve Service Tags      │
│                           │
│ Requested Service Tags    │
│ e.g. LogicApps            │
│ PowerPlatformPlex         │
│ PowerPlatformInfra        │
└────────────┬──────────────┘
             │
             │ CIDR list
             ▼
      ┌─────────────┐
      │ Merge       │◄──── Custom IPs
      │ allow list  │      203.0.113.10/32
      └──────┬──────┘      198.51.100.0/24
             │
             ▼
       Azure Resource Manager REST API
             │
             ▼
┌──────────────────────────────┐
│ Application Gateway          │
│                              │
│ WAF Policy                   │
│                              │
│ Replace one named custom rule│
│ RemoteAddr / IPMatch         │
│ Negated match                │
│ Action = Block (default)     │
└─────────────┬────────────────┘
              │
              └── Trusted traffic continues through the policy
```


### WAF Policy Design:

The script replaces the rule named by `-RuleName` (default `BlockNonTrustedSources`) and sets its priority from `-RulePriority` (default `10`). It removes any existing rule with that name, then adds the generated rule. Other custom rules remain in the policy; if another rule already uses the selected priority, the script stops without updating.

```text
Application Gateway
        │
        ▼
WAF Policy
│
├── Other existing custom rules (retained)
│
└── Priority 10 (default; configurable)
    BlockNonTrustedSources (default name; configurable)
    MatchRule: RemoteAddr / IPMatch
    Negated: true
    Values: resolved Service Tag prefixes + custom prefixes
    Action: Block (default; configurable to Log)
    State: Enabled (default; configurable to Disabled)
    │
    ├── Untrusted source matches this rule → Block (or Log)
    └── Trusted source does not match → continue through policy evaluation
```

### Script Execution Flow

```text
                 Script invocation
                         │
                         ▼
             Import Az.Accounts / set context
             (or connect with managed identity)
                         │
                         ▼
             Service Tag Discovery API
                         │
          Match requested tags and collect prefixes
          (exact name, or name prefix for parent tags)
          (missing tags warn, or fail with the strict switch)
                         ▼
             Validate and normalize custom IPs
             (bare IPs become /32 or /128)
                         │
                         ▼
             Skip IPv6 unless -IncludeIPv6
                         │
                         ▼
            Combine prefixes, sort and deduplicate
                         │
                         ▼
             Read current WAF policy with ARM
             Check priority conflict; build body
             (retain other rules and policy settings)
                         │
             -ExportArtifacts? ── Yes ──► Write JSON artifacts
                         │
                         ▼
                 ShouldProcess approval?
                  (supports -WhatIf/-Confirm)
                    /              \
              Not approved        Approved
              Return; no PUT          │
                                     ▼
                       Unless -Force, require typing YES
                                     │
                                     ▼
                               PUT policy
                                     │
                                     ▼
                         GET policy and verify rule
```

There is no comparison with the current allowlist and no no-change shortcut: an approved invocation sends a PUT even if the generated rule is unchanged. `-WhatIf` prevents the PUT, but artifact export happens before the ShouldProcess check.

`-Force` skips the script's additional `Type YES` prompt. It does not disable PowerShell's `ShouldProcess` confirmation; use `-Confirm:$false` to suppress that confirmation when appropriate.

## Prerequisites

- PowerShell 7.2+
- `Az.Accounts`
- Permission to read Azure Service Tags
- Permission to read and update the target Application Gateway WAF Policy

Install the module:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
```

## Power Automate service tags

For Power Automate HTTP / HTTP + Swagger scenarios, start with:

```powershell
@('LogicApps','PowerPlatformPlex','PowerPlatformInfra')
```

For connector scenarios, use the service tags appropriate for the connector, for example `AzureConnectors`. Confirm the tags required by your flow before production rollout.

## Preview first

```powershell
./Sync-PowerAutomateWafAllowlist.ps1 `
  -SubscriptionId '00000000-0000-0000-0000-000000000000' `
  -ResourceGroupName 'rg-network-prod' `
  -WafPolicyName 'waf-policy-prod' `
  -ServiceTagLocation 'eastasia' `
  -ServiceTagNames @('LogicApps','PowerPlatformPlex','PowerPlatformInfra') `
  -CustomIpAddresses @('203.0.113.10/32','198.51.100.0/24') `
  -ExportArtifacts `
  -WhatIf
```

## Apply

```powershell
./Sync-PowerAutomateWafAllowlist.ps1 `
  -SubscriptionId '00000000-0000-0000-0000-000000000000' `
  -ResourceGroupName 'rg-network-prod' `
  -WafPolicyName 'waf-policy-prod' `
  -ServiceTagLocation 'eastasia' `
  -ServiceTagNames @('LogicApps','PowerPlatformPlex','PowerPlatformInfra') `
  -CustomIpAddresses @('203.0.113.10/32','198.51.100.0/24') `
  -ExportArtifacts `
  -Force
```

## Managed identity

For Azure Automation or another Azure host with a managed identity:

```powershell
./Sync-PowerAutomateWafAllowlist.ps1 `
  -SubscriptionId '<subscription-id>' `
  -ResourceGroupName '<resource-group>' `
  -WafPolicyName '<policy-name>' `
  -ServiceTagLocation 'eastasia' `
  -UseManagedIdentity `
  -Force
```

## Safety features

- `-WhatIf` previews the update.
- Existing custom rules with other names are retained.
- A priority collision with another custom rule causes the script to stop.
- The existing managed rules and policy settings are retained in the PUT payload.
- Missing service tags generate a warning, or an error with `-FailOnMissingServiceTag`.
- IPv6 prefixes are skipped unless `-IncludeIPv6` is specified.
- `-ExportArtifacts` writes the resolved allowlist and generated ARM request body for inspection.

## Production recommendation

Always run `-WhatIf` first and inspect `waf-policy-request.json` before the first production update. Also test from one trusted and one untrusted source after deployment.
