# Copilot instructions

## Architecture

`Sync-PowerAutomateWafAllowlist.ps1` is the package's single automation entry point; see [README.md](../README.md) for prerequisites and usage. It authenticates with `Az.Accounts`, retrieves regional Azure Service Tags and the existing Application Gateway WAF policy through ARM REST, resolves and deduplicates trusted CIDRs, then replaces one named custom rule. It preserves other custom rules and the policy's existing settings, managed rules, tier, and tags, writes the policy through ARM, and reads it back to verify the target rule.

## Build and validation

There is no build, test/Pester, or lint runner in the repository, and no single-test command is available. Run this parser-only check from the repository root to validate the PowerShell script (it exits nonzero and prints parser errors if any):

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path '.\Sync-PowerAutomateWafAllowlist.ps1'),
    [ref]$tokens,
    [ref]$errors
) | Out-Null
if ($errors) { $errors; exit 1 }
```

For an operational preview, use the README command with `-WhatIf`; inspect `waf-policy-request.json` when exporting artifacts before applying an update.

`-WhatIf` suppresses the policy PUT, but the script still authenticates, retrieves Service Tags and the current WAF policy, and writes artifacts if `-ExportArtifacts` is supplied.

The workspace Azure MCP server is configured in [.vscode/mcp.json](../.vscode/mcp.json). It uses the developer's local Azure sign-in; authenticate with Azure CLI (`az login`) and verify the intended subscription before using Azure tools.

## Repository-specific conventions

- Keep changes in the PowerShell 7.2+ script compatible with its `Az.Accounts` requirement. It uses strict mode, terminating errors, small helper functions, and ARM REST JSON serialization with deep nesting.
- Preserve the update boundary: replace only the rule named by `RuleName`, retain all other WAF policy data, and stop on a priority collision. The rule intentionally uses the ARM field spelling `negationConditon`; do not “correct” it.
- The default rule is a negated `RemoteAddr`/`IPMatch` rule with `Block` action: addresses in the trusted list do not match this blocking rule. Preserve this behavior when changing rule construction or documentation.
- Service tag matching is case-insensitive and accepts exact names or regional child tags whose names start with `<tag>.`. IPv6 prefixes are skipped unless `-IncludeIPv6` is set; keep normalization and deduplication for both service-tag and custom CIDRs.
- Keep the update behind `ShouldProcess` and the explicit confirmation (unless `-Force` is supplied). `-WhatIf` prevents the ARM write; artifact export, if requested, occurs before that check.
