# Extra control-port firewall allowance (design A, evaluated 2026-09-30).
# Idempotent inbound allow rules for auxiliary MCP service ports that share
# the FakeNet-NG control link: host-only scope, own rule name so the
# product's strict single-rule startup verification is never touched.
# B (folding this into install -ExtraExcludePort semantics) is a recorded
# TODO for the next natural product build; see the deployment appendix.
param(
    [Parameter(Mandatory = $true)][string]$VmIp,
    [Parameter(Mandatory = $true)][string[]]$Ports,
    [string]$AllowedHost = '192.168.204.1',
    [string]$RuleName = 'FakeNet-NG MCP Extra Control'
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'add-extra-control-firewall must run elevated (Administrator)'
}
# Tolerate single comma-separated strings (powershell -File binds arrays as
# one literal string): normalize once before use.
$Ports = @($Ports | ForEach-Object { "$_" -split ',' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
foreach ($port in $Ports) {
    if ($port -notmatch '^[0-9]+$' -or [int]$port -lt 1 -or [int]$port -gt 65535) {
        throw "invalid port: $port"
    }
}
# Delete-then-add keeps repeated runs from duplicating or drifting.
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule
$clean = @($Ports | ForEach-Object { [int]$_ })
$null = New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $clean -RemoteAddress $AllowedHost
$rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
$filter = $rule | Get-NetFirewallPortFilter
$addr = $rule | Get-NetFirewallAddressFilter
[pscustomobject]@{
    rule = $RuleName
    enabled = [string]$rule.Enabled
    direction = [string]$rule.Direction
    action = [string]$rule.Action
    protocol = [string]$filter.Protocol
    local_ports = @($filter.LocalPort) -join ','
    remote = @($addr.RemoteAddress) -join ','
} | ConvertTo-Json -Compress
