[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackageRoot,
    [Parameter(Mandatory=$true)][string]$LauncherPath,
    [Parameter(Mandatory=$true)][string]$RunnerPath
)

$ErrorActionPreference = 'Stop'

function Invoke-ManifestVerifierFromScript {
    param([string]$ScriptPath, [string]$Root)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "PowerShell parse failure: $ScriptPath"
    }
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Read-AndVerifyManifest'
    }, $true))
    if ($definitions.Count -ne 1) {
        throw "Manifest verifier count mismatch: $ScriptPath"
    }
    $invocation = [scriptblock]::Create(
        $definitions[0].Extent.Text + [Environment]::NewLine +
        'Read-AndVerifyManifest -Root $args[0]')
    return & $invocation $Root
}

foreach ($script in @($LauncherPath, $RunnerPath)) {
    $manifest = Invoke-ManifestVerifierFromScript -ScriptPath $script `
        -Root $PackageRoot
    if ($null -eq $manifest -or @($manifest.files).Count -eq 0) {
        throw "Manifest verifier returned no files: $script"
    }
    $profiles = @($manifest.reviewed_ipv4_profiles)
    if ($manifest.package_version -ne 'v12' -or
            $manifest.policy_version -ne 'v6' -or
            $manifest.plan_version -ne 'v4' -or
            $manifest.reviewed_ipv4_target -ne '192.168.204.1' -or
            $manifest.negative_test_ipv4 -ne '192.168.204.2' -or
            $profiles.Count -ne 2 -or
            [int]$manifest.reviewed_route_probe_udp_port -ne 9 -or
            [int]$manifest.address_refresh_seconds -ne 5 -or
            @($profiles | Where-Object {
                @($_.rules).Count -lt 1 -or
                @($_.rule_ids).Count -ne @($_.rules).Count -or
                ([string]$_.rules_sha256) -notmatch '^[0-9a-f]{64}$' -or
                ([string]$_.config_sha256) -notmatch '^[0-9a-f]{64}$'
            }).Count -ne 0) {
        throw "Reviewed IPv4 manifest contract mismatch: $script"
    }
    Write-Output ('MANIFEST_READER_PASS script={0} files={1}' -f
        [IO.Path]::GetFileName($script), @($manifest.files).Count)
}
