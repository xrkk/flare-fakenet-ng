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
    Write-Output ('MANIFEST_READER_PASS script={0} files={1}' -f
        [IO.Path]::GetFileName($script), @($manifest.files).Count)
}
