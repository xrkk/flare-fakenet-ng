function Read-ExitCodeEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('Exit-code evidence is missing: ' + $Path)
    }
    $lines = @(Get-Content -LiteralPath $Path -Encoding ASCII)
    if ($lines.Count -ne 1) {
        throw ('Exit-code evidence must contain exactly one line: ' + $Path)
    }
    $text = [string]$lines[0]
    if ($text -notmatch '^([0-9]|[1-9][0-9]{1,2})$') {
        throw ('Exit-code evidence is not a decimal byte: ' + $text)
    }
    $value = [int]$text
    if ($value -gt 255) {
        throw ('Exit-code evidence exceeds 255: ' + $text)
    }
    return $value
}
