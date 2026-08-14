function Test-LogContainsMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $text = Get-Content -LiteralPath $Path -Raw
    return ($null -ne $text -and $text.Contains($Marker))
}

function Test-AnyLogContainsMarker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$Marker
    )

    foreach ($path in $Paths) {
        if (Test-LogContainsMarker -Path $path -Marker $Marker) {
            return $true
        }
    }
    return $false
}

function Get-LogSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return '<missing>'
    }
    $text = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace([string]$text)) {
        return '<empty>'
    }
    $summary = ([string]$text).Replace("`r",' ').Replace("`n",' ').Trim()
    if ($summary.Length -gt 512) { return $summary.Substring(0,512) }
    return $summary
}
