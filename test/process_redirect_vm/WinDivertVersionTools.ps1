function ConvertTo-WinDivertVersionParts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [switch]$AllowWinDdkSuffix
    )

    $suffix = if ($AllowWinDdkSuffix) {
        '(?: built by: WinDDK)?'
    } else { '' }
    $match = [regex]::Match(
        $Value,
        ('^(?<version>[0-9]+(?:\.[0-9]+){{1,3}}){0}$' -f $suffix),
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { return $null }

    $textParts = @($match.Groups['version'].Value.Split('.'))
    $parts = @(0,0,0,0)
    for ($index = 0; $index -lt $textParts.Count; $index++) {
        $part = 0
        if (-not [int]::TryParse(
                $textParts[$index],
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$part)) {
            return $null
        }
        $parts[$index] = $part
    }
    return $parts
}

function Test-WinDivertVersionMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Actual
    )

    $expectedParts = @(ConvertTo-WinDivertVersionParts -Value $Expected)
    $actualParts = @(ConvertTo-WinDivertVersionParts -Value $Actual `
        -AllowWinDdkSuffix)
    if ($expectedParts.Count -ne 4 -or $actualParts.Count -ne 4) {
        return $false
    }
    for ($index = 0; $index -lt 4; $index++) {
        if ($expectedParts[$index] -ne $actualParts[$index]) {
            return $false
        }
    }
    return $true
}
