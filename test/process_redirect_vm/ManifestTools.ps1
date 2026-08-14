function Read-StrictUtf8Json([Parameter(Mandatory = $true)][string]$Path) {
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $text = [IO.File]::ReadAllText($Path, $utf8)
    return $text | ConvertFrom-Json
}
