function ConvertFrom-RouteTargetsBase64(
        [Parameter(Mandatory = $true)][string]$TargetsBase64) {
    $bytes = [Convert]::FromBase64String($TargetsBase64)
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $json = $utf8.GetString($bytes)
    $decoded = $json | ConvertFrom-Json
    return $decoded
}
