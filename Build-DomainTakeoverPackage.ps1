[CmdletBinding()]
param(
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$packageVersion = 'v18'
$packageName = "Windows公网指定IPv4放行-$packageVersion"
$planRelative = 'PLAN\2026.08.05\2026.08.05-01-Windows指定IPv4全端口及指定端口放行方案.md'
$reviewedRouteProbeUdpPort = 9
$addressRefreshSeconds = 5
$fixedTimestamp = [DateTimeOffset]::new(
    [DateTime]::SpecifyKind([DateTime]'2000-01-01T00:00:00',
        [DateTimeKind]::Utc))

function Invoke-GitCaptured {
    param([string[]]$Arguments)
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('git failed: {0}' -f ($output -join [Environment]::NewLine))
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Get-NormalizedText {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw).Replace("`r`n", "`n")
}

function Get-TextSha256 {
    param([string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
        return ([BitConverter]::ToString(
            $algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Test-ReviewedGlobalIPv4 {
    param([string]$Value)
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address) -or
            $address.AddressFamily -ne
                [Net.Sockets.AddressFamily]::InterNetwork -or
            $address.ToString() -ne $Value) {
        return $false
    }
    $b = $address.GetAddressBytes()
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or
            $b[0] -ge 224 -or
            ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and $b[1] -eq 168) -or
            ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 0) -or
            ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) -or
            ($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99) -or
            ($b[0] -eq 198 -and $b[1] -in @(18, 19)) -or
            ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) -or
            ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) {
        return $false
    }
    return $true
}

function Get-NormalizedReviewedRules {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'ExternalAllowedIPv4Rules must be present and non-empty for v18.'
    }
    $parts = @($Value.Split(','))
    if ($parts.Count -gt 32 -or @($parts | Where-Object {
                [string]::IsNullOrWhiteSpace($_)
            }).Count -ne 0) {
        throw 'ExternalAllowedIPv4Rules has an empty item or exceeds 32 rules.'
    }
    $normalized = @()
    $scopes = @{}
    $ips = @{}
    foreach ($part in $parts) {
        $token = $part.Trim()
        if ($token -notmatch '^(TCP|UDP)/([^/]+)/(\*|[0-9]+)$') {
            throw "Invalid reviewed IPv4 rule: $token"
        }
        $protocol = $matches[1]
        $ipv4 = $matches[2]
        $port = $matches[3]
        if (-not (Test-ReviewedGlobalIPv4 $ipv4)) {
            throw "Reviewed rule does not contain a canonical global IPv4: $token"
        }
        if ($port -ne '*' -and
                ([int64]$port -lt 1 -or [int64]$port -gt 65535)) {
            throw "Reviewed rule port is outside 1..65535: $token"
        }
        $canonical = '{0}/{1}/{2}' -f $protocol, $ipv4, $port
        if ($normalized -contains $canonical) {
            throw "Duplicate reviewed IPv4 rule: $canonical"
        }
        $scopeKey = '{0}/{1}' -f $protocol, $ipv4
        if (-not $scopes.ContainsKey($scopeKey)) {
            $scopes[$scopeKey] = @()
        }
        if (($port -eq '*' -and $scopes[$scopeKey].Count -gt 0) -or
                ($port -ne '*' -and $scopes[$scopeKey] -contains '*')) {
            throw "Wildcard and exact reviewed rules conflict: $scopeKey"
        }
        $scopes[$scopeKey] += $port
        $ips[$ipv4] = $true
        $normalized += $canonical
    }
    if ($ips.Count -gt 16) {
        throw 'ExternalAllowedIPv4Rules exceeds 16 distinct IPv4 addresses.'
    }
    return @($normalized | Sort-Object)
}

function Assert-ReviewedTemplate {
    param([string]$BasePath, [string]$TemplatePath)
    $base = Get-NormalizedText $BasePath
    $template = Get-NormalizedText $TemplatePath
    if (($template.Split("`n") | Where-Object {
                $_ -eq '# __REVIEWED_PUBLIC_IPV4_RULES__'
            }).Count -ne 1 -or
            $template -match '(?m)^ExternalAllowedIPv4Rules\s*:') {
        throw 'Reviewed IPv4 source template marker/active-rule contract failed.'
    }
    foreach ($comment in @(
            '# Build-only marker. The source template deliberately grants no public IPv4.',
            '# The v18 builder emits one manifest-bound TCP/443 runtime profile from here.',
            '# __REVIEWED_PUBLIC_IPV4_RULES__')) {
        $template = $template.Replace($comment + "`n", '')
    }
    if ($template -ne $base) {
        throw 'Reviewed IPv4 template differs from the allow-list base outside its marker.'
    }
}

function New-ReviewedProfile {
    param(
        [string]$TemplatePath,
        [string]$DestinationPath,
        [string]$RulesValue
    )
    $normalized = @(Get-NormalizedReviewedRules $RulesValue)
    $text = Get-NormalizedText $TemplatePath
    $marker = '# __REVIEWED_PUBLIC_IPV4_RULES__'
    if (($text.Split("`n") | Where-Object { $_ -eq $marker }).Count -ne 1) {
        throw 'Reviewed IPv4 profile marker count mismatch.'
    }
    $text = $text.Replace(
        $marker, 'ExternalAllowedIPv4Rules: ' + $RulesValue)
    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($DestinationPath, $text, $utf8NoBom)
    return [PSCustomObject]@{
        Raw = $RulesValue
        Normalized = @($normalized)
        NormalizedSha256 = Get-TextSha256 ($normalized -join ',')
        ConfigSha256 = (Get-FileHash -LiteralPath $DestinationPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Get-LockRows {
    param([string]$LockPath)
    $rows = @()
    foreach ($line in Get-Content -LiteralPath $LockPath) {
        if ($line -match '^\s*(?:#.*)?$') { continue }
        if ($line -notmatch '^([^= ]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})$') {
            throw "Invalid lock line: $line"
        }
        $rows += [PSCustomObject]@{
            Name = $matches[1]
            Version = $matches[2]
            Hash = $matches[3]
        }
    }
    return $rows
}

function Assert-Wheelhouse {
    param([string]$Root)
    $lockPath = Join-Path $Root 'requirements-domain-takeover-windows.lock'
    $wheelPath = Join-Path $Root 'wheelhouse'
    $rows = @(Get-LockRows $lockPath)
    $wheels = @(Get-ChildItem -LiteralPath $wheelPath -Filter '*.whl')
    $nonWheels = @(Get-ChildItem -LiteralPath $wheelPath -File |
        Where-Object Extension -notin @('.whl', '.md'))
    if ($nonWheels.Count -ne 0 -or $rows.Count -ne $wheels.Count) {
        throw 'Wheelhouse contains an unexpected file or lock/wheel count mismatch.'
    }
    foreach ($row in $rows) {
        $prefix = ('{0}_{1}_' -f
            $row.Name.ToLowerInvariant().Replace('-', '_'), $row.Version)
        $match = @($wheels | Where-Object {
            $_.Name.ToLowerInvariant().Replace('-', '_').StartsWith($prefix)
        })
        if ($match.Count -ne 1) {
            throw "Lock entry does not map to exactly one wheel: $($row.Name)"
        }
        if ($match[0].Name -notmatch
                '(cp313-cp313-win_amd64|cp3\d+-abi3-win_amd64|py3-none-any|py2\.py3-none-any)\.whl$') {
            throw "Wheel tag is incompatible with reviewed CPython 3.13 x64: $($match[0].Name)"
        }
        $actual = (Get-FileHash -LiteralPath $match[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $row.Hash) {
            throw "Wheel hash mismatch: $($match[0].Name)"
        }
    }
    $critical = @{
        'pyasynchat' = @('1.0.5',
            '35b7859515693e479e8d95ebe9f32cbf4d6312ab7599ced39fc24699e51de46f')
        'pyasyncore' = @('1.0.5',
            '269bbc5252671827387636822841a1fb721ec6e858b23a3e12cf92eb1f97da2a')
        'netifaces-plus' = @('0.12.5',
            'ee3287ddbf73221cd4310a7a087f22e4c8c134c4d22bec9d4a65aa75f970eb8f')
        'pydivert' = @('2.1.0',
            '382db488e3c37c03ec9ec94e061a0b24334d78dbaeebb7d4e4d32ce4355d9da1')
    }
    foreach ($name in $critical.Keys) {
        $row = @($rows | Where-Object Name -eq $name)
        if ($row.Count -ne 1 -or $row[0].Version -ne $critical[$name][0] -or
                $row[0].Hash -ne $critical[$name][1]) {
            throw "Reviewed critical dependency mismatch: $name"
        }
    }
    return $rows
}

function Assert-PowerShellSyntax {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw ('PowerShell syntax failure in {0}: {1}' -f
            $Path, (($errors | ForEach-Object Message) -join '; '))
    }
    $orphanParameters = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.CommandElements.Count -gt 0 -and
            $node.CommandElements[0].Extent.Text -match '^-[A-Za-z]'
    }, $true))
    if ($orphanParameters.Count -ne 0) {
        $first = $orphanParameters[0]
        throw ('PowerShell orphan parameter command in {0}, line {1}: {2}' -f
            $Path, $first.Extent.StartLineNumber, $first.Extent.Text)
    }
}

function Assert-PythonNativeArgumentSafety {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "Cannot inspect Python native arguments in invalid script: $Path"
    }

    $commands = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            @($node.CommandElements | Where-Object {
                $_.Extent.Text -eq '-c'
            }).Count -gt 0
    }, $true))
    foreach ($command in $commands) {
        $elements = @($command.CommandElements)
        $index = -1
        for ($i = 0; $i -lt $elements.Count; $i++) {
            if ($elements[$i].Extent.Text -eq '-c') {
                $index = $i
                break
            }
        }
        if ($index -lt 0 -or $index + 1 -ge $elements.Count) {
            throw "Malformed Python -c command in $Path"
        }
        $payload = $elements[$index + 1]
        if ($payload -is
                [System.Management.Automation.Language.VariableExpressionAst]) {
            throw ("Dynamic Python source must use stdin, not -c, in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
        if ($payload -isnot
                [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $payload -isnot
                [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
            throw ("Unreviewable Python -c payload in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
        if ([string]$payload.Value -match '"') {
            throw ("Python -c payload contains a PowerShell 5.1-unsafe double quote in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
    }

    $text = Get-Content -LiteralPath $Path -Raw
    $requiredStdin = if ([IO.Path]::GetFileName($Path) -like
            'Start-*.ps1') {
        @('identityCommand', 'dependencyCommand')
    } else {
        @('identityCommand', 'dependencyCommand')
    }
    foreach ($name in $requiredStdin) {
        $pattern = ('\${0}\s*\|\s*&\s*\$[A-Za-z][A-Za-z0-9]*\s+-\s*' -f
            [regex]::Escape($name))
        if ($text -notmatch $pattern) {
            throw "Dynamic Python source is not transported through stdin in ${Path}: `${name}"
        }
    }
}

function Assert-RunnerProbeDefaultSafety {
    param([string]$Path)
    $text = Get-Content -LiteralPath $Path -Raw
    $unsafe = 'ExternalTakeoverProbeTCPPorts\s*:\s*'
    if ($text.Contains($unsafe)) {
        throw 'VM runner uses a cross-line whitespace regex for the optional probe default.'
    }
    foreach ($required in @(
            "`$templateText -split '\r?\n'",
            "'^[ \t]*ExternalTakeoverProbeTCPPorts[ \t]*:[ \t]*`$'")) {
        if (-not $text.Contains($required)) {
            throw "VM runner is missing the line-local optional probe default contract: $required"
        }
    }
}

function Assert-ManifestReaderEncodingSafety {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "Cannot inspect manifest reader in invalid script: $Path"
    }
    $definitions = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Read-AndVerifyManifest'
    }, $true))
    if ($definitions.Count -ne 1) {
        throw "Manifest reader count mismatch: $Path"
    }
    $commands = @($definitions[0].FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'Get-Content'
    }, $true))
    if ($commands.Count -ne 1) {
        throw "Manifest reader Get-Content count mismatch: $Path"
    }
    $elements = @($commands[0].CommandElements)
    $hasUtf8 = $false
    for ($i = 0; $i -lt $elements.Count - 1; $i++) {
        if ($elements[$i] -is
                [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$i].ParameterName -eq 'Encoding' -and
                [string]$elements[$i + 1].Value -eq 'UTF8') {
            $hasUtf8 = $true
            break
        }
    }
    if (-not $hasUtf8) {
        throw "Manifest reader must specify Get-Content -Encoding UTF8: $Path"
    }
}

function New-DeterministicZip {
    param([string]$SourceRoot, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }
    $stream = [IO.File]::Open(
        $Destination, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $parent = Split-Path -Parent $SourceRoot
            foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse |
                    Sort-Object FullName) {
                $relative = $file.FullName.Substring($parent.Length + 1).Replace('\', '/')
                $entry = $archive.CreateEntry(
                    $relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                } finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$gitRootText = Invoke-GitCaptured @('-C', $repoRoot, 'rev-parse', '--show-toplevel')
$gitRoot = [IO.Path]::GetFullPath($gitRootText)
if ($gitRoot -ne $repoRoot) {
    throw 'Build script must run from the repository root.'
}
$resolvedCommit = Invoke-GitCaptured @(
    '-C', $repoRoot, 'rev-parse', ('{0}^{{commit}}' -f $SourceCommit))
if ($resolvedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceCommit did not resolve to one commit.'
}

$buildName = '.build-domain-takeover-{0}' -f [Guid]::NewGuid().ToString('N')
$buildRoot = Join-Path $repoRoot $buildName
$stage = Join-Path $buildRoot $packageName
$archivePath = Join-Path $buildRoot 'source.zip'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $outputRoot = Join-Path $repoRoot 'dist'
} else {
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
}
$zipPath = Join-Path $outputRoot ($packageName + '.zip')
if ($packageName -match '(?i)logs|日志') {
    throw 'Package name must not contain a log marker.'
}

try {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    & git -C $repoRoot archive --format=zip --output=$archivePath $resolvedCommit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $stage
    $archivedDist = Join-Path $stage 'dist'
    if (Test-Path -LiteralPath $archivedDist) {
        Remove-Item -LiteralPath $archivedDist -Recurse -Force
    }

    $required = @(
        'Start-ReviewedIPv4.cmd',
        'Start-ReviewedIPv4.ps1',
        'Test-ReviewedIPv4Routes.ps1',
        'Build-DomainTakeoverPackage.ps1',
        'requirements-domain-takeover-windows.lock',
        'wheelhouse\SOURCES.md',
        'fakenet\configs\domain_allowlist_windows.ini',
        'fakenet\configs\domain_reviewed_ipv4_windows.ini',
        'fakenet\configs\domain_takeover_windows.ini',
        'test\public_ipv4_allowlist_vm\Run-Tests.cmd',
        'test\public_ipv4_allowlist_vm\Run-ReviewedIPv4Tests.ps1',
        'test\public_ipv4_allowlist_vm\Test-LauncherContracts.ps1',
        'test\public_ipv4_allowlist_vm\Test-ManifestContracts.ps1',
        'test\analyze_reviewed_ipv4_pcap.py',
        'test\test_reviewed_ipv4_pcap.py',
        $planRelative)
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $relative))) {
            throw "Required archived file is missing: $relative"
        }
    }

    $baseConfig = Join-Path $stage 'fakenet\configs\domain_allowlist_windows.ini'
    $reviewedTemplate = Join-Path $stage `
        'fakenet\configs\domain_reviewed_ipv4_windows.ini'
    $takeoverConfig = Join-Path $stage 'fakenet\configs\domain_takeover_windows.ini'
    Assert-ReviewedTemplate $baseConfig $reviewedTemplate
    $takeoverText = Get-NormalizedText $takeoverConfig
    if ($takeoverText -match '(?m)^ExternalAllowedIPv4Rules\s*:' -or
            ($takeoverText.Split("`n") | Where-Object {
                $_ -eq 'ExternalTakeoverIPv4: 192.168.204.1'
            }).Count -ne 1) {
        throw 'Takeover regression profile must not contain reviewed IPv4 rules.'
    }
    if (Test-Path -LiteralPath (Join-Path $stage 'test\domain_takeover_vm')) {
        throw 'Legacy domain_takeover_vm directory must not enter the public IPv4 package.'
    }
    $baiduConfigRelative =
        'fakenet/configs/domain_reviewed_ipv4_baidu_tcp443_windows.ini'
    $baiduConfig = Join-Path $stage ($baiduConfigRelative.Replace('/', '\'))
    $baiduContract = New-ReviewedProfile $reviewedTemplate $baiduConfig `
        'TCP/110.242.69.21/443'
    $profileContracts = @(
        [PSCustomObject]@{
            Name = 'baidu_tcp443'; ConfigPath = $baiduConfigRelative
            Contract = $baiduContract
        })
    $dependencyRows = @(Assert-Wheelhouse $stage)
    $scriptSearch = @{
        LiteralPath = $stage
        Recurse = $true
        Filter = '*.ps1'
        File = $true
    }
    $powerShellScripts = @(Get-ChildItem @scriptSearch)
    foreach ($powerShellScript in $powerShellScripts) {
        Assert-PowerShellSyntax $powerShellScript.FullName
    }
    $launcherPath = Join-Path $stage 'Start-ReviewedIPv4.ps1'
    $runnerPath = Join-Path $stage `
        'test\public_ipv4_allowlist_vm\Run-ReviewedIPv4Tests.ps1'
    Assert-PythonNativeArgumentSafety $launcherPath
    Assert-PythonNativeArgumentSafety (
        $runnerPath)
    Assert-ManifestReaderEncodingSafety $launcherPath
    Assert-ManifestReaderEncodingSafety $runnerPath

    $launcherText = Get-Content -LiteralPath $launcherPath -Raw
    foreach ($forbidden in @('8.8.8.8', '1.1.1.1', 'Invoke-WebRequest',
            'pip download', 'pip install -U')) {
        if ($launcherText -match [regex]::Escape($forbidden)) {
            throw "Launcher contains forbidden fallback/download marker: $forbidden"
        }
    }
    foreach ($requiredMarker in @('--no-index', '--require-hashes',
            'IP_ALLOW_ROUTE_OK', 'IP_ALLOW_RISK_ACK',
            'IP_ALLOW_DNS_FRESHNESS_OK', 'Assert-ReviewedDnsFreshness',
            'Invoke-ReviewedRoutePreflight', 'WaitForExit(2000)',
            'DNS restoration check', 'TreatControlCAsInput',
            'Show-FakeNetLogUntilStop', 'Test-FakeNetTrafficReady',
            'EGRESS_CONTROL_READY', 'Ctrl+C')) {
        if ($launcherText -notmatch [regex]::Escape($requiredMarker)) {
            throw "Launcher is missing required marker: $requiredMarker"
        }
    }
    $windowsDiverterText = Get-Content -LiteralPath (
        Join-Path $stage 'fakenet\diverters\windows.py') -Raw
    foreach ($requiredMarker in @('ROUTE_PROBE_UDP_PORT = 9',
            '_REVIEWED_ROUTE_QUERY_TIMEOUT_SECONDS = 2',
            '_run_reviewed_route_checker', 'subprocess.Popen',
            "'-ReadyFile'",
            'while not self._stopping.wait(5)')) {
        if (-not $windowsDiverterText.Contains($requiredMarker)) {
            throw "Windows reviewed-route contract is missing: $requiredMarker"
        }
    }
    $routeCheckerText = Get-Content -LiteralPath (
        Join-Path $stage 'Test-ReviewedIPv4Routes.ps1') -Raw
    if (-not $routeCheckerText.Contains('$routeProbeUdpPort = 9') -or
            -not $routeCheckerText.Contains('Import-Module NetTCPIP') -or
            -not $routeCheckerText.Contains('ReadyFile') -or
            -not $routeCheckerText.Contains('GoFile') -or
            $routeCheckerText.Contains('.Send(') -or
            $routeCheckerText.Contains('.SendTo(') -or
            $routeCheckerText.Contains('Default route is not permitted') -or
            $routeCheckerText.Contains('Gateway route is not permitted')) {
        throw 'Reviewed route checker UDP/9 no-payload contract mismatch.'
    }
    $identityScripts = [ordered]@{
        Launcher = $launcherText
        Runner = Get-Content -LiteralPath $runnerPath -Raw
    }
    foreach ($identityScript in $identityScripts.GetEnumerator()) {
        if ($identityScript.Value -notmatch
                [regex]::Escape("json.dumps({'version':") -or
                $identityScript.Value -notmatch
                [regex]::Escape('python-identity.log') -or
                $identityScript.Value -notmatch
                '\$identityCommand\s*\|\s*&\s*\$[A-Za-z][A-Za-z0-9]*\s+-') {
            throw ("{0} is missing the stdin-safe Python identity contract." -f
                $identityScript.Key)
        }
        if ($identityScript.Value -match [regex]::Escape('json.dumps({"version"')) {
            throw ("{0} contains the PowerShell 5.1-unsafe Python identity payload." -f
                $identityScript.Key)
        }
    }

    $windowsPowerShell = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell)) {
        throw 'Windows PowerShell 5.1 is required for contract validation.'
    }
    $launcherContractLog = Join-Path $buildRoot 'launcher-contract'
    New-Item -ItemType Directory -Path $launcherContractLog -Force |
        Out-Null
    $launcherContractOutput = @(& $windowsPowerShell -NoLogo -NoProfile `
        -ExecutionPolicy Bypass -File (Join-Path $stage `
            'test\public_ipv4_allowlist_vm\Test-LauncherContracts.ps1') `
        -LauncherPath $launcherPath -RunnerPath $runnerPath `
        -LogDirectory $launcherContractLog `
        -SkipLiveRoute 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('PowerShell 5.1 launcher contract failed: {0}' -f
            ($launcherContractOutput -join [Environment]::NewLine))
    }

    $planPath = Join-Path $stage $planRelative
    $fileRows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Sort-Object FullName) {
        $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        if ($relative -eq 'domain-takeover-manifest.json') { continue }
        $fileRows += [ordered]@{
            path = $relative
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [uint64]$file.Length
        }
    }
    $templateHash = (Get-FileHash -LiteralPath $reviewedTemplate `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $takeoverConfigHash = (Get-FileHash -LiteralPath $takeoverConfig `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $planHash = (Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schema_version = 1
        policy_version = 'v7'
        plan_version = 'v5'
        package_version = $packageVersion
        source_commit = $resolvedCommit
        allowed_domain = 'api.deepseek.com'
        reviewed_hostname = 'www.baidu.com'
        reviewed_ipv4_target = '110.242.69.21'
        negative_test_ipv4 = '110.242.70.57'
        dns_freshness_required = $true
        reviewed_ipv4_template =
            'fakenet/configs/domain_reviewed_ipv4_windows.ini'
        reviewed_ipv4_template_sha256 = $templateHash
        reviewed_ipv4_profiles = @($profileContracts | ForEach-Object {
            [ordered]@{
                name = $_.Name
                config_path = $_.ConfigPath
                rules_raw = [string]$_.Contract.Raw
                rules = @($_.Contract.Normalized)
                rules_sha256 = [string]$_.Contract.NormalizedSha256
                rule_ids = @($_.Contract.Normalized | ForEach-Object {
                    (Get-TextSha256 $_).Substring(0, 16)
                })
                config_sha256 = [string]$_.Contract.ConfigSha256
            }
        })
        takeover_regression_profile = [ordered]@{
            config_path = 'fakenet/configs/domain_takeover_windows.ini'
            config_sha256 = $takeoverConfigHash
            takeover_ipv4 = '192.168.204.1'
            takeover_dns_ttl = 60
        }
        reviewed_route_probe_udp_port = $reviewedRouteProbeUdpPort
        address_refresh_seconds = $addressRefreshSeconds
        windows_build = '10.0.19045'
        python_version = '3.13.7'
        python_architecture = 'AMD64'
        plan_sha256 = $planHash
        dependencies = @($dependencyRows | Sort-Object Name | ForEach-Object {
            [ordered]@{ name=$_.Name; version=$_.Version; sha256=$_.Hash }
        })
        files = $fileRows
    }
    $manifestPath = Join-Path $stage 'domain-takeover-manifest.json'
    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    $manifestJson = $manifest | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText(
        $manifestPath, $manifestJson + [Environment]::NewLine, $utf8NoBom)

    $manifestContractPath = Join-Path $stage `
        'test\public_ipv4_allowlist_vm\Test-ManifestContracts.ps1'
    if (-not (Test-Path -LiteralPath $manifestContractPath)) {
        throw 'Archived PowerShell manifest contract test is missing.'
    }
    $contractOutput = @(& $windowsPowerShell -NoLogo -NoProfile `
        -ExecutionPolicy Bypass -File $manifestContractPath `
        -PackageRoot $stage -LauncherPath $launcherPath `
        -RunnerPath $runnerPath 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('PowerShell 5.1 manifest contract failed: {0}' -f
            ($contractOutput -join [Environment]::NewLine))
    }

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-DeterministicZip -SourceRoot $stage -Destination $zipPath
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "Package: $zipPath"
    Write-Host "SHA-256: $zipHash"
    Write-Host "Source commit: $resolvedCommit"
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $resolvedBuild = [IO.Path]::GetFullPath($buildRoot)
        $expectedPrefix = $repoRoot + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedBuild.StartsWith(
                $expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedBuild) -notlike
                    '.build-domain-takeover-*') {
            throw 'Refusing to remove an unexpected build path.'
        }
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
    }
}
