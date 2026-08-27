import codecs
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProcessRedirectVmContractTests(unittest.TestCase):
    def test_builder_is_utf8_bom_for_windows_powershell_51(self):
        data = (ROOT / 'Build-ProcessRedirectVmPackage.ps1').read_bytes()
        self.assertTrue(data.startswith(codecs.BOM_UTF8))

    def test_runner_is_noninteractive_fail_closed_and_collects_wire_evidence(self):
        path = ROOT / 'test' / 'process_redirect_vm' / 'Run-ProcessRedirectTests.ps1'
        text = path.read_text(encoding='utf-8')
        required = (
            'Test-IsVirtualMachine', 'Assert-Manifest', 'Select-ReviewedDns',
            'Invoke-RouteSnapshot', 'Find-NetRoute', 'Test-Sentinel',
            'FNPR/1', 'PROCESS_REDIRECT_READY', 'EGRESS_CONTROL_READY',
            'owner-gate-10000', "'--parallel-connections','64'",
            "'16-22 minutes on the reviewed 4 GB VM'", '1500000',
            "'OfflineEnvironmentSetup'", "'FakeNetStartup'",
            'Get-CompletedConnectionCount', 'Write-LongTaskProgress',
            "'StopAndVerify'",
            'pktmon.exe start', 'pktmon.exe etl2pcap',
            'FrozenImageWriteDenial', 'target-client-log',
            'verify_process_redirect.py', 'verify_dual_pcap.py',
            'DualPcapVerification', 'Stop-FakeNet',
            'dns-before.txt', 'dns-after.txt', 'Plain logs available at:',
            "Join-Path $root 'Logs'",
        )
        for marker in required:
            self.assertIn(marker, text, marker)
        forbidden = (
            'Read-Host', 'Invoke-WebRequest', 'Start-BitsTransfer',
            'pip download', '8.8.8.8', '1.1.1.1', 'Stop-Process',
        )
        for marker in forbidden:
            self.assertNotIn(marker, text, marker)

    def test_builder_binds_one_profile_two_native_clients_and_no_log_archive(self):
        text = (ROOT / 'Build-ProcessRedirectVmPackage.ps1').read_text(
            encoding='utf-8')
        required = (
            "packageVersion = 'v23'", 'Parameter(Mandatory = $true)',
            'New-Client', '/DTARGET_CLIENT=1', '/Brepro',
            'target_client_sha256', 'non_target_client_sha256',
            'process-redirect-manifest.json', 'New-DeterministicZip',
            '$buildMarkers', 'Runner contains unresolved build marker:',
            'No Logs directory and no .sha256 sidecar were generated.',
        )
        for marker in required:
            self.assertIn(marker, text, marker)
        self.assertNotIn('Compress-Archive', text)

    def test_wire_verifier_checks_transparency_and_loop_bound(self):
        text = (ROOT / 'test' / 'process_redirect_vm' /
                'verify_process_redirect.py').read_text(encoding='utf-8')
        required = (
            "row.get('peer') != peer",
            "counts['original'] != 0",
            "counts['target'] > 200000",
            "'PROCESS_REDIRECT_AUDIT_SUMMARY'",
            "'PROCESS_REDIRECT_SUSPEND'",
            "'PROCESS_REDIRECT_RESUME'",
            "'reason=route_query_'",
            "'reason=route_snapshot_changed'",
            "'reason=policy_exception'",
        )
        for marker in required:
            self.assertIn(marker, text, marker)

    def test_runtime_template_has_only_the_reviewed_single_tcp_rule(self):
        text = (ROOT / 'fakenet' / 'configs' /
                'process_redirect_windows.ini').read_text(encoding='utf-8')
        self.assertIn('ExternalProcessRedirectEnabled: Yes', text)
        self.assertIn('ExternalProcessRedirectProtocol: TCP', text)
        self.assertIn('__RUNTIME_PROCESS_IMAGE_PATH__', text)
        self.assertIn('__RUNTIME_PROCESS_IMAGE_SHA256__', text)
        self.assertIn('__RUNTIME_PUBLIC_IPV4_A__', text)
        self.assertIn('__RUNTIME_PRIVATE_IPV4_B__', text)
        self.assertNotIn('ExternalAllowedIPv4Rules:', text)

    def test_runner_accepts_reviewed_build_with_windows_revision_component(self):
        text = (ROOT / 'test' / 'process_redirect_vm' /
                'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        self.assertIn('$osVersion.Major -ne 10', text)
        self.assertIn('$osVersion.Minor -ne 0', text)
        self.assertIn('$osVersion.Build -ne 19045', text)
        self.assertNotIn(
            "[Environment]::OSVersion.Version.ToString() -ne '10.0.19045'",
            text)

    def test_manifest_is_decoded_as_strict_utf8_on_windows_powershell_51(self):
        text = (ROOT / 'test' / 'process_redirect_vm' /
                'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'ManifestTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-ManifestEncoding.ps1').read_text(encoding='utf-8')
        self.assertIn('Read-StrictUtf8Json $manifestPath', text)
        self.assertIn('Text.UTF8Encoding($false, $true)', tools)
        self.assertIn('[IO.File]::ReadAllText($Path, $utf8)', tools)
        self.assertIn('Windows仅放行指定域名方案.md', regression)
        self.assertNotIn('manifest-path-error.json', text)
        self.assertIn('[IO.Path]::GetFullPath($candidatePath)', text)

    def test_route_target_array_is_not_nested_by_powershell_51_pipeline(self):
        route_script = (ROOT / 'Test-ProcessRedirectRoutes.ps1').read_text(
            encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'RouteTargetTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-RouteTargetEncoding.ps1').read_text(encoding='utf-8')
        self.assertIn(
            '$targets = @(ConvertFrom-RouteTargetsBase64 $TargetsBase64)',
            route_script)
        self.assertNotIn('@($json | ConvertFrom-Json)', route_script)
        self.assertIn('$decoded = $json | ConvertFrom-Json', tools)
        self.assertIn("@('110.242.69.21', '192.168.204.1')", regression)

    def test_find_net_route_two_object_result_is_decoded_fail_closed(self):
        route_script = (ROOT / 'Test-ProcessRedirectRoutes.ps1').read_text(
            encoding='utf-8')
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'RouteResultTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-RouteResultShape.ps1').read_text(encoding='utf-8')
        for consumer in (route_script, runner):
            self.assertIn('ConvertFrom-FindNetRouteResult', consumer)
        self.assertIn(
            '$routes = @(ConvertFrom-RouteSnapshotJson $routeJson)', runner)
        self.assertNotIn(
            '@(Get-Content -LiteralPath $stdout -Raw | ConvertFrom-Json)',
            runner)
        self.assertIn('$items.Count -ne 2', tools)
        self.assertIn('$addresses.Count -ne 1', tools)
        self.assertIn('$routes.Count -ne 1', tools)
        self.assertIn(
            '$address.InterfaceIndex -ne [int]$route.InterfaceIndex', tools)
        self.assertIn('-Result @($address, $route)', regression)
        self.assertIn('$decoded = $Json | ConvertFrom-Json', tools)
        self.assertIn('$snapshots.Count -ne 2', regression)

    def test_windows_powershell_child_exit_codes_are_explicitly_tracked(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'ProcessExitTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-ProcessExitTracking.ps1').read_text(
                          encoding='utf-8')
        self.assertGreaterEqual(
            runner.count('Register-ProcessExitCodeTracking'), 3)
        self.assertGreaterEqual(
            runner.count('Read-TrackedProcessExitCode'), 3)
        self.assertNotIn('$process.ExitCode -ne 0', runner)
        self.assertNotIn('$process.ExitCode -notin', runner)
        self.assertIn('$handle = $Process.Handle', tools)
        self.assertIn('$null -eq $exitCode', tools)
        self.assertIn("'System.Int32'", regression)
        self.assertIn('exit /b 7', regression)

    def test_runtime_markers_are_separate_from_builder_markers(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        template = (ROOT / 'fakenet' / 'configs' /
                    'process_redirect_windows.ini').read_text(encoding='utf-8')
        builder = (ROOT / 'Build-ProcessRedirectVmPackage.ps1').read_text(
            encoding='utf-8')
        for marker in (
                '__RUNTIME_EXTERNAL_DNS__',
                '__RUNTIME_PROCESS_IMAGE_PATH__',
                '__RUNTIME_PROCESS_IMAGE_SHA256__',
                '__RUNTIME_PUBLIC_IPV4_A__',
                '__RUNTIME_PRIVATE_IPV4_B__'):
            self.assertIn(marker, runner)
            self.assertIn(marker, template)
        self.assertIn('Test-RuntimeConfigMarkers.ps1', builder)
        self.assertIn(
            'Runtime config marker separation regression failed.', builder)
        self.assertIn('Runtime config contains unresolved markers:', runner)

    def test_native_stderr_is_captured_before_strict_exit_verdicts(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'NativeCommandTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-NativeCommandCapture.ps1').read_text(
                          encoding='utf-8')
        self.assertGreaterEqual(runner.count('Invoke-NativeCaptured'), 8)
        self.assertIn('PktmonPreStop OBSERVED', runner)
        self.assertIn('pktmon start failed with exit code', runner)
        self.assertIn('pktmon stop failed with exit code', runner)
        self.assertIn('pktmon final stop exit=', runner)
        self.assertIn("$ErrorActionPreference = 'Continue'", tools)
        self.assertIn('$nativeExitCode = $LASTEXITCODE', tools)
        self.assertIn('$ErrorActionPreference = $previousPreference', tools)
        self.assertIn('packet monitor is not running', regression)
        self.assertIn('$exitCode -ne 7', regression)

    def test_fakenet_launches_as_package_module_and_reports_early_exit(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'FakeNetLaunchTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-FakeNetModuleLaunch.ps1').read_text(
                          encoding='utf-8')
        self.assertIn("'-X','utf8','-u','-m','fakenet.fakenet'", runner)
        self.assertNotIn("Join-Path $root 'fakenet\\fakenet.py'", runner)
        self.assertIn('$env:PYTHONPATH = $root', runner)
        self.assertIn('$previousPythonPath = $env:PYTHONPATH', runner)
        self.assertIn('Remove-Item Env:PYTHONPATH', runner)
        self.assertIn('Read-TrackedProcessExitCode $script:FakeNet', runner)
        self.assertIn('Get-LogSummary $ErrorPath', runner)
        self.assertIn(
            'Test-AnyLogContainsMarker -Paths @($Path,$ErrorPath)', runner)
        self.assertIn('--port $sentinelPort --log $fakeErr', runner)
        self.assertNotIn('--port $sentinelPort --log $fakeLog', runner)
        self.assertIn('$null -ne $text -and $text.Contains($Marker)', tools)
        self.assertIn('foreach ($path in $Paths)', tools)
        self.assertIn("return '<empty>'", tools)
        self.assertIn("find_spec('fakenet')", regression)
        self.assertIn('fakenet\\__init__.py', regression)
        self.assertIn('A READY marker in FakeNet stderr was not detected.',
                      regression)

    def test_windivert_pe_version_is_compared_semantically_and_strictly(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        tools = (ROOT / 'test' / 'process_redirect_vm' /
                 'WinDivertVersionTools.ps1').read_text(encoding='utf-8')
        regression = (ROOT / 'test' / 'process_redirect_vm' /
                      'Test-WinDivertVersion.ps1').read_text(encoding='utf-8')
        self.assertIn('Test-WinDivertVersionMatch', runner)
        self.assertNotIn('actual_file_version).StartsWith(', runner)
        self.assertIn('(?: built by: WinDDK)?', tools)
        self.assertIn("'1.3.0' -Actual '1.3 built by: WinDDK'", regression)
        self.assertIn("'1.3 built by: unknown'", regression)

    def test_forward_vm_path_has_pacing_capture_cleanup_and_full_evidence(self):
        runner = (ROOT / 'test' / 'process_redirect_vm' /
                  'Run-ProcessRedirectTests.ps1').read_text(encoding='utf-8')
        client = (ROOT / 'test' / 'process_redirect_vm' / 'client' /
                  'process_redirect_client.c').read_text(encoding='utf-8')
        verifier = (ROOT / 'test' / 'process_redirect_vm' /
                    'verify_process_redirect.py').read_text(encoding='utf-8')
        builder = (ROOT / 'Build-ProcessRedirectVmPackage.ps1').read_text(
            encoding='utf-8')
        self.assertIn('--capture --comp nics --pkt-size 0', runner)
        self.assertIn('--minimum-start-interval-ms', client)
        self.assertIn('--parallel-connections', client)
        self.assertIn('Stop-TrackedClientProcesses', runner)
        burst = runner.index('ConcurrentBurst64')
        self.assertLess(
            runner.index('\n    Stop-TrackedClientProcesses\n', burst),
            runner.index('Stop-FakeNet $root', burst))
        self.assertIn("'budget_pressure'", verifier)
        self.assertIn('minimum_mappings', verifier)
        self.assertIn('owner_query_budget_exhausted', verifier)
        self.assertIn('expected_windivert_x64_dll_sha256', builder)
        self.assertIn('expected_windivert_x64_sys_sha256', builder)
        self.assertIn('Test-RunnerForwardContracts.ps1', builder)
        self.assertIn('Test-LongTaskConsole.ps1', builder)
        self.assertIn(
            'Long-task console visibility regression failed.', builder)


if __name__ == '__main__':
    unittest.main()
