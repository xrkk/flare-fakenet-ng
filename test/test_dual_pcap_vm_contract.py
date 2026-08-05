import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).parents[1]


class DualPcapVmContractTests(unittest.TestCase):
    def test_runner_is_parameter_free_offline_and_plaintext(self):
        runner = (ROOT / 'test/dual_pcap_vm/Run-DualPcapTests.ps1').read_text(
            encoding='utf-8')
        for required in (
                'Test-IsVirtualMachine', '--no-index', '--require-hashes',
                'TreatControlCAsInput', 'Plain logs available at:',
                "@('raw-write', 'ethernet-write', 'close')",
                'Test-NetworkRestored', 'benchmark_dual_pcap.py'):
            self.assertIn(required, runner)
        for forbidden in (
                'Invoke-WebRequest', 'pip download', '8.8.8.8', '1.1.1.1',
                'Compress-Archive', 'Read-Host'):
            self.assertNotIn(forbidden, runner)

    def test_builder_uses_unique_versioned_name_without_sidecar(self):
        builder = (ROOT / 'Build-DualPcapVmPackage.ps1').read_text(
            encoding='utf-8')
        self.assertIn('$packageVersion = \'v3\'', builder)
        self.assertIn('Windows双PCAP同步输出-', builder)
        self.assertNotIn("Set-Content -LiteralPath ($zipPath + '.sha256')",
                         builder)
        self.assertIn('No .sha256 sidecar was generated.', builder)

    def test_faults_are_process_local_test_seams(self):
        launcher = (ROOT / 'test/dual_pcap_vm/fault_launcher.py').read_text(
            encoding='utf-8')
        self.assertIn('diverterbase.DualPcapWriter = dual_factory', launcher)
        self.assertNotIn('os.environ', launcher)
        self.assertNotIn('ConfigParser', launcher)

    def test_python_warning_cannot_abort_powershell_runner(self):
        runner = (ROOT / 'test/dual_pcap_vm/Run-DualPcapTests.ps1').read_text(
            encoding='utf-8')
        helper = (ROOT / 'test/dual_pcap_vm/Invoke-PythonLogged.ps1').read_text(
            encoding='utf-8')
        fakenet = (ROOT / 'fakenet/fakenet.py').read_text(encoding='utf-8')

        self.assertIn('Invoke-PythonLogged.ps1', runner)
        self.assertIn('function Invoke-PythonLogged', helper)
        self.assertIn("$ErrorActionPreference = 'Continue'", helper)
        self.assertNotRegex(
            runner,
            re.compile(r'&\s+\$script:PythonExe[^\r\n]*\*>\&1\s*\|'))
        self.assertIn('print(r"""', fakenet)

    def test_runner_bootstrap_handles_unicode_paths_and_early_exit(self):
        runner = (ROOT / 'test/dual_pcap_vm/Run-DualPcapTests.ps1').read_text(
            encoding='utf-8')

        self.assertIn('$env:PYTHONPATH = $script:RepoRoot', runner)
        self.assertIn("'fakenet_path': fakenet.__file__", runner)
        self.assertIn("'utf8_mode': sys.flags.utf8_mode", runner)
        self.assertGreaterEqual(runner.count('-X utf8'), 2)
        self.assertNotIn('[Text.UTF8Encoding]::new($true)', runner)
        self.assertRegex(
            runner,
            re.compile(
                r'if \(\$process\.HasExited\) \{\s*'
                r'\$process\.WaitForExit\(\)\s*\$process\.Refresh\(\)',
                re.MULTILINE))


if __name__ == '__main__':
    unittest.main()
