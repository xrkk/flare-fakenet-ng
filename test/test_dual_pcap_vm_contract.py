import pathlib
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
        self.assertIn('$packageVersion = \'v1\'', builder)
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


if __name__ == '__main__':
    unittest.main()
