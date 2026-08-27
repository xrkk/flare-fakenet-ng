from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

RUNTIME_OUTPUT_FILES = (
    'Start-EgressControl.ps1',
    'Start-FNPR-Sentinel.ps1',
    'Start-FNPR-Sentinel.sh',
    'Start-ReviewedIPv4.ps1',
    'test/dual_pcap_linux/run_tests.py',
    'test/process_redirect_vm/Run-ProcessRedirectTests.ps1',
    'test/process_redirect_vm/Run-Tests.cmd',
    'tools/replay_sample_payload.py',
)


def test_runtime_output_does_not_target_distribution_directory():
    forbidden = ('dist' + '/logs', 'dist' + '/样本实测')
    for relative in RUNTIME_OUTPUT_FILES:
        source = (ROOT / relative).read_text(encoding='utf-8').replace('\\', '/')
        lowered = source.lower()
        for marker in forbidden:
            assert marker not in lowered, '%s still targets %s' % (relative, marker)


def test_runtime_evidence_directory_is_gitignored():
    rules = (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()
    assert 'Logs/' in rules
