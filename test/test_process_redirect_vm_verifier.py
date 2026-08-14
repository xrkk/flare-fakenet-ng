import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'verify_process_redirect', ROOT / 'test' / 'process_redirect_vm' /
    'verify_process_redirect.py')
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def write_evidence(path, role, count, failures, peer='110.242.69.21:443',
                   elapsed_ms=1000):
    rows = [{'event': 'identity', 'role': role, 'pid': 123,
             'final_path': r'\\?\C:\reviewed.exe'}]
    for index in range(count):
        success = index >= failures
        rows.append({'event': 'connection', 'role': role, 'index': index,
                     'success': success, 'peer': peer if success else '',
                     'nonce': f'test-{index}',
                     'failure_stage': '' if success else 'connect',
                     'winsock_error': 0 if success else 10060})
    rows.append({'event': 'summary', 'role': role, 'connections': count,
                 'failures': failures, 'elapsed_ms': elapsed_ms})
    path.write_text('\n'.join(json.dumps(row) for row in rows) + '\n',
                    encoding='utf-8')


class ProcessRedirectVmVerifierTests(unittest.TestCase):
    def test_rejects_runtime_route_suspension_and_packet_handler_exception(self):
        base = '\n'.join((
            'PROCESS_REDIRECT_READY',
            'PROCESS_REDIRECT_WINDIVERT_BASELINE',
            'PROCESS_REDIRECT_QUIESCENCE_OK',
            'PROCESS_REDIRECT_AUDIT_SUMMARY',
        ))
        self.assertEqual([], VERIFIER.validate_runtime_log(base))
        for evidence in (
                'PROCESS_REDIRECT_SUSPEND reason=route_query_timeout',
                'PROCESS_REDIRECT_RESUME reason=full_snapshot_revalidated',
                'PROCESS_REDIRECT_DENY reason=route_query_timeout',
                'PROCESS_REDIRECT_DENY reason=route_query_failed',
                'PROCESS_REDIRECT_DENY reason=route_snapshot_changed',
                'DROP_EXTERNAL reason=policy_exception',
                'Traceback (most recent call last):',
                'UnicodeDecodeError: invalid start byte'):
            with self.subTest(evidence=evidence):
                with self.assertRaisesRegex(ValueError, 'unexpected'):
                    VERIFIER.validate_runtime_log(base + '\n' + evidence)

    def test_accepts_complete_owner_and_mixed_burst_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = pathlib.Path(directory) / 'owner.jsonl'
            burst = pathlib.Path(directory) / 'burst.jsonl'
            write_evidence(owner, 'target', 10000, 0, elapsed_ms=500000)
            write_evidence(burst, 'target', 64, 48)
            self.assertEqual(
                {'connections': 10000, 'successes': 10000, 'failures': 0},
                VERIFIER.validate_client_log(
                    owner, 'target', 10000, '110.242.69.21:443', 0, 399960))
            self.assertEqual(48, VERIFIER.validate_client_log(
                burst, 'target', 64, '110.242.69.21:443',
                'budget_pressure')['failures'])

    def test_rejects_incomplete_owner_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = pathlib.Path(directory) / 'owner.jsonl'
            write_evidence(owner, 'target', 9999, 0)
            with self.assertRaisesRegex(ValueError, 'unexpected event rows'):
                VERIFIER.validate_client_log(
                    owner, 'target', 10000, '110.242.69.21:443', 0)

    def test_accepts_burst_that_recovers_after_initial_budget_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            burst = pathlib.Path(directory) / 'burst.jsonl'
            write_evidence(burst, 'target', 64, 0)
            self.assertEqual(64, VERIFIER.validate_client_log(
                burst, 'target', 64, '110.242.69.21:443',
                'budget_pressure')['successes'])

    def test_rejects_burst_without_any_success(self):
        with tempfile.TemporaryDirectory() as directory:
            burst = pathlib.Path(directory) / 'burst.jsonl'
            write_evidence(burst, 'target', 64, 64)
            with self.assertRaisesRegex(ValueError, 'no successful'):
                VERIFIER.validate_client_log(
                    burst, 'target', 64, '110.242.69.21:443',
                    'budget_pressure')

    def test_accepts_semantic_failure_with_zero_winsock_error(self):
        with tempfile.TemporaryDirectory() as directory:
            negative = pathlib.Path(directory) / 'negative.jsonl'
            write_evidence(negative, 'non-target', 1, 1)
            rows = VERIFIER.read_jsonl(negative)
            rows[1]['failure_stage'] = 'recv_eof'
            rows[1]['winsock_error'] = 0
            negative.write_text(
                '\n'.join(json.dumps(row) for row in rows) + '\n',
                encoding='utf-8')
            self.assertEqual(1, VERIFIER.validate_client_log(
                negative, 'non-target', 1, '110.242.69.21:443', 1)[
                    'failures'])

    def test_rejects_owner_evidence_that_exceeds_the_reviewed_start_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = pathlib.Path(directory) / 'owner.jsonl'
            write_evidence(owner, 'target', 10000, 0, elapsed_ms=399959)
            with self.assertRaisesRegex(ValueError, 'invalid summary'):
                VERIFIER.validate_client_log(
                    owner, 'target', 10000, '110.242.69.21:443', 0, 399960)


if __name__ == '__main__':
    unittest.main()
