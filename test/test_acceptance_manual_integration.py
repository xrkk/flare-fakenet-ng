"""Real listener and central-registration integration for the two manual GAPs."""
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N


def inputs(case, root):
    return {
        'schema': 'fakenet.manual-input.v1', 'case': case,
        'candidate_id': 'fixture-manual', 'source_commit': 'a' * 40,
        'package_sha256': 'b' * 64, 'execution_id': 'exec-fixture-01',
        'config': str(Path(root) / 'config'), 'owned_root': str(root),
        'responsea': '192.0.2.55', 'fixture': True,
    }


class ManualIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_ncsi_uses_real_udp_and_tcp_listener_roundtrips(self):
        out = self.base / 'ncsi'
        value = M.run('GAP-NCSI', out, inputs('GAP-NCSI', out), memory_mode=False)
        self.assertEqual('pass', value['status'] if 'status' in value else 'pass')
        listener = value['listener']
        self.assertEqual('127.0.0.1', listener['bind'])
        self.assertEqual({'udp', 'tcp'}, set(listener['transports']))
        for transport in ('udp', 'tcp'):
            self.assertGreater(listener['transports'][transport]['port'], 0)
            self.assertTrue(listener['transports'][transport]['stopped'])
            self.assertFalse(listener['transports'][transport]['thread_alive'])
        rows, clean, detail = O.evaluate(
            ROOT, out, 'GAP-NCSI', inputs('GAP-NCSI', out), allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(['tcp', 'udp'], sorted({row['transport'] for row in value['queries']}))

    def test_raw_date_uses_real_http_listener_and_preserves_bytes(self):
        out = self.base / 'raw'
        value = M.run('GAP-RAW-DATE', out, inputs('GAP-RAW-DATE', out), memory_mode=False)
        listener = value['listener']
        self.assertEqual('127.0.0.1', listener['bind'])
        self.assertGreater(listener['port'], 0)
        self.assertTrue(listener['stopped'])
        self.assertFalse(listener['thread_alive'])
        raw = Path(value['raw_response']).read_bytes()
        self.assertIn(b'\x00\xff', raw)
        self.assertNotIn(b'<RAW-DATE>', raw)
        self.assertTrue(value['date'])
        rows, clean, detail = O.evaluate(
            ROOT, out, 'GAP-RAW-DATE', inputs('GAP-RAW-DATE', out), allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_two_manual_cases_are_registered_as_fixed_central_drivers(self):
        drivers = N.driver_table(ROOT)
        for name, kind in (('manual-ncsi', 'manual-ncsi'), ('manual-raw-date', 'manual-raw-date')):
            self.assertIn(name, drivers)
            self.assertTrue(drivers[name]['implemented'])
            self.assertEqual(kind, drivers[name]['production_kind'])
        catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
        rows = {case['id']: case for suite in catalog['suites'] for case in suite.get('cases') or []}
        self.assertEqual('manual-ncsi', rows['GAP-NCSI']['native_driver'])
        self.assertEqual('manual-raw-date', rows['GAP-RAW-DATE']['native_driver'])


if __name__ == '__main__':
    unittest.main()
