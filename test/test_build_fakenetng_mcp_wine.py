# Copyright 2026 Google LLC
"""Gate-side unit tests for the Windows build gate's skip ledger.

Covers the R03 contract: every observed skip must be explained by the
finite node-granularity allowlist, unknown skips (from a known module or
not) fail the gate, and failures/errors still fail it.
"""
import importlib.util
import sys
import unittest
from pathlib import Path
import xml.etree.ElementTree as ElementTree

BUILDER = Path(__file__).resolve().parents[1] / 'tools' / 'build_fakenetng_mcp_wine.py'
_spec = importlib.util.spec_from_file_location('build_fakenetng_mcp_wine', BUILDER)
gate = importlib.util.module_from_spec(_spec)
sys.modules['build_fakenetng_mcp_wine'] = gate
_spec.loader.exec_module(gate)


def junit_xml(cases):
    """cases: list of (classname, name, outcome) with outcome in
    pass/failure/error/skip plus optional message."""
    parts = ['<testsuite>']
    for entry in cases:
        classname, name, outcome = entry[0], entry[1], entry[2]
        message = entry[3] if len(entry) > 3 else 'x'
        parts.append('<testcase classname="%s" name="%s">' % (classname, name))
        if outcome == 'failure':
            parts.append('<failure message="boom"/>')
        elif outcome == 'error':
            parts.append('<error message="setup died"/>')
        elif outcome == 'skip':
            parts.append('<skipped message="%s"/>' % message)
        parts.append('</testcase>')
    parts.append('</testsuite>')
    return ElementTree.fromstring(''.join(parts))


class SkipLedgerTests(unittest.TestCase):
    def test_known_skips_are_explained_with_full_ledger(self):
        root = junit_xml([
            ('test.mcp.test_singleinstance', 'test_second_acquire_fails',
             'skip', 'posix flock path tested here'),
            ('test.mcp.test_build_identity', 'test_symlinked_manifest_refused',
             'skip', 'symlink creation unavailable'),
            ('test.mcp.test_anything', 'test_plain_pass', 'pass'),
        ])
        summary = gate.evaluate_gate_group('main', root)
        self.assertEqual(0, summary['failures'])
        self.assertEqual(2, len(summary['skips']))
        ledger = {item['nodeid']: item for item in summary['skips']}
        self.assertIn('native Windows qualification pending',
                      ledger['test.mcp.test_singleinstance::'
                             'test_second_acquire_fails']['allowlist_reason'])
        self.assertEqual(
            'symlink creation unavailable in Wine (native Windows gap)',
            ledger['test.mcp.test_build_identity::'
                   'test_symlinked_manifest_refused']['allowlist_reason'])

    def test_unknown_module_skip_is_rejected(self):
        root = junit_xml([
            ('test.mcp.test_mystery_module', 'test_new_case',
             'skip', 'whatever'),
        ])
        with self.assertRaises(RuntimeError) as caught:
            gate.evaluate_gate_group('main', root)
        self.assertIn('test_mystery_module::test_new_case', str(caught.exception))

    def test_unknown_case_inside_known_module_is_rejected(self):
        # A new skip inside an allowlisted module must not inherit the
        # module's permission; only exact nodeids are allowed.
        root = junit_xml([
            ('test.mcp.test_singleinstance', 'test_brand_new_case',
             'skip', 'posix flock path tested here'),
        ])
        with self.assertRaises(RuntimeError) as caught:
            gate.evaluate_gate_group('main', root)
        self.assertIn('test_singleinstance::test_brand_new_case', str(caught.exception))

    def test_failures_and_errors_still_reject(self):
        for outcome in ('failure', 'error'):
            root = junit_xml([
                ('test.mcp.test_x', 'test_bad', outcome),
            ])
            with self.assertRaises(RuntimeError):
                gate.evaluate_gate_group('main', root)

    def test_allowlist_has_no_module_level_blanket_permission(self):
        for nodeid, reason in gate.WINE_ALLOWED_SKIPS.items():
            self.assertIn('::', nodeid, nodeid)
            self.assertTrue(reason.strip(), nodeid)
            self.assertNotEqual(reason.strip().lower(), 'todo', nodeid)


if __name__ == '__main__':
    unittest.main()
