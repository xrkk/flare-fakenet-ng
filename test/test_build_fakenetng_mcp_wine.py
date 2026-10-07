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
            ('test.mcp.test_formal_runtime_batch_audit',
             'test_streamed_inventory_refuses_symlinks_and_seal_requires_actual_execution',
             'skip', 'symlink creation unavailable'),
            ('test.mcp.test_anything', 'test_plain_pass', 'pass'),
        ])
        summary = gate.evaluate_gate_group('main', root)
        self.assertEqual(0, summary['failures'])
        self.assertEqual(3, len(summary['skips']))
        ledger = {item['nodeid']: item for item in summary['skips']}
        self.assertEqual(
            'posix flock path tested here',
            ledger['test.mcp.test_singleinstance::'
                   'test_second_acquire_fails']['allowlist_reason'])
        self.assertEqual(
            'symlink creation unavailable',
            ledger['test.mcp.test_build_identity::'
                   'test_symlinked_manifest_refused']['allowlist_reason'])

    def test_known_node_with_unknown_reason_is_rejected(self):
        root = junit_xml([
            ('test.mcp.test_build_identity', 'test_symlinked_manifest_refused',
             'skip', 'required dependency BROKEN'),
        ])
        with self.assertRaises(RuntimeError) as caught:
            gate.evaluate_gate_group('main', root)
        self.assertIn('rejected_skips', str(caught.exception))
        self.assertIn('required dependency BROKEN', str(caught.exception))

    def test_known_node_with_empty_reason_is_rejected(self):
        root = junit_xml([
            ('test.mcp.test_singleinstance', 'test_second_acquire_fails',
             'skip', ''),
        ])
        with self.assertRaises(RuntimeError):
            gate.evaluate_gate_group('main', root)

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


class ShardLayerTests(unittest.TestCase):
    def test_core_layer_excludes_formal_runtime_family(self):
        files = ['test/mcp/test_config.py',
                 'test/mcp/test_formal_runtime_audit.py',
                 'test/test_gui_configmodel.py',
                 'test/mcp/test_formal_runtime_z.py']
        core = [f for f in files
                if not Path(f).name.startswith(gate.FORMAL_RUNTIME_PREFIX)]
        self.assertEqual(['test/mcp/test_config.py',
                          'test/test_gui_configmodel.py'], core)

    def test_shards_partition_without_overlap(self):
        files = ['f%d.py' % i for i in range(10)]
        parts = [gate.shard_files(files, i, 4) for i in range(4)]
        self.assertEqual(sorted(files), sorted(f for p in parts for f in p))
        for a in range(4):
            for b in range(a + 1, 4):
                self.assertFalse(set(parts[a]) & set(parts[b]))

    def test_merge_gate_xml_keeps_cases_and_verdict(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            for name, cls in (('windows-pytest-main-shard-0.xml', 'm.test_a'),
                              ('windows-pytest-main-shard-1.xml', 'm.test_b'),
                              ('windows-pytest-http.xml', 'h.test_http')):
                Path(tmp, name).write_text(
                    '<testsuite><testcase classname="%s" name="t" /></testsuite>' % cls)
            main, http = gate.merge_gate_xml(
                sorted(Path(tmp).glob('windows-pytest-main-shard-*.xml')) +
                sorted(Path(tmp).glob('windows-pytest-http.xml')))
            self.assertEqual(2, len(list(main.iter('testcase'))))
            self.assertEqual(1, len(list(http.iter('testcase'))))
            # a merged skip ledger still evaluates normally
            known = [('test.mcp.test_singleinstance', 'test_second_acquire_fails',
                      'posix flock path tested here'),
                     ('test.mcp.test_singleinstance', 'test_guard_holds_both_locks',
                      'posix flock path tested here')]
            for case, (cls, name, message) in zip(main.iter('testcase'), known):
                case.set('classname', cls); case.set('name', name)
                case.append(ElementTree.Element('skipped'))
                case.find('skipped').set('message', message)
            summary = gate.evaluate_gate_group('main', main)
            self.assertEqual(2, len(summary['skips']))
