# Copyright 2026 Google LLC
"""Gate-side unit tests for the Windows build gate's skip ledger.

Covers the R03 contract: every observed skip must be explained by the
finite node-granularity allowlist, unknown skips (from a known module or
not) fail the gate, and failures/errors still fail it.
"""
import importlib.util
import sys
import unittest
import tempfile
import json
from unittest.mock import patch
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


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name).resolve()
        self.commit = 'a' * 40
        self.image = 'sha256:' + 'b' * 64
        for name in ('test/mcp/test_config.py', 'test/mcp/test_other.py',
                     'test/mcp/test_formal_runtime_context.py',
                     'test/test_http_listener_stop.py', 'test/test_build_fakenetng_mcp_wine.py'):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('')
        self.receipts = []
        for index in range(2):
            selections = {'main': gate.gate_selection(self.repo, 'core', (index, 2))}
            if index == 0:
                selections.update(http=list(gate.HTTP_CONFLICT_TESTS), sentinel=list(gate.WINDOWS_SENTINELS))
            self.receipts.append(self.receipt('shard-%d' % index, selections, (index, 2)))
        self.host = self.receipt('host', {'host': gate.gate_selection(self.repo, 'core', host=True)}, None, True)

    def receipt(self, directory, selections, shard, host=False):
        validation = self.repo / directory
        validation.mkdir()
        groups = {}
        for name, selection in selections.items():
            nodes = [item if '::' in item else item + '::test_actual' for item in selection]
            root = ElementTree.Element('testsuite')
            for node in nodes:
                classname, case = gate.junit_node(node).split('::')
                ElementTree.SubElement(root, 'testcase', classname=classname, name=case)
            xml = validation / (name + '.xml')
            ElementTree.ElementTree(root).write(xml)
            collection = validation / (name + '-collection.txt')
            collection.write_text('\n'.join(nodes))
            log = validation / (name + '.txt')
            log.write_text('actual command output')
            groups[name] = dict(selection=selection, nodes=sorted(map(gate.junit_node, nodes)),
                                summary=gate.evaluate_gate_group(name, root), seconds=1,
                                xml_path=xml, collection_path=collection, log_path=log)
        return gate.write_receipt(self.repo, self.repo, validation, self.commit, self.image,
                                  'core', shard, groups, host)

    def qualification(self, receipts=None, host=True):
        return gate.qualify(self.repo, self.repo, self.commit, self.image, 'core', 2,
                            self.receipts if receipts is None else receipts, self.host if host else None)

    def test_complete_evidence_can_package_only_with_exact_pin(self):
        credential = self.qualification()
        self.assertEqual('PARTIAL', credential['verdict'])
        self.assertEqual('PASS', credential['build_gate'])
        path = self.repo / 'qualification.json'
        path.write_text(json.dumps(credential))
        self.assertEqual(credential, gate.validate_qualification(
            self.repo, self.repo, self.commit, self.image, 'core', path, gate.sha256(path)))
        with self.assertRaises(RuntimeError):
            gate.validate_qualification(self.repo, self.repo, self.commit, self.image, 'core', path, '0' * 64)

    def test_missing_duplicate_and_absent_host_receipts_refused(self):
        for receipts in (self.receipts[:1], [self.receipts[0]] * 2):
            with self.assertRaises(RuntimeError):
                self.qualification(receipts)
        with self.assertRaises(RuntimeError):
            self.qualification(host=False)

    def test_changed_identity_selection_and_missing_group_refused(self):
        path = self.receipts[0]
        original = json.loads(path.read_text())
        for field, value in (('source_commit', 'c' * 40), ('builder_image_id', 'sha256:wrong'),
                             ('layer', 'full'), ('shard', [1, 2])):
            altered = dict(original, **{field: value})
            path.write_text(json.dumps(altered))
            with self.assertRaises(RuntimeError):
                self.qualification()
        for mutation in ('selection', 'group'):
            altered = json.loads(json.dumps(original))
            if mutation == 'selection':
                altered['groups']['main']['selection'] = ['test/mcp/test_config.py']
            else:
                del altered['groups']['http']
            path.write_text(json.dumps(altered))
            with self.assertRaises(RuntimeError):
                self.qualification()

    def test_result_tampering_failure_unknown_skip_and_duplicate_refused(self):
        path = self.receipts[0]
        original = path.read_text()
        original_xml = (self.repo / json.loads(original)['groups']['main']['xml']['path']).read_bytes()
        for outcome in ('failure', 'skipped', 'duplicate', 'missing'):
            receipt = json.loads(original)
            entry = receipt['groups']['main']
            xml = self.repo / entry['xml']['path']
            xml.write_bytes(original_xml)
            root = ElementTree.parse(xml).getroot()
            case = next(root.iter('testcase'))
            if outcome == 'duplicate':
                root.append(ElementTree.fromstring(ElementTree.tostring(case)))
            elif outcome == 'missing':
                root.remove(case)
            else:
                ElementTree.SubElement(case, outcome, message='unknown skip')
            ElementTree.ElementTree(root).write(xml)
            entry['xml'] = gate.evidence_record(self.repo, xml)
            path.write_text(json.dumps(receipt))
            expected = 'rejected_skips' if outcome == 'skipped' else (
                'gate failed' if outcome == 'failure' else 'testcase coverage')
            with self.assertRaisesRegex(RuntimeError, expected):
                self.qualification()

    def test_nonsharded_core_selection_reaches_actual_gate(self):
        wheel = self.repo / 'wheelhouse' / gate.PYDIVERT_WHEEL
        wheel.parent.mkdir()
        import zipfile
        with zipfile.ZipFile(wheel, 'w'):
            pass
        build_root = self.repo / 'build'
        build_root.mkdir()
        with patch.object(gate, 'wine_path', side_effect=str), \
                patch.object(gate, 'collect_and_run', return_value={'summary': {}}) as execute, \
                patch.object(gate, 'write_receipt', return_value=self.receipts[0]):
            gate.run_windows_test_gate(self.repo, build_root, layer='core', repo=self.repo,
                                        resolved=self.commit, image_id=self.image)
        main_selection = execute.call_args_list[0].args[3]
        self.assertTrue(main_selection)
        self.assertFalse(any('test_formal_runtime_' in name for name in main_selection))
        self.assertEqual(list(gate.WINDOWS_SENTINELS), execute.call_args_list[2].args[3])

    def test_host_only_never_creates_distributable_output(self):
        import zipfile

        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                bundle.writestr('test/mcp/test_formal_runtime_context.py', '')

        output = self.repo / 'must-not-create-dist'
        with patch.object(gate, 'captured', return_value=self.commit), \
                patch.object(gate, 'run', side_effect=archive), \
                patch.object(gate, 'verify_source'), \
                patch.object(gate, 'collect_and_run', return_value={}), \
                patch.object(gate, 'write_receipt', return_value=self.host), \
                patch.object(gate, 'offline_install_sdk') as install:
            result = gate.build(self.repo, self.commit, output, host_only=True,
                                layer='core', image_id=self.image)
        self.assertEqual(self.host, result)
        self.assertFalse(output.exists())
        install.assert_not_called()
