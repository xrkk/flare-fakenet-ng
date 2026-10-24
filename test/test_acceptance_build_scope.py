"""Pure file/mocked-boundary tests for the bounded regression build layer."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('regression_build_gate', ROOT / 'tools/build_fakenetng_mcp_wine.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class RegressionBuildScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.commit, self.image = 'a' * 40, 'sha256:' + 'b' * 64
        self.catalog = {'schema': 'fakenet.acceptance-catalog.v2', 'suites': [
            {'id': 'CORE', 'cases': [
                self.case('WINDOWS', ['test/test_a.py', 'test/test_b.py']),
                self.case('HOST', ['test/test_linuxnetpolicy.py']),
                self.case('SHARED', ['test/test_a.py']),
                self.case('UNSAFE', ['test/test_unsafe.py'], collection_safe=False),
                dict(self.case('NATIVE', ['test/test_a.py']), adapter='native'),
                dict(self.case('EXCLUDED', ['test/test_gui_smoke.py']), excluded=True),
                dict(self.case('STRESS', ['test/test_stress.py']), stress=True),
            ]}]}
        for name in ('test/test_a.py', 'test/test_b.py', 'test/test_linuxnetpolicy.py',
                     'test/test_unsafe.py', 'test/test_gui_smoke.py', 'test/test_stress.py',
                     'test/mcp/test_formal_runtime_audit.py', 'test/test_unregistered.py'):
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('raise AssertionError("selection must never import me")\n')
        self.write_catalog()

    def case(self, name, modules, **values):
        return dict({'id': name, 'suite_id': 'CORE', 'required_for_full': True,
                     'adapter': 'offline-pytest', 'collection_safe': True,
                     'platforms': ['any'], 'input': {'modules': modules}}, **values)

    def write_catalog(self):
        path = self.root / 'docs/acceptance/catalog.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.catalog))

    def receipt(self, name, host=False, shard=None):
        directory = self.root / name
        directory.mkdir()
        if host:
            selection = gate.gate_selection(self.root, 'regression', host=True)
            selections = {'host': selection} if selection else {}
        else:
            selections = gate.windows_gate_groups(self.root, 'regression', shard)
        groups = {}
        for label, selection in selections.items():
            raw_nodes = [module + '::test_original' for module in selection]
            nodes = sorted(gate.junit_node(node) for node in raw_nodes)
            xml = ET.Element('testsuite')
            for node in nodes:
                classname, testname = node.split('::')
                ET.SubElement(xml, 'testcase', classname=classname, name=testname)
            xml_path = directory / (label + '.xml')
            ET.ElementTree(xml).write(xml_path)
            collection = directory / (label + '-collection.txt')
            collection.write_text('\n'.join(raw_nodes))
            log = directory / (label + '.log')
            log.write_text('fixture original execution log\n')
            groups[label] = {'selection': selection, 'nodes': nodes,
                             'summary': gate.evaluate_gate_group(label, xml), 'seconds': 1,
                             'xml_path': xml_path, 'collection_path': collection, 'log_path': log}
        return gate.write_receipt(self.root, self.root, directory, self.commit,
                                  self.image, 'regression', shard, groups, host)

    def originals(self):
        receipts = [self.receipt('shard%d' % i, shard=(i, 2)) for i in range(2)]
        host = self.receipt('host', host=True)
        return receipts, host

    def qualify(self, receipts, host):
        return gate.qualify(self.root, self.root, self.commit, self.image,
                            'regression', 2, receipts, host)

    def rewrite(self, path, value):
        path.write_text(json.dumps(value))

    def test_registered_inputs_only_no_imports_and_dedup_shared_helper(self):
        self.catalog['suites'][0]['cases'][0]['sources'] = ['test/gui_vm/verify_payload_integrity.py']
        self.write_catalog()
        with mock.patch.object(Path, 'rglob', side_effect=AssertionError('tree scan')):
            scope = gate.regression_scope(self.root)
        self.assertEqual(['test/test_a.py', 'test/test_b.py'], scope['windows'])
        self.assertEqual(['test/test_linuxnetpolicy.py'], scope['host'])
        self.assertEqual({'UNSAFE', 'NATIVE'}, {row['case_id'] for row in scope['unverified']})
        self.assertEqual(5, len(scope['required_case_ids']))
        self.assertFalse(scope['full_functional_pass'])
        self.assertNotIn('EXCLUDED', scope['required_case_ids'])
        self.assertNotIn('test/gui_vm/verify_payload_integrity.py', scope['test_source_hashes'])
        self.assertEqual(scope, gate.regression_scope(self.root))

    def test_actual_catalog_keeps_all_required_and_names_unverified(self):
        # Metadata only: the real catalog and test bytes are never imported.
        catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
        scope = gate.regression_scope(ROOT)
        required = {case['id'] for suite in catalog['suites'] for case in suite['cases']
                    if case.get('required_for_full', True) and not case.get('excluded')
                    and not case.get('stress')}
        self.assertEqual(required, set(scope['required_case_ids']))
        self.assertEqual(62, len(required))
        import os
        if os.environ.get('FN_BUILD_CHECK_OUTPUT'):
            (Path(os.environ['FN_BUILD_CHECK_OUTPUT']) / 'actual-regression-scope.json').write_text(
                json.dumps(scope, indent=2) + '\n')
        self.assertTrue(any(row['reason'] == 'collection not approved safe'
                            for row in scope['unverified']))
        self.assertFalse(any('test_gui_' in name or 'test_formal_runtime_' in name
                             for name in scope['windows'] + scope['host']))

    def test_invalid_registry_paths_schema_and_duplicate_inputs_refused(self):
        original = copy.deepcopy(self.catalog)
        for edit in (
                lambda c: c.update(schema='unknown'),
                lambda c: c['suites'].append(copy.deepcopy(c['suites'][0])),
                lambda c: c['suites'][0]['cases'].append(copy.deepcopy(c['suites'][0]['cases'][0])),
                lambda c: c['suites'][0]['cases'][0].update(collection_safe='true'),
                lambda c: c['suites'][0]['cases'][0].update(platforms=['unknown']),
                lambda c: c['suites'][0]['cases'][0]['input'].update(module='test/test_a.py'),
                lambda c: c['suites'][0]['cases'][0]['input'].update(shell='unregistered'),
                lambda c: c['suites'][0]['cases'][0]['input'].update(modules=['../escape.py']),
                lambda c: c['suites'][0]['cases'][0]['input'].update(modules=['test/test_missing.py']),
                lambda c: c['suites'][0]['cases'][0]['input'].update(modules=['test/test_a.py'] * 2),
                lambda c: c['suites'][0]['cases'][0]['input'].update(modules=['test/test_gui_smoke.py']),
                lambda c: c['suites'][0]['cases'][0]['input'].update(modules=['test/mcp/test_formal_runtime_audit.py'])):
            with self.subTest(edit=edit):
                self.catalog = copy.deepcopy(original)
                edit(self.catalog)
                self.write_catalog()
                with self.assertRaises((RuntimeError, ValueError)):
                    gate.regression_scope(self.root)

    def test_linked_module_and_catalog_are_refused(self):
        linked = self.root / 'test/test_a.py'
        linked.unlink()
        linked.symlink_to(self.root / 'test/test_b.py')
        with self.assertRaisesRegex(RuntimeError, 'linked'):
            gate.regression_scope(self.root)
        linked.unlink()
        linked.write_text('')
        catalog = self.root / 'docs/acceptance/catalog.json'
        target = catalog.with_name('original.json')
        catalog.rename(target)
        catalog.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'regular'):
            gate.regression_scope(self.root)

    def test_linux_only_applicability_and_unsafe_remain_explicit(self):
        self.catalog['suites'][0]['cases'][1]['platforms'] = ['windows']
        self.catalog['suites'][0]['cases'][2]['platforms'] = ['linux']
        self.write_catalog()
        scope = gate.regression_scope(self.root)
        self.assertEqual(['test/test_a.py'], scope['host'])
        self.assertTrue(any(row['reason'] == 'not applicable to linux gate'
                            for row in scope['unverified']))

    def test_shards_are_exact_partition_and_empty_shard_refuses(self):
        parts = [gate.gate_selection(self.root, 'regression', (i, 2)) for i in range(2)]
        self.assertEqual(gate.gate_selection(self.root, 'regression'), sorted(sum(parts, [])))
        self.assertFalse(set(parts[0]) & set(parts[1]))
        with self.assertRaisesRegex(RuntimeError, 'Empty gate shard'):
            gate.windows_gate_groups(self.root, 'regression', (2, 3))

    def test_actual_windows_gate_uses_scope_without_legacy_extras(self):
        wheel = self.root / 'wheelhouse' / gate.PYDIVERT_WHEEL
        wheel.parent.mkdir()
        with zipfile.ZipFile(wheel, 'w'):
            pass
        output = self.root / 'gate'
        output.mkdir()
        with mock.patch.object(gate, 'wine_path', side_effect=str), \
                mock.patch.object(gate, 'collect_and_run', return_value={'summary': {}}) as collect, \
                mock.patch.object(gate, 'write_receipt', return_value=wheel):
            result = gate.run_windows_test_gate(self.root, output, layer='regression',
                                                repo=self.root, resolved=self.commit, image_id=self.image)
        self.assertEqual(1, collect.call_count)
        self.assertEqual('main', collect.call_args.args[2])
        self.assertEqual(gate.regression_scope(self.root)['windows'], collect.call_args.args[3])
        self.assertEqual(gate.regression_scope(self.root), result['regression_scope'])

    def test_credential_roundtrip_rejudges_originals_and_stays_partial(self):
        receipts, host = self.originals()
        credential = self.qualify(receipts, host)
        self.assertEqual('PASS', credential['build_gate'])
        self.assertEqual('PARTIAL', credential['verdict'])
        self.assertFalse(credential['regression_scope']['full_functional_pass'])
        path = self.root / 'qualification.json'
        self.rewrite(path, credential)
        self.assertEqual(credential, gate.validate_qualification(self.root, self.root,
            self.commit, self.image, 'regression', path, gate.sha256(path)))
        for layer in ('core', 'full'):
            with self.subTest(layer=layer), self.assertRaises(RuntimeError):
                gate.validate_qualification(self.root, self.root, self.commit, self.image,
                                             layer, path, gate.sha256(path))
        with self.assertRaises(RuntimeError):
            gate.validate_qualification(self.root, self.root, self.commit, self.image,
                                         'regression', path, '0' * 64)

    def test_missing_duplicate_wrong_shard_and_host_refused(self):
        receipts, host = self.originals()
        for selected, host_path in ((receipts[:1], host), ([receipts[0]] * 2, host), (receipts, None)):
            with self.subTest(selected=selected, host=host_path), self.assertRaises(RuntimeError):
                self.qualify(selected, host_path)
        value = json.loads(receipts[1].read_text())
        value['shard'] = [0, 2]
        self.rewrite(receipts[1], value)
        with self.assertRaisesRegex(RuntimeError, 'Duplicate shard'):
            self.qualify(receipts, host)

    def test_source_image_scope_catalog_and_module_drift_refused(self):
        receipts, host = self.originals()
        original = json.loads(receipts[0].read_text())
        for key, value in (('source_commit', 'c' * 40), ('builder_image_id', 'sha256:' + 'c' * 64),
                           ('layer', 'core'), ('regression_scope', {})):
            changed = copy.deepcopy(original)
            changed[key] = value
            self.rewrite(receipts[0], changed)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.qualify(receipts, host)
        self.rewrite(receipts[0], original)
        (self.root / 'test/test_a.py').write_text('changed bytes')
        with self.assertRaisesRegex(RuntimeError, 'scope/source/catalog'):
            self.qualify(receipts, host)
        (self.root / 'test/test_a.py').write_text('raise AssertionError("selection must never import me")\n')
        self.catalog['note'] = 'changed catalog with identical selection'
        self.write_catalog()
        with self.assertRaisesRegex(RuntimeError, 'scope/source/catalog'):
            self.qualify(receipts, host)

    def test_rehashed_bad_raw_xml_coverage_and_skip_refused(self):
        receipts, host = self.originals()
        receipt = json.loads(receipts[0].read_text())
        original_xml = (self.root / receipt['groups']['main']['xml']['path']).read_bytes()
        for problem in ('failure', 'error', 'unknown-skip', 'missing', 'extra', 'duplicate'):
            value = copy.deepcopy(receipt)
            entry = value['groups']['main']
            path = self.root / entry['xml']['path']
            tree = ET.fromstring(original_xml)
            case = tree.find('testcase')
            if problem == 'unknown-skip':
                ET.SubElement(case, 'skipped', message='invented')
            elif problem in ('failure', 'error'):
                ET.SubElement(case, problem)
            elif problem == 'missing':
                tree.remove(case)
            elif problem == 'extra':
                ET.SubElement(tree, 'testcase', classname='foreign', name='test_bad')
            else:
                tree.append(copy.deepcopy(case))
            ET.ElementTree(tree).write(path)
            entry['xml'] = gate.evidence_record(self.root, path)
            self.rewrite(receipts[0], value)
            with self.subTest(problem=problem), self.assertRaises(RuntimeError):
                self.qualify(receipts, host)
        # Restore raw XML but forge both selected paths and its scope hash.
        (self.root / receipt['groups']['main']['xml']['path']).write_bytes(original_xml)
        changed = copy.deepcopy(receipt)
        changed['regression_scope']['windows'].pop()
        changed['regression_scope']['scope_sha256'] = 'd' * 64
        self.rewrite(receipts[0], changed)
        with self.assertRaisesRegex(RuntimeError, 'scope/source/catalog'):
            self.qualify(receipts, host)

    def test_rehashed_bad_collection_log_selection_summary_and_credential_refused(self):
        receipts, host = self.originals()
        original = json.loads(receipts[0].read_text())
        for key in ('selection', 'summary', 'nodes'):
            value = copy.deepcopy(original)
            value['groups']['main'][key] = [] if key != 'summary' else {}
            self.rewrite(receipts[0], value)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.qualify(receipts, host)
        self.rewrite(receipts[0], original)
        path = self.root / original['groups']['main']['collection']['path']
        old = path.read_bytes()
        path.write_text('test/test_foreign.py::test_foreign\n')
        changed = copy.deepcopy(original)
        changed['groups']['main']['collection'] = gate.evidence_record(self.root, path)
        self.rewrite(receipts[0], changed)
        with self.assertRaises(RuntimeError):
            self.qualify(receipts, host)
        path.write_bytes(old)
        self.rewrite(receipts[0], original)
        credential = self.qualify(receipts, host)
        credential['regression_scope']['full_functional_pass'] = True
        out = self.root / 'forged-qualification.json'
        self.rewrite(out, credential)
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            gate.validate_qualification(self.root, self.root, self.commit, self.image,
                                         'regression', out, gate.sha256(out))
        # A missing raw log invalidates even a previously issued credential.
        (self.root / original['groups']['main']['log']['path']).unlink()
        with self.assertRaises(RuntimeError):
            self.qualify(receipts, host)

    def test_rehashed_matching_foreign_xml_and_collection_cannot_pass(self):
        receipts, host = self.originals()
        value = json.loads(receipts[0].read_text())
        entry = value['groups']['main']
        raw = 'test/test_unregistered.py::test_forged'
        canonical = gate.junit_node(raw)
        classname, name = canonical.split('::')
        xml = ET.Element('testsuite')
        ET.SubElement(xml, 'testcase', classname=classname, name=name)
        path = self.root / entry['xml']['path']
        ET.ElementTree(xml).write(path)
        collection = self.root / entry['collection']['path']
        collection.write_text(raw + '\n')
        entry.update(xml=gate.evidence_record(self.root, path),
                     collection=gate.evidence_record(self.root, collection),
                     nodes=[canonical], summary=gate.evaluate_gate_group('main', xml))
        self.rewrite(receipts[0], value)
        with self.assertRaisesRegex(RuntimeError, 'Foreign regression collection'):
            self.qualify(receipts, host)

    def test_matching_trimmed_collection_must_still_cover_every_module(self):
        receipt = self.receipt('serial')
        host = self.receipt('serial-host', host=True)
        value = json.loads(receipt.read_text())
        entry = value['groups']['main']
        raw = 'test/test_a.py::test_only_one_module'
        canonical = gate.junit_node(raw)
        classname, name = canonical.split('::')
        xml = ET.Element('testsuite')
        ET.SubElement(xml, 'testcase', classname=classname, name=name)
        path = self.root / entry['xml']['path']
        ET.ElementTree(xml).write(path)
        collection = self.root / entry['collection']['path']
        collection.write_text(raw + '\n')
        entry.update(xml=gate.evidence_record(self.root, path),
                     collection=gate.evidence_record(self.root, collection),
                     nodes=[canonical], summary=gate.evaluate_gate_group('main', xml))
        self.rewrite(receipt, value)
        with self.assertRaisesRegex(RuntimeError, 'misses selected module'):
            gate.qualify(self.root, self.root, self.commit, self.image,
                         'regression', 1, [receipt], host)

    def test_regression_host_build_reaches_exact_group_and_no_sdk(self):
        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                for path in self.root.rglob('*'):
                    if path.is_file() and not path.is_relative_to(self.root / 'Logs'):
                        bundle.write(path, path.relative_to(self.root).as_posix())
        with mock.patch.object(gate, 'captured', return_value=self.commit), \
                mock.patch.object(gate, 'run', side_effect=archive), \
                mock.patch.object(gate, 'verify_source'), \
                mock.patch.object(gate, 'offline_install_sdk') as install, \
                mock.patch.object(gate, 'collect_and_run', return_value={'summary': {}}) as collect, \
                mock.patch.object(gate, 'write_receipt', return_value=self.root / 'receipt.json'):
            gate.build(self.root, self.commit, self.root / 'unused-dist',
                       layer='regression', host_only=True, image_id=self.image)
        self.assertEqual(['test/test_linuxnetpolicy.py'], collect.call_args.args[3])
        self.assertFalse(collect.call_args.kwargs['windows'])
        install.assert_not_called()
        self.assertFalse((self.root / 'unused-dist').exists())

    def test_package_only_rejects_bad_original_before_sdk_install(self):
        receipts, host = self.originals()
        credential = self.qualify(receipts, host)
        credential['regression_scope']['full_functional_pass'] = True
        original = self.root / 'bad-qualification.json'
        self.rewrite(original, credential)
        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                for path in self.root.rglob('*'):
                    if path.is_file() and not path.is_relative_to(self.root / 'Logs'):
                        bundle.write(path, path.relative_to(self.root).as_posix())
        with mock.patch.object(gate, 'captured', return_value=self.commit), \
                mock.patch.object(gate, 'run', side_effect=archive), \
                mock.patch.object(gate, 'verify_source'), \
                mock.patch.object(gate, 'offline_install_sdk') as install:
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                gate.build(self.root, self.commit, self.root / 'unused-dist',
                           layer='regression', package_only=True, image_id=self.image,
                           qualification=original, qualification_sha256=gate.sha256(original))
        install.assert_not_called()
        self.assertFalse((self.root / 'unused-dist').exists())

    def test_valid_package_credential_reaches_sdk_boundary_after_rejudgment(self):
        receipts, host = self.originals()
        original = self.root / 'qualification.json'
        self.rewrite(original, self.qualify(receipts, host))
        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                for path in self.root.rglob('*'):
                    if path.is_file() and not path.is_relative_to(self.root / 'Logs'):
                        bundle.write(path, path.relative_to(self.root).as_posix())
        class SDKBoundary(Exception):
            pass
        with mock.patch.object(gate, 'captured', return_value=self.commit), \
                mock.patch.object(gate, 'run', side_effect=archive), \
                mock.patch.object(gate, 'verify_source'), \
                mock.patch.object(gate, 'validate_qualification', wraps=gate.validate_qualification) as validate, \
                mock.patch.object(gate, 'offline_install_sdk', side_effect=SDKBoundary) as install:
            with self.assertRaises(SDKBoundary):
                gate.build(self.root, self.commit, self.root / 'unused-dist',
                           layer='regression', package_only=True, image_id=self.image,
                           qualification=original, qualification_sha256=gate.sha256(original))
        validate.assert_called_once()
        install.assert_called_once()
        self.assertFalse((self.root / 'unused-dist').exists())

    def add_git_host(self):
        name = 'test/test_acceptance_package.py'
        (self.root / name).write_text('# fixture source; never imported\n')
        self.catalog['suites'][0]['cases'].append(self.case('GIT-HOST', [name]))
        self.write_catalog()
        return name

    def source_git(self, command):
        if '--show-toplevel' in command:
            return str(self.root)
        if 'status' in command:
            return ''
        return self.commit

    def test_actual_catalog_platform_map_keeps_union_and_explicit_reasons(self):
        scope = gate.regression_scope(ROOT)
        expected = {
            'test/test_acceptance_catalog.py', 'test/test_acceptance_mcp.py',
            'test/test_acceptance_native.py', 'test/test_acceptance_native_channels.py',
            'test/test_acceptance_native_oracles.py', 'test/test_acceptance_orchestration.py',
            'test/test_acceptance_package.py', 'test/test_acceptance_regression.py',
            'test/test_acceptance_scheduler.py', 'test/test_linuxnetpolicy.py',
            'test/test_linux_owner_rules.py'}
        self.assertEqual(expected, set(scope['host']))
        self.assertEqual(12, len(scope['windows']))
        self.assertEqual(23, len(set(scope['windows']) | set(scope['host'])))
        self.assertFalse(set(scope['windows']) & set(scope['host']))
        self.assertEqual(expected, set(scope['host_reasons']))
        self.assertTrue(all(scope['host_reasons'].values()))
        self.assertEqual(62, len(scope['required_case_ids']))
        self.assertEqual(12, len(scope['cases']))
        self.assertEqual(50, len(scope['unverified']))
        self.assertEqual(9, len(gate.REGRESSION_HOST_REASONS))
        self.assertIn('/proc', gate.REGRESSION_HOST_REASONS['test/test_acceptance_scheduler.py'])
        self.assertIn('Git', gate.REGRESSION_HOST_REASONS['test/test_acceptance_package.py'])

    def test_finite_host_map_does_not_sweep_similarly_named_registered_input(self):
        name = 'test/test_acceptance_unreviewed.py'
        (self.root / name).write_text('')
        self.catalog['suites'][0]['cases'].append(self.case('OTHER', [name]))
        self.write_catalog()
        scope = gate.regression_scope(self.root)
        self.assertIn(name, scope['windows'])
        self.assertNotIn(name, scope['host'])

    def test_real_host_consumer_uses_committed_worktree_and_records_identity(self):
        name = self.add_git_host()
        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                for path in self.root.rglob('*'):
                    if path.is_file() and not path.is_relative_to(self.root / 'Logs'):
                        bundle.write(path, path.relative_to(self.root).as_posix())
        def collect(stage, validation, group, selection, env, windows):
            self.assertEqual(self.root, stage)
            self.assertIn(name, selection)
            self.assertFalse(windows)
            xml = ET.Element('testsuite')
            ET.SubElement(xml, 'testcase', classname='fixture', name='unexecuted')
            files = {}
            for key in ('xml', 'collection', 'log'):
                path = validation / key
                path.write_text('fixture raw bytes')
                files[key + '_path'] = path
            return dict(files, selection=selection, nodes=[], summary={})
        with mock.patch.object(gate, 'captured', side_effect=self.source_git) as git, \
                mock.patch.object(gate, 'run', side_effect=archive), \
                mock.patch.object(gate, 'verify_source'), \
                mock.patch.object(gate, 'offline_install_sdk') as install, \
                mock.patch.object(gate, 'collect_and_run', side_effect=collect) as execute:
            receipt = gate.build(self.root, self.commit, self.root / 'unused-dist',
                                 layer='regression', host_only=True, image_id=self.image)
        execute.assert_called_once()
        install.assert_not_called()
        value = json.loads(receipt.read_text())
        self.assertEqual('committed-live-worktree', value['host_source']['mode'])
        self.assertEqual(str(self.root), value['host_source']['root'])
        self.assertEqual(self.commit, value['host_source']['source_commit'])
        self.assertEqual(value['regression_scope']['scope_sha256'],
                         value['host_source']['scope_sha256'])
        self.assertEqual(7, git.call_count)  # initial commit + before/after three reads
        self.assertFalse((self.root / 'unused-dist').exists())

    def test_wrong_top_head_dirty_or_immutable_source_refuses_host(self):
        self.add_git_host()
        for kind in ('top', 'head', 'dirty', 'scope'):
            def git(command):
                if '--show-toplevel' in command:
                    return str(self.root / 'foreign') if kind == 'top' else str(self.root)
                if 'status' in command:
                    return ' M test/test_a.py' if kind == 'dirty' else ''
                return 'c' * 40 if kind == 'head' else self.commit
            with self.subTest(kind=kind), mock.patch.object(gate, 'captured', side_effect=git):
                if kind == 'scope':
                    actual = gate.regression_scope(self.root)
                    changed = dict(actual, scope_sha256='d' * 64)
                    with mock.patch.object(gate, 'regression_scope', side_effect=[actual, changed]):
                        with self.assertRaisesRegex(RuntimeError, 'immutable scope'):
                            gate.regression_host_source(self.root, self.root, self.commit)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'committed Git worktree'):
                        gate.regression_host_source(self.root, self.root, self.commit)

    def test_wrong_group_missing_host_and_rehashed_host_identity_refused(self):
        self.add_git_host()
        receipts, host = self.originals()
        value = json.loads(host.read_text())
        identity = {'mode': 'committed-live-worktree', 'root': str(self.root),
                    'git_top': str(self.root), 'source_commit': self.commit,
                    'scope_sha256': gate.regression_scope(self.root)['scope_sha256']}
        # A host group containing the modules is insufficient without its
        # committed execution-root evidence. Do not credit archive-root Git.
        with self.assertRaisesRegex(RuntimeError, 'committed-source identity'):
            self.qualify(receipts, host)
        value['host_source'] = identity
        self.rewrite(host, value)
        qualification = self.qualify(receipts, host)
        self.assertEqual('PARTIAL', qualification['verdict'])
        for field, wrong in (('mode', 'archive-no-git'), ('source_commit', 'c' * 40),
                             ('scope_sha256', 'd' * 64), ('git_top', str(self.root / 'other'))):
            changed = copy.deepcopy(value)
            changed['host_source'][field] = wrong
            self.rewrite(host, changed)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'committed-source identity'):
                self.qualify(receipts, host)
        changed = copy.deepcopy(value)
        changed['groups']['host']['selection'].remove('test/test_acceptance_package.py')
        self.rewrite(host, changed)
        with self.assertRaisesRegex(RuntimeError, 'selection mismatch'):
            self.qualify(receipts, host)
        self.rewrite(host, value)
        with self.assertRaises(RuntimeError):
            self.qualify(receipts, None)
        changed = json.loads(receipts[0].read_text())
        changed['regression_scope']['windows'].append('test/test_acceptance_package.py')
        self.rewrite(receipts[0], changed)
        with self.assertRaisesRegex(RuntimeError, 'scope/source/catalog'):
            self.qualify(receipts, host)

    def test_direct_regression_build_cannot_bypass_host_qualification(self):
        with mock.patch.object(gate, 'captured') as git, \
                mock.patch.object(gate, 'offline_install_sdk') as install:
            with self.assertRaisesRegex(RuntimeError, 'merged host/shard qualification'):
                gate.build(self.root, self.commit, self.root / 'unused-dist',
                           layer='regression', image_id=self.image)
        git.assert_not_called()
        install.assert_not_called()
        self.assertFalse((self.root / 'unused-dist').exists())

    def test_cli_and_wrapper_propagate_exact_layer_and_keep_default(self):
        wrapper = (ROOT / 'Build-FakeNetNgMcpPackage.sh').read_text()
        self.assertIn('LAYER="${LAYER:-full}"', wrapper)
        self.assertIn('full|core|regression)', wrapper)
        self.assertIn('[[ "$LAYER" == core || "$LAYER" == regression ]]', wrapper)
        self.assertIn('--host-only --layer "$LAYER"', wrapper)
        self.assertLess(wrapper.index('case "$LAYER"'), wrapper.index('if ! docker image inspect'))
        for flag in ('--gate-only', '--host-only', '--package-only'):
            argv = ['builder', '--repo', str(self.root), '--layer', 'regression', flag]
            if flag == '--package-only':
                argv += ['--qualification', 'original.json', '--qualification-sha256', 'd' * 64]
            with self.subTest(flag=flag), mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(gate, 'build') as build:
                gate.main()
            self.assertEqual('regression', build.call_args.kwargs['layer'])
            self.assertTrue(build.call_args.kwargs[flag[2:].replace('-', '_')])

    def test_actual_merge_cli_reads_originals(self):
        receipts, host = self.originals()
        out = self.root / 'merged-qualification.json'
        argv = ['builder', '--repo', str(self.root), '--source-commit', self.commit,
                '--builder-image-id', self.image, '--layer', 'regression', '--gate-merge',
                '--shard-count', '2', '--host-receipt', str(host), '--qualification', str(out)]
        for receipt in receipts:
            argv += ['--receipt', str(receipt)]
        def git(command):
            return '' if 'status' in command else self.commit
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(gate, 'captured', side_effect=git):
            gate.main()
        self.assertEqual(self.qualify(receipts, host), json.loads(out.read_text()))

    def test_build_preflight_rejects_before_any_sdk_or_windows_execution(self):
        # Real build control flow, with only archive/SDK/OS boundaries modeled.
        self.catalog['schema'] = 'bad'
        self.write_catalog()
        def archive(command):
            with zipfile.ZipFile(command[command.index('--output') + 1], 'w') as bundle:
                for path in self.root.rglob('*'):
                    if path.is_file() and not path.is_relative_to(self.root / 'Logs'):
                        bundle.write(path, path.relative_to(self.root).as_posix())
        with mock.patch.object(gate, 'captured', return_value=self.commit), \
                mock.patch.object(gate, 'run', side_effect=archive), \
                mock.patch.object(gate, 'verify_source'), \
                mock.patch.object(gate, 'offline_install_sdk') as install, \
                mock.patch.object(gate, 'run_windows_test_gate') as windows:
            with self.assertRaisesRegex(RuntimeError, 'catalog schema'):
                gate.build(self.root, self.commit, self.root / 'unused-dist',
                           layer='regression', gate_only=True, image_id=self.image)
        install.assert_not_called()
        windows.assert_not_called()
        self.assertFalse((self.root / 'unused-dist').exists())
