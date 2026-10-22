"""Offline contract tests for the original test.py runner and fixtures.

These tests never start FakeNet, open a socket or read the network.  The
original driver is imported with local stubs because its client libraries are
not required to test exit propagation, fixture selection or the SMTP function.
"""
import configparser
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))


def _install_stubs():
    requests = sys.modules.setdefault('requests', types.ModuleType('requests'))
    requests.Session = object
    requests.exceptions = types.SimpleNamespace(Timeout=Exception, SSLError=Exception)
    adapters = sys.modules.setdefault('requests.adapters', types.ModuleType('requests.adapters'))
    adapters.HTTPAdapter = object
    irc = sys.modules.setdefault('irc', types.ModuleType('irc'))
    client = sys.modules.setdefault('irc.client', types.ModuleType('irc.client'))
    client.Reactor = object
    irc.client = client
    netifaces = sys.modules.setdefault('netifaces', types.ModuleType('netifaces'))
    netifaces.AF_INET = 2
    netifaces.AF_INET6 = 10
    netifaces.interfaces = lambda: []
    netifaces.ifaddresses = lambda name: {}
    icmplib = sys.modules.setdefault('icmplib', types.ModuleType('icmplib'))
    icmplib.ping = lambda *args, **kwargs: None


def load_driver():
    _install_stubs()
    spec = importlib.util.spec_from_file_location(
        'fakenet_upstream_driver', ROOT / 'test' / 'test.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRIVER = load_driver()


def settings_stub(**overrides):
    values = {
        'domain_dne': 'does-not-exist-amirite.mandiant.com',
        'ext_ip': '192.0.2.10',
        'arbitrary': '8.8.8.8',
        'blacklistedhost': '6.6.6.6',
        'blacklistedtcp': 139,
        'blacklistedudp': 67,
        'blacklistedicmp': 1234,
        'localhost': '127.0.0.1',
        'dns_expected': '192.0.2.123',
        'hidden_tcp': 12345,
        'no_service': 10,
        'sender': 'from-fakenet@example.org',
        'recipient': 'to-fakenet@example.org',
        'smtpmsg': 'FakeNet-NG SMTP test email',
        'listener_proc_black': 8080,
        'listener_proc_white': 8081,
        'listener_host_black': 8082,
        'listener_host_white': 8083,
        'listener_filter_host': '9.9.9.9',
        'singlehost': True,
        'windows': False,
        'linux': True,
        'sleep_after_start': 0,
        'sleep_before_stop': 0,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


class FixtureTests(unittest.TestCase):
    def test_listener_host_filters_are_not_shadowed_by_global_blacklist(self):
        parser = configparser.RawConfigParser()
        parser.read(ROOT / 'test' / 'template.ini')
        global_blacklist = parser['Diverter'].get('HostBlackList')
        black = parser['HTTPListener8082HostBlack'].get('HostBlackList')
        white = parser['HTTPListener8083HostWhite'].get('HostWhiteList')
        self.assertEqual('6.6.6.6', global_blacklist)
        self.assertEqual('9.9.9.9', black)
        self.assertEqual('9.9.9.9', white)
        self.assertNotEqual(black, global_blacklist)
        self.assertNotEqual(white, global_blacklist)

    def test_general_cases_use_distinct_host_filter_targets(self):
        tester = DRIVER.FakeNetTester(settings_stub())
        cases = tester.generalTests()
        filter_host = tester.settings.listener_filter_host
        self.assertEqual((tester.settings.arbitrary, 8082),
                         cases['Listener host blacklist'][1])
        self.assertTrue(cases['Listener host blacklist'][2])
        self.assertEqual((filter_host, 8082),
                         cases['Listener host blacklist blocked'][1])
        self.assertFalse(cases['Listener host blacklist blocked'][2])
        self.assertEqual((filter_host, 8083),
                         cases['Listener host whitelist'][1])
        self.assertTrue(cases['Listener host whitelist'][2])
        self.assertEqual((tester.settings.arbitrary, 8083),
                         cases['Listener host whitelist blocked'][1])
        self.assertFalse(cases['Listener host whitelist blocked'][2])


class SmtpSslContractTests(unittest.TestCase):
    class FakeSmtp:
        instances = []

        def __init__(self, host, port, local_hostname=None, timeout=None):
            self.host = host
            self.port = port
            self.local_hostname = local_hostname
            self.timeout = timeout
            self.sendmail_args = None
            self.quit_called = False
            FakeSmtp = SmtpSslContractTests.FakeSmtp
            FakeSmtp.instances.append(self)

        def sendmail(self, sender, recipient, msg):
            self.sendmail_args = (sender, recipient, msg)

        def quit(self):
            self.quit_called = True

    def setUp(self):
        self.FakeSmtp.instances = []
        self.tester = DRIVER.FakeNetTester(settings_stub())

    def test_successful_send_uses_keywords_and_returns_true(self):
        with mock.patch.object(DRIVER.smtplib, 'SMTP_SSL', self.FakeSmtp):
            value = self.tester._test_smtp_ssl('from@example.org',
                                               'to@example.org', 'body',
                                               '192.0.2.10', 25)
        self.assertTrue(value)
        instance = self.FakeSmtp.instances[0]
        self.assertEqual(('192.0.2.10', 25), (instance.host, instance.port))
        self.assertEqual('fake.net', instance.local_hostname)
        self.assertEqual(5, instance.timeout)
        self.assertEqual(('from@example.org', 'to@example.org', 'body'),
                         instance.sendmail_args)
        self.assertTrue(instance.quit_called)

    def test_send_error_propagates_and_quit_runs(self):
        class FailingSmtp(self.FakeSmtp):
            def sendmail(self, sender, recipient, msg):
                raise RuntimeError('send failed')
        with mock.patch.object(DRIVER.smtplib, 'SMTP_SSL', FailingSmtp):
            with self.assertRaisesRegex(RuntimeError, 'send failed'):
                self.tester._test_smtp_ssl('a', 'b', 'c', 'host', 25)
        self.assertTrue(FailingSmtp.instances[0].quit_called)

    def test_construction_error_propagates(self):
        class BrokenSmtp:
            def __init__(self, *args, **kwargs):
                raise TypeError('bad construction')
        with mock.patch.object(DRIVER.smtplib, 'SMTP_SSL', BrokenSmtp):
            with self.assertRaisesRegex(TypeError, 'bad construction'):
                self.tester._test_smtp_ssl('a', 'b', 'c', 'host', 25)

    def test_partial_refusal_is_not_success(self):
        class PartialSmtp(self.FakeSmtp):
            def sendmail(self, sender, recipient, msg):
                self.sendmail_args = (sender, recipient, msg)
                return {'bad@example.org': (550, b'no such user')}
        with mock.patch.object(DRIVER.smtplib, 'SMTP_SSL', PartialSmtp):
            with self.assertRaisesRegex(DRIVER.FakeNetTestException, 'refused'):
                self.tester._test_smtp_ssl('a', 'b', 'c', 'host', 25)
        self.assertTrue(PartialSmtp.instances[0].quit_called)

    def test_plain_smtp_refusal_is_not_success(self):
        class PartialPlain(self.FakeSmtp):
            def sendmail(self, sender, recipient, msg):
                return {'bad@example.org': (550, b'no such user')}
        with mock.patch.object(DRIVER.smtplib, 'SMTP', PartialPlain):
            with self.assertRaisesRegex(DRIVER.FakeNetTestException, 'refused'):
                self.tester._test_smtp('a', 'b', 'c', 'host', 25)
        self.assertTrue(PartialPlain.instances[0].quit_called)


class ResultAggregationTests(unittest.TestCase):
    def make_tester(self, results_path):
        settings = settings_stub(results_path=results_path,
                                 ancillary_files_dest=os.path.dirname(results_path),
                                 ancillary_files=[])
        tester = DRIVER.FakeNetTester(settings)
        tester.writeConfig = lambda config: None
        tester.executeFakenet = lambda: True
        tester.stopFakenetAndWait = lambda timeout, kill: True
        tester.delConfig = lambda: None
        return tester

    def test_retry_success_is_flaky_not_pass(self):
        attempts = {'count': 0}

        def flaky():
            attempts['count'] += 1
            return attempts['count'] > 1

        tests = OrderedDict([
            ('first fails then retries', (flaky, (), True)),
            ('always passes', (lambda: True, (), True)),
            ('always fails', (lambda: False, (), True)),
        ])
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, 'results.tsv')
            tester = self.make_tester(path)
            with mock.patch.object(DRIVER.time, 'sleep', lambda seconds: None):
                result = tester._testGeneric('fixture', object(), tests, [])
            DRIVER.writeResults(path, result['rows'])
            statuses = {row['id']: row['status'] for row in result['rows']}
            self.assertEqual(DRIVER.STATUS_FLAKY,
                             statuses['first fails then retries'])
            self.assertEqual(DRIVER.STATUS_PASS, statuses['always passes'])
            self.assertEqual(DRIVER.STATUS_FAIL, statuses['always fails'])
            self.assertIsNotNone(result['failure'])
            content = Path(path).read_text(encoding='utf-8')
            # A retry-only success is written as FAIL, never erased.
            self.assertIn('FAIL\tfirst fails then retries\t', content)
            self.assertIn('FAIL\talways fails\t', content)

    def test_do_tests_aggregates_and_writes_tsv(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, 'results.tsv')
            tester = self.make_tester(path)
            tester.testGeneral = lambda match: {
                'label': 'General', 'rows': [{'id': 'g', 'status': 'PASS',
                                              'detail': 'ok'}], 'failure': None}
            tester.testNoRedirect = lambda match: {
                'label': 'NoRedirect',
                'rows': [{'id': 'n', 'status': 'FAIL', 'detail': 'boom'}],
                'failure': 'one or more cases failed'}
            tester.testBlacklistProcess = lambda match: {
                'label': 'Blacklist', 'rows': [], 'failure': None}
            tester.testWhitelistProcess = lambda match: {
                'label': 'Whitelist', 'rows': [], 'failure': None}
            result = tester.doTests([])
            self.assertEqual(1, result['exit_code'])
            self.assertEqual(1, result['failed'])
            content = Path(path).read_text(encoding='utf-8')
            self.assertEqual('PASS\tg\tok\nFAIL\tn\tboom\n', content)

    def test_main_returns_nonzero_when_cases_fail(self):
        class FakeSettings:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.platform_name = 'Linux'

        class FakeTester:
            def __init__(self, settings):
                self.settings = settings

            def doTests(self, match_spec):
                return {'exit_code': 1}

        with mock.patch.object(DRIVER, 'is_admin', lambda: True), \
                mock.patch.object(DRIVER, 'FakeNetTestSettings', FakeSettings), \
                mock.patch.object(DRIVER, 'FakeNetTester', FakeTester), \
                mock.patch.object(DRIVER.sys, 'argv', ['test.py', 'here']):
            self.assertEqual(1, DRIVER.main())

    def test_main_returns_zero_when_all_cases_pass(self):
        class FakeSettings:
            def __init__(self, *args, **kwargs):
                self.platform_name = 'Linux'

        class FakeTester:
            def __init__(self, settings):
                pass

            def doTests(self, match_spec):
                return {'exit_code': 0}

        with mock.patch.object(DRIVER, 'is_admin', lambda: True), \
                mock.patch.object(DRIVER, 'FakeNetTestSettings', FakeSettings), \
                mock.patch.object(DRIVER, 'FakeNetTester', FakeTester), \
                mock.patch.object(DRIVER.sys, 'argv', ['test.py', 'here']):
            self.assertEqual(0, DRIVER.main())

    def test_parse_args_preserves_matchspec_and_flags(self):
        positional, results, non_interactive, multihost_ready = DRIVER.parseArgs(
            ['here', '-GUI', '--results', 'out.tsv', '--non-interactive',
             '--multihost-ready'])
        self.assertEqual(['here', '-GUI'], positional)
        self.assertEqual('out.tsv', results)
        self.assertTrue(non_interactive)
        self.assertTrue(multihost_ready)

    def test_stop_failure_is_a_case_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            tester = self.make_tester(os.path.join(temp, 'results.tsv'))
            tester.stopFakenetAndWait = lambda timeout, kill: False
            tests = OrderedDict([('passes', (lambda: True, (), True))])
            with mock.patch.object(DRIVER.time, 'sleep', lambda seconds: None):
                result = tester._testGeneric('fixture', object(), tests, [])
            self.assertIn('did not stop cleanly', result['failure'])

    def test_stop_exception_is_a_case_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            tester = self.make_tester(os.path.join(temp, 'results.tsv'))

            def broken_stop(timeout, kill):
                raise RuntimeError('stop channel closed')
            tester.stopFakenetAndWait = broken_stop
            tests = OrderedDict([('passes', (lambda: True, (), True))])
            with mock.patch.object(DRIVER.time, 'sleep', lambda seconds: None):
                result = tester._testGeneric('fixture', object(), tests, [])
            self.assertIn('stop raised', result['failure'])

    def test_multihost_noninteractive_requires_explicit_readiness(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = settings_stub(
                singlehost=False, non_interactive=True, multihost_ready=False,
                ancillary_files=[], ancillary_files_dest=temp,
                configpath=os.path.join(temp, 'fakenet.ini'),
                results_path=os.path.join(temp, 'results.tsv'))
            tester = DRIVER.FakeNetTester(settings)
            tests = OrderedDict([('passes', (lambda: True, (), True))])
            result = tester._testGeneric('multi', object(), tests, [])
            self.assertIn('readiness was not provided', result['failure'])
            self.assertEqual([], result['rows'])

    def test_multihost_noninteractive_with_readiness_runs(self):
        with tempfile.TemporaryDirectory() as temp:
            settings = settings_stub(
                singlehost=False, non_interactive=True, multihost_ready=True,
                ancillary_files=[], ancillary_files_dest=temp,
                configpath=os.path.join(temp, 'fakenet.ini'),
                results_path=os.path.join(temp, 'results.tsv'))
            tester = DRIVER.FakeNetTester(settings)
            tester.writeConfig = lambda config: None
            tester._mkzip = lambda path, files: None
            tester.delConfig = lambda: None
            tests = OrderedDict([('passes', (lambda: True, (), True))])
            class Config:
                def multiHostMode(self):
                    pass
            with mock.patch.object(DRIVER.time, 'sleep', lambda seconds: None):
                result = tester._testGeneric('multi', Config(), tests, [])
            self.assertIsNone(result['failure'])
            self.assertEqual(DRIVER.STATUS_PASS, result['rows'][0]['status'])

    def test_try_test_reports_exception_detail(self):
        tester = DRIVER.FakeNetTester(settings_stub())

        def broken():
            raise ValueError('bad value')

        value = tester._tryTest('case', broken, (), True)
        self.assertFalse(value['passed'])
        self.assertIn('ValueError', value['detail'])


if __name__ == '__main__':
    unittest.main()


class MechanicalUpstreamTests(unittest.TestCase):
    def _tester(self, **kwargs):
        with mock.patch.object(DRIVER, 'get_external_ip', return_value='192.0.2.10'):
            settings = DRIVER.FakeNetTestSettings(str(ROOT/'test'), non_interactive=True)
        for key, value in kwargs.items():
            setattr(settings, key, value)
        return DRIVER.FakeNetTester(settings)

    def test_collection_is_exact_platform_and_mode_specific_without_actions(self):
        for windows in (False, True):
            for singlehost in (False, True):
                tester = self._tester(windows=windows, singlehost=singlehost)
                with mock.patch.object(tester, 'writeConfig', side_effect=AssertionError('I/O')):
                    suites = tester.collectSuites()
                identities = [s['label']+'::'+n for s in suites for n in s['tests']]
                self.assertEqual(len(identities), len(set(identities)))
                self.assertEqual(windows, any('hostname test' in n for n in identities))
                self.assertEqual(singlehost, any('Listener process' in n for n in identities))
                self.assertEqual(singlehost, any('Global blacklisted process' in n for n in identities))

    def test_invalid_selection_fails_before_target_or_files(self):
        tester = self._tester()
        import acceptance_runtime as rt
        with mock.patch.object(rt, 'require_target') as target:
            for checks in ([], ['bogus'], ['General::DNS listener test']*2):
                with self.assertRaises(ValueError):
                    tester.runMechanical({'schema':'fakenet.upstream-selection.v1',
                        'checks': checks, 'target': {}, 'work_root': '/not-created'})
            target.assert_not_called()

    def test_exact_selected_callbacks_and_cleanup(self):
        import acceptance_runtime as rt
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temp:
            tester = self._tester()
            identity = 'General::DNS listener test'
            spec = {'schema':'fakenet.upstream-selection.v1', 'checks':[identity],
                    'target':{}, 'work_root':str(Path(temp)/'work')}
            core = MagicMock()
            core.state = {'ready':True, 'stopped':True, 'forced':False, 'returncode':0}
            core.stop.return_value = True
            with mock.patch.object(rt, 'require_target'), mock.patch.object(rt, 'network_snapshot', return_value={'dns':'same'}), mock.patch.object(rt, 'OwnedCore', return_value=core), mock.patch.object(tester, '_tryTest', return_value={'passed':True,'detail':'observed'}) as probe:
                self.assertEqual(0, tester.runMechanical(spec))
            self.assertEqual([identity], [c.args[0] for c in probe.call_args_list])
            core.start.assert_called_once()
            core.stop.assert_called_once()
            import json
            result = json.loads((Path(spec['work_root'])/'upstream.json').read_text())
            self.assertTrue(result['passed'])
            self.assertEqual([identity], [row['id'] for row in result['checks']])

    def test_start_failure_still_stops_and_cannot_pass(self):
        import acceptance_runtime as rt
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temp:
            tester = self._tester()
            core = MagicMock(); core.state = {'ready':False}; core.start.side_effect = TimeoutError('no ready'); core.stop.return_value = True
            spec = {'schema':'fakenet.upstream-selection.v1','checks':['General::DNS listener test'], 'target':{}, 'work_root':str(Path(temp)/'work')}
            with mock.patch.object(rt, 'require_target'), mock.patch.object(rt, 'network_snapshot', return_value={}), mock.patch.object(rt, 'OwnedCore', return_value=core), mock.patch.object(tester, '_tryTest') as probe:
                self.assertEqual(1, tester.runMechanical(spec))
            core.stop.assert_called_once(); probe.assert_not_called()

    def test_network_difference_stops_subsequent_suites(self):
        import acceptance_runtime as rt
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as temp:
            tester = self._tester()
            core = MagicMock(); core.state = {}; core.stop.return_value = True
            spec = {'schema':'fakenet.upstream-selection.v1', 'checks':['General::DNS listener test','No Redirect::RedirectAllTraffic disabled external IP @ bound'], 'target':{}, 'work_root':str(Path(temp)/'work')}
            with mock.patch.object(rt,'require_target'), mock.patch.object(rt,'network_snapshot', side_effect=[{'dns':'old'},{'dns':'changed'}]), mock.patch.object(rt,'OwnedCore', return_value=core) as owner, mock.patch.object(tester,'_tryTest',return_value={'passed':True,'detail':'ok'}):
                self.assertEqual(1, tester.runMechanical(spec))
            owner.assert_called_once()


class OwnedCoreTests(unittest.TestCase):
    def test_observed_ready_and_graceful_exit(self):
        import acceptance_runtime as rt
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); app = directory/'core.log'
            child = mock.Mock(pid=123, returncode=0)
            child.poll.side_effect = [None, None, 0, 0]
            def launch(*args, **kwargs):
                app.write_text('FakeNet-NG started successfully')
                self.assertFalse(kwargs['shell'])
                return child
            with mock.patch.object(rt.subprocess,'Popen',side_effect=launch):
                core = rt.OwnedCore(['python','-m','fixed'], directory, directory, directory/'stop', app)
                core.start()
                self.assertTrue(core.stop())
                self.assertTrue(core.state['ready'])

    def test_exited_before_ready_fails_and_closes_console(self):
        import acceptance_runtime as rt
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp); child=mock.Mock(pid=42, returncode=1); child.poll.return_value=1
            with mock.patch.object(rt.subprocess,'Popen',return_value=child):
                core=rt.OwnedCore(['fixed'],d,d,d/'stop',d/'app.log')
                with self.assertRaisesRegex(RuntimeError,'before ready'): core.start()
                self.assertTrue(core.console.closed)
                self.assertFalse(core.state['ready'])
