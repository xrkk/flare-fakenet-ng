"""DEFAULT_INTERCEPTION_READY is emitted exactly when startup truly finished.

The legacy/default probe used to wait for the diverter's first background
flow ("requested TCP/UDP"), which a quiet network never produces
(candidate04-dns-01: probe released 02:04:13, first background flow 02:05:28,
75s later). The product now logs one INFO FakeNet DEFAULT_INTERCEPTION_READY
line at the end of a successful legacy start, after diverter.start() returns
cleanly — on every platform that return means the packet source is open and
its receiver is running (each step raises and rolls back otherwise).

These tests drive the REAL Fakenet.start path with controlled dependencies
(a fake platform Diverter class injected at its import site; the method
under test is never mocked): quiet network with zero traffic still emits the
marker; every failure path stays silent; the marker follows the diverter
start; one start logs it exactly once.
"""
import contextlib
import logging
import os
import sys
import types
import unittest
import unittest.mock


class ExitStackWithPatches:
    def __init__(self, patches):
        self._patches = patches

    def __enter__(self):
        self._stack = contextlib.ExitStack()
        for patch in self._patches:
            self._stack.enter_context(patch)
        return self._stack

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)

fake_netifaces = types.ModuleType('netifaces')
fake_netifaces.AF_INET = 2
fake_netifaces.AF_INET6 = 23
fake_netifaces.interfaces = lambda: ['lo']
fake_netifaces.ifaddresses = lambda interface: {2: [{'addr': '127.0.0.1'}]}
sys.modules.setdefault('netifaces', fake_netifaces)

from fakenet import fakenet as fakenet_module
from fakenet.fakenet import Fakenet


class RecordingDiverter:
    """Stands in at the platform import site; the real start() drives it."""

    started = 0
    fail_start = False

    def __init__(self, diverter_config, listeners_config, ip_addrs, level):
        self.start_calls = 0

    def start(self):
        RecordingDiverter.started += 1
        if RecordingDiverter.fail_start:
            raise RuntimeError('platform capture failed to open')

    # Policy-mode start touches these before diverter.start(); recording
    # no-ops keep the policy path fully driven without faking success.
    def configure_policy_runtime(self, *args, **kwargs):
        pass

    def suspend_policy(self):
        pass


class DefaultInterceptionReadyTests(unittest.TestCase):

    def _fakenet(self, policy=False):
        fakenet = Fakenet(logging.ERROR)
        fakenet.fakenet_config = {'diverttraffic': 'yes'}
        fakenet.diverter_config = {
            'externalaccesspolicy': 'egresscontrol' if policy else 'disabled',
            'networkmode': 'multihost' if os.name == 'posix' else 'singlehost',
            'linuxrestrictinterface': 'off',
        }
        fakenet.listeners_config = {}
        return fakenet

    def _diverter_patch(self, force_windows=False):
        # Import-site seam for BOTH platforms: the current platform's branch
        # resolves its own module name from sys.modules, so the recording
        # stand-in replaces the platform Diverter without mocking the method
        # under test. Policy runs are forced down the Windows branch because
        # EgressControl exists only there.
        stub = types.ModuleType('fakenet.diverters.linux')
        stub.Diverter = RecordingDiverter
        win = types.ModuleType('fakenet.diverters.windows')
        win.Diverter = RecordingDiverter
        patches = [unittest.mock.patch.dict(sys.modules, {
            'fakenet.diverters.linux': stub,
            'fakenet.diverters.windows': win})]
        if force_windows:
            patches.append(unittest.mock.patch.object(
                fakenet_module.platform, 'system', return_value='Windows'))
        return ExitStackWithPatches(patches)

    def setUp(self):
        RecordingDiverter.started = 0
        RecordingDiverter.fail_start = False


    def test_quiet_network_successful_start_emits_marker_after_diverter(self):
        fakenet = self._fakenet()
        fakenet.logger.setLevel(logging.INFO)
        with self._diverter_patch():
            with self.assertLogs('FakeNet', level='INFO') as captured:
                fakenet.start()
        messages = [record.getMessage() for record in captured.records]
        self.assertIn('DEFAULT_INTERCEPTION_READY', messages)
        # Zero traffic flowed: the only readiness fact is the startup marker,
        # and the diverter really started exactly once before it.
        self.assertEqual(RecordingDiverter.started, 1)
        self.assertEqual(messages.count('DEFAULT_INTERCEPTION_READY'), 1)

    def test_diverter_start_failure_never_emits_marker(self):
        fakenet = self._fakenet()
        RecordingDiverter.fail_start = True
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        fakenet.logger.addHandler(handler)
        try:
            with self._diverter_patch():
                with self.assertRaises(RuntimeError):
                    fakenet.start()
        finally:
            fakenet.logger.removeHandler(handler)
        self.assertNotIn('DEFAULT_INTERCEPTION_READY',
                         [r.getMessage() for r in records])
        self.assertEqual(RecordingDiverter.started, 1)

    def test_policy_mode_never_emits_default_marker(self):
        # Policy mode re-derives from the config and only exists on Windows;
        # the start is forced down that branch with the recording stand-in,
        # so a fully successful POLICY start still logs no default marker.
        fakenet = self._fakenet(policy=True)
        fakenet.running_listener_providers = []
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        fakenet.logger.addHandler(handler)
        try:
            with self._diverter_patch(force_windows=True):
                fakenet.start()
        finally:
            fakenet.logger.removeHandler(handler)
        self.assertTrue(fakenet.policy_mode)
        self.assertNotIn('DEFAULT_INTERCEPTION_READY',
                         [r.getMessage() for r in records])

    def test_without_diverter_no_marker(self):
        fakenet = Fakenet(logging.ERROR)
        fakenet.fakenet_config = {'diverttraffic': 'no'}
        fakenet.diverter_config = {
            'externalaccesspolicy': 'disabled',
            'networkmode': 'singlehost',
        }
        fakenet.listeners_config = {}
        fakenet.logger.setLevel(logging.INFO)
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        fakenet.logger.addHandler(handler)
        try:
            fakenet.start()
        finally:
            fakenet.logger.removeHandler(handler)
        self.assertIsNone(fakenet.diverter)
        self.assertNotIn('DEFAULT_INTERCEPTION_READY',
                         [r.getMessage() for r in records])


if __name__ == '__main__':
    unittest.main()
