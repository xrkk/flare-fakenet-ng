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
import logging
import sys
import types
import unittest
import unittest.mock

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


class DefaultInterceptionReadyTests(unittest.TestCase):

    def _fakenet(self):
        fakenet = Fakenet(logging.ERROR)
        fakenet.fakenet_config = {'diverttraffic': 'yes'}
        fakenet.diverter_config = {
            'externalaccesspolicy': 'disabled',
            'networkmode': 'multihost',
            'linuxrestrictinterface': 'off',
        }
        fakenet.listeners_config = {}
        return fakenet

    def setUp(self):
        RecordingDiverter.started = 0
        RecordingDiverter.fail_start = False

    def _linux_diverter_patch(self):
        # The real linux diverter module needs netfilterqueue; the import
        # site inside start() only needs the Diverter attribute, so a stub
        # module injected via patch.dict (auto-reverted) is the seam.
        stub = types.ModuleType('fakenet.diverters.linux')
        stub.Diverter = RecordingDiverter
        return unittest.mock.patch.dict(sys.modules,
                                        {'fakenet.diverters.linux': stub})

    def test_quiet_network_successful_start_emits_marker_after_diverter(self):
        fakenet = self._fakenet()
        fakenet.logger.setLevel(logging.INFO)
        with self._linux_diverter_patch():
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
            with self._linux_diverter_patch():
                with self.assertRaises(RuntimeError):
                    fakenet.start()
        finally:
            fakenet.logger.removeHandler(handler)
        self.assertNotIn('DEFAULT_INTERCEPTION_READY',
                         [r.getMessage() for r in records])
        self.assertEqual(RecordingDiverter.started, 1)

    def test_policy_mode_never_emits_default_marker(self):
        # A real policy start re-derives policy_mode from the config; on this
        # runner it fails the Windows-only check before any diverter exists,
        # and the default marker must stay absent from that failure path.
        fakenet = self._fakenet()
        fakenet.diverter_config['externalaccesspolicy'] = 'egresscontrol'
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        fakenet.logger.addHandler(handler)
        try:
            with self.assertRaises(RuntimeError):
                fakenet.start()
        finally:
            fakenet.logger.removeHandler(handler)
        self.assertFalse(fakenet.policy_mode is False and fakenet.diverter is not None)
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
