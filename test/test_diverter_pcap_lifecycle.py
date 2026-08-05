import logging
import os
import tempfile
import threading
import unittest

from fakenet.diverters.diverterbase import DiverterBase
from fakenet.diverters.pcapwriter import PcapWriteError


class Packet(object):
    octets = b'\x45\x00'
    mangled = False

    @staticmethod
    def hdrToStr2():
        return 'test packet'


class FailingCapture(object):
    def __init__(self, error):
        self.error = error
        self.calls = 0

    def write_ip_packet(self, raw):
        self.calls += 1
        raise self.error


class ClosingCapture(object):
    def __init__(self, events):
        self.events = events
        self.close_calls = 0

    def close(self, discard_if_empty=False):
        self.close_calls += 1
        self.events.append('capture-close')
        return type('Summary', (), {
            'raw_filename': 'raw.pcap',
            'ethernet_filename': 'ethernet.pcap',
            'raw_write_count': 1,
            'ethernet_write_count': 1,
            'rejected_input_count': 0,
            'healthy': True,
        })()


class DummyDiverter(DiverterBase):
    def startCallback(self):
        self.callback_saw_capture = self.dual_pcap is not None
        if getattr(self, 'fail_start_after_write', False):
            self.dual_pcap.write_ip_packet(
                b'\x45' + (b'\x00' * 19))
            raise RuntimeError('injected platform startup after write')
        if getattr(self, 'fail_start', False):
            raise RuntimeError('injected platform startup failure')
        return True

    def stopCallback(self):
        self.stop_callback_calls += 1
        self.events.append('platform-stop')
        return True


class DiverterPcapLifecycleTests(unittest.TestCase):
    def _diverter(self, prefix=None):
        diverter = DummyDiverter.__new__(DummyDiverter)
        diverter.logger = logging.getLogger('diverter-pcap-test')
        diverter.pdebug_level = 0
        diverter.pdebug_labels = {}
        diverter._stopping = threading.Event()
        diverter._initialize_capture_state()
        diverter.dump_packets = prefix is not None
        diverter.pcap_prefix = prefix or 'packets'
        diverter.stop_callback_calls = 0
        diverter.fail_start = False
        diverter.fail_start_after_write = False
        diverter.events = []
        diverter.prettyPrintNbi = lambda: diverter.events.append('nbi-report')
        diverter.generate_html_report = lambda: diverter.events.append('html-report')
        return diverter

    def test_capture_failure_is_recorded_once_and_signals_stopping(self):
        diverter = self._diverter()
        failure = PcapWriteError('injected')
        diverter.dual_pcap = FailingCapture(failure)

        with self.assertLogs(diverter.logger, level='CRITICAL') as captured:
            with self.assertRaises(PcapWriteError):
                diverter.write_pcap(Packet())
            with self.assertRaises(PcapWriteError):
                diverter.write_pcap(Packet())

        self.assertIs(failure, diverter.capture_failure)
        self.assertTrue(diverter.wait_for_capture_failure(0))
        self.assertTrue(diverter._stopping.is_set())
        self.assertEqual(1, len([
            line for line in captured.output
            if 'PCAP_DUAL_WRITE_FAILED' in line]))

    def test_start_opens_capture_before_callback_and_rolls_back_empty_failure(self):
        with tempfile.TemporaryDirectory() as tempdir:
            prefix = os.path.join(tempdir, 'packets')
            diverter = self._diverter(prefix)
            diverter.fail_start = True

            with self.assertRaisesRegex(RuntimeError, 'platform startup'):
                diverter.start()

            self.assertTrue(diverter.callback_saw_capture)
            self.assertEqual(1, diverter.stop_callback_calls)
            self.assertEqual([], os.listdir(tempdir))
            self.assertTrue(diverter.stop())
            self.assertEqual(1, diverter.stop_callback_calls)

    def test_capture_constructor_failure_never_invokes_platform_cleanup(self):
        diverter = self._diverter('unused')

        def fail_factory(*args):
            raise OSError('injected capture constructor failure')

        diverter._dual_pcap_factory = fail_factory
        with self.assertRaisesRegex(OSError, 'constructor failure'):
            diverter.start()

        self.assertTrue(diverter.stop())
        self.assertEqual(0, diverter.stop_callback_calls)

    def test_start_failure_preserves_partial_capture_after_a_record(self):
        with tempfile.TemporaryDirectory() as tempdir:
            prefix = os.path.join(tempdir, 'packets')
            diverter = self._diverter(prefix)
            diverter.fail_start_after_write = True

            with self.assertRaisesRegex(RuntimeError, 'after write'):
                diverter.start()

            self.assertEqual(1, diverter.stop_callback_calls)
            self.assertEqual(2, len(os.listdir(tempdir)))
            self.assertTrue(diverter.stop())
            self.assertEqual(1, diverter.stop_callback_calls)

    def test_normal_stop_reports_then_platform_then_capture_and_is_idempotent(self):
        diverter = self._diverter()
        capture = ClosingCapture(diverter.events)
        diverter.dual_pcap = capture

        self.assertTrue(diverter.stop())
        self.assertTrue(diverter.stop())

        self.assertEqual([
            'nbi-report', 'html-report', 'platform-stop', 'capture-close'
        ], diverter.events)
        self.assertEqual(1, diverter.stop_callback_calls)
        self.assertEqual(1, capture.close_calls)

    def test_capture_fatal_stops_platform_and_capture_before_best_effort_reports(self):
        diverter = self._diverter()
        capture = ClosingCapture(diverter.events)
        diverter.dual_pcap = capture
        diverter._record_capture_failure(PcapWriteError('injected fatal'))

        with self.assertRaisesRegex(PcapWriteError, 'injected fatal'):
            diverter.stop()

        self.assertEqual([
            'platform-stop', 'capture-close', 'nbi-report', 'html-report'
        ], diverter.events)
        self.assertEqual(1, diverter.stop_callback_calls)
        self.assertEqual(1, capture.close_calls)


if __name__ == '__main__':
    unittest.main()
