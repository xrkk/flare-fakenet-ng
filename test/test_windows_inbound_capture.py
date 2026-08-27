# -*- coding: utf-8 -*-
"""Host-side lifecycle checks for the inbound capture thread
(plan 2026.08.21-01 I7/I9.4).

Covers: normal receive->record->reinjection, handle-closing exit codes,
pcap write failure mapping to a capture failure, and the shutdown ordering
(close capture handle -> join thread -> only then the writer may close).
"""

import logging
import threading
import unittest
from unittest import mock

from fakenet.diverters import windows
from fakenet.diverters.pcapwriter import PcapWriteError


def make_diverter():
    diverter = windows.Diverter.__new__(windows.Diverter)
    diverter._stopping = threading.Event()
    diverter.egress_control_mode = False
    diverter._inbound_capture_handle = None
    diverter.inbound_capture_thread = None
    diverter.logger = logging.getLogger('inbound-capture-test')
    return diverter


class _FakePacket(object):
    def __init__(self, raw=b'\x45\x00\x00\x14'):
        self.raw = raw


class InboundCaptureTests(unittest.TestCase):
    def test_queue_parameters_are_set_and_read_back_for_each_handle(self):
        diverter = make_diverter()
        diverter._capture_queue_bindings = {}
        handle = mock.Mock()
        values = {}
        from pydivert import Param

        def set_param(param, value):
            values[param] = value
            return True

        def get_param(param):
            return values[param]

        handle.set_param.side_effect = set_param
        handle.get_param.side_effect = get_param
        diverter.log_egress_event = mock.Mock()
        diverter._configure_windivert_queue(handle, 'main')
        diverter._configure_windivert_queue(handle, 'inbound')
        self.assertEqual(8192, values[Param.QUEUE_LEN])
        self.assertEqual(2048, values[Param.QUEUE_TIME])
        self.assertEqual(33554432, values[Param.QUEUE_SIZE])
        self.assertEqual(8192, diverter._capture_queue_bindings['inbound']['queue_len'])

    def test_queue_set_failure_is_fatal_for_each_handle_role(self):
        from pydivert import Param

        for role in ('main', 'inbound'):
            with self.subTest(role=role):
                diverter = make_diverter()
                diverter._capture_queue_bindings = {}
                diverter.log_egress_event = mock.Mock()
                handle = mock.Mock()
                handle.set_param.return_value = False

                with self.assertRaisesRegex(
                        PcapWriteError,
                        '%s WinDivert queue_len set returned false' % role):
                    diverter._configure_windivert_queue(handle, role)

                handle.set_param.assert_called_once_with(Param.QUEUE_LEN, 8192)
                handle.get_param.assert_not_called()
                self.assertNotIn(role, diverter._capture_queue_bindings)
                diverter.log_egress_event.assert_not_called()

    def test_queue_readback_mismatch_is_fatal_for_each_handle_role(self):
        from pydivert import Param

        for role in ('main', 'inbound'):
            with self.subTest(role=role):
                diverter = make_diverter()
                diverter._capture_queue_bindings = {}
                diverter.log_egress_event = mock.Mock()
                handle = mock.Mock()
                handle.set_param.return_value = True
                handle.get_param.return_value = 8191

                with self.assertRaisesRegex(
                        PcapWriteError,
                        '%s WinDivert queue_len readback 8191 != 8192' % role):
                    diverter._configure_windivert_queue(handle, role)

                handle.set_param.assert_called_once_with(Param.QUEUE_LEN, 8192)
                handle.get_param.assert_called_once_with(Param.QUEUE_LEN)
                self.assertNotIn(role, diverter._capture_queue_bindings)
                diverter.log_egress_event.assert_not_called()

    def test_queue_set_exception_identifies_field_stage_and_value(self):
        from pydivert import Param

        diverter = make_diverter()
        diverter._capture_queue_bindings = {}
        diverter.log_egress_event = mock.Mock()
        handle = mock.Mock()
        handle.set_param.side_effect = (
            True, True, OSError(87, 'invalid parameter'))
        handle.get_param.side_effect = (8192, 2048)

        with self.assertRaisesRegex(
                PcapWriteError,
                'main WinDivert queue_size_bytes set value=33554432 failed'):
            diverter._configure_windivert_queue(handle, 'main')

        self.assertEqual([
            mock.call(Param.QUEUE_LEN, 8192),
            mock.call(Param.QUEUE_TIME, 2048),
            mock.call(Param.QUEUE_SIZE, 33554432),
        ], handle.set_param.call_args_list)
        self.assertNotIn('main', diverter._capture_queue_bindings)
        diverter.log_egress_event.assert_not_called()

    def test_recv_gap_boundary_is_fail_closed_and_single_record(self):
        diverter = make_diverter()
        diverter._initialize_capture_state()
        diverter._capture_queue_required = True
        diverter._capture_queue_bindings = {
            'main': {'queue_time_ms': 2048},
            'inbound': {'queue_time_ms': 2048},
        }
        self.assertTrue(diverter._check_recv_cycle_gap('main', 10.0, 12.047))
        self.assertFalse(diverter._check_recv_cycle_gap('main', 10.0, 12.048))
        self.assertFalse(diverter._check_recv_cycle_gap('main', 10.0, 12.100))
        self.assertIsNotNone(diverter.capture_failure)

    def test_coverage_requires_complete_main_and_inbound_queue_readback(self):
        diverter = make_diverter()
        diverter._initialize_capture_state()
        diverter._capture_queue_required = True
        complete = {
            'queue_len': 8192, 'queue_time_ms': 2048,
            'queue_size_bytes': 33554432,
        }
        diverter._capture_queue_bindings = {
            'main': dict(complete), 'inbound': dict(complete),
        }
        self.assertTrue(diverter._capture_queue_bindings_complete())
        diverter._capture_queue_bindings.pop('inbound')
        self.assertFalse(diverter._capture_queue_bindings_complete())
        diverter._capture_queue_bindings['inbound'] = {
            'queue_time_ms': 2048,
        }
        self.assertFalse(diverter._capture_queue_bindings_complete())
        diverter._capture_queue_bindings['inbound'] = dict(complete)
        diverter._capture_queue_bindings['inbound']['queue_len'] = 4096
        self.assertFalse(diverter._capture_queue_bindings_complete())

    def test_loop_records_and_reinjects_each_packet(self):
        diverter = make_diverter()
        packets = [_FakePacket(b'\x45\x00\x00\x14'),
                   _FakePacket(b'\x45\x00\x00\x15')]
        sent = list(packets)
        writer = mock.Mock()

        def recv():
            if packets:
                return packets.pop(0)
            diverter._stopping.set()
            return None

        handle = mock.Mock()
        handle.recv.side_effect = recv
        diverter._inbound_capture_handle = handle
        diverter.dual_pcap = writer
        diverter._record_capture_failure = mock.Mock()

        diverter._inbound_capture_loop()

        self.assertEqual(
            [call[0][0] for call in writer.write_ip_packet.call_args_list],
            [b'\x45\x00\x00\x14', b'\x45\x00\x00\x15'])
        handle.send.assert_any_call(sent[0])
        handle.send.assert_any_call(sent[1])
        diverter._record_capture_failure.assert_not_called()

    def test_windows_error_995_exits_without_failure(self):
        diverter = make_diverter()
        error = WindowsError()
        error.winerror = 995
        handle = mock.Mock()
        handle.recv.side_effect = error
        diverter._inbound_capture_handle = handle
        diverter.dual_pcap = mock.Mock()
        diverter._record_capture_failure = mock.Mock()

        diverter._inbound_capture_loop()

        diverter._record_capture_failure.assert_not_called()

    def test_pcap_write_failure_maps_to_capture_failure(self):
        diverter = make_diverter()
        handle = mock.Mock()
        handle.recv.return_value = _FakePacket()
        diverter._inbound_capture_handle = handle
        diverter.dual_pcap = mock.Mock()
        diverter.dual_pcap.write_ip_packet.side_effect = PcapWriteError('x')
        diverter._record_capture_failure = mock.Mock()

        diverter._inbound_capture_loop()

        diverter._record_capture_failure.assert_called_once()
        handle.send.assert_not_called()

    def test_open_failure_records_capture_failure_not_degrade(self):
        diverter = make_diverter()
        diverter.dump_packets = True
        diverter.dual_pcap = object()
        diverter._record_capture_failure = mock.Mock()
        error = WindowsError()
        error.winerror = 5

        with mock.patch.object(windows, 'WinDivert',
                               side_effect=error) as windivert_cls:
            diverter._open_inbound_capture()

        windivert_cls.assert_called_once()
        diverter._record_capture_failure.assert_called_once()
        self.assertIsNone(diverter._inbound_capture_handle)

    def test_open_skipped_without_dual_pcap(self):
        diverter = make_diverter()
        diverter.dump_packets = False
        diverter.dual_pcap = None
        with mock.patch.object(windows, 'WinDivert') as windivert_cls:
            diverter._open_inbound_capture()
        windivert_cls.assert_not_called()

    def test_filter_matches_directional_scope_per_mode(self):
        diverter = make_diverter()
        diverter.egress_control_mode = True
        self.assertEqual(diverter._inbound_capture_filter(),
                         'inbound and (ip or ipv6)')
        diverter.egress_control_mode = False
        self.assertEqual(diverter._inbound_capture_filter(),
                         'inbound and ip')

    def test_stop_closes_capture_then_joins_before_main_handle(self):
        diverter = make_diverter()
        diverter._stopping = threading.Event()
        diverter._flush_reviewed_ip_audit = mock.Mock()
        diverter._flush_process_redirect_audit = mock.Mock()
        diverter.egress_policy = None
        diverter.handle = mock.Mock()
        diverter._restore_network_settings = mock.Mock()
        diverter._capture_writers_safe_to_close = True
        diverter._inbound_capture_handle = mock.Mock()
        capture_worker = mock.Mock()
        capture_worker.is_alive.return_value = False
        diverter.inbound_capture_thread = capture_worker
        close_calls = []
        diverter._close_inbound_capture_handle = lambda: (
            close_calls.append('inbound'))
        diverter._close_windivert_handle = lambda: close_calls.append('main')
        self.assertTrue(diverter.stopCallback())

        self.assertEqual(close_calls, ['inbound', 'main'])
        capture_worker.join.assert_called_once_with(5)
        self.assertTrue(diverter._capture_writers_safe_to_close)

    def test_stop_timeout_blocks_capture_close(self):
        diverter = make_diverter()
        diverter._stopping = threading.Event()
        diverter._flush_reviewed_ip_audit = mock.Mock()
        diverter._flush_process_redirect_audit = mock.Mock()
        diverter.egress_policy = None
        diverter.handle = None
        diverter._restore_network_settings = mock.Mock()
        diverter._capture_writers_safe_to_close = True
        worker = mock.Mock()
        worker.is_alive.return_value = True
        diverter.inbound_capture_thread = worker
        diverter._close_inbound_capture_handle = mock.Mock()

        self.assertFalse(diverter.stopCallback())
        self.assertFalse(diverter._capture_writers_safe_to_close)


if __name__ == '__main__':
    unittest.main()
