import socket
import struct
import subprocess
import tempfile
import unittest
import json
from unittest import mock

from fakenet.diverters.processredirect import (
    PacketTuple, PreparedRedirect, ProcessRedirectAction,
    ProcessRedirectDecision)
from fakenet.diverters.egresspolicy import PolicyConfigError
from fakenet.diverters.windows import (
    Diverter, ProcessRedirectRouteGuard, build_egress_control_filter,
    classify_process_redirect_ipv4_fragment)


def snapshot(target, source='10.0.0.5', interface=7, prefix='0.0.0.0/0',
             next_hop='10.0.0.1'):
    return {
        'target_ipv4': target,
        'interface_index': interface,
        'interface_alias': 'Ethernet0',
        'source_ipv4': source,
        'destination_prefix': prefix,
        'next_hop': next_hop,
        'route_metric': 1,
        'interface_metric': 5,
    }


class ProcessRedirectWindowsAdapterTests(unittest.TestCase):
    def test_disabled_filter_is_byte_for_byte_legacy_policy_filter(self):
        self.assertEqual(
            'outbound and (ip or ipv6)',
            build_egress_control_filter())

    def test_enabled_filter_uses_ipv4_protocol_field_for_all_tcp_fragments(self):
        value = build_egress_control_filter(
            '192.168.204.1', '10.0.0.5')

        self.assertEqual(
            '(outbound and (ip or ipv6)) or '
            '(inbound and ip and ip.SrcAddr == 192.168.204.1 and '
            'ip.DstAddr == 10.0.0.5 and ip.Protocol == 6)', value)
        self.assertNotIn('inbound and ip and tcp', value)

    def test_runtime_filter_preflight_records_exact_bundled_dll(self):
        diverter = Diverter.__new__(Diverter)
        diverter.filter = build_egress_control_filter(
            '192.168.204.1', '10.0.0.5')
        diverter.log_egress_event = mock.Mock()
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b'reviewed-windivert-dll')
            path = handle.name
        try:
            with mock.patch(
                    'fakenet.diverters.windows.WinDivert.check_filter',
                    return_value=(True, 0, '')), mock.patch(
                    'fakenet.diverters.windows.windivert_dll.DLL_PATH', path):
                diverter._validate_process_redirect_windivert_runtime()
        finally:
            import os
            os.unlink(path)

        diverter.log_egress_event.assert_called_once()
        event, = diverter.log_egress_event.call_args.args
        fields = diverter.log_egress_event.call_args.kwargs
        self.assertEqual('PROCESS_REDIRECT_WINDIVERT_BASELINE', event)
        self.assertEqual('1.3.0', fields['expected_version'])
        self.assertEqual(path, fields['dll_path'])
        self.assertEqual(64, len(fields['dll_sha256']))

    def test_startup_quiescence_rejects_running_image_or_existing_a_row(self):
        diverter = Diverter.__new__(Diverter)
        diverter._process_identity_api = mock.Mock()
        diverter.log_egress_event = mock.Mock()
        rule = mock.Mock()
        rule.file_identity = mock.sentinel.reviewed_identity
        rule.original_ipv4 = '93.184.216.34'
        diverter.egress_policy = mock.Mock(process_redirect_rule=rule)

        diverter._process_identity_api.find_reviewed_processes.return_value = (
            mock.sentinel.running_process,)
        with self.assertRaisesRegex(Exception, 'already running'):
            diverter._validate_process_redirect_quiescence()

        diverter._process_identity_api.find_reviewed_processes.return_value = ()
        row = mock.Mock(remote_ipv4='93.184.216.34', state=3)
        diverter._process_identity_api.get_tcp_owner_rows.return_value = (row,)
        with self.assertRaisesRegex(Exception, 'existing TCP row'):
            diverter._validate_process_redirect_quiescence()

        diverter._process_identity_api.get_tcp_owner_rows.return_value = ()
        diverter._validate_process_redirect_quiescence()

    def test_fragment_guard_covers_outbound_a_and_inbound_b_non_first_parts(self):
        def raw(src, dst, fragment_bits):
            return (bytes.fromhex('450000140000') +
                    struct.pack('!H', fragment_bits) +
                    bytes.fromhex('40060000') +
                    socket.inet_aton(src) + socket.inet_aton(dst))

        self.assertTrue(classify_process_redirect_ipv4_fragment(
            raw('10.0.0.5', '93.184.216.34', 0x2000), True,
            '93.184.216.34', '192.168.204.1', '10.0.0.5'))
        self.assertTrue(classify_process_redirect_ipv4_fragment(
            raw('192.168.204.1', '10.0.0.5', 0x0001), False,
            '93.184.216.34', '192.168.204.1', '10.0.0.5'))
        self.assertFalse(classify_process_redirect_ipv4_fragment(
            raw('192.168.204.2', '10.0.0.5', 0x0001), False,
            '93.184.216.34', '192.168.204.1', '10.0.0.5'))

    def test_route_guard_requires_frozen_source_interface_and_exact_snapshots(self):
        expected = (
            snapshot('93.184.216.34'),
            snapshot('192.168.204.1', prefix='192.168.204.0/24',
                     next_hop='0.0.0.0'),
        )
        current = [expected]
        guard = ProcessRedirectRouteGuard(
            expected, lambda: current[0])
        packet = PacketTuple(
            'outbound', 4, False, 'TCP', 0x02,
            '10.0.0.5', 50000, '93.184.216.34', 443, 7, 0)

        self.assertTrue(guard.is_current(packet))
        self.assertFalse(guard.is_current(PacketTuple(
            'outbound', 4, False, 'TCP', 0x02,
            '10.0.0.6', 50000, '93.184.216.34', 443, 7, 0)))

        current[0] = (
            snapshot('93.184.216.34', interface=8), expected[1])
        self.assertFalse(guard.refresh())
        self.assertEqual('route_snapshot_changed', guard.failure_reason)
        self.assertFalse(guard.validate_resume())

    def test_route_guard_distinguishes_query_timeout_from_route_drift(self):
        expected = (
            snapshot('93.184.216.34'),
            snapshot('192.168.204.1', prefix='192.168.204.0/24',
                     next_hop='0.0.0.0'),
        )

        def timed_out_reader():
            try:
                raise subprocess.TimeoutExpired('powershell.exe', 10)
            except subprocess.TimeoutExpired as exc:
                raise PolicyConfigError(
                    'process redirect route query exceeded 10 seconds') from exc

        guard = ProcessRedirectRouteGuard(expected, timed_out_reader)

        self.assertFalse(guard.refresh())
        self.assertEqual('route_query_timeout', guard.failure_reason)
        self.assertEqual('PolicyConfigError', guard.failure_error)
        self.assertIn('exceeded 10 seconds', guard.failure_detail)

    def test_process_route_reader_requires_weak_host_and_preferred_source(self):
        diverter = Diverter.__new__(Diverter)
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.process_redirect_rule.original_ipv4 = (
            '93.184.216.34')
        diverter.egress_policy.process_redirect_rule.target_ipv4 = (
            '192.168.204.1')
        diverter.egress_policy.is_exact_local_ipv4.return_value = True
        rows = []
        for item in (
                snapshot('93.184.216.34'),
                snapshot('192.168.204.1', prefix='192.168.204.0/24',
                         next_hop='0.0.0.0')):
            item.update({
                'weak_host_send': 'Disabled',
                'weak_host_receive': 'Disabled',
                'address_state': 'Preferred',
                'skip_as_source': False,
            })
            rows.append(item)
        diverter._run_process_redirect_route_checker = mock.Mock(
            return_value=(0, json.dumps(rows), ''))

        self.assertEqual(
            2, len(diverter._read_process_redirect_route_snapshots()))

        rows[0]['weak_host_send'] = 'Enabled'
        diverter._run_process_redirect_route_checker.return_value = (
            0, json.dumps(rows), '')
        with self.assertRaisesRegex(Exception, 'weak-host'):
            diverter._read_process_redirect_route_snapshots()

    def test_rewrite_decision_is_one_adapter_transaction(self):
        diverter = Diverter.__new__(Diverter)
        diverter.write_pcap = mock.Mock()
        diverter._send_packet = mock.Mock(return_value=True)
        diverter.log_egress_event = mock.Mock()
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.process_redirect_rule.image_sha256 = 'a' * 64
        diverter.process_redirect_engine = mock.Mock()
        diverter.process_redirect_engine.prepare.return_value = PreparedRedirect(
            ProcessRedirectDecision(
                ProcessRedirectAction.REWRITE_OUTBOUND, 'new_mapping', 9,
                rewrite_target_ipv4='192.168.204.1',
                rewrite_target_port=443), token=17)
        packet = mock.Mock()
        packet.proto = 'TCP'
        packet.src_ip = packet.src_ip0 = '10.0.0.5'
        packet.sport = packet.sport0 = 50000
        packet.dst_ip = packet.dst_ip0 = '93.184.216.34'
        packet.dport = packet.dport0 = 443
        packet.ipver = 4
        packet.interface_index = 7
        packet.subinterface_index = 0
        packet.is_outbound = True
        packet.hdr.data.flags = 0x02

        handled = diverter._apply_process_redirect(packet)

        self.assertTrue(handled)
        self.assertEqual('192.168.204.1', packet.dst_ip)
        diverter.write_pcap.assert_called_once_with(packet)
        diverter._send_packet.assert_called_once_with(packet)
        diverter.process_redirect_engine.commit.assert_called_once_with(
            17, True)
        diverter.process_redirect_engine.abort.assert_not_called()
        diverter.log_egress_event.assert_called_with(
            'PROCESS_REDIRECT_INJECT_CALL_SUCCEEDED',
            action='REWRITE_OUTBOUND', generation=9)

    def test_pcap_failure_aborts_token_without_injection(self):
        diverter = Diverter.__new__(Diverter)
        diverter.write_pcap = mock.Mock(side_effect=RuntimeError('pcap'))
        diverter._send_packet = mock.Mock()
        diverter.log_egress_event = mock.Mock()
        diverter.process_redirect_engine = mock.Mock()
        diverter.process_redirect_engine.prepare.return_value = PreparedRedirect(
            ProcessRedirectDecision(
                ProcessRedirectAction.REWRITE_INBOUND, 'reverse_mapping', 4,
                rewrite_source_ipv4='93.184.216.34',
                rewrite_source_port=443), token=12)
        packet = mock.Mock()
        packet.proto = 'TCP'
        packet.src_ip = packet.src_ip0 = '192.168.204.1'
        packet.sport = packet.sport0 = 443
        packet.dst_ip = packet.dst_ip0 = '10.0.0.5'
        packet.dport = packet.dport0 = 50000
        packet.ipver = 4
        packet.interface_index = 7
        packet.subinterface_index = 0
        packet.is_outbound = False
        packet.hdr.data.flags = 0x10

        with self.assertRaises(RuntimeError):
            diverter._apply_process_redirect(packet)

        diverter.process_redirect_engine.abort.assert_called_once_with(
            12, reason='RuntimeError')
        diverter._send_packet.assert_not_called()

    def test_route_refresh_failure_suspends_only_process_redirect_engine(self):
        diverter = Diverter.__new__(Diverter)
        diverter._stopping = mock.Mock()
        diverter._stopping.wait.side_effect = [False, True]
        diverter._stopping.is_set.return_value = False
        diverter.get_adapters_info = mock.Mock(return_value=[])
        diverter.get_ipaddresses = mock.Mock(return_value=[])
        diverter.external_ip = '10.0.0.5'
        diverter.egress_policy = mock.Mock()
        diverter.egress_policy.takeover_available.return_value = False
        diverter.egress_policy.update_local_ipv4.return_value = True
        diverter.egress_policy.reviewed_ipv4_enabled = False
        diverter.egress_policy.drain_expired_leases.return_value = []
        diverter.egress_policy.process_redirect_rule.original_ipv4 = (
            '93.184.216.34')
        diverter.egress_policy.process_redirect_rule.target_ipv4 = (
            '192.168.204.1')
        diverter.process_redirect_engine = mock.Mock()
        diverter.process_redirect_engine.settings.return_value = {
            'available': True}
        diverter.process_redirect_engine.drain_audit_summary.return_value = None
        diverter._process_redirect_route_guard = mock.Mock()
        diverter._process_redirect_route_guard.refresh.return_value = False
        diverter._process_redirect_route_guard.failure_reason = (
            'route_query_timeout')
        diverter._process_redirect_route_guard.failure_error = (
            'PolicyConfigError')
        diverter._process_redirect_route_guard.failure_detail = (
            'process redirect route query exceeded 10 seconds')
        diverter.log_egress_event = mock.Mock()
        diverter.logger = mock.Mock()
        diverter._flush_reviewed_ip_audit = mock.Mock()

        diverter._refresh_local_addresses()

        diverter.process_redirect_engine.suspend.assert_called_once_with(
            'route_query_timeout')
        diverter.egress_policy.suspend.assert_not_called()
        diverter.log_egress_event.assert_called_with(
            'PROCESS_REDIRECT_SUSPEND', reason='route_query_timeout',
            error='PolicyConfigError',
            detail='process redirect route query exceeded 10 seconds')

    def test_timed_write_pcap_delegates_and_returns_underlying_value(self):
        diverter = Diverter.__new__(Diverter)
        diverter.log_egress_event = mock.Mock()
        pkt = mock.Mock()
        sentinel = object()
        diverter.write_pcap = mock.Mock(return_value=sentinel)

        result = diverter._timed_write_pcap(pkt)

        diverter.write_pcap.assert_called_once_with(pkt)
        self.assertIs(sentinel, result)
        # Fast path: the wrapper must stay silent (no latency event).
        diverter.log_egress_event.assert_not_called()

    def test_is_current_does_not_block_while_refresh_runs_route_reader(self):
        import threading
        expected = (
            snapshot('93.184.216.34'),
            snapshot('192.168.204.1', prefix='192.168.204.0/24',
                     next_hop='0.0.0.0'),
        )
        reader_started = threading.Event()
        release_reader = threading.Event()

        def blocking_reader():
            reader_started.set()
            release_reader.wait(10)
            return expected

        guard = ProcessRedirectRouteGuard(expected, blocking_reader)
        # Pre-validate so is_current() does not itself trigger refresh().
        guard._first_validated = True
        guard._available = True
        packet = PacketTuple(
            'outbound', 4, False, 'TCP', 0x02,
            guard.frozen_local_ipv4, 50000, '93.184.216.34', 443,
            guard.frozen_interface_index, 0)

        refresh_thread = threading.Thread(target=guard.refresh)
        refresh_thread.start()
        self.assertTrue(reader_started.wait(2),
                        'route reader never started')
        # While refresh()'s reader is mid-flight, is_current() must return
        # promptly: the route-checker subprocess must run outside the lock.
        done = threading.Event()
        result = {}

        def call_current():
            result['current'] = guard.is_current(packet)
            done.set()

        current_thread = threading.Thread(target=call_current)
        current_thread.start()
        self.assertTrue(done.wait(2),
                        'is_current blocked while refresh ran the reader')
        release_reader.set()
        refresh_thread.join(2)
        self.assertTrue(result.get('current'))


if __name__ == '__main__':
    unittest.main()
