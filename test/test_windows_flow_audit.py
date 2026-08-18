# -*- coding: utf-8 -*-
"""Host-side checks for PROCESS_FLOW attribution (plan v1.32 12.32.2)."""

import logging
from unittest import mock

from fakenet.diverters.egresspolicy import Verdict
from fakenet.diverters.windows import Diverter


class Lease(object):
    domain = 'api.deepseek.com'


class FlowPolicy(object):
    relay_port = 38927

    def is_exact_local_ipv4(self, value):
        return value in ('127.0.0.1', '10.0.0.5')

    def lease_for(self, ip, port):
        return Lease() if ip == '93.184.216.34' else None

    def matches_takeover_sink(self, proto, src_ip, sport, dst_ip, dport):
        return False


class _HdrData(object):
    def __init__(self, flags=0x02):
        self.flags = flags


class _Hdr(object):
    def __init__(self, flags=0x02):
        self.data = _HdrData(flags)


class FlowPacket(object):
    is_outbound = True
    proto = 'TCP'
    src_ip0 = '10.0.0.5'
    sport0 = 50000
    dst_ip0 = '93.184.216.34'
    dport0 = 443
    src_ip = '10.0.0.5'
    sport = 50000
    dst_ip = '93.184.216.34'
    dport = 443

    def __init__(self, **overrides):
        self.hdr = _Hdr()
        for key, value in overrides.items():
            setattr(self, key, value)


def make_diverter():
    diverter = Diverter.__new__(Diverter)
    diverter.egress_policy = FlowPolicy()
    diverter.egress_control_mode = True
    diverter._flow_audit = {}
    diverter._flow_audit_suspended = False
    diverter._flow_audit_last_cleanup = 0.0
    diverter.logger = logging.getLogger('flow-audit-test')
    return diverter


def events_of(diverter):
    return [call for call in diverter.log_egress_event.call_args_list]


def test_first_packet_emits_process_flow_with_owner_and_domain():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock(return_value=(4242, 'malware.exe'))
    diverter.log_egress_event = mock.Mock()

    verdict = diverter.finalize_egress_verdict(FlowPacket(), takeover_sink=True)

    assert verdict == Verdict.DROP_EXTERNAL  # sink mismatch in this stub
    assert diverter.log_egress_event.call_count == 1
    event, fields = diverter.log_egress_event.call_args[0][0], \
        diverter.log_egress_event.call_args[1]
    assert event == 'PROCESS_FLOW'
    assert fields['pid'] == 4242
    assert fields['process'] == 'malware.exe'
    assert fields['disposition'] == 'DROP_EXTERNAL'
    assert fields['domain'] == 'api.deepseek.com'
    assert fields['dst'] == '93.184.216.34'


def test_subsequent_packets_do_not_reemit_and_tcp_teardown_evicts():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock(return_value=(1, 'a.exe'))
    diverter.log_egress_event = mock.Mock()

    diverter.finalize_egress_verdict(FlowPacket())
    assert diverter.log_egress_event.call_count == 1

    diverter.finalize_egress_verdict(FlowPacket())
    assert diverter.log_egress_event.call_count == 1
    diverter.get_pid_comm.assert_called_once()

    # FIN (0x01) tears the flow down; a fresh SYN emits again
    fin = FlowPacket()
    fin.hdr.data.flags = 0x01
    diverter.finalize_egress_verdict(fin)
    assert diverter.log_egress_event.call_count == 1

    diverter.finalize_egress_verdict(FlowPacket())
    assert diverter.log_egress_event.call_count == 2


def test_owner_resolution_failure_degrades_to_unknown_not_crash():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock(side_effect=OSError('boom'))
    diverter.log_egress_event = mock.Mock()

    verdict = diverter.finalize_egress_verdict(FlowPacket())
    assert verdict is not None
    fields = diverter.log_egress_event.call_args[1]
    assert fields['pid'] == 'unknown'
    assert fields['process'] == 'unknown'
    assert fields['domain'] == 'api.deepseek.com'


def test_unresolved_owner_does_not_requery_per_packet():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock(return_value=(None, None))
    diverter.log_egress_event = mock.Mock()

    diverter.finalize_egress_verdict(FlowPacket())
    diverter.finalize_egress_verdict(FlowPacket())
    diverter.get_pid_comm.assert_called_once()
    assert diverter.log_egress_event.call_count == 1


def test_audit_suspends_after_internal_failure_and_never_breaks_verdict():
    diverter = make_diverter()
    diverter.log_egress_event = mock.Mock(
        side_effect=RuntimeError('logger broke'))

    verdict = diverter.finalize_egress_verdict(FlowPacket())
    assert verdict is not None
    assert diverter._flow_audit_suspended

    # suspended: no further work, verdict still computed
    diverter.get_pid_comm = mock.Mock()
    verdict = diverter.finalize_egress_verdict(FlowPacket())
    assert verdict is not None
    diverter.get_pid_comm.assert_not_called()


def test_non_outbound_and_legacy_mode_are_skipped():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock()
    diverter.log_egress_event = mock.Mock()

    inbound = FlowPacket(is_outbound=False)
    diverter.finalize_egress_verdict(inbound)
    diverter.get_pid_comm.assert_not_called()

    diverter.egress_control_mode = False
    diverter.finalize_egress_verdict(FlowPacket())
    diverter.get_pid_comm.assert_not_called()
    assert diverter.log_egress_event.call_count == 0


def test_space_in_process_name_is_sanitized_for_kwargs_parsing():
    diverter = make_diverter()
    diverter.get_pid_comm = mock.Mock(return_value=(7, 'my malware.exe'))
    diverter.log_egress_event = mock.Mock()

    diverter.finalize_egress_verdict(FlowPacket())
    fields = diverter.log_egress_event.call_args[1]
    assert fields['process'] == 'my_malware.exe'
    assert ' ' not in fields['process']
