"""Synthetic counterexamples; these cannot qualify a real VM scenario."""
import importlib.util
from pathlib import Path

import pytest

SOURCE = Path(__file__).parent / 'acceptance/scenario_pktmon.py'
SPEC = importlib.util.spec_from_file_location('scenario_pktmon', SOURCE)
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)

HEADER = ('[00]1374.12F4::2026-09-12 21:53:47.559793400 '
          '[Microsoft-Windows-PktMon] PktGroupId 21788，PktNumber 1，出现 1，'
          '方向 Tx ，类型 以太网 ，组件 9，边缘 1，筛选器 0，OriginalSize 66，LoggedSize 66\r\n')
BODY = ('\t00-0C-29-C1-CA-49 > 00-50-56-E7-FE-AA, ethertype IPv4 (0x0800), '
        'length 66: 192.168.204.233.63813 > 198.51.100.77.1337: Flags [S], seq 1\r\n')
SRC, DST = '192.168.204.233:63813', '198.51.100.77:1337'


@pytest.mark.parametrize('codec', ['utf-8', 'utf-8-sig', 'utf-16'])
def test_preserves_original_byte_offsets(codec):
    raw = (HEADER + BODY).encode(codec)
    packet, = p.parse_packets(raw)
    assert packet['component'] == 9 and packet['direction'] == 'Tx'
    assert packet['protocol'] == 'TCP' and packet['src'] == SRC and packet['dst'] == DST
    assert raw[packet['byte_start']:packet['byte_end']].decode(
        'utf-16-le' if codec == 'utf-16' else 'utf-8') == HEADER + BODY


def test_internal_tuple_is_not_nic_leak_but_real_nic_packet_is():
    internal = p.parse_packets((HEADER.replace('组件 9', '组件 42') + BODY).encode())
    assert p.select_packets(internal, SRC, DST, 'TCP', component_ids={9}, direction='Tx') == []
    external = p.parse_packets((HEADER + BODY).encode())
    assert len(p.select_packets(internal + external, SRC, DST, 'TCP', component_ids={9}, direction='Tx')) == 1
    assert not p.select_packets(external, SRC + '0', DST, 'TCP', component_ids={9}, direction='Tx')
    assert not p.select_packets(external, SRC, DST + '0', 'TCP', component_ids={9}, direction='Tx')


def test_direction_and_transport_are_not_inferred_from_tuple():
    incoming = p.parse_packets((HEADER.replace('方向 Tx', '方向 Rx') + BODY).encode())
    assert not p.select_packets(incoming, SRC, DST, 'TCP', component_ids={9}, direction='Tx')
    udp = p.parse_packets((HEADER + BODY.replace('Flags [S], seq 1', 'UDP, length 12')).encode())
    assert len(p.select_packets(udp, SRC, DST, 'UDP', component_ids={9}, direction='Tx')) == 1
    assert not p.select_packets(udp, SRC, DST, 'TCP', component_ids={9}, direction='Tx')


@pytest.mark.parametrize('changed', [HEADER.replace('组件 9', 'unknown 9'),
                                   HEADER.replace('方向 Tx', 'unknown Tx'),
                                   HEADER.replace('LoggedSize 66', 'LoggedSize 20')])
def test_unknown_or_truncated_matching_evidence_cannot_prove_absence(changed):
    with pytest.raises(p.PacketEvidenceError):
        p.select_packets(p.parse_packets((changed + BODY).encode()), SRC, DST, 'TCP',
                         component_ids={9}, direction='Tx')


def test_missing_component_binding_is_not_absence_proof():
    with pytest.raises(p.PacketEvidenceError):
        p.select_packets([], SRC, DST, 'TCP', component_ids=set(), direction='Tx')


def test_unknown_payload_protocol_is_not_silently_ignored():
    rows = p.parse_packets((HEADER + BODY.replace('Flags [S], seq 1', 'unknown')).encode())
    with pytest.raises(p.PacketEvidenceError):
        p.select_packets(rows, SRC, DST, 'UDP', component_ids={9}, direction='Tx')
