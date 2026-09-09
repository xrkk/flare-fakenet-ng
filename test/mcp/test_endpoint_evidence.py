"""Native AFD evidence includes pointer reuse across two DNS queries and Edge."""
import json
from pathlib import Path

import pytest

from fakenet.mcp.endpoint_evidence import socket_address, udp_lifetimes


def events():
    return json.loads((Path(__file__).parent / 'fixtures' / 'native_afd_socket_reuse.json').read_text())['events']


def test_native_same_pointer_has_three_separate_udp_lifetimes():
    rows = [r for r in udp_lifetimes(events()) if r['bound']]
    assert [(r['pid'], r['bound']['port']) for r in rows] == [(7092, 54811), (7092, 63443), (7316, 63444)]
    assert len({r['endpoint_pointer'] for r in rows}) == 1
    assert all(r['creation_succeeded'] and r['closed'] is not None for r in rows)
    assert all(r['requested_bind']['port'] == 0 for r in rows)
    assert [len(r['outbound']) for r in rows] == [3, 3, 4]
    assert all(s['destination']['port'] == 53 for r in rows[:2] for s in r['outbound'])
    assert all(s['destination']['port'] == 1900 for s in rows[2]['outbound'])
    assert rows[0]['closed'] < rows[1]['created'] < rows[1]['closed'] < rows[2]['created']


def test_missing_bind_cannot_borrow_previous_generation_port():
    source = events()
    rows = udp_lifetimes(source)
    second = next(r for r in rows if (r['bound'] or {}).get('port') == 63443)
    source.pop(second['bind_event'])
    rows = [r for r in udp_lifetimes(source) if r['pid'] == 7092]
    assert rows[0]['bound']['port'] == 54811
    assert rows[1]['bound'] is None


def test_missing_close_is_not_inferred_from_pointer_reuse():
    source = events()
    first = next(r for r in udp_lifetimes(source) if (r['bound'] or {}).get('port') == 54811)
    source.pop(first['closed'])
    rows = [r for r in udp_lifetimes(source) if r['pid'] == 7092]
    assert rows[0]['closed'] is None and rows[0]['superseded_without_close']
    assert rows[1]['closed'] is not None


def test_missing_creation_cannot_attach_orphan_events_to_another_process():
    source = events()
    row = next(r for r in udp_lifetimes(source) if r['pid'] == 7316)
    source.pop(row['created'])
    assert not any(r['pid'] == 7316 for r in udp_lifetimes(source))


def test_raw_event_identity_must_match_exported_metadata():
    source = events()
    source[0]['xml'] = source[0]['xml'].replace('Microsoft-Windows-Winsock-AFD', 'DifferentProvider')
    with pytest.raises(ValueError, match='identity'):
        udp_lifetimes(source)


@pytest.mark.parametrize('raw', ['17000000', '02000000', 'FF000000' + '00' * 12])
def test_incomplete_or_unknown_sockaddr_is_not_accepted(raw):
    with pytest.raises(ValueError):
        socket_address(raw)
