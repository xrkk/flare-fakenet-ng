import struct

import fakenet.diverters.windows as windows


def _build_ip_tcp(declared_len, payload=b''):
    """Minimal IPv4+TCP header; declared_len overrides the total-length field."""
    tcp = struct.pack('>HHIIHHHH', 49854, 443, 1, 0, (5 << 12) | 0x02,
                      0xffff, 0, 0)
    wire_len = 20 + 20 + len(payload)
    declared = wire_len if declared_len is None else declared_len
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, declared, 1, 0x4000, 128, 6, 0,
                     bytes([192, 168, 204, 130]), bytes([192, 168, 204, 130]))
    return bytearray(ip + tcp + payload)


class _FakeWdpkt(object):
    def __init__(self, raw):
        self.raw = memoryview(raw)
        self.interface = (1, 0)
        self.is_outbound = True


def test_tso_length_mismatch_is_shrunk_in_place():
    buf = _build_ip_tcp(declared_len=2781, payload=b'\x00' * 1460)
    snapshot = bytes(buf)
    wdpkt = _FakeWdpkt(buf)
    ctx = windows.WindowsPacketCtx('test', wdpkt)

    assert len(wdpkt.raw) == 1500
    assert bytes(wdpkt.raw[2:4]) == struct.pack('>H', 1500)
    assert ctx.tso_length_fix == (2781, 1500)
    # only the total-length field changed; everything else is byte-identical
    patched = bytes(wdpkt.raw)
    assert patched[:2] == snapshot[:2]
    assert patched[4:] == snapshot[4:]
    # the dpkt-side raw copy was built after the patch and agrees
    assert int.from_bytes(ctx._raw[2:4], 'big') == 1500


def test_consistent_packet_is_untouched():
    buf = _build_ip_tcp(declared_len=None, payload=b'payload')
    snapshot = bytes(buf)
    wdpkt = _FakeWdpkt(buf)
    ctx = windows.WindowsPacketCtx('test', wdpkt)

    assert ctx.tso_length_fix is None
    assert bytes(wdpkt.raw) == snapshot


def test_padded_packet_is_untouched():
    # declared < buffer (trailing padding) is tolerated by the driver today
    # and must stay untouched (shrink-only fix)
    buf = _build_ip_tcp(declared_len=60, payload=b'\x00' * 40)
    snapshot = bytes(buf)
    wdpkt = _FakeWdpkt(buf)
    ctx = windows.WindowsPacketCtx('test', wdpkt)

    assert ctx.tso_length_fix is None
    assert bytes(wdpkt.raw) == snapshot


# No IPv6 case here: PacketCtx._parseIp only converts IPv4 addresses and the
# production paths classify IPv6 before WindowsPacketCtx is constructed, so a
# v6 buffer cannot round-trip this constructor at all. The version guard in
# the fix is defensive only.


def test_send_packet_aggregates_and_throttles_reports():
    diverter = windows.Diverter.__new__(windows.Diverter)
    events = []
    diverter.log_egress_event = lambda event, **kw: events.append((event, kw))
    diverter._send_windivert_packet = lambda wdpkt, desc: True

    bufs = [_build_ip_tcp(declared_len=2781, payload=b'\x00' * 60),
            _build_ip_tcp(declared_len=7161, payload=b'\x00' * 60)]
    for buf in bufs:
        ctx = windows.WindowsPacketCtx('test', _FakeWdpkt(buf))
        assert windows.Diverter._send_packet(diverter, ctx) is True

    # both sends counted, but the report is throttled after the first
    assert diverter._tso_length_stats['count'] == 2
    assert len(events) == 1
    event, fields = events[0]
    assert event == 'TSO_LENGTH_FIX'
    assert fields['declared'] == 2781
    assert fields['buffer'] == 100
    assert fields['total'] == 1
