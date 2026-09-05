# -*- coding: utf-8 -*-
"""Auto upstream DNS selection with probing (plan v1.25 §12.28)."""

import logging
import os
import socket
import sys
import threading

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _udp_responder(port, reply_size=64):
    ready = threading.Event()
    received = []

    def serve():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', port))
        sock.settimeout(5)
        ready.set()
        try:
            data, addr = sock.recvfrom(512)
            received.append(data)
            sock.sendto(b'\x00' * reply_size, addr)
        except OSError:
            pass
        finally:
            sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(2)
    return thread, received


def test_probe_accepts_responder_on_custom_port():
    from fakenet.diverters import windows

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    thread, received = _udp_responder(port)
    assert windows.probe_dns_resolver('127.0.0.1', timeout=2, port=port)
    thread.join(3)
    assert received  # the responder really got our query


def test_probe_rejects_dead_port():
    from fakenet.diverters import windows

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    # nothing listens: ICMP unreachable or timeout, either way not alive
    assert not windows.probe_dns_resolver('127.0.0.1', timeout=0.5,
                                          port=port)


def _minimal_diverter(monkeypatch, probe_results, configured='Auto',
                      dns_list=('192.168.243.1', '192.168.204.2')):
    from fakenet.diverters import windows

    diverter = windows.Diverter.__new__(windows.Diverter)
    diverter.logger = logging.getLogger('test.dns.selection')
    diverter.ip_addrs = {4: ['10.0.0.5']}
    diverter.external_ip = '10.0.0.5'
    diverter.loopback_ip = '127.0.0.1'
    monkeypatch.setattr(diverter, 'getconfigval',
                        lambda key, default=None: configured)
    monkeypatch.setattr(diverter, 'get_dns_servers', lambda: list(dns_list))
    monkeypatch.setattr(windows, 'probe_dns_resolver',
                        lambda resolver, timeout=1.0, port=53:
                        probe_results.get(resolver, False))
    return diverter


def test_selection_skips_dead_first_resolver(monkeypatch):
    diverter = _minimal_diverter(
        monkeypatch, {'192.168.243.1': False, '192.168.204.2': True})
    assert diverter._select_external_dns_server() == '192.168.204.2'


def test_selection_falls_back_to_first_when_none_answer(monkeypatch):
    diverter = _minimal_diverter(monkeypatch, {})
    assert diverter._select_external_dns_server() == '192.168.243.1'


def test_selection_prefers_first_when_it_answers(monkeypatch):
    diverter = _minimal_diverter(
        monkeypatch, {'192.168.243.1': True, '192.168.204.2': True})
    assert diverter._select_external_dns_server() == '192.168.243.1'


def test_selection_explicit_config_skips_probing(monkeypatch):
    diverter = _minimal_diverter(monkeypatch, {}, configured='223.5.5.5')
    assert diverter._select_external_dns_server() == '223.5.5.5'
