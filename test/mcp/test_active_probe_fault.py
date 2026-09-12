import json
import socket
import threading
from types import SimpleNamespace

from fakenet.mcp.faultinject import FaultInjector
from fakenet.mcp.managed import probe_with_faults


def test_armed_health_request_closes_handle_after_healthy(tmp_path, monkeypatch):
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    monkeypatch.chdir(tmp_path)
    class Handle:
        def __init__(self):
            self.socket = socket.socket()
        @property
        def is_open(self):
            return self.socket.fileno() >= 0
        def close(self):
            self.socket.close()
    handle = Handle()
    listener = socket.socket()
    try:
        diverter = SimpleNamespace(handle=handle,
                                   diverter_thread=threading.current_thread())
        def close_diverter_handle():
            diverter.handle.close()
            diverter.handle = None
        diverter._close_windivert_handle = close_diverter_handle
        instance = SimpleNamespace(diverter=diverter,
            running_listener_providers=[SimpleNamespace(sock=listener)])
        fault = FaultInjector()
        assert probe_with_faults(instance, fault)['probe']
        fault.arm('diverter_stop')
        observed = probe_with_faults(instance, fault)
        assert not observed['probe']
        assert observed['init_evidence']
        assert observed['capture_threads_alive']
        assert not handle.is_open and listener.fileno() >= 0
        assert json.loads((tmp_path / 'fault-triggered.json').read_text())['fault'] == 'diverter_stop'
    finally:
        handle.close()
        listener.close()
