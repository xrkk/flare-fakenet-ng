import socket
import threading
from types import SimpleNamespace

from fakenet.mcp.managed import probe_instance


def test_capture_worker_exit_revokes_health_even_with_open_handles():
    release = threading.Event()
    ready = threading.Event()
    def run():
        ready.set()
        release.wait(3)
    thread = threading.Thread(target=run)
    thread.start()
    listener = socket.socket()
    try:
        assert ready.wait(1)
        instance = SimpleNamespace(diverter=SimpleNamespace(
            handle=SimpleNamespace(is_open=True), diverter_thread=thread),
            running_listener_providers=[SimpleNamespace(sock=listener)])
        assert probe_instance(instance)['probe']
        release.set()
        thread.join(1)
        observed = probe_instance(instance)
        assert observed['init_evidence']
        assert not observed['probe']
        assert not observed['capture_threads_alive']
        assert listener.fileno() >= 0
        assert instance.diverter.handle.is_open
    finally:
        release.set()
        thread.join(1)
        listener.close()


def test_recorded_capture_failure_revokes_health_before_worker_exits():
    listener = socket.socket()
    try:
        instance = SimpleNamespace(diverter=SimpleNamespace(
            handle=SimpleNamespace(is_open=True), diverter_thread=threading.current_thread(),
            capture_failure=RuntimeError('writer failed')),
            running_listener_providers=[SimpleNamespace(sock=listener)])
        observed = probe_instance(instance)
        assert observed['capture_threads_alive']
        assert not observed['probe']
        assert observed['capture_error'] == 'writer failed'
    finally:
        listener.close()
