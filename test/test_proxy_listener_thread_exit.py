"""A proxied-listener close must end the proxy thread without SystemExit.

The managed runtime reports any exception escaping a thread as an
unhandled thread exception; sys.exit in the proxy client thread turned a
benign probe hangup into a failed run (maintainer handoff 2026-09-12,
run f464a287 / c886473a).
"""
import queue
import socket
import threading

from fakenet.listeners.ProxyListener import ThreadedTCPClientSocket


class _ClosedRemoteSocket:
    """Behaves like a socket whose peer already closed."""

    def select_ready(self):
        return True

    def recv(self, n):
        return b''

    def close(self):
        self.closed = True


def test_proxy_thread_returns_on_remote_close(monkeypatch):
    thread = ThreadedTCPClientSocket('127.0.0.1', 8080, queue.Queue(), queue.Queue(),
                                     {}, logging_stub())
    remote = _ClosedRemoteSocket()
    monkeypatch.setattr(thread, 'sock', remote)
    monkeypatch.setattr('fakenet.listeners.ProxyListener.select.select',
                        lambda r, w, x, t: (list(r), [], []))
    # Must return cleanly; sys.exit would raise SystemExit out of run().
    assert thread.run() is None
    assert remote.closed is True


def test_proxy_thread_survives_queue_send_error(monkeypatch):
    thread = ThreadedTCPClientSocket('127.0.0.1', 8080, queue.Queue(), queue.Queue(),
                                     {}, logging_stub())
    remote = _ClosedRemoteSocket()
    sent = []

    class BrokenQueue:
        def empty(self):
            return True

    monkeypatch.setattr(thread, 'sock', remote)
    monkeypatch.setattr('fakenet.listeners.ProxyListener.select.select',
                        lambda r, w, x, t: (list(r), [], []))
    thread.run()
    assert remote.closed is True


class logging_stub:
    def debug(self, *a, **k):
        pass

    warning = error = info = debug
