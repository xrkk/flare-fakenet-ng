# Copyright 2026 Google LLC
"""Repeatable fault injection for acceptance (P04 IMP-P04-05).

Five RACC-013 fault classes with distinct, attributable mechanisms.  Only
active when the service process runs with
``FAKENETNG_MCP_FAULT_INJECTION=1`` AND a fault is explicitly armed via
the fixed local ``logs/fault-injection.json``; never exposed as an MCP tool, disabled by
default in production.

Faults:
  policy_pause      — the stop sequence stalls before the listener phase
  listener_stop     — a running listener's listening socket is shut down
  diverter_stop     — the main WinDivert handle is closed directly
  child_hang        — a managed-range child process refuses to exit
  cleanup_error     — the stop sequence raises at a chosen phase
"""

import os
import socket
import threading
import time
import json
from pathlib import Path

FAULTS = ('policy_pause', 'listener_stop', 'diverter_stop', 'child_hang',
          'cleanup_error')


def enabled():
    return os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') == '1'


def armed_fault():
    path = _fault_file()
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if set(data) == {'fault', 'nonce'} and data['fault'] in FAULTS and data['nonce']:
                return data['fault']
        except (OSError, ValueError, TypeError):
            return None
    return None


def _fault_file():
    return Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'FakeNet-NG-MCP' / 'logs' / 'fault-injection.json'


def clear():
    path = _fault_file()
    if enabled() and path.is_file():
        receipt = Path.cwd() / 'fault-triggered.json'
        # Each run has its own directory. Retain the exact nonce/class for
        # the native runner; never overwrite another run's receipt.
        with receipt.open('x', encoding='utf-8') as stream:
            stream.write(path.read_text(encoding='utf-8'))
        path.unlink()


class FaultInjector:

    """Hooks consumed by the supervisor's stop/start path."""

    def __init__(self):
        self._held_sockets = []
        self._child = None

    def arm(self, fault):
        if fault not in FAULTS:
            raise ValueError('unknown fault %r' % fault)
        import uuid
        path = _fault_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('x', encoding='utf-8') as stream:
            json.dump({'fault': fault, 'nonce': str(uuid.uuid4())}, stream)

    # -- stop-path hooks ---------------------------------------------------
    def before_listener_phase(self):
        if enabled() and armed_fault() == 'policy_pause':
            clear()
            time.sleep(3600)

    def on_stop_error(self):
        """cleanup_error: raise once when the stop sequence runs."""
        if enabled() and armed_fault() == 'cleanup_error':
            clear()
            raise RuntimeError('injected cleanup error')

    # -- run-path hooks -----------------------------------------------------
    def inject_listener_stop(self, listeners):
        """Close the first bound listener socket (representative class)."""
        if not (enabled() and armed_fault() == 'listener_stop'):
            return False
        clear()
        for listener in listeners or []:
            sock = getattr(listener, 'sock', None) or getattr(
                listener, 'socket', None) or getattr(getattr(listener, 'server', None), 'socket', None)
            if isinstance(sock, socket.socket):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return True
                except OSError:
                    continue
        return False

    def inject_diverter_stop(self, diverter):
        if not (enabled() and armed_fault() == 'diverter_stop'):
            return False
        clear()
        handle = getattr(diverter, 'handle', None)
        if handle is None:
            return False
        try:
            handle.close()
        finally:
            diverter.handle = None
        return True

    def inject_child_hang(self):
        """Spawn a managed-range child that refuses to exit."""
        if not (enabled() and armed_fault() == 'child_hang'):
            return False
        clear()
        import subprocess
        import sys

        prefix = ([sys.executable] if getattr(sys, 'frozen', False) else
                  [sys.executable, '-m', 'fakenet.mcp'])
        self._child = subprocess.Popen(
            prefix + ['managed-fault-hang'],
            creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
        return True

    def release(self):
        for sock in self._held_sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._held_sockets = []
        if self._child is not None:
            try:
                self._child.terminate()
                self._child.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
            self._child = None
