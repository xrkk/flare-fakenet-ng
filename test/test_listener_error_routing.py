# -*- coding: utf-8 -*-
"""Listener worker exception routing (plan v1.22 §12.25).

Two field defects seen in the VM console spam:
  1. socketserver's default handle_error prints raw tracebacks to stderr,
     bypassing the logging framework entirely.
  2. ProxyListener.get_top_listener crashed with AttributeError while the
     diverter reference had not been handed to the listener yet.
"""

import logging
import os
import socketserver
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


def test_get_top_listener_tolerates_missing_diverter():
    from fakenet.listeners.ProxyListener import get_top_listener

    # No diverter reference yet (startup window / no-divert mode): the
    # helper must degrade gracefully instead of raising AttributeError.
    result = get_top_listener({}, b'data', [], None, '127.0.0.1', 12345,
                              'UDP')
    assert result is None


def test_threading_mixin_routes_worker_errors_into_logging(caplog):
    from fakenet.listeners.servermixins import LoggingThreadingMixIn

    class Server(LoggingThreadingMixIn):
        def __init__(self):
            self.logger = logging.getLogger('test.servermixins')

    with caplog.at_level(logging.ERROR, logger='test.servermixins'):
        try:
            raise RuntimeError('worker boom')
        except RuntimeError:
            Server().handle_error(object(), ('10.0.0.1', 5555))
    assert any('10.0.0.1:5555' in record.message or
               '10.0.0.1:5555' in str(record.__dict__.get('msg', ''))
               for record in caplog.records)
    assert any(record.exc_info for record in caplog.records)


def test_all_threaded_listener_servers_use_logging_mixin():
    import importlib
    import pkgutil

    from fakenet.listeners import servermixins
    from fakenet import listeners as listeners_pkg

    checked = 0
    for module_info in pkgutil.iter_modules(listeners_pkg.__path__):
        module = importlib.import_module(
            'fakenet.listeners.%s' % module_info.name)
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and
                    issubclass(obj, socketserver.ThreadingMixIn) and
                    obj is not socketserver.ThreadingMixIn and
                    obj.__module__ == module.__name__):
                assert issubclass(obj, servermixins.LoggingThreadingMixIn), \
                    '%s.%s does not route worker errors into logging' % (
                        module.__name__, attr)
                checked += 1
    assert checked >= 8  # Proxy x2, DNS x2, IRC, POP, SMTP, TFTP, Raw


def test_diverter_starts_after_listener_dependency_injection():
    """Accept wiring must precede diverter.start() so no redirected packet
    can reach a listener whose diverter reference is still None."""
    source_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'fakenet', 'fakenet.py')
    with open(source_path, 'r', encoding='utf-8') as handle:
        source = handle.read()
    accept_pos = source.index('listener.acceptDiverter(self.diverter)')
    diverter_start = source.index('# Start the diverter')
    assert accept_pos < diverter_start
