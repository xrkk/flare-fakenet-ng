# -*- coding: utf-8 -*-
"""Shared socket server mixins for listeners (plan v1.22 §12.25).

socketserver's default handle_error prints raw tracebacks straight to
stderr, which never reach the log file.  Listener worker threads must
report through the logging framework so console and file stay consistent.
"""

import logging
import socketserver


class LoggingThreadingMixIn(socketserver.ThreadingMixIn):
    """Threading mixin whose worker exceptions go through logging."""

    daemon_threads = True

    def handle_error(self, request, client_address):
        logger = getattr(self, 'logger', None) or \
            logging.getLogger('fakenet')
        try:
            peer = '%s:%s' % (client_address[0], client_address[1])
        except (TypeError, IndexError):
            peer = str(client_address)
        logger.exception(
            'Exception while processing connection from %s', peer)
