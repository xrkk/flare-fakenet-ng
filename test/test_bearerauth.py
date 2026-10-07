# Copyright 2026 Google LLC
"""Bearer gate unit tests (pure ASGI, no network)."""
import asyncio
import json
import sys
import unittest
from unittest import mock

sys.path.insert(0, '.')

from fakenet.mcp.bearerauth import BearerAuthMiddleware, load_token


class Recorder:
    def __init__(self):
        self.calls = []

    async def __call__(self, scope, receive, send):
        self.calls.append(scope)


def run(middleware, headers):
    inner = Recorder()
    wrapped = BearerAuthMiddleware(inner, 'secret-token') if middleware is None else middleware
    sent = []

    async def receive():
        return {'type': 'http.request', 'body': b''}

    async def send(message):
        sent.append(message)

    scope = {'type': 'http', 'path': '/mcp',
             'headers': [(k.encode(), v.encode()) for k, v in headers.items()]}
    asyncio.run(wrapped(scope, receive, send))
    return inner, sent


class BearerTests(unittest.TestCase):
    def test_missing_or_wrong_token_rejected_401(self):
        for headers in ({}, {'Authorization': 'Bearer wrong'},
                        {'Authorization': 'Basic secret-token'},
                        {'Authorization': 'bearer secret-token'}):
            inner, sent = run(None, headers)
            self.assertFalse(inner.calls, headers)
            start = sent[0]
            self.assertEqual(start['status'], 401)
            body = json.loads(sent[1]['body'])
            self.assertEqual(body['error']['code'], -32001)

    def test_correct_token_passes_through(self):
        inner = Recorder()
        wrapped = BearerAuthMiddleware(inner, 'secret-token')
        _, sent = run(wrapped, {'Authorization': 'Bearer secret-token'})
        self.assertEqual(len(inner.calls), 1)
        self.assertFalse(sent)  # inner recorder never sends

    def test_non_endpoint_path_not_gated(self):
        app = BearerAuthMiddleware(Recorder(), 'secret-token')
        sent = []
        async def receive():
            return {'type': 'http.request', 'body': b''}
        async def send(message):
            sent.append(message)
        scope = {'type': 'http', 'path': '/other',
                 'headers': []}
        inner = Recorder()
        asyncio.run(BearerAuthMiddleware(inner, 'secret-token')(scope, receive, send))
        self.assertEqual(len(inner.calls), 1)

    def test_empty_token_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            BearerAuthMiddleware(Recorder(), '')

    def test_load_token(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile('w', suffix='.tok', delete=False) as handle:
            handle.write('  abc123  \n')
            name = handle.name
        try:
            self.assertEqual(load_token(name), 'abc123')
            open(name, 'w').write('   ')
            with self.assertRaises(ValueError):
                load_token(name)
        finally:
            os.unlink(name)


if __name__ == '__main__':
    unittest.main()
