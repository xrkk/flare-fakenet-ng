# Copyright 2026 Google LLC
"""Optional bearer-token gate for the fakenetng MCP endpoint (LNX-FN).

MalTrace's LNX-FN contract requires that the management MCP identity cannot
be spoofed by an ordinary sample.  The cooperative controller header is not
authentication (REQ-009), so Linux deployments additionally enable this
gate: requests must carry ``Authorization: Bearer <token>`` where the token
lives in a root-owned 0600 file.  The gate is OFF unless a token is
configured, so existing Windows deployments are unchanged.
"""
import hmac
import json


class BearerAuthMiddleware:
    """Pure ASGI middleware; wraps the app ahead of the transport guard."""

    def __init__(self, app, token, endpoint_path='/mcp'):
        if not token or not isinstance(token, str):
            raise ValueError('bearer token must be a non-empty string')
        self.app = app
        self.token = token
        self.endpoint_path = endpoint_path

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http' or scope.get('path') != self.endpoint_path:
            await self.app(scope, receive, send)
            return
        headers = {k.decode('latin-1').lower(): v.decode('latin-1')
                   for k, v in scope.get('headers', [])}
        provided = headers.get('authorization', '')
        expected = 'Bearer ' + self.token
        if not hmac.compare_digest(provided, expected):
            body = json.dumps({
                'jsonrpc': '2.0', 'id': None,
                'error': {'code': -32001, 'message': 'AUTH_FAILED'},
            }).encode()
            await send({'type': 'http.response.start', 'status': 401,
                        'headers': [(b'content-type', b'application/json'),
                                    (b'content-length', str(len(body)).encode())]})
            await send({'type': 'http.response.body', 'body': body})
            return
        await self.app(scope, receive, send)


def load_token(path):
    """Read the bearer token from a file (root 0600 in deployment)."""
    with open(path, 'r', encoding='utf-8') as handle:
        token = handle.read().strip()
    if not token:
        raise ValueError('token file is empty: %s' % path)
    return token
