# Copyright 2026 Google LLC
"""ASGI transport guard freezing the modern (2026-07-28 only) MCP contract.

The official SDK server is dual-era by default (it answers legacy
``initialize``).  The P01 contract freezes this service to the modern era
only (REQ-002: no legacy GET SSE/session as the core protocol), so this
pure-ASGI middleware enforces, before the SDK app runs:

* only POST reaches the MCP endpoint (GET/DELETE -> 405, per spec);
* every request carries ``MCP-Protocol-Version: 2026-07-28`` (missing or
  unknown -> 400 with UnsupportedProtocolVersionError(-32022) listing
  supported versions; spec allows rejecting header-less requests because
  pre-2025-06-18 clients are not supported);
* header version must equal the body ``_meta`` protocol version when both
  are present (mismatch -> 400 HeaderMismatch(-32020));
* ``Mcp-Method`` is required and must match the body method; ``Mcp-Name`` is
  required for ``tools/call`` and must match the body tool name (-32020);
* legacy ``initialize``/``notifications/initialized`` are not served: the
  server answers a modern error naming its supported versions so legacy
  clients surface an actionable message (spec compatibility matrix);
* ``Origin`` is never read and never validated (user-adjudicated deviation
  from the 2026-07-28 security clause, see CON-003/NON-004/FB-014);
* ``X-FakeNet-Controller-ID`` is captured (validated UUID format) into a
  ContextVar for domain tools; absence never blocks read-only calls
  (REQ-009: identity is cooperative, not authentication).
"""

import contextvars
import json
import uuid

from fakenet.mcp import CONTROLLER_HEADER, MCP_PROTOCOL_VERSION

JSONRPC_HEADER_MISMATCH = -32020
JSONRPC_UNSUPPORTED_VERSION = -32022  # spec-allocated error code
SUPPORTED_VERSIONS = [MCP_PROTOCOL_VERSION]

controller_header_state = contextvars.ContextVar(
    'fakenetng_mcp_controller_header', default=None)

_METHODS_NEEDING_NAME = frozenset(('tools/call', 'resources/read', 'prompts/get'))
_LEGACY_METHODS = frozenset(('initialize', 'notifications/initialized'))


def classify_controller_header(value):
    """Return one of valid_uuid / missing / invalid_format."""
    if value is None or value == '':
        return 'missing'
    candidate = value.strip()
    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError):
        return 'invalid_format'
    if str(parsed).lower() != candidate.lower():
        return 'invalid_format'
    return 'valid_uuid'


def _error_body(request_id, code, message, data=None):
    error = {'code': code, 'message': message}
    if data is not None:
        error['data'] = data
    return {'jsonrpc': '2.0', 'id': request_id, 'error': error}


class TransportGuardMiddleware:

    def __init__(self, app, endpoint_path='/mcp', logger=None):
        self.app = app
        self.endpoint_path = endpoint_path
        self.logger = logger

    def _log(self, message):
        if self.logger:
            self.logger.info(message)

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        path = scope.get('path', '')
        if path != self.endpoint_path:
            await self.app(scope, receive, send)
            return

        method = scope.get('method', '')
        headers = {}
        for name, value in scope.get('headers', []):
            headers[name.decode('latin-1').lower()] = value.decode('latin-1')

        if method != 'POST':
            await self._plain(send, 405, b'{"error":"method not allowed"}')
            return

        controller_value = headers.get(CONTROLLER_HEADER.lower())
        controller_header_state.set(controller_value)

        version_header = headers.get('mcp-protocol-version')
        if not version_header:
            await self._jsonrpc(send, 400, _error_body(
                None, JSONRPC_HEADER_MISMATCH,
                'Header mismatch: MCP-Protocol-Version header is required',
                {'supported': SUPPORTED_VERSIONS}))
            self._log('rejected: missing MCP-Protocol-Version')
            return
        if version_header != MCP_PROTOCOL_VERSION:
            await self._jsonrpc(send, 400, _error_body(
                None, JSONRPC_UNSUPPORTED_VERSION,
                'Unsupported protocol version', {
                    'supported': SUPPORTED_VERSIONS,
                    'requested': version_header,
                }))
            self._log('rejected: unsupported protocol version %s' % version_header)
            return

        body = await self._read_body(receive)
        message = self._parse_json(body)
        if message is None or not isinstance(message, dict) or 'method' not in message:
            await self._jsonrpc(send, 400, _error_body(
                None, JSONRPC_HEADER_MISMATCH,
                'Header mismatch: request body is not a JSON-RPC request'))
            return

        request_method = message['method']
        request_id = message.get('id')

        if request_method in _LEGACY_METHODS:
            await self._jsonrpc(send, 400, _error_body(
                request_id, JSONRPC_UNSUPPORTED_VERSION,
                'Unsupported protocol version (legacy initialize era not '
                'served; this server speaks MCP %s only)' % MCP_PROTOCOL_VERSION,
                {'supported': SUPPORTED_VERSIONS,
                 'requested': version_header}))
            self._log('rejected: legacy method %s' % request_method)
            return

        method_header = headers.get('mcp-method')
        if not method_header or method_header != request_method:
            await self._jsonrpc(send, 400, _error_body(
                request_id, JSONRPC_HEADER_MISMATCH,
                'Header mismatch: Mcp-Method header missing or does not match body',
                {'header': method_header, 'body': request_method}))
            self._log('rejected: Mcp-Method mismatch')
            return

        if request_method in _METHODS_NEEDING_NAME:
            name_header = headers.get('mcp-name')
            body_name = (message.get('params') or {}).get('name')
            if not name_header or name_header != body_name:
                await self._jsonrpc(send, 400, _error_body(
                    request_id, JSONRPC_HEADER_MISMATCH,
                    'Header mismatch: Mcp-Name header missing or does not match body',
                    {'header': name_header, 'body': body_name}))
                self._log('rejected: Mcp-Name mismatch')
                return

        meta_version = ((message.get('params') or {}).get('_meta') or {}).get(
            'io.modelcontextprotocol/protocolVersion')
        if meta_version is not None and meta_version != version_header:
            await self._jsonrpc(send, 400, _error_body(
                request_id, JSONRPC_HEADER_MISMATCH,
                'Header mismatch: MCP-Protocol-Version does not match body _meta',
                {'header': version_header, 'body': meta_version}))
            self._log('rejected: version header vs _meta mismatch')
            return

        # Replay the body downstream (we consumed it above).
        body_bytes = body if isinstance(body, bytes) else body.encode('utf-8')

        async def replay_receive():
            return {'type': 'http.request', 'body': body_bytes, 'more_body': False}

        await self.app(scope, replay_receive, send)

    async def _read_body(self, receive):
        chunks = []
        while True:
            event = await receive()
            if event['type'] != 'http.request':
                break
            chunks.append(event.get('body', b''))
            if not event.get('more_body'):
                break
        return b''.join(chunks)

    @staticmethod
    def _parse_json(body):
        try:
            return json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return None

    async def _jsonrpc(self, send, status, payload):
        raw = json.dumps(payload).encode('utf-8')
        await send({
            'type': 'http.response.start', 'status': status,
            'headers': [
                (b'content-type', b'application/json'),
                (b'content-length', str(len(raw)).encode('ascii')),
            ],
        })
        await send({'type': 'http.response.body', 'body': raw})

    async def _plain(self, send, status, raw):
        await send({
            'type': 'http.response.start', 'status': status,
            'headers': [
                (b'content-type', b'application/json'),
                (b'content-length', str(len(raw)).encode('ascii')),
            ],
        })
        await send({'type': 'http.response.body', 'body': raw})
