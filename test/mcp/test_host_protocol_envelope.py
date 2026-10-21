"""Exercise the actual HTTP client against the deployed stateless envelope rule."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from fakenet.mcp.host_stdio import FakeNetHttpClient, PROTOCOL_VERSION


def test_tools_list_sends_stateless_protocol_envelope():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            seen.append(request)
            meta = request.get('params', {}).get('_meta', {})
            valid = (meta.get('io.modelcontextprotocol/protocolVersion') == PROTOCOL_VERSION
                     and isinstance(meta.get('io.modelcontextprotocol/clientCapabilities'), dict))
            self.send_response(200 if valid else 400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body = {'jsonrpc': '2.0', 'id': 1, 'result': {'tools': [
                {'name': name} for name in ('get_status', 'read_config', 'verify_egress_isolation')]}}
            self.wfile.write(json.dumps(body).encode())

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        client = FakeNetHttpClient({'url': 'http://127.0.0.1:%d/mcp' % server.server_port,
                                    'controller_id': '11111111-2222-4333-8444-555555555555'})
        assert len(client.list_tools(timeout=3)) == 3
        assert len(seen) == 1
        assert seen[0]['method'] == 'tools/list'
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
