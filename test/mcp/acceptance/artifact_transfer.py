"""Bounded transfer of a listed runtime artifact to the authorized host."""
import hashlib
import json
import http.server
import re
import threading
import uuid
from pathlib import Path, PureWindowsPath

from helpers import StepError


def listener_rows(table, port):
    """A TCP TIME_WAIT row is not a live accepting socket."""
    result = []
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
            result.append(line)
    return result


def receive_artifact(channel, artifact, destination):
    source = PureWindowsPath(artifact['path'])
    root = PureWindowsPath('C:/ProgramData/FakeNet-NG-MCP/artifacts')
    if not source.is_relative_to(root) or '..' in source.parts or "'" in str(source):
        raise ValueError('artifact outside registered root')
    size, digest = artifact['size'], artifact['sha256']
    if (not isinstance(size, int) or not 0 < size <= 512 * 1024 * 1024 or
            not re.fullmatch('[0-9a-fA-F]{64}', digest) or not artifact.get('complete')):
        raise ValueError('artifact metadata incomplete or outside transfer bound')
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    token = '/' + uuid.uuid4().hex
    received = {}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_PUT(self):
            self.connection.settimeout(10)
            if (self.client_address[0] != '192.168.204.149' or self.path != token or
                    self.headers.get('Content-Length') != str(size)):
                self.send_error(403)
                return
            actual = hashlib.sha256()
            remaining = size
            try:
                with destination.open('xb') as stream:
                    while remaining:
                        block = self.rfile.read(min(1048576, remaining))
                        if not block:
                            raise StepError('short artifact body')
                        stream.write(block)
                        actual.update(block)
                        remaining -= len(block)
                received.update(size=size, sha256=actual.hexdigest())
                if received['sha256'].lower() != digest.lower():
                    raise StepError('artifact bytes differ from listed hash')
                self.send_response(200)
                self.end_headers()
            except Exception as exc:
                received['error'] = repr(exc)
                self.send_error(409)
        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(('192.168.204.1', 0), Handler)
    port = server.server_address[1]
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        transfer = channel.powershell(
            "$ErrorActionPreference='Stop';$file='" + str(source) + "'; "
            "if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower() -ne '" + digest.lower() + "'){throw 'artifact changed'}; "
            "Invoke-WebRequest -UseBasicParsing -Uri 'http://192.168.204.1:" + str(port) + token + "' -Method Put -InFile $file | Out-Null; "
            "'transferred listed artifact'", timeout=180)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(15)
    host_rows = listener_rows(Path('/proc/net/tcp').read_text(), port)
    receiver = {'address': '192.168.204.1', 'port': port,
                'thread_stopped': not worker.is_alive(),
                'socket_fileno': server.socket.fileno(), 'kernel_listeners': host_rows}
    if worker.is_alive() or received.get('error') or received.get('sha256', '').lower() != digest.lower():
        raise StepError('artifact transfer failed: ' + str(received))
    closed = channel.powershell(
        "$c=[Net.Sockets.TcpClient]::new();try{$a=$c.BeginConnect('192.168.204.1'," + str(port) + ",$null,$null); "
        "if($a.AsyncWaitHandle.WaitOne(1500)){try{$c.EndConnect($a);'OPEN'}catch{'CLOSED'}}else{'TIMEOUT'}}finally{$c.Dispose()}", timeout=10)
    result = {'path': str(destination), 'size': size, 'sha256': received['sha256'],
            'guest_metadata': artifact, 'transfer': transfer, 'closure': closed,
            'receiver': receiver}
    with destination.with_suffix('.transfer.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    if (receiver['socket_fileno'] != -1 or not receiver['thread_stopped'] or host_rows or
            closed['output'].strip() not in ('CLOSED', 'TIMEOUT')):
        raise StepError('receiver closure not confirmed: ' + str(receiver) + ' ' + closed['output'])
    return result
