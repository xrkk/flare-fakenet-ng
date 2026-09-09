"""External programs must not contaminate the private managed protocol."""
import json
import os
import subprocess
import sys

import pytest


def test_real_ftp_server_nested_socket_health():
    from types import SimpleNamespace
    from pyftpdlib.servers import FTPServer
    from pyftpdlib.handlers import FTPHandler
    from fakenet.mcp.managed import probe_instance
    server = FTPServer(('127.0.0.1', 0), FTPHandler)
    instance = SimpleNamespace(diverter=SimpleNamespace(handle=SimpleNamespace(is_open=True)),
                               running_listener_providers=[SimpleNamespace(server=server)])
    try:
        assert not hasattr(server, 'fileno')
        assert probe_instance(instance)['probe']
        server.close_all()
        assert not probe_instance(instance)['probe']
    finally:
        server.close_all()


@pytest.mark.skipif(os.name != 'nt', reason='Windows standard handle inheritance')
def test_external_non_utf8_output_isolated_from_protocol(tmp_path):
    script = r'''
import json, subprocess, sys
from fakenet.mcp.managed import redirect_child_streams
source, sink, output = redirect_child_streams(sys.argv[1])
subprocess.run([sys.executable, '-c', 'import os; os.write(1, bytes([0xca,0xdc,0xd0,0xc5])); os.write(2,b"external-error")'], check=True)
request = json.loads(source.readline())
sink.write(json.dumps({'seq': request['seq'], 'ok': True}).encode() + b'\n')
sink.flush()
'''
    child = subprocess.run([sys.executable, '-c', script, str(tmp_path)],
                           input=b'{"seq": 1}\n', capture_output=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == {'seq': 1, 'ok': True}
    raw = (tmp_path / 'stdout_stderr.log').read_bytes()
    assert bytes([0xca, 0xdc, 0xd0, 0xc5]) in raw
    assert b'external-error' in raw


def test_stop_watchdog_captures_blocked_ipc_thread(tmp_path):
    import subprocess
    import sys
    code = '''
import sys, time
from fakenet.mcp.managed import capture_stop_stacks
from pathlib import Path
root = Path(sys.argv[1])
with capture_stop_stacks(root):
    time.sleep(1.2)
    during = (root / 'stop-thread-stacks.txt').read_text()
    assert 'Timeout' in during and 'File "' in during
    assert 'STOP ATTEMPT pid=' in during
'''
    result = subprocess.run([sys.executable, '-c', code, str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
