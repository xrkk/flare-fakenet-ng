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
    assert 'LIVE STOP STACKS' in during and 'File "' in during
    assert 'STOP ATTEMPT pid=' in during
'''
    result = subprocess.run([sys.executable, '-c', code, str(tmp_path)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_stop_stack_capture_releases_watchdog_after_exception(tmp_path):
    import threading
    from fakenet.mcp.managed import capture_stop_stacks
    before = set(threading.enumerate())
    with pytest.raises(RuntimeError, match='stop failed'):
        with capture_stop_stacks(tmp_path):
            raise RuntimeError('stop failed')
    assert not [t for t in set(threading.enumerate()) - before
                if t.name == 'stop-stack-capture']
    evidence = (tmp_path / 'stop-thread-stacks.txt').read_text()
    assert 'test_stop_stack_capture_releases_watchdog_after_exception' in evidence
    assert 'LIVE STOP STACKS' in evidence


def test_listener_fault_is_real_thread_exception_with_consumed_nonce(tmp_path):
    code = r'''
import json, logging, os, socketserver, threading, time
from pathlib import Path
from types import SimpleNamespace
from fakenet.mcp.faultinject import FaultInjector, _fault_file
from fakenet.mcp.managed import install_thread_exception_logging
root = Path.cwd()
os.environ['PROGRAMDATA'] = str(root)
os.environ['FAKENETNG_MCP_FAULT_INJECTION'] = '1'
logging.basicConfig(filename='run.log', level=logging.INFO)
install_thread_exception_logging()
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        pass
server = socketserver.TCPServer(('127.0.0.1', 0), Handler)
worker = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), name='real-listener')
worker.start()
fault = FaultInjector()
assert fault.install_listener_exception_hook([SimpleNamespace(server=server, server_thread=worker)])
assert worker.is_alive() and not (root / 'fault-triggered.json').exists()
fault.arm('listener_exception')
armed = json.loads(_fault_file().read_text())
worker.join(3)
assert not worker.is_alive()
assert not _fault_file().exists()
assert json.loads((root / 'fault-triggered.json').read_text()) == armed
logging.shutdown()
raw = (root / 'run.log').read_text()
assert 'Unhandled exception in managed thread real-listener' in raw
assert 'Traceback (most recent call last)' in raw
assert 'service_actions' in raw
assert 'RuntimeError: injected listener thread exception' in raw
server.server_close()
'''
    env = dict(os.environ)
    env['PYTHONPATH'] = os.pathsep.join([str(__import__('pathlib').Path(__file__).resolve().parents[2]),
                                       env.get('PYTHONPATH', '')])
    result = subprocess.run([sys.executable, '-c', code], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'Exception in thread real-listener' in result.stderr
