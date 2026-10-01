import importlib.util,json,threading,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest,sys
sys.path.insert(0,str(Path(__file__).parent/'acceptance'))
import bounded_mcp as b
from scenario_suite import RawMcp
class Slow(BaseHTTPRequestHandler):
    mode='drip';sent=0
    def log_message(self,*args):pass
    def do_POST(self):
        request=json.loads(self.rfile.read(int(self.headers['Content-Length'])));type(self).sent+=1
        if self.mode=='vm':
            time.sleep(.3);self.send_response(200);self.send_header('Mcp-Session-Id','own-test-session');payload=json.dumps({'jsonrpc':'2.0','id':request.get('id'),'result':{}}).encode() if 'id' in request else b'';self.send_header('Content-Length',str(len(payload)));self.end_headers()
            try:self.wfile.write(payload)
            except (BrokenPipeError,ConnectionResetError):pass
            return
        if self.mode=='headers_never':self.server.stop_event.wait(3);return
        self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Transfer-Encoding','chunked');self.end_headers()
        try:
            if self.mode=='no_end':
                self.wfile.write(b'1\r\nx\r\n');self.wfile.flush();self.server.stop_event.wait(3);return
            if self.mode=='complete':
                data=b'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n\n';self.wfile.write(('%x\r\n'%len(data)).encode()+data+b'\r\n');self.wfile.flush()
            for _ in range(25):
                self.wfile.write(b'3\r\n: \n\r\n');self.wfile.flush();time.sleep(.04)
            self.wfile.write(b'0\r\n\r\n');self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError):pass
@pytest.fixture
def server():
    Slow.sent=0;Slow.mode='drip';s=ThreadingHTTPServer(('127.0.0.1',0),Slow);s.stop_event=threading.Event();s.daemon_threads=False;t=threading.Thread(target=s.serve_forever);t.start()
    yield s
    s.stop_event.set();s.shutdown();s.server_close();t.join(2);assert not t.is_alive()
def client(server,tmp_path):
    c=RawMcp('http://127.0.0.1:%s/mcp'%server.server_port);c.transport_evidence=tmp_path;return c
def test_slow_drip_has_absolute_deadline_and_no_local_worker(server,tmp_path):
    start=time.monotonic()
    with pytest.raises(Exception):b.post(client(server,tmp_path),{'jsonrpc':'2.0','id':1,'method':'tools/call'},timeout=.35)
    assert time.monotonic()-start<.8
    assert Slow.sent==1

def test_complete_sse_returns_without_stream_eof(server,tmp_path):
    Slow.mode='complete';start=time.monotonic();r,h=b.post(client(server,tmp_path),{'jsonrpc':'2.0','id':1,'method':'tools/call'},timeout=.5)
    assert r['result']['ok'] and time.monotonic()-start<.8
def completions(tmp_path):return [json.loads(p.read_text()) for p in tmp_path.glob('*/completion.json')]
def test_actual_launch_sent_but_missing_receipt_is_unknown_without_replay(server,tmp_path):
    with pytest.raises(b.TransportUnknown) as ex:b.post(client(server,tmp_path),{'jsonrpc':'2.0','id':1,'method':'launch-own-test'},timeout=.4)
    rows=completions(tmp_path);assert Slow.sent==1 and len(rows)==1 and rows[0]['sent']=='possibly_sent' and rows[0]['local_writer_ended']
    assert rows[0]['status']=='UNKNOWN' and (next(tmp_path.glob('*/partial.bin'))).stat().st_size>0

def test_real_sigint_preserves_entered_failure_and_closes_transport_even_finally_error(server,tmp_path):
    import signal
    state={'business_entered':True,'run_id':'actual-own-test','stage':'launch_sent'};saved=[];cleanup=[]
    timer=threading.Timer(.2,lambda:signal.raise_signal(signal.SIGINT));timer.start();start=time.monotonic()
    def execute():b.post(client(server,tmp_path),{'id':1,'method':'launch'},timeout=.7)
    def close():cleanup.append(True);raise ValueError('own finally error')
    try:r=b.guarded(execute,close,lambda x:saved.append(dict(x)),state)
    finally:timer.join(1)
    assert time.monotonic()-start<1.1 and cleanup==[True] and r['status']=='FAILED' and r['business_entered']
    assert r['exception_type']=='KeyboardInterrupt' and 'KeyboardInterrupt' in r['traceback'] and 'finally error' in r['closure_error']
    assert saved[0]['stage']=='launch_sent' and completions(tmp_path)[0]['local_writer_ended']

def test_cleanup_success_never_overwrites_original_transport_failure(server,tmp_path):
    state={'business_entered':True};r=b.guarded(lambda:b.post(client(server,tmp_path),{'id':1},timeout=.35),lambda:None,lambda _:None,state)
    assert r['status']=='FAILED' and r['exception_type']=='TransportUnknown' and r['business_entered']

def test_nested_boundary_uses_one_absolute_deadline(server,tmp_path):
    c=client(server,tmp_path);c._absolute_deadline=time.monotonic()+.35;start=time.monotonic()
    with pytest.raises(b.TransportUnknown):b.post(c,{'id':1},timeout=3)
    assert time.monotonic()-start<.8 and completions(tmp_path)[0]['budget']<.36

@pytest.mark.parametrize('mode',['headers_never','no_end'])
def test_no_completion_headers_or_body_has_same_original_deadline(server,tmp_path,mode):
    Slow.mode=mode;start=time.monotonic()
    with pytest.raises(b.TransportUnknown):b.post(client(server,tmp_path),{'id':1},timeout=.35)
    assert time.monotonic()-start<.8 and Slow.sent==1
    assert completions(tmp_path)[0]['local_writer_ended'] and completions(tmp_path)[0]['status']=='UNKNOWN'

def test_vm_initialize_notification_and_tool_share_original_total_deadline(server,tmp_path):
    from scenario_suite import VmMcp
    Slow.mode='vm';c=b.install(VmMcp('http://127.0.0.1:%s/mcp'%server.server_port),tmp_path);start=time.monotonic()
    with pytest.raises(b.TransportUnknown):c.powershell('own local test, not actual guest',timeout=.75)
    assert time.monotonic()-start<1.1 and all(r['local_writer_ended'] for r in completions(tmp_path))
    requests=[json.loads(p.read_text()) for p in tmp_path.glob('*/request.json')];assert len(requests)>=2 and min(r['budget'] for r in requests)<.5
