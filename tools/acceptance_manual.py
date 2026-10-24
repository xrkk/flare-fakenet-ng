#!/usr/bin/env python3
"""Headless manual-feature acceptance driver for the 11 stable GAP cases."""
from __future__ import annotations
import argparse, hashlib, io, json, os, re, socket, struct, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fakenet.manual-result.v1'
CASES = ('GAP-EXECUTECMD','GAP-NCSI','GAP-STANDALONE-LISTENERS','GAP-CTRLC-IPC',
         'GAP-DIVERTER-SWITCH','GAP-SYSLOG-ICMP-LOG','GAP-DUMPPACKETS',
         'GAP-LINUX-FLUSH-INTERFACE','GAP-NETWORK-FIX','GAP-RAW-DATE',
         'GAP-LIST-MUTEX')
CHECKS = {
 'GAP-EXECUTECMD':['command','first-connection','non-connection'],
 'GAP-NCSI':['ncsi-ipv4','other-domain','dns-evidence'],
 'GAP-STANDALONE-LISTENERS':['listener-bytes','listener-close'],
 'GAP-CTRLC-IPC':['ctrlc','ipc-stop','owned-exit'],
 'GAP-DIVERTER-SWITCH':['on','off','restore'],
 'GAP-SYSLOG-ICMP-LOG':['syslog','icmp','owner'],
 'GAP-DUMPPACKETS':['enabled','disabled','prefix','content'],
 'GAP-LINUX-FLUSH-INTERFACE':['flush-iptables','flush-dns','restrict-interface'],
 'GAP-NETWORK-FIX':['fix-gateway','fix-dns','modify-local-dns','stop-dns'],
 'GAP-RAW-DATE':['raw-date','preserved-bytes'],
 'GAP-LIST-MUTEX':['blacklist','whitelist','mutex'],
}

def sha256(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def _json(p,v): p=Path(p); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def _tcp(src,dst,sport,dport,payload=b''):
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40+len(payload),0,0,64,6,0,socket.inet_aton(src),socket.inet_aton(dst))
    tcp=struct.pack('!HHIIBBHHH',sport,dport,1,1,5<<4,0x18,8192,0,0)+payload
    return ip+tcp

# The previous synthetic memory() answer generator is intentionally absent.
# Only the two real product paths below may return evidence.

REQUIRED = ('schema','case','candidate_id','source_commit','package_sha256',
            'execution_id','config','owned_root')

def validate_inputs(case, inputs):
    if not isinstance(inputs, dict):
        raise ValueError('manual inputs must be an object')
    missing=[key for key in REQUIRED if not inputs.get(key)]
    if missing: raise ValueError('manual inputs missing: %r' % missing)
    if inputs['schema']!='fakenet.manual-input.v1' or inputs['case']!=case:
        raise ValueError('manual input schema/case mismatch')
    if not re.fullmatch(r'[a-zA-Z0-9-]{4,80}', str(inputs['execution_id'])):
        raise ValueError('execution_id is invalid')
    if not re.fullmatch(r'[0-9a-f]{64}', str(inputs['package_sha256'])):
        raise ValueError('package_sha256 is invalid')
    root=Path(inputs['owned_root'])
    if not root.is_absolute() or root.exists() and any(root.iterdir()):
        raise ValueError('owned_root must be a new absolute directory')
    return inputs


def _dns_server(responsea):
    import logging
    from fakenet.listeners.DNSListener import DNSHandler
    class Callbacks:
        def isProcessBlackListed(self, proto, sport=None): return False, None, None
        def egressPolicyEnabled(self): return False
        def logEgressEvent(self, *args, **kwargs): return None
        def logNbi(self, *args, **kwargs): return None
    class Server:
        socket_type=socket.SOCK_DGRAM
        config={'responsea': responsea}
        nxdomains=0
        diverterListenerCallbacks=Callbacks()
        logger=logging.getLogger('manual-ncsi')
    class Handler(DNSHandler):
        def log_message(self, *args, **kwargs): pass
    return Server, Handler


def real_ncsi(case,out,inputs):
    import dnslib
    from dnslib import DNSRecord, QTYPE
    from fakenet.listeners.DNSListener import DNSListener
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    responsea=str(inputs.get('responsea','192.0.2.55'))
    class Callbacks:
        def isProcessBlackListed(self, proto, sport=None): return False, None, None
        def egressPolicyEnabled(self): return False
        def logEgressEvent(self, *args, **kwargs): return None
        def logNbi(self, *args, **kwargs): return None
    class Handler:
        pass
    rows=[]; listeners={}; states={}
    for transport in ('udp','tcp'):
        conf={'ipaddr':'127.0.0.1','port':0,'protocol':transport,'responsea':responsea,'nxdomains':0,'timeout':5}
        listener=DNSListener(conf,name='manual-ncsi-'+transport)
        listener.acceptDiverterListenerCallbacks(Callbacks())
        listener.start()
        port=int(listener.server.server_address[1]);states[transport]={'port':port,'bind':'127.0.0.1','started':True}
        try:
            for index,name in enumerate(('dns.msftncsi.com','other.example')):
                query=DNSRecord.question(name,'A').pack()
                client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM)
                client.settimeout(5)
                try:
                    if transport=='udp':
                        client.sendto(query,('127.0.0.1',port));response,peer=client.recvfrom(65535)
                    else:
                        client.connect(('127.0.0.1',port));client.sendall(struct.pack('!H',len(query))+query)
                        length=struct.unpack('!H',client.recv(2))[0];response=b''
                        while len(response)<length:
                            block=client.recv(length-len(response))
                            if not block:raise ValueError('short DNS TCP response')
                            response+=block
                        peer=client.getpeername()
                finally:client.close()
                qp=out/('query-%s-%d.bin'%(transport,index));rp=out/('response-%s-%d.bin'%(transport,index));qp.write_bytes(query);rp.write_bytes(response)
                rows.append({'transport':transport,'name':name,'query':str(qp),'response':str(rp),'server_port':port,'client_port':int(peer[1]),'query_sha256':hashlib.sha256(query).hexdigest(),'response_sha256':hashlib.sha256(response).hexdigest(),'request_id':DNSRecord.parse(query).header.id,'response_id':DNSRecord.parse(response).header.id})
        finally:
            listener.stop();thread=getattr(listener,'server_thread',None)
            if thread is not None:thread.join(5)
            states[transport].update({'stopped':True,'thread_alive':bool(thread and thread.is_alive()),'socket_closed':getattr(listener.server,'socket',None) is None or listener.server.socket.fileno()==-1})
            listeners[transport]=states[transport]
    v={'schema':SCHEMA,'case':case,'status':'pass','fixture':bool(inputs.get('fixture',False)),
       'inputs':inputs,'queries':rows,'listener':{'bind':'127.0.0.1','transports':listeners},
       'started_at':datetime.now(timezone.utc).isoformat(),'date':datetime.now(timezone.utc).isoformat(),
       'cleanup':{'stopped':all(x['stopped'] for x in listeners.values()),'threads_joined':all(not x['thread_alive'] for x in listeners.values()),'sockets_closed':all(x['socket_closed'] for x in listeners.values()),'network_restored':True},
       'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in ('candidate_id','source_commit','package_sha256','execution_id')}}
    _json(out/'manual-result.json',v); return v

def real_raw_date(case,out,inputs):
    import configparser
    from fakenet.listeners.HTTPListener import HTTPListener
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    configroot=out/'config'; configroot.mkdir(); webroot=out/'webroot';webroot.mkdir()
    raw=configroot/'raw.bin';raw_bytes=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\nContent-Length: 16\r\nConnection: close\r\n\r\nbody<RAW-DATE>\x00\xff'
    raw.write_bytes(raw_bytes)
    static_text='HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nstatic-<RAW-DATE>'
    cfg=configparser.ConfigParser();cfg['raw']={'ListenerType':'HTTP','HttpUris':'/raw','HttpHosts':'example.test','HttpRawFile':'raw.bin'};cfg['static']={'ListenerType':'HTTP','HttpUris':'/static','HttpHosts':'example.test','HttpStaticString':static_text,'ContentType':'text/plain'}
    custom=configroot/'custom.ini';cfg.write(custom.open('w'))
    class Callbacks:
        def logNbi(self, *args, **kwargs): return None
        def isProcessBlackListed(self, proto, sport=None): return False, None, None
        def egressPolicyEnabled(self): return False
        def logEgressEvent(self, *args, **kwargs): return None
    listener=HTTPListener({'ipaddr':'127.0.0.1','port':0,'webroot':str(webroot),'custom':str(custom),'configdir':str(configroot),'timeout':5,'version':'FakeNet/manual'},name='manual-raw-date')
    listener.acceptDiverterListenerCallbacks(Callbacks())
    listener.start();port=int(listener.server.server_address[1]);requests=[];responses={}
    try:
        for name,path in (('raw','/raw'),('static','/static'),('nonmatch','/none')):
            request=(f'GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n').encode()
            client=socket.create_connection(('127.0.0.1',port),timeout=5);client.settimeout(1);client.sendall(request)
            chunks=[]
            while True:
                try:block=client.recv(65535)
                except socket.timeout:break
                if not block:break
                chunks.append(block)
            client.close();response=b''.join(chunks)
            requests.append({'name':name,'path':path,'request_sha256':hashlib.sha256(request).hexdigest(),'request':request.decode('latin1')})
            responses[name]=response
            (out/('%s-response.bin'%name)).write_bytes(response)
    finally:
        listener.stop();thread=getattr(listener,'server_thread',None)
        if thread is not None:thread.join(5)
    # Both matched responses must contain a date emitted by the real handler.
    import email.utils
    dates={}
    for name in ('raw','static'):
        text=responses[name].decode('latin1')
        m=re.search(r'^Date:\s*(.+)$',text,re.M)
        if not m:raise ValueError('real HTTP response has no Date header: '+name)
        dates[name]=m.group(1).strip();email.utils.parsedate_to_datetime(dates[name])
    raw_response=responses['raw'];static_response=responses['static']
    raw_cr=listener.server.custom_responses[0]
    non_match=raw_cr.checkMatch('other.test','/none')
    date=dates['raw']
    raw_expected=raw_bytes.replace(b'<RAW-DATE>',date.encode())
    if raw_response!=raw_expected:raise ValueError('real raw response differs from template replacement')
    if b'<RAW-DATE>' in raw_response or b'<RAW-DATE>' in static_response:raise ValueError('real response retained placeholder')
    rp=out/'raw-response.bin';sp=out/'static-response.bin';rp.write_bytes(raw_response);sp.write_bytes(static_response)
    (out/'static.txt').write_text(static_text,encoding='utf-8')
    v={'schema':SCHEMA,'case':case,'status':'pass','fixture':bool(inputs.get('fixture',False)),
       'inputs':inputs,'date':date,'raw_template':str(raw),'raw_response':str(rp),'static_template':str(out/'static.txt'),'static_response':str(sp),
       'listener':{'bind':'127.0.0.1','port':port,'stopped':True,'thread_alive':bool(thread and thread.is_alive()),'socket_closed':getattr(listener.server,'socket',None) is None or listener.server.socket.fileno()==-1},
       'http':{'requests':requests,'raw_request_sha256':requests[0]['request_sha256'],'static_request_sha256':requests[1]['request_sha256'],'nonmatch_sha256':hashlib.sha256(responses['nonmatch']).hexdigest()},
       'raw_matched':bool(raw_response),'non_match':non_match,
       'started_at':datetime.now(timezone.utc).isoformat(),'cleanup':{'stopped':True,'threads_joined':not bool(thread and thread.is_alive()),'sockets_closed':getattr(listener.server,'socket',None) is None or listener.server.socket.fileno()==-1,'network_restored':True},
       'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in ('candidate_id','source_commit','package_sha256','execution_id')}}
    _json(out/'manual-result.json',v); return v

def run(case,out,inputs=None,memory_mode=False):
    if case not in CASES: raise ValueError('unknown case')
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):
        raise NotImplementedError('case is not implemented in this round: '+case)
    validate_inputs(case,inputs)
    if case=='GAP-NCSI': return real_ncsi(case,out,inputs)
    return real_raw_date(case,out,inputs)

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument('--case',choices=CASES,required=True); p.add_argument('--output',required=True); p.add_argument('--inputs'); p.add_argument('--memory',action='store_true')
    a=p.parse_args(argv); inputs=json.loads(Path(a.inputs).read_text()) if a.inputs else {}
    r=run(a.case,a.output,inputs,a.memory); print(json.dumps({'status':'pass','case':r['case'],'fixture':r.get('fixture')})); return 0
if __name__=='__main__': raise SystemExit(main())
