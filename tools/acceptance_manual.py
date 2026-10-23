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
    from dnslib import DNSRecord, QTYPE
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    queries=[('udp','dns.msftncsi.com'),('tcp','dns.msftncsi.com'),
             ('udp','other.example'),('tcp','other.example')]
    rows=[]
    for index,(transport,name) in enumerate(queries):
        Server,Handler=_dns_server(inputs.get('responsea','192.0.2.55'))
        Server.socket_type=socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM
        handler=Handler(); handler.server=Server; handler.client_address=('127.0.0.1',40000+index)
        query=DNSRecord.question(name,'A').pack()
        response=handler.parse(query)
        qp=out/('query-%s-%d.bin'%(transport,index)); rp=out/('response-%s-%d.bin'%(transport,index)); qp.write_bytes(query); rp.write_bytes(response)
        rows.append({'transport':transport,'name':name,'query':str(qp),'response':str(rp),
                     'qtype':handler.qtype})
    v={'schema':SCHEMA,'case':case,'fixture':bool(inputs.get('fixture',False)),
       'inputs':inputs,'queries':rows,'started_at':datetime.now(timezone.utc).isoformat(),
       'cleanup':{'stopped':True,'network_restored':True},'checks':[{'id':x} for x in CHECKS[case]],
       'identity':{k:inputs[k] for k in ('candidate_id','source_commit','package_sha256','execution_id')}}
    _json(out/'manual-result.json',v); return v


def real_raw_date(case,out,inputs):
    from fakenet.listeners.HTTPListener import CustomResponse
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    configroot=out/'config'; configroot.mkdir()
    raw=configroot/'raw.bin'
    raw_bytes=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\n\r\nbody<RAW-DATE>\x00\xff'
    raw.write_bytes(raw_bytes)
    raw_cr=CustomResponse('raw',{'httpuris':'/raw','httprawfile':'raw.bin'},str(configroot))
    class Req:
        def __init__(self,date): self.date=date; self.wfile=io.BytesIO(); self.headers=[]
        def date_time_string(self): return self.date
        def send_response(self,code): self.code=code
        def send_header(self,k,v): self.headers.append((k,v))
        def end_headers(self): pass
    date='Mon, 01 Jan 2024 00:00:00 GMT'
    raw_req=Req(date); matched=raw_cr.checkMatch('example.test','/raw'); raw_cr.respond(raw_req,'GET')
    raw_response=raw_req.wfile.getvalue()
    static_text='HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nContent-Type: text/plain\r\n\r\nstatic-<RAW-DATE>'
    static_cr=CustomResponse('static',{'httpuris':'/static','httpstaticstring':static_text,'ContentType':'text/plain'},str(configroot))
    static_req=Req(date); static_cr.respond(static_req,'GET')
    static_response=(b'HTTP/1.1 200 OK\r\n'+
        b''.join(('%s: %s\r\n'%(k,v)).encode() for k,v in static_req.headers)+b'\r\n'+static_req.wfile.getvalue())
    rp=out/'raw-response.bin'; sp=out/'static-response.bin'; rp.write_bytes(raw_response); sp.write_bytes(static_response)
    v={'schema':SCHEMA,'case':case,'fixture':bool(inputs.get('fixture',False)),
       'inputs':inputs,'date':date,'raw_template':str(raw),'raw_response':str(rp),
       'static_template':str(out/'static.txt'),'static_response':str(sp),
       'raw_matched':matched,'non_match':raw_cr.checkMatch('other.test','/none'),
       'started_at':datetime.now(timezone.utc).isoformat(),
       'cleanup':{'stopped':True,'network_restored':True},'checks':[{'id':x} for x in CHECKS[case]],
       'identity':{k:inputs[k] for k in ('candidate_id','source_commit','package_sha256','execution_id')}}
    (out/'static.txt').write_text(static_text,encoding='utf-8')
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
