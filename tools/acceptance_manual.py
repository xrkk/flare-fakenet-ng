#!/usr/bin/env python3
"""Fixed manual feature producers. Real listeners; immutable retained originals."""
from __future__ import annotations
import argparse
import configparser
import hashlib
import json
import re
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA='fakenet.manual-result.v1'
CASES=('GAP-EXECUTECMD','GAP-NCSI','GAP-STANDALONE-LISTENERS','GAP-CTRLC-IPC','GAP-DIVERTER-SWITCH','GAP-SYSLOG-ICMP-LOG','GAP-DUMPPACKETS','GAP-LINUX-FLUSH-INTERFACE','GAP-NETWORK-FIX','GAP-RAW-DATE','GAP-LIST-MUTEX')
CHECKS={'GAP-EXECUTECMD':['command','first-connection','non-connection'],'GAP-NCSI':['ncsi-ipv4','other-domain','dns-evidence'],'GAP-STANDALONE-LISTENERS':['listener-bytes','listener-close'],'GAP-CTRLC-IPC':['ctrlc','ipc-stop','owned-exit'],'GAP-DIVERTER-SWITCH':['on','off','restore'],'GAP-SYSLOG-ICMP-LOG':['syslog','icmp','owner'],'GAP-DUMPPACKETS':['enabled','disabled','prefix','content'],'GAP-LINUX-FLUSH-INTERFACE':['flush-iptables','flush-dns','restrict-interface'],'GAP-NETWORK-FIX':['fix-gateway','fix-dns','modify-local-dns','stop-dns'],'GAP-RAW-DATE':['raw-date','preserved-bytes'],'GAP-LIST-MUTEX':['blacklist','whitelist','mutex']}
RAW=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\nContent-Length: 35\r\nConnection: close\r\n\r\nbody<RAW-DATE>\x00\xff'
STATIC='static-<RAW-DATE>'
IDENTITY=('candidate_id','source_commit','package_sha256','execution_id')
def sha256(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def _json(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def validate_inputs(case,inputs):
    if not isinstance(inputs,dict):raise ValueError('manual inputs must be an object')
    if inputs.get('schema')!='fakenet.manual-input.v1' or inputs.get('case')!=case:raise ValueError('manual input schema/case mismatch')
    for k in (*IDENTITY,'config','owned_root'):
        if not inputs.get(k):raise ValueError('manual inputs missing: '+k)
    if not re.fullmatch('[0-9a-f]{40}',inputs['source_commit']) or not re.fullmatch('[0-9a-f]{64}',inputs['package_sha256']):raise ValueError('manual content identity invalid')
    if not re.fullmatch('[a-zA-Z0-9-]{4,80}',inputs['execution_id']):raise ValueError('execution_id is invalid')
    for k in ('config','owned_root'):
        if not Path(inputs[k]).is_absolute() or Path(inputs[k]).is_symlink():raise ValueError('manual path must be absolute/no symlink: '+k)
    socket.inet_pton(socket.AF_INET,inputs.get('responsea','192.0.2.55'))
class Callbacks:
    def isProcessBlackListed(self,*a,**kw):return False,None,None
    def egressPolicyEnabled(self):return False
    def logEgressEvent(self,*a,**kw):pass
    def logNbi(self,*a,**kw):pass

def _start(listener):
    # Keep original objects: HTTP stop intentionally clears its public references.
    listener.start()
    return listener.server,listener.server_thread,listener.server.socket

def _stop(listener,server,thread,sock,port):
    error=None
    try:
        if thread is not None and thread.is_alive():listener.stop()
        else:server.server_close()
    except Exception as e:error=type(e).__name__+': '+str(e)
    if thread is not None:thread.join(5)
    return dict(bind='127.0.0.1',port=port,started=True,thread_id=thread.ident if thread else None,
                stopped=error is None,thread_alive=thread.is_alive() if thread else True,
                socket_closed=sock.fileno()==-1,stop_error=error)

def _bytes(out,name,value):
    p=out/name;p.write_bytes(value);return str(p)

def _recv_exact(client,length):
    chunks=[];remaining=length
    while remaining:
        chunk=client.recv(remaining)
        if not chunk:raise ValueError('short DNS TCP response')
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

def real_ncsi(case,out,inputs):
    from dnslib import DNSRecord
    from fakenet.listeners.DNSListener import DNSListener
    rows=[];states={}
    for transport in ('udp','tcp'):
        listener=DNSListener(dict(ipaddr='127.0.0.1',port=0,protocol=transport,responsea=inputs.get('responsea','192.0.2.55'),nxdomains=0,timeout=5),name='manual-ncsi-'+transport)
        listener.acceptDiverterListenerCallbacks(Callbacks())
        server=thread=sock=None
        try:
            server,thread,sock=_start(listener);port=server.server_address[1]
            for index,name in enumerate(('dns.msftncsi.com','other.example')):
                query=DNSRecord.question(name,'A').pack();start=time.time()
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as client:
                    client.settimeout(5)
                    if transport=='udp':
                        wire_query=query;client.sendto(wire_query,('127.0.0.1',port));response,peer=client.recvfrom(65535);wire_response=response
                    else:
                        client.connect(('127.0.0.1',port));wire_query=struct.pack('!H',len(query))+query;client.sendall(wire_query)
                        prefix=_recv_exact(client,2);response=_recv_exact(client,struct.unpack('!H',prefix)[0]);wire_response=prefix+response;peer=client.getpeername()
                    local=client.getsockname()
                qp=_bytes(out,'query-%s-%d.bin'%(transport,index),query);rp=_bytes(out,'response-%s-%d.bin'%(transport,index),response)
                rows.append(dict(name=name,transport=transport,query=qp,response=rp,wire_query=_bytes(out,'wire-query-%s-%d.bin'%(transport,index),wire_query),wire_response=_bytes(out,'wire-response-%s-%d.bin'%(transport,index),wire_response),query_sha256=sha256(qp),response_sha256=sha256(rp),server_port=port,peer=list(peer),client_port=local[1],started_epoch=start,ended_epoch=time.time(),client_closed=client.fileno()==-1))
        finally:
            if server is None:
                server=getattr(listener,'server',None);thread=getattr(listener,'server_thread',None)
                if server is not None:sock=server.socket;port=server.server_address[1]
            if server is not None:
                states[transport]=_stop(listener,server,thread,sock,port)
                _json(out/('lifecycle-'+transport+'.json'),states[transport])
    return dict(queries=rows,listener={'bind':'127.0.0.1','transports':states})

def real_raw_date(case,out,inputs):
    from fakenet.listeners.HTTPListener import HTTPListener
    config=out/'config';config.mkdir();web=out/'webroot';web.mkdir()
    raw=config/'raw.bin';raw.write_bytes(RAW);(out/'static.txt').write_text(STATIC)
    # A real normal unmatched request follows the original file responder.
    (web/'raw').write_bytes(b'normal-file-raw');(web/'none').write_bytes(b'normal-file-none')
    cfg=configparser.ConfigParser();cfg['raw']={'ListenerType':'HTTP','HttpUris':'/raw','HttpHosts':'example.test','HttpRawFile':'raw.bin'};cfg['static']={'ListenerType':'HTTP','HttpUris':'/static','HttpHosts':'example.test','HttpStaticString':STATIC,'ContentType':'text/plain'}
    with (config/'custom.ini').open('w') as stream:cfg.write(stream)
    listener=HTTPListener(dict(ipaddr='127.0.0.1',port=0,webroot=str(web),custom=str(config/'custom.ini'),configdir=str(config),timeout=5,version='FakeNet/manual'),name='manual-raw-date')
    listener.acceptDiverterListenerCallbacks(Callbacks());server=thread=sock=None;rows=[]
    try:
        server,thread,sock=_start(listener);port=server.server_address[1]
        raw_match=server.custom_responses[0].checkMatch('example.test','/raw')
        non_match=server.custom_responses[0].checkMatch('other.test','/none')
        for name,host,path in [('raw','example.test','/raw'),('static','example.test','/static'),('wrong-host','other.test','/raw'),('wrong-uri','example.test','/none')]:
            request=('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'%(path,host)).encode();start=time.time()
            with socket.create_connection(('127.0.0.1',port),timeout=5) as client:
                client.settimeout(5);client.sendall(request);chunks=[]
                while True:
                    block=client.recv(65535)
                    if not block:break
                    chunks.append(block)
                local=client.getsockname();peer=client.getpeername()
            response=b''.join(chunks);qp=_bytes(out,name+'-request.bin',request);rp=_bytes(out,name+'-response.bin',response)
            rows.append(dict(name=name,host=host,path=path,request=qp,response=rp,request_sha256=sha256(qp),response_sha256=sha256(rp),client_port=local[1],peer=list(peer),started_epoch=start,ended_epoch=time.time(),client_closed=client.fileno()==-1))
    finally:
        if server is None:
            server=getattr(listener,'server',None);thread=getattr(listener,'server_thread',None)
            if server is not None:sock=server.socket;port=server.server_address[1]
        if server is not None:
            state=_stop(listener,server,thread,sock,port)
            _json(out/'lifecycle-http.json',state)
    header=Path(rows[0]['response']).read_bytes().split(b'\r\n\r\n',1)[0]
    date=next(x[6:].decode() for x in header.split(b'\r\n') if x.startswith(b'Date: '))
    return dict(date=date,raw_template=str(raw),static_template=str(out/'static.txt'),raw_response=str(out/'raw-response.bin'),static_response=str(out/'static-response.bin'),raw_matched=raw_match,non_match=non_match,listener=state,http={'exchanges':rows},config_sha256=sha256(config/'custom.ini'))

def run(case,out,inputs=None,memory_mode=False):
    if case not in CASES:raise ValueError('unknown case')
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):raise NotImplementedError('case is not implemented in this round: '+case)
    validate_inputs(case,inputs);out=Path(out).absolute()
    if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
    out.mkdir(parents=True,exist_ok=False);start=time.time()
    value=dict(schema=SCHEMA,case=case,fixture=bool(memory_mode or inputs.get('fixture',False)),inputs=inputs,identity={k:inputs[k] for k in IDENTITY},started_epoch=start)
    try:value.update(real_ncsi(case,out,inputs) if case=='GAP-NCSI' else real_raw_date(case,out,inputs))
    except Exception as e:
        value['error']=type(e).__name__+': '+str(e);value['cleanup']={'stopped':False,'recovery_required':True};_json(out/'manual-result.json',value);raise
    states=list(value['listener']['transports'].values()) if case=='GAP-NCSI' else [value['listener']]
    value.update(ended_epoch=time.time(),cleanup=dict(stopped=all(x['stopped'] for x in states),threads_joined=all(not x['thread_alive'] for x in states),sockets_closed=all(x['socket_closed'] for x in states)),checks=[{'id':x} for x in CHECKS[case]])
    _json(out/'manual-result.json',value);return value

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--case',choices=CASES,required=True);p.add_argument('--inputs',required=True);p.add_argument('--output',required=True);p.add_argument('--memory',action='store_true');a=p.parse_args(argv)
    run(a.case,a.output,json.loads(Path(a.inputs).read_text()),a.memory);return 0
if __name__=='__main__':raise SystemExit(main())
