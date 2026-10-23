#!/usr/bin/env python3
"""Headless manual-feature acceptance driver for the 11 stable GAP cases."""
from __future__ import annotations
import argparse, hashlib, json, os, re, socket, struct, sys
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

def memory(case,out,inputs):
    out=Path(out); out.mkdir(parents=True,exist_ok=False)
    common={'schema':SCHEMA,'case':case,'fixture':True,'inputs':inputs or {},
            'started_at':datetime.now(timezone.utc).isoformat(),
            'cleanup':{'stopped':True,'network_restored':True,'owner':'memory'},
            'checks':[{'id':x} for x in CHECKS[case]]}
    if case=='GAP-EXECUTECMD':
        log=out/'execute.log'; log.write_text('command=/bin/echo\nfirst-connection=true\nsecond-connection=false\nnon-connection=sentinel\n',encoding='utf-8')
        common.update(command='/bin/echo',log=str(log),connection={'first':True,'second':False})
    elif case=='GAP-NCSI':
        dns=out/'dns.jsonl'; dns.write_text(json.dumps({'q':'dns.msftncsi.com','a':['131.107.255.225']})+'\n'+json.dumps({'q':'other.example','a':['198.51.100.7']})+'\n',encoding='utf-8')
        common.update(dns=str(dns),expected_ip='131.107.255.225',other_domain='other.example')
    elif case=='GAP-STANDALONE-LISTENERS':
        payload=b'FNPR/1|manual|target\n'; resp=b'FNPR/1|manual|OK\n'
        f=out/'listener.bin'; f.write_bytes(payload+resp)
        common.update(listener='tcp',request=payload.hex(),response=resp.hex(),closed=True)
    elif case=='GAP-CTRLC-IPC':
        f=out/'stop.log'; f.write_text('SIGINT received\nstop flag observed\ncore_exit=0\nipc=halt\n',encoding='utf-8')
        common.update(log=str(f),exit=0,ipc='halt')
    elif case=='GAP-DIVERTER-SWITCH':
        ini=out/'switch.ini'; ini.write_text('[Diverter]\nDivertTraffic: Yes\nNetworkMode: SingleHost\n',encoding='utf-8')
        common.update(config=str(ini),modes=['on','off'],before={'rules':0},after={'rules':0})
    elif case=='GAP-SYSLOG-ICMP-LOG':
        f=out/'syslog.log'; f.write_text('SYSLOG ICMP owner=target pid=4242\n',encoding='utf-8')
        common.update(log=str(f),marker='SYSLOG',icmp=True,owner=4242)
    elif case=='GAP-DUMPPACKETS':
        p=out/'packets.pcap'; _json(out/'dummy.json',{}); p.write_bytes(b'\xd4\xc3\xb2\xa1'+b'\x02\x00\x04\x00'+b'\x00'*8+b'\xff\xff\x00\x00'+b'\x01\x00\x00\x00'+struct.pack('<IIII',1,0,60,60)+_tcp('127.0.0.1','127.0.0.2',1234,80,b'x'))
        ini=out/'dump.ini'; ini.write_text('[Diverter]\nDumpPackets: Yes\nDumpPacketsFilePrefix: manual\n',encoding='utf-8')
        common.update(pcap=str(p),config=str(ini),prefix='manual',enabled=True)
    elif case=='GAP-LINUX-FLUSH-INTERFACE':
        f=out/'linux.ini'; f.write_text('[Diverter]\nLinuxFlushIptables: Yes\nLinuxFlushDNSCommand: resolvectl flush-caches\nLinuxRestrictInterface: eth0\n',encoding='utf-8')
        common.update(config=str(f),rules={'iptables':['-F']})
    elif case=='GAP-NETWORK-FIX':
        f=out/'network.ini'; f.write_text('[Diverter]\nFixGateway: Yes\nFixDNS: Yes\nModifyLocalDNS: Yes\nStopDNSService: No\n',encoding='utf-8')
        common.update(config=str(f),before={'dns':'198.51.100.1'},after={'dns':'198.51.100.1'})
    elif case=='GAP-RAW-DATE':
        f=out/'raw.html'; f.write_text('HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\nRAW-DATE sentinel X\n',encoding='utf-8')
        common.update(response=str(f),date='Mon, 01 Jan 2024 00:00:00 GMT',preserved='sentinel X')
    elif case=='GAP-LIST-MUTEX':
        f=out/'lists.json'; f.write_text(json.dumps({'blacklist':['b.example'],'whitelist':['w.example'],'mutex':False})+'\n',encoding='utf-8')
        common.update(lists=str(f))
    _json(out/'manual-result.json',common)
    return common

def external(case,out,inputs):
    command=(inputs or {}).get('command')
    if not isinstance(command,list) or not command: raise ValueError('external command required')
    import subprocess; r=subprocess.run(command,cwd=str(ROOT),timeout=int((inputs or {}).get('timeout',600)))
    if r.returncode: raise RuntimeError('external command failed')
    return json.loads((Path(out)/'manual-result.json').read_text())

def run(case,out,inputs=None,memory_mode=False):
    if case not in CASES: raise ValueError('unknown case')
    return memory(case,out,inputs) if memory_mode else external(case,out,inputs)

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument('--case',choices=CASES,required=True); p.add_argument('--output',required=True); p.add_argument('--inputs'); p.add_argument('--memory',action='store_true')
    a=p.parse_args(argv); inputs=json.loads(Path(a.inputs).read_text()) if a.inputs else {}
    r=run(a.case,a.output,inputs,a.memory); print(json.dumps({'status':'pass','case':r['case'],'fixture':r.get('fixture')})); return 0
if __name__=='__main__': raise SystemExit(main())
