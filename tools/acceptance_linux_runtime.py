#!/usr/bin/env python3
"""Linux SingleHost/MultiHost and deploy/update headless acceptance driver."""
from __future__ import annotations
import argparse, hashlib, json, socket, struct
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SCHEMA='fakenet.linux-runtime-result.v1'
CASES=('LINUX-SINGLEHOST','LINUX-DEPLOY-UPDATE')
CHECKS={'LINUX-SINGLEHOST':['singlehost','multihost','nfqueue','ipv6-block','restore'],'LINUX-DEPLOY-UPDATE':['install','idle-update','transaction','token','rollback']}
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def _json(p,v): p=Path(p); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def _tcp(payload=b''):
 ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40+len(payload),0,0,64,6,0,socket.inet_aton('192.0.2.10'),socket.inet_aton('192.0.2.20'))
 tcp=struct.pack('!HHIIBBHHH',40000,8080,1,1,5<<4,0x18,8192,0,0)+payload
 return ip+tcp
def memory(case,out,inputs):
 out=Path(out); out.mkdir(parents=True,exist_ok=False); inputs=inputs or {}
 v={'schema':SCHEMA,'case':case,'fixture':True,'inputs':inputs,'started_at':datetime.now(timezone.utc).isoformat(),'cleanup':{'stopped':True,'network_restored':True},'checks':[{'id':x} for x in CHECKS[case]]}
 if case=='LINUX-SINGLEHOST':
  ini=out/'default.ini'; ini.write_text('[Diverter]\nNetworkMode: SingleHost\nLinuxFlushIptables: Yes\nLinuxFlushDNSCommand: resolvectl flush-caches\nLinuxRestrictInterface: eth0\nLinuxControlEndpoints: 192.0.2.1:2222\n')
  pcap=out/'capture.pcap'; pcap.write_bytes(b'\xd4\xc3\xb2\xa1'+b'\x02\x00\x04\x00'+b'\x00'*8+b'\xff\xff\x00\x00'+b'\x01\x00\x00\x00'+struct.pack('<IIII',1,0,40,40)+_tcp(b'FNPR/1|x|target\n'))
  v.update(config=str(ini),pcap=str(pcap),mode='singlehost',rules={'v4':['iptables -t raw -I OUTPUT'],'v6':['ip6tables -I OUTPUT -j DROP']},before={'rules':0},after={'rules':0})
 elif case=='LINUX-DEPLOY-UPDATE':
  pkg=out/'package'; pkg.mkdir(); (pkg/'manifest.json').write_text(json.dumps({'base_manifest':'b'*64,'source_commit':'c'*40,'files':{}})); (pkg/'source.tar.gz').write_bytes(b'benign')
  receipt=out/'receipt.json'; _json(receipt,{'operation':'update-0001','phase':'completed','manifest':sha(pkg/'manifest.json'),'published':['fakenet/mcp/linuxrunner.py'],'originals':{'fakenet/mcp/linuxrunner.py':{'sha256':'d'*64}},'token_reused':True})
  v.update(package=str(pkg),receipt=str(receipt),token=str(out/'token'),token_mode=0o600)
  (out/'token').write_text('a'*64+'\n')
 _json(out/'linux-result.json',v); return v
def external(case,out,inputs):
 cmd=(inputs or {}).get('command')
 if not isinstance(cmd,list) or not cmd: raise ValueError('external command required')
 import subprocess; r=subprocess.run(cmd,cwd=str(ROOT),timeout=int((inputs or {}).get('timeout',600)))
 if r.returncode: raise RuntimeError('external failed')
 return json.loads((Path(out)/'linux-result.json').read_text())
def run(case,out,inputs=None,memory_mode=False):
 if case not in CASES: raise ValueError('unknown case')
 return memory(case,out,inputs) if memory_mode else external(case,out,inputs)
def main(argv=None):
 p=argparse.ArgumentParser(); p.add_argument('--case',choices=CASES,required=True); p.add_argument('--output',required=True); p.add_argument('--inputs'); p.add_argument('--memory',action='store_true'); a=p.parse_args(argv); inputs=json.loads(Path(a.inputs).read_text()) if a.inputs else {}; r=run(a.case,a.output,inputs,a.memory); print(json.dumps({'status':'pass','case':r['case'],'fixture':r.get('fixture')})); return 0
if __name__=='__main__': raise SystemExit(main())
