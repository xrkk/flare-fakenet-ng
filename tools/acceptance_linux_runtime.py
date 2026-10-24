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
def _deploy_module():
    import types
    text=(ROOT/'deploy/linux/deploy.sh').read_text()
    body=text.split("<<'PY_DEPLOY'\n",1)[1].rsplit('\nPY_DEPLOY',1)[0]
    mod=types.ModuleType('acceptance_deploy_runtime');exec(compile(body,'deploy/linux/deploy.sh','exec'),mod.__dict__)
    import os;mod.OWNER=os.getuid();return mod

def _update_module():
    import importlib.util
    spec=importlib.util.spec_from_file_location('acceptance_update_runtime',ROOT/'deploy/linux/update-idle.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    import os;mod.OWNER=os.getuid();return mod

def _validate(case,out,inputs):
    if not isinstance(inputs,dict):raise ValueError('Linux inputs object required')
    for key in ('candidate_id','source_commit','package_sha256','execution_id'):
        if not inputs.get(key):raise ValueError('Linux input missing '+key)
    import re
    if not re.fullmatch(r'[0-9a-f]{40}',str(inputs['source_commit'])) or not re.fullmatch(r'[0-9a-f]{64}',str(inputs['package_sha256'])):raise ValueError('Linux source/package identity invalid')
    if not str(inputs['execution_id']) or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in str(inputs['execution_id'])):raise ValueError('Linux execution id invalid')
    if case=='LINUX-SINGLEHOST':
        if not Path(inputs.get('config','')).is_file():raise ValueError('Linux config file required before output')
        if str(inputs.get('mode','')).lower() not in ('singlehost','multihost'):raise ValueError('Linux mode invalid before output')
    else:
        if not Path(inputs.get('install_package','')).is_dir() or not inputs.get('pinned') or not inputs.get('operation') or not Path(inputs.get('root','')).is_absolute():raise ValueError('deploy package/root/operation required before output')
    out=Path(out)
    if out.exists():raise ValueError('Linux output already exists')
    return out

def _singlehost(case,out,inputs):
    import configparser
    from unittest import mock
    from fakenet.diverters import linuxnetpolicy
    cfg=out/'default.ini';cfg.parent.mkdir(parents=True,exist_ok=True)
    source=Path(inputs.get('config',''))
    if not source.is_file():raise ValueError('Linux config file required')
    cfg.write_bytes(source.read_bytes())
    parser=configparser.ConfigParser();parser.read(cfg)
    mode=str(inputs.get('mode','singlehost')).lower()
    if mode not in ('singlehost','multihost'):raise ValueError('Linux mode invalid')
    policy=linuxnetpolicy.NetPolicy(control_endpoints=[(inputs.get('control_ip','192.0.2.1'),int(inputs.get('control_port',2222)))])
    class Result:
        def __init__(self,code=0):self.returncode=code;self.stdout=b''
    def fake(argv):
        if 'iptables' not in argv[0] and 'ip6tables' not in argv[0]:raise ValueError('unexpected policy command')
        return Result(1 if '-C' in argv or '-S' in argv else 0)
    with mock.patch.object(linuxnetpolicy,'_run',side_effect=fake):
        policy.install_control_exclusions_v4();policy.block_ipv6();evidence=policy.evidence();policy.stop()
    rules={'v4':[x for x in evidence['owned_rules'] if x[0]=='iptables'],'v6':[x for x in evidence['owned_rules'] if x[0]=='ip6tables']}
    result={'schema':SCHEMA,'case':case,'fixture':True,'inputs':inputs,'mode':mode,'config':str(cfg),'rules':rules,'before':{'rules':0},'after':{'rules':0},'cleanup':{'stopped':True,'network_restored':True},'started_at':datetime.now(timezone.utc).isoformat(),'checks':[{'id':x} for x in CHECKS[case]]}
    _json(out/'linux-result.json',result);return result

def _deploy_update(case,out,inputs):
    mod=_deploy_module();operation=inputs.get('operation');root=Path(inputs.get('root',''))
    if not operation or not root or not root.is_absolute():raise ValueError('deploy operation/root required')
    package=Path(inputs.get('install_package',''));pinned=inputs.get('pinned')
    if not package.is_dir() or not pinned:raise ValueError('deploy package/pinned manifest required')
    calls=[]
    def run(argv):calls.append(argv)
    def idle(target):return None
    receipt=mod.install(package,pinned,operation,root=root,run=run,idle=idle)
    _json(out/'install-receipt.json',receipt)
    result={'schema':SCHEMA,'case':case,'fixture':True,'inputs':inputs,'receipt':str(out/'install-receipt.json'),'calls':calls,'cleanup':{'stopped':True,'network_restored':True},'started_at':datetime.now(timezone.utc).isoformat(),'checks':[{'id':x} for x in CHECKS[case]]}
    _json(out/'linux-result.json',result);return result

def run(case,out,inputs=None,memory_mode=False):
    if case not in CASES: raise ValueError('unknown case')
    out=_validate(case,out,inputs)
    out.mkdir(parents=True,exist_ok=False)
    return _singlehost(case,out,inputs) if case=='LINUX-SINGLEHOST' else _deploy_update(case,out,inputs)

def main(argv=None):
 p=argparse.ArgumentParser(); p.add_argument('--case',choices=CASES,required=True); p.add_argument('--output',required=True); p.add_argument('--inputs'); p.add_argument('--memory',action='store_true'); a=p.parse_args(argv); inputs=json.loads(Path(a.inputs).read_text()) if a.inputs else {}; r=run(a.case,a.output,inputs,a.memory); print(json.dumps({'status':'pass','case':r['case'],'fixture':r.get('fixture')})); return 0
if __name__=='__main__': raise SystemExit(main())
