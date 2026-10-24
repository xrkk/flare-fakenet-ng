#!/usr/bin/env python3
"""Independent Linux runtime/deploy oracle."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
CHECKS={'LINUX-SINGLEHOST':['singlehost','multihost','nfqueue','ipv6-block','restore'],'LINUX-DEPLOY-UPDATE':['install','idle-update','transaction','token','rollback']}
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def evaluate(root,original,case,checks=None,allow_fixture=False):
 v=json.loads((Path(original)/'linux-result.json').read_text())
 if v.get('case')!=case or v.get('schema')!='fakenet.linux-runtime-result.v1':raise ValueError('Linux result case/schema mismatch')
 if v.get('fixture') is True and not allow_fixture:raise ValueError('Linux fixture cannot earn native credit')
 if v.get('case')!=case: raise ValueError('case mismatch')
 if v.get('fixture') is True and not allow_fixture: raise ValueError('fixture cannot native credit')
 rows={}
 try:
  if case=='LINUX-SINGLEHOST':
   t=Path(v['config']).read_text(); compact=''.join(t.split())
   rows['singlehost']='pass' if 'networkmode:singlehost' in compact.lower() and v.get('mode')=='singlehost' else 'fail'
   rows['multihost']='pass' if 'multihost' in compact.lower() else 'fail'
   rows['nfqueue']='pass' if bool(v['rules'].get('v4')) else 'fail'
   rows['ipv6-block']='pass' if any(x and x[0]=='ip6tables' for x in v['rules'].get('v6',[])) else 'fail'
   rows['restore']='pass' if v.get('before')==v.get('after')=={'rules':0} and v.get('cleanup',{}).get('stopped') is True else 'fail'
  else:
   r=json.loads(Path(v['receipt']).read_text()); package=Path(v['inputs']['install_package'])
   rows['install']='pass' if r.get('phase')=='completed' else 'fail'
   rows['idle-update']='pass' if r.get('operation')==v['inputs'].get('operation') else 'fail'
   rows['transaction']='pass' if r.get('manifest')==sha(package/'manifest.json') else 'fail'
   token=Path(v['inputs']['root'])/'etc/fakenet-ng-linux/token'
   rows['token']='pass' if token.is_file() and len(token.read_text().strip()) in (64,65) and (token.stat().st_mode & 0o777)==0o600 else 'fail'
   rows['rollback']='pass' if r.get('originals') else 'fail'
 except Exception as exc:
  rows={x:'fail' for x in CHECKS[case]}; rows['error']='%s: %s' % (type(exc).__name__,exc)
 out=[{'id':x,'status':rows.get(x,'fail')} for x in (checks or CHECKS[case])]
 clean=all(x['status']=='pass' for x in out) and v['cleanup']['stopped'] is True and v['cleanup']['network_restored'] is True
 return out,clean,rows
