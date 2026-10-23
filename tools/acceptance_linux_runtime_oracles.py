#!/usr/bin/env python3
"""Independent Linux runtime/deploy oracle."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
CHECKS={'LINUX-SINGLEHOST':['singlehost','multihost','nfqueue','ipv6-block','restore'],'LINUX-DEPLOY-UPDATE':['install','idle-update','transaction','token','rollback']}
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def evaluate(root,original,case,checks=None,allow_fixture=False):
 raise NotImplementedError('Linux runtime/deploy oracle is not implemented in T007/R02')
 v=json.loads((Path(original)/'linux-result.json').read_text())
 if v.get('case')!=case: raise ValueError('case mismatch')
 if v.get('fixture') is True and not allow_fixture: raise ValueError('fixture cannot native credit')
 rows={}
 try:
  if case=='LINUX-SINGLEHOST':
   t=Path(v['config']).read_text(); rows['singlehost']='pass' if 'NetworkMode: SingleHost' in t else 'fail'; rows['multihost']='pass' if 'LinuxRestrictInterface: eth0' in t else 'fail'; rows['nfqueue']='pass' if 'LinuxControlEndpoints: 192.0.2.1:2222' in t else 'fail'; rows['ipv6-block']='pass' if 'ip6tables' in str(v['rules']) else 'fail'; rows['restore']='pass' if v['before']==v['after']=={'rules':0} else 'fail'
  else:
   r=json.loads(Path(v['receipt']).read_text()); rows['install']='pass' if r.get('phase')=='completed' else 'fail'; rows['idle-update']='pass' if r.get('operation')=='update-0001' else 'fail'; rows['transaction']='pass' if r.get('manifest')==sha(v['package']+'/manifest.json') else 'fail'; rows['token']='pass' if len(Path(v['token']).read_text().strip())==64 and v['token_mode']==0o600 else 'fail'; rows['rollback']='pass' if r.get('originals') else 'fail'
 except Exception as exc:
  rows={x:'fail' for x in CHECKS[case]}; rows['error']='%s: %s' % (type(exc).__name__,exc)
 out=[{'id':x,'status':rows.get(x,'fail')} for x in (checks or CHECKS[case])]
 clean=all(x['status']=='pass' for x in out) and v['cleanup']['stopped'] is True and v['cleanup']['network_restored'] is True
 return out,clean,rows
