"""P14 single input case and strict responsibility observer, never a P05 batch.

Operator/recoverable native fixtures are deliberately admission gated. A stopped
service cannot prove retained recovery ownership by closing an unrelated client.
"""
from __future__ import annotations
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
import scenario_suite as suite

BUDGETS = {'start':480, 'stop':480, 'operator':510, 'reconcile':60, 'read':90}
SECTIONS = {'dns_servers','routes','listen_ports','windivert_processes','services'}

def responsibility_verdict(proof):
    """Logical observer only; native acquisition and integrity are separate gates."""
    errors=[]
    before=proof.get('before',{});held=proof.get('held',{});after=proof.get('after',{})
    fields=('run_id','controller','pid','creation_time','job','helper','exit_deadline','failure_reason')
    if any(not before.get(k) for k in fields) or not before.get('failure_reason'):
        errors.append('missing native responsibility or original failure')
    if not before.get('needs_recovery') or not held.get('needs_recovery'):
        errors.append('operation completion is not recovery')
    if any(before.get(k)!=held.get(k) for k in fields):errors.append('responsibility replaced')
    op=proof.get('operation',{})
    if op.get('semantic')!='fakenetng-mcp.exe stop' or op.get('exit_code')!=1 or not 0<=op.get('seconds',-1)<=BUDGETS['operator']:
        errors.append('unsupported or unbounded operator operation')
    start=proof.get('start',{})
    if start.get('error_code')!='not_allowed_in_state' or start.get('owner_after')!=held:
        errors.append('start overwrote owner or was not rejected')
    disabled=proof.get('fault_disabled',{})
    arm=proof.get('fault_arm',{})
    retry=proof.get('retry',{})
    if disabled.get('run_id')!=before.get('run_id') or not disabled.get('nonce') or disabled.get('nonce')!=arm.get('nonce') or arm.get('run_id')!=before.get('run_id') or not disabled.get('verified_absent'):
        errors.append('fault disable is not bound to own run')
    if retry.get('run_id')!=before.get('run_id') or not 0<=retry.get('seconds',-1)<=BUDGETS['operator'] or retry.get('exit_code')!=0:
        errors.append('retry is not same responsibility or bounded')
    if after.get('needs_recovery') is not False or after.get('owner') is not None:
        errors.append('recovery remains unresolved')
    if set(proof.get('five_sections_before',{}))!=SECTIONS or set(proof.get('five_sections_after',{}))!=SECTIONS or proof.get('audit_diff')!={}:
        errors.append('five-section recovery proof missing or different')
    return {'passed':not errors,'errors':errors,'nature':'logical observer, not native acceptance'}

class Journal:
    def __init__(self, out):self.out=out;self.seq=0
    def save(self,name,value):
        with (self.out/name).open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2)
    def append(self,value):
        with (self.out/'rpc.jsonl').open('a',encoding='utf-8') as stream:stream.write(json.dumps(value,ensure_ascii=False)+'\n')
    def vm(self,command,timeout=90):
        try:r=self.channel.powershell(command,timeout)
        except Exception as exc:
            self.append({'kind':'vm','command':command,'error':repr(exc),'record':getattr(exc,'record',None)});raise
        self.append({'kind':'vm','response':r});assert not r['is_error'],r
        return r
    def call(self,name,args=None,timeout=90):
        try:return self.service.tool_outcome(name,args,timeout)
        except Exception as exc:
            self.append({'kind':'command_unknown','name':name,'arguments':args,'error':repr(exc)})
            if args and 'command_id' in args:
                r=suite.reconcile_timed_out_command(self.service,args['command_id'],name,self.service.controller_id,budget_seconds=60)
                self.save('unknown-'+args['command_id']+'.json',r)
            raise # never resend unknown mutation
    def value(self,name,args=None,timeout=90):
        r=self.call(name,args,timeout);assert r['ok'],r;return r['value']
    def mutation(self,tool,**args):
        self.gate(clean=tool not in ('stop',))
        status=self.value('get_status')
        args.update(command_id='r05-p14-'+uuid.uuid4().hex,expected_state_version=status['state_version'])
        return self.call(tool,args,BUDGETS.get(tool,90))
    def snapshot(self):
        r=self.vm(r'''$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'";$p=Get-Process -Id $s.ProcessId;@{computer=$env:COMPUTERNAME;uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;mac=@(Get-NetAdapter|Select-Object MacAddress);pid=$p.Id;creation_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();exe_sha=(Get-FileHash 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe').Hash.ToLower();default_sha=(Get-FileHash 'C:\Program Files\FakeNet-NG-MCP\configs\default.ini').Hash.ToLower();marker=(Get-Content 'C:\ProgramData\FakeNet-NG-MCP\state\state.json' -Raw|ConvertFrom-Json);space=@(Get-PSDrive C,E|Select-Object Name,Free);processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match 'fakenet|curl|probe|pktmon'}|Select-Object Name,ProcessId,CommandLine);fault_env=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\fakenetng-mcp' -Name Environment -ErrorAction SilentlyContinue).Environment;utc=[DateTime]::UtcNow.ToString('o');qpc=[Diagnostics.Stopwatch]::GetTimestamp();frequency=[Diagnostics.Stopwatch]::Frequency}|ConvertTo-Json -Depth 7 -Compress''')
        return json.loads(r['output'])
    def gate(self,clean=True):
        v=self.snapshot();self.seq+=1;self.save('gate-%02d.json'%self.seq,v)
        assert v['computer']=='DESKTOP-3FI41GR' and v['uuid']=='D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49'
        assert any(x['MacAddress']=='00-0C-29-C1-CA-49' for x in v['mac'])
        assert (v['pid'],v['creation_filetime'])==(7484,134335767401378067), 'instance changed: native first self-check required'
        assert v['exe_sha']=='1dc9ab9bff26d3aeabedbae98c0c4e737025fb591f39edd96c9fdfcff9ca312c'
        assert v['default_sha']=='71e530fa54710c8c6e4f6644f99858b514e3e724d7957e7bdbaa6de0029cac1a'
        free={x['Name']:x['Free'] for x in v['space']}
        assert free['C']>=2*2**30+64*2**20 and free['E']>=3*2**30+64*2**20
        for p,minfree in [(ROOT,4*2**30),('/tmp',512*2**20)]:
            s=os.statvfs(p);assert s.f_bavail*s.f_frsize>=minfree
        assert not v['fault_env'], 'foreign or enabled fault source: separate native contract required'
        assert not any(x['Name'].lower() in ('curl.exe','pktmon.exe','fakenetng-mcp-managed.exe','fakenetng-mcp-exit-monitor.exe') for x in v['processes']) if clean else True
        status=self.value('get_status')
        if clean:assert status['state']=='stopped' and not status['run_id'] and not status['controller'] and not v['marker']['needs_recovery']
        else:assert status['run_id'] in (None,self.run_id) and status['controller'] in (None,self.service.controller_id)
        return v
    def sections(self,label):
        from fakenet.mcp.baseline import process_capture_script
        cmd=r'''$ErrorActionPreference='Stop';@{dns_servers=(Get-DnsClientServerAddress -AddressFamily IPv4|Select-Object InterfaceAlias,ServerAddresses|ConvertTo-Json -Compress);routes=(& route.exe print -4|Out-String);listen_ports=(& netstat.exe -ano|Out-String);windivert_processes=(& {'''+process_capture_script()+r'''}|Out-String);services=(Get-Service dnscache,mpssvc|Select-Object Name,Status|ConvertTo-Json -Compress)}|ConvertTo-Json -Depth 8 -Compress'''
        v=json.loads(self.vm(cmd)['output']);assert set(v)==SECTIONS;self.save(label+'.json',v);return v
    def operator_stop(self, native_owner):
        """Invoke the actual installed administrative pre-stop, without kill fallback.

        Requires an acquired current own-run native responsibility proof. Missing
        proof is an admission failure; a caller must retain the original deadline.
        """
        observed=self.snapshot();status=self.value('get_status')
        assert status['state']=='failed' and observed['marker']['needs_recovery']
        assert status['run_id']==self.run_id and status['controller']==self.service.controller_id
        assert all(native_owner.get(k) is not None for k in ('pid','creation_time','job','helper','exit_deadline','failure_reason'))
        assert native_owner['run_id']==self.run_id and native_owner['controller']==self.service.controller_id
        assert observed['pid']==7484 and observed['creation_filetime']==134335767401378067
        # CLI has its own unchanged 60+450 second ceiling. A transport timeout
        # is unknown, not authorization to resend or terminate the service.
        command=r"$ErrorActionPreference='Stop';$began=[Diagnostics.Stopwatch]::GetTimestamp();$before=Get-Content 'C:\ProgramData\FakeNet-NG-MCP\logs\service-stop-result.json' -Raw;$marker=Get-Content 'C:\ProgramData\FakeNet-NG-MCP\state\state.json' -Raw;& 'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe' stop;$code=$LASTEXITCODE;@{exit_code=$code;seconds=([Diagnostics.Stopwatch]::GetTimestamp()-$began)/[Diagnostics.Stopwatch]::Frequency;before=$before;marker_before=$marker;prestop_after=(Get-Content 'C:\ProgramData\FakeNet-NG-MCP\logs\service-stop-result.json' -Raw);marker_after=(Get-Content 'C:\ProgramData\FakeNet-NG-MCP\state\state.json' -Raw);utc=[DateTime]::UtcNow.ToString('o');qpc=[Diagnostics.Stopwatch]::GetTimestamp()}|ConvertTo-Json -Depth 6 -Compress"
        r=self.vm(command,540);result=json.loads(r['output'])
        assert result['seconds']<=BUDGETS['operator']
        result.update(semantic='fakenetng-mcp.exe stop',native_owner_before=native_owner)
        return result

    def export(self):
        # Exact own-run paths, bounded per file and total; no broad Logs export.
        run=self.run_id;assert run and str(uuid.UUID(run))==run
        cmd=r'''$ErrorActionPreference='Stop';$run='''+suite.quote_ps(run)+r''';$root='C:\ProgramData\FakeNet-NG-MCP';$dirs=@((Join-Path $root ('artifacts\runs\'+$run)),(Join-Path $root ('logs\\exit-evidence\'+$run)));$items=@();foreach($dir in $dirs){if(Test-Path -LiteralPath $dir){$items+=@(Get-ChildItem -LiteralPath $dir -File -Recurse)}};$items+=@(Get-ChildItem (Join-Path $root 'logs') -File -Filter ('recovery-audit-'+$run+'-*.jsonl'));$baseline=Join-Path $root ('baselines\'+$run+'.json');if(Test-Path $baseline){$items+=Get-Item $baseline};$total=0;$files=@();foreach($p in $items){if($p.Extension -notin @('.json','.jsonl','.log','.ini','.txt')){continue};if($p.Length -gt 8MB){throw 'bounded export file exceeds 8 MiB'};$total+=$p.Length;if($total -gt 64MB){throw 'bounded export exceeds 64 MiB'};$b=[IO.File]::ReadAllBytes($p.FullName);$files+=@{path=$p.FullName;size=$b.Length;sha256=(Get-FileHash $p.FullName).Hash.ToLower();base64=[Convert]::ToBase64String($b)}};@{run_id=$run;files=$files}|ConvertTo-Json -Depth 5 -Compress'''
        result=json.loads(self.vm(cmd,120)['output']);directory=self.out/'originals';directory.mkdir()
        records=[]
        for i,f in enumerate(result['files']):
            b=base64.b64decode(f['base64'],validate=True);assert len(b)==f['size'] and hashlib.sha256(b).hexdigest()==f['sha256']
            name='%03d-%s'%(i,Path(f['path'].replace('\\','/')).name);(directory/name).write_bytes(b)
            records.append({k:v for k,v in f.items() if k!='base64'}|{'local':'originals/'+name})
        self.save('export-index.json',{'run_id':run,'files':records});return records

def main():
    p=argparse.ArgumentParser();p.add_argument('--case',required=True,choices=['unsatisfiable-input','recoverable','operator']);p.add_argument('--output',required=True,type=Path);p.add_argument('--contract',required=True,type=Path);a=p.parse_args()
    c=json.loads(a.contract.read_text(encoding='utf-8'));assert c['budgets']==BUDGETS and c['self_review']=='within-original-scope'
    for name,sha in c['wrappers'].items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha, 'wrapper identity changed: '+name
    a.output.resolve().relative_to((ROOT/'Logs').resolve());a.output.mkdir(parents=True,exist_ok=False)
    j=Journal(a.output);j.channel=suite.VmMcp('http://192.168.204.233:28787/mcp');j.service=suite.RawMcp('http://192.168.204.233:28788/mcp',controller_id=str(uuid.uuid4()));j.run_id=None
    original_post=j.service._post
    def recorded(body,headers=None,timeout=120):
        begun=time.monotonic();row={'kind':'product','body':body,'headers':headers,'timeout':timeout,'host_started':datetime.datetime.now().astimezone().isoformat()}
        try:r=original_post(body,headers,timeout);row['response'],row['response_headers']=r;return r
        except Exception as exc:row['error']=repr(exc);raise
        finally:row['seconds']=time.monotonic()-begun;j.append(row)
    j.service._post=recorded
    outcome={'case':a.case,'status':'BLOCKED','new_native_case':False}
    try:
        j.gate();before=j.sections('five-sections-before')
        if a.case!='unsatisfiable-input':
            outcome['reason']=('recoverable: inherit verified R89 originals, no new run' if a.case=='recoverable' else 'No current failed/needs_recovery native owner or approved persistent-own-fault fixture. Existing receiver faults are recoverable; operator action is SCM PRESTOP through fakenetng-mcp.exe stop. No kill, poison baseline or unrelated client substitute authorized.')
            return 2
        assert j.value('get_status')['config_identity']['name']=='default.ini'
        content=suite.profile_content(suite.profile_for_bucket('B2',0),'8.8.8.8',reviewed_ipv4='8.8.8.8')
        (a.output/'input.ini').write_bytes(content.encode('utf-8'))
        verdict=j.value('validate_config',{'content':content});j.save('static-validation.json',verdict);assert verdict['valid'],verdict
        name='r05-p14-unsatisfiable-'+uuid.uuid4().hex[:12]+'.ini'
        r=j.mutation('create_config',name=name,content=content);assert r['ok'],r
        r=j.mutation('load_config',name=name);assert r['ok'],r
        r=j.mutation('start');j.save('start-original.json',r)
        j.run_id=(r.get('value') or {}).get('run_id') or j.value('get_status').get('run_id')
        if not j.run_id:
            marker=j.snapshot()['marker']
            assert marker['command_id']==r['sent_arguments']['command_id'] and marker['controller_id']==j.service.controller_id, 'completed failed run identity mismatch'
            j.run_id=marker['run_id']
        current=j.value('get_status');j.save('after-start.json',current)
        assert current['state']!='healthy', 'unexpected acceptance of incompatible resolver rule'
        if current['run_id']:
            assert current['controller']==j.service.controller_id
            j.run_id=current['run_id']
            j.save('retained-before-retry.json',j.snapshot())
            r=j.mutation('stop');j.save('same-owner-stop.json',r);assert r['ok'],r
        j.gate()
        if j.run_id:j.export()
        outcome.update(status='PARTIAL',new_native_case=True,reason='Actual input attempted; evaluate protected-resolver rejection originals before claiming baseline clause.')
    except Exception as exc:outcome.update(status='FAILED',reason=repr(exc));raise
    finally:
        # Preserve failed/needs_recovery responsibility. Never clean state or kill.
        try:
            current=j.value('get_status');j.save('finally-status-before.json',current)
            if current['state']=='stopped' and not current['run_id'] and not current['controller']:
                if current['config_identity']['name']!='default.ini':
                    r=j.mutation('load_config',name='default.ini');j.save('restore-default.json',r);assert r['ok'],r
                j.gate();j.sections('five-sections-after')
            else:outcome.update(status='BLOCKED',needs_recovery=True,reason='Recovery remains owned; later mutations stopped')
            j.save('finally-status.json',j.value('get_status'))
        except Exception as exc:outcome['finally_error']=repr(exc);outcome['status']='FAILED'
        j.save('result.json',outcome)
    return 0 if outcome['status']=='PARTIAL' else 1
if __name__=='__main__':raise SystemExit(main())
