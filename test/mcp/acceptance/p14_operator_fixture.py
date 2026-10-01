"""Approved P14 one-case external-loopback audit fixture. No product repair.

Mutations are sent once. CLI completion is a native process fact, separate from
RPC completion and from retained recovery responsibility. Rejudge reads SHA
bound original bytes and never contacts a VM.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid
ROOT=Path(__file__).resolve().parents[3]
SOURCE='ade1059e99e654bf7a263e3b133afd61de67f314'
CANDIDATE='mcp-cade1059e-0ef21513488c'
ZIP='0ef21513488c2645fd9924cba1499c9113454644616922b2f823050d86ecec64'
PS_ENGINE=r'C:\Program Files\PowerShell\7\pwsh.exe'
PS_ENGINE_SHA='db6dd81183fe57d22e03b911ec9a30a2fd7c40542e97743615355a6fb44f458f'
EXE='1dc9ab9bff26d3aeabedbae98c0c4e737025fb591f39edd96c9fdfcff9ca312c'
SECTIONS={'dns_servers','routes','listen_ports','windivert_processes','services'}
WORKER=Path(__file__).with_name('p14_loopback_listener.ps1')
class Unknown(RuntimeError):pass

def sha(raw):return hashlib.sha256(raw).hexdigest()
def write_new(path,value):
    with Path(path).open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2)
def release_receipt(ready):
    return {k:ready[k] for k in ('run_id','controller','nonce','pid','creation_time')}|{'action':'release'}
def release_matches(receipt,ready):return receipt==release_receipt(ready)
def fixture_valid(ready,run,controller,nonce,elapsed):
    return (ready.get('run_id')==run and ready.get('controller')==controller and ready.get('nonce')==nonce and
            ready.get('address')=='127.0.0.1' and type(ready.get('port')) is int and 0<ready['port']<65536 and
            type(ready.get('pid')) is int and bool(ready.get('creation_time')) and ready.get('in_any_job') is False and 0<=elapsed<1800)
def preparation_eligible(previous_result,observation,fixture_or_operator_entered):
    return (previous_result.get('status')=='FAILED' and not fixture_or_operator_entered and observation.get('observer') is None and observation.get('service',{}).get('State')=='Running' and observation.get('prestop',{}).get('phase')=='idle' and observation.get('prestop',{}).get('attempt')==0 and any('Get-FileHash' in (f.get('raw') or '') for row in observation.get('own',[]) for f in row.get('files',[]) if f.get('name')=='worker-err.txt'))

def export_plan(label):
    if label=='healthy-originals':return {'sealed_only':True,'binary_inventory':False,'names':['creation.jsonl','active-config.ini']}
    return {'sealed_only':False,'binary_inventory':True,'names':None}

def once(call,*args,**kwargs):
    try:return call(*args,**kwargs)
    except Exception as exc:raise Unknown('mutation/launch outcome unknown; read-only reconciliation only') from exc

def validate_responsibility(before,held,kind,resources):
    if not all(before.get(k) for k in ('run_id','controller','baseline_sha256','failure_reason')):return False
    if any(before.get(k)!=held.get(k) for k in ('run_id','controller','baseline_sha256')):return False
    if held.get('needs_recovery') is not True:return False
    if kind=='audit_pending':return bool(resources.get('native_ended')) and bool(before.get('audit_tcp_difference'))
    if kind=='resource_pending':return bool(resources.get('independent_native_live')) and bool(resources.get('original_deadline'))
    return False

def cli_valid(result,code):
    return (result.get('native_ended') is True and result.get('exit_code')==code and
            0<=result.get('seconds',-1)<=510 and bool(result.get('cli',{}).get('creation_time')) and
            type(result.get('cli',{}).get('pid')) is int and result['cli'].get('semantic')=='fakenetng-mcp.exe stop')
def new_attempt(before,after):
    return (before.get('instance_id')==after.get('instance_id') and
            before.get('pid')==after.get('pid') and before.get('creation_time')==after.get('creation_time') and
            type(after.get('attempt')) is int and after['attempt']>before['attempt'])

def verdict(p):
    checks={
      'CLI1_native_ended_bounded':cli_valid(p.get('operator',{}),1),
      'audit_pending_owner_retained':validate_responsibility(p.get('before',{}),p.get('held',{}),'audit_pending',p.get('resources',{})),
      'service_same_instance_alive_at_CLI1':p.get('service_alive_at_CLI1') is True,
      'new_failed_PRESTOP':new_attempt(p.get('prestop_before',{}),p.get('prestop_failed',{})) and p.get('prestop_failed',{}).get('phase')=='failed',
      'start_rejected_no_owner_replacement':p.get('start_error')=='not_allowed_in_state' and p.get('start_owner_preserved') is True,
      'cooperative_fixture_release':p.get('fixture_closed',{}).get('reason')=='cooperative_release' and p.get('fixture_native_ended') is True and p.get('three_absent_samples') is True,
      'CLI0_native_ended_bounded':cli_valid(p.get('retry',{}),0),
      'new_succeeded_PRESTOP':new_attempt(p.get('prestop_failed',{}),p.get('prestop_final',{})) and p.get('prestop_final',{}).get('phase')=='succeeded',
      'SCM_STOPPED_marker_false':p.get('service_stopped') is True and p.get('final_marker',{}).get('needs_recovery') is False,
      'same_baseline_bytes':p.get('baseline_sha_before')==p.get('baseline_sha_after') and bool(p.get('baseline_sha_before')),
      'two_clean_audit_samples':p.get('two_clean_audit_samples') is True,
      'original_failure_preserved':p.get('original_failure_preserved') is True,
      'fixture_did_not_expire':p.get('fixture_did_not_expire') is True,
    }
    return {'passed':all(checks.values()),'checks':checks,'nature':'must be backed by indexed native originals; self-contained proofs are logical only'}

class Runner:
    def __init__(self,out):
        sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).parent))
        import p14_single
        self.suite=p14_single.suite;self.j=p14_single.Journal(out)
        self.j.channel=self.suite.VmMcp('http://192.168.204.233:28787/mcp')
        self.j.service=self.suite.RawMcp('http://192.168.204.233:28788/mcp',controller_id=str(uuid.uuid4()))
        self.j.run_id=None;self.out=out;self.n=0;self.root=None;self.ready=None;self.launched=False;self.released=False
        self.retry_sent=False;self.last_mutation_terminal=True;self.records=[];self.proof={};self.started=time.monotonic()
        original=self.j.service._post
        def recorded(body,headers=None,timeout=120):
            row={'kind':'product','body':body,'headers':headers,'timeout':timeout};t=time.monotonic()
            try:r=original(body,headers,timeout);row['response'],row['response_headers']=r;return r
            except Exception as e:row['error']=repr(e);raise
            finally:row['elapsed']=time.monotonic()-t;self.j.append(row)
        self.j.service._post=recorded
    def stage(self,text):print(json.dumps({'stage':text,'elapsed':time.monotonic()-self.started}),flush=True)
    def vm(self,cmd,timeout=60):return self.j.vm(cmd,timeout)
    def ps(self,x):return self.suite.quote_ps(str(x))
    def vm_json(self,cmd,timeout=60):return json.loads(self.vm(cmd,timeout)['output'])
    def save(self,name,value):self.j.save(name,value)
    def status(self):return self.j.value('get_status')
    def mutate(self,name,**args):
        status=self.status();args.update(command_id='r07-'+uuid.uuid4().hex,expected_state_version=status['state_version'])
        self.last_mutation_terminal=False
        try:r=self.j.call(name,args,480)
        except Exception:
            # Journal.call performs only command-ID reconciliation, never resend.
            raise
        self.last_mutation_terminal=True;self.save(name+'-'+args['command_id']+'.json',r);return r
    def scene(self,label,product=True):
        self.n+=1
        cmd=r'''$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'";$p=if($s.ProcessId){Get-Process -Id $s.ProcessId -ErrorAction SilentlyContinue};$pre='C:\ProgramData\FakeNet-NG-MCP\logs\service-stop-result.json';$state='C:\ProgramData\FakeNet-NG-MCP\state\state.json';@{service=$s|Select-Object State,ProcessId,ExitCode;pid=$p.Id;creation_time=if($p){[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()};prestop=(Get-Content $pre -Raw|ConvertFrom-Json);marker=(Get-Content $state -Raw|ConvertFrom-Json);processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match 'fakenet|powershell'}|Select-Object ProcessId,ParentProcessId,Name,CommandLine);utc=[DateTime]::UtcNow.ToString('o');qpc=[Diagnostics.Stopwatch]::GetTimestamp();frequency=[Diagnostics.Stopwatch]::Frequency}|ConvertTo-Json -Depth 9 -Compress'''
        v=self.vm_json(cmd);v['product']=self.status() if product else None
        self.save('%02d-%s-scene.json'%(self.n,label),v);return v
    def read_guest_json(self,path):
        return self.vm_json('$ErrorActionPreference=\'Stop\';$p='+self.ps(path)+";if(Test-Path -LiteralPath $p){Get-Content -LiteralPath $p -Raw}else{'null'}",30)
    def native_sample(self,label):
        r=self.ready;cmd=r'''$ErrorActionPreference='Stop';$id='''+str(r['pid'])+r''';$port='''+str(r['port'])+r''';$p=Get-Process -Id $id -ErrorAction SilentlyContinue;@{pid=$p.Id;creation_time=if($p){[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()};rows=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object {$_.LocalPort -eq $port}|Select-Object LocalAddress,LocalPort,OwningProcess);netstat=(& netstat.exe -ano|Out-String);qpc=[Diagnostics.Stopwatch]::GetTimestamp();frequency=[Diagnostics.Stopwatch]::Frequency}|ConvertTo-Json -Depth 5 -Compress'''
        v=self.vm_json(cmd,30);self.n+=1;self.save('%02d-%s-sample.json'%(self.n,label),v);return v
    def samples(self,present):
        samples=[self.native_sample('present' if present else 'absent') for _ in range(3)]
        for s in samples:
            rows=s['rows'];rows=rows if isinstance(rows,list) else [rows] if rows else []
            if present:
                assert str(s['pid'])==str(self.ready['pid']) and str(s['creation_time'])==self.ready['creation_time']
                assert rows and all(x['LocalAddress']=='127.0.0.1' and x['OwningProcess']==self.ready['pid'] for x in rows)
            else:assert not rows
        return samples
    def resource_gate(self,label):
        v=self.vm_json("@{space=@(Get-PSDrive C,E|Select-Object Name,Free);processes=@(Get-Process|Where-Object {$_.ProcessName -match 'fakenet|mcp|python|powershell'}|Select-Object Id,ProcessName,WorkingSet64,PrivateMemorySize64,HandleCount);utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5 -Compress",30)
        for name,minfree in [('C',2*2**30+64*2**20),('E',3*2**30+64*2**20)]:assert next(x['Free'] for x in v['space'] if x['Name']==name)>=minfree
        v['host']={}
        for path,minfree in [(ROOT,4*2**30),('/tmp',512*2**20)]:
            st=os.statvfs(path);free=st.f_bavail*st.f_frsize;assert free>=minfree;v['host'][str(path)]=free
        self.n+=1;self.save('%02d-%s-resources.json'%(self.n,label),v)
    def collect(self,label):
        self.resource_gate(label)
        run=self.j.run_id;assert run and str(uuid.UUID(run))==run
        roots=[r'C:\ProgramData\FakeNet-NG-MCP\artifacts'+'\\'+run,'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\'+run,'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\exit-evidence\\'+run]
        if self.root:roots.append(self.root)
        roots_ps='@('+','.join(self.ps(x) for x in roots)+')'
        plan=export_plan(label)
        select=(";$files=@($files|Where-Object {$_.Name -in @('creation.jsonl','active-config.ini')});" if plan['sealed_only'] else ';')
        cmd=r'''$ErrorActionPreference='Stop';$files=@();foreach($d in '''+roots_ps+r'''){if(Test-Path -LiteralPath $d){$files+=@(Get-ChildItem -LiteralPath $d -Recurse -File)}}'''+select+r'''$files+=@(Get-ChildItem 'C:\ProgramData\FakeNet-NG-MCP\logs' -File -Filter '''+self.ps('recovery-audit-'+run+'-*')+r''');$files+=Get-Item '''+self.ps('C:\\ProgramData\\FakeNet-NG-MCP\\baselines\\'+run+'.json')+r''';$files+=Get-Item 'C:\ProgramData\FakeNet-NG-MCP\logs\service-stop-result.json';$files+=Get-Item 'C:\ProgramData\FakeNet-NG-MCP\state\state.json';$total=0;$rows=@();$binary=@();foreach($f in $files){if($f.Extension -notin @('.json','.jsonl','.log','.ini','.txt')){$binary+=@{path=$f.FullName;size=$f.Length;sha256=(Get-FileHash $f.FullName).Hash.ToLower();retained_guest=$true};continue};if($f.Length -gt 8MB){throw 'single original exceeds 8MiB cap'};$total+=$f.Length;if($total -gt 64MB){throw 'export exceeds 64MiB cap'};$bytes=[IO.File]::ReadAllBytes($f.FullName);$rows+=@{path=$f.FullName;size=$bytes.Length;sha256=(Get-FileHash $f.FullName).Hash.ToLower();base64=[Convert]::ToBase64String($bytes)}};@{files=$rows;total=$total;binary_retained_guest=$binary}|ConvertTo-Json -Depth 6 -Compress'''
        data=self.vm_json(cmd,120);directory=self.out/label;directory.mkdir();records=[]
        for i,f in enumerate(data['files']):
            raw=base64.b64decode(f['base64'],validate=True);assert len(raw)==f['size'] and sha(raw)==f['sha256']
            local=directory/('%03d-%s'%(i,Path(f['path'].replace('\\','/')).name));local.write_bytes(raw)
            records.append({k:v for k,v in f.items() if k!='base64'}|{'local':str(local.relative_to(self.out))})
        self.save(label+'-index.json',{'files':records,'run_id':run,'total':data['total'],'binary_retained_guest':data['binary_retained_guest']});self.records.extend(records);return records
    def baseline(self):
        path='C:\\ProgramData\\FakeNet-NG-MCP\\baselines\\'+self.j.run_id+'.json'
        v=self.vm_json('$p='+self.ps(path)+";$b=[IO.File]::ReadAllBytes($p);@{sha256=(Get-FileHash $p).Hash.ToLower();base64=[Convert]::ToBase64String($b)}|ConvertTo-Json -Compress")
        raw=base64.b64decode(v['base64'],validate=True);assert sha(raw)==v['sha256'];return raw
    def setup_worker(self,directory,mode):
        script=WORKER.read_bytes();manifest={'run_id':self.j.run_id,'controller':self.j.service.controller_id,'nonce':self.nonce,'lease_seconds':1800,'directory':directory,'worker_sha256':sha(script),'exe_sha256':EXE,'service_pid':7484,'service_filetime':'134335767401378067'}
        raw=json.dumps(manifest).encode();payload={ 'worker.ps1':script,'manifest.json':raw }
        cmd="$ErrorActionPreference='Stop';$dir="+self.ps(directory)+";if(Test-Path $dir){throw 'own directory collision'};New-Item -ItemType Directory -Path $dir|Out-Null;"
        for name,b in payload.items():
            cmd+="$b=[Convert]::FromBase64String('"+base64.b64encode(b).decode()+"');$p=Join-Path $dir '"+name+"';$s=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$s.Write($b,0,$b.Length)}finally{$s.Dispose()};if((Get-FileHash $p).Hash.ToLower() -ne '"+sha(b)+"'){throw 'transfer SHA mismatch'};"
        cmd+="'SHA verified own tools';";self.vm(cmd,30)
        # At most one launch. Unknown result is reconciled only through own files.
        launch="$ErrorActionPreference='Stop';$dir="+self.ps(directory)+";$engine="+self.ps(PS_ENGINE)+";if((Get-FileHash $engine).Hash.ToLower() -cne '"+PS_ENGINE_SHA+"'){throw 'PowerShell engine drift'};$p=Start-Process $engine -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $dir 'worker.ps1'),'-Manifest',(Join-Path $dir 'manifest.json'),'-Mode','"+mode+"') -PassThru -RedirectStandardOutput (Join-Path $dir 'worker-out.txt') -RedirectStandardError (Join-Path $dir 'worker-err.txt');@{pid=$p.Id;creation_time=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()}|ConvertTo-Json -Compress"
        return once(self.vm_json,launch,30)
    def wait_file(self,path,seconds):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            v=self.read_guest_json(path)
            if v:return v
            time.sleep(2)
        raise Unknown('own output not published before original deadline: '+path)
    def release(self):
        if not self.launched or self.released:return
        if not self.ready:
            self.ready=self.wait_file(self.root+r'\ready.json',60)
        assert fixture_valid(self.ready,self.j.run_id,self.j.service.controller_id,self.nonce,0)
        receipt=release_receipt(self.ready);raw=base64.b64encode(json.dumps(receipt).encode()).decode()
        path=self.root+r'\release.json'
        cmd="$ErrorActionPreference='Stop';$p="+self.ps(path)+";$b=[Convert]::FromBase64String('"+raw+"');if(Test-Path $p){$old=[IO.File]::ReadAllBytes($p);if([Convert]::ToBase64String($old) -cne '"+raw+"'){throw 'foreign release receipt'}}else{$s=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()}};'own release published'"
        once(self.vm,cmd,30);closed=self.wait_file(self.root+r'\closed.json',30)
        assert closed['reason']=='cooperative_release' and closed['listener_stopped']
        self.proof['fixture_closed']=closed;self.samples(False)
        cmd="$p=Get-Process -Id "+str(self.ready['pid'])+" -ErrorAction SilentlyContinue;if($p -and [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -ceq '"+self.ready['creation_time']+"'){if(!$p.WaitForExit(10000)){throw 'fixture worker not ended'}};'native fixture ended'"
        ended=self.vm(cmd,15);self.save('fixture-native-ended.json',ended);self.proof.update(fixture_native_ended=True,three_absent_samples=True,fixture_did_not_expire=closed['seconds']<1800);self.released=True
    def cli(self,label):
        directory=self.root+'\\'+label;begin=time.monotonic();launch=self.setup_worker(directory,'Cli');self.save(label+'-launch.json',launch)
        r=self.wait_file(directory+r'\result.json',max(0,510-(time.monotonic()-begin)));self.save(label+'-cli-original.json',r)
        # Also join the CLI observer; never kill a live CLI or observer.
        self.vm('$p=Get-Process -Id '+str(launch['pid'])+" -ErrorAction SilentlyContinue;if($p -and [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -ceq '"+launch['creation_time']+"'){if(!$p.WaitForExit(5000)){throw 'CLI observer remains alive'}};'CLI observer ended'",10)
        return r,begin
    def wait_prestop_terminal(self,initial,deadline):
        while time.monotonic()<deadline:
            s=self.scene('prestop-readonly')
            if new_attempt(initial,s['prestop']) and s['prestop']['phase'] in ('failed','succeeded'):
                # failure file publication can precede worker finally; get_status
                # and read-only get_commands below prove command complete.
                events=self.j.call('get_events',{'limit':500});self.save('prestop-command-journal-'+str(s['prestop']['attempt'])+'.json',events)
                assert events['ok'] and any(e.get('kind')=='command.completed' and e.get('operation')=='service_controlled_stop' for e in events['value']['events']), 'internal command not terminal'
                time.sleep(1);return s
            time.sleep(3)
        raise Unknown('PRESTOP new attempt did not reach terminal within original budget')
    def execute(self,resume=None):
        if resume is None:
            self.stage('live admission');g=self.j.gate();scene=self.scene('admission');assert scene['prestop']['phase']=='idle'
            cfg=self.read_guest_json(r'C:\ProgramData\FakeNet-NG-MCP\configs\service.json');assert cfg['stop_grace_seconds']==60
            # Exact inherited six native cap originals, not a new cap operation.
            cap=ROOT/'Logs/fakenet-completion-20261001/r02/current-instance-final/9c984802-137a-4b15-bbf2-7e1c4f44c32c'
            inherited=json.loads((ROOT/'Logs/fakenet-completion-20261001/r06/specialty-consolidated.json').read_text())['instance_map']['latest_inherited']
            for r in inherited['six_originals']:assert sha((ROOT/r['path']).read_bytes())==r['sha256']
            self.save('cap-inheritance.json',inherited)
            r=self.mutate('start');assert r['ok'] and r['value']['state']=='healthy',r
        else:
            self.stage('same run preparation-only continuation')
            previous=Path(resume);old=json.loads((previous/'03-finally-scene.json').read_text())
            assert (previous/'result.json').exists(), 'previous writer must have ended'
            previous_result=json.loads((previous/'result.json').read_text())
            observation=json.loads(json.loads((previous.parent/'native-reconcile-01.json').read_text())['output'])
            assert preparation_eligible(previous_result,observation,(previous/'fixture-launch.json').exists() or (previous/'operator-cli-original.json').exists()), 'only proven pre-CLI tool preparation errors may continue'
            self.save('preparation-reconciliation.json',observation)
            assert previous_result['status']=='FAILED' and not (previous/'fixture-launch.json').exists() and not (previous/'operator-cli-original.json').exists()
            self.j.service.controller_id=old['product']['controller']
            self.j.run_id=old['product']['run_id']
            snap=self.j.snapshot();assert (snap['pid'],snap['creation_filetime'])==(7484,134335767401378067)
            assert snap['exe_sha']==EXE and snap['default_sha']=='71e530fa54710c8c6e4f6644f99858b514e3e724d7957e7bdbaa6de0029cac1a' and not snap['fault_env']
            current=self.scene('resumed-admission');assert current['prestop']['attempt']==0 and current['prestop']['phase']=='idle'
            assert current['product']['state']=='healthy' and current['product']['run_id']==self.j.run_id and current['product']['controller']==self.j.service.controller_id
            self.resource_gate('resumed-admission')
            inherited=json.loads((previous/'cap-inheritance.json').read_text())
            for f in inherited['six_originals']:assert sha((ROOT/f['path']).read_bytes())==f['sha256']
            self.save('cap-inheritance.json',inherited)
            cfg=self.read_guest_json(r'C:\ProgramData\FakeNet-NG-MCP\configs\service.json');assert cfg['stop_grace_seconds']==60
            assert sha(self.baseline())==sha((previous/'baseline-original.json').read_bytes()), 'same original baseline required'
            self.save('preparation-continuation.json',{'previous':str(previous),'same_run':self.j.run_id,'controller':self.j.service.controller_id,'new_business_start':False,'reason':'proven immutable export and old PowerShell engine preparation faults; no fixture/public stop/operator/actual CLI was executed; PRESTOP still idle0'})
            r={'value':{'run_id':self.j.run_id}}
        self.j.run_id=r['value']['run_id'];self.nonce=str(uuid.uuid4());self.root='E:\\FakeNetEvidence\\r07\\'+self.j.run_id+'\\'+self.nonce
        self.stage('healthy baseline sealed');raw=self.baseline();self.save('baseline-sealed.json',{'sha256':sha(raw),'run_id':self.j.run_id});(self.out/'baseline-original.json').write_bytes(raw)
        b=json.loads(raw);assert set(b['sections'])==SECTIONS
        self.collect('healthy-originals');self.launched=True
        launch=self.setup_worker(self.root,'Listener');self.save('fixture-launch.json',launch)
        self.ready=self.wait_file(self.root+r'\ready.json',60);self.save('fixture-ready.json',self.ready)
        assert fixture_valid(self.ready,self.j.run_id,self.j.service.controller_id,self.nonce,time.monotonic()-self.started)
        assert (launch['pid'],launch['creation_time'])==(self.ready['pid'],self.ready['creation_time'])
        assert ('127.0.0.1:'+str(self.ready['port'])) not in b['sections']['listen_ports']
        self.samples(True);self.stage('public stop with own TCP held');stopped=self.mutate('stop')
        s=self.scene('public-stop-failed');assert s['product']['state']=='failed' and s['marker']['needs_recovery']
        assert s['product']['run_id']==self.j.run_id and s['product']['controller']==self.j.service.controller_id
        assert 'audit' in (s['product']['failure_reason'] or '').lower()
        self.collect('public-stop-originals')
        self.proof.update(before={'run_id':self.j.run_id,'controller':self.j.service.controller_id,'baseline_sha256':sha(raw),'failure_reason':s['product']['failure_reason'],'audit_tcp_difference':True,'needs_recovery':True},prestop_before=s['prestop'],baseline_sha_before=sha(raw))
        self.stage('operator CLI once');op,begin=self.cli('operator');self.proof['operator']=op
        s=self.wait_prestop_terminal(self.proof['prestop_before'],begin+480)
        self.proof['prestop_failed']=s['prestop'];assert cli_valid(op,1)
        assert s['prestop']['phase']=='failed' and (s['pid'],s['creation_time'])==(7484,'134335767401378067') and s['service']['State']=='Running'
        assert s['marker']['needs_recovery'] and s['product']['run_id']==self.j.run_id and s['product']['controller']==self.j.service.controller_id
        self.samples(True);self.collect('operator-held-originals')
        self.proof.update(held=dict(self.proof['before'],needs_recovery=s['marker']['needs_recovery']),service_alive_at_CLI1=True)
        rejected=self.mutate('start');error=rejected.get('error') or {};code=error.get('code') if isinstance(error,dict) else None
        s=self.scene('start-refused');self.proof.update(start_error=code,start_owner_preserved=s['product']['run_id']==self.j.run_id and s['product']['controller']==self.j.service.controller_id)
        assert code=='not_allowed_in_state' and self.proof['start_owner_preserved'],rejected
        self.stage('cooperative own fixture release');self.release();self.collect('release-originals')
        self.stage('one same responsibility CLI retry');self.retry_sent=True;retry,begin=self.cli('retry');self.proof['retry']=retry
        s=self.wait_prestop_terminal(self.proof['prestop_failed'],begin+480) if not cli_valid(retry,0) else self.scene('retry-terminal',product=False)
        self.proof.update(prestop_final=s['prestop'],final_marker=s['marker'],service_stopped=s['service']['State']=='Stopped')
        self.collect('final-originals');self.proof['baseline_sha_after']=sha(self.baseline())
        self.stage('rejudge original bytes');self.rejudge()
    def rejudge(self):
        # Store the native originals list; rejudge derives lifecycle/audit facts
        # from their raw bytes, never from boolean success strings.
        write_new(self.out/'proof-input.json',self.proof)
        sidecars=[{'local':str(f.relative_to(self.out)),'size':f.stat().st_size,'sha256':sha(f.read_bytes())} for f in self.out.glob('*.json') if f.name not in ('proof-input.json','original-index.json')]
        write_new(self.out/'original-index.json',{'files':self.records,'sidecars':sidecars})
        v=rejudge(self.out);write_new(self.out/'verdict.json',v);assert v['passed'],v


def rejudge(out):
    out=Path(out);p=json.loads((out/'proof-input.json').read_text());files=json.loads((out/'original-index.json').read_text())['files'];contents=[]
    for f in files:
        path=(out/f['local']).resolve();path.relative_to(out.resolve());raw=path.read_bytes();assert len(raw)==f['size'] and sha(raw)==f['sha256'];contents.append((f,raw))
    sidecars={}
    for f in json.loads((out/'original-index.json').read_text()).get('sidecars',[]):
        path=(out/f['local']).resolve();path.relative_to(out.resolve());raw=path.read_bytes()
        assert len(raw)==f['size'] and sha(raw)==f['sha256'];sidecars[f['local']]=json.loads(raw)
    def scene(suffix):
        rows=[v for name,v in sidecars.items() if name.endswith(suffix)]
        assert rows,'missing bound scene '+suffix
        return rows[-1]
    initial=scene('-public-stop-failed-scene.json');refused=scene('-start-refused-scene.json')
    helds=[v for name,v in sidecars.items() if name.endswith('-prestop-readonly-scene.json') and v['prestop']['phase']=='failed']
    assert helds,'missing native held scene';held=helds[0]
    finals=[v for name,v in sidecars.items() if (name.endswith('-retry-terminal-scene.json') or name.endswith('-prestop-readonly-scene.json')) and v['prestop']['attempt']>held['prestop']['attempt']]
    final=finals[-1] if finals else {}
    p['operator']=sidecars.get('operator-cli-original.json',{})
    p['retry']=sidecars.get('retry-cli-original.json',{})
    p['prestop_before']=initial['prestop'];p['prestop_failed']=held['prestop'];p['prestop_final']=final.get('prestop',{})
    p['service_alive_at_CLI1']=(held['service']['State']=='Running' and held['pid']==7484 and str(held['creation_time'])=='134335767401378067')
    p['before']={'run_id':initial['product']['run_id'],'controller':initial['product']['controller'],'baseline_sha256':sidecars['baseline-sealed.json']['sha256'],'failure_reason':initial['product']['failure_reason'],'audit_tcp_difference':False,'needs_recovery':initial['marker']['needs_recovery']}
    p['held']={'run_id':held['product']['run_id'],'controller':held['product']['controller'],'baseline_sha256':p['before']['baseline_sha256'],'needs_recovery':held['marker']['needs_recovery']}
    p['start_owner_preserved']=(refused['product']['run_id']==p['before']['run_id'] and refused['product']['controller']==p['before']['controller'] and refused['marker']['needs_recovery'] is True)
    starts=[v for name,v in sidecars.items() if name.startswith('start-r07-')]
    errors=[v.get('error') for v in starts if not v.get('ok')]
    p['start_error']=next((e.get('code') for e in errors if isinstance(e,dict)),None)
    p['service_stopped']=final.get('service',{}).get('State')=='Stopped';p['final_marker']=final.get('marker',{})
    p['baseline_sha_before']=sidecars['baseline-sealed.json']['sha256']
    audits=[];owners=[];versions=[]
    for f,raw in contents:
        name=Path(f['path'].replace('\\','/')).name
        if name.startswith('recovery-audit-') and name.endswith('.jsonl'):
            rows=[json.loads(x) for x in raw.decode().splitlines()];audits.append((f,rows))
        if name=='owner-result.json':owners.append(json.loads(raw))
        if name=='versions.json':versions.append(json.loads(raw))
    ready=sidecars['fixture-ready.json'];endpoint='127.0.0.1:'+str(ready['port'])
    failed=[rows for f,rows in audits if f['local'].startswith('operator-held-originals/') and rows and any(endpoint in x['current']['listen_ports'] and 'listen_ports' in x['differences'] for x in rows)]
    # Native object-end reports are accepted only for same run and original budget.
    ended=[r for r in owners if r.get('target',{}).get('run_id')==p['before']['run_id'] and r.get('target',{}).get('budget_seconds')==60 and r.get('completed_monotonic',float('inf'))<=r.get('deadline_monotonic',-1) and r.get('helper_ended') is True and r.get('retained_target_handle_closed') is True and r.get('complete') is True]
    managed_ended=any(v.get('managed_process',{}).get('exit_code') is not None and v.get('managed_process',{}).get('job_members')==[] for v in versions)
    p['resources']={'native_ended':bool(ended) and managed_ended};p['before']['audit_tcp_difference']=bool(failed)
    final=[rows for f,rows in audits if f['local'].startswith('final-originals/') and len(rows)>=2 and rows[-1]['differences']=={} and rows[-2]['differences']=={}]
    p['two_clean_audit_samples']=bool(final)
    baseline_after=[raw for f,raw in contents if f['local'].startswith('final-originals/') and f['path'].replace('\\','/').endswith('/baselines/'+p['before']['run_id']+'.json')]
    p['baseline_sha_after']=sha(baseline_after[-1]) if baseline_after else None
    closed=[json.loads(raw) for f,raw in contents if f['path'].replace('\\','/').endswith('/'+ready['nonce']+'/closed.json')]
    p['fixture_closed']=closed[-1] if closed else {}
    p['fixture_did_not_expire']=bool(closed) and closed[-1].get('seconds',1800)<1800
    native_end=sidecars.get('fixture-native-ended.json',{})
    p['fixture_native_ended']=native_end.get('exit_code')==0 and native_end.get('output')=='native fixture ended'
    absent=[v for name,v in sidecars.items() if name.endswith('-absent-sample.json')]
    p['three_absent_samples']=len(absent)>=3 and all(not v['rows'] for v in absent)
    # Require native worker's original result, not only a cached runner object.
    for role in ['operator','retry']:
        originals=[json.loads(raw) for f,raw in contents if f['path'].replace('\\','/').endswith('/'+role+'/result.json')]
        assert originals and originals[-1]==p[role], 'CLI original mismatch'
    p['original_failure_preserved']=bool(failed) and cli_valid(p.get('operator',{}),1)
    return verdict(p)|{'derivation':{'bound_files':len(files),'failed_TCP_audits':len(failed),'same_run_native_end_reports':len(ended),'two_clean_audits':len(final)}}

def main(argv=None):
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=ROOT/'Logs/fakenet-completion-20261001/r07/native-case')
    ap.add_argument('--rejudge',type=Path);ap.add_argument('--contract',type=Path);ap.add_argument('--resume-preparation',type=Path);a=ap.parse_args(argv)
    if a.rejudge:print(json.dumps(rejudge(a.rejudge),ensure_ascii=False));return 0 if rejudge(a.rejudge)['passed'] else 1
    assert a.contract, 'approved execution contract required'
    contract=json.loads(a.contract.read_text())
    assert contract['status']=='APPROVED_R07' and contract['candidate']==CANDIDATE and contract['product_source']==SOURCE and contract['zip_sha256']==ZIP
    assert contract['budgets_seconds']=={'public_stop':480,'SCM_PRESTOP':480,'CLI':510,'original_exit':60,'fixture_lease':1800}
    for path,digest in contract['tools'].items():assert sha((ROOT/path).read_bytes())==digest, 'tool changed after freeze'
    a.output.resolve().relative_to((ROOT/'Logs').resolve());a.output.mkdir(parents=True,exist_ok=False)
    r=Runner(a.output);outcome={'status':'BLOCKED','case':'operator-audit','new_native_case':False,'formal_new':0}
    try:r.execute(a.resume_preparation);outcome.update(status='COMPLETED',new_native_case=True)
    except Exception as e:
        outcome.update(status='FAILED' if r.j.run_id else 'BLOCKED',reason=repr(e),new_native_case=bool(r.j.run_id))
        import traceback;outcome['traceback']=traceback.format_exc();print(json.dumps(outcome),flush=True)
    finally:
        try:
            if r.launched:r.release()
            if r.j.run_id:
                s=r.scene('finally',product=not r.proof.get('service_stopped'))
                # One recovery retry only if not already attempted, no unknown command.
                if not r.retry_sent and r.last_mutation_terminal and s['marker']['needs_recovery'] and (not r.launched or r.released):
                    r.retry_sent=True;op,begin=r.cli('recovery-only');outcome['recovery_only_cli']=op
                    r.wait_prestop_terminal(s['prestop'],begin+480) if not cli_valid(op,0) else None
                r.collect('closure-originals')
                r.save('closure-scene.json',r.scene('closed-final',product=False))
        except Exception as e:outcome['closure_error']=repr(e)
        if not (r.out/'proof-input.json').exists():write_new(r.out/'proof-input.json',r.proof)
        if not (r.out/'original-index.json').exists():
            sidecars=[{'local':str(f.relative_to(r.out)),'size':f.stat().st_size,'sha256':sha(f.read_bytes())} for f in r.out.glob('*.json') if f.name not in ('proof-input.json','original-index.json')]
            write_new(r.out/'original-index.json',{'files':r.records,'sidecars':sidecars})
        r.save('result.json',outcome)
    return 0 if outcome['status']=='COMPLETED' else 2 if outcome['status']=='BLOCKED' else 1
if __name__=='__main__':raise SystemExit(main())
