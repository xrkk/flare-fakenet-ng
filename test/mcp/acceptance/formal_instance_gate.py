"""Native instance admission inside the standard formal IPC cycle.

No traffic oracle is replaced. Enabled admission creates a fresh Suite
preflight; restored admission makes only the independent default cycle.
Unknown IPC mutations disable automatic finally replay until reconciled.
"""
from __future__ import annotations
import hashlib,json,time,uuid
from pathlib import Path,PureWindowsPath
import bounded_mcp as bounded
import scenario_suite as suite

class IpcUnresolved(RuntimeError):
    pass

def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as stream:json.dump(value,stream,ensure_ascii=False,indent=2)

def install_ipc_guard(runner,evidence):
    """Keep the original single cycle; reconcile only a completed receipt."""
    directory=Path(evidence);directory.mkdir(exist_ok=False,parents=True)
    original=runner._ipc_evidence_mode;state={'safe':True,'cycles':0}
    runner._ipc_restore_allowed=lambda:state['safe']
    def guarded(enabled):
        if not state['safe']:raise IpcUnresolved('prior IPC outcome remains unresolved')
        state['cycles']+=1
        receipt=(runner.guest_work_root+r'\scenario-suite-20260912\ipc-cycle-'+uuid.uuid4().hex+r'\receipt.json')
        runner.ipc_cycle_receipt=receipt
        save(directory/(str(state['cycles'])+'-intent.json'),{'enabled':enabled,'receipt':receipt,'budget':180,'standard_cycle':True})
        try:
            answer=original(enabled)
            save(directory/(str(state['cycles'])+'-outcome.json'),answer)
            return answer
        except (bounded.TransportUnknown, suite.VmCommandError) as error:
            state['safe']=False
            record={'enabled':enabled,'receipt':receipt,'error':repr(error),'transport':getattr(error,'record',{}),'no_mutation_replay':True}
            try:
                command="$ErrorActionPreference='Stop';$r="+suite.quote_ps(receipt)+";if(Test-Path $r){Get-Content $r -Raw}else{@{stage='absent'}|ConvertTo-Json -Compress}"
                raw=runner.vm.powershell(command,30);phase=json.loads(raw['output']);record.update(reconciliation=raw,phase=phase)
                # The entire mutation was proven completed. Only read status;
                # never resend its stop/environment/start script.
                if phase.get('stage')=='completed' and phase.get('enabled') is enabled:
                    answer=phase['answer'];deadline=time.monotonic()+60
                    while time.monotonic()<deadline:
                        try:status=runner._status(timeout=min(10,deadline-time.monotonic()))
                        except bounded.TransportUnknown:time.sleep(.25);continue
                        if status.get('state')=='stopped' and not status.get('run_id') and not status.get('controller'):
                            answer.update(endpoint_status=status,reconciled_original_response_unknown=True,receipt_reconciliation=raw)
                            state['safe']=True;record['settled']=True;save(directory/(str(state['cycles'])+'-unknown.json'),record);return answer
                        time.sleep(.25)
            except BaseException as reconcile:record['reconcile_error']=repr(reconcile)
            save(directory/(str(state['cycles'])+'-unknown.json'),record)
            raise IpcUnresolved('IPC partial outcome; retain native receipt and responsibility, no blind finally mutation') from error
        finally:
            runner.ipc_cycle_receipt=None
    runner._ipc_evidence_mode=guarded
    return state

class NativeInstanceGate:
    def __init__(self,spike):
        self.spike=Path(spike);self.instances=[];self.formal_identity=None
    def __call__(self,runner,phase,ipc):
        root=runner.root/'instance-gates'/phase;root.mkdir(parents=True,exist_ok=False)
        seq=0;unknown=False;admission=None;out={'passed':False,'phase':phase,'formal_credit':0}
        def native(name,command,timeout=60):
            save(root/(name+'-intent.json'),{'command':command,'timeout':timeout})
            raw=runner.vm.powershell(command,timeout);save(root/(name+'-original.json'),raw);return json.loads(raw['output'])
        def call(name,args=None,mutate=False):
            nonlocal seq,unknown
            seq+=1;arguments=dict(args or {})
            if mutate:arguments.update(command_id='instance-admission-'+uuid.uuid4().hex,expected_state_version=runner._status(timeout=30)['state_version'])
            save(root/(f'{seq:02d}-{name}-intent.json'),{'tool':name,'arguments':arguments,'controller':runner.service.controller_id,'timeout':480 if mutate else 60})
            try:answer=runner.service.tool_outcome(name,arguments,timeout=480 if mutate else 60)
            except bounded.TransportUnknown as error:
                unknown=mutate;save(root/(f'{seq:02d}-{name}-unknown.json'),{'error':repr(error),'record':error.record,'no_resend':True})
                if mutate:
                    settled=suite.reconcile_timed_out_command(runner.service,arguments['command_id'],name,runner.service.controller_id,60)
                    save(root/(f'{seq:02d}-{name}-reconcile.json'),settled);unknown=not settled['settled']
                raise
            save(root/(f'{seq:02d}-{name}-outcome.json'),answer)
            if not answer['ok']:raise RuntimeError('admission tool rejected: '+repr(answer['error']))
            return answer['value']
        try:
            scene=native('identity-candidate-environment',r'''$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'";$p=Get-Process -Id $s.ProcessId;$root='C:\Program Files\FakeNet-NG-MCP';$m=Get-Content (Join-Path $root 'mcp-candidate-manifest.json') -Raw|ConvertFrom-Json;$prop=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\fakenetng-mcp' -Name Environment -ErrorAction SilentlyContinue;@{computer=$env:COMPUTERNAME;uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;mac=@(Get-NetAdapter|Select-Object -ExpandProperty MacAddress);service=$s.State;pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();marker=(Get-Content 'C:\ProgramData\FakeNet-NG-MCP\state\state.json' -Raw|ConvertFrom-Json);source=$m.source_commit;members=@($m.files|ForEach-Object{@{path=$_.path;expected=$_.sha256;actual=(Get-FileHash (Join-Path $root $_.path)).Hash.ToLower()}});environment_present=($null -ne $prop -and $null -ne $prop.Environment);environment=@($prop.Environment);fault=Test-Path 'C:\ProgramData\FakeNet-NG-MCP\logs\fault-injection.json';fault_gate=Test-Path 'C:\ProgramData\FakeNet-NG-MCP\logs\fault-injection-gate.json';config=(Get-Content 'C:\ProgramData\FakeNet-NG-MCP\configs\service.json' -Raw|ConvertFrom-Json);space=@(Get-PSDrive C,E|Select-Object Name,Free);utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 8 -Compress''')
            identity={k:scene[k] for k in ('pid','filetime')};assert scene['computer']=='DESKTOP-3FI41GR' and scene['uuid']=='D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49' and '00-0C-29-C1-CA-49' in scene['mac']
            assert scene['service']=='Running' and identity not in self.instances and identity!={'pid':4828,'filetime':'134353511031106360'} and not scene['marker']['needs_recovery'] and not scene['fault'] and not scene['fault_gate'] and scene['config']['stop_grace_seconds']==60
            assert scene['source']==runner.identity.source_commit and len(scene['members'])==199 and all(x['actual']==x['expected'] for x in scene['members'])
            backup=native('original-environment',"$saved=Import-Clixml "+suite.quote_ps(ipc['backup'])+";@{present=$saved.present;values=@($saved.values)}|ConvertTo-Json -Compress",30)
            original=[x for x in backup['values'] if x];expected=[x for x in original if not x.startswith('FAKENETNG_MCP_FAULT_INJECTION=')]+['FAKENETNG_MCP_FAULT_INJECTION=1'] if phase=='enabled' else original
            assert [x for x in scene['environment'] if x]==expected and scene['environment_present']==(True if phase=='enabled' else backup['present'])
            self.instances.append(identity);save(root/'new-instance-identity.json',identity)
            status=call('get_status');assert status['state']=='stopped' and not status['controller'] and not status['run_id']
            call('load_config',{'name':'default.ini'},True);started=call('start',mutate=True);admission=started['run_id'];assert started['state']=='healthy'
            for _ in range(3):time.sleep(2);assert call('get_status')['state']=='healthy'
            call('get_events',{'limit':500});stopped=call('stop',mutate=True);assert stopped['state']=='stopped';assert call('get_status')['config_identity']['sha256']=='71e530fa54710c8c6e4f6644f99858b514e3e724d7957e7bdbaa6de0029cac1a'
            inventory=native('six-original-inventory',r'''$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter "Name='fakenetng-mcp'";$p=Get-Process -Id $s.ProcessId;$runs=@();foreach($d in @(Get-ChildItem 'C:\ProgramData\FakeNet-NG-MCP\logs\exit-evidence' -Directory)){if(Test-Path (Join-Path $d.FullName 'capability.json')){$entry=Get-Content (Join-Path $d.FullName 'entry.json') -Raw|ConvertFrom-Json;if($entry.target.supervisor_pid -eq $p.Id -and [string]$entry.target.supervisor_creation_time -ceq [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()){$runs+=@{run_id=$d.Name;files=@(Get-ChildItem $d.FullName -File|ForEach-Object{@{path=$_.FullName;size=$_.Length;sha256=(Get-FileHash $_.FullName).Hash.ToLower()}})}}}};@{pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();runs=$runs}|ConvertTo-Json -Depth 7 -Compress''')
            assert {k:inventory[k] for k in identity}==identity and len(inventory['runs'])==1;run=inventory['runs'][0];files=run['files'];assert len(files)==6 and sum(x['size'] for x in files)<=64*2**20
            local=root/'six-originals';records=[]
            for row in files:
                assert row['size']<=32*2**20
                dest=local/PureWindowsPath(row['path']).name;records.append({'guest':row,'host':runner._transfer_guest_file(row['path'],row['size'],row['sha256'],dest)})
            entry=json.loads((local/'entry.json').read_text());result=json.loads((local/'result.json').read_text());owner=json.loads((local/'owner-result.json').read_text());cap=json.loads((local/'capability.json').read_text());target=result['target'];dump=local/result['dump']['name']
            checks={'same_target':entry['target']==owner['target']==target,'current_supervisor':target['supervisor_pid']==identity['pid'] and str(target['supervisor_creation_time'])==identity['filetime'],'budget60':target['budget_seconds']==60,'deadline':result['entered_monotonic']<=result['completed_monotonic']<=result['deadline_monotonic'] and result['deadline_monotonic']-result['entered_monotonic']<=60,'capability':cap['passed'] is True and 0<=cap['elapsed_seconds']<=60,'self_exit':result['notification']['target_pid']==result['notification']['initiator_pid']==target['pid'] and result['notification']['exit_status']==49158,'dump_SHA_size':hashlib.sha256(dump.read_bytes()).hexdigest()==result['dump']['sha256'] and dump.stat().st_size==result['dump']['size'],'native_closed':result['target_handle_closed'] and owner['helper_ended'] and owner['retained_target_handle_closed']};assert all(checks.values())
            save(root/'six-native-verdict.json',{'passed':True,'identity':identity,'checks':checks,'records':records,'run_id':run['run_id']})
            if phase=='enabled':
                preflight=runner.preflight();assert preflight['passed'];runner._require_preflight();runner._validate_fault_spike(self.spike)
                save(root/'Spike-current-rejudge.json',{'passed':True,'original':suite.file_record(self.spike),'new_fault_runs':0});self.formal_identity=identity
            final=call('get_status');assert final['state']=='stopped' and not final['run_id'] and not final['controller'] and final['config_identity']['sha256']=='71e530fa54710c8c6e4f6644f99858b514e3e724d7957e7bdbaa6de0029cac1a'
            out.update(passed=True,identity=identity,admission_run=admission,native_run=run['run_id'],checks=checks,environment_expected=expected,environment_backup=backup,final_status=final)
            return out
        except BaseException as error:
            out.update(error=repr(error),admission_run=admission,unsettled=unknown)
            if unknown:runner._ipc_restore_allowed=lambda:False
            if not unknown:
                try:
                    status=call('get_status')
                    if status['controller']==runner.service.controller_id and status['state'] in ('healthy','failed'):out['cleanup']=call('stop',mutate=True)
                except BaseException as cleanup:out['cleanup_error']=repr(cleanup)
            raise
        finally:save(root/'result.json',out)
