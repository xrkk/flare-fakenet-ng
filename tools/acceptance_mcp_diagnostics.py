"""Fixed diagnostic producers and original consumers. Execution is separately gated.

Native-crash and explicitly scoped no-stack paths are source candidates.
Raw incomplete no-stack packages remain incomplete. Unknown lacks an
independent unclassified terminal observation and is never relabeled as pass.
"""
from __future__ import annotations
import base64
import json
from pathlib import Path, PureWindowsPath
import threading
import time
from fakenet.mcp import diagnostic_faults as d

DIAGNOSTIC_CLASSES=d.CLASSES
SELECTED_UNITS={'DIAGNOSTIC-NATIVE-CRASH':'native_crash',
                'DIAGNOSTIC-STACKS-UNAVAILABLE':'stacks_unavailable',
                'DIAGNOSTIC-UNKNOWN-CAUSE':'unknown_cause'}
UNSUPPORTED={
 'unknown_cause':'no independently observed unclassified terminal event; a supplied reason or known Python exception cannot establish it',
}


def _response_json(response):
    if (not isinstance(response,dict) or response.get('exit_code')!=0
            or response.get('is_error') is not False):
        raise d.DiagnosticUnavailable('diagnostic transport response unresolved')
    return json.loads(response['output'])


def _encoded(value):
    return base64.b64encode(json.dumps(value,separators=(',',':')).encode()).decode('ascii')


class DiagnosticProducer:
    """One fixed plan and actual child observation; no caller-selected process."""
    def __init__(self,channel,plan):
        if not d.plan_shape(plan):raise d.DiagnosticUnavailable('diagnostic plan is not live')
        self.channel=channel;self.plan=dict(plan);self.arm=None;self.ready=None;self.error=None
        self.cancel=threading.Event();self.paths={}
        root=PureWindowsPath(channel.inputs['programdata_root'])/'logs'
        for key,name in [('plan','diagnostic-plan.json'),('ready','diagnostic-ready.json'),('arm','fault-injection.json')]:
            self.paths[key]=str(root/name).replace("'","''")
        self.created_options=False
        if plan['fault']=='unknown_cause' and d.unknown_options(channel.inputs.get('diagnostic')):
            self.paths['options']=str(root/'diagnostic-unknown-options.json').replace("'","''")
        self.created_plan=False

    def read(self,key):
        script=("$ErrorActionPreference='Stop';$p='"+self.paths[key]+"';"
                "if(Test-Path -LiteralPath $p){$f=Get-Item -LiteralPath $p -Force;"
                "if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint)-or $f.Length -gt 4096){throw 'diagnostic file identity refused'};"
                "Get-Content -LiteralPath $p -Raw}else{'null'}")
        return _response_json(self.channel.powershell(script,timeout=2))

    def write(self,key,value):
        script=("$ErrorActionPreference='Stop';$p='"+self.paths[key]+"';"
                "$raw=[Convert]::FromBase64String('"+_encoded(value)+"');"
                "$f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);"
                "try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()};Get-Content -LiteralPath $p -Raw")
        observed=_response_json(self.channel.powershell(script,timeout=2))
        if observed!=value:raise d.DiagnosticUnavailable('diagnostic write receipt differs')

    def write_plan(self):
        if 'options' in self.paths:
            self.write('options',self.channel.inputs['diagnostic']);self.created_options=True
        self.write('plan',self.plan);self.created_plan=True

    def run(self):
        deadline=time.monotonic()+max(0,(self.plan['expires_ns']-time.time_ns())/1e9)
        try:
            while not self.cancel.is_set() and time.monotonic()<deadline:
                ready=self.read('ready')
                if ready is not None:
                    arm=d.arm_from_ready_observation(ready,self.plan)
                    self.ready=ready
                    if self.cancel.is_set():return
                    self.write('arm',arm);self.arm=arm;return
                self.cancel.wait(.02)
            raise d.DiagnosticUnavailable('diagnostic arm producer did not observe its live child')
        except Exception as exc:self.error={'type':type(exc).__name__,'message':str(exc)}

    def cleanup(self):
        """Compare exact bytes/nonce before removing only our rendezvous files."""
        outcomes={}
        owned=[('arm',self.arm),('ready',self.ready),('plan',self.plan if self.created_plan else None)]
        if 'options' in self.paths:owned.append(('options',self.channel.inputs['diagnostic'] if self.created_options else None))
        for key,expected in owned:
            current=self.read(key)
            if current is None:outcomes[key]='absent';continue
            if expected is None or current!=expected:
                raise d.DiagnosticUnavailable('changed or unowned diagnostic residue; preserve scene: '+key)
            # Hash the exact observed serialization once more inside the same
            # fixed removal command. No foreign name-based cleanup is allowed.
            raw=_encoded(current)
            script=("$ErrorActionPreference='Stop';$p='"+self.paths[key]+"';"
                    "$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+raw+"'))|ConvertFrom-Json;"
                    "$f=Get-Item -LiteralPath $p -Force;"
                    "if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint)-or$f.Length-gt4096){throw 'diagnostic cleanup source refused'};"
                    "$before=Get-Content -LiteralPath $p -Raw;$actual=$before|ConvertFrom-Json;"
                    "if(($actual|ConvertTo-Json -Compress -Depth 16)-ne($expected|ConvertTo-Json -Compress -Depth 16)){throw 'diagnostic cleanup owner changed'};"
                    "$sha=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash;"
                    "if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash-ne$sha){throw 'diagnostic cleanup bytes changed'};"
                    "Remove-Item -LiteralPath $p;@{removed=$true;absent=(!(Test-Path -LiteralPath $p))}|ConvertTo-Json -Compress")
            receipt=_response_json(self.channel.powershell(script,timeout=2))
            if receipt!={'removed':True,'absent':True}:raise d.DiagnosticUnavailable('diagnostic cleanup receipt unresolved')
            outcomes[key]='owned_removed'
        return outcomes


def read_stack_context(channel, run_id, plan):
    """Fixed same-run originals; existing fallback files are never removed."""
    import uuid, hashlib
    if not isinstance(run_id, str) or str(uuid.UUID(run_id)) != run_id:
        raise d.DiagnosticUnavailable('no-stack observed run identity missing')
    directory = PureWindowsPath(channel.inputs['programdata_root'])/'artifacts'/'runs'/run_id
    originals = {}
    decoded = {}
    for key, name in [('window','diagnostic-window.json'), ('trigger','diagnostic-triggered.json')]:
        path = str(directory/name).replace("'", "''")
        script = ("$ErrorActionPreference='Stop';$p='"+path+"';$f=Get-Item -LiteralPath $p -Force;"
            "if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint)-or$f.Length-gt8192){throw 'no-stack original source refused'};"
            "$b=[IO.File]::ReadAllBytes($p);@{base64=[Convert]::ToBase64String($b);sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
        response = channel.powershell(script, timeout=2)
        wrapped = _response_json(response)
        raw = base64.b64decode(wrapped['base64'], validate=True)
        if len(raw)>8192 or hashlib.sha256(raw).hexdigest()!=wrapped['sha256']:
            raise d.DiagnosticUnavailable('no-stack raw source differs')
        originals[key] = response; decoded[key] = json.loads(raw)
    window = decoded['window']
    if window != {'schema':'fakenet.diagnostic-window.v1', 'plan':plan, 'ready':window.get('ready')}:
        raise d.DiagnosticUnavailable('no-stack original plan differs')
    ready = window['ready']; arm = {key:ready[key] for key in d.ARM_KEYS}
    script = "$ErrorActionPreference='Stop';$files=@{};"
    for name in ('managed-thread-stacks.json','stop-thread-stacks.txt','fault-child-stacks.txt'):
        path = str(directory/name).replace("'", "''")
        script += "$p='"+path+"';$files['"+name+"']=@{exists=[bool](Test-Path -LiteralPath $p)};"
    script += "$files|ConvertTo-Json -Depth 8 -Compress"
    originals['fallbacks'] = channel.powershell(script, timeout=2)
    import copy
    wanted = [originals[key] for key in ('window','trigger','fallbacks')]
    originals['transport'] = [copy.deepcopy(row) for row in channel.records
        if row.get('kind')=='powershell' and any(row.get('output')==value for value in wanted)]
    context = {'schema':'fakenet.no-stack-context.v1', 'plan':plan, 'ready':ready, 'arm':arm,
        'trigger':decoded['trigger'], 'fallback_files':_response_json(originals['fallbacks']),
        'originals':originals}
    from evidence_integrity import validate_stack_context
    validate_stack_context(context, run_id)
    return context


def _unknown_enabled(gate):
    return d.unknown_options(getattr(getattr(gate,'channel',None),'inputs',{}).get('diagnostic'))


def run_diagnostic_round(gate,fault,index=1):
    if fault in UNSUPPORTED and not _unknown_enabled(gate):return dict(status='blocked',**{'class':fault,'failure':UNSUPPORTED[fault]})
    if fault not in ('native_crash','stacks_unavailable','unknown_cause'):raise ValueError('diagnostic class is not registered')
    import acceptance_mcp as m
    inputs=gate.channel.inputs
    service=m.service_preflight(gate.channel,inputs)
    plan=d.make_plan(fault,ttl_ns=d.ARM_WINDOW_NS,config_sha256=inputs['config_identity']['sha256'],
                     service_identity={'pid':service['pid'],'creation_time':service['birth']})
    producer=DiagnosticProducer(gate.channel,plan)
    record={'class':fault,'round':index,'nonce':plan['nonce']};cleanup=None
    def action():
        thread=None
        try:
            producer.write_plan()
            thread=threading.Thread(target=producer.run,name='diagnostic-arm-producer',daemon=False)
            thread.start()
            if fault == 'stacks_unavailable':
                value=gate._fault_round(fault,index,plan['nonce'],
                    diagnostic_context=lambda run:read_stack_context(gate.channel,run,plan))
            elif fault=='unknown_cause':
                value=gate._fault_round(fault,index,plan['nonce'],unknown_diagnostic=dict(d.UNKNOWN_OPTIONS))
            else:
                value=gate._fault_round(fault,index,plan['nonce'])
            return value
        finally:
            producer.cancel.set()
            # Never return a stopped result while a writer may still exist.
            # Each exchange has its own 2s transport timeout. A broken timeout
            # cannot turn a live thread into a successful stopped declaration.
            if thread is not None:thread.join()
    try:
        record=gate.observe_round(action)
    except Exception as exc:
        record['failure']='original diagnostic observation failed: '+repr(exc)
    finally:
        try:
            cleanup=producer.cleanup()
        except Exception as exc:
            record['failure']='diagnostic owned cleanup unresolved: '+repr(exc)
        record.update(diagnostic_plan=plan,diagnostic_ready=producer.ready,
                      diagnostic_arm=producer.arm,diagnostic_cleanup=cleanup,
                      diagnostic_service_observation=service)
    if producer.error or producer.arm is None:
        record['failure']='diagnostic arm not confirmed: '+str(producer.error)
    if record.get('failure'):
        return record
    if fault == 'stacks_unavailable':
        return record
    run_id=record.get('run_id')
    import uuid
    try:
        valid_run=isinstance(run_id,str) and str(uuid.UUID(run_id))==run_id
    except (ValueError,TypeError,AttributeError):
        valid_run=False
    if not valid_run:
        record['failure']='original diagnostic run identity missing'
        return record
    raw_files={}
    record['diagnostic_raw']=raw_files
    for name in (('diagnostic-window.json','diagnostic-triggered.json','diagnostic-self-exit.json') if fault=='unknown_cause' else ('diagnostic-window.json','diagnostic-triggered.json')):
        path=str(PureWindowsPath(inputs['programdata_root'])/'artifacts'/'runs'/run_id/name).replace("'","''")
        script=("$ErrorActionPreference='Stop';$p='"+path+"';$f=Get-Item -LiteralPath $p -Force;"
                "if(($f.Attributes -band [IO.FileAttributes]::ReparsePoint)-or$f.Length-gt8192){throw 'diagnostic raw source refused'};"
                "$b=[IO.File]::ReadAllBytes($p);@{base64=[Convert]::ToBase64String($b);sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
        try:
            raw_files[name]=gate.channel.powershell(script,timeout=2)
        except Exception as exc:
            record['failure']='diagnostic raw source unavailable: '+repr(exc)
            break
    record['diagnostic_raw']=raw_files
    return record


def run_diagnostic_case(gate,fault,index=1):
    if fault in UNSUPPORTED and not _unknown_enabled(gate):return run_diagnostic_round(gate,fault,index)
    import acceptance_mcp as m
    inputs=gate.channel.inputs
    before=m.service_preflight(gate.channel,inputs)
    record={'class':fault,'round':index}
    try:
        # The original consumer loads DEFAULT_INI. Reject a different frozen
        # request before enabling fault mode, rather than testing another config.
        if inputs['config_identity']['name']!=m.modules()['run_p05_release'].DEFAULT_INI:
            raise d.DiagnosticUnavailable('original fault consumer requires its builtin configuration')
        gate.configure_fault_mode(True)
        record=run_diagnostic_round(gate,fault,index)
    except Exception as exc:
        record['failure']='diagnostic source/consumer failed: '+repr(exc)
    finally:
        try:
            # Unknown service mutation responses cannot authorize a restart.
            if getattr(gate.channel,'preserve_scene',False) or any(
                    op.get('response_unknown') for op in getattr(gate.channel,'mutation_operations',[])):
                raise d.DiagnosticUnavailable('unresolved operation; preserve diagnostic scene')
            helper=m.modules()['helpers']
            receipt=helper.configure_fault_service(gate.channel,before['enabled'],before['grace'])
            after=m.service_preflight(gate.channel,inputs)
            if any(after[k]!=before[k] for k in ('image','sha256','enabled','grace','fault_exists','service_config')):
                raise d.DiagnosticUnavailable('original service mode restoration is unverified')
            record['diagnostic_service_restoration']={'before':before,'after':after,'receipt':receipt}
        except Exception as exc:
            record['diagnostic_restore_error']=repr(exc)
            record['failure']='diagnostic service restoration unresolved: '+repr(exc)
    return record


def execute_unit(unit,args,channel,writer,root):
    fault=SELECTED_UNITS[unit]
    if fault in UNSUPPORTED and not d.unknown_options(getattr(channel,'inputs',{}).get('diagnostic')):
        writer.blocker={'reason':UNSUPPORTED[fault],'class':fault}
        return 2
    import acceptance_mcp as m
    from types import SimpleNamespace
    mods=m.modules(root)
    settings={k:getattr(args,k) for k in m.IDENTITY_FIELDS}
    gate=mods['run_p05_release'].ReleaseGate(SimpleNamespace(**settings,
        target_base_url=args.target_base_url,win10vm_mcp=args.win10vm_mcp,
        output_root=str(Path(writer.out_dir)/'diagnostic-rounds')))
    gate.channel=channel
    record=run_diagnostic_case(gate,fault)
    record['diagnostic_source_pins']=m.source_pins(root)
    if fault=='unknown_cause':
        record['unknown_original_context']={'inputs':channel.inputs,'source_root':str(root),'transport':list(channel.records)}
    writer.add_evidence('diagnostic-record',record)
    writer.evidence.extend(record.get('capture_evidence',[]))
    for item in record.get('incident_exports',[]):
        writer.evidence.append({k:item[k] for k in ('path','sha256','size')})
    from acceptance_mcp_diagnostic_oracles import validate_original_record
    facts=validate_original_record(record,record.get('fault_evidence'),
                                   record.get('incident_exports'),expected=channel.inputs,root=root,
                                   transport=channel.records)
    writer.add_evidence('diagnostic-original-judgment',facts)
    return 0


def central_rejudge(record_paths,localization_path,inputs,root,writer):
    import acceptance_mcp as m
    from types import SimpleNamespace
    from acceptance_mcp_capabilities import OriginalArchiveChannel
    records=[]
    if not isinstance(record_paths,list) or not 1<=len(record_paths)<=128:
        raise ValueError('bounded original records required')
    for name in record_paths:
        path=Path(name)
        if path.is_symlink() or path.stat().st_size>16*1024*1024:raise ValueError('original record identity refused')
        records.append((path,json.loads(path.read_text(encoding='utf-8'))))
    channel=OriginalArchiveChannel(records)
    args=SimpleNamespace(**inputs['identity'],fault_record=[str(p) for p,v in records],
                         localization_record=str(localization_path))
    return m.modules(root)['run_p04_acc'].run_acc014('',channel,writer,args)
