"""Fail-closed diagnostic targeting and the original incident/dump predicates.

Native process/Job/ABI observations are test boundaries. No target process,
VM, network, DLL or native crash is started by this file.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from fakenet.mcp import diagnostic_faults as d, faultinject as f
from fakenet.mcp import incident_task, managed_stacks, baseline
from fakenet.mcp.exit_native import verify_dump

RUN='33333333-3333-4333-8333-333333333333'


@pytest.fixture
def target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('PROGRAMDATA', str(tmp_path))
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION', '1')
    run=tmp_path/RUN
    run.mkdir()
    monkeypatch.chdir(run)
    config=run/'active-config.ini'
    config.write_text('[FakeNet]\nDumpPackets=No\n')
    identity={'pid':4242,'creation_time':'123456789'}
    from fakenet.mcp import service_stop
    monkeypatch.setattr(service_stop,'process_identity',lambda pid=None:dict(identity))
    monkeypatch.setattr(d,'current_job_members',lambda:[4242])
    context=dict(identity,run_id=RUN,run_dir=str(run),config_path=str(config),nonce='same-window-nonce',
                 config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),initialized=True)
    value=dict(fault='native_crash',nonce='same-window-nonce',run_id=RUN,
               **identity,config_sha256=context['config_sha256'],job_members=[4242],
               expires_ns=time.time_ns()+60_000_000_000)
    path=f._fault_file()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(value))
    return context,value,path


def test_disabled_or_legacy_arm_never_reaches_process_observation(target,monkeypatch):
    context,value,path=target
    monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION')
    with mock.patch.object(d,'current_job_members',side_effect=AssertionError('no OS')):
        assert d.matching_arm(context,path) is None
    monkeypatch.setenv('FAKENETNG_MCP_FAULT_INJECTION','1')
    path.write_text(json.dumps({'fault':'native_crash','nonce':'legacy'}))
    with mock.patch.object(d,'current_job_members',side_effect=AssertionError('no OS')):
        assert d.matching_arm(context,path) is None
        assert f.armed_fault() is None


@pytest.mark.parametrize('field,replacement',[
    ('run_id','44444444-4444-4444-8444-444444444444'),('pid',7),
    ('creation_time','99'),('config_sha256','0'*64),('job_members',[7]),
    ('expires_ns',1),('nonce',''),('nonce','different-window'),('pid',True)])
def test_wrong_target_or_expired_arm_has_no_trigger_file(target,field,replacement):
    context,value,path=target
    value[field]=replacement
    path.write_text(json.dumps(value))
    before=path.read_bytes()
    injector=f.FaultInjector()
    injector._diagnostic_context=context
    with mock.patch.object(d,'trigger_native_crash',side_effect=AssertionError('no ABI')):
        injector.maybe_native_crash()
    assert path.read_bytes()==before
    assert not (Path(context['run_dir'])/'diagnostic-triggered.json').exists()


def test_actual_birth_job_config_and_initialization_must_still_match(target,monkeypatch):
    context,value,path=target
    assert d.matching_arm(context,path)==value
    monkeypatch.setattr(d,'current_job_members',lambda:[4242,99])
    assert d.matching_arm(context,path) is None
    monkeypatch.setattr(d,'current_job_members',lambda:[4242])
    from fakenet.mcp import service_stop
    monkeypatch.setattr(service_stop,'process_identity',lambda pid=None:{'pid':4242,'creation_time':'other'})
    assert d.matching_arm(context,path) is None
    monkeypatch.setattr(service_stop,'process_identity',lambda pid=None:{'pid':4242,'creation_time':'123456789'})
    assert d.matching_arm(dict(context,initialized=False),path) is None
    Path(context['config_path']).write_text('changed config')
    assert d.matching_arm(context,path) is None


def test_native_stimulus_uses_fixed_failfast_abi_after_verified_target(target,monkeypatch):
    context,value,path=target
    calls=[]
    class FakeCall:
        def __call__(self,*args):
            calls.append(args)
            raise OSError('modeled native termination')
    function=FakeCall()
    import ctypes
    def dll(name,**kwargs):
        assert name=='kernel32' and kwargs=={'use_last_error':True}
        return SimpleNamespace(RaiseFailFastException=function)
    monkeypatch.setattr(ctypes,'WinDLL',dll,raising=False)
    # Replace this module's OS boundary, without changing pathlib or host os.name.
    monkeypatch.setattr(d,'os',SimpleNamespace(name='nt',environ=os.environ,
                                             getpid=os.getpid,fsync=os.fsync))
    with pytest.raises(OSError,match='modeled native termination'):
        d.trigger_native_crash(context,path)
    assert calls==[(None,None,0)]
    receipt=json.loads((Path(context['run_dir'])/'diagnostic-triggered.json').read_text())
    assert all(receipt[k]==v for k,v in value.items())
    assert receipt['observed_time_ns']>0
    assert function.restype is None
    assert len(function.argtypes)==3


def test_native_stimulus_cannot_be_called_without_matching_arm(target):
    context,value,path=target
    path.unlink()
    with pytest.raises(d.DiagnosticUnavailable,match='arm unconfirmed'):
        d.trigger_native_crash(context,path)


def test_unknown_is_not_synthesized_as_a_known_python_exception(target):
    context,value,path=target
    value['fault']='unknown_cause'
    path.write_text(json.dumps(value))
    injector=f.FaultInjector();injector._diagnostic_context=context
    before=path.read_bytes()
    assert injector.maybe_unknown_cause() is None
    assert path.read_bytes()==before
    assert not (Path(context['run_dir'])/'diagnostic-triggered.json').exists()
    with pytest.raises(d.DiagnosticUnavailable,match='no verified'):
        d.unknown_cause_observation()


def test_no_stack_arm_cannot_discard_a_preexisting_fallback(target):
    context,value,path=target
    value['fault']='stacks_unavailable';path.write_text(json.dumps(value))
    injector=f.FaultInjector();injector._diagnostic_context=context
    managed_stacks.save_stacks(context['run_dir'],RUN,
        {'pid':4242,'creation_time':'123456789'},'real prior stack')
    raw=(Path(context['run_dir'])/'managed-thread-stacks.json').read_bytes()
    assert injector.stacks_snapshot_allowed() is True
    assert injector.ipc_response({'kind':'stacks'},{'stacks':'live'})==('send',{'stacks':'live'})
    assert (Path(context['run_dir'])/'managed-thread-stacks.json').read_bytes()==raw


def test_live_health_and_stacks_are_distinct_and_receipt_is_original_shape(target):
    context,value,path=target
    value['fault']='stacks_unavailable';path.write_text(json.dumps(value))
    injector=f.FaultInjector();injector._diagnostic_context=context
    assert injector.stacks_snapshot_allowed() is False
    assert injector.ipc_response({'kind':'health'},{'probe':True})==('send',{'probe':True})
    assert injector.ipc_response({'kind':'stacks'},{'stacks':'live'})==('drop',None)
    assert json.loads((Path(context['run_dir'])/'fault-triggered.json').read_text())=={
        'fault':'stacks_unavailable','nonce':value['nonce']}
    assert injector.stacks_snapshot_allowed() is False
    assert not path.exists()


def test_original_preparer_uses_real_stack_fallback_and_pinned_dump_target(target,monkeypatch):
    context,value,path=target
    directories={'artifacts':Path(context['run_dir']).parent/'artifacts',
                 'baselines':Path(context['run_dir']).parent/'baselines'}
    run=directories['artifacts']/'runs'/RUN;run.mkdir(parents=True)
    (run/'active-config.ini').write_text('[FakeNet]\n')
    identity={'pid':4242,'creation_time':'123456789'}
    request=dict(run_id=RUN,config_sha256=value['config_sha256'],reason='managed IPC unavailable',
                 live_stacks=None,last_stacks=None,timeline=[{'run_id':RUN}],
                 managed={'identity':identity,'exit_code':None,'job_members':[4242]},
                 dump_target={'role':'managed','identity':identity},exit_report=None)
    monkeypatch.setattr(baseline,'capture',lambda deadline:{})
    monkeypatch.setattr(baseline.BaselineStore,'load',lambda self,run:None)
    prepared=incident_task.prepare(request,directories,run,time.monotonic()+10)
    assert prepared['dump_reason']=='managed stacks unavailable'
    assert prepared['dump_target_pid']==4242
    assert prepared['managed_thread_stacks'] is None
    managed_stacks.save_stacks(run,RUN,identity,'observed managed stack')
    prepared=incident_task.prepare(request,directories,run,time.monotonic()+10)
    assert 'observed managed stack' in prepared['managed_thread_stacks']
    assert prepared['dump_reason']=='live managed IPC stacks unavailable'
    request['dump_target']=None
    assert incident_task.prepare(request,directories,run,time.monotonic()+10)['dump_reason'] is None


def test_original_dump_parser_rejects_rehashed_wrong_pid(target):
    context,value,path=target
    dump=Path(context['run_dir'])/'userdump.dmp'
    data=bytearray(56)
    struct.pack_into('<IIII',data,0,0x504d444d,0xa793,1,32)
    struct.pack_into('<III',data,32,15,12,44)
    struct.pack_into('<III',data,44,12,1,4242)
    dump.write_bytes(data)
    assert verify_dump(dump,4242)==56
    struct.pack_into('<I',data,52,7);dump.write_bytes(data)
    assert hashlib.sha256(dump.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError,match='identity mismatch'):
        verify_dump(dump,4242)



def test_version_chain_rejects_unexplained_advance_and_scoped_replay():
    import acceptance_mcp as m
    def operation(expected,end,command='one',accepted=True,replay=False,error=None):
        return dict(epoch=0,accepted=accepted,replay=replay,response_unknown=False,
                    request_command_id=command,request_expected_version=expected,
                    response=dict(state_version=end,error=error))
    def session(ops):
        return SimpleNamespace(mutation_operations=ops,operation_epoch=0,
                               epoch_initial_versions={0:1})
    m._verified_version_chain(session([operation(1,2)]),{'state_version':1},{'state_version':2})
    with pytest.raises(ValueError,match='advance lacks'):
        m._verified_version_chain(session([operation(1,9)]),{'state_version':1},{'state_version':9})
    with pytest.raises(ValueError,match='continuity'):
        m._verified_version_chain(session([operation(2,3)]),{'state_version':1},{'state_version':3})
    with pytest.raises(ValueError,match='advance lacks'):
        m._verified_version_chain(session([operation(1,9,accepted=False,error={'code':'state_conflict'})]),{'state_version':1},{'state_version':9})
    with pytest.raises(ValueError,match='duplicate'):
        m._verified_version_chain(session([operation(1,2),operation(2,3)]),{'state_version':1},{'state_version':3})
    ops=[operation(1,2),operation(2,3,'two'),operation(1,2,replay=True)]
    m._verified_version_chain(session(ops),{'state_version':1},{'state_version':3})
    boundary=object.__new__(m.BoundarySession)
    boundary.operation_epoch=0;boundary.epoch_initial_versions={0:1};boundary.lock=__import__('threading').RLock()
    command={'command':'sc.exe start fakenetng-mcp'}
    boundary._observe_service_restart('powershell',command,{'exit_code':1,'is_error':False,'output':'STARTED'})
    assert boundary.operation_epoch==0
    boundary._observe_service_restart('powershell',command,{'exit_code':0,'is_error':False,'output':'GONE'})
    assert boundary.operation_epoch==0
    boundary._observe_service_restart('powershell',command,{'exit_code':0,'is_error':False,'output':'STARTED'})
    assert boundary.operation_epoch==0  # Banners cannot prove a real restart.
    before={'pid':12,'birth':'1234','image':'fixture.exe','sha256':'a'*64,
            'service_config':{},'enabled':False,'grace':60,'fault_exists':False}
    after=dict(before,birth='1235')
    proof={'before':before,'after':after,'exit':{'old_pid':12,'old_birth':'1234','old_exited':False}}
    with pytest.raises(ValueError,match='instance proof'):
        boundary._observe_service_restart('verified-service-restart',proof,{})
    assert boundary.operation_epoch==0
    proof['exit']['old_exited']=True
    boundary._observe_service_restart('verified-service-restart',proof,{})
    assert boundary.operation_epoch==1


def test_typed_early_window_and_exact_child_arm(target):
    context,value,path=target
    plan=d.make_plan('stacks_unavailable',nonce=value['nonce'],
        config_sha256=value['config_sha256'],
        service_identity={'pid':4242,'creation_time':'123456789'})
    ready=d.build_ready(context,plan)
    assert d.ready_shape(ready)
    assert ready['run_id']==RUN and ready['pid']==4242
    assert ready['job_members']==[4242]
    arm=d.arm_from_ready_observation(ready,plan)
    assert set(arm)==d.ARM_KEYS
    assert arm['fault']=='stacks_unavailable' and arm['nonce']==value['nonce']
    # Shape cannot establish a process identity: reject against the actual
    # observed current process at the child-side admission boundary.
    wrong=d.arm_from_ready_observation(dict(ready,pid=7,job_members=[7]),plan)
    path.write_text(json.dumps(wrong))
    assert d.matching_arm(context,path) is None
    assert d.ready_shape(dict(ready,expires_ns=1)) is False
    with pytest.raises(d.DiagnosticUnavailable,match='another plan'):
        d.arm_from_ready_observation(ready,dict(plan,nonce='another-window'))


def test_plan_is_fixed_local_input_not_a_caller_target(target):
    context,value,path=target
    assert d.read_plan() is None
    plan=d.write_plan('native_crash',nonce='fixed-plan-nonce',ttl_ns=30_000_000_000,
        config_sha256=value['config_sha256'],
        service_identity={'pid':4242,'creation_time':'123456789'})
    assert d.read_plan()==plan
    with pytest.raises(FileExistsError):
        d.write_plan('native_crash',nonce='second-plan-nonce',
            config_sha256=value['config_sha256'],
            service_identity={'pid':4242,'creation_time':'123456789'})
    assert d.plan_path()==Path(context['run_dir']).parent/'FakeNet-NG-MCP'/'logs'/'diagnostic-plan.json'
    with pytest.raises(d.DiagnosticUnavailable,match='outside the fixed bound'):
        d.make_plan('native_crash',ttl_ns=1)
    d.remove_window_files(plan,None)
    assert not d.plan_path().exists()
    d.remove_window_files(plan,None)


def test_native_receipt_is_original_shape_and_consumes_the_arm(target,monkeypatch):
    context,value,path=target
    calls=[]
    class FakeCall:
        def __call__(self,*args):
            calls.append(args)
            raise OSError('modeled native termination')
    function=FakeCall()
    import ctypes
    monkeypatch.setattr(ctypes,'WinDLL',lambda *a,**k:SimpleNamespace(RaiseFailFastException=function),raising=False)
    monkeypatch.setattr(d,'os',SimpleNamespace(name='nt',environ=os.environ,
                                             getpid=os.getpid,fsync=os.fsync))
    with pytest.raises(OSError,match='modeled native termination'):
        d.trigger_native_crash(context,path)
    receipt=json.loads((Path(context['run_dir'])/'fault-triggered.json').read_text())
    assert receipt=={'fault':'native_crash','nonce':value['nonce']}
    assert calls==[(None,None,0)]


def test_original_diagnostic_oracle_rejects_known_cause_and_missing_receipt():
    from acceptance_mcp_diagnostic_oracles import validate_unknown_original
    record={'class':'unknown_cause','terminal_observed':True,'stimulus':{'kind':'unattributed'}}
    with pytest.raises(ValueError,match='independent original observation unavailable'):
        validate_unknown_original(record,[],known_cause='managed initialization failure')
    with pytest.raises(ValueError,match='independent original observation unavailable'):
        validate_unknown_original(dict(record,fault_evidence={}),[])


@pytest.mark.parametrize('unit',['DIAGNOSTIC-NATIVE-CRASH','DIAGNOSTIC-STACKS-UNAVAILABLE'])
def test_central_diagnostic_dispatch_calls_the_fixed_producer(target,monkeypatch,unit):
    import acceptance_mcp as m
    import acceptance_mcp_diagnostics as diagnostics
    token=object();calls=[]
    def execute(unit,args,channel,writer,root):
        calls.append((unit,args,channel,writer,root));return 2
    monkeypatch.setattr(diagnostics,'execute_unit',execute)
    result=m.invoke_unit(unit,
        SimpleNamespace(target_base_url='http://local.invalid'),token,token,
        {'run_p01_acc':token,'run_p02_acc':token,'run_p03_acc':token,'run_p04_acc':token})
    assert result==2
    assert len(calls)==1 and calls[0][0]==unit
    assert calls[0][2:4]==(token,token)


@pytest.mark.parametrize('fault',['unknown_cause'])
def test_unsupported_classes_stop_before_any_transport_or_service_mutation(fault):
    import acceptance_mcp_diagnostics as diagnostics
    gate=SimpleNamespace()
    result=diagnostics.run_diagnostic_case(gate,fault)
    assert result['status']=='blocked' and result['class']==fault
    assert result['failure']==diagnostics.UNSUPPORTED[fault]
    writer=SimpleNamespace(blocker=None)
    unit=next(k for k,v in diagnostics.SELECTED_UNITS.items() if v==fault)
    assert diagnostics.execute_unit(unit,None,None,writer,None)==2
    assert writer.blocker=={'reason':diagnostics.UNSUPPORTED[fault],'class':fault}


def test_plan_requires_verified_configuration_and_service_birth(target):
    context,value,path=target
    with pytest.raises(d.DiagnosticUnavailable,match='plan is invalid'):
        d.make_plan('native_crash')
    with pytest.raises(d.DiagnosticUnavailable,match='plan is invalid'):
        d.make_plan('native_crash',config_sha256=value['config_sha256'],
                    service_identity={'pid':True,'creation_time':'123'})
    plan=d.make_plan('native_crash',config_sha256=value['config_sha256'],
                    service_identity={'pid':4242,'creation_time':'999'})
    with pytest.raises(d.DiagnosticUnavailable,match='managed parent differs'):
        d.build_ready(context,plan)



def test_changed_rendezvous_bytes_are_preserved(target):
    context,value,path=target
    plan=d.write_plan('native_crash',config_sha256=value['config_sha256'],
                     service_identity={'pid':4242,'creation_time':'123456789'})
    changed=dict(plan,nonce='foreign-window')
    d.plan_path().write_text(json.dumps(changed))
    before=d.plan_path().read_bytes()
    with pytest.raises(d.DiagnosticUnavailable,match='cleanup identity differs'):
        d.remove_window_files(plan,None)
    assert d.plan_path().read_bytes()==before


def test_producer_waits_for_start_after_environment_capture(target,monkeypatch):
    import acceptance_mcp_diagnostics as diagnostics
    context,value,path=target
    path.unlink()
    plan=d.make_plan('native_crash',config_sha256=value['config_sha256'],
                    service_identity={'pid':4242,'creation_time':'123456789'})
    ready=d.build_ready(context,plan)
    producer=diagnostics.DiagnosticProducer(
        SimpleNamespace(inputs={'programdata_root':'C:/ProgramData/FakeNet-NG-MCP'}),plan)
    # A first observation after the former 5s deadline must still be eligible.
    ticks=iter([10.0,16.0])
    monkeypatch.setattr(diagnostics.time,'monotonic',lambda:next(ticks))
    monkeypatch.setattr(producer,'read',lambda key:ready)
    written=[]
    monkeypatch.setattr(producer,'write',lambda key,data:written.append((key,data)))
    producer.run()
    assert producer.error is None and written==[('arm',d.arm_from_ready_observation(ready,plan))]


def test_cleanup_runs_after_worker_exit_when_original_consumer_fails(target,monkeypatch):
    import acceptance_mcp as m
    import acceptance_mcp_diagnostics as diagnostics
    context,value,path=target
    order=[]
    class Producer:
        def __init__(self,channel,plan):
            self.plan=plan;self.cancel=__import__('threading').Event()
            self.ready=None;self.arm=None;self.error=None
        def write_plan(self):order.append('plan')
        def run(self):
            self.cancel.wait();order.append('worker-exit')
        def cleanup(self):
            assert 'worker-exit' in order
            order.append('cleanup');return {'plan':'owned_removed','ready':'absent','arm':'absent'}
    def consume(*args):raise RuntimeError('original consumer failure')
    gate=SimpleNamespace(channel=SimpleNamespace(inputs={
        'config_identity':{'sha256':value['config_sha256']}}),
        _fault_round=consume,observe_round=lambda action:action())
    monkeypatch.setattr(m,'service_preflight',lambda *a:{'pid':4242,'birth':'123456789'})
    monkeypatch.setattr(diagnostics,'DiagnosticProducer',Producer)
    record=diagnostics.run_diagnostic_round(gate,'native_crash')
    assert order==['plan','worker-exit','cleanup']
    assert record['failure'] and record['diagnostic_cleanup']['plan']=='owned_removed'


def test_raw_byte_receipt_hash_is_recomputed():
    import base64
    from acceptance_mcp_diagnostic_oracles import _raw_response
    raw=b'{"run_id":"original"}'
    response={'exit_code':0,'is_error':False,'output':json.dumps({
        'base64':base64.b64encode(raw).decode(),
        'sha256':hashlib.sha256(raw).hexdigest()})}
    assert _raw_response(response)=={'run_id':'original'}
    bad=copy.deepcopy(response)
    payload=json.loads(bad['output']);payload['sha256']='0'*64
    bad['output']=json.dumps(payload)
    with pytest.raises(ValueError,match='byte identity differs'):
        _raw_response(bad)


def test_archive_expansion_bound_precedes_original_validator(target,monkeypatch):
    import zipfile
    import acceptance_mcp_diagnostic_oracles as oracle
    context,value,path=target
    package=Path(context['run_dir'])/'diagnostic.zip'
    with zipfile.ZipFile(package,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json',json.dumps({'run_id':RUN}))
        archive.writestr('oversized.txt',b'x'*8192)
    exported={'path':str(package),'size':package.stat().st_size,
              'sha256':hashlib.sha256(package.read_bytes()).hexdigest()}
    monkeypatch.setattr(oracle,'MAX_ARCHIVE_BYTES',4096)
    with pytest.raises(ValueError,match='expansion'):
        oracle._archive(exported,RUN)



def test_detached_raw_response_cannot_replace_original_transport():
    from acceptance_mcp_diagnostic_oracles import _transport_rows, _require_original_response
    response={'exit_code':0,'is_error':False,'output':'{"base64":"e30=","sha256":"x"}'}
    path='C:/ProgramData/FakeNet-NG-MCP/artifacts/runs/'+RUN+'/diagnostic-window.json'
    rows=_transport_rows([{'kind':'powershell','input':{'command':path},'output':response}])
    _require_original_response(rows,path,response)
    with pytest.raises(ValueError,match='absent from original transport'):
        _require_original_response(rows,path,dict(response,output='changed original'))
    with pytest.raises(ValueError,match='absent from original transport'):
        _require_original_response(rows,path.replace(RUN,'another-run'),response)



def _no_stack_original_fixture(target):
    """Benign closed ZIP using the actual original basic-member names."""
    import base64, zipfile
    from fakenet.mcp.incident import BASIC_ITEMS
    context,value,path=target
    plan=d.make_plan('stacks_unavailable',nonce=value['nonce'],
        config_sha256=value['config_sha256'],
        service_identity={'pid':4242,'creation_time':'123456789'})
    ready=d.build_ready(context,plan)
    # Remote observation is a Windows path; benign host config bytes remain
    # local fixture data and are never used as a guest path.
    ready['run_dir']='C:/ProgramData/FakeNet-NG-MCP/artifacts/runs/'+RUN
    ready['config_path']='C:/Program Files/FakeNet-NG-MCP/configs/default.ini'
    arm=d.arm_from_ready_observation(ready,plan)
    trigger=dict(arm,observed_time_ns=time.time_ns())
    def original(value):
        raw=json.dumps(value).encode()
        return {'exit_code':0,'is_error':False,'output':json.dumps({
            'base64':base64.b64encode(raw).decode(), 'sha256':hashlib.sha256(raw).hexdigest()})}
    fallbacks={name:{'exists':False} for name in
        ('managed-thread-stacks.json','stop-thread-stacks.txt','fault-child-stacks.txt')}
    expected={'schema':'fakenet.no-stack-context.v1','plan':plan,'ready':ready,'arm':arm,
        'trigger':trigger,'fallback_files':fallbacks,
        'originals':{'window':original({'schema':'fakenet.diagnostic-window.v1','plan':plan,'ready':ready}),
            'trigger':original(trigger),'fallbacks':{'exit_code':0,'is_error':False,'output':json.dumps(fallbacks)}}}
    from pathlib import PureWindowsPath
    directory=PureWindowsPath(ready['run_dir'])
    expected['originals']['transport']=[
        {'kind':'powershell','input':{'command':str(directory/'diagnostic-window.json')},
         'output':expected['originals']['window']},
        {'kind':'powershell','input':{'command':str(directory/'diagnostic-triggered.json')},
         'output':expected['originals']['trigger']},
        {'kind':'powershell','input':{'command':' '.join(str(directory/name) for name in fallbacks)},
         'output':expected['originals']['fallbacks']}]
    data=bytearray(56)
    struct.pack_into('<IIII',data,0,0x504d444d,0xa793,1,32)
    struct.pack_into('<III',data,32,15,12,44)
    struct.pack_into('<III',data,44,12,1,4242)
    members={name:('benign '+name).encode() for name,kind in BASIC_ITEMS if name!='thread_stacks.txt'}
    members['config_snapshot.ini']=Path(context['config_path']).read_bytes()
    members['versions.json']=json.dumps({'config_sha256':arm['config_sha256'],
        'managed_process':{'identity':{'pid':4242,'creation_time':'123456789'},'exit_code':0xc0000602}}).encode()
    members['managed-exit.json']=json.dumps({'schema':'fakenet.exit-result.v1',
        'target':{'run_id':RUN,'pid':4242,'creation_time':'123456789'},'complete':True}).encode()
    members['userdump.dmp']=bytes(data)
    entries=[{'item':name,'result':'ok','failure_reason':None,'size':len(raw),
              'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in members.items()]
    entries.append({'item':'thread_stacks.txt','result':'failed','failure_reason':'unavailable','size':0,'sha256':None})
    manifest={'run_id':RUN,'complete':False,'entries':entries}
    def save(label,manifest_value=manifest,member_values=members):
        package=Path(context['run_dir'])/(label+'.zip')
        with zipfile.ZipFile(package,'w') as archive:
            archive.writestr('manifest.json',json.dumps(manifest_value))
            for name,raw in member_values.items():archive.writestr(name,raw)
        return {'path':str(package),'size':package.stat().st_size,
            'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'run_id':RUN,'incident_name':'incident',
            'complete':False,'manifest':manifest_value}
    return expected,members,manifest,save


def test_explicit_no_stack_assessment_preserves_raw_failure_and_default_rejects(target):
    import acceptance_mcp as m
    integrity=m.modules()['evidence_integrity']
    expected,members,manifest,save=_no_stack_original_fixture(target)
    exported=save('no-stack-valid')
    facts=integrity.assess_no_stack_export(exported,RUN,expected)
    assert facts['expected_unavailable']=='thread_stacks.txt'
    assert facts['raw_manifest_complete'] is False and exported['complete'] is False
    assert integrity.validate_incident_export(exported,RUN,fault_round=True)
    assert integrity.validate_incident_export(exported,RUN,fault_round=True,expected_diagnostic=expected)==[]
    assert exported['manifest']['complete'] is False
    assert next(x for x in manifest['entries'] if x['item']=='thread_stacks.txt')['result']=='failed'


@pytest.mark.parametrize('mode',['reason','other-basic','missing-dump','wrong-dump-pid','raw-complete','stacks-present','export-complete'])
def test_rehashed_no_stack_packages_do_not_bypass_original_content_predicates(target,mode):
    import acceptance_mcp as m
    integrity=m.modules()['evidence_integrity']
    expected,members,manifest,save=_no_stack_original_fixture(target)
    members=copy.deepcopy(members);manifest=copy.deepcopy(manifest)
    if mode=='reason':
        next(x for x in manifest['entries'] if x['item']=='thread_stacks.txt')['failure_reason']='total budget exhausted'
    elif mode=='other-basic':
        next(x for x in manifest['entries'] if x['result']=='ok')['result']='failed'
    elif mode=='missing-dump':
        members.pop('userdump.dmp')
    elif mode=='wrong-dump-pid':
        data=bytearray(members['userdump.dmp']);struct.pack_into('<I',data,52,7);members['userdump.dmp']=bytes(data)
        item=next(x for x in manifest['entries'] if x['item']=='userdump.dmp')
        item['sha256']=hashlib.sha256(data).hexdigest()
    elif mode=='raw-complete':manifest['complete']=True
    elif mode=='stacks-present':members['thread_stacks.txt']=b'prior real stack'
    exported=save('bad-'+mode,manifest,members)
    if mode=='export-complete':exported['complete']=True
    with pytest.raises((ValueError,RuntimeError,KeyError)):
        integrity.assess_no_stack_export(exported,RUN,expected)


@pytest.mark.parametrize('mode',['cached','wrong-target','expired','raw-hash','boolean','uninitialized'])
def test_no_stack_context_cannot_self_grant_expected_failure_credit(target,mode):
    import acceptance_mcp as m
    integrity=m.modules()['evidence_integrity']
    expected,members,manifest,save=_no_stack_original_fixture(target)
    bad=copy.deepcopy(expected)
    if mode=='cached':bad['fallback_files']['managed-thread-stacks.json']={'exists':True}
    elif mode=='wrong-target':bad['arm']['creation_time']='999'
    elif mode=='expired':bad['trigger']['observed_time_ns']=bad['arm']['expires_ns']
    elif mode=='raw-hash':
        response=bad['originals']['window'];value=json.loads(response['output']);value['sha256']='0'*64;response['output']=json.dumps(value)
    elif mode=='boolean':bad={'class':'stacks_unavailable','verified':True}
    else:bad['ready']['service_identity']['creation_time']='wrong'
    with pytest.raises((ValueError,TypeError,KeyError)):
        integrity.assess_no_stack_export(save('bad-context-'+mode),RUN,bad)


def test_original_exporter_keeps_no_stack_archive_incomplete(target):
    import acceptance_mcp as m
    from acceptance_mcp_capabilities import OriginalArchiveChannel
    mods=m.modules();expected,members,manifest,save=_no_stack_original_fixture(target)
    source=save('export-source')
    record={'fault_evidence':{'receipt':{'run_id':RUN}},'incident_exports':[source]}
    channel=OriginalArchiveChannel([(Path(source['path']),record)])
    exported=mods['helpers'].export_incident_bundle(channel,RUN,
        Path(target[0]['run_dir'])/'export-copy.zip',fault_round=True,expected_diagnostic=expected)
    assert exported['complete'] is False and exported['manifest']['complete'] is False
    assert 'thread_stacks.txt: unavailable' in exported['failures']
    assert exported['diagnostic_assessment']['expected_unavailable']=='thread_stacks.txt'
    assert mods['evidence_integrity'].validate_incident_export(exported,RUN,fault_round=True)


def test_no_stack_transparent_stimulus_requires_early_binding_and_preserves_cached_source(target):
    context,value,path=target
    value['fault']='stacks_unavailable';path.write_text(json.dumps(value))
    with pytest.raises(d.DiagnosticUnavailable,match='bound before snapshots'):
        d.trigger_stack_unavailability(context,path)
    context=dict(context,no_stack_bound_early=True)
    source=Path(context['run_dir'])/'managed-thread-stacks.json'
    source.write_text('existing stack source')
    with pytest.raises(d.DiagnosticUnavailable,match='preserve fallback'):
        d.trigger_stack_unavailability(context,path)
    assert source.read_text()=='existing stack source' and path.exists()



def test_no_stack_context_requires_original_transport_paths_even_if_rehashed(target):
    import acceptance_mcp as m
    integrity=m.modules()['evidence_integrity']
    expected,members,manifest,save=_no_stack_original_fixture(target)
    expected['originals']['transport'][0]['input']['command']='another run diagnostic-window.json'
    with pytest.raises(ValueError,match='detached from transport'):
        integrity.assess_no_stack_export(save('detached-original'),RUN,expected)



def test_original_fault_consumer_rejudges_explicit_no_stack_archive(target,monkeypatch):
    import acceptance_mcp as m
    from acceptance_mcp_capabilities import OriginalArchiveChannel
    mods=m.modules();release=mods['run_p05_release']
    expected,members,manifest,save=_no_stack_original_fixture(target)
    source=save('original-consumer-source')
    record={'fault_evidence':{'receipt':{'run_id':RUN}},'incident_exports':[source]}
    archives=OriginalArchiveChannel([(Path(source['path']),record)])
    class Channel:
        def powershell(self,command,timeout=120):
            if '$receipts=@(' in command:
                original={'receipt':{'run_id':RUN,'receipt':{
                    'fault':'stacks_unavailable','nonce':expected['arm']['nonce']}},
                    'incidents':[{'path':'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\'+RUN+'\\incident\\manifest.json',
                                  'manifest':manifest}]}
                return {'output':json.dumps(original),'exit_code':0,'is_error':False}
            return archives.powershell(command,timeout=timeout)
    gate=object.__new__(release.ReleaseGate)
    gate.base='http://local.invalid';gate.channel=Channel()
    gate.release=Path(target[0]['run_dir'])/'original-consumer-export';gate.release.mkdir()
    # OS environment capture is modeled; the original fault consumer,
    # archive exporter, byte validator and all their conditions execute.
    gate.capture_sections=lambda:{'benign':'same OS snapshot'}
    gate.audit_diff=lambda before:{}
    def remote_call(base,tool,arguments=None,**kwargs):
        if tool=='get_status':return {'state_version':1}
        if tool=='load_config':return {'state_version':2}
        if tool=='start':return {'state':'failed','run_id':RUN,'state_version':3}
        raise AssertionError('unexpected original consumer transport '+tool)
    monkeypatch.setattr(release,'call',remote_call)
    final={'state':'stopped','last_run_outcome':'failed','run_id':None,'controller':None}
    monkeypatch.setattr(release,'wait_state',lambda base,predicate,timeout:(True,final))
    observed=gate._fault_round('stacks_unavailable',1,expected['arm']['nonce'],
                              diagnostic_context=lambda run:expected)
    assert 'failure' not in observed
    assert observed['expected_diagnostic']==expected
    exported=observed['incident_exports'][0]
    assert exported['complete'] is False and exported['manifest']['complete'] is False
    assert exported['diagnostic_assessment']['expected_unavailable']=='thread_stacks.txt'
    # Same raw missing-stack package without explicit context remains a failure.
    gate.release=Path(target[0]['run_dir'])/'default-consumer-export';gate.release.mkdir()
    original=gate._fault_round('stacks_unavailable',2,expected['arm']['nonce'])
    assert original.get('failure')


def test_original_acc014_keeps_five_class_and_independent_localization_requirements(target):
    import acceptance_mcp as m
    from acceptance_mcp_capabilities import OriginalArchiveChannel
    mods=m.modules();expected,members,manifest,save=_no_stack_original_fixture(target)
    exported=save('incomplete-matrix-source')
    record={'class':'stacks_unavailable','expected_diagnostic':expected,
        'fault_evidence':{'receipt':{'run_id':RUN}},'incident_exports':[exported]}
    file=Path(target[0]['run_dir'])/'only-no-stack-record.json';file.write_text(json.dumps(record))
    writer=mods['helpers'].EvidenceWriter(Path(target[0]['run_dir'])/'matrix-check','fixture')
    args=SimpleNamespace(**{name:'fixture-'+name for name in m.IDENTITY_FIELDS},
                         fault_record=[str(file)],localization_record='')
    code=mods['run_p04_acc'].run_acc014('',OriginalArchiveChannel([(file,record)]),writer,args)
    assert code==mods['helpers'].EXIT_BLOCKED
    assert writer.blocker['reason']=='actual five-class incident coverage missing'


class _ModeledSelfExit(OSError):
    pass


def test_unknown_exact_current_child_stimulus_and_one_shot(target,monkeypatch):
    context,value,path=target
    value['fault']='unknown_cause';path.write_text(json.dumps(value))
    context=dict(context,unknown_options=dict(d.UNKNOWN_OPTIONS));calls=[]
    class Exit:
        def __call__(self,code):calls.append(code);raise _ModeledSelfExit('modeled current-child exit')
    edge=Exit()
    import ctypes
    monkeypatch.setattr(ctypes,'WinDLL',lambda name,**kw:SimpleNamespace(ExitProcess=edge),raising=False)
    monkeypatch.setattr(d,'os',SimpleNamespace(name='nt',environ=os.environ,getpid=os.getpid,fsync=os.fsync))
    injector=f.FaultInjector();injector._diagnostic_context=context
    with pytest.raises(_ModeledSelfExit):injector.maybe_unknown_cause()
    assert calls==[d.UNKNOWN_EXIT_CODE] and len(edge.argtypes)==1 and edge.restype is None
    assert not path.exists()
    truth=json.loads((Path(context['run_dir'])/'diagnostic-self-exit.json').read_text())
    assert truth['arm']==value and truth['mechanism']=='current-child-ExitProcess'
    assert injector.maybe_unknown_cause() is None and calls==[d.UNKNOWN_EXIT_CODE]


@pytest.mark.parametrize('mode',['disabled','wrong-run','wrong-birth','wrong-job','wrong-config','expired','wrong-nonce','missing-optin'])
def test_unknown_wrong_window_cannot_reach_native_edge(target,monkeypatch,mode):
    context,value,path=target;value['fault']='unknown_cause'
    context=dict(context,unknown_options=dict(d.UNKNOWN_OPTIONS))
    if mode=='disabled':monkeypatch.delenv('FAKENETNG_MCP_FAULT_INJECTION')
    elif mode=='missing-optin':context.pop('unknown_options')
    else:
        key,new={'wrong-run':('run_id','44444444-4444-4444-8444-444444444444'),
            'wrong-birth':('creation_time','99'),'wrong-job':('job_members',[99]),
            'wrong-config':('config_sha256','0'*64),'expired':('expires_ns',1),
            'wrong-nonce':('nonce','another')}[mode];value[key]=new
    path.write_text(json.dumps(value));before=path.read_bytes()
    injector=f.FaultInjector();injector._diagnostic_context=context
    with mock.patch.object(d,'trigger_unknown_self_exit',side_effect=AssertionError('no native call')):
        assert injector.maybe_unknown_cause() is None
    assert path.read_bytes()==before
    assert not (Path(context['run_dir'])/'diagnostic-self-exit.json').exists()


def _unknown_boundary(inputs,target,monkeypatch):
    """Model remote OS bytes; run original child hook and central driver."""
    from test_acceptance_mcp import FaultProcessBoundary
    import base64,io,re,zipfile
    from pathlib import PureWindowsPath
    context,unused,armfile=target;armfile.unlink()
    config=Path(context['config_path']);config.write_bytes((Path(__file__).resolve().parents[1]/'fakenet/configs/default.ini').read_bytes())
    from fakenet.mcp import service_stop
    real_time=time.time;real_mono=time.monotonic
    monkeypatch.setattr(service_stop,'process_identity',lambda pid=None:{'pid':12,'creation_time':str(1234+getattr(boundary,'service_generation',0))} if pid==os.getppid() else {'pid':4242,'creation_time':'123456789'})
    monkeypatch.setattr(d,'os',SimpleNamespace(name='nt',environ=os.environ,getpid=os.getpid,getppid=os.getppid,fsync=os.fsync))
    class Exit:
        def __call__(self,code):
            assert code==d.UNKNOWN_EXIT_CODE
            raise _ModeledSelfExit('modeled fixed ExitProcess')
    import ctypes
    monkeypatch.setattr(ctypes,'WinDLL',lambda name,**kw:SimpleNamespace(ExitProcess=Exit()),raising=False)
    event_record='Event[0]:\n  Log Name: System\n  Source: Service Control Manager\n  Event ID: 7036\n  Level: Information\n  Description:\nThe FakeNet-NG MCP service entered the running state.\n'
    class Boundary(FaultProcessBoundary):
        def __init__(self):
            super().__init__(inputs);self.run_id=RUN;self.child_terminated=False;self.child_calls=0
        def archive(self):
            from fakenet.mcp.incident import BASIC_ITEMS
            members={name:b'{}' for name,unused in BASIC_ITEMS}
            normal=b'2026-10-26 07:30:00,000 INFO FakeNet DEFAULT_INTERCEPTION_READY\n'
            members.update({'stdout_stderr.log':normal, 'run_log.txt':normal,
                'process_tree.txt':json.dumps([{'ProcessId':4242,'ParentProcessId':12,
                    'Name':'fakenetng-mcp-managed.exe','CommandLine':'managed-child',
                    'CreationDate':'/Date(0)/'}]).encode(),
                'handle_summary.txt':json.dumps([{'Id':4242,'ProcessName':'fakenetng-mcp-managed',
                    'HandleCount':30,'StartTime':'/Date(0)/'}]).encode(),
                'windivert_filter.txt':json.dumps({'final_filter':'outbound and ip',
                    'tasklist_m':'INFO: No tasks are running which match the specified criteria.'}).encode(),
                'firewall_diff.txt':json.dumps({'before':'No rules match the specified criteria.',
                    'after':'No rules match the specified criteria.','changed':False}).encode(),
                'thread_stacks.txt':b'SUPERVISOR\nThread 1:\n  C:/app/supervisor.py:30 run\nMANAGED\nThread 2:\n  C:/app/managed.py:50 health\n',
                'event_log.txt':(event_record+'\n----APPLICATION----\n'+event_record).encode()})
            members['timeline.json']=b'[]';members['artifact_metadata.json']=b'[]'
            members['baseline_diff.json']=b'{"before":{},"after":{},"differences":{}}'
            members['config_snapshot.ini']=config.read_bytes();members['exception.txt']=b'managed IPC EOF'
            members['versions.json']=json.dumps({'config_sha256':inputs['config_identity']['sha256'],
                'managed_process':{'identity':{'pid':4242,'creation_time':'123456789'},'exit_code':d.UNKNOWN_EXIT_CODE,'job_members':[]}}).encode()
            members['managed-exit.json']=json.dumps({'schema':'fakenet.exit-result.v1','target':{'run_id':RUN,'pid':4242,'creation_time':'123456789'},
                'classification':'self_exit','complete':True,'target_handle_closed':True,'error':None,
                'stop_intent_claim':None,'normal_ack':None,'notification':{'target_pid':4242,'initiator_pid':4242}}).encode()
            dump=bytearray(56);struct.pack_into('<IIII',dump,0,0x504d444d,0xa793,1,32);struct.pack_into('<III',dump,32,15,12,44);struct.pack_into('<III',dump,44,12,1,4242)
            members['userdump.dmp']=bytes(dump);self.members=members
            self.manifest={'run_id':RUN,'complete':True,'entries':[{'item':name,'result':'ok','failure_reason':None,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in members.items()]}
            self.manifest_bytes=json.dumps(self.manifest).encode()
            from fakenet.mcp.artifacts import write_publication
            published=Path(context['run_dir'])/'fixture-publication'
            published.mkdir(exist_ok=True)
            for name,raw in dict(members,**{'manifest.json':self.manifest_bytes}).items():
                (published/name).write_bytes(raw)
            write_publication(published,[published/name for name in list(members)+['manifest.json']])
            members['published.json']=(published/'published.json').read_bytes()
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as archive:
                archive.writestr('manifest.json',self.manifest_bytes)
                for name,raw in members.items():archive.writestr(name,raw)
            self.zip_bytes=stream.getvalue()
        def exchange(self,kind,value):
            if kind=='time':return real_time()
            if kind=='monotonic':return real_mono()
            if kind=='http':
                req=json.loads(value['data']);tool=req['params']['name']
                if tool=='start':
                    injector=f.FaultInjector()
                    assert injector.prepare_diagnostic_start(RUN,context['run_dir'],{'pid':4242,'creation_time':'123456789'},str(config))
                    self.child_calls+=1
                    with pytest.raises(_ModeledSelfExit):injector.maybe_unknown_cause()
                    self.child_terminated=True
                    self.fault=json.loads((Path(context['run_dir'])/'fault-triggered.json').read_text());self.archive()
                    response=super().exchange(kind,value);payload=json.loads(json.loads(response['body'])['result']['content'][0]['text']);payload['state']='healthy';return self.response(payload)
                if tool=='get_status':
                    response=super().exchange(kind,value)
                    if self.child_terminated:
                        payload=json.loads(json.loads(response['body'])['result']['content'][0]['text']);payload['failure_reason']='managed IPC EOF';return self.response(payload)
                    return response
            if kind=='powershell':
                command=value['command'];match=re.search(r"\$p='([^']+)';",command)
                if match and ('diagnostic-' in match.group(1) or 'fault-injection.json' in match.group(1)):
                    name=PureWindowsPath(match.group(1)).name
                    source=(armfile.parent/name) if name in ('diagnostic-plan.json','diagnostic-ready.json','fault-injection.json','diagnostic-unknown-options.json') else Path(context['run_dir'])/name
                    if '[IO.FileMode]::CreateNew' in command:
                        raw=base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)",command).group(1));source.write_bytes(raw);output=raw.decode()
                    elif 'Remove-Item -LiteralPath' in command:source.unlink();output=json.dumps({'removed':True,'absent':True})
                    elif 'ReadAllBytes' in command:
                        raw=source.read_bytes();output=json.dumps({'base64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()})
                    else:output=source.read_text() if source.exists() else 'null'
                    return {'output':output,'raw':output,'exit_code':0,'is_error':False}
            return super().exchange(kind,value)
    boundary=Boundary()
    return boundary


def test_unknown_original_chain_same_central_cli_and_rehashed_bad_domain(target,monkeypatch):
    import acceptance_mcp as m
    from test_acceptance_mcp import PublicMcpCliTests
    client=PublicMcpCliTests();client.setUp();client.inputs['diagnostic']=dict(d.UNKNOWN_OPTIONS)
    boundary=_unknown_boundary(client.inputs,target,monkeypatch)
    client.prepare(case='MCP-P04-FULL',checks=['DIAGNOSTIC-UNKNOWN-CAUSE'])
    with mock.patch.object(m,'NativeBoundary',side_effect=lambda *a,**kw:boundary):
        execution=client.cli('execute','--plan',client.run/'plan.json')
    assert execution[0]==0,execution
    judged=client.cli('judge','--plan',client.run/'plan.json','--results',client.run/'results','--output',client.run/'positive.json')
    assert judged[0]==0,judged
    result=m.read(client.run/'positive.json');assert result['fixture_contract_pass'] and not result['full_functional_pass']
    assert boundary.child_calls==1 and boundary.child_terminated
    case=client.run/'results/MCP-P04-FULL';unit=case/'driver/units/DIAGNOSTIC-UNKNOWN-CAUSE'
    result=m.read(unit/'result.json');ref=next(x for x in result['evidence'] if x.get('name')=='diagnostic-record');record=m.read(ref['path'])
    trace=m.read(unit/'trace.json')
    import acceptance_mcp_diagnostic_oracles as oracle
    assert oracle.validate_unknown_original(record,record['incident_exports'],expected=client.inputs,root=m.ROOT,transport=trace['records'])['class']=='unknown_cause'
    for mode in ('known-cause','plain-cause','hidden-log-cause','raw-terminal','missing','truncated','bad-hash','bad-dump','wrong-birth','external','normal','live','failed-restore','detached'):
        bad=copy.deepcopy(record);transport=copy.deepcopy(trace['records']);members=copy.deepcopy(boundary.members)
        if mode=='known-cause':members['exception.txt']=b'ValueError: known application input failure'
        elif mode=='plain-cause':members['exception.txt']=b'port 80 is already in use'
        elif mode=='hidden-log-cause':members['stdout_stderr.log']=b'binding port 80 was denied'
        elif mode=='raw-terminal':bad['unknown_terminal_observation']['unobserved']='forged'
        elif mode=='missing':members.pop('thread_stacks.txt')
        elif mode=='truncated':members['versions.json']=b'{'
        elif mode=='bad-hash':members['config_snapshot.ini']+=b'changed'
        elif mode=='bad-dump':raw=bytearray(members['userdump.dmp']);struct.pack_into('<I',raw,52,7);members['userdump.dmp']=bytes(raw)
        elif mode=='wrong-birth':bad['diagnostic_arm']['creation_time']='99'
        elif mode in ('external','normal'):
            raw=json.loads(members['managed-exit.json']);raw['classification']='external_termination' if mode=='external' else 'controlled_normal_exit';members['managed-exit.json']=json.dumps(raw).encode()
        elif mode=='live':bad['unknown_terminal_observation']['state']='healthy'
        elif mode=='failed-restore':bad['diagnostic_service_restoration']['after']['grace']=99
        elif mode=='detached':transport=[]
        import zipfile
        manifest=copy.deepcopy(boundary.manifest)
        if mode!='bad-hash':manifest['entries']=[dict(row,size=len(members[row['item']]),sha256=hashlib.sha256(members[row['item']]).hexdigest()) for row in manifest['entries'] if row['item'] in members]
        publication=json.loads(members['published.json'])
        manifest_raw=json.dumps(manifest).encode()
        publication['files']={name:{'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in dict(members,**{'manifest.json':manifest_raw}).items() if name!='published.json'}
        members['published.json']=json.dumps(publication).encode()
        package=client.base/('unknown-negative-'+mode+'.zip')
        with zipfile.ZipFile(package,'w') as archive:
            archive.writestr('manifest.json',json.dumps(manifest))
            for name,raw in members.items():archive.writestr(name,raw)
        exported=bad['incident_exports'][0];exported.update(path=str(package),size=package.stat().st_size,sha256=m.sha256(package),manifest=manifest)
        with pytest.raises((ValueError,RuntimeError,KeyError,TypeError)):
            oracle.validate_unknown_original(bad,bad['incident_exports'],expected=client.inputs,root=m.ROOT,transport=transport)
    record['diagnostic_service_restoration']['after']['grace']=99
    Path(ref['path']).write_text(json.dumps(record));ref.update(size=Path(ref['path']).stat().st_size,sha256=m.sha256(ref['path']))
    (unit/'result.json').write_text(json.dumps(result));receipt=m.read(case/'receipt.json')
    for item in receipt['artifacts']:item['sha256']=m.sha256(item['path'])
    (case/'receipt.json').write_text(json.dumps(receipt));index=m.read(client.run/'results/results.json')
    for row in index['receipts']:
        if row['case_id']=='MCP-P04-FULL':row['sha256']=m.sha256(case/'receipt.json')
    (client.run/'results/results.json').write_text(json.dumps(index))
    negative=client.cli('judge','--plan',client.run/'plan.json','--results',client.run/'results','--output',client.run/'negative.json')
    assert negative[0]!=0,negative
    assert not m.read(client.run/'negative.json')['fixture_contract_pass']


def test_unknown_p04_rejects_record_chosen_source_root_before_consumer(target,monkeypatch):
    import acceptance_mcp as m
    import acceptance_mcp_diagnostic_oracles as oracle
    mods=m.modules();root=Path(target[0]['run_dir']);identity={name:'fixture-'+name for name in m.IDENTITY_FIELDS}
    unknown={'class':'unknown_cause','unknown_original_context':{'source_root':str(root),'inputs':{'identity':identity},'transport':[]}}
    records=[unknown]+[{'class':name} for name in mods['run_p05_release'].FAULT_CLASSES]
    paths=[]
    for n,row in enumerate(records):
        path=root/('root-boundary-'+str(n)+'.json');path.write_text(json.dumps(row));paths.append(str(path))
    writer=mods['helpers'].EvidenceWriter(root/'root-boundary-output','fixture')
    with mock.patch.object(oracle,'validate_unknown_original',side_effect=AssertionError('foreign root cannot load consumer')):
        code,bundles,observed=mods['run_p04_acc'].collect_acc014_incident_integrity('',None,writer,SimpleNamespace(**identity,fault_record=paths))
    assert code==mods['helpers'].EXIT_FAIL and bundles=={}
    assert writer.blocker['reason']=='unknown original source root or candidate differs'


def test_closed_fixture_legacy_scope_resets_and_native_stays_strict(target,monkeypatch):
    import acceptance_mcp as m
    import acceptance_mcp_capabilities as cap
    from test_acceptance_mcp import inputs_at,ReadOnlyBoundary
    mods=m.modules();scope=mods['run_p04_acc'].CLOSED_FIXTURE_LEGACY_RECORDS
    root=Path(target[0]['run_dir'])/'fixture-scope';inputs=inputs_at(root);inputs['references']={'ACC-014':{'isolated':'test boundary'}}
    for fixture in (True,False):
        seen=[]
        def evaluate(*args,**kwargs):
            seen.append(scope.get());raise ValueError('modeled closed capability refusal')
        boundary=ReadOnlyBoundary(inputs);boundary.fixture=fixture
        with mock.patch.object(cap,'evaluate',evaluate):
            value=m.run('MCP-P04-FULL',root/str(fixture),inputs,selected=['ACC-014'],boundary=boundary,fixture=fixture)
        assert seen==[fixture] and scope.get() is False
        assert value['checks']['ACC-014']['status']!='pass'


def test_unknown_cli_input_validation_loads_fixed_root_from_external_cwd(tmp_path):
    import subprocess,sys
    root=Path(__file__).resolve().parents[1]
    # Complete inputs reach unknown_options before other validations.
    from test_acceptance_mcp import inputs_at
    inputs=inputs_at(tmp_path/'input');inputs['diagnostic']={}
    code="import runpy,json; m=runpy.run_path(%r); m['validate_inputs'](json.loads(%r),'MCP-P04-FULL',['DIAGNOSTIC-UNKNOWN-CAUSE'],fixture=True)" % (str(root/'tools/acceptance_mcp.py'),json.dumps(inputs))
    env=dict(os.environ);env.pop('PYTHONPATH',None);env['PYTHONDONTWRITEBYTECODE']='1'
    result=subprocess.run([sys.executable,'-B','-I','-c',code],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert result.returncode!=0
    assert 'exact unknown diagnostic options required' in result.stderr,result.stderr
    assert 'ModuleNotFoundError' not in result.stderr
    inputs['diagnostic']=dict(d.UNKNOWN_OPTIONS)
    code="import runpy,json; m=runpy.run_path(%r); m['validate_inputs'](json.loads(%r),'MCP-P04-FULL',['DIAGNOSTIC-UNKNOWN-CAUSE'],fixture=True)" % (str(root/'tools/acceptance_mcp.py'),json.dumps(inputs))
    positive=subprocess.run([sys.executable,'-B','-I','-c',code],cwd=tmp_path,env=env,capture_output=True,text=True)
    assert positive.returncode==0,positive.stderr



@pytest.mark.parametrize('mode',['size','hash','missing','extra','path','schema','boolean','duplicate'])
def test_unknown_canonical_publication_rejects_rehashed_bad_metadata(mode):
    from fakenet.mcp.artifacts import write_publication
    import acceptance_mcp_diagnostic_oracles as oracle
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);(root/'manifest.json').write_bytes(b'{}');(root/'exception.txt').write_bytes(b'managed IPC EOF')
        write_publication(root,[root/'manifest.json',root/'exception.txt'])
        members={p.name:p.read_bytes() for p in root.iterdir()}
        data=json.loads(members['published.json'])
        if mode=='size':data['files']['exception.txt']['size']+=1
        elif mode=='hash':data['files']['exception.txt']['sha256']='0'*64
        elif mode=='missing':data['files'].pop('exception.txt')
        elif mode=='extra':members['extra.txt']=b'unknown bytes'
        elif mode=='path':data['files']['../exception.txt']=data['files'].pop('exception.txt')
        elif mode=='schema':data['schema']='unknown'
        elif mode=='boolean':data['files']['exception.txt']['size']=True
        else:
            members['published.json']=b'{"schema":"fakenet.artifact-publication.v1","files":{},"files":{}}'
        if mode!='duplicate':members['published.json']=json.dumps(data).encode()
        with pytest.raises(ValueError):oracle._validate_publication(members)


@pytest.mark.parametrize('member,raw',[
 ('stdout_stderr.log',b'2026-10-26 07:30:00,000 ERROR FakeNet port 80 is already in use\n'),
 ('run_log.txt',b'2026-10-26 07:30:00,000 INFO FakeNet ValueError: hidden cause\n'),
 ('stdout_stderr.log',b'2026-10-26 07:30:00,000 INFO FakeNet an undocumented line\n'),
 ('versions.json',b'{"managed_process":{"initialization_error":"port 80 is already in use"}}'),
 ('process_tree.txt',b'not an inventory'),
 ('process_tree.txt',b'[{"ProcessId":true,"ParentProcessId":1,"Name":"app","CommandLine":"app","CreationDate":"/Date(0)/"}]'),
 ('windivert_filter.txt',b'{"final_filter":"outbound and ip","tasklist_m":"unresolved collector error"}'),
 ('firewall_diff.txt',b'{"before":"old","after":"changed","changed":false}'),
 ('event_log.txt',b'Event[0]:\n  Source: App\n  Event ID: 1\n  Level: Error\n  Description:\nknown error\n'),
 ('exception.txt',b"managed start failed: EOFError('managed IPC EOF'); ValueError: hidden cause"),
 ('exception.txt',b"managed start failed: ValueError('managed IPC EOF')"),
 ('thread_stacks.txt',b'Traceback (most recent call last):\nValueError: known\n'),
 ('versions.json',b'{"error":null,"error":"hidden"}'),
 ('timeline.json',b'[{"message":"hidden unexplained diagnostic"}]'),
 ('artifact_metadata.json',b'[{"path":"x","size":true,"sha256":"bad"}]'),
 ('windivert_filter.txt',b'{"final_filter":"ValueError.hidden","tasklist_m":"INFO: No tasks are running which match the specified criteria."}'),
 ('run_log.txt',b'\xff'),
])
def test_unknown_typed_domain_never_ignores_unresolved_or_known_diagnostics(member,raw):
    import acceptance_mcp_diagnostic_oracles as oracle
    with pytest.raises((ValueError,UnicodeError)):
        oracle._classify_domain_member(member,raw)


def test_unknown_transport_wrapper_is_exact_and_original_text_is_retained():
    import acceptance_mcp_diagnostic_oracles as oracle
    raw=b"managed start failed: EOFError('managed IPC EOF')"
    result=oracle._classify_domain_member('exception.txt',raw)
    assert result['kind']=='transport-symptom' and result['symptom']=='managed IPC EOF'
    assert raw==b"managed start failed: EOFError('managed IPC EOF')"
