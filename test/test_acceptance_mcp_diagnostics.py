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
    assert boundary.operation_epoch==1
