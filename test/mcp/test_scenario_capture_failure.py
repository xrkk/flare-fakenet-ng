"""Offline response and command-boundary controls for shared writer ownership."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite


PROFILE = {'bucket':'B1','tempo':'normal','variant':'v','interleave':'restart-window',
           'cadence_ms':100,'connection_window_seconds':10,
           'probe_target':{'host':'example.com','port':443,'protocol':'tls'}}


def runner():
    s=suite.Suite.__new__(suite.Suite)
    s.vm=object();s.guest_work_root=suite.E_GUEST_WORK_ROOT
    s.native_clock_diagnostic=True;s.capture_contract='scenario-shared-v2'
    s.pktmon_file_size_mib=128;s.identity=SimpleNamespace(candidate_id='candidate')
    s._start_kernel_capture=lambda root:{'session_name':'owned-kernel'}
    return s


@pytest.mark.parametrize('terminal', [
    {'cooperative_exit':'timeout','physical_terminal':'retained'},
    {'cooperative_exit':'identity-unknown','physical_terminal':'retained'},
    {'cooperative_exit':'identity-mismatch','physical_terminal':'retained'},
    {'cooperative_exit':'exited','physical_terminal':'retained',
     'cooperative_errors':['probe query failed']},
    {'cooperative_exit':'identity-unknown','physical_terminal':'retained',
     'cooperative_errors':['stopfile failed']},
    {'cooperative_exit':'exited','physical_terminal':'start-unknown'},
    {'cooperative_exit':'not-created','physical_terminal':'start-unknown'},
    {'cooperative_exit':'exited','physical_terminal':'retained',
     'cooperative_errors':['pktmon stop response unknown']},
    {'cooperative_exit':'exited','physical_terminal':'stopped','cooperative_errors':['stopfile']},
])
def test_returned_failure_retains_uncertain_writers(terminal):
    s=runner();commands=[]
    s._stop_kernel_capture=lambda _:pytest.fail('kernel stopped while writer uncertain')
    s._vm_json=lambda cmd,timeout:(commands.append(cmd) or
        (dict(startup_failed=True,**terminal),'failure wire'))
    with pytest.raises(suite.UnsettledCaptureStart,match='live/unknown writer'):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')
    assert len(commands)==1
    command=commands[0]
    assert command.count('pktmon start --capture')==1
    assert 'pktmon retry start failed' not in command
    assert "$probeTerminal -eq 'exited' -or $probeTerminal -eq 'not-created'" in command
    assert 'physical_terminal=$physicalTerminal' in command


def test_returned_proven_stop_can_close_owned_kernel():
    s=runner();closed=[]
    s._stop_kernel_capture=lambda c:(closed.append(c) or {'files':[]})
    s._vm_json=lambda cmd,timeout:({'startup_failed':True,'cooperative_exit':'exited',
        'physical_terminal':'stopped','cooperative_errors':[]},'wire')
    with pytest.raises(suite.SuiteError,match='capture/probe startup failed'):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')
    assert closed==[{'session_name':'owned-kernel'}]


def test_no_probe_created_and_no_pktmon_attempt_closes_only_kernel():
    s=runner();closed=[]
    s._stop_kernel_capture=lambda c:(closed.append(c) or {'files':[]})
    s._vm_json=lambda cmd,timeout:({'startup_failed':True,
        'cooperative_exit':'not-created','physical_terminal':'not-started',
        'cooperative_errors':[]},'wire')
    with pytest.raises(suite.SuiteError,match='capture/probe startup failed'):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')
    assert closed==[{'session_name':'owned-kernel'}]


def test_unknown_response_and_unreadable_snapshot_retains_writer():
    s=runner();calls=[]
    s._stop_kernel_capture=lambda _:pytest.fail('kernel stopped after unknown response')
    s._vm_json=lambda cmd,timeout:(_ for _ in ()).throw(TimeoutError('wire lost'))
    s._capture_start_snapshot=lambda *args:(calls.append('snapshot') or {'snapshot_error':'unreadable'})
    with pytest.raises(suite.UnsettledCaptureStart,match='snapshot'):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')
    assert calls==['snapshot']


def test_first_probe_created_but_not_ready_without_receipt_retains_both_writers():
    s=runner()
    s._stop_kernel_capture=lambda _:pytest.fail('kernel stopped without probe identity')
    s._stop_capture_and_probe=lambda _:pytest.fail('physical capture stopped without probe identity')
    s._vm_json=lambda cmd,timeout:(_ for _ in ()).throw(TimeoutError('ready response lost'))
    s._capture_start_snapshot=lambda *args:{'value':{
        'probe_ready':None,'launch_receipt':None,'process':{'pid':101},
        'etl_exists':True,'pktmon_exit':0,'pktmon_status':'Running'},
        'identity_match':False}
    with pytest.raises(suite.UnsettledCaptureStart,match='kernel session retained'):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')


def test_first_unknown_response_with_exact_ready_recovers_only_owned_writer():
    s=runner();closed=[]
    s._vm_json=lambda cmd,timeout:(_ for _ in ()).throw(TimeoutError('response lost'))
    s._capture_start_snapshot=lambda *args:{'identity_match':True,'value':{
        'probe_ready':{'pid':101,'creation_ticks':123},
        'process':{'pid':101,'creation_ticks':123},
        'etl_exists':True,'pktmon_exit':0,'pktmon_status':'Running'}}
    s._stop_capture_and_probe=lambda c:(closed.append(c) or {'files':[]})
    with pytest.raises(suite.RecoveredCaptureStart):
        s._start_capture_and_probe(r'E:\scope',PROFILE,'nonce','run-01')
    assert len(closed)==1
    assert closed[0]['physical_owner_id']=='nonce:pktmon'
    assert closed[0]['pid']==101 and closed[0]['probe_creation_ticks']==123


def test_second_probe_created_without_ready_recovers_only_exact_receipt():
    s=runner();commands=[];closed=[]
    owner={'run_label':'run-01','etl':r'E:\scope\run-01\pktmon.etl',
           'pktmon_nic':r'E:\scope\run-01\pktmon-nic.json',
           'physical_owner_id':'nonce:pktmon'}
    creation=638000000000000101
    receipt={'pid':101,'creation_ticks':creation,'nonce':'nonce',
             'native_identity':{'supported':True,'run_id':'nonce:run-02',
                                'candidate_id':'candidate'}}
    def vm(cmd,timeout):
        commands.append(cmd)
        if len(commands)==1:raise TimeoutError('ready response lost')
        return {'probe_ready':None,'launch_receipt':receipt,
                'process':{'pid':101,'creation_ticks':creation},
                'etl_exists':True,'pktmon_exit':0,
                'pktmon_status':'数据包监视器正在运行。'},'snapshot wire'
    s._vm_json=vm
    s._stop_capture_and_probe=lambda c:(closed.append(c) or {'files':[]})
    with pytest.raises(suite.RecoveredCaptureStart):
        s._start_probe_on_shared_capture(r'E:\scope',PROFILE,'nonce','run-02',owner)
    assert len(closed)==1 and closed[0]['startup_recovery'] is True
    assert closed[0]['shared_physical'] is True
    assert commands[0].index('probe-launch.json') < commands[0].index('$deadline=')


def test_second_response_mismatch_retains_writer_without_exact_receipt():
    s=runner();owner={'run_label':'run-01','etl':r'E:\scope\run-01\pktmon.etl',
           'pktmon_nic':r'E:\scope\run-01\pktmon-nic.json',
           'physical_owner_id':'nonce:pktmon'}
    s._vm_json=lambda cmd,timeout:({'physical_owner_id':'foreign','etl':owner['etl'],
        'pktmon_nic':owner['pktmon_nic']},'returned wire')
    s._capture_start_snapshot=lambda *args:{'snapshot_error':'no exact identity'}
    s._stop_capture_and_probe=lambda c:pytest.fail('stopped foreign writer')
    with pytest.raises(suite.UnsettledCaptureStart,match='response changed physical owner'):
        s._start_probe_on_shared_capture(r'E:\scope',PROFILE,'nonce','run-02',owner)


def capture():
    return {'pid':101,'probe_creation_ticks':123,'probe':r'E:\scope\run-01\probe.jsonl',
            'stop':r'E:\scope\run-01\probe.stop',
            'etl':r'E:\scope\run-01\pktmon.etl',
            'pktmon_nic':r'E:\scope\run-01\pktmon-nic.json',
            'stdout':r'E:\scope\run-01\probe.stdout',
            'stderr':r'E:\scope\run-01\probe.stderr',
            'kernel_capture':{'session_name':'owned-kernel'},
            'physical_owner_id':'nonce:pktmon','capture_run_id':'nonce:run-01',
            'nonce':'nonce','run_label':'run-01'}


def test_cooperative_timeout_never_sends_physical_stop():
    s=runner();commands=[]
    s._stop_kernel_capture=lambda _:pytest.fail('kernel stopped on probe timeout')
    s._vm_json=lambda cmd,timeout:(commands.append(cmd) or
        ({'coop':{'cooperative_exit':'timeout','errors':[]}},'wire'))
    with pytest.raises(suite.UnsettledCaptureStop,match='probe close uncertain'):
        s._stop_capture_and_probe(capture())
    assert len(commands)==1 and 'pktmon stop' not in commands[0]


def test_physical_stop_unknown_retains_kernel_and_avoids_conversion():
    s=runner();commands=[]
    s._stop_kernel_capture=lambda _:pytest.fail('kernel stopped on physical stop timeout')
    def vm(cmd,timeout):
        commands.append(cmd)
        if len(commands)==1:return {'coop':{'cooperative_exit':'exited','errors':[]}},'coop wire'
        raise TimeoutError('stop response lost')
    s._vm_json=vm
    with pytest.raises(suite.UnsettledCaptureStop,match='stop response unknown'):
        s._stop_capture_and_probe(capture())
    assert len(commands)==2
    assert 'pktmon stop' in commands[1]
    assert all('etl2txt' not in command for command in commands)


def test_conversion_failure_is_after_proven_stop_and_keeps_etl(monkeypatch):
    s=runner();commands=[];kernel=[]
    monkeypatch.setattr(suite.time,'sleep',lambda _:None)
    s._stop_kernel_capture=lambda c:(kernel.append(c) or {'files':[],'raw':'kernel wire'})
    def vm(cmd,timeout):
        commands.append(cmd)
        if len(commands)==1:return {'coop':{'cooperative_exit':'exited','errors':[]}},'coop wire'
        if len(commands)==2:return {'owner_id':'nonce:pktmon','output':'stopped','exit':0,
                                     'status':'Not Running','status_exit':0},'stop wire'
        raise ValueError('conversion failed')
    s._vm_json=vm
    with pytest.raises(suite.SuiteError,match='conversion incomplete'):
        s._stop_capture_and_probe(capture())
    assert len(commands)==3 and 'etl2txt' in commands[2]
    assert sum('pktmon stop' in cmd for cmd in commands)==1
    assert kernel==[{'session_name':'owned-kernel'}]
