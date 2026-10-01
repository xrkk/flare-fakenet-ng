"""Self-contained IPC receipt counterexamples; no live service or network."""
import sys,json
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).parent/'acceptance'))
import formal_instance_gate as gate
import bounded_mcp as bounded
import scenario_suite as suite

@pytest.mark.parametrize('completed',[True,False])
@pytest.mark.parametrize('error_class',[bounded.TransportUnknown,suite.VmCommandError])
def test_unknown_cycle_only_reconciles_receipt_and_never_replays_mutation(tmp_path,completed,error_class):
    sends=[];reads=[]
    def original(enabled):sends.append(enabled);raise error_class('deadline',{'sent':'possibly_sent'})
    phase={'stage':'completed' if completed else 'stop_intent','enabled':True,'answer':{'enabled':True,'state':'Running','backup':'exact'}}
    def read(command,timeout):reads.append((command,timeout));return {'output':json.dumps(phase)}
    runner=SimpleNamespace(guest_work_root=r'E:\work',_ipc_evidence_mode=original,vm=SimpleNamespace(powershell=read),_status=lambda timeout:{'state':'stopped','run_id':None,'controller':None})
    state=gate.install_ipc_guard(runner,tmp_path/'ipc')
    if completed:
        answer=runner._ipc_evidence_mode(True);assert answer['reconciled_original_response_unknown'] and runner._ipc_restore_allowed()
    else:
        with pytest.raises(gate.IpcUnresolved):runner._ipc_evidence_mode(True)
        assert not runner._ipc_restore_allowed()
        with pytest.raises(gate.IpcUnresolved):runner._ipc_evidence_mode(False)
    assert sends==[True] and len(reads)==1 and state['cycles']==1
    assert 'Get-Content' in reads[0][0] and 'Start-Service' not in reads[0][0]

@pytest.mark.parametrize('enabled',[True,False])
def test_standard_cycle_receipt_preserves_one_stop_start_and180_budget(tmp_path,enabled):
    commands=[]
    runner=suite.Suite.__new__(suite.Suite);runner.vm=object();runner.guest_work_root=r'E:\work';runner.ipc_cycle_receipt=r'E:\exact\receipt.json'
    def vm(command,timeout):
        commands.append((command,timeout));return {'state':'Running','environment_restored':True},{}
    runner._vm_json=vm;runner._status=lambda timeout:{'state':'stopped','run_id':None,'controller':None}
    runner._ipc_evidence_mode(enabled)
    cmd,timeout=commands[0];assert timeout==180 and cmd.count('Start-Service fakenetng-mcp')==1 and cmd.count("fakenetng-mcp.exe' stop")==1
    for phase in ['entered','stop_intent','stop_completed','environment_completed','start_intent','start_completed','completed']:assert "Write-IpcPhase '"+phase+"'" in cmd
    assert "Write-IpcPhase 'completed' $answer" in cmd and 'fault-injection.json' not in cmd and 'service.json' not in cmd


def test_readiness_unknown_is_read_only_with_original60_deadline(monkeypatch):
    runner=suite.Suite.__new__(suite.Suite);runner.vm=object();runner.guest_work_root=r'E:\work';calls=[]
    runner._vm_json=lambda command,timeout:({'state':'Running'}, {})
    def status(timeout):
        calls.append(timeout)
        if len(calls)==1:raise bounded.TransportUnknown('not yet ready',{})
        return {'state':'stopped','run_id':None,'controller':None}
    runner._status=status;monkeypatch.setattr(suite.time,'sleep',lambda seconds:None)
    runner._ipc_evidence_mode(True)
    assert len(calls)==2 and 0<calls[1]<=calls[0]<=60
