"""Held probes inherit the original restart deadline; receipts cannot release another owner."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as s


def fixture():
    r=s.Suite.__new__(s.Suite);r.vm=object();commands=[]
    c={'pid':7140,'probe_creation_ticks':639264780363763372,'nonce':'attempt-nonce',
       'capture_run_id':'attempt-nonce:run-02','stop':r'E:\owned\run-02\probe.stop'}
    profile={'bucket':'B4','interleave':'before-start'}
    contract='engine-wait-v1|attempt-nonce|attempt-nonce:run-02|7140|639264780363763372|old-run|command|100|960100|1000'
    def execute(command, timeout):
        commands.append((command,timeout))
        if 'engine gate collision' in command:
            return {'path':r'E:\owned\run-02\probe.engine-wait','contract':contract,'began':100,
                    'deadline':960100,'frequency':1000,'budget_seconds':960,'command_id':'command','old_run_id':'old-run'}, {'original':True}
        return {'path':r'E:\owned\run-02\probe.engine-ok','written_qpc':180100},{'original':True}
    r._vm_json=execute
    return r,c,profile,commands


def test_preparation_uses_existing_restart_rpc_budget_and_bound_launcher():
    r,c,p,commands=fixture();gate=r._prepare_restart_engine(c,p,'old-run','command')
    assert gate['budget_seconds']==s.lifecycle_rpc_timeout('restart')==960
    assert c['engine_gate'] is gate
    command,budget=commands[0]
    assert budget==60 and '[Diagnostics.Stopwatch]::GetTimestamp()' in command
    assert '960*$frequency' in command and '639264780363763372' in command
    assert 'healthy' not in command and 'probe.engine-ok' not in command
    with pytest.raises(s.SuiteError,match='already prepared'):r._prepare_restart_engine(c,p,'old-run','command')


@pytest.mark.parametrize('field,value',[('state','failed'),('state','starting'),('command_id','wrong'),
 ('bound_run_id','wrong'),('run_id','old-run'),('run_id',None)])
def test_wrong_or_unhealthy_restart_cannot_emit_signal(field,value):
    r,c,p,commands=fixture();r._prepare_restart_engine(c,p,'old-run','command');commands.clear()
    receipt={'state':'healthy','command_id':'command','bound_run_id':'old-run','run_id':'new-run'}
    receipt[field]=value
    with pytest.raises(s.SuiteError,match='bound healthy'):r._signal_engine_ok(c,receipt)
    assert commands==[]


def test_healthy_receipt_emits_identity_bound_atomic_signal_not_plain_ok():
    r,c,p,commands=fixture();r._prepare_restart_engine(c,p,'old-run','command');commands.clear()
    r._signal_engine_ok(c,{'state':'healthy','command_id':'command','bound_run_id':'old-run','run_id':'new-run'})
    command,budget=commands[0]
    assert budget==60 and '|old-run|command|100|960100|1000|healthy|new-run' in command
    assert "$now -ge 960100" in command and 'engine gate cancelled' in command
    assert 'Move-Item -LiteralPath' in command


@pytest.mark.parametrize('bucket,interleave',[('B1','before-start'),('B4','stop-window'),('B2','restart-window')])
def test_unheld_and_approved_refusal_paths_do_not_receive_engine_gate(bucket,interleave):
    r,c,_,commands=fixture()
    assert r._prepare_restart_engine(c,{'bucket':bucket,'interleave':interleave},'old-run','command') is None
    assert commands==[] and 'engine_gate' not in c
