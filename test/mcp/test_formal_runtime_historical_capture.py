"""Actual indexed legacy identities and bounded read-only guest environment."""
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_prepare import prepared
from test_formal_runtime_entry import config_prepared, entry_material
from test_formal_runtime_export_entry import export_material
from test_formal_runtime_source import historical
from test_formal_runtime_clients import server, client
from formal_runtime.context import load_context, MaterialError
from formal_runtime import historical_capture, source
from formal_runtime.execution import Execution, _assemble
from formal_runtime.instance import ProtectedVm, Responsibility
from formal_runtime.runner import BatchRequest, single_batch_request


@pytest.fixture
def inherited(prepared):
    repo,material,pin,data,plan=prepared
    context,root,_,_,files,freeze=historical.__wrapped__((repo,material,pin,data))
    inherited='SST-Kernel-dead-beef'
    files['final-capture-baseline-original.json']={'output':json.dumps({'sessions':[
        {'name':inherited,'exit':-2144337918,'query':'Data Collector Set was not found.'}],
        'pktmon':'PktMon is not running.'})}
    write_json(root/'final-capture-baseline-original.json',files['final-capture-baseline-original.json'])
    files['fault-spike-result.json']={'schema':'sst.fault-spike.v1'}
    data['spike_source']=write_json(root/'fault-spike-result.json',files['fault-spike-result.json'])
    data['credited_selection']=write_json(Path(data['credited_selection']['path']),{'sst-005':str(root)})
    context=freeze()
    return context,root,files,freeze,inherited


def test_historical_baseline_uses_actual_owned_and_indexed_inherited_names(inherited):
    context,root,_,_,inherited_name=inherited
    names,witnesses=historical_capture.sessions(context)
    assert set(names)=={'SST-Kernel-abc-1','SST-Kernel-abc-2',inherited_name}
    assert any(Path(row['path']).name=='final-capture-baseline-original.json' for row in witnesses)
    assert any(Path(row['path']).name=='full-SHA-index.json' for row in witnesses)


def test_changed_original_baseline_is_rejected_before_guest_query(inherited):
    context,root,_,_,_=inherited
    (root/'final-capture-baseline-original.json').write_text('{}')
    with pytest.raises(MaterialError,match='fingerprint mismatch'):historical_capture.sessions(context)


@pytest.mark.parametrize('active',['closed','etw','pktmon','namespace'])
def test_actual_fresh_query_keeps_inherited_capture_and_unused_namespace_gate(inherited,server,active):
    context,_,_,_,_=inherited
    names,_=historical_capture.sessions(context)
    def boundary(command,timeout):
        if 'Test-Path -LiteralPath' in command:return {'output':json.dumps({'exists':active=='namespace'}),'exit_code':0}
        queried=re.findall(r"'(SST-Kernel-[a-f0-9-]+)'",command)
        assert sorted(queried)==names
        value={'sessions':[{'name':name,'exit':0 if active=='etw' else -2144337918,
                           'query':'running' if active=='etw' else 'Data Collector Set was not found.'} for name in queried],
               'pktmon':'PktMon is running.' if active=='pktmon' else 'PktMon is not running.'}
        return {'output':json.dumps(value),'exit_code':0}
    server.vm_boundary=boundary
    state=Responsibility();vm=client(server,context,vm=True,state=state);service=client(server,context,state=state)
    protected=ProtectedVm(vm,context,state)
    request=BatchRequest(context,'benign-00','benign',('sst-010',),{}, {}, {})
    runner=SimpleNamespace(root=context.evidence_root,vm=protected)
    execution=Execution(context,request,runner,state,vm,service,None,None)
    if active=='closed':
        result=historical_capture.gate(execution,'initial',unused_namespace=True)
        assert json.loads(Path(result['path']).read_bytes())['sessions']==names
    else:
        with pytest.raises(MaterialError,match='active or unknown|namespace exists'):
            historical_capture.gate(execution,'initial',unused_namespace=True)
    calls=[r['body']['params']['arguments']['command'] for r in server.received if r['body']['method']=='tools/call']
    assert len(calls)==(2 if active in ('closed','namespace') else 1)
    assert all('logman start' not in c and 'logman stop' not in c and 'Start-Service' not in c for c in calls)
    assert vm.responsibility()['host_writers_ended'] and not state.admission_ready


@pytest.mark.parametrize('failure',['closed','config','identity','post-export-instance'])
def test_original_native_scene_and_service_config_bytes_are_bound(export_material,failure):
    context,_,_,scene,_,_=export_material
    scene['config_sha']='f'*64
    data=json.loads(context.materials_path.read_bytes())
    import scenario_suite as suite
    for row in data['suite_argv'].values():
        value=json.loads(Path(row['path']).read_bytes())
        value['argv']+=['--guest-work-root',suite.E_GUEST_WORK_ROOT]
        row.update(write_json(Path(row['path']),value))
    context=load_context(context.materials_path,write_json(context.materials_path,data)['sha256'],repository_root=context.repository_root)
    execution=_assemble(context,single_batch_request(context,'benign-00'))
    initial=historical_capture.native_gate(execution,'initial')
    scene['pid']+=1  # A legitimate later SCM instance may differ initially.
    if failure=='config':scene['config_sha']='e'*64
    elif failure=='identity':scene['uuid']='other-vm'
    if failure in ('config','identity'):
        with pytest.raises((MaterialError,AssertionError)):
            historical_capture.native_gate(execution,'final',initial=initial)
    else:
        final=historical_capture.native_gate(execution,'final',initial=initial)
        identity=json.loads(Path(final['path']).read_bytes())['identity']
        if failure=='post-export-instance':scene['pid']+=1
        if failure=='closed':
            historical_capture.native_gate(execution,'post-export',initial=initial,expected_identity=identity)
        else:
            with pytest.raises(MaterialError,match='instance changed'):
                historical_capture.native_gate(execution,'post-export',initial=initial,expected_identity=identity)
    assert not execution.state.admission_ready and not execution.coordinator.admitted
    assert execution.vm.responsibility()['host_writers_ended']
