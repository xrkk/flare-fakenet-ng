"""Actual original full Spike refusal and owned isolated invocation."""
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared
from test_formal_runtime_entry import config_prepared, entry_material, reseal_history
from formal_runtime.context import load_context, MaterialError
from formal_runtime import spike_gate
import scenario_suite as suite


@pytest.fixture
def five_unverified(entry_material):
    repo,material,_,data,plan=entry_material
    report_path=Path(data['spike_source']['path']);history=report_path.parent
    identity=json.loads((history/'results/scenario-sst-005.json').read_bytes())['identity']
    cases=[]
    for n,fault in zip(range(5,10),suite.FAULTS):
        sid='sst-%03d'%n
        attempt=history/'evidence'/sid/'attempt-01';attempt.mkdir(parents=True)
        (attempt/'incomplete-original.bin').write_bytes(b'no full Spike proof\n')
        result=history/'results'/('scenario-'+sid+'.json')
        cases.append({'scenario_id':sid,'fault_class':fault,'result':dict(record(result),path='results/'+result.name)})
    data['spike_source']=write_json(report_path,{'schema':'sst.fault-spike.v1','identity':identity,
        'passed':True,'synthetic':False,'five_classes':list(suite.FAULTS),
        'manifest':dict(record(history/'scenario-manifest.json'),path='scenario-manifest.json'),'cases':cases})
    # Every copy is actual indexed metadata, without claiming original PASS.
    index=Path(data['source_indices'][0]['path'])
    data['source_indices'][0]=write_json(index,{'rows':[dict(record(p),path=p.relative_to(history).as_posix())
        for p in sorted(history.rglob('*')) if p.is_file() and p!=index]})
    context=load_context(material,write_json(material,data)['sha256'],repository_root=repo)
    return context


def test_runtime_spike_frozen_parent_preserves_exact_contract_and_no_retry(five_unverified):
    context=five_unverified
    child,selected=spike_gate.freeze(context,1)
    assert spike_gate.selection(child)==spike_gate.original_selection(context)
    assert child.materials_sha256!=context.materials_sha256
    assert not child.audit_root.exists() and not child.evidence_root.exists()
    assert read(selected)==spike_gate.selection(child)
    with pytest.raises(MaterialError,match='no retry'):spike_gate.freeze(context,1)


def read(record):return json.loads(Path(record['path']).read_bytes())


@pytest.mark.parametrize('change',['parent-pin','resource','plan','argv','source-index','ordinal'])
def test_child_self_rehash_cannot_change_runtime_spike_parent(five_unverified,change):
    context=five_unverified;child,_=spike_gate.freeze(context,1)
    data=json.loads(child.materials_path.read_bytes());plan=read(data['plan'])
    if change=='parent-pin':plan['runtime_spike_audit']['main_materials']['sha256']='0'*64
    elif change=='resource':data['resource_plan']['per_scenario_audit_copy_bytes']+=1
    elif change=='plan':plan['cycles_bound']=69
    elif change=='argv':
        for row in data['suite_argv'].values():
            value=read(row);value['argv']+=['--seed','1'];row.update(write_json(Path(row['path']),value))
    elif change=='source-index':data['source_indices']=[]
    else:plan['runtime_spike_audit']['ordinal']=True
    data['plan']=write_json(Path(data['plan']['path']),plan)
    with pytest.raises(MaterialError):
        changed=load_context(child.materials_path,write_json(child.materials_path,data)['sha256'],repository_root=context.repository_root)
        spike_gate.selection(changed)


def test_actual_full_original_spike_gate_rejects_unverified_five_case_claim(five_unverified,tmp_path):
    context=five_unverified;child,selected=spike_gate.freeze(context,1)
    entry=context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'
    code='import runpy,shutil,sys;from types import SimpleNamespace;shutil.disk_usage=lambda _:SimpleNamespace(free=100*2**30);sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")'
    command=[sys.executable,'-B','-c',code,str(entry.parent),str(entry),'--materials-json',str(child.materials_path),
        '--materials-sha256',child.materials_sha256,'--selection-json',selected['path'],'--scope','spike-only',
        '--repository-root',str(context.repository_root)]
    result=subprocess.run(command,cwd=context.source_root,capture_output=True,text=True,timeout=480)
    (tmp_path/'stdout').write_text(result.stdout);(tmp_path/'stderr').write_text(result.stderr)
    assert result.returncode!=0 and 'Spike case/scenario/candidate mismatch' in result.stderr
    terminal=json.loads((child.audit_root/'audit-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['adapter_restored'] and terminal['host_audit_writers_ended']
    assert terminal['VM_calls']==terminal['new_formal_credit']==0


def test_business_seam_waits_its_actual_owned_process_and_restores_on_failure(five_unverified):
    context=five_unverified
    def inline():raise AssertionError('business must not run inline original Spike rejudge')
    runner=SimpleNamespace(root=context.evidence_root,_require_fault_spike=inline)
    gate=spike_gate.SpikeAudits(context,runner)
    with gate.installed():
        with pytest.raises(MaterialError,match='runtime Spike audit failed'):runner._require_fault_spike()
    assert runner._require_fault_spike is inline and gate.writers_ended and not gate.records
    assert len(gate.processes)==1 and gate.processes[0].poll() is not None
    output=context.audit_root/'runtime-spike-processes/0001'
    assert read(record(output/'completion.json'))['audit_process_waited']
    terminal=read(record(output/'terminal.json'))
    assert not terminal['passed'] and terminal['audit_writer_ended'] and terminal['VM_calls']==0
