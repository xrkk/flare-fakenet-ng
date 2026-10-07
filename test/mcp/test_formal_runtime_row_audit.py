"""Actual narrow row gate and original independent refusal; zero formal credit."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared, repin
from test_formal_runtime_entry import config_prepared, entry_material
from test_formal_runtime_batch_audit import declared_batch
from test_formal_runtime_instance import full_preflight_environment
from test_formal_runtime_coordinator import environment
from test_formal_runtime_clients import server, client
from test_formal_runtime_producer import current
from test_formal_runtime_producer_source import pin_source, ExactCaptureClient
from test_formal_runtime_current_source import live
from formal_runtime import row_audit, row_selection, current_source, runner
from formal_runtime.execution import Execution
from formal_runtime.context import MaterialError, load_context


def test_actual_current_capture_query_needs_no_final_export_runtime_record(live):
    context,r,vm,service,_,_=live
    original=context.evidence_root/'execution-context.json'
    original.rename(context.evidence_root/'retained-fixture-runtime.json')
    _,binding=current_source.resolve_current_capture(context,r.vm,service)
    assert binding.values['capture_query_only'] and binding.values['no_business_admission']
    assert 'required_files' not in binding.values and len(binding.values['captures'])==1
    assert vm.responsibility()['host_writers_ended']
    assert not r.vm.state.admission_ready


def test_original_traffic_function_cannot_bypass_independent_row_authority(environment):
    context,r,_,state,caps,co,_,calls,_=environment
    request=runner.single_batch_request(context,'benign-00')
    execution=Execution(context,request,r,state,r.vm.client.client,r.service.client,caps,co)
    row=next(x for x in r.manifest()['scenarios'] if x['scenario_id']==request.scenario_ids[0])
    # Deliberately incomplete stored metadata can pass the ORIGINAL narrow
    # traffic recheck because it claims no healthy runs. No validator is mocked.
    value={'scenario_id':row['scenario_id'],'state':'pass','attempt':1,
           'traffic_evidence':{'nonce':'unverified','runtime_profile':row['config_profile']},'run_chain':[]}
    assert r._traffic_recheck_issues(value,row)==[]
    path=r._result_path(row['scenario_id']);path.parent.mkdir(exist_ok=True);write_json(path,value)
    audits=row_audit.RowAudits(execution);original=r._traffic_recheck_issues
    before=len(calls)
    with audits.installed():
        first=r._traffic_recheck_issues(value,row)
        second=r._traffic_recheck_issues(value,row)
        assert first==second and 'independent original row audit failed' in first[0]
    assert r._traffic_recheck_issues==original and not audits.records
    assert audits.errors and audits.writers_ended and len(calls)==before


@pytest.fixture
def row_batch(entry_material):
    repo,material,pin,data,plan=entry_material
    # Incomplete old metadata also has an indexed attempt, so the independent
    # original verifier, rather than a missing-copy gate, rejects its claims.
    selected=json.loads(Path(data['credited_selection']['path']).read_bytes())
    history=Path(next(iter(selected.values())))
    for sid in selected:
        case=history/'evidence'/sid/'attempt-01';case.mkdir(parents=True)
        (case/'incomplete-original.bin').write_bytes(b'old unverified metadata\n')
    index=Path(data['source_indices'][0]['path'])
    data['source_indices'][0]=write_json(index,{'rows':[dict(record(p),path=p.relative_to(history).as_posix())
        for p in sorted(history.rglob('*')) if p.is_file() and p!=index]})
    pin=write_json(material,data)['sha256']
    return declared_batch.__wrapped__((repo,material,pin,data,plan))


@pytest.fixture
def indexed_row(row_batch,server):
    context,request,_=row_batch;sid=request.scenario_ids[0];root=context.evidence_root
    gate=root/'row-source-gates'/sid;gate.mkdir(parents=True)
    query={'sessions':[{'name':'SST-Kernel-controlled','exit':-2144337918,'query':'Data Collector Set was not found.'}],
           'probe':[],'children':[],'pktmon':'PktMon is not running.'}
    server.vm_boundary=lambda command,timeout:{'output':json.dumps(query),'exit_code':0}
    vm=client(server,context,vm=True)
    raw=vm.powershell('original controlled readonly capture query',3)
    write_json(gate/'source-capture-gate-original.json',raw)
    witnesses=[record(p) for p in vm.root.rglob('completion.json')]
    write_json(gate/'source-closure.json',{'materials_sha256':context.materials_sha256,'scenario_id':sid,
        'capture_query_only':True,'capture_sessions':['SST-Kernel-controlled'],'actual_immutable_witnesses':witnesses})
    original_paths=[root/'execution-binding.json',root/'scenario-manifest.json',root/'results'/('scenario-'+sid+'.json'),
        root/'formal-batches'/request.batch_id/'start.json',*gate.glob('*.json'),*[Path(r['path']) for r in witnesses]]
    original_paths += [p for p in (root/'evidence'/sid/'attempt-01').rglob('*') if p.is_file()]
    path=root/('row-source-index-'+sid+'.json')
    index=write_json(path,{'schema':'fakenetng.formal-runtime.row-source-index.v1','root':str(root),
        'materials_sha256':context.materials_sha256,'batch_id':request.batch_id,'scenario_id':sid,
        'rows':[dict(record(p),path=p.relative_to(root).as_posix()) for p in sorted(set(original_paths))]})
    return context,request,sid,index


def test_row_source_pin_selects_one_closed_attempt_not_the_whole_mutable_batch(indexed_row):
    context,request,sid,index=indexed_row
    child=row_audit.freeze(context,request,sid,index)
    expected=row_selection.selected_prefix(context,request,sid)
    assert row_selection.selection(child)==expected and len(expected)==6
    (context.evidence_root/'later-unrelated-row-file').write_bytes(b'outside indexed immutable attempt')
    assert row_selection.selection(child)==expected
    with pytest.raises(MaterialError,match='no retry'):row_audit.freeze(context,request,sid,index)


def test_cumulative_selection_keeps_old_credits_and_only_closed_ordered_prefix(indexed_row):
    context,request,sid,index=indexed_row
    second=request.scenario_ids[1]
    expected=row_selection.selected_prefix(context,request,second)
    assert set(expected)=={'sst-%03d'%n for n in range(5,10)}|set(request.scenario_ids[:2])
    assert not set(request.scenario_ids[2:]).intersection(expected)
    child=row_audit.freeze(context,request,sid,index)
    selected=Path(child.materials['credited_selection']['path'])
    data=json.loads(child.materials_path.read_bytes())
    data['credited_selection']=write_json(selected,{sid:str(context.evidence_root)})
    changed=load_context(child.materials_path,write_json(child.materials_path,data)['sha256'],repository_root=context.repository_root)
    with pytest.raises(MaterialError,match='original credits'):row_selection.selection(changed)


def test_only_canonical_manifest_is_shared_and_each_producer_stays_checked(indexed_row):
    context,request,sid,index=indexed_row
    child=row_audit.freeze(context,request,sid,index)
    from formal_runtime import audit_view
    m=audit_view.build_view(child,'row-selection')
    assert len(m.selected)==6
    assert sum(Path(key).name=='scenario-manifest.json' for key in m.records)==1
    # The alternate manifest was omitted only from duplicate copying, never
    # from the exact original source-authority checks.
    copied=Path(m.records[str(m.view/'scenario-manifest.json')]['source_root'])
    alternate=next(Path(row['root']) for row in m.selected.values() if Path(row['root'])!=copied)
    (alternate/'scenario-manifest.json').write_bytes(b'changed alternate original')
    with pytest.raises(MaterialError,match='fingerprint mismatch'):m.verify_snapshot()


@pytest.mark.parametrize('change',['writer','capture-active','wrong-sid','source-byte'])
def test_row_binding_refuses_changed_or_unclosed_originals(indexed_row,change):
    context,request,sid,index=indexed_row
    child=row_audit.freeze(context,request,sid,index)
    if change=='source-byte':
        (context.evidence_root/'results'/('scenario-'+sid+'.json')).write_text('changed')
        # Row selection binds lineage; actual source-copy/original verifier
        # checks every selected result, without trusting the pass field.
        from formal_runtime.audit_view import plan_view
        with pytest.raises(MaterialError):plan_view(child,'row-selection')
        return
    elif change=='writer':
        marker=context.evidence_root/'row-source-gates'/sid/'source-closure.json'
        value=json.loads(marker.read_bytes());p=Path(value['actual_immutable_witnesses'][0]['path'])
        d=json.loads(p.read_bytes());d['local_writer_ended']=False;write_json(p,d)
    elif change=='capture-active':
        p=context.evidence_root/'row-source-gates'/sid/'source-capture-gate-original.json'
        d=json.loads(p.read_bytes());q=json.loads(d['output']);q['probe']=[{'pid':999}];d['output']=json.dumps(q);write_json(p,d)
    else:
        data=json.loads(child.materials_path.read_bytes());p=Path(data['plan']['path']);d=json.loads(p.read_bytes())
        d['row_audit']['scenario_id']='sst-005';data['plan']=write_json(p,d)
        child=load_context(child.materials_path,write_json(child.materials_path,data)['sha256'],repository_root=context.repository_root)
    with pytest.raises(MaterialError):row_selection.selection(child)


def test_independent_original_row_verifier_rejects_incomplete_claims(indexed_row,tmp_path):
    context,request,sid,index=indexed_row
    child=row_audit.freeze(context,request,sid,index)
    entry=context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'
    code='import shutil,sys,runpy; from types import SimpleNamespace; shutil.disk_usage=lambda _:SimpleNamespace(free=100*2**30); sys.path.insert(0,sys.argv[1]);sys.argv=sys.argv[2:];runpy.run_path(sys.argv[0],run_name="__main__")'
    args=[str(entry),'--materials-json',str(child.materials_path),'--materials-sha256',child.materials_sha256,
        '--selection-json',child.materials['credited_selection']['path'],'--scope','row-selection','--repository-root',str(context.repository_root)]
    completed=subprocess.run([sys.executable,'-B','-c',code,str(entry.parent),*args],capture_output=True,cwd=context.source_root,text=True,timeout=480)
    (tmp_path/'row.stdout').write_text(completed.stdout);(tmp_path/'row.stderr').write_text(completed.stderr)
    assert completed.returncode!=0
    terminal=json.loads((child.audit_root/'audit-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['verify']['problems']
    assert terminal['adapter_restored'] and terminal['host_audit_writers_ended'] and terminal['VM_calls']==terminal['new_formal_credit']==0
