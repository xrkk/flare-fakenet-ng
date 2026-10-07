"""Separate CLI invokes original failed verdicts; no proof PASS replacement."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from test_formal_runtime_context import materials, write_json, record, git
from test_formal_runtime_prepare import prepared
from test_formal_runtime_audit import authority
from test_formal_runtime_audit_view import copy_context
from formal_runtime.audit_entry import source_closure

ACTUAL_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def cli(copy_context):
    root = copy_context.repository_root
    source_paths = source_closure(ACTUAL_ROOT,ACTUAL_ROOT/'test/mcp/acceptance/run_formal_source_audit.py')
    for path in source_paths:
        target = root/path.relative_to(ACTUAL_ROOT)
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target)
    git(root,'add','test/mcp','fakenet')
    git(root,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
        '-c','commit.gpgsign=false','commit','-qm','independent actual source snapshot')
    commit = git(root,'rev-parse','HEAD')
    data = json.loads(copy_context.materials_path.read_bytes())
    data['tool_source']={'commit':commit,'files':[record(root/p.relative_to(ACTUAL_ROOT))
        for p in sorted(source_paths) if p.is_relative_to(ACTUAL_ROOT/'test/mcp')]}
    data['candidate_identity']['source']=commit
    planpath=Path(data['plan']['path']); plan=json.loads(planpath.read_bytes())
    plan['identity']=data['candidate_identity']; data['plan']=write_json(planpath,plan)
    for row in data['suite_argv'].values():
        path=Path(row['path']); value=json.loads(path.read_bytes())
        value['argv'][value['argv'].index('--source-commit')+1]=commit
        row.update(write_json(path,value))
    history=Path(next(iter(json.loads(Path(data['credited_selection']['path']).read_bytes()).values())))
    for path in (history/'results').glob('*.json'):
        value=json.loads(path.read_bytes());value['identity']['source_commit']=commit;write_json(path,value)
    spike=Path(data['spike_source']['path']);value=json.loads(spike.read_bytes());value['identity']['source_commit']=commit
    data['spike_source']=write_json(spike,value)
    index=Path(data['source_indices'][0]['path']);sealed=json.loads(index.read_bytes())
    for row in sealed['rows']:
        row.update({k:v for k,v in record(history/row['path']).items() if k!='path'})
    data['source_indices']=[write_json(index,sealed)]
    pin=write_json(copy_context.materials_path,data)['sha256']
    command=[sys.executable,'-B',str(root/'test/mcp/acceptance/run_formal_source_audit.py'),
             '--materials-json',str(copy_context.materials_path),'--materials-sha256',pin,
             '--selection-json',data['credited_selection']['path']]
    return root,copy_context.materials_path,data,command


def run_boundary(cli,monkeypatch,tmp_path):
    # The child patches only disk measurement. All entry/source/byte-copy and
    # original Suite/Spike/derive functions execute from the pinned snapshot.
    root,material,data,command=cli
    launcher=tmp_path/'capacity-boundary.py'
    launcher.write_text('import runpy,shutil,sys\nfrom types import SimpleNamespace\n'
        'shutil.disk_usage=lambda _:SimpleNamespace(free=100*2**30)\n'
        'script=sys.argv.pop(1)\nsys.path.insert(0,__import__("os").path.dirname(script))\n'
        'runpy.run_path(script,run_name="__main__")\n')
    argv=[command[0],'-B',str(launcher),*command[2:]]
    result=subprocess.run(argv,cwd=root,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240)
    (tmp_path/'child-stdout.log').write_text(result.stdout)
    (tmp_path/'child-stderr.log').write_text(result.stderr)
    write_json(tmp_path/'child-command-and-exit.json',{'argv':argv,'returncode':result.returncode,
                                                       'child_writer_ended':True,'VM_calls':0})
    return result


def test_real_separate_entry_keeps_original_verifier_failure_and_no_credit(cli,monkeypatch,tmp_path):
    result=run_boundary(cli,monkeypatch,tmp_path)
    root,_,data,_=cli
    output=Path(data['audit_root'])
    assert result.returncode in (3,4),result.stderr
    assert output.exists(),result.stderr
    terminal=json.loads((output/'audit-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['VM_calls']==terminal['new_formal_credit']==0
    assert terminal['adapter_restored'] and terminal['host_audit_writers_ended']
    assert terminal['source_qualification'] and terminal['initial_modules']
    assert 'original verify' in terminal['error'] or 'KeyError' in terminal['error']
    assert not (output/'audit-result.json').exists()
    assert (output/'source-copy-complete.json').exists()


def test_separate_entry_rejects_missing_static_tool_before_output(cli,monkeypatch,tmp_path):
    _,material,data,command=cli
    data['tool_source']['files']=[row for row in data['tool_source']['files']
                                if not row['path'].replace('\\', '/').endswith('/scenario_pktmon.py')]
    command[command.index('--materials-sha256')+1]=write_json(material,data)['sha256']
    result=run_boundary(cli,monkeypatch,tmp_path)
    assert result.returncode==4 and 'unpinned tool dependencies' in result.stderr
    assert not Path(data['audit_root']).exists()


def test_separate_entry_material_self_tamper_cannot_change_independent_pin(cli,monkeypatch,tmp_path):
    _,material,data,_=cli
    data['candidate_identity']['candidate']='forged';write_json(material,data)
    result=run_boundary(cli,monkeypatch,tmp_path)
    assert result.returncode==4 and 'independent materials SHA256 mismatch' in result.stderr
    assert not Path(data['audit_root']).exists()


def test_separate_entry_original_product_helper_must_match_candidate_git_source(cli,monkeypatch,tmp_path):
    root,_,data,_=cli
    baseline=root/'fakenet/mcp/baseline.py'
    baseline.write_bytes(baseline.read_bytes()+b'\n# changed original helper\n')
    result=run_boundary(cli,monkeypatch,tmp_path)
    assert result.returncode==4 and 'product helper differs from candidate source' in result.stderr
    assert not Path(data['audit_root']).exists()


def test_separate_original_Spike_gate_rejects_incomplete_original_case_set(cli,monkeypatch,tmp_path):
    root,material,data,command=cli
    report_path=Path(data['spike_source']['path']);history=report_path.parent
    result_path=history/'results/scenario-sst-005.json'
    report={'schema':'sst.fault-spike.v1','identity':json.loads(result_path.read_bytes())['identity'],
            'passed':True,'synthetic':False,'five_classes':['policy_pause','listener_stop','diverter_stop','child_hang','cleanup_error'],
            'manifest':dict(record(history/'scenario-manifest.json'),path='scenario-manifest.json'),
            'cases':[{'scenario_id':'sst-005','fault_class':'policy_pause',
                      'result':dict(record(result_path),path='results/scenario-sst-005.json')}]}
    data['spike_source']=write_json(report_path,report)
    index=Path(data['source_indices'][0]['path']);sealed=json.loads(index.read_bytes())
    for row in sealed['rows']:
        if row['path']=='fault-spike-result.json': row.update({k:v for k,v in record(report_path).items() if k!='path'})
    data['source_indices']=[write_json(index,sealed)]
    command[command.index('--materials-sha256')+1]=write_json(material,data)['sha256']
    command.extend(['--scope','spike-only'])
    result=run_boundary(cli,monkeypatch,tmp_path)
    assert result.returncode==3,result.stderr
    assert 'exactly one case per fault class' in result.stderr
    terminal=json.loads((Path(data['audit_root'])/'audit-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['adapter_restored'] and terminal['host_audit_writers_ended']


def test_separate_entry_help_and_import_do_not_load_audit_or_write_outputs(tmp_path):
    script=ACTUAL_ROOT/'test/mcp/acceptance/run_formal_source_audit.py'
    result=subprocess.run([sys.executable,'-B',str(script),'--help'],cwd=tmp_path,text=True,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    assert result.returncode==0 and '--selection-json' in result.stdout
    code='import runpy,sys;runpy.run_path(sys.argv[1],run_name="import_only");assert "formal_runtime.audit" not in sys.modules'
    result=subprocess.run([sys.executable,'-B','-c',code,str(script)],cwd=tmp_path,text=True,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    assert result.returncode==0,result.stderr
    assert not list(tmp_path.iterdir())
