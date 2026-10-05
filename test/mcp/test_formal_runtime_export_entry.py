"""Actual readonly CLI/Fresh HTTP/Suite export with controlled environment bytes."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared, repin
from test_formal_runtime_entry import config_prepared, entry_material
from test_formal_runtime_source import historical
from test_formal_runtime_source_export import SourceClient, RID
from test_formal_runtime_clients import server
from formal_runtime import source, export_entry


@pytest.fixture
def export_material(entry_material,historical,server):
    context,root,_,_,files,freeze_index = historical
    data = entry_material[3]
    endpoint = 'http://127.0.0.1:%d/mcp'%server.server_port
    for row in data['suite_argv'].values():
        path = Path(row['path']); value = json.loads(path.read_bytes())
        value['argv'] += ['--target-base-url',endpoint,'--win10vm-mcp',endpoint]
        row.update(write_json(path,value))
    files['results/scenario-sst-010.json'] = {'run_chain':[{'run_id':RID}]}
    (root/'results').mkdir(); write_json(root/'results/scenario-sst-010.json',files['results/scenario-sst-010.json'])
    context = freeze_index()
    binding = source.resolve_source(context,root)
    environment = SourceClient(binding)
    package = json.loads(Path(entry_material[4]['candidate_files']['manifest']['path']).read_bytes())
    scene = {'computer':'DESKTOP-3FI41GR','uuid':'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49',
        'mac':['00-0C-29-C1-CA-49'],'source':context.candidate_identity['source'],
        'manifest_sha':context.candidate_identity['manifest_sha256'],'service':'Running',
        'pid':2716,'filetime':'134353511031206360','members':copy.deepcopy(package['files']),
        'marker':{'needs_recovery':False},'workers':[],'fault':False,'fault_gate':False,
        'grace':60,'env_present':False,'env':[],'space':[{'Name':'C','Free':5*2**30},{'Name':'E','Free':12*2**30}]}
    observed = {'scene_calls':0,'drift':False}
    def boundary(command,timeout):
        if command == export_entry.SCENE:
            observed['scene_calls'] += 1
            answer = copy.deepcopy(scene)
            if observed['drift'] and observed['scene_calls'] > 1: answer['pid'] += 1
            return {'output':json.dumps(answer),'exit_code':0}
        return environment.powershell(command,timeout)
    server.vm_boundary = boundary
    class StatusEnvironment:
        controller_id = ''
        def tool_outcome(self,name,args):
            assert name == 'get_status'
            return {'ok':True,'error':None,'value':{'state':'stopped','controller':None,'run_id':None,
                'config_identity':{'sha256':context.candidate_identity['default_sha256']}}}
    server.store = StatusEnvironment()
    return context,root,environment,scene,observed,server


def invoke(export_material,tmp_path, *, free_gib=50, injected=''):
    context,root,_,_,_,_ = export_material
    entry = context.source_root/'test/mcp/acceptance/run_formal_completion.py'
    arguments=[str(entry),'--materials-json',str(context.materials_path),'--materials-sha256',context.materials_sha256,
               '--repository-root',str(context.repository_root),'export-source','--source-root',str(root)]
    script='import shutil,runpy,sys; from types import SimpleNamespace; shutil.disk_usage=lambda _:SimpleNamespace(free='+str(free_gib)+'*2**30); sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:];'+injected+'runpy.run_path(sys.argv[0],run_name="__main__")'
    result=subprocess.run([sys.executable,'-B','-c',script,str(entry.parent),*arguments],
                          cwd=context.source_root,capture_output=True,text=True,timeout=60)
    (tmp_path/'entry.stdout').write_text(result.stdout); (tmp_path/'entry.stderr').write_text(result.stderr)
    return result


def test_actual_public_readonly_export_closes_original_transports_and_preserves_all_SHA(export_material,tmp_path):
    context,root,boundary,_,observed,server=export_material
    result=invoke(export_material,tmp_path)
    assert result.returncode==0, result.stdout+result.stderr
    output=context.evidence_root/'source-originals'
    rows=json.loads((output/'guest-original-index.json').read_bytes())
    assert {row['guest']['path'] for row in rows}==set(boundary.bytes)
    assert all(Path(row['host_path']).read_bytes()==boundary.bytes[row['guest']['path']] for row in rows)
    terminal=json.loads((context.evidence_root/'source-export-entry-terminal.json').read_bytes())
    assert terminal['passed'] and terminal['host_writers_ended'] and terminal['guest_mutations']==terminal['new_formal_credit']==0
    assert observed['scene_calls']==2 and terminal['source_namespace']==boundary.binding.physical_namespace
    assert terminal['source_namespace']!=context.physical_namespace
    assert not (context.evidence_root/'execution-binding.json').exists()
    assert {call['body']['params']['name'] for call in server.received if call['body']['method']=='tools/call'}=={'get_status','PowerShell'}


def test_public_export_capacity_refuses_all_RPC_and_output_before_source_reads(export_material,tmp_path):
    context,_,_,_,_,server=export_material
    result=invoke(export_material,tmp_path,free_gib=23)
    assert result.returncode==4 and 'host/tmp capacity insufficient' in result.stdout
    assert not server.received and not context.evidence_root.exists()


@pytest.mark.parametrize('failure',['identity','active-capture','native-drift','unknown-transfer'])
def test_public_export_keeps_original_failure_partial_and_no_retry(export_material,tmp_path,failure):
    context,_,boundary,scene,observed,server=export_material
    if failure=='identity':scene['uuid']='wrong-vm'
    elif failure=='active-capture':boundary.failure='writer'
    elif failure=='native-drift':observed['drift']=True
    else:boundary.failure='unknown'
    result=invoke(export_material,tmp_path)
    assert result.returncode!=0
    terminal=json.loads((context.evidence_root/'source-export-entry-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['original_error']
    assert terminal['guest_mutations']==terminal['new_formal_credit']==0
    assert not (context.evidence_root/'source-originals/guest-original-index.json').exists()
    if failure=='unknown-transfer':assert sum('OpenRead(' in command for command,_ in boundary.calls)==1
    if failure=='native-drift':assert list((context.evidence_root/'source-originals/guest-originals').rglob('*'))
    count=len(server.received)
    again=invoke(export_material,tmp_path)
    assert again.returncode!=0 and 'unused output' in again.stdout and len(server.received)==count


def test_received_status_with_local_audit_failure_withholds_export_index(export_material,tmp_path):
    context,_,boundary,_,_,_=export_material
    fault='''from pathlib import Path
original_open=Path.open
def storage_boundary(path,*args,**kwargs):
    mode=args[0] if args else kwargs.get('mode','r')
    if path.name=='call-terminal.json' and '/transport/service/' in str(path) and mode=='x' and Path('''+repr(str(context.evidence_root/'source-originals/source-post-inventory-value.json'))+''').exists():
        raise OSError('controlled final received-status audit storage failure')
    return original_open(path,*args,**kwargs)
Path.open=storage_boundary
'''
    result=invoke(export_material,tmp_path,injected='exec('+repr(fault)+');')
    assert result.returncode!=0 and 'closure unresolved' in result.stdout
    output=context.evidence_root/'source-originals'
    assert (output/'source-post-inventory-value.json').is_file()
    assert list((output/'guest-originals').rglob('*'))
    assert not (output/'guest-original-index.json').exists()
    terminal=json.loads((context.evidence_root/'source-export-entry-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['closure_error'] and terminal['host_writers_ended']
    assert not terminal['transport_audit_safe'] and not terminal['transport_closure_resolved']
    # Real original response bytes survive local audit failure; no product
    # mutation or lost-response claim is substituted for the storage failure.
    replies=list((context.evidence_root/'transport/service').rglob('response.json'))
    assert any(b'config_identity' in path.read_bytes() for path in replies)
