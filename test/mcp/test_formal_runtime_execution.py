"""Private original assembly is admission-free; public entry needs real proof."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_prepare import prepared, repin
from test_formal_runtime_entry import config_prepared, entry_material, invoke
from formal_runtime.context import load_context, MaterialError
from formal_runtime import execution, runner
from formal_runtime.instance import ProtectedVm, ProtectedService
from formal_runtime.clients import FreshClient


def test_actual_original_assembly_creates_no_rpc_and_grants_no_instance_admission(entry_material,monkeypatch):
    repo,material,_,data,plan = entry_material
    for row in data['suite_argv'].values():
        path = Path(row['path']); value = json.loads(path.read_bytes())
        value['argv'] += ['--guest-work-root', execution.suite.E_GUEST_WORK_ROOT,
                          '--target-base-url','http://127.0.0.1:9/mcp',
                          '--win10vm-mcp','http://127.0.0.1:9/mcp']
        row.update(write_json(path,value))
    data['plan'] = write_json(Path(data['plan']['path']),plan)
    context = load_context(material,write_json(material,data)['sha256'],repository_root=repo)
    def deny(*args,**kwargs):raise AssertionError('construction cannot send an RPC')
    monkeypatch.setattr(FreshClient,'_invoke',deny)
    requested = runner.single_batch_request(context,'benign-00')
    built = execution._assemble(context,requested)
    assert type(built.runner) is execution.suite.Suite
    assert isinstance(built.runner.vm,ProtectedVm) and isinstance(built.runner.service,ProtectedService)
    assert built.runner.vm.client.client is built.vm and built.runner.service.client is built.service
    assert isinstance(built.vm,FreshClient) and isinstance(built.service,FreshClient)
    assert built.vm.calls == built.service.calls == {} and built.state.admission_ready is False
    assert built.runner.physical_namespace == context.physical_namespace
    assert built.runner.manifest_path.read_bytes() == Path(requested.manifest_record['path']).read_bytes()
    assert (context.evidence_root/'execution-binding.json').exists()
    from formal_runtime.sealing import seal
    with pytest.raises(MaterialError,match='native/restoration responsibility'):
        seal(built,{})
    assert not (context.evidence_root/'host-source-index.json').exists()
    with pytest.raises(MaterialError,match='business output exists'):
        execution._assemble(context,requested)


def test_nonprepared_object_cannot_construct_suite_or_clients(materials,monkeypatch):
    def deny(*args,**kwargs):raise AssertionError('a declaration cannot construct a business runtime')
    monkeypatch.setattr(execution.suite.Suite,'__init__',deny)
    with pytest.raises(MaterialError,match='independently bound complete preparation'):
        execution.run_batch(SimpleNamespace(passed=True),'benign-00')


def test_public_batch_entry_rejects_unknown_group_before_preparation_output(entry_material,tmp_path):
    import subprocess,sys
    repo,material,pin,data,_ = entry_material
    command=[sys.executable,'-B',str(repo/'test/mcp/acceptance/run_formal_completion.py'),
             '--materials-json',str(material),'--materials-sha256',pin,
             '--repository-root',str(repo),'run-batch','--batch-id','unknown-group']
    result=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=30)
    (tmp_path/'unknown-batch.stdout').write_text(result.stdout)
    (tmp_path/'unknown-batch.stderr').write_text(result.stderr)
    assert result.returncode == 4 and 'absent from the frozen remaining plan' in result.stdout
    assert not Path(data['evidence_root']).exists() and not Path(data['audit_root']).exists()


def test_public_batch_entry_never_infers_preparation_hash_from_existing_result(entry_material,tmp_path):
    import subprocess,sys
    repo,material,pin,data,_ = entry_material
    command=[sys.executable,'-B',str(repo/'test/mcp/acceptance/run_formal_completion.py'),
             '--materials-json',str(material),'--materials-sha256',pin,
             '--repository-root',str(repo),'run-batch','--batch-id','benign-00',
             '--preparation-json',str(Path(data['audit_root'])/'preparation-result.json')]
    result=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=30)
    (tmp_path/'missing-pin.stdout').write_text(result.stdout)
    (tmp_path/'missing-pin.stderr').write_text(result.stderr)
    assert result.returncode == 2 and 'must be supplied together' in result.stderr
    assert not Path(data['evidence_root']).exists() and not Path(data['audit_root']).exists()
