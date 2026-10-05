"""Runtime source maps qualify scripts as bytes without importing or running."""
import json
from pathlib import Path
import shutil

import pytest

from test_formal_runtime_context import materials, git, record, write_json
from formal_runtime.context import load_context, MaterialError
from formal_runtime import runtime_sources, audit_entry
from formal_runtime.source_graph import source_closure


@pytest.fixture
def qualified(materials):
    repo,material,_,data=materials
    real=Path(__file__).resolve().parents[2]
    entry=real/'test/mcp/acceptance/run_formal_source_audit.py'
    wanted=runtime_sources.expected_sources(real,entry)
    for path in wanted:
        target=repo/path.relative_to(real);target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,target)
    git(repo,'add','test/mcp','fakenet','fnpr_sentinel.py')
    git(repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
        '-c','commit.gpgsign=false','commit','-qm','immutable candidate helpers and tool data')
    candidate=git(repo,'rev-parse','HEAD')
    marker=repo/'test/mcp/acceptance/qualification-generation.txt';marker.write_text('different tool snapshot\n')
    git(repo,'add','test/mcp/acceptance/qualification-generation.txt')
    git(repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
        '-c','commit.gpgsign=false','commit','-qm','separate host tool snapshot')
    data['candidate_identity']['source']=candidate
    data['tool_source']={'commit':git(repo,'rev-parse','HEAD'),
        'files':[record(repo/p.relative_to(real)) for p in sorted(wanted) if p.is_relative_to(real/'test/mcp')]}
    plan_path=Path(data['plan']['path']);plan=json.loads(plan_path.read_bytes())
    plan['identity']=data['candidate_identity']
    plan['additional_tool_files']=[record(repo/'fnpr_sentinel.py')]
    for row in data['suite_argv'].values():
        path=Path(row['path']);argv=json.loads(path.read_bytes())
        argv['argv'][argv['argv'].index('--source-commit')+1]=candidate
        row.update(write_json(path,argv))

    def pin():
        data['plan']=write_json(plan_path,plan)
        return load_context(material,write_json(material,data)['sha256'],repository_root=repo)
    return pin(),repo/'test/mcp/acceptance/run_formal_source_audit.py',wanted,data,plan,pin


def test_complete_runtime_map_keeps_root_subprocess_and_dynamic_scripts_pinned_as_data(qualified,monkeypatch):
    context,entry,wanted,_,_,_=qualified
    def deny(*args,**kwargs):raise AssertionError('no import or business process during map qualification')
    monkeypatch.setattr(runtime_sources,'loaded_sources',deny)
    rows=runtime_sources.qualify(context,entry)
    mapped={Path(row['path']):row for row in rows}
    assert len(rows)==len(wanted)
    for name in runtime_sources.DYNAMIC:
        assert entry.parent/name in mapped
    root=mapped[context.source_root/'fnpr_sentinel.py']
    assert root['commit']==context.tool_source['commit'] and root['kind']=='tool'
    product=mapped[context.source_root/'fakenet/mcp/faultinject.py']
    assert product['commit']==context.candidate_identity['source'] != root['commit']
    assert product['kind']=='product-helper'
    assert not context.evidence_root.exists() and not context.audit_root.exists()
    # Graph reading never imported FNPR or the Windows staged programs.
    assert 'fnpr_sentinel' not in runtime_sources.sys.modules


@pytest.mark.parametrize('change,reason',[
    ('missing-root-record','root-tool file records'),('wrong-root-record','exact FNPR'),
    ('malformed-root-record','file objects'),
    ('missing-dynamic','dependency not pinned'),('root-worktree','immutable tool'),
    ('candidate-helper','immutable candidate')])
def test_source_map_refuses_even_internally_rehashed_wrong_or_unpinned_code(qualified,change,reason):
    context,entry,_,data,plan,pin=qualified
    if change=='missing-root-record':plan.pop('additional_tool_files')
    elif change=='wrong-root-record':plan['additional_tool_files']=[record(entry)]
    elif change=='malformed-root-record':plan['additional_tool_files']=[True]
    elif change=='missing-dynamic':
        data['tool_source']['files']=[row for row in data['tool_source']['files']
                                    if Path(row['path']).name!='scenario_probes.ps1']
    elif change=='root-worktree':
        path=context.source_root/'fnpr_sentinel.py';path.write_text(path.read_text()+'\n# changed\n')
        plan['additional_tool_files']=[record(path)]
    else:
        path=context.source_root/'fakenet/mcp/faultinject.py';path.write_text(path.read_text()+'\n# changed\n')
    context=pin()
    with pytest.raises(MaterialError,match=reason):runtime_sources.qualify(context,entry)


def test_generic_graph_missing_explicit_dynamic_file_refused_without_import(qualified):
    context,entry,*_=qualified
    with pytest.raises(MaterialError,match='entry dependency missing'):
        source_closure(context.source_root,entry,dynamic=('missing-runtime-script.py',))


def test_original_audit_dynamic_set_remains_narrow_and_excludes_business_sentinel(qualified):
    context,entry,*_=qualified
    paths=audit_entry.source_closure(context.source_root,entry)
    assert context.source_root/'fnpr_sentinel.py' not in paths
    assert all(entry.parent/name in paths for name in audit_entry.AUDIT_DYNAMIC)
    assert entry.parent/'formal_runtime/source_graph.py' in paths


def test_actual_wrong_module_location_cannot_be_qualified_by_only_a_declared_map(qualified):
    context,entry,*_=qualified
    rows=runtime_sources.qualify(context,entry)
    # Test imports come from the real repository; claiming a copied fixture
    # source root cannot qualify those actual module locations.
    with pytest.raises(MaterialError,match='runtime loaded code from Logs|outside qualified source'):
        runtime_sources.loaded_sources(context,rows)
