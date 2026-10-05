"""Explicit original one-batch selection grants no execution or preparation."""
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_prepare import prepared, repin
from formal_runtime.context import load_context, MaterialError
from formal_runtime import runner


def context(prepared):
    return load_context(prepared[1],prepared[2],repository_root=prepared[0])


@pytest.mark.parametrize('kind',['benign','fault'])
def test_one_explicit_batch_uses_original_argv_and_exact_selected_rows_without_clients(prepared,monkeypatch,kind):
    def deny(*_args,**_kwargs):raise AssertionError('batch request cannot construct client or Suite')
    monkeypatch.setattr(runner.suite.Suite,'__init__',deny)
    monkeypatch.setattr(runner.suite.RawMcp,'__init__',deny)
    monkeypatch.setattr(runner.suite.VmMcp,'__init__',deny)
    ctx=context(prepared)
    item=next(row for row in prepared[4]['batches'] if row['kind']==kind)
    request=runner.single_batch_request(ctx,item['batch_id'])
    assert request.scenario_ids==tuple(item['scenario_ids']) and 1<=len(request.scenario_ids)<=5
    assert request.kind==kind and request.suite_args().filter==kind
    assert request.suite_args().stop_on_first_failure is True
    assert request.suite_args().suite_root==str(ctx.evidence_root)
    assert request.argv_record==ctx.materials['suite_argv'][kind]
    assert request.context.evidence_root.parent.is_relative_to(ctx.repository_root/'Logs')
    assert not ctx.evidence_root.exists() and not ctx.audit_root.exists()
    with pytest.raises(FrozenInstanceError):request.scenario_ids=('sst-100',)
    with pytest.raises(TypeError):request.argv_record['sha256']='0'*64


@pytest.mark.parametrize('batch_id',[None,'','all','benign-99','bad/path','benign-00 fault-00'])
def test_missing_all_unknown_or_multiple_batch_selector_is_refused_without_output(prepared,batch_id):
    ctx=context(prepared)
    with pytest.raises(MaterialError):runner.single_batch_request(ctx,batch_id)
    assert not ctx.evidence_root.exists() and not ctx.audit_root.exists()


@pytest.mark.parametrize('change,reason',[
    ('oversize','one to five'),('duplicate','one to five'),('credited','repeats selected/credited'),
    ('filter','filter mismatch'),('missing','exact uncredited'),('stop','first_nonpass_stop')])
def test_frozen_plan_still_must_cover_original_exact_remaining_ids(prepared,change,reason):
    plan=prepared[4];item=plan['batches'][0]
    if change=='oversize':item['scenario_ids'].append(plan['batches'][1]['scenario_ids'][0])
    elif change=='duplicate':item['scenario_ids'][1]=item['scenario_ids'][0]
    elif change=='credited':item['scenario_ids'][0]='sst-005'
    elif change=='filter':item['kind']='fault'
    elif change=='missing':plan['batches'].pop()
    else:plan['first_nonpass_stop']=False
    modified=repin(prepared)
    with pytest.raises(MaterialError,match=reason):runner.single_batch_request(context(modified),item['batch_id'])


def test_same_request_rechecks_manifest_and_independent_material_before_args_use(prepared):
    ctx=context(prepared);request=runner.single_batch_request(ctx,prepared[4]['batches'][0]['batch_id'])
    path=Path(request.manifest_record['path']);path.write_text('changed original manifest')
    with pytest.raises(MaterialError,match='fingerprint mismatch'):request.suite_args()
    ctx.materials_path.write_text('changed independent material')
    with pytest.raises(MaterialError,match='materials SHA256'):request.suite_args()
