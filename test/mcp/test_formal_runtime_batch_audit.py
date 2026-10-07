"""New-batch lineage/copies with actual original rejection, never fake proof PASS."""
import copy
import json
import os
import tempfile
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared, repin
from test_formal_runtime_entry import config_prepared, entry_material
from formal_runtime.context import load_context, MaterialError
from formal_runtime import batch_rejudge, batch_selection, sealing, runner, producer


@pytest.fixture
def declared_batch(entry_material):
    repo, material, pin, data, plan = entry_material
    context = load_context(material, pin, repository_root=repo)
    request = runner.single_batch_request(context, 'benign-00')
    producer.register_execution(context)
    root = context.evidence_root
    (root/'scenario-manifest.json').write_bytes(Path(plan['original_manifest']['path']).read_bytes())
    batch_root = root/'formal-batches'/request.batch_id; batch_root.mkdir(parents=True)
    # These are explicitly unverified metadata fixtures. Original Suite verify
    # is invoked below and MUST reject their absent run/traffic/native proofs.
    events = [{'scenario_id': sid, 'event': 'executed', 'classification': 'pass', 'state': 'pass',
               'traffic_recheck_issues': [], 'post_gate_error': None} for sid in request.scenario_ids]
    terminal = {'schema': 'fakenetng.final100.formal-batch.terminal.v1', 'batch_id': request.batch_id,
                'status': 'complete', 'passed': True, 'stop_reason': None, 'not_executed': [], 'events': events}
    write_json(batch_root/'terminal.json', terminal)
    write_json(batch_root/'start.json', {'scenario_ids': list(request.scenario_ids)})
    handoff = {'original_batch_terminal': terminal, 'original_primary_error': None, 'secondary_errors': [],
               'scenario_ids': list(request.scenario_ids), 'final_original_status': {'state': 'stopped',
                    'config_identity': {'sha256': context.candidate_identity['default_sha256']}}}
    write_json(root/'batch-handoff.json', handoff)
    product = context.candidate_identity
    identity = dict(candidate_id=product['candidate'], source_commit=product['source'], package_sha256=product['zip_sha256'])
    for sid in request.scenario_ids:
        target = root/'results'/('scenario-'+sid+'.json'); target.parent.mkdir(exist_ok=True)
        value = {'scenario_id': sid, 'state': 'pass', 'identity': identity,
                 'scenario': next(row for row in json.loads((root/'scenario-manifest.json').read_bytes())['scenarios']
                                  if row['scenario_id'] == sid),
                 'attempt': 1, 'traffic_evidence': {'nonce': sid+'-a1-'+'d'*32},
                 'run_chain': [{'run_id': sid+'-unverified-metadata'}]}
        write_json(target, value)
        attempt = root/'evidence'/sid/'attempt-01'; attempt.mkdir(parents=True)
        (attempt/'incomplete-original.bin').write_bytes(b'no proof success\n')
    index_path = root/sealing.INDEX_NAME
    write_json(index_path, {'schema': 'fakenetng.formal-runtime.host-source-index.v1', 'root': str(root),
                           'materials_sha256': context.materials_sha256, 'batch_id': request.batch_id,
                           'rows': sealing.inventory(root)})
    context.audit_root.mkdir()
    return context, request, record(index_path)


def _can_symlink():
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 't')
            link = os.path.join(tmp, 'l')
            open(target, 'w').close()
            os.symlink(target, link)
            # Some Wine configurations silently materialize a copy instead
            # of a real link; refusing a symlink requires a true link.
            return os.path.islink(link)
    except OSError:
        return False


@pytest.mark.skipif(not _can_symlink(), reason='symlink creation unavailable')
def test_streamed_inventory_refuses_symlinks_and_seal_requires_actual_execution(declared_batch):
    context, request, index = declared_batch
    assert sealing.check_index(context.evidence_root, index)['batch_id'] == request.batch_id
    with pytest.raises(MaterialError, match='actual original execution'):
        sealing.seal(SimpleNamespace(passed=True), {'passed': True})
    (context.evidence_root/'outside-link').symlink_to(context.materials_path)
    with pytest.raises(MaterialError, match='symlink'):
        sealing.check_index(context.evidence_root, index)


@pytest.mark.parametrize('change', ['new-file', 'changed-bytes', 'missing-file'])
def test_seal_rechecks_exact_set_and_all_bytes(declared_batch, change):
    context, _, index = declared_batch
    path = context.evidence_root/'batch-handoff.json'
    if change == 'new-file': (context.evidence_root/'new-writer.bin').write_bytes(b'new')
    elif change == 'changed-bytes': path.write_bytes(path.read_bytes()+b' ')
    else: path.unlink()
    with pytest.raises(MaterialError, match='changed after seal'):
        batch_rejudge.freeze(context, 'benign-00', index)
    assert not (context.audit_root/'new-batch-inputs').exists()


def test_freeze_binds_same_parent_and_no_default_retry(declared_batch):
    context, request, index = declared_batch
    child = batch_rejudge.freeze(context, request.batch_id, index)
    selected = batch_selection.selection(child)
    assert selected == {sid: str(context.evidence_root) for sid in request.scenario_ids}
    assert child.materials_sha256 != context.materials_sha256
    assert child.candidate_identity == context.candidate_identity and child.tool_source == context.tool_source
    assert not child.evidence_root.exists() and not child.audit_root.exists()
    with pytest.raises(MaterialError, match='no implicit retry'):
        batch_rejudge.freeze(context, request.batch_id, index)


@pytest.mark.parametrize('change', ['parent-pin', 'candidate', 'source-index', 'selected-credit', 'nonpass'])
def test_self_rehashed_child_cannot_change_original_parent_or_selected_batch(declared_batch, change):
    context, request, index = declared_batch
    child = batch_rejudge.freeze(context, request.batch_id, index)
    data = json.loads(child.materials_path.read_bytes())
    plan = json.loads(Path(data['plan']['path']).read_bytes())
    if change == 'parent-pin': plan['new_batch_audit']['main_materials']['sha256'] = '0'*64
    elif change == 'candidate':
        data['candidate_identity']['exe_sha256'] = '0'*64; plan['identity'] = data['candidate_identity']
    elif change == 'source-index': data['source_indices'].pop()
    elif change == 'selected-credit':
        data['credited_selection'] = write_json(Path(data['credited_selection']['path']), {'sst-005':str(context.evidence_root)})
    else:
        handoff_path = context.evidence_root/'batch-handoff.json'
        handoff = json.loads(handoff_path.read_bytes()); handoff['original_primary_error'] = 'original first nonpass'
        write_json(handoff_path, handoff)
        # Even a newly pinned index cannot turn an original failed terminal into admission.
        value = json.loads(Path(index['path']).read_bytes()); value['rows'] = sealing.inventory(context.evidence_root)
        index = write_json(Path(index['path']), value)
        plan['new_batch_audit']['source_index'] = index; data['source_indices'][-1] = index
    data['plan'] = write_json(Path(data['plan']['path']), plan)
    pin = write_json(child.materials_path, data)['sha256']
    changed = load_context(child.materials_path, pin, repository_root=context.repository_root)
    with pytest.raises(MaterialError): batch_selection.selection(changed)
    assert not child.audit_root.exists()


def test_actual_independent_original_cli_rejects_incomplete_batch_and_restores_adapter(declared_batch,tmp_path):
    context, request, index = declared_batch
    child = batch_rejudge.freeze(context, request.batch_id, index)
    command = [sys.executable, '-B', str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
               '--materials-json',str(child.materials_path),'--materials-sha256',child.materials_sha256,
               '--selection-json',child.materials['credited_selection']['path'],'--scope','batch-selection',
               '--repository-root',str(context.repository_root)]
    # Host resource measurements are the only environmental seam. Proof,
    # verify/replay/summary and independent guards remain the original code.
    source = 'import shutil,runpy,sys; from types import SimpleNamespace; shutil.disk_usage=lambda _:SimpleNamespace(free=50*2**30); sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name="__main__")'
    result = subprocess.run([sys.executable,'-B','-c',source,str(context.source_root/'test/mcp/acceptance'),*command[2:]],
                            cwd=context.source_root,capture_output=True,text=True,timeout=60)
    (tmp_path/'audit.stdout').write_text(result.stdout); (tmp_path/'audit.stderr').write_text(result.stderr)
    assert result.returncode != 0
    terminal = json.loads((child.audit_root/'audit-terminal.json').read_bytes())
    assert terminal['passed'] is False and terminal['adapter_restored'] is True
    assert terminal['host_audit_writers_ended'] is True and terminal['VM_calls'] == terminal['new_formal_credit'] == 0
    assert terminal['verify'] is not None and terminal['verify']['problems']
    assert not (child.audit_root/'audit-result.json').exists()
    assert sealing.check_index(context.evidence_root,index)
