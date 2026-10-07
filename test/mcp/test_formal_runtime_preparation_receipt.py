"""Invalid preparation declarations never reach a client or actual audit.

These are rejection tests, not a fabricated successful preparation fixture.
The producer's actual separate-audit failure chain is exercised alongside.
"""
from pathlib import Path
import hashlib
import os
import tempfile

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_prepare import prepared
from test_formal_runtime_audit import authority
from formal_runtime.context import MaterialError, load_context
from formal_runtime.preparation import output_inventory, check_audit_copies
from formal_runtime.preparation_receipt import load_preparation
from formal_runtime import runner


@pytest.fixture
def receipt(materials):
    repo, material, pin, _ = materials
    context = load_context(material, pin, repository_root=repo)
    path = context.audit_root/'preparation-result.json'
    path.parent.mkdir(parents=True)
    record = write_json(path, {'schema': 'fakenetng.formal-runtime.preparation.v1',
        'passed': False, 'materials_sha256': context.materials_sha256,
        'business_authorized': False, 'VM_calls': 0, 'new_formal_credit': 0,
        'live_instance_and_resource_admission_required': True})
    return context, path, record['sha256']


def consume(receipt):
    context, path, pin = receipt
    return load_preparation(context, path, pin,
        context.source_root/'test/mcp/acceptance/run_formal_completion.py')


def test_failed_preparation_receipt_cannot_be_relabelled_as_admission(receipt):
    with pytest.raises(MaterialError, match='failed or incomplete'): consume(receipt)
    assert not receipt[0].evidence_root.exists()


@pytest.mark.parametrize('pin', [None, '', 'A'*64, '0'*63, 'neighbour.json'])
def test_external_preparation_sha_is_required_and_never_read_from_a_neighbour(receipt, pin):
    context, path, _ = receipt
    with pytest.raises(MaterialError, match='independent preparation SHA256 is required'):
        consume((context, path, pin))


def test_receipt_and_self_hash_changes_cannot_override_external_expected_sha(receipt):
    context, path, pin = receipt
    write_json(path, {'passed': True, 'materials_sha256': context.materials_sha256})
    write_json(path.parent/'expected-sha.json', {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    with pytest.raises(MaterialError, match='independent preparation SHA256 mismatch'):
        consume(receipt)
    assert not context.evidence_root.exists()


def test_preparation_receipt_must_be_exact_owned_path_not_equal_bytes_elsewhere(receipt):
    context, path, pin = receipt
    other = context.audit_root/'other-result.json'; other.write_bytes(path.read_bytes())
    with pytest.raises(MaterialError, match='exact owned regular result'):
        consume((context, other, pin))


@pytest.mark.parametrize('change', ['boolean-VM', 'business', 'credit', 'wrong-schema', 'different-material'])
def test_internally_frozen_bogus_success_is_refused_before_source_or_dispatch(receipt, change):
    context, path, _ = receipt
    value = {'schema': 'fakenetng.formal-runtime.preparation.v1', 'passed': True,
             'materials_sha256': context.materials_sha256, 'business_authorized': False,
             'VM_calls': 0, 'new_formal_credit': 0, 'live_instance_and_resource_admission_required': True}
    if change == 'boolean-VM': value['VM_calls'] = False
    elif change == 'business': value['business_authorized'] = True
    elif change == 'credit': value['new_formal_credit'] = 1
    elif change == 'wrong-schema': value['schema'] = 'input-check'
    else: value['materials_sha256'] = '0'*64
    pin = write_json(path,value)['sha256']
    with pytest.raises(MaterialError, match='failed or incomplete|different main material'):
        consume((context,path,pin))
    assert not context.evidence_root.exists()


def test_audit_inventory_fingerprints_nested_outputs_and_detects_changes(tmp_path):
    nested = tmp_path/'proofs/derived.json'; nested.parent.mkdir()
    nested.write_bytes(b'original failed proof')
    initial = output_inventory(tmp_path)
    assert initial == [{'path': str(nested), 'size': nested.stat().st_size,
                        'sha256': hashlib.sha256(nested.read_bytes()).hexdigest()}]
    nested.write_bytes(b'changed proof')
    assert output_inventory(tmp_path) != initial
    extra = tmp_path/'proofs/new-output.json'; extra.write_text('{}')
    assert len(output_inventory(tmp_path)) == 2


def _can_symlink():
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 't.json')
            link = os.path.join(tmp, 'l.json')
            open(target, 'w').close()
            os.symlink(target, link)
            # Some Wine configurations silently materialize a copy instead
            # of a real link; refusing a symlink requires a true link.
            return os.path.islink(link)
    except OSError:
        return False


@pytest.mark.skipif(not _can_symlink(), reason='symlink creation unavailable')
def test_audit_inventory_refuses_symlink_dependency_even_with_same_bytes(tmp_path):
    original = tmp_path/'actual.json'; original.write_text('{}')
    (tmp_path/'alias.json').symlink_to(original)
    assert (tmp_path/'alias.json').is_symlink()
    with pytest.raises(MaterialError, match='symlink path refused'): output_inventory(tmp_path)


def copy_binding(authority):
    context,path,pin,_ = authority
    # This is a data-authority check with actual indexed/copy bytes; it never
    # declares the INCOMPLETE original proof a successful audit or preparation.
    return context, {'authority':str(path), 'authority_sha256':pin, 'scope':'credited-selection'}


def test_final_original_copy_bytes_are_checked_without_installing_mapper(authority):
    context, binding = copy_binding(authority)
    check_audit_copies(context,binding)
    assert not context.evidence_root.exists()


@pytest.mark.parametrize('change', ['target-bytes','source-bytes','hardlink','authority'])
def test_final_copy_check_refuses_changed_source_copy_shared_inode_or_authority(authority,change):
    context,binding = copy_binding(authority)
    row = next(iter(authority[3]['records'].values()))
    target,source = Path(row['target']),Path(row['source_path'])
    if change == 'target-bytes': target.write_bytes(target.read_bytes()+b'changed')
    elif change == 'source-bytes': source.write_bytes(source.read_bytes()+b'changed')
    elif change == 'hardlink':
        # Retain the fixture's original independent inode before testing a
        # deliberately invalid shared-inode target; no evidence cleanup.
        target.rename(target.with_name(target.name+'.independent-before-test'))
        target.hardlink_to(source)
    else: Path(binding['authority']).write_bytes(Path(binding['authority']).read_bytes()+b' ')
    with pytest.raises(MaterialError, match='fingerprint|shares source inode'):
        check_audit_copies(context,binding)


def test_rechecked_metadata_can_read_existing_audit_but_never_reuse_business_output(prepared):
    repo,material,pin,data,_ = prepared
    context = load_context(material,pin,repository_root=repo)
    context.audit_root.mkdir()
    with pytest.raises(MaterialError, match='unused output roots'):
        runner.check_preparation_inputs(context)
    inputs = runner.check_preparation_inputs(context,prepared_audit=True)
    assert inputs['business_authorized'] is False and inputs['VM_calls'] == 0
    context.evidence_root.mkdir()
    with pytest.raises(MaterialError, match='unused output roots'):
        runner.check_preparation_inputs(context,prepared_audit=True)


def test_self_reported_success_without_qualified_sources_never_reaches_clients(receipt,monkeypatch):
    context,path,_ = receipt
    record = write_json(path, {'schema':'fakenetng.formal-runtime.preparation.v1','passed':True,
        'materials_sha256':context.materials_sha256,'business_authorized':False,
        'VM_calls':0,'new_formal_credit':0,'live_instance_and_resource_admission_required':True})
    def deny(*args,**kwargs):raise AssertionError('a claimed result cannot reach clients')
    monkeypatch.setattr(runner.suite.RawMcp,'__init__',deny)
    monkeypatch.setattr(runner.suite.VmMcp,'__init__',deny)
    with pytest.raises(MaterialError,match='root-tool file records'):
        consume((context,path,record['sha256']))
    assert not context.evidence_root.exists()
