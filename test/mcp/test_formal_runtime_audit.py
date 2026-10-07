"""Frozen source-key bijection; no formal pass stand-in or real VM credit."""
import copy
import json
import shutil
import socket
import subprocess
from pathlib import Path
import tempfile

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared
from formal_runtime.context import load_context, MaterialError
from formal_runtime import audit
import scenario_aux_qpc_v2 as v2


@pytest.fixture
def authority(prepared):
    root, material, _, data, plan = prepared
    history = Path(data['source_indices'][0]['path']).parent
    sid = 'sst-005'
    result_path = history / 'results' / ('scenario-' + sid + '.json')
    result = json.loads(result_path.read_bytes())
    native = history / 'evidence' / sid / 'attempt-01/run-01/auxiliary-qpc'
    native.mkdir(parents=True)
    case = {'schema': 'sst.aux-qpc-input.v1', 'candidate_id': data['candidate_identity']['candidate'],
            'run_id': result['run_chain'][0]['run_id'], 'nonce': result['traffic_evidence']['nonce'],
            'files': [{'path': str((native / 'original.bin').relative_to(history))}], 'cases': []}
    (native / 'original.bin').write_bytes(b'independent sealed byte fixture')
    write_json(native / 'auxiliary-qpc-input.json', case)
    write_json(native / 'qpc-process-responsibility.json', {'run_id': case['run_id']})
    write_json(native / 'stored-proof.json', {'schema': v2.PROOF_SCHEMA})
    export = native / 'qpc-native/export'
    for path in v2._source_paths(native / 'auxiliary-qpc-input.json', history, case, export)[2:]:
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, {})
    write_json(export / 'manifest.json', {'schema': v2.SCHEMA, 'status': 'INCOMPLETE'})
    result['run_chain'][0].update(label='run-01', auxiliary_qpc_proof={**record(native / 'stored-proof.json'),
        'path': str((native / 'stored-proof.json').relative_to(history))}, auxiliary_qpc_process={
        'qpc-process-responsibility.json': {**record(native / 'qpc-process-responsibility.json'),
        'path': str((native / 'qpc-process-responsibility.json').relative_to(history))}})
    write_json(result_path, result)
    index = history / 'full-SHA-index.json'
    originals = [p for p in sorted(history.rglob('*')) if p.is_file() and p != index]
    data['source_indices'] = [write_json(index, {'rows': [dict(record(p), path=p.relative_to(history).as_posix()) for p in originals]})]
    context = load_context(material, write_json(material, data)['sha256'], repository_root=root)
    view = context.audit_root / 'view'
    view.mkdir(parents=True)
    records = {}
    cert = {'root': str(history), 'index': str(index), 'sha256': data['source_indices'][0]['sha256']}
    for source in originals:
        target = view / source.relative_to(history)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        records[str(target)] = {'source_root': str(history), 'source_path': str(source), 'target': str(target),
                               'size': source.stat().st_size, 'sha256': record(source)['sha256'], 'source_seal': cert}
    target_case = view / (native / 'auxiliary-qpc-input.json').relative_to(history)
    target_export = view / export.relative_to(history)
    contexts = {str(target_case): {'keys': [str(p) for p in v2._source_paths(target_case, view, case, target_export)],
        'export': str(target_export), 'role': {'scenario': sid, 'attempt': 1, 'run_label': 'run-01',
        'run_id': case['run_id'], 'nonce': case['nonce'], 'source_root': str(history)}}}
    selected = {}
    for n in range(5, 10):
        result = json.loads((history / 'results' / ('scenario-sst-%03d.json' % n)).read_bytes())
        selected[result['scenario_id']] = {'root': str(history), 'attempt': result['attempt'],
            'nonce': result['traffic_evidence']['nonce'], 'run_ids': [run['run_id'] for run in result['run_chain']]}
    snapshot = {'schema': audit.SCHEMA, 'scope': 'credited-selection', 'runtime_view': str(view),
                'records': records, 'contexts': contexts, 'selected': selected,
                'identity': {'candidate_id': data['candidate_identity']['candidate'],
                             'source_commit': data['candidate_identity']['source'],
                             'package_sha256': data['candidate_identity']['zip_sha256']}}
    authority = context.audit_root / 'authorities/selected.json'
    authority.parent.mkdir()
    pin = write_json(authority, snapshot)['sha256']
    return context, authority, pin, snapshot


def mapper(values): return audit.Mapper(*values[:3])
def binding(m): return copy.deepcopy(next(iter(m.contexts.values())))
def proof(m):
    values = {key: {'bytes': m.records[key]['size'], 'sha256': m.records[key]['sha256']}
              for key in binding(m)['keys']}
    return {'schema': v2.PROOF_SCHEMA, 'status': 'INCOMPLETE', 'inputs_before': values,
            'inputs_after': copy.deepcopy(values), 'nested': {'arbitrary': ['unchanged', 7]}}


def test_projection_changes_only_key_maps_preserving_every_other_value(authority):
    m = mapper(authority); raw = proof(m)
    projected, trace = m.project(raw, binding(m))
    assert projected['status'] == 'INCOMPLETE' and projected['nested'] == raw['nested']
    assert {k:v for k,v in projected.items() if k not in ('inputs_before','inputs_after')} == {
        k:v for k,v in raw.items() if k not in ('inputs_before','inputs_after')}
    assert len(trace) == 2 * len(binding(m)['keys'])
    assert set(projected['inputs_before']) == {m.records[key]['source_path'] for key in binding(m)['keys']}
    assert raw == proof(m)


@pytest.mark.parametrize('field,value', [('source_root','/wrong'),('source_path','/samebytes-wrong'),('target','/alias')])
def test_mutated_mapping_refused_even_if_bytes_match(authority, field, value):
    m = mapper(authority); b = binding(m); m.records[b['keys'][0]][field] = value
    with pytest.raises(audit.AuditError, match='trusted authority'): m.project(proof(m), b)


@pytest.mark.parametrize('field,value', [('run_id','wrong'),('attempt',99),('nonce','wrong'),('source_root','/wrong')])
def test_wrong_selected_context_refused(authority, field, value):
    m = mapper(authority); b = binding(m); b['role'][field] = value
    with pytest.raises(audit.AuditError, match='context differs'): m.project(proof(m), b)


@pytest.mark.parametrize('kind', ['missing','extra','unstable','value','schema'])
def test_actual_rebuilt_keys_and_values_are_exact(authority, kind):
    m = mapper(authority); p = proof(m); key = binding(m)['keys'][0]
    if kind == 'missing': p['inputs_before'].pop(key)
    if kind == 'extra': p['inputs_before'][key + '/extra'] = p['inputs_before'][key]
    if kind == 'unstable': p['inputs_after'][key]['bytes'] += 1
    if kind == 'value':
        p['inputs_before'][key]['bytes'] += 1
        p['inputs_after'] = copy.deepcopy(p['inputs_before'])
    if kind == 'schema': p['schema'] = 'wrong'
    with pytest.raises(audit.AuditError): m.project(p, binding(m))


@pytest.mark.parametrize('kind', ['certificate','selected','duplicate_keys','missing_nested','extra_context','candidate'])
def test_forged_authority_cannot_override_independent_material_source(authority, kind):
    context, path, _, snapshot = authority
    altered = copy.deepcopy(snapshot); first = next(iter(altered['records']))
    b = next(iter(altered['contexts'].values()))
    if kind == 'certificate': altered['records'][first]['source_seal']['sha256'] = 'f' * 64
    if kind == 'selected': altered['selected']['sst-005']['attempt'] = 2
    if kind == 'duplicate_keys': b['keys'] += [b['keys'][0]]
    if kind == 'missing_nested': del altered['records'][b['keys'][-1]]
    if kind == 'extra_context': altered['contexts']['/unregistered'] = b
    if kind == 'candidate': altered['identity']['candidate_id'] = 'wrong'
    with pytest.raises((audit.AuditError, MaterialError)):
        audit.Mapper(context, path, write_json(path, altered)['sha256'])


def test_authority_drift_rejected_before_derivation(authority):
    m = mapper(authority); authority[1].write_bytes(b'{}')
    with pytest.raises(audit.AuditError, match='after independent freeze'): m.project(proof(m), binding(m))


@pytest.mark.parametrize('where', ['copy','original','selected_result'])
def test_byte_drift_rejected_before_original_derivation(authority, where):
    m = mapper(authority); b = binding(m)
    key = b['keys'][-1] if where != 'selected_result' else str(m.view / 'results/scenario-sst-005.json')
    row = m.records[key]; path = Path(row['source_path'] if where == 'original' else key)
    path.write_bytes(path.read_bytes() + b'changed')
    with pytest.raises(MaterialError, match='fingerprint mismatch'): m.project(proof(m), b)


def test_actual_original_derive_rejects_incomplete_fixture_and_scope_restores(authority):
    m = mapper(authority); b = binding(m); original = audit.contract.offline.derive
    oldtemp = tempfile.tempdir
    with pytest.raises(v2.raw.DiagnosticError, match='input schema/cases invalid'):
        with m.installed(m.context.audit_root / 'proofs'):
            audit.contract.offline.derive(Path(next(iter(m.contexts))), m.view,
                Path(b['export']), m.context.audit_root / 'derived')
    assert m.count == 0 and audit.contract.offline.derive is original and tempfile.tempdir == oldtemp
    assert not m.guard.active and not audit._LOCK.locked()


def test_scope_refuses_nested_network_business_process_writes_and_source_fallback(authority):
    m = mapper(authority); original = audit.contract.offline.derive
    source = Path(next(iter(m.records.values()))['source_path'])
    with m.installed(m.context.audit_root / 'scope'):
        with pytest.raises(audit.AuditError, match='nonnested'):
            with m.installed(m.context.audit_root / 'nested'): pytest.fail('nested scope')
        with pytest.raises(audit.AuditError, match='network'): socket.socket()
        with pytest.raises(audit.AuditError, match='business subprocess'): subprocess.Popen(['echo','forbidden'])
        with pytest.raises(audit.AuditError, match='outside independent'): source.write_bytes(b'forbidden')
        m.guard.deriving = True
        try:
            with pytest.raises(audit.AuditError, match='historical fallback'): source.read_bytes()
            with pytest.raises(audit.AuditError, match='historical fallback'): list(source.parent.iterdir())
        finally: m.guard.deriving = False
        m.validate(binding(m))  # only exact pinned read-only git calls are allowed
    assert audit.contract.offline.derive is original and not m.guard.active


def test_setup_failure_releases_scope_lock_and_original_function(authority):
    m = mapper(authority); original = audit.contract.offline.derive
    output = m.context.audit_root / 'exists'; output.mkdir()
    with pytest.raises(FileExistsError):
        with m.installed(output): pytest.fail('existing audit output is not a retry')
    assert audit.contract.offline.derive is original and not audit._LOCK.locked() and not m.guard.active


@pytest.mark.parametrize('kind', ['symlink','hardlink','samebytes_source_swap'])
def test_copies_cannot_alias_or_swap_exact_source(authority, kind):
    context, path, pin, snapshot = authority
    m = mapper(authority); b = binding(m)
    key = b['keys'][-1]; target = Path(key); source = Path(m.records[key]['source_path'])
    if kind == 'samebytes_source_swap':
        other = b['keys'][-2]
        assert m.records[other]['sha256'] == m.records[key]['sha256']
        m.records[key]['source_path'], m.records[other]['source_path'] = (
            m.records[other]['source_path'], m.records[key]['source_path'])
        with pytest.raises(audit.AuditError, match='trusted authority'): m.project(proof(m), b)
    else:
        target.unlink()
        if kind == 'symlink': target.symlink_to(source)
        else: target.hardlink_to(source)
        with pytest.raises((audit.AuditError, MaterialError)): audit.Mapper(context, path, pin)


def test_scoped_guard_refuses_code_execution_from_historical_Logs(authority):
    m = mapper(authority)
    historical = m.context.repository_root / 'Logs/inputs/forbidden.py'
    payload = compile('raise AssertionError("must never execute")',str(historical),'exec')
    with m.installed(m.context.audit_root / 'exec-scope'):
        with pytest.raises(audit.AuditError,match='code execution from Logs'): exec(payload,{})
    assert not m.guard.active


def test_audit_guard_accepts_windows_string_argv_for_allowlisted_git():
    """Windows Python audits the joined command line, not the argv list.

    The guard must accept the list2cmdline rendering of an allowlisted git
    read (string form) as well as the original list form, and refuse any
    non-whitelisted string such as an echo command.
    """
    from types import SimpleNamespace
    from formal_runtime.audit import AuditGuard, AuditError
    from subprocess import list2cmdline

    source_root = Path('C:/repository')
    context = SimpleNamespace(
        source_root=source_root,
        tool_source={'commit': 'c' * 40,
                     'files': [{'path': str(source_root / 'test/mcp/acceptance/helper.py')}]})
    guard = AuditGuard(context)
    guard.active = True
    allowed = next(iter(guard.git_reads))

    guard('subprocess.Popen', (None, list(allowed), None, None))
    guard('subprocess.Popen', (None, list2cmdline(list(allowed)), None, None))

    with pytest.raises(AuditError, match='business subprocess'):
        guard('subprocess.Popen', (None, 'echo forbidden', None, None))
    with pytest.raises(AuditError, match='business subprocess'):
        guard('subprocess.Popen',
              (None, list2cmdline(['git', '-C', str(source_root), 'status']), None, None))


def test_audit_guard_allows_real_pinned_git_and_refuses_unlisted_process(materials):
    import sys
    context = load_context(materials[1], materials[2], repository_root=materials[0])
    guard = audit.AuditGuard(context)
    observed = []

    def hook(event, arguments):
        if guard.active and event == 'subprocess.Popen':
            observed.append(arguments[1])
        guard(event, arguments)

    sys.addaudithook(hook)
    guard.active = True
    try:
        assert context.revalidate().materials_sha256 == context.materials_sha256
        assert len(observed) == 1
        assert isinstance(observed[0], str if sys.platform == 'win32' else list)
        with pytest.raises(audit.AuditError, match='business subprocess'):
            subprocess.run(['git', '-C', str(materials[0]), 'status'], check=True)
    finally:
        guard.active = False
