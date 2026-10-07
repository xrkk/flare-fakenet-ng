"""Indexed original producer identity and real Suite transfer classifications."""

import base64
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, record, write_json
from formal_runtime.context import MaterialError, load_context
from formal_runtime import source
import scenario_suite as suite


@pytest.fixture
def historical(materials):
    repo, material, _, data = materials
    root = repo / 'Logs/old-source'
    root.mkdir()
    driver = repo / 'Logs/driver-r53/formal_adapter.py'
    driver.parent.mkdir()
    driver.write_text('# frozen historical data, never imported\n')
    nonce = '1' * 32
    start = driver.parent / 'start.json'
    write_json(start, {'nonce': nonce})
    namespace = r'E:\FakeNet-NG-MCP-test-work\clean-r53-20261004' + '\\' + nonce + '\\' + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    freeze = driver.parent / 'frozen-plan2.json'
    freeze_rec = write_json(freeze, {
        'identity': data['candidate_identity'], 'root': str(root), 'physical_namespace': namespace,
        'dependencies': {path.relative_to(repo).as_posix(): record(path)['sha256'] for path in (driver, start)}})
    files = {}
    files['guest-namespace-binding.json'] = {
        'schema': 'source-namespace-binding.v1', 'original_execution_root': str(root),
        'physical_namespace': namespace, 'driver': str(driver), 'nonce_file': record(start),
        'frozen_inputs_sha256': freeze_rec['sha256']}
    guest = namespace + r'\scenario-suite-20260912\owned-sst-010-a1'
    for number in (1, 2):
        label = 'run-%02d' % number
        run = guest + '\\' + label
        capture = {'guest': run, 'run_label': label, 'pid': 7 + number, 'probe_creation_ticks': 11 + number,
                   'etl': guest + r'\run-01\pktmon.etl', 'probe': run + r'\probe.jsonl',
                   'pktmon_nic': guest + r'\run-01\pktmon-nic.json', 'nonce': 'traffic-nonce'}
        if number == 2:
            capture.update(shared_physical=True, physical_owner_id='traffic-nonce:pktmon')
        files['file-transport/%d/execution-original.json' % number] = {'output': json.dumps(capture)}
        files['file-transport/%d/intent.json' % number] = {'original_command': "capture '" + run + "' traffic-nonce:pktmon"}
        files['VM-final-intents/%d.json' % number] = {'command': "$r='" + run + "';$s='SST-Kernel-abc-%d';logman start $s -ets" % number}
    files['execution-context.json'] = {'backup_names': ['original-environment.xml']}
    files['cycle-01-intent.json'] = {'receipt': r'E:\FakeNet-NG-MCP-test-work\scenario-suite-20260912\receipt.json'}
    for name, value in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, value)

    def freeze_index():
        rows = []
        for name in files:
            rec = record(root / name)
            rows.append(dict(rec, path=name))
        data['source_indices'] = [write_json(root / 'full-SHA-index.json', {'rows': rows})]
        data['protected_sources'].append(str(root)) if str(root) not in data['protected_sources'] else None
        pin = write_json(material, data)['sha256']
        return load_context(material, pin, repository_root=repo)

    context = freeze_index()
    return context, root, namespace, guest, files, freeze_index


def test_actual_source_identity_does_not_follow_new_output_namespace(historical):
    context, root, namespace, guest, _, _ = historical
    binding = source.resolve_source(context, root)
    assert namespace != context.physical_namespace
    assert binding.physical_namespace == namespace
    assert binding.owner_roots == {source.parts(guest)}
    assert len(binding.values['captures']) == 2 and len(binding.values['kernels']) == 2
    assert namespace + r'\scenario-suite-20260912\receipt.json' in binding.values['required_files']
    assert len(binding.values['witnesses']) >= 10
    with pytest.raises(TypeError):
        binding.values['physical_namespace'] = 'forged'


@pytest.mark.parametrize('change,reason', [
    ('owner', 'owner mismatch'), ('nonce', 'nonce/scope/path'),
    ('candidate', 'candidate identity'), ('missing-owner', 'no actual owner'),
    ('missing-kernel', 'ownership incomplete'), ('backup-escape', 'backup name escape')])
def test_indexed_but_invalid_source_witness_refused(historical, change, reason):
    context, root, _, _, files, freeze_index = historical
    if change == 'owner':
        p = root / 'file-transport/2/execution-original.json'
        value = json.loads(p.read_text())
        capture = json.loads(value['output']); capture['physical_owner_id'] = 'another:pktmon'
        value['output'] = json.dumps(capture); write_json(p, value)
    elif change == 'nonce':
        p = root / 'file-transport/1/execution-original.json'
        value = json.loads(p.read_text()); value['output'] = value['output'].replace('1' * 32, '2' * 32)
        write_json(p, value)
    elif change == 'candidate':
        p = root / 'guest-namespace-binding.json'
        value = json.loads(p.read_text()); frozen = Path(value['driver']).parent / 'frozen-plan2.json'
        freeze = json.loads(frozen.read_text()); freeze['identity']['candidate'] = 'wrong'
        value['frozen_inputs_sha256'] = write_json(frozen, freeze)['sha256']; write_json(p, value)
    elif change == 'missing-owner':
        files.pop('file-transport/1/execution-original.json')
    elif change == 'missing-kernel':
        files.pop('VM-final-intents/1.json'); files.pop('VM-final-intents/2.json')
    else:
        write_json(root / 'execution-context.json', {'backup_names': ['../escape']})
    context = freeze_index()
    with pytest.raises(source.SourceError, match=reason):
        source.resolve_source(context, root)


def test_unindexed_or_changed_source_cannot_self_supply_new_hash(historical):
    context, root, _, _, _, _ = historical
    write_json(root / 'file-transport/1/execution-original.json', {'output': 'changed'})
    with pytest.raises(MaterialError, match='fingerprint mismatch'):
        source.resolve_source(context, root)


def instance_for(binding, root):
    instance = suite.Suite.__new__(suite.Suite)
    instance.root = root
    instance.guest_work_root = suite.E_GUEST_WORK_ROOT
    instance.capture_contract = 'scenario-shared-v2'
    instance.physical_source_binding = binding
    instance.vm = SimpleNamespace(powershell=lambda *_: pytest.fail('must refuse before VM'))
    return instance


def test_original_239mib_shared_limit_refuses_unbound_and_accepts_exact_producer(historical):
    context, root, _, guest, _, _ = historical
    binding = source.resolve_source(context, root)
    instance = instance_for(binding, context.evidence_root)
    path = guest + r'\run-01\pktmon.txt'
    destination = context.evidence_root / 'after/run-01/pktmon.txt'
    size = 239 * 2 ** 20
    instance.physical_source_binding = None
    with pytest.raises(suite.SuiteError, match='outside transfer bound'):
        instance._transfer_guest_file(path, size, 'a' * 64, destination)
    assert not context.evidence_root.exists()
    instance.physical_source_binding = binding
    block = b'0' * 2 ** 20
    digest = hashlib.sha256()
    for _ in range(239):
        digest.update(block)
    calls = []

    def bytes_client(command, timeout):
        length = int(re.search(r'New-Object byte\[\] (\d+)', command)[1])
        calls.append(command)
        return {'output': base64.b64encode(block[:length]).decode('ascii')}

    instance.vm = SimpleNamespace(powershell=bytes_client)
    result = instance._transfer_guest_file(path, size, digest.hexdigest(), destination)
    assert result['size'] == size and result['sha256'] == digest.hexdigest() and len(calls) == 239
    assert instance.guest_work_root == suite.E_GUEST_WORK_ROOT
    assert source.transfer_limit(instance, path, destination) == suite.MAX_SHARED_PKTMON_TEXT_TRANSFER


@pytest.mark.parametrize('bad', ['owner', 'namespace', 'traversal', 'auxiliary'])
def test_bad_scope_cannot_borrow_shared_or_auxiliary_budget(historical, bad):
    context, root, _, guest, _, _ = historical
    binding = source.resolve_source(context, root)
    instance = instance_for(binding, context.evidence_root)
    path = guest + r'\run-01\pktmon.txt'
    aux = False
    if bad == 'owner':
        path = path.replace('owned-sst-010-a1', 'other-sst-010-a1')
    elif bad == 'namespace':
        path = path.replace('clean-r53-', 'clean-r55-')
    elif bad == 'traversal':
        path = guest + r'\..\run-01\pktmon.txt'
    else:
        aux = True
    with pytest.raises(suite.SuiteError):
        instance._transfer_guest_file(path, 239 * 2 ** 20, 'a' * 64,
                                      context.evidence_root / 'run-01/pktmon.txt', auxiliary_v2_output=aux)
    assert not context.evidence_root.exists()


def test_original_ordinary_auxiliary_and_destination_classifications_unchanged(historical):
    context, root, _, guest, _, _ = historical
    instance = instance_for(source.resolve_source(context, root), context.evidence_root)
    ordinary = context.evidence_root / 'ordinary/probe.jsonl'
    assert source.transfer_limit(instance, guest + r'\run-01\probe.jsonl', ordinary) == 192 * 2 ** 20
    assert source.transfer_limit(instance, guest + r'\run-01\pktmon.txt', ordinary) == 192 * 2 ** 20
    aux = suite.E_GUEST_WORK_ROOT + r'\qpc-contract-owned\output.zip'
    dst = context.evidence_root / 'auxiliary-qpc/qpc-output.zip'
    assert source.transfer_limit(instance, aux, dst, auxiliary_v2_output=True) == 256 * 2 ** 20
    assert source.export_destination(instance.physical_source_binding, context.evidence_root, 9,
                                     guest + r'\run-01\pktmon.txt').parts[-3:] == ('00009', 'run-01', 'pktmon.txt')


@pytest.mark.parametrize('failure', ['sha', 'short', 'collision', 'over-limit'])
def test_real_transfer_integrity_and_boundaries_remain_active(historical, failure):
    context, root, _, guest, _, _ = historical
    instance = instance_for(source.resolve_source(context, root), context.evidence_root)
    path = guest + r'\run-01\probe.jsonl'
    destination = context.evidence_root / 'ordinary/probe.jsonl'
    if failure == 'collision':
        destination.parent.mkdir(parents=True); destination.write_bytes(b'retained')
    instance.vm = SimpleNamespace(powershell=lambda *_: {'output': base64.b64encode(b'a' if failure == 'short' else b'ab').decode()})
    size = 192 * 2 ** 20 + 1 if failure == 'over-limit' else 2
    with pytest.raises(suite.SuiteError, match={'sha': 'SHA-256 mismatch', 'short': 'short base64 block',
                                             'collision': 'destination collision', 'over-limit': 'outside transfer bound'}[failure]):
        instance._transfer_guest_file(path, size, '0' * 64, destination)
    assert destination.read_bytes() == b'retained' if failure == 'collision' else not destination.exists()
