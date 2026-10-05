"""Current producer witnesses through original Suite/VM environment boundaries."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, load, write_json
from test_formal_runtime_instance import subject, CaptureClient, PROFILE
from test_formal_runtime_transport import ByteClient, LONG_COMMAND
from formal_runtime.context import load_context
from formal_runtime import instance, producer
from formal_runtime.source import SourceError
from bounded_mcp import TransportUnknown


@pytest.fixture
def current(materials):
    repo, material, _, data = materials
    namespace = (r'E:\FakeNet-NG-MCP-test-work\clean-r60-20261005'+'\\'+'3'*32+'\\'+
                 hashlib.sha256(data['evidence_root'].encode()).hexdigest()[:12])
    data['physical_namespace'] = namespace
    plan_path = Path(data['plan']['path'])
    plan = json.loads(plan_path.read_bytes())
    plan['physical_namespace'] = namespace
    data['plan'] = write_json(plan_path, plan)
    pin = write_json(material, data)['sha256']
    return load_context(material, pin, repository_root=repo)


def rows(context, folder):
    return {p.stem: json.loads(p.read_bytes()) for p in (context.evidence_root/folder).glob('*.json')}


def test_register_preserves_independent_material_and_explicit_original_namespace(current):
    value = producer.register_execution(current)
    assert value['materials']['sha256'] == current.materials_sha256
    assert value['tool_commit'] == current.tool_source['commit'] != current.candidate_identity['source']
    assert value['source_nonce'] == '3'*32
    assert value['original_execution_root'] == str(current.evidence_root)
    assert value['no_business_admission'] is True
    original = (current.evidence_root/'execution-binding.json').read_bytes()
    with pytest.raises(FileExistsError):
        producer.register_execution(current)
    assert (current.evidence_root/'execution-binding.json').read_bytes() == original


def test_wrong_scope_and_changed_material_refused_without_output(materials):
    context = load(materials)
    with pytest.raises(SourceError, match='nonce/scope'):
        producer.register_execution(context)
    assert not context.evidence_root.exists()
    context.materials_path.write_text('changed')
    with pytest.raises(ValueError, match='materials SHA256'):
        producer.register_execution(context)
    assert not context.evidence_root.exists()


def test_short_actual_capture_responses_are_paired_without_guest_projection(current):
    r = subject(current)
    client = CaptureClient(current, success=True)
    state = instance.Responsibility()
    r.vm = instance.ProtectedVm(client, current, state)
    instance.bind_namespace(r, current)
    guest = r._guest_scenario_root('sst-001', 1)
    client.run = guest+r'\run-01'
    capture = r._start_capture_and_probe(guest, PROFILE, 'bound-nonce', 'run-01')
    intents, responses, terminals = (rows(current, name) for name in
                                    ('VM-final-intents','VM-final-responses','VM-final-terminals'))
    assert set(intents) == set(responses) == set(terminals)
    assert any('logman start $s -ets' in v['command'] for v in intents.values())
    captures = [json.loads(v['output']) for v in responses.values()
                if '"probe_creation_ticks"' in v.get('output','')]
    assert captures and capture['guest'] == captures[0]['guest']
    assert 'physical_owner_id' not in captures[0] and 'physical_owner_id' not in capture
    assert all(v['response_known'] and v['response_persisted'] for v in terminals.values())
    assert all(intents[k]['materials_sha256'] == current.materials_sha256 for k in intents)
    assert r.vm.journal.responsibility()['unknown_dispatches'] == []


def test_staged_response_keeps_original_body_and_exact_final_command(current):
    client, state = ByteClient(), instance.Responsibility()
    guarded = instance.ProtectedVm(client, current, state)
    answer = guarded.powershell(LONG_COMMAND, 120)
    intent = next(iter(rows(current,'VM-final-intents').values()))
    response = next(iter(rows(current,'VM-final-responses').values()))
    assert intent['command'] == LONG_COMMAND and client.executions == [LONG_COMMAND]
    assert response == answer and all(response[k] == v for k,v in client.response.items())
    assert (current.evidence_root/'file-transport').is_dir()
    assert next(iter(guarded.journal.calls.values()))['known_original_response'] is None
    assert 'command' not in next(iter(guarded.journal.calls.values()))['intent']


def test_short_received_response_survives_local_audit_failure_and_blocks_next_mutation(current, monkeypatch):
    state, calls = instance.Responsibility(), []
    original = {'output': '{"owned":"actual-known"}', 'exit_code': 0, 'stderr': 'original'}
    def dispatch(command, timeout):
        calls.append(command)
        return original
    guarded = instance.ProtectedVm(SimpleNamespace(powershell=dispatch), current, state)
    save = producer.write_new_json
    def fail(path, value):
        if path.parent.name == 'VM-final-responses':
            raise OSError('controlled witness disk failure')
        return save(path, value)
    monkeypatch.setattr(producer, 'write_new_json', fail)
    answer = guarded.powershell("Set-Content 'E:\\owned' 'body'", 30)
    assert answer is original and len(calls) == 1 and not state.safe
    ledger = next(iter(guarded.journal.calls.values()))
    assert ledger['known_original_response'] is original
    assert ledger['terminal']['response_known'] and not ledger['terminal']['response_persisted']
    with pytest.raises(RuntimeError, match='no replay'):
        guarded.powershell('Start-Service fakenetng-mcp', 30)
    assert len(calls) == 1 and not guarded.journal.audit_safe


def test_unknown_kernel_start_keeps_exact_intent_and_error_without_replay(current):
    state, calls = instance.Responsibility(), []
    record = {'sent':'possibly-sent', 'local_writer_ended':True}
    error = TransportUnknown('actual controlled unknown dispatch', record)
    def dispatch(command, timeout):
        calls.append(command)
        raise error
    guarded = instance.ProtectedVm(SimpleNamespace(powershell=dispatch), current, state)
    command = "$r='"+current.physical_namespace+r"\scenario-suite-20260912\owned\run-01';$s='SST-Kernel-abc-1';logman start $s -ets"
    with pytest.raises(TransportUnknown) as caught:
        guarded.powershell(command, 30)
    assert caught.value is error
    intents, terminals = rows(current,'VM-final-intents'), rows(current,'VM-final-terminals')
    key = next(iter(intents))
    assert intents[key]['command'] == command
    assert terminals[key]['original_error_record'] == record and not terminals[key]['response_known']
    assert not rows(current,'VM-final-responses')
    assert guarded.journal.responsibility()['unknown_dispatches'] == [key]
    with pytest.raises(RuntimeError):
        guarded.powershell(command, 30)
    assert len(calls) == 1


def test_intent_failure_sends_nothing_and_preserves_in_memory_responsibility(current, monkeypatch):
    state, calls = instance.Responsibility(), []
    journal = producer.VmJournal(current, state)
    def fail(*_): raise OSError('controlled intent write failure')
    monkeypatch.setattr(producer, 'write_new_json', fail)
    with pytest.raises(OSError):
        journal.dispatch(lambda *args: calls.append(args), 'Start-Service fakenetng-mcp', 30)
    assert not calls and not state.safe and not journal.audit_safe
    assert next(iter(journal.calls.values()))['terminal']['dispatch_started'] is False


@pytest.mark.parametrize('local_failure', ['none', 'receipt-audit', 'transport-audit'])
def test_completed_receipt_records_separate_actual_read_and_never_erases_local_unknown(current, monkeypatch, local_failure):
    state = instance.Responsibility()
    state.receipt = current.physical_namespace+r'\scenario-suite-20260912\cycle\receipt.json'
    state.expected_enabled = True
    calls = []
    class Client:
        audit_safe = local_failure != 'transport-audit'
        def powershell(self, command, timeout):
            calls.append(command)
            if 'Start-Service' in command:
                raise TransportUnknown('original SCM unknown', {'sent':'possibly-sent'})
            return {'output':json.dumps({'stage':'completed','enabled':True,
                'dispatch_nonce':hashlib.sha256(state.receipt.encode()).hexdigest(),
                'answer':{'enabled':True,'state':'Running'}}),'exit_code':0}
    guarded = instance.ProtectedVm(Client(), current, state)
    save = producer.write_new_json
    def fail(path, value):
        if local_failure == 'receipt-audit' and path.parent.name == 'VM-final-responses':
            raise OSError('receipt raw audit failure')
        return save(path, value)
    monkeypatch.setattr(producer, 'write_new_json', fail)
    answer = guarded.powershell("Start-Service fakenetng-mcp;@{enabled=$true;backup='owned'}|ConvertTo-Json -Compress", 180)
    assert answer['projection'] == 'completed receipt.answer' and state.cycle_applied
    assert not state.admission_ready and state.safe is (local_failure == 'none')
    intents = rows(current,'VM-final-intents')
    assert len(intents) == 2 and sum('Start-Service' in v['command'] for v in intents.values()) == 1
    assert len(calls) == 2
    if local_failure == 'none':
        responses = rows(current,'VM-final-responses')
        assert len(responses) == 1 and 'stage' in json.loads(next(iter(responses.values()))['output'])
        assert 'projection' not in next(iter(responses.values()))


def test_unknown_primary_survives_terminal_audit_failure(current, monkeypatch):
    state = instance.Responsibility()
    journal = producer.VmJournal(current, state)
    original = TransportUnknown('unknown original', {'sent':'possibly-sent'})
    def dispatch(*_): raise original
    save = producer.write_new_json
    def fail(path, value):
        if path.parent.name == 'VM-final-terminals': raise OSError('terminal audit failure')
        return save(path, value)
    monkeypatch.setattr(producer, 'write_new_json', fail)
    with pytest.raises(TransportUnknown) as caught:
        journal.dispatch(dispatch, 'Get-Content original', 30)
    assert caught.value is original and 'independent VM witness' in original.__notes__[0]
    assert journal.responsibility()['unknown_dispatches'] and not state.safe
