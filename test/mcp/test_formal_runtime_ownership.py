"""Current-execution ownership over the actual ConfigStore, with RPC-only seams."""

import copy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import threading
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json
from formal_runtime.context import load_context
from formal_runtime import config_ownership as ownership
from bounded_mcp import TransportUnknown
import scenario_suite as suite
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp import errors


INI = '[FakeNet]\r\nDumpPackets = No\r\nLogConsole = No\r\n'
OTHER = '[FakeNet]\nDumpPackets = Yes\n'


class StoreClient:
    controller_id = 'actual-config-store-fixture'

    def __init__(self, store):
        self.store, self.calls = store, []

    def tool_outcome(self, name, args=None, timeout=120):
        args = copy.deepcopy(args or {})
        self.calls.append((name, args))
        try:
            if name == 'list_configs':
                result = {'configs': self.store.list()}
            elif name == 'read_config':
                result = self.store.read(args['name'])
            elif name == 'get_status':
                result = {'state': 'stopped'}
            else:
                operation = {'create_config': 'create', 'import_config': 'create', 'edit_config': 'edit',
                             'rename_config': 'rename', 'delete_config': 'delete'}[name]
                fields = {key: value for key, value in args.items() if key in
                          ('name', 'content', 'new_name', 'expected_sha256', 'command_id')}
                fields.setdefault('command_id', 'recorded-%d' % len(self.calls))
                result = getattr(self.store, operation)(controller=self.controller_id, **fields)
            return {'ok': True, 'value': result, 'error': None}
        except errors.McpError as error:
            return {'ok': False, 'value': None, 'error': {'code': error.code, 'message': str(error)}}


def inventory(client):
    rows = []
    for row in client.store.list():
        rows.append(dict(row, path=str(PureWindowsPath(ownership.BUILTIN if row['builtin'] else ownership.CUSTOM) / row['name'])))
    return {'schema': 'r48.config-inventory.v1', 'complete': True, 'custom_root': ownership.CUSTOM,
            'builtin_root': ownership.BUILTIN, 'rows': rows, 'count': len(rows)}


@pytest.fixture
def configured(materials):
    repo, material, _, data = materials
    data['candidate_identity']['default_sha256'] = hashlib.sha256(INI.encode()).hexdigest()
    plan_path = Path(data['plan']['path'])
    plan = json.loads(plan_path.read_bytes()); plan['identity'] = data['candidate_identity']
    data['plan'] = write_json(plan_path, plan)
    pin = write_json(material, data)['sha256']
    context = load_context(material, pin, repository_root=repo)
    instance = suite.Suite(suite.parse_args(['generate', '--suite-root', str(context.evidence_root),
                                           '--candidate-id', 'c', '--source-commit', 's', '--package-sha256', 'p']))
    instance.generate()
    instance.args.command = 'run'  # Pure planning uses the original formal selection branch.
    plan = ownership.selection_plan(instance)
    store = ConfigStore(custom_root=context.evidence_root / 'product-store/custom',
                        builtin_root=context.evidence_root / 'product-store/builtin',
                        audit_path=context.evidence_root / 'product-store/config-audit.jsonl')
    store.builtin_root.mkdir(parents=True)
    (store.builtin_root / 'default.ini').write_bytes(INI.encode())
    client = StoreClient(store)
    listing = {'configs': store.list()}
    native = inventory(client)
    ownership.validate_inventory(plan, listing, native, context.candidate_identity['default_sha256'])
    wrapper = ownership.ConfigOwnedService(client, context, plan, native)
    return context, instance, plan, client, wrapper


def test_original_config_lifecycle_owns_exact_changed_bytes_and_retains_noop_edit(configured):
    context, _, plan, client, wrapper = configured
    case = plan['selected'][0]
    scratch, active, imported = (case[key] for key in ('scratch', 'active', 'import'))
    created = wrapper.tool('create_config', {'name': scratch, 'content': INI})
    assert created['changed'] and wrapper.owned[scratch] == hashlib.sha256(INI.encode()).hexdigest()
    assert client.store.read(scratch)['content'] == INI
    before = dict(wrapper.owned)
    noop = wrapper.tool('edit_config', {'name': scratch, 'content': INI, 'expected_sha256': created['sha256']})
    assert noop['changed'] is False and wrapper.owned == before
    changed = wrapper.tool('edit_config', {'name': scratch, 'content': OTHER, 'expected_sha256': created['sha256']})
    assert wrapper.owned[scratch] == hashlib.sha256(OTHER.encode()).hexdigest()
    renamed = wrapper.tool('rename_config', {'name': scratch, 'new_name': active, 'expected_sha256': changed['sha256']})
    assert scratch not in wrapper.owned and wrapper.owned[active] == renamed['sha256']
    value = wrapper.tool('import_config', {'name': imported, 'content': INI})
    wrapper.tool('delete_config', {'name': imported, 'expected_sha256': value['sha256']})
    wrapper.tool('delete_config', {'name': active, 'expected_sha256': renamed['sha256']})
    assert not wrapper.owned and wrapper.audit_safe and wrapper.mutation_safe
    assert (client.store.builtin_root / 'default.ini').read_bytes() == INI.encode()
    events = [json.loads(path.read_bytes()) for path in (context.evidence_root / 'config-ownership').glob('*.json')]
    assert len(events) == len(client.calls) and any('no-op edit' in event.get('ownership_effect', '') for event in events)


def test_prestart_gate_preserves_original_plan_and_wraps_only_complete_clean_inventory(configured):
    context, instance, plan, client, _ = configured
    instance.service = client
    native = inventory(client)
    commands = []

    def powershell(command, timeout):
        commands.append((command, timeout))
        return {'output': json.dumps(native)}

    instance.vm = SimpleNamespace(powershell=powershell)
    verdict = ownership.prestart_gate(instance, context)
    assert verdict['passed'] and verdict['mutations_before_gate'] == 0
    assert commands == [(ownership.INVENTORY_COMMAND, 30)]
    assert [name for name, _ in client.calls] == ['list_configs']
    assert instance.service.plan == plan and len(plan['selected']) == 100
    assert instance.service.client is client and not instance.service.owned
    assert (context.evidence_root / 'config-namespace-verdict.json').is_file()


def test_original_name_conflict_rejection_does_not_grant_other_file_ownership(configured):
    _, _, plan, client, wrapper = configured
    name = plan['selected'][0]['scratch']
    # A file appearing after the clean gate remains another execution's file.
    client.store.create(controller='other', command_id='other-create', name=name, content=INI)
    outcome = wrapper.tool_outcome('create_config', {'name': name, 'content': OTHER})
    assert outcome['ok'] is False and outcome['error']['code'] == 'name_conflict'
    assert not wrapper.owned and wrapper.mutation_safe
    assert client.store.read(name)['content'] == INI


def test_false_noop_with_changed_content_never_changes_ownership(configured):
    _, _, plan, client, wrapper = configured
    name = plan['selected'][0]['scratch']
    created = wrapper.tool('create_config', {'name': name, 'content': INI})
    prior = dict(wrapper.owned)
    client.tool_outcome = lambda *args: {'ok': True, 'error': None, 'value': {
        'name': name, 'sha256': hashlib.sha256(OTHER.encode()).hexdigest(), 'changed': False}}
    with pytest.raises(RuntimeError, match='changed=false'):
        wrapper.tool_outcome('edit_config', {'name': name, 'content': OTHER,
                                           'expected_sha256': created['sha256']})
    assert wrapper.owned == prior and not wrapper.mutation_safe


@pytest.mark.parametrize('operation', ['edit_config', 'rename_config', 'delete_config', 'create_config', 'save_config'])
def test_builtin_and_other_configuration_never_grant_current_ownership(configured, operation):
    _, _, _, client, wrapper = configured
    with pytest.raises(RuntimeError):
        wrapper.tool_outcome(operation, {'name': 'default.ini', 'new_name': 'other.ini', 'content': OTHER,
                                          'expected_sha256': hashlib.sha256(INI.encode()).hexdigest()})
    assert not client.calls and not wrapper.owned and wrapper.mutation_safe
    assert (client.store.builtin_root / 'default.ini').read_bytes() == INI.encode()


@pytest.mark.parametrize('failure', ['changed-false', 'wrong-sha', 'wrong-name', 'unknown'])
def test_unknown_or_inconsistent_create_cannot_acquire_or_cleanup_configuration(configured, failure):
    _, _, plan, client, wrapper = configured
    scratch = plan['selected'][0]['scratch']
    calls = []

    def response(name, args, timeout):
        calls.append(name)
        if name == 'get_status':
            return {'ok': True, 'value': {'state': 'stopped'}, 'error': None}
        if failure == 'unknown':
            raise TransportUnknown('original create outcome unknown', {})
        return {'ok': True, 'error': None, 'value': {
            'name': 'wrong.ini' if failure == 'wrong-name' else scratch,
            'sha256': '0' * 64 if failure == 'wrong-sha' else hashlib.sha256(INI.encode()).hexdigest(),
            'changed': failure != 'changed-false'}}

    client.tool_outcome = response
    with pytest.raises((RuntimeError, TransportUnknown)):
        wrapper.tool_outcome('create_config', {'name': scratch, 'content': INI})
    assert not wrapper.owned and not wrapper.mutation_safe
    wrapper.tool_outcome('get_status', {})
    with pytest.raises(RuntimeError, match='no replay'):
        wrapper.tool_outcome('delete_config', {'name': scratch, 'expected_sha256': '0' * 64})
    assert calls == ['create_config', 'get_status']


def test_audit_write_failure_keeps_known_response_and_prevents_cleanup(configured, monkeypatch):
    _, _, plan, client, wrapper = configured
    scratch = plan['selected'][0]['scratch']
    original = ownership.save

    def fail(path, value):
        if path.parent.name == 'config-ownership':
            raise OSError('explicit audit boundary failure')
        original(path, value)

    monkeypatch.setattr(ownership, 'save', fail)
    with pytest.raises(ownership.AuditWriteError) as error:
        wrapper.tool_outcome('create_config', {'name': scratch, 'content': INI})
    assert error.value.response_known and client.store.read(scratch)['content'] == INI
    assert wrapper.owned[scratch] == hashlib.sha256(INI.encode()).hexdigest()
    assert not wrapper.audit_safe and wrapper.mutation_safe
    assert wrapper.audit_responsibility()['audit_failures']
    with pytest.raises(RuntimeError, match='no replay'):
        wrapper.tool_outcome('delete_config', {'name': scratch, 'expected_sha256': wrapper.owned[scratch]})
    assert len(client.calls) == 1


def test_inflight_mutation_does_not_hold_state_lock_or_allow_second_dispatch(configured):
    _, _, plan, client, wrapper = configured
    scratch = plan['selected'][0]['scratch']
    entered, release, read_done = threading.Event(), threading.Event(), threading.Event()
    errors_seen, calls = [], []

    def response(name, args, timeout):
        calls.append(name)
        if name == 'create_config':
            entered.set()
            assert release.wait(5)
            raise TransportUnknown('original response lost', {})
        read_done.set()
        return {'ok': True, 'error': None, 'value': {'state': 'stopped'}}

    client.tool_outcome = response

    def create():
        try:
            wrapper.tool_outcome('create_config', {'name': scratch, 'content': INI})
        except BaseException as error:
            errors_seen.append(error)

    thread = threading.Thread(target=create)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RuntimeError, match='inflight'):
            wrapper.tool_outcome('create_config', {'name': scratch, 'content': INI})
        wrapper.tool_outcome('get_status', {})
        assert read_done.is_set()
    finally:
        release.set(); thread.join(5)
    assert not thread.is_alive() and len(errors_seen) == 1 and calls.count('create_config') == 1
    assert not wrapper.mutation_safe and wrapper.audit_responsibility()['inflight_mutation'] is None


@pytest.mark.parametrize('failure', ['collision', 'wrong-path', 'incomplete', 'default-sha', 'case-duplicate'])
def test_original_prestart_inventory_refuses_conflict_without_pruning_or_service_change(configured, failure):
    context, instance, plan, client, _ = configured
    native = inventory(client)
    if failure == 'collision':
        name = plan['selected'][0]['scratch']
        client.store.create(controller='other', command_id='other-create', name=name, content=INI)
        native = inventory(client)
    elif failure == 'wrong-path':
        native['rows'][0]['path'] = r'C:\elsewhere\default.ini'
    elif failure == 'incomplete':
        native['complete'] = False
    elif failure == 'default-sha':
        native['rows'][0]['sha256'] = '0' * 64
    else:
        native['rows'].append(dict(native['rows'][0], name='DEFAULT.INI')); native['count'] += 1
    instance.service = client
    vm_calls = []

    def vm(command, timeout):
        vm_calls.append(command)
        assert command == ownership.INVENTORY_COMMAND
        return {'output': json.dumps(native)}

    instance.vm = SimpleNamespace(powershell=vm)
    with pytest.raises(RuntimeError):
        ownership.prestart_gate(instance, context)
    assert [name for name, _ in client.calls] == ['list_configs'] and len(vm_calls) == 1
    assert (context.evidence_root / 'config-namespace-blocked.json').is_file()
    assert (client.store.builtin_root / 'default.ini').read_bytes() == INI.encode()
    if failure == 'collision':
        assert client.store.read(plan['selected'][0]['scratch'])['content'] == INI
