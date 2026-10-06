# Copyright 2026 Google LLC
"""Config mutation receipts: stored SHA/identity flow through one chain.

A real ConfigStore under a temporary root plus the real Coordinator: the
create→edit→rename→delete chain is driven ONLY by each prior response's
state_version and config_result.sha256 (no extra read_config), the stored
bytes are hashed independently to confirm the receipt, and replays plus
get_command_status keep the ORIGINAL identity after the file changed.
"""

import hashlib

import pytest

from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble

OWNER = '11111111-2222-4333-8444-555555555555'
ASCII_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
UNICODE_INI = '[FakeNet]\n; 采集配置 中文\nDumpPackets = No\n'


def store_under(tmp_path):
    return ConfigStore(custom_root=tmp_path / 'custom',
                       builtin_root=tmp_path / 'builtin',
                       audit_path=tmp_path / 'audit.jsonl')


def submit(coordinator, command_id, kind, execute, version):
    return coordinator.submit(
        command_id=command_id, expected_version=version, controller=OWNER,
        controller_valid=True, kind=kind, describe={},
        execute=execute)


def stored_bytes_sha(store, name):
    return hashlib.sha256(
        (store.custom_root / name).read_bytes()).hexdigest()


def mutate_via(coordinator, store):
    """The production wiring: execute returns the store result plus the
    config_result mapping tools.config_mutation builds."""
    def runner(kind, command_id, store_call, version):
        def execute(coord):
            stored = store_call()
            result = dict(stored)
            if kind == 'delete_config':
                result['config_result'] = {
                    'name': stored.get('name'), 'sha256': None,
                    'builtin': False, 'deleted': True}
            else:
                result['config_result'] = {
                    'name': stored.get('name'),
                    'sha256': stored.get('sha256'),
                    'builtin': bool(stored.get('builtin', False)),
                    'deleted': False}
            return result
        return submit(coordinator, command_id, kind, execute, version)
    return runner


def test_receipt_chain_matches_disk_bytes_without_extra_reads(tmp_path):
    store = store_under(tmp_path)
    coordinator = Coordinator(LifecycleDouble())
    run = mutate_via(coordinator, store)

    created = run('create_config', 'rc-create',
                  lambda: store.create(controller=OWNER, command_id='rc-1',
                                       name='receipt.ini', content=ASCII_INI),
                  coordinator.snapshot()['state_version'])
    assert created['error'] is None
    receipt = created['config_result']
    assert receipt == {'name': 'receipt.ini',
                       'sha256': stored_bytes_sha(store, 'receipt.ini'),
                       'builtin': False, 'deleted': False}
    assert 'content' not in receipt

    # The next write chains on the PREVIOUS response only.
    edited = run('edit_config', 'rc-edit',
                 lambda: store.edit(controller=OWNER, command_id='rc-2',
                                    name='receipt.ini', content=UNICODE_INI,
                                    expected_sha256=receipt['sha256']),
                 created['state_version'])
    assert edited['error'] is None
    edited_receipt = edited['config_result']
    assert edited_receipt['sha256'] == stored_bytes_sha(store, 'receipt.ini')
    assert edited_receipt['sha256'] != receipt['sha256']  # non-ASCII changed bytes

    # A no-op edit (same bytes) returns the SAME actual identity.
    noop = run('edit_config', 'rc-noop',
               lambda: store.edit(controller=OWNER, command_id='rc-3',
                                  name='receipt.ini', content=UNICODE_INI,
                                  expected_sha256=edited_receipt['sha256']),
               edited['state_version'])
    assert noop['config_result']['sha256'] == edited_receipt['sha256']
    assert noop['config_result']['name'] == 'receipt.ini'

    renamed = run('rename_config', 'rc-rename',
                  lambda: store.rename(controller=OWNER, command_id='rc-4',
                                       name='receipt.ini',
                                       new_name='renamed.ini',
                                       expected_sha256=edited_receipt['sha256']),
                  noop['state_version'])
    assert renamed['config_result'] == {
        'name': 'renamed.ini',
        'sha256': stored_bytes_sha(store, 'renamed.ini'),
        'builtin': False, 'deleted': False}
    assert not (store.custom_root / 'receipt.ini').exists()

    deleted = run('delete_config', 'rc-delete',
                  lambda: store.delete(controller=OWNER, command_id='rc-5',
                                       name='renamed.ini',
                                       expected_sha256=renamed['config_result']['sha256']),
                  renamed['state_version'])
    assert deleted['config_result'] == {
        'name': 'renamed.ini', 'sha256': None,
        'builtin': False, 'deleted': True}


def test_load_config_response_keeps_identity(tmp_path):
    store = store_under(tmp_path)
    coordinator = Coordinator(LifecycleDouble())
    run = mutate_via(coordinator, store)
    created = run('create_config', 'lc-create',
                  lambda: store.create(controller=OWNER, command_id='lc-1',
                                       name='load.ini', content=ASCII_INI),
                  coordinator.snapshot()['state_version'])
    record = store.read('load.ini')

    def execute(coord):
        coord.set_config_identity(
            {'name': 'load.ini', 'sha256': record['sha256'],
             'builtin': False})
        return {'state': coord.snapshot()['state'], 'changed': True,
                'config_identity': {'name': 'load.ini',
                                    'sha256': record['sha256'],
                                    'builtin': False}}
    loaded = submit(coordinator, 'lc-load', 'load_config', execute,
                    created['state_version'])
    assert loaded['config_identity'] == {
        'name': 'load.ini', 'sha256': record['sha256'], 'builtin': False}


def test_failures_and_replays_keep_receipts_honest(tmp_path):
    store = store_under(tmp_path)
    coordinator = Coordinator(LifecycleDouble())
    run = mutate_via(coordinator, store)
    created = run('create_config', 'fr-create',
                  lambda: store.create(controller=OWNER, command_id='fr-1',
                                       name='chain.ini', content=ASCII_INI),
                  coordinator.snapshot()['state_version'])
    original = created['config_result']

    # A CAS failure never fabricates a receipt: the tool surface returns
    # ctx.error_response (no config_result key at all).
    from fakenet.mcp.errors import McpError
    with pytest.raises(McpError) as excinfo:
        submit(coordinator, 'fr-stale', 'edit_config',
               lambda coord: (_ for _ in ()).throw(McpError(
                   'state_conflict', 'stale')), 999999)
    assert excinfo.value.code == 'state_conflict'

    # A rejected mutation (wrong expected sha) raises through the store.
    with pytest.raises(McpError):
        run('edit_config', 'fr-cas',
            lambda: store.edit(controller=OWNER, command_id='fr-2',
                               name='chain.ini', content=ASCII_INI,
                               expected_sha256='not-the-sha'),
            coordinator.snapshot()['state_version'])

    # The file changes afterwards; the SAME command_id replays the ORIGINAL
    # receipt and get_command_status returns that same isolated identity.
    changed = run('edit_config', 'fr-later',
                  lambda: store.edit(controller=OWNER, command_id='fr-3',
                                     name='chain.ini', content=UNICODE_INI,
                                     expected_sha256=original['sha256']),
                  coordinator.snapshot()['state_version'])
    assert changed['config_result']['sha256'] != original['sha256']
    replay = submit(coordinator, 'fr-create', 'create_config',
                    lambda coord: {'changed': False}, 999999)
    assert replay['replayed'] is True
    assert replay['config_result'] == original
    status = coordinator.command_status(
        command_id='fr-create', controller=OWNER, controller_valid=True)
    assert status['status'] == 'completed'
    assert status['response']['config_result'] == original
    status['response']['config_result']['sha256'] = 'tampered'
    again = coordinator.command_status(
        command_id='fr-create', controller=OWNER, controller_valid=True)
    assert again['response']['config_result'] == original
