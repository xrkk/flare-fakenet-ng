# Copyright 2026 Google LLC
"""Coordinator receipt passthrough (unit level; no production mapping copy).

The full production chain (tools mapping, receipts, disk bytes, replays)
is proven over real SDK HTTP in test_config_receipts_http.py. Here the
coordinator alone is exercised: an execute result carrying
config_result/config_identity passes into the cached final response (and
replays/command_status keep it), while unlisted internal result fields
never leak.
"""

import pytest

from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.errors import McpError
from fakenet.mcp.testdouble import LifecycleDouble

OWNER = '11111111-2222-4333-8444-555555555555'
RECEIPT = {'name': 'x.ini', 'sha256': 'a' * 64, 'builtin': False,
           'deleted': False}
IDENTITY = {'name': 'x.ini', 'sha256': 'a' * 64, 'builtin': False}


def submit(coordinator, command_id, execute, version=None):
    return coordinator.submit(
        command_id=command_id,
        expected_version=(coordinator.snapshot()['state_version']
                          if version is None else version),
        controller=OWNER, controller_valid=True, kind='edit',
        describe={}, execute=execute)


def test_whitelisted_receipt_and_identity_pass_through():
    coordinator = Coordinator(LifecycleDouble())

    def execute(coord):
        return {'changed': True, 'config_result': dict(RECEIPT),
                'config_identity': dict(IDENTITY),
                'release_controller': False, 'internal_only': 'secret'}
    response = submit(coordinator, 'passthrough', execute)
    assert response['config_result'] == RECEIPT
    assert response['config_identity'] == IDENTITY
    # Only the two whitelisted extras flow into the cached response.
    assert 'release_controller' not in response
    assert 'internal_only' not in response


def test_replay_and_command_status_keep_original_receipt():
    coordinator = Coordinator(LifecycleDouble())
    submit(coordinator, 'keep', lambda coord: {
        'changed': True, 'config_result': dict(RECEIPT)})
    # A later command changes everything; the old receipt stands.
    submit(coordinator, 'later', lambda coord: {
        'changed': True,
        'config_result': {'name': 'y.ini', 'sha256': 'b' * 64,
                          'builtin': False, 'deleted': False}})
    replay = submit(coordinator, 'keep', lambda coord: {'changed': False},
                    version=999999)
    assert replay['replayed'] is True
    assert replay['config_result'] == RECEIPT
    status = coordinator.command_status(
        command_id='keep', controller=OWNER, controller_valid=True)
    assert status['status'] == 'completed'
    assert status['response']['config_result'] == RECEIPT
    status['response']['config_result']['sha256'] = 'tampered'
    assert coordinator.command_status(
        command_id='keep', controller=OWNER,
        controller_valid=True)['response']['config_result'] == RECEIPT


def test_failed_command_carries_no_receipt():
    coordinator = Coordinator(LifecycleDouble())

    def failing(coord):
        raise McpError('validation_failed', 'no',
                       {'config_result': {'forged': True}})
    with pytest.raises(McpError):
        submit(coordinator, 'fails', failing)
    status = coordinator.command_status(
        command_id='fails', controller=OWNER, controller_valid=True)
    assert status['status'] == 'failed'
    assert status['command_error']['code'] == 'validation_failed'
    # The exception's own payload never masquerades as a committed receipt.
    assert status.get('response') is None
    assert status.get('config_result') is None
