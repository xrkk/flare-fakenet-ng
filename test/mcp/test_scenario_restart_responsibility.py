"""Offline contracts for a lifecycle RPC whose response is delayed or lost."""

import importlib.util
import json
from pathlib import Path
import sys


PATH = Path(__file__).parent / 'acceptance' / 'scenario_suite.py'
SPEC = importlib.util.spec_from_file_location('scenario_restart_responsibility', PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


class ReadOnlyService:
    def __init__(self, events, status=None):
        self.events = events
        self.status = status or {'state': 'healthy', 'run_id': 'run-02'}
        self.calls = []

    def tool(self, name, arguments=None, timeout=120):
        self.calls.append((name, arguments, timeout))
        if name == 'get_events':
            return {'events': self.events}
        if name == 'get_status':
            return self.status
        raise AssertionError('reconciliation sent a mutation')


def test_restart_rpc_budget_covers_server_stop_and_new_start():
    assert suite.lifecycle_rpc_timeout('restart') == 960
    assert suite.lifecycle_rpc_timeout('stop') == 480
    assert suite.lifecycle_rpc_timeout('start') == 480
    assert suite.lifecycle_rpc_timeout('get_status') == 120


def test_delayed_same_restart_response_fits_transport_budget(monkeypatch):
    client = suite.RawMcp('http://127.0.0.1:28788/mcp', controller_id='owner-1')
    seen = []

    def delayed_post(body, headers, timeout):
        seen.append((body['params']['name'], headers['X-FakeNet-Controller-ID'], timeout))
        if timeout < 200:
            raise TimeoutError('simulated 200-second response')
        value = {'state': 'healthy', 'run_id': 'run-02', 'command_id': 'cmd-1'}
        return {'jsonrpc': '2.0', 'id': 1,
                'result': {'content': [{'type': 'text', 'text': json.dumps(value)}]}}, {}

    monkeypatch.setattr(client, '_post', delayed_post)
    result = client.tool_outcome('restart', {'command_id': 'cmd-1'},
                                 timeout=suite.lifecycle_rpc_timeout('restart'))
    assert result['ok'] is True
    assert result['value']['run_id'] == 'run-02'
    assert seen == [('restart', 'owner-1', 960)]


def test_lost_response_requires_same_controller_acceptance_and_terminal_event():
    events = [
        {'kind': 'command.accepted', 'command_id': 'cmd-1',
         'operation': 'restart', 'controller': 'owner-1'},
        {'kind': 'command.completed', 'command_id': 'cmd-1',
         'operation': 'restart', 'state': 'healthy'},
    ]
    service = ReadOnlyService(events)
    result = suite.reconcile_timed_out_command(service, 'cmd-1', 'restart',
                                               'owner-1', budget_seconds=0)
    assert result['settled'] is True
    assert [call[0] for call in service.calls] == ['get_events', 'get_status']
    assert service.calls[0][1] == {'limit': 500}


def test_unknown_or_foreign_command_does_not_authorize_cleanup():
    cases = [
        [],
        [{'kind': 'command.accepted', 'command_id': 'cmd-1',
          'operation': 'restart', 'controller': 'owner-1'}],
        [{'kind': 'command.accepted', 'command_id': 'cmd-1',
          'operation': 'restart', 'controller': 'foreign'},
         {'kind': 'command.completed', 'command_id': 'cmd-1',
          'operation': 'restart'}],
        [{'kind': 'command.accepted', 'command_id': 'cmd-1',
          'operation': 'restart', 'controller': 'owner-1'},
         {'kind': 'command.completed', 'command_id': 'other',
          'operation': 'restart'}],
        [{'kind': 'command.accepted', 'command_id': 'cmd-1',
          'operation': 'restart', 'controller': 'owner-1'},
         {'kind': 'command.completed', 'command_id': 'cmd-1',
          'operation': 'stop'}],
    ]
    for events in cases:
        service = ReadOnlyService(events)
        result = suite.reconcile_timed_out_command(service, 'cmd-1', 'restart',
                                                   'owner-1', budget_seconds=0)
        assert result['settled'] is False
        assert [call[0] for call in service.calls] == ['get_events', 'get_status']


def test_failed_original_command_is_terminal_but_not_success():
    events = [
        {'kind': 'command.accepted', 'command_id': 'cmd-1',
         'operation': 'restart', 'controller': 'owner-1'},
        {'kind': 'command.failed', 'command_id': 'cmd-1',
         'operation': 'restart', 'reason': 'server failure'},
    ]
    result = suite.reconcile_timed_out_command(ReadOnlyService(events), 'cmd-1',
                                               'restart', 'owner-1', budget_seconds=0)
    assert result['settled'] is True
    assert result['samples'][0]['terminal_event']['kind'] == 'command.failed'


def test_terminal_event_during_recovery_still_retains_cleanup_responsibility():
    events = [
        {'kind': 'command.accepted', 'command_id': 'cmd-1',
         'operation': 'restart', 'controller': 'owner-1'},
        {'kind': 'command.completed', 'command_id': 'cmd-1',
         'operation': 'restart'},
    ]
    service = ReadOnlyService(events, {'state': 'recovering',
                                       'controller': 'owner-1', 'run_id': 'run-01'})
    result = suite.reconcile_timed_out_command(service, 'cmd-1', 'restart',
                                               'owner-1', budget_seconds=0)
    assert result['settled'] is False
    assert result['samples'][0]['terminal_status_ok'] is False


def test_read_only_observation_failure_keeps_command_unknown():
    class UnreachableService:
        def tool(self, name, arguments=None, timeout=120):
            raise TimeoutError('read-only channel unavailable')

    result = suite.reconcile_timed_out_command(
        UnreachableService(), 'cmd-1', 'restart', 'owner-1', budget_seconds=0)
    assert result['settled'] is False
    assert result['samples'][0]['read_error'] == "TimeoutError('read-only channel unavailable')"
