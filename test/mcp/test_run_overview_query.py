# Copyright 2026 Google LLC
"""get_run_overview aggregate over the guarded HTTP endpoint.

Drives the real transport (guard + coordinator + store + lifecycle double)
with the diagnostic IPC edge replaced by the real diagnostic task code
(the worker function the spawned process runs); no Windows, no VM. Covers
the five contract classes: current run, explicit historical run,
no_current_run, a mutation landing mid-aggregate (consistent=false), and
one failing sub-query keeping the other results with partial=true.
"""

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

mcp = pytest.importorskip('mcp')

from fakenet.mcp import diagnostic_tasks, diagnostic_process, server as server_module  # noqa: E402
from fakenet.mcp.config import ServiceConfig  # noqa: E402

CONTROLLER = '11111111-2222-4333-8444-555555555555'
VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
HISTORICAL_RUN = '44444444-aaaa-4bbb-8ccc-000000000004'


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint(tmp_path_factory):
    programdata = tmp_path_factory.mktemp('overview-programdata')
    os.environ['FAKENETNG_MCP_PROGRAMDATA'] = str(programdata)
    os.environ['FAKENETNG_MCP_TESTDOUBLE'] = '1'
    port = _free_port()
    config = ServiceConfig(listen_ip='127.0.0.1', listen_port=port,
                           allowed_host_ips=['127.0.0.1'])
    ready = threading.Event()
    failure = {}

    def serve():
        try:
            server_module.run_server(config, ready_event=ready)
        except BaseException:
            import traceback
            failure['error'] = traceback.format_exc()
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(timeout=30), failure
    assert not failure, failure
    time.sleep(0.3)
    yield 'http://127.0.0.1:%d/mcp' % port
    server_module.request_shutdown()
    os.environ.pop('FAKENETNG_MCP_PROGRAMDATA', None)
    os.environ.pop('FAKENETNG_MCP_TESTDOUBLE', None)


@pytest.fixture()
def local_diagnostics(monkeypatch):
    """Run the real diagnostic task code instead of the Windows-only IPC."""
    def call(self, operation, payload, deadline, wait=None):
        return diagnostic_tasks.execute(operation, payload, deadline)
    monkeypatch.setattr(diagnostic_process.DiagnosticOwner, 'call', call)


def envelope():
    return {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientInfo': {'name': 'pytest-overview',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def call(endpoint_url, tool, arguments=None, controller=CONTROLLER):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments or {},
                       '_meta': envelope()}}
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/call',
        'Mcp-Name': tool,
    }
    if controller is not None:
        headers['X-FakeNet-Controller-ID'] = controller
    request = urllib.request.Request(endpoint_url,
                                     data=json.dumps(body).encode('utf-8'),
                                     method='POST', headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode('utf-8', 'replace')
    outer = json.loads(raw)
    if outer.get('error'):
        return {'transport_error': outer['error']}
    return json.loads(outer['result']['content'][0]['text'])


def seed_artifacts(run_id):
    from pathlib import Path

    from fakenet.mcp import artifacts as artifacts_module
    root = Path(os.environ['FAKENETNG_MCP_PROGRAMDATA']) / \
        'FakeNet-NG-MCP' / 'artifacts'
    run_dir = root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, blob in (('capture.pcap', b'pcap-bytes'),
                       ('run.log', b'log-bytes'),
                       ('report.html', b'<html>r</html>')):
        path = run_dir / name
        path.write_bytes(blob)
        paths.append(path)
    artifacts_module.write_publication(run_dir, paths)
    paths = []
    for name, blob in (('capture.pcap', b'pcap-bytes'),
                       ('run.log', b'log-bytes'),
                       ('report.html', b'<html>r</html>')):
        path = os.path.join(run_dir, name)
        with open(path, 'wb') as handle:
            handle.write(blob)
        paths.append(path)
    from pathlib import Path
    artifacts_module.write_publication(Path(run_dir), [Path(p) for p in paths])


def start_run(endpoint_url, name):
    version = call(endpoint_url, 'get_status')['state_version']
    created = call(endpoint_url, 'create_config',
                   {'name': name, 'content': VALID_INI,
                    'command_id': 'ov-create-%s' % name,
                    'expected_state_version': version})
    assert created['error'] is None
    loaded = call(endpoint_url, 'load_config',
                  {'name': name, 'command_id': 'ov-load-%s' % name,
                   'expected_state_version': created['state_version']})
    assert loaded['error'] is None
    started = call(endpoint_url, 'start',
                   {'command_id': 'ov-start-%s' % name,
                    'expected_state_version': loaded['state_version']})
    assert started['error'] is None
    return started


def test_no_current_run_overview(endpoint, local_diagnostics):
    payload = call(endpoint, 'get_run_overview')
    assert payload['error'] is None
    assert payload['selected_run_id'] is None
    assert payload['selection'] == 'no_current_run'
    assert payload['events_query']['events'] == []
    assert payload['events_query']['selection_note'] == 'no_current_run'
    assert payload['artifacts_query']['artifacts'] == []
    assert payload['artifacts_query']['matched_count'] == 0
    assert payload['artifacts_query']['selection_note'] == 'no_current_run'
    assert payload['consistent'] is True
    assert payload['partial'] is False
    assert payload['service_status']['run_id'] is None


def test_current_run_overview(endpoint, local_diagnostics):
    started = start_run(endpoint, 'overview-current.ini')
    run_id = started['run_id']
    seed_artifacts(run_id)
    # One event explicitly tagged with the run's own id: only such events
    # match the run filter — command events carry no run_id and must never
    # be guessed into membership.
    coordinator = server_module._active_context.coordinator
    coordinator._events.record('run.note', run_id=run_id,
                               detail='seeded for the aggregate query')
    payload = call(endpoint, 'get_run_overview')
    assert payload['selection'] == 'current'
    assert payload['selected_run_id'] == run_id
    assert payload['consistent'] is True
    assert payload['partial'] is False
    events = payload['events_query']['events']
    assert [event['kind'] for event in events] == ['run.note']
    assert all(event['run_id'] == run_id for event in events)
    assert all('epoch' in event and 'seq' in event for event in events)
    assert payload['events_query']['next_cursor']
    # Artifacts sub-query flows through the diagnostic task code with the
    # run filter applied end to end.
    artifacts = payload['artifacts_query']['artifacts']
    assert payload['artifacts_query']['matched_count'] == len(artifacts) == 3
    assert all(run_id in row['path'] for row in artifacts)
    assert all(row['complete'] for row in artifacts)
    # Cleanup: stop the run so later cases start from a clean current state.
    version = call(endpoint, 'get_status')['state_version']
    stopped = call(endpoint, 'stop', {'command_id': 'ov-stop-current',
                                      'expected_state_version': version})
    assert stopped['error'] is None



def test_explicit_historical_run_keeps_current_status(endpoint, local_diagnostics):
    started = start_run(endpoint, 'overview-hist.ini')
    run_id = started['run_id']
    seed_artifacts(run_id)
    version = call(endpoint, 'get_status')['state_version']
    stopped = call(endpoint, 'stop', {'command_id': 'ov-stop-hist',
                                      'expected_state_version': version})
    assert stopped['error'] is None
    # After the stop there is no current run; the explicit historical run is
    # queried without inheriting any current health attribution.
    payload = call(endpoint, 'get_run_overview', {'run_id': run_id})
    assert payload['selection'] == 'explicit'
    assert payload['selected_run_id'] == run_id
    assert payload['service_status']['run_id'] is None
    assert payload['service_status']['state'] == 'stopped'
    assert 'health' in payload['service_status']
    for field in ('failure_reason', 'config_identity', 'last_run_outcome',
                  'controller'):
        assert field in payload['service_status']
    # Command events carry no run_id of their own, so the run filter matches
    # nothing — that is correct membership, not an error.
    assert payload['events_query']['events'] == []
    assert payload['events_query']['error'] is None
    # The historical run's artifacts are still reachable explicitly.
    assert payload['artifacts_query']['matched_count'] == 3
    assert payload['partial'] is False


def test_mutation_during_aggregate_reports_inconsistent(endpoint, local_diagnostics,
                                                         monkeypatch):
    started = start_run(endpoint, 'overview-race.ini')
    run_id = started['run_id']
    seed_artifacts(run_id)
    real_call = diagnostic_process.DiagnosticOwner.call

    def racing_call(self, operation, payload, deadline, wait=None):
        if operation == 'list-artifacts':
            # A real accepted mutation lands between the overview's two
            # status snapshots: the version must report the change. The
            # run's owning controller submits it (a second controller
            # would be rejected, which is a different contract).
            coordinator = server_module._active_context.coordinator
            coordinator.submit(
                command_id='ov-racer', expected_version=(
                    coordinator.snapshot()['state_version']),
                controller=CONTROLLER,
                controller_valid=True, kind='edit', describe={},
                execute=lambda coord: {'changed': True})
        return real_call(self, operation, payload, deadline, wait)

    monkeypatch.setattr(diagnostic_process.DiagnosticOwner, 'call', racing_call)
    try:
        payload = call(endpoint, 'get_run_overview')
        assert payload['consistent'] is False
        assert (payload['status_before_version']
                != payload['status_after_version'])
        # The sub-results are still delivered; only consistency is withdrawn.
        assert payload['artifacts_query']['matched_count'] == 3
        assert payload['partial'] is False
    finally:
        version = call(endpoint, 'get_status')['state_version']
        stopped = call(endpoint, 'stop', {'command_id': 'ov-stop-race',
                                          'expected_state_version': version})
        assert stopped['error'] is None
    assert run_id


def test_one_subquery_failure_keeps_other_results(endpoint):
    # No diagnostic monkeypatch: on this host the real IPC edge fails fast,
    # which exercises the partial path — the events side must survive.
    started = start_run(endpoint, 'overview-partial.ini')
    run_id = started['run_id']
    seed_artifacts(run_id)
    try:
        payload = call(endpoint, 'get_run_overview')
        assert payload['artifacts_query']['error'] is not None
        assert payload['artifacts_query']['artifacts'] == []
        assert payload['events_query']['error'] is None
        assert 'events' in payload['events_query']
        assert payload['partial'] is True
        assert 'artifacts_query' in payload['error']
    finally:
        version = call(endpoint, 'get_status')['state_version']
        stopped = call(endpoint, 'stop', {
            'command_id': 'ov-stop-partial',
            'expected_state_version': version})
        assert stopped['error'] is None
    assert run_id


def test_invalid_event_cursor_fails_events_keeps_artifacts(endpoint, local_diagnostics):
    started = start_run(endpoint, 'overview-cursor.ini')
    run_id = started['run_id']
    seed_artifacts(run_id)
    try:
        payload = call(endpoint, 'get_run_overview',
                       {'event_cursor': 'garbage-cursor'})
        assert payload['events_query']['error']['code'] == 'invalid_request'
        assert payload['events_query']['events'] == []
        assert payload['artifacts_query']['error'] is None
        assert payload['artifacts_query']['matched_count'] == 3
        assert payload['partial'] is True
    finally:
        version = call(endpoint, 'get_status')['state_version']
        stopped = call(endpoint, 'stop', {
            'command_id': 'ov-stop-cursor',
            'expected_state_version': version})
        assert stopped['error'] is None
    assert run_id
