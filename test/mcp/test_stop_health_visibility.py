from types import SimpleNamespace

from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.snapshot import StateSnapshot
from fakenet.mcp.supervisor import RealSupervisor


def test_stop_does_not_report_healthy_during_full_restoration(tmp_path):
    root = tmp_path / 'baselines'
    root.mkdir()
    snapshot = StateSnapshot(tmp_path / 'state.json')
    marker = dict(run_id='run1', controller_id='owner', state_version=2,
                  command_id='start1', config_sha256='a'*64,
                  baseline_path=str(root/'run1.json'), needs_recovery=True)
    snapshot.write(**marker)
    observations = []
    def check(*a, **kw):
        observations.append(coord.snapshot())
        return {}
    baseline = SimpleNamespace(root=root, compensate=check, full_audit_diff=check)
    runner = RealSupervisor(snapshot=snapshot, baseline_store=baseline)
    coord = Coordinator(runner)
    coord.restore_responsibility(marker, 'healthy')
    runner._health_cache = dict(process_alive=True, init_evidence=True, probe=True,
                               final_filter='outbound and ip')
    result = runner.stop(coord)
    assert result['state'] == 'stopped'
    assert observations
    assert all(x['state'] == 'recovering' and not x['health']['probe'] for x in observations)
    assert runner._last_final_filter == 'outbound and ip'


def test_late_health_result_cannot_reopen_a_stopping_run():
    runner = RealSupervisor()
    coord = Coordinator(runner)
    runner._coordinator = coord
    child = object()
    runner._fakenet = child
    runner._health_stop.set()
    coord.update_health_state('recovering')
    assert not runner._publish_health(child, 'healthy', dict(
        process_alive=True, init_evidence=True, probe=True))
    assert coord.snapshot()['state'] == 'recovering'


def test_restoration_failure_collects_incident_and_keeps_responsibility(tmp_path):
    for phase in ('audit', 'compensation'):
        root = tmp_path / phase / 'baselines'
        root.mkdir(parents=True)
        snapshot = StateSnapshot(root.parent / 'state.json')
        marker = dict(run_id='run1', controller_id='owner', state_version=2,
                      command_id='stop1', config_sha256='a'*64,
                      baseline_path=str(root/'run1.json'), needs_recovery=True)
        snapshot.write(**marker)
        def compensate(*args):
            if phase == 'compensation':
                raise RuntimeError('actual restoration command failed')
        baseline = SimpleNamespace(root=root, compensate=compensate,
                                   full_audit_diff=lambda *a, **k: {'listen_ports': {'changed': True}})
        runner = RealSupervisor(snapshot=snapshot, baseline_store=baseline)
        coord = Coordinator(runner)
        coord.restore_responsibility(marker, 'failed')
        evidence = []
        runner._collect_incident = lambda reason, deadline=None: evidence.append((reason, deadline))
        result = runner.stop(coord)
        assert result['state'] == 'failed'
        assert result['last_run_outcome'] == 'failed'
        assert snapshot.read()[0]['needs_recovery']
        assert len(evidence) == 1 and evidence[0][1] is not None
        assert ('restoration audit failed' if phase == 'audit' else 'restoration command failed') in evidence[0][0]


def test_stop_transport_failure_after_tree_exit_does_not_dump_dead_target(tmp_path):
    for error, members, exit_code, prior_run, expected_incidents in (
            (TimeoutError('managed IPC response timeout'), [], 0, 'run1', 0),
            (EOFError('managed pipe closed'), [], 0, 'run1', 0),
            (TimeoutError('managed IPC response timeout'), [], 0, None, 1),
            (TimeoutError('managed IPC response timeout'), [], 0, 'old-run', 1),
            (TimeoutError('managed IPC response timeout'), [42], None, 'run1', 1),
            (TimeoutError('managed IPC response timeout'), [43], 0, 'run1', 1),
            (ValueError('wrong run response'), [], 0, 'run1', 1)):
        root = tmp_path / str(expected_incidents) / type(error).__name__ / str(members)
        root.mkdir(parents=True, exist_ok=True)
        snapshot = StateSnapshot(root / 'state.json')
        marker = dict(run_id='run1', controller_id='owner', state_version=2,
                      command_id='stop1', config_sha256='a'*64,
                      baseline_path=str(root/'run1.json'), needs_recovery=True)
        snapshot.write(**marker)
        baseline = SimpleNamespace(root=root, compensate=lambda *a: None,
                                   full_audit_diff=lambda *a, **k: {})
        runner = RealSupervisor(snapshot=snapshot, baseline_store=baseline)
        coord = Coordinator(runner)
        coord.restore_responsibility(marker, 'failed')
        live_members = list(members)
        def request(kind, **kwargs):
            if kind == 'stacks':
                return {'stacks': 'live managed stacks'}
            raise error
        child = SimpleNamespace(request=request, identity={'pid': 42, 'creation_time': '123'},
                                job=SimpleNamespace(members=lambda: list(live_members), poll=lambda: exit_code),
                                terminate=lambda deadline: live_members.clear(), close=lambda: None)
        runner._fakenet = child
        if prior_run:
            runner._completed_failure_evidence = (prior_run, dict(child.identity), str(error))
        incidents = []
        runner._collect_incident = lambda reason, deadline=None: incidents.append(reason)
        result = runner.stop(coord)
        assert result['state'] == 'stopped'
        assert result['last_run_outcome'] == 'failed'
        assert len(incidents) == expected_incidents
        assert not snapshot.read()[0]['needs_recovery']


def test_tree_exit_during_incident_preparation_reuses_same_complete_failure(tmp_path, monkeypatch):
    from fakenet.mcp import baseline, incident, incident_task, service_stop
    runner = RealSupervisor(artifacts_root=tmp_path)
    runner._marker = {'run_id': 'run1', 'config_sha256': 'a'*64}
    runner._baseline_store = SimpleNamespace(load=lambda run: {'sections': {}})
    runner._coordinator = SimpleNamespace(events=lambda count: [])
    identity = {'pid': 42, 'creation_time': '123'}
    runner._completed_failure_evidence = ('run1', identity, 'managed IPC response timeout')
    monkeypatch.setattr(service_stop, 'process_identity', lambda pid: identity)
    state = {'alive': True}

    def stacks(kind, **kwargs):
        raise TimeoutError('response missing')

    child = SimpleNamespace(identity=identity, pid=42, request=stacks,
                            alive=lambda: state['alive'],
                            job=SimpleNamespace(poll=lambda: None if state['alive'] else 0,
                                                members=lambda: [42] if state['alive'] else []))
    runner._fakenet = child
    directories = {'artifacts': tmp_path, 'baselines': tmp_path / 'baselines'}

    def diagnostic_call(operation, payload, deadline):
        # Preparation is the phase during which the tree exits; collection
        # only happens through the supervisor's boundary decision.
        if operation == 'incident-prepare':
            return incident_task.prepare_stage(payload, directories, tmp_path, deadline)
        assert operation == 'incident-collect', operation
        assert payload.get('abort') is True, 'must not collect a duplicate pack'
        return incident_task.collect_stage(payload, directories, tmp_path, deadline)

    runner._diagnostic_call = diagnostic_call

    def capture(deadline):
        state['alive'] = False
        return {}

    monkeypatch.setattr(baseline, 'capture', capture)

    def forbidden(*args, **kwargs):
        raise AssertionError('must not create a duplicate pack for an already captured exited target')

    monkeypatch.setattr(incident, 'IncidentCollector', forbidden)
    runner._collect_incident_impl('managed IPC response timeout')
    assert not state['alive']
    # The staging file of the aborted collection is not left behind either.
    assert not list((tmp_path / 'run1').glob('incident-staging-*'))
