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
    runner._health_cache = dict(process_alive=True, init_evidence=True, probe=True)
    result = runner.stop(coord)
    assert result['state'] == 'stopped'
    assert observations
    assert all(x['state'] == 'recovering' and not x['health']['probe'] for x in observations)


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
