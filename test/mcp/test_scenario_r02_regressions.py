"""R02 regression seams, including sealed historical refusal originals."""
import copy
import json
from pathlib import Path
import pytest
from test_scenario_suite import suite
from scenario_refusal_test_fixture import match_restart_refusal, nonmatch_refusal

ROOT = Path(__file__).resolve().parents[2] / 'Logs/fakenetng-mcp/final100-20260920/formal-post-snapshot-20260930-22'

def original():
    path = ROOT / 'results/scenario-sst-043.json'
    if not path.exists():
        pytest.skip('sealed sst-043 originals unavailable in this checkout')
    return json.loads(path.read_text(encoding='utf-8'))

def test_approved_restart_refusal_from_original_bytes():
    result = original()
    assert suite.refusal_recheck_issues(result, ROOT) == []
    assert suite.result_issues(result, ROOT) == []
    from scenario_capture_view import validate_shared_views
    validate_shared_views(result, ROOT)


def test_synthetic_approved_restart_refusal(tmp_path):
    result = match_restart_refusal(tmp_path)
    assert suite.refusal_recheck_issues(result, tmp_path) == []
    from scenario_capture_view import validate_shared_views
    validate_shared_views(result, tmp_path)

@pytest.mark.parametrize('change', ['code', 'message', 'state', 'changed', 'run_id', 'other_call', 'family', 'healthy', 'extra_run', 'restart_success', 'version', 'status_reason'])
def test_restart_refusal_does_not_waive_arbitrary_failure(tmp_path, change):
    result = match_restart_refusal(tmp_path)
    restart = next(c for c in result['interface_calls'] if c['tool'] == 'restart')
    value = json.loads(restart['response']['result']['content'][0]['text'])
    if change == 'code': value['error']['code'] = 'operation_busy'
    elif change == 'message': value['error']['message'] = 'arbitrary failure'
    elif change == 'state': value['state'] = 'healthy'
    elif change == 'changed': value['changed'] = True
    elif change == 'run_id': value['run_id'] = 'published-run'
    elif change == 'other_call': result['interface_calls'][0]['ok'] = False
    elif change == 'family': result['traffic_evidence']['runtime_profile']['bucket'] = 'B4'
    elif change == 'healthy': result['health_trace']['samples'] = [{'state': 'healthy'}]
    elif change == 'restart_success': restart['ok'] = True
    elif change == 'version': value['state_version'] += 1
    elif change == 'status_reason': result['run_chain'][0]['refusal_status_samples'][0]['failure_reason'] = 'other failure'
    elif change == 'extra_run': result['run_chain'].append(copy.deepcopy(result['run_chain'][0]))
    restart['response']['result']['content'][0]['text'] = json.dumps(value)
    from scenario_capture_view import validate_shared_views
    with pytest.raises(ValueError):
        validate_shared_views(result, tmp_path)



@pytest.mark.parametrize('interleave', ['before-start', 'restart-window', 'during-start', 'after-healthy'])
@pytest.mark.parametrize('bucket', ['B3', 'B4'])
def test_healthy_restart_releases_every_held_second_probe(interleave, bucket):
    runner = suite.Suite.__new__(suite.Suite)
    seen = []
    runner._signal_engine_ok = lambda capture: seen.append(capture) or {'signaled': True}
    capture = {'probe': 'new-attempt/run-02/probe.jsonl'}
    assert runner._release_restart_engine({'state': 'healthy'}, {'bucket': bucket, 'interleave': interleave}, capture) == {'signaled': True}
    assert seen == [capture]

@pytest.mark.parametrize('state', ['stopped', 'failed', 'starting', None])
def test_unsuccessful_restart_never_releases_probe(state):
    runner = suite.Suite.__new__(suite.Suite)
    runner._signal_engine_ok = lambda _: pytest.fail('unhealthy restart released traffic')
    assert runner._release_restart_engine({'state': state}, {'bucket': 'B4', 'interleave': 'before-start'}, {}) is None


def test_bound_file_records_use_portable_producer_paths(tmp_path):
    path = tmp_path / 'nested' / 'raw.json'
    path.parent.mkdir()
    path.write_bytes(b'raw bytes')
    assert suite.file_record(path, tmp_path)['path'] == 'nested/raw.json'


@pytest.mark.parametrize('change', ['plan_missing', 'plan_reordered', 'controller', 'start_identity', 'file_hash', 'residue', 'receipt_missing'])
def test_complete_contract_and_recovery_are_required(tmp_path, change):
    result = match_restart_refusal(tmp_path)
    if change == 'plan_missing': result['interface_calls'].pop(0)
    elif change == 'plan_reordered': result['interface_calls'][0:2] = result['interface_calls'][1::-1]
    elif change == 'controller': result['run_chain'][0]['refusal_status_samples'][0]['controller'] = 'wrong-owner'
    elif change == 'start_identity': result['run_chain'][0]['start_response'] = dict(result['run_chain'][0]['start_response'], run_id='other')
    elif change == 'file_hash': (tmp_path/'five-sections-after.json').write_text('{}')
    elif change == 'residue': result['recovery']['cleanup_errors'] = ['writer remains']
    elif change == 'receipt_missing': del result['interface_calls'][15]['response']
    assert suite.refusal_recheck_issues(result, tmp_path)


def test_nonmatch_requires_exact_synthetic_native_a_chain(tmp_path):
    result = nonmatch_refusal(tmp_path)
    assert suite.refusal_recheck_issues(result, tmp_path) == []
    for change in ('nonce','tuple','pid_creation','healthy_event','missing_event','missing_proof'):
        bad = copy.deepcopy(result)
        if change == 'nonce': bad['traffic_evidence']['nonce']='wrong'
        elif change == 'tuple': bad['traffic_evidence']['runtime_profile']['probe_target']['host']='203.0.113.1'
        elif change == 'pid_creation': bad['run_chain'][0]['expected_refusal']['proof']['creation_ticks'] += 1
        elif change == 'missing_proof': del bad['run_chain'][0]['expected_refusal']['proof']
        else:
            call = next(c for c in bad['interface_calls'] if c['tool']=='get_events')
            value = json.loads(call['response']['result']['content'][0]['text'])
            if change == 'missing_event': value['events']=[]
            else: value['events'].append(dict(value['events'][0],state='healthy'))
            call['response']['result']['content'][0]['text']=json.dumps(value)
        assert suite.refusal_recheck_issues(bad,tmp_path),change


def test_ordinary_healthy_restart_still_requires_two_runs(tmp_path):
    from scenario_capture_view import validate_shared_views
    result = match_restart_refusal(tmp_path)
    run = result['run_chain'][0]
    del run['expected_refusal']
    run['start_response']['state']='healthy'
    with pytest.raises(ValueError,match='exactly two'):
        validate_shared_views(result,tmp_path)
