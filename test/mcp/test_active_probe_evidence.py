"""Reject plausible but insufficient native active-probe evidence."""
import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
from run_active_probe import probe_loss_observation


def observations():
    return [
        {'event': 'request', 'monotonic': 10, 'frame': {'run_id': 'current', 'seq': 2, 'kind': 'health'}},
        {'event': 'response', 'monotonic': 10.1, 'frame': {'run_id': 'current', 'seq': 2,
         'result': {'probe': False, 'init_evidence': True, 'listeners': [{'alive': True}]}}},
        {'event': 'health_state', 'monotonic': 10.2, 'frame': {'run_id': 'current', 'state': 'failed',
         'identity': {'pid': 9, 'creation_time': '100'}}},
    ]


@pytest.mark.parametrize('bad', ['dead_listener', 'missing_listener', 'wrong_run', 'wrong_seq',
                                 'wrong_child', 'failure_before_response', 'late_failure'])
def test_active_probe_rejects_invalid_evidence(bad):
    rows = copy.deepcopy(observations())
    if bad == 'dead_listener':
        rows[1]['frame']['result']['listeners'][0]['alive'] = False
    elif bad == 'missing_listener':
        rows[1]['frame']['result'].pop('listeners')
    elif bad == 'wrong_run':
        rows[1]['frame']['run_id'] = 'previous'
    elif bad == 'wrong_seq':
        rows[1]['frame']['seq'] = 1
    elif bad == 'wrong_child':
        rows[2]['frame']['identity']['creation_time'] = '99'
    elif bad == 'failure_before_response':
        rows[2]['monotonic'] = 10.05
    elif bad == 'late_failure':
        rows[2]['monotonic'] = 14.01
    assert not all(probe_loss_observation(rows, 'current', {'pid': 9, 'creation_time': '100'}))


def test_active_probe_matches_same_run_live_listeners_and_child_failure():
    assert probe_loss_observation(observations(), 'current', {'pid': 9, 'creation_time': '100'}) == (True, True)
