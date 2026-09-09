import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import replay_observation
import run_p02_acc


@pytest.mark.parametrize('bad', ['replayed-command', 'missing-recovery', 'uncleared-marker'])
def test_replay_observation_rejects_incomplete_or_contradictory_evidence(monkeypatch, bad):
    marker = {'command_id': 'old-start', 'run_id': 'run', 'needs_recovery': False}
    events = [{'kind': 'recovery', 'state': 'stopped'}]
    if bad == 'replayed-command':
        events.append({'kind': 'command.accepted', 'command_id': 'old-start'})
    if bad == 'missing-recovery':
        events = []
    if bad == 'uncleared-marker':
        marker['needs_recovery'] = True
    monkeypatch.setattr(run_p02_acc, 'status', lambda _: {'state': 'stopped', 'run_id': None})
    monkeypatch.setattr(run_p02_acc, 'call', lambda *a, **k: {'events': events, 'error': None})
    ticks = iter([0, 11, 12])
    monkeypatch.setattr(replay_observation.time, 'monotonic', lambda: next(ticks))
    class Channel:
        def powershell(self, *a, **k):
            return {'output': json.dumps(marker)}
    class Writer:
        def add_evidence(self, *a):
            pass
    assert not replay_observation.observe_no_replay('base', Channel(), Writer(), 'test',
        {'command_id': 'old-start', 'run_id': 'run', 'needs_recovery': True})
