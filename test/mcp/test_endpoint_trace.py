import copy
import json
from pathlib import Path

import pytest

from fakenet.mcp.endpoint_trace import complete_trace, trace_action_script


def native_statistics():
    return json.loads((Path(__file__).parent / 'fixtures' / 'native_trace_statistics.json').read_text())


def test_native_sequential_trace_with_windows_shutdown_flag_is_complete():
    d = native_statistics()
    assert complete_trace(d['start'], d['stop'], d['after_stop'], d['size'])


@pytest.mark.parametrize('bad', ['event_loss', 'buffer_loss', 'realtime_loss', 'missing_counter',
                                 'still_running', 'identity_drift', 'path_drift', 'circular',
                                 'file_limit', 'invalid_boolean', 'unknown_stop_result'])
def test_trace_coverage_rejects_loss_gaps_or_identity_changes(bad):
    d = copy.deepcopy(native_statistics())
    if bad == 'event_loss':
        d['stop']['EventsLost'] = 1
    elif bad == 'buffer_loss':
        d['stop']['LogBuffersLost'] = 1
    elif bad == 'realtime_loss':
        d['stop']['RealTimeBuffersLost'] = 1
    elif bad == 'missing_counter':
        d['stop'].pop('EventsLost')
    elif bad == 'still_running':
        d['after_stop']['Code'] = 0
    elif bad == 'identity_drift':
        d['stop']['SessionGuid'] = 'another-session'
    elif bad == 'path_drift':
        d['stop']['LogFileName'] = r'C:\unrelated.etl'
    elif bad == 'circular':
        d['start']['LogFileMode'] = d['stop']['LogFileMode'] = 0x00400002
    elif bad == 'file_limit':
        d['size'] = 16 * 1024 * 1024
    elif bad == 'invalid_boolean':
        d['stop']['EventsLost'] = False
    elif bad == 'unknown_stop_result':
        d['after_stop']['Code'] = 5
    assert not complete_trace(d['start'], d['stop'], d['after_stop'], d['size'])


def test_trace_actions_cannot_select_arbitrary_sessions_or_operations():
    with pytest.raises(ValueError):
        trace_action_script('stop', 'foreign-session-name', r'C:\trace.etl')
    with pytest.raises(ValueError):
        trace_action_script('delete', '00000000-0000-0000-0000-000000000001', r'C:\trace.etl')
