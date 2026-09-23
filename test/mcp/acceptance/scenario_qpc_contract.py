"""Explicit diverter_stop QPC interval proof from sealed originals only."""
import json
from pathlib import Path
import tempfile

import scenario_qpc_offline as offline
import sst_fault_evidence as fault

MODE = 'native-qpc-complete-v1'
SCHEMA = 'sst.fault-evidence.case.v3'


def _positive(value, label):
    if type(value) is not int or value <= 0:
        raise fault.EvidenceError(label + ' must be a positive integer')
    return value


def _ordered_clock(sample, label, frequency, pid):
    if (not isinstance(sample, dict) or sample.get('supported') is not True
            or sample.get('api') != 'GetSystemTimePreciseAsFileTime'
            or sample.get('pid') != pid or sample.get('qpc_frequency') != frequency):
        raise fault.EvidenceError(label + ' native clock API/PID/frequency differs')
    a = _positive(sample.get('qpc_before'), label + '.qpc_before')
    b = _positive(sample.get('qpc_after'), label + '.qpc_after')
    _positive(sample.get('filetime_100ns'), label + '.filetime')
    tid = _positive(sample.get('thread_id'), label + '.thread_id')
    if a > b:
        raise fault.EvidenceError(label + ' QPC bracket reversed')
    return a, b, tid


def evaluate(base_path, evidence_root, export, *, require_complete=True):
    """Reconstruct identity and all native targets; never consume a PASS flag."""
    base_path, evidence_root, export = map(Path, (base_path, evidence_root, export))
    with tempfile.TemporaryDirectory() as temporary:
        derived = offline.derive(base_path, evidence_root, export,
                                 Path(temporary) / 'derived')
    if require_complete and derived['source_windows_status'] != 'COMPLETE_DIAGNOSTIC_ONLY':
        raise fault.EvidenceError('original Windows QPC diagnostic did not complete')
    base = json.loads(base_path.read_text(encoding='utf-8'))
    if (base.get('schema') != 'sst.fault-evidence.case.v2'
            or base.get('fault') != 'diverter_stop'
            or base.get('session', {}).get('observation_kind') != 'tcpip_etw'):
        raise fault.EvidenceError('QPC mode requires diverter_stop/tcpip_etw base')
    evidence = fault.Evidence(evidence_root, base['files'])
    capture = evidence.read(base['session']['connection_capture']['metadata_ref'])
    action = evidence.read(base['trigger']['upper_ref'])
    identity = derived['identity']
    pid = _positive(identity['managed_pid'], 'managed PID')
    frequency = _positive(identity['qpc_frequency'], 'QPC frequency')
    before, after = (action['clock_observations'][name] for name in ('before', 'after'))
    ba, bb, bt = _ordered_clock(before, 'action.before', frequency, pid)
    aa, ab, at = _ordered_clock(after, 'action.after', frequency, pid)
    if bt != at or bb > aa or before['filetime_100ns'] > after['filetime_100ns']:
        raise fault.EvidenceError('action same-thread/before-after order changed')
    if (action.get('pid') != pid or action.get('run_id') != base['run_id']
            or action.get('nonce') != base['nonce']):
        raise fault.EvidenceError('action run/PID/nonce differs')
    cb, ca = (capture.get('clock_' + name) for name in ('before', 'after'))
    if not isinstance(cb, dict) or not isinstance(ca, dict):
        raise fault.EvidenceError('capture QPC brackets missing')
    cb0, cb1 = (_positive(cb.get(name), 'capture.before.' + name) for name in ('q0', 'q1'))
    ca0, ca1 = (_positive(ca.get(name), 'capture.after.' + name) for name in ('q0', 'q1'))
    if not cb0 <= cb1 <= ca0 <= ca1:
        raise fault.EvidenceError('capture QPC brackets reversed')
    samples = [x['raw_qpc'] for x in derived['targets']] + [ba, bb, aa, ab]
    if any(type(x) is not int or not cb1 <= x <= ca0 for x in samples):
        raise fault.EvidenceError('native event/action outside capture QPC range')
    established = [x for x in derived['targets'] if x['kind'] in
                   ('connect completed', 'accept completed')]
    terminal = [x for x in derived['targets'] if x['terminal']]
    if (sum(x['kind'] == 'connect completed' for x in established) != 1
            or sum(x['kind'] == 'accept completed' for x in established) > 1):
        raise fault.EvidenceError('native establishment set incomplete')
    if not terminal:
        raise fault.EvidenceError('native terminal set empty')
    latest = max(x['raw_qpc'] for x in established)
    earliest = min(x['raw_qpc'] for x in terminal)
    left, right = ba - latest, earliest - ab
    utc = derived['conservative_utc_bounds_ns']
    # Recompute probe first-termination lower bound from the original, not
    # the derived status or the ETW end chosen by the old full UTC verdict.
    resolution = base['clock']['resolution_ns']
    probe_end = offline.conservative_time_bounds(
        evidence.read(base['session']['end_ref']), resolution)[0]
    utc_values = [utc[k] for k in ('session_begin_upper', 'trigger_lower',
                                   'trigger_upper')]
    utc_ok = utc_values[0] <= utc_values[1] <= utc_values[2] <= probe_end
    return {'schema': 'sst.qpc-contract.v1', 'mode': MODE,
            'identity': identity, 'target_count': len(derived['targets']),
            'target_seqs': [x['seq'] for x in derived['targets']],
            'source_windows_status': derived['source_windows_status'],
            'capture_qpc': {'before': [cb0, cb1], 'after': [ca0, ca1]},
            'action_qpc': {'before': [ba, bb], 'after': [aa, ab], 'thread_id': bt},
            'native_qpc': {'latest_establishment': latest,
                           'earliest_terminal': earliest,
                           'establishment_to_action_ticks': left,
                           'action_to_terminal_ticks': right,
                           'passed': left > 1 and right > 1},
            'utc': {'session_begin_upper': utc_values[0],
                    'trigger_lower': utc_values[1], 'trigger_upper': utc_values[2],
                    'probe_end_lower': probe_end, 'passed': utc_ok},
            'passed': utc_ok and left > 1 and right > 1}
