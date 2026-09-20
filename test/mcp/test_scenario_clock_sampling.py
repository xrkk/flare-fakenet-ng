"""Bracketed clock sampling: strict interval continuity at the real entries.

Two layers, both against production code paths:

* validator layer — kernel.validate_capture / tcpip.validate_capture with the
  candidate03-dns-01 originals plus clearly-marked synthetic clock variants
  (legacy point rule unchanged for old records; bracketed records judged by
  full-interval containment, never "some legal point exists");
* generation layer — the four real capture methods (_start_kernel_capture,
  _stop_kernel_capture, _start_capture_and_probe, _stop_capture_and_probe)
  composed through a recording fake VM, proving every command carries the
  same helper, the warmup+official pair, and the required ordering (before
  the real start, after the real stop).
"""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ACCEPT = Path(__file__).parent / 'acceptance'


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ACCEPT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


clock = _load('scenario_clock_test', 'scenario_clock.py')
kernel = _load('scenario_kernel_network_test', 'scenario_kernel_network.py')
tcpip = _load('scenario_tcpip_test', 'scenario_tcpip.py')
suite = _load('scenario_suite_clock_test', 'scenario_suite.py')

RUN = (Path(__file__).resolve().parents[2] / 'Logs/fakenetng-mcp/final100-20260920'
       / 'candidate03-dns-01/arm128/evidence/sst-077/attempt-01/run-01')
FREQ = 10**7
SCHEMA = clock.CLOCK_SAMPLING_SCHEMA


def _read(name):
    return (RUN / name).read_bytes()


def kernel_meta():
    return json.loads(_read('kernel-network.metadata.json').decode('utf-8-sig'))


def kernel_files():
    return (_read('kernel-network.events.jsonl'), _read('kernel-network.etl'),
            _read('kernel-network.header.xml'), _read('kernel-network.summary.txt'))


def bracket(base, width_ticks=1000, **overrides):
    """Wrap a legacy clock record in a deterministic narrow new-schema bracket."""
    q0 = base['mono'] - width_ticks
    q1 = base['mono'] + width_ticks
    record = {'schema': SCHEMA, 'version': 1,
              'utc_ticks': base['utc_ticks'], 'q0': q0, 'q1': q1,
              'mono': q0 + (q1 - q0) // 2,
              'stopwatch_frequency': base['stopwatch_frequency'],
              'offset_minutes': base['offset_minutes'],
              'warmup': {'utc_ticks': base['utc_ticks'] - 10, 'q0': q0 - 5,
                         'q1': q0 + 5, 'mono': q0}}
    for key, value in overrides.items():
        if key.endswith('_ticks') and key != 'utc_ticks':
            continue
        record[key] = value
    return record


def run_kernel(meta):
    try:
        kernel.validate_capture(*kernel_files(), meta,
                                str(RUN / 'kernel-network.events.jsonl'))
        return 'ACCEPTED'
    except ValueError as exc:
        return 'REJECTED: ' + str(exc)


# ---- legacy records: original rule, original thresholds, replay parity ----

def test_real_originals_replay_unchanged_udp_rejected():
    assert run_kernel(kernel_meta()).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_real_originals_replay_unchanged_tcp_passes():
    nic = json.loads(_read('pktmon-nic.json').decode('utf-8-sig'))
    lo, hi = tcpip.validate_capture(_read('pktmon.txt'), _read('pktmon.etl'), nic, 50000000)
    assert isinstance(lo, int)


# ---- bracketed records through the REAL kernel entry ----

def test_narrow_zero_drift_bracket_passes():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    drift_ns = ((after['utc_ticks'] - before['utc_ticks']) * 100
                - (after['mono'] - before['mono']) * 100)
    meta['clock_before'] = bracket(before)
    meta['clock_after'] = bracket(after, utc_ticks=after['utc_ticks'] - drift_ns // 100)
    assert run_kernel(meta) == 'ACCEPTED'


def test_point_inside_threshold_but_interval_exceeds_rejects():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    # Point value would be ~5ms inside 15.625ms, but +/- 11ms brackets push
    # the full interval past the budget.
    drift_ns = ((after['utc_ticks'] - before['utc_ticks']) * 100
                - (after['mono'] - before['mono']) * 100)
    target_ns = 5_000_000
    meta['clock_before'] = bracket(before)
    meta['clock_after'] = bracket(
        after, width_ticks=110_000,
        utc_ticks=after['utc_ticks'] - (drift_ns - target_ns) // 100)
    assert run_kernel(meta).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_point_outside_but_interval_intersecting_still_rejects():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    drift_ns = ((after['utc_ticks'] - before['utc_ticks']) * 100
                - (after['mono'] - before['mono']) * 100)
    target_ns = 20_000_000  # point value beyond 15.625ms
    meta['clock_before'] = bracket(before, width_ticks=200_000)
    meta['clock_after'] = bracket(
        after, width_ticks=200_000,
        utc_ticks=after['utc_ticks'] - (drift_ns - target_ns) // 100)
    assert run_kernel(meta).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_true_utc_jumps_reject_under_brackets():
    for jump_ms in (5000, -1000):
        meta = kernel_meta()
        before, after = meta['clock_before'], meta['clock_after']
        meta['clock_before'] = bracket(before)
        meta['clock_after'] = bracket(
            after, utc_ticks=after['utc_ticks'] + jump_ms * 10_000)
        assert run_kernel(meta).startswith('REJECTED: Kernel-Network clock discontinuity'), jump_ms


def test_wide_bracket_cannot_rescue_out_of_budget_point():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    drift_ns = ((after['utc_ticks'] - before['utc_ticks']) * 100
                - (after['mono'] - before['mono']) * 100)
    target_ns = 20_000_000
    meta['clock_before'] = bracket(before, width_ticks=5_000_000)
    meta['clock_after'] = bracket(
        after, width_ticks=5_000_000,
        utc_ticks=after['utc_ticks'] - (drift_ns - target_ns) // 100)
    assert run_kernel(meta).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_mixed_and_malformed_brackets_reject():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    mixed = dict(meta)
    mixed['clock_before'] = bracket(before)
    # after left legacy -> mixed schemas must reject, never silently pass.
    assert 'mixed clock sampling schemas' in run_kernel(mixed)

    def variant(**after_overrides):
        m = dict(meta)
        m['clock_before'] = bracket(before)
        m['clock_after'] = bracket(after, **after_overrides)
        return run_kernel(m)

    missing = bracket(after)
    del missing['q1']
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = missing
    # An incomplete new-schema record is rejected fail-closed: either as a
    # malformed bracket or, because the schema tag survives without its
    # fields, as a mixed pair. Both refuse to judge it as legacy.
    assert run_kernel(m).startswith(('REJECTED: Kernel-Network invalid clock sampling schema or fields',
                                     'REJECTED: Kernel-Network mixed clock sampling schemas'))
    assert 'clock bracket' in variant(q0=after['mono'] + 5000)          # reversed
    off_mid = bracket(after); off_mid['mono'] = off_mid['mono'] + 7
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = off_mid
    assert 'clock bracket' in run_kernel(m)                              # midpoint rule
    # A frequency change is rejected fail-closed: either by the entry's own
    # legacy domain check or by the shared strict domain check.
    freq_verdict = variant(stopwatch_frequency=FREQ + 1)
    assert freq_verdict.startswith(('REJECTED: invalid Kernel-Network clock domain',
                                     'REJECTED: Kernel-Network invalid capture monotonic frequency'))
    float_mono = bracket(after); float_mono['mono'] = float(float_mono['mono'])
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = float_mono
    assert run_kernel(m).startswith(('REJECTED: Kernel-Network invalid clock sampling schema or fields',
                                     'REJECTED: Kernel-Network mixed clock sampling schemas'))
    bool_q0 = bracket(after); bool_q0['q0'] = True
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = bool_q0
    assert run_kernel(m).startswith(('REJECTED: Kernel-Network invalid clock sampling schema or fields',
                                     'REJECTED: Kernel-Network mixed clock sampling schemas'))
    str_utc = bracket(after); str_utc['utc_ticks'] = str(str_utc['utc_ticks'])
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = str_utc
    assert run_kernel(m).startswith(('REJECTED: Kernel-Network invalid clock sampling schema or fields',
                                     'REJECTED: Kernel-Network mixed clock sampling schemas'))


def test_integer_rational_bounds_round_outward():
    before = bracket({'utc_ticks': 639255197450351630, 'mono': 1000,
                      'stopwatch_frequency': 10**7 + 3, 'offset_minutes': 480})
    after = bracket({'utc_ticks': 639255197450351630 + 10**7, 'mono': 1000 + 10**7 - 3,
                     'stopwatch_frequency': 10**7 + 3, 'offset_minutes': 480})
    result = clock.check_continuity(before, after, 10**9, lambda d: d)
    # Non-divisible frequency must widen, never shrink, the interval.
    assert result['elapsed_lo_ns'] <= result['elapsed_hi_ns']
    assert (after['q1'] - before['q0']) * 10**9 % (10**7 + 3) != 0
    assert result['wall_minus_mono_lo_ns'] <= result['wall_minus_mono_hi_ns']


# ---- generation layer: the four real methods carry the shared helper ----

class RecordingVM:
    def __init__(self):
        self.commands = []

    def powershell(self, command, timeout=120):
        self.commands.append(command)
        if 'logman start' in command:
            return {'output': json.dumps({'session_name': 'SST-Kernel-x',
                                          'metadata': 'C:/m.json', 'guest': 'C:/g',
                                          'start_output': ''})}
        if 'pktmon start --capture --comp all' in command:
            raise _LaunchCaptured()
        return {'output': json.dumps({'files': [], 'session_present': False,
                                      'coop': {'cooperative_exit': 'exited'}})}


class _LaunchCaptured(Exception):
    pass


OFFLINE_PROFILE = {
    'bucket': 'default', 'tempo': 'steady', 'variant': 'main', 'interleave': 'none',
    'cadence_ms': 1000, 'connection_window_seconds': 70,
    'probe_target': {'host': '198.51.100.77', 'port': 1337, 'protocol': 'tcp',
                     'process_mode': 'match', 'tls_server_name': '', 'fnpr_role': ''},
    'negative_cases': [], 'probe_cases': [], 'startup_retry_seconds': 70,
}


def _suite_instance(tmp_path):
    argv = ['run', '--filter', 'benign',
            '--candidate-id', 'c', '--source-commit', 's', '--package-sha256', 'p',
            '--package-manifest', str(tmp_path / 'm.json'),
            '--package-verification', str(tmp_path / 'v.json'),
            '--deployment-record', str(tmp_path / 'd.json'),
            '--target-base-url', 'http://127.0.0.1:1', '--win10vm-mcp', 'http://127.0.0.1:1',
            '--suite-root', str(tmp_path)]
    return suite.Suite(suite.parse_args(argv))


def test_four_real_capture_sites_carry_helper_and_order(tmp_path):
    registry = _suite_instance(tmp_path)
    fake = RecordingVM()
    registry.vm = fake
    start_kernel_cmd = None
    try:
        registry._start_kernel_capture('C:/r')
    except Exception:
        pass
    start_kernel_cmd = fake.commands[-1]
    assert clock.clock_sample_ps('clock')[:40] in start_kernel_cmd
    assert start_kernel_cmd.index('function __sstClock') < start_kernel_cmd.index('logman start')

    fake.commands.clear()
    registry._stop_kernel_capture(
        {'metadata': 'C:/m.json', 'session_name': 'SST-Kernel-x'})
    stop_kernel_cmd = fake.commands[-1]
    assert 'function __sstClock' in stop_kernel_cmd
    assert stop_kernel_cmd.index('logman stop') < stop_kernel_cmd.index('function __sstClock') \
        or 'logman stop' not in stop_kernel_cmd
    # The clock sample must come after the session-stop attempt, before the
    # conversion writes.
    clock_pos = stop_kernel_cmd.index('function __sstClock')
    query_pos = stop_kernel_cmd.index('logman query')
    convert_pos = stop_kernel_cmd.index('Get-WinEvent -Path')
    assert query_pos < clock_pos < convert_pos

    fake.commands.clear()
    try:
        registry._start_capture_and_probe('C:/guest', OFFLINE_PROFILE, 'n', 'run-01')
    except _LaunchCaptured:
        pass
    launch_cmd = next(c for c in fake.commands if 'pktmon start --capture' in c)
    assert 'function __sstClock' in launch_cmd
    assert launch_cmd.index('function __sstClock') < launch_cmd.index('pktmon start --capture')

    fake.commands.clear()
    capture = {'metadata': 'C:/m.json', 'session_name': 'SST-Kernel-x', 'probe': 'C:/p',
               'stop': 'C:/s', 'pid': 1, 'probe_creation_ticks': 1, 'etl': 'C:/e.etl',
               'pktmon_nic': 'C:/n.json', 'stdout': 'C:/o', 'stderr': 'C:/e', 'run_label': 'run-01',
               'kernel_capture': {'metadata': 'C:/m.json', 'session_name': 'SST-Kernel-x'}}
    registry._stop_capture_and_probe(capture)
    # The only composed stop command runs the coop body (which stops pktmon)
    # BEFORE the bracketed clock sample: clock_after must follow pktmon stop.
    composed = [c for c in fake.commands if 'clockAfter' in c]
    assert len(composed) == 1
    stop_probe_cmd = composed[0]
    assert stop_probe_cmd.index('pktmon stop') < stop_probe_cmd.index('clockAfter')
    assert stop_probe_cmd.count('function __sstClock') == 1
    assert '$__sstWarm=& __sstClock' in stop_probe_cmd
    assert '$__sstOff=& __sstClock' in stop_probe_cmd


def test_stop_capture_errors_keep_cooperative_responsibility(tmp_path, monkeypatch):
    """A failing coop body must still surface; the helper never replaces it."""
    registry = _suite_instance(tmp_path)
    fake = RecordingVM()
    registry.vm = fake

    def failing_json(command, timeout=120):
        fake.commands.append(command)
        if 'clockAfter' in command:
            return ({'coop': {'cooperative_exit': 'timeout'}},
                    {'raw': 'x'})
        return {'output': json.dumps({'files': [], 'session_present': False})}

    monkeypatch.setattr(registry, '_vm_json', failing_json)
    capture = {'metadata': 'C:/m.json', 'session_name': 'SST-Kernel-x', 'probe': 'C:/p',
               'stop': 'C:/s', 'pid': 1, 'probe_creation_ticks': 1, 'etl': 'C:/e.etl',
               'pktmon_nic': 'C:/n.json', 'stdout': 'C:/o', 'stderr': 'C:/e', 'run_label': 'run-01',
               'kernel_capture': {'metadata': 'C:/m.json', 'session_name': 'SST-Kernel-x'}}
    with pytest.raises(suite.SuiteError):
        registry._stop_capture_and_probe(capture)
