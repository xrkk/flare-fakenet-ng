"""Bracketed clock sampling: strict interval continuity at the real entries.

Machine-independent: every capture record here is a clearly-marked SYNTHETIC
fixture — small, self-coherent inputs the REAL parsers fully validate (real
tracerpt-header XML shape, real MSNT header line, hash-bound conversion
blocks, epoch-consistent StartTime/EndTime). No gitignored Logs/ originals
are read; replaying the historical captures stays a separate offline
evidence command (clock-portable-01), not a unit-test dependency.

Two layers, both against production code paths:

* validator layer — kernel.validate_capture / tcpip.validate_capture over
  the synthetic fixtures plus clock variants (legacy point rule unchanged
  for old records; bracketed records judged by full-interval containment,
  never "some legal point exists");
* generation layer — the four real capture methods (_start_kernel_capture,
  _stop_kernel_capture, _start_capture_and_probe, _stop_capture_and_probe)
  composed through a recording fake VM, proving every command carries the
  same helper, the warmup+official pair, and the required ordering.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

ACCEPT = Path(__file__).parent / 'acceptance'
DOTNET_EPOCH_1970 = 621355968000000000   # .NET ticks at 1970-01-01
FILETIME_1601_TICKS = 504911232000000000  # .NET ticks at FILETIME epoch 1601-01-01


def _filetime(utc_ticks, delta_ticks=0):
    return utc_ticks - FILETIME_1601_TICKS + delta_ticks


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

FREQ = 10**7
SCHEMA = clock.CLOCK_SAMPLING_SCHEMA
# A synthetic baseline pair: 200 wall seconds, mono 200s minus 21.9605ms —
# the same failure magnitude family as the historical capture, standing in
# for it without reading it.
BASE_BEFORE = {'utc_ticks': 639255197450351630, 'mono': 1016029778022,
               'stopwatch_frequency': FREQ, 'offset_minutes': 480}
BASE_AFTER = {'utc_ticks': 639255197450351630 + 200 * 10**7 + 219605,
              'mono': 1016029778022 + 200 * 10**7,
              'stopwatch_frequency': FREQ, 'offset_minutes': 480}


# ---- synthetic, parser-valid capture fixtures -------------------------

def _kernel_header(before, after):
    start_ft = _filetime(before['utc_ticks'], 5 * 10**6)
    end_ft = _filetime(after['utc_ticks'], -5 * 10**6)
    fields = [('BufferSize', 8192), ('Version', 83951626), ('ProviderVersion', 19045),
              ('NumberOfProcessors', 4), ('EndTime', end_ft), ('TimerResolution', 156250),
              ('MaxFileSize', 0), ('LogFileMode', '0x0'), ('BuffersWritten', 80),
              ('StartBuffers', 1), ('PointerSize', 8), ('EventsLost', 0), ('BuffersLost', 0),
              ('CPUSpeed', 2419), ('LoggerName', 'SST-Kernel-synth'),
              ('SessionNameString', 'SST-Kernel-synth'), ('LogFileNameString', 'C:/synth/kernel.etl'),
              ('StartTime', start_ft)]
    data = ''.join('<Data Name="%s">%s</Data>' % (k, v) for k, v in fields)
    return ('<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><Provider Guid="{00000000-0000-0000-0000-000000000000}"/>'
            '</System><EventData>' + data + '</EventData></Event></Events>').encode()


def kernel_meta(before=None, after=None):
    """A fully valid synthetic kernel-network capture around the clock pair."""
    before = dict(BASE_BEFORE if before is None else before)
    after = dict(BASE_AFTER if after is None else after)
    etl = b'synthetic-etl-bytes'
    header = _kernel_header(before, after)
    summary = 'Total Events   Lost   0\r\n'.encode('utf-16')
    events = b''  # no UDP sends: clock validation is independent of payloads
    conversion = {
        'event_reader': 'Get-WinEvent -Path C:/synth/kernel.etl -Oldest | ForEach-Object { $_.ToXml() }',
        'event_reader_exit_code': 0,
        'tracerpt_argv': ['tracerpt', 'C:/synth/kernel.etl', '-o', 'C:/synth/kernel.header.xml',
                          '-of', 'XML', '-summary', 'C:/synth/kernel.summary.txt', '-y'],
        'tracerpt_exit_code': 0,
        'etl_sha256': hashlib.sha256(etl).hexdigest(),
        'events_sha256': hashlib.sha256(events).hexdigest(),
        'header_sha256': hashlib.sha256(header).hexdigest(),
        'summary_sha256': hashlib.sha256(summary).hexdigest()}
    return {'capture_mode': 'kernel-network-ipv4', 'session_name': 'SST-Kernel-synth',
            'etl_path': 'C:/synth/kernel.etl', 'events_path': 'C:/synth/kernel.events.jsonl',
            'header_path': 'C:/synth/kernel.header.xml', 'summary_path': 'C:/synth/kernel.summary.txt',
            'clock_before': before, 'clock_after': after, 'conversion': conversion}


def kernel_parts(meta):
    return (b'', b'synthetic-etl-bytes',
            _kernel_header(meta['clock_before'], meta['clock_after']),
            'Total Events   Lost   0\r\n'.encode('utf-16'))


def _tcpip_line(before, after):
    start_ft = _filetime(before['utc_ticks'], 10**6)
    end_ft = _filetime(after['utc_ticks'], -10**6)
    return ('[00]0ABC.0A3C:: header [MSNT_SystemTrace] 事件: Header, StartTime: %d, EndTime: %d, '
            'EventsLost: 0, BuffersLost: 0, LogFileNameString: C:/synth/pktmon.etl' % (start_ft, end_ft))


def tcpip_meta(before=None, after=None):
    before = dict(BASE_BEFORE if before is None else before)
    after = dict(BASE_AFTER if after is None else after)
    txt = (_tcpip_line(before, after) + '\r\n').encode('utf-16')
    etl = b'synthetic-tcpip-etl'
    return {'capture_mode': 'all-components-tcpip',
            'clock_before': before, 'clock_after': after,
            'conversion': {'exit_code': 0,
                           'argv': ['pktmon', 'etl2txt', 'C:/synth/pktmon.etl', '--out', 'C:/synth/pktmon.txt'],
                           'etl_sha256': hashlib.sha256(etl).hexdigest(),
                           'text_sha256': hashlib.sha256(txt).hexdigest()}}


def tcpip_parts(meta):
    return ((_tcpip_line(meta['clock_before'], meta['clock_after']) + '\r\n').encode('utf-16'),
            b'synthetic-tcpip-etl')


def bracket(base, width_ticks=1000, **overrides):
    """Wrap a legacy-style clock record in a deterministic new-schema bracket."""
    q0 = base['mono'] - width_ticks
    q1 = base['mono'] + width_ticks
    record = {'schema': SCHEMA, 'version': 1,
              'utc_ticks': base['utc_ticks'], 'q0': q0, 'q1': q1,
              'mono': q0 + (q1 - q0) // 2,
              'stopwatch_frequency': base['stopwatch_frequency'],
              'offset_minutes': base['offset_minutes'],
              'warmup': {'utc_ticks': base['utc_ticks'] - 10, 'q0': q0 - 5,
                         'q1': q0 + 5, 'mono': q0}}
    record.update(overrides)
    return record


def run_kernel(meta, regenerate=True):
    import copy
    meta = copy.deepcopy(meta)
    parts = kernel_parts(meta if regenerate else kernel_meta())
    if regenerate:
        names = ('events_sha256', 'etl_sha256', 'header_sha256', 'summary_sha256')
        for name, data in zip(names, parts):
            meta['conversion'][name] = hashlib.sha256(data).hexdigest()
    try:
        kernel.validate_capture(*parts, meta, 'C:/synth/kernel.events.jsonl')
        return 'ACCEPTED'
    except ValueError as exc:
        return 'REJECTED: ' + str(exc)


def drift_ns(before, after):
    return ((after['utc_ticks'] - before['utc_ticks']) * 100
            - (after['mono'] - before['mono']) * 100)


# ---- legacy records: original rule, original thresholds ----------------

def test_legacy_point_failure_still_rejects_on_synthetic_fixture():
    # wall - mono = 21.9605ms on the synthetic pair: the historical failure
    # magnitude family, judged by the unchanged legacy point rule.
    assert run_kernel(kernel_meta()).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_legacy_point_within_threshold_passes_tcpip_entry():
    meta = tcpip_meta()
    assert drift_ns(meta['clock_before'], meta['clock_after']) < 50_000_000
    txt, etl = tcpip_parts(meta)
    lo, hi = tcpip.validate_capture(txt, etl, meta, 50000000)
    assert isinstance(lo, int) and isinstance(hi, int)


# ---- bracketed records through the REAL kernel entry -------------------

def test_narrow_zero_drift_bracket_passes():
    meta = kernel_meta()
    d = drift_ns(meta['clock_before'], meta['clock_after'])
    before, after = meta['clock_before'], meta['clock_after']
    meta['clock_before'] = bracket(before)
    meta['clock_after'] = bracket(after, utc_ticks=after['utc_ticks'] - d // 100)
    assert run_kernel(meta) == 'ACCEPTED'


def test_point_inside_threshold_but_interval_exceeds_rejects():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    d = drift_ns(before, after)
    target_ns = 5_000_000  # point value inside 15.625ms
    meta['clock_before'] = bracket(before)
    meta['clock_after'] = bracket(
        after, width_ticks=110_000,
        utc_ticks=after['utc_ticks'] - (d - target_ns) // 100)
    assert run_kernel(meta).startswith('REJECTED: Kernel-Network clock discontinuity')


def test_point_outside_but_interval_intersecting_still_rejects():
    meta = kernel_meta()
    before, after = meta['clock_before'], meta['clock_after']
    d = drift_ns(before, after)
    target_ns = 20_000_000  # point value beyond 15.625ms
    meta['clock_before'] = bracket(before, width_ticks=200_000)
    meta['clock_after'] = bracket(
        after, width_ticks=200_000,
        utc_ticks=after['utc_ticks'] - (d - target_ns) // 100)
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
    d = drift_ns(before, after)
    target_ns = 20_000_000
    meta['clock_before'] = bracket(before, width_ticks=5_000_000)
    meta['clock_after'] = bracket(
        after, width_ticks=5_000_000,
        utc_ticks=after['utc_ticks'] - (d - target_ns) // 100)
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
    assert run_kernel(m).startswith(('REJECTED: Kernel-Network invalid after clock q1',
                                     'REJECTED: Kernel-Network mixed clock sampling schemas',
                                     'REJECTED: Kernel-Network invalid clock sampling schema or fields'))
    assert 'clock bracket' in variant(q0=after['mono'] + 5000)          # reversed
    off_mid = bracket(after); off_mid['mono'] = off_mid['mono'] + 7
    m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = off_mid
    assert 'clock bracket' in run_kernel(m)                              # midpoint rule
    # A frequency change is rejected fail-closed: either by the entry's own
    # legacy domain check or by the shared strict domain check.
    freq_verdict = variant(stopwatch_frequency=FREQ + 1)
    assert freq_verdict.startswith(('REJECTED: invalid Kernel-Network clock domain',
                                     'REJECTED: Kernel-Network invalid capture monotonic frequency'))
    for key, marker in (('mono', 'invalid after clock mono'), ('q0', 'invalid after clock q0'),
                        ('utc_ticks', 'invalid after clock utc_ticks')):
        for bad in (lambda v: float(v), lambda v: str(v), lambda v: True):
            mangled = bracket(after)
            mangled[key] = bad(mangled[key])
            m = dict(meta); m['clock_before'] = bracket(before); m['clock_after'] = mangled
            assert run_kernel(m, regenerate=False).startswith(('REJECTED: Kernel-Network ' + marker,
                                             'REJECTED: Kernel-Network mixed clock sampling schemas',
                                             'REJECTED: Kernel-Network invalid clock sampling schema or fields')), key


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
