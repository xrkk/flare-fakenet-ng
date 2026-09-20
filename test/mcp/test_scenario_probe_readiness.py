"""Readiness-marker contract for the probe's during-start wait (T005-R05).

The bucket-to-marker mapping and the legacy default anchor are extracted
from the PRODUCTION scenario_probes.ps1 text; the regex semantics below run
against the extracted production pattern strings themselves, never against a
rewritten mirror.  The default anchor must stay as strict as the host
oracle's ``_LEGACY_READY_RE``: a timestamped INFO Diverter line carrying a
pid and a TCP or UDP request from packet handling, not startup output.
"""

import importlib.util
import re
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('suite_readiness_probe', HERE / 'acceptance/scenario_suite.py')
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)
PROBES = (HERE / 'acceptance/scenario_probes.ps1').read_text(encoding='utf-8-sig' if False else 'utf-8')


def marker_pattern_for(bucket):
    """Reproduce the production if/elseif selection literally."""
    is_b3 = bucket == ('B3', 'match')
    if is_b3:
        return re.search(r"if \(\$isB3\) \{ '([^']+)' \}", PROBES).group(1)
    if bucket == 'default':
        return re.search(r"elseif \(\$isLegacyDefault\) \{ '([^']+)' \}", PROBES).group(1)
    return re.search(r"else \{ '([^']+)' \}", PROBES).group(1)


LEGACY_LINES = [
    '2026-09-20 18:28:34,293 INFO Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337',
    '2026-09-20 18:28:34,293 INFO Diverter powershell.exe (42) requested UDP 198.51.100.77:53',
]

NON_LEGACY_LINES = [
    # Wrong level / logger: startup or debug output never releases the wait.
    '2026-09-20 18:28:34,293 DEBUG Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337',
    '2026-09-20 18:28:34,293 INFO Other svchost.exe (3164) requested TCP 198.51.100.77:1337',
    # Missing pid parentheses or missing protocol.
    '2026-09-20 18:28:34,293 INFO Diverter svchost.exe requested TCP 198.51.100.77:1337',
    '2026-09-20 18:28:34,293 INFO Diverter svchost.exe (3164) requested TLS 198.51.100.77:443',
    # Arbitrary "requested" prose without the strict line shape.
    'engine requested TCP listeners during configuration load',
    # Milliseconds missing.
    '2026-09-20 18:28:34 INFO Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337',
]


DEFAULT_READY_LINES = [
    '2026-09-21 02:04:38,308 INFO FakeNet DEFAULT_INTERCEPTION_READY',
    '2026-09-21 02:04:38,308 INFO FakeNet DEFAULT_INTERCEPTION_READY extra',
]

NON_DEFAULT_LINES = [
    # Background-flow shape: a real historical legacy line, but the new
    # default probe must never fall back to it again.
    '2026-09-20 18:28:34,293 INFO Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337',
    # Wrong level / logger / missing milliseconds / arbitrary prose.
    '2026-09-21 02:04:38,308 DEBUG FakeNet DEFAULT_INTERCEPTION_READY',
    '2026-09-21 02:04:38,308 INFO Diverter DEFAULT_INTERCEPTION_READY',
    '2026-09-21 02:04:38 INFO FakeNet DEFAULT_INTERCEPTION_READY',
    'configuration mentioned DEFAULT_INTERCEPTION_READY during load',
]


def test_default_anchor_matches_production_marker_semantics():
    pattern = marker_pattern_for('default')
    dotnet_to_python = pattern.replace('\\d', r'\d').replace('\\s', r'\s')
    regex = re.compile(dotnet_to_python)
    for line in DEFAULT_READY_LINES:
        assert regex.search(line), line
    for line in NON_DEFAULT_LINES:
        assert not regex.search(line), line
    # Background traffic can no longer release the default wait, and a
    # policy marker never satisfies it either.
    assert not regex.search('EGRESS_CONTROL_READY')


def test_legacy_requested_lines_stay_parseable_for_historical_originals():
    # Historical originals recorded readiness only as background flows; the
    # host oracle keeps parsing them (compat only, new probes never wait on
    # them). The suite boundary prefers the explicit new marker over them.
    host = suite.Suite._LEGACY_READY_RE
    for line in LEGACY_LINES:
        assert host.match(line), line
    for line in NON_LEGACY_LINES:
        assert not host.match(line), line
    default_re = suite.Suite._DEFAULT_READY_RE
    assert default_re.match(DEFAULT_READY_LINES[0])
    assert not default_re.match(NON_DEFAULT_LINES[2])


def test_egress_boundary_prefers_explicit_marker_over_background_flow():
    mixed = (
        '2026-09-21 02:05:28,860 INFO Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337\n'
        '2026-09-21 02:06:10,000 INFO FakeNet DEFAULT_INTERCEPTION_READY\n')
    assert suite.Suite._egress_ready_boundary(mixed) == '2026-09-21 02:06:10.000'
    marker_first = (
        '2026-09-21 02:06:10,000 INFO FakeNet DEFAULT_INTERCEPTION_READY\n'
        '2026-09-21 02:07:28,860 INFO Diverter svchost.exe (3164) requested TCP 198.51.100.77:1337\n')
    assert suite.Suite._egress_ready_boundary(marker_first) == '2026-09-21 02:06:10.000'
    # Historical original with only a background flow still resolves.
    assert suite.Suite._egress_ready_boundary(LEGACY_LINES[0] + '\n') == '2026-09-20 18:28:34.293'
    # Policy logs keep their own boundary untouched.
    policy = '2026-09-21 02:06:10,000 INFO Diverter EGRESS_CONTROL_READY\n'
    assert suite.Suite._egress_ready_boundary(policy) == '2026-09-21 02:06:10.000'


def test_default_and_standard_buckets_keep_disjoint_markers():
    default = marker_pattern_for('default')
    standard = marker_pattern_for('B1')
    b2 = marker_pattern_for('B2')
    b4 = marker_pattern_for('B4')
    b3 = marker_pattern_for(('B3', 'match'))
    assert default != standard
    assert standard == b2 == b4 == 'EGRESS_CONTROL_READY|DOMAIN_TAKEOVER_READY'
    assert b3 == 'PROCESS_REDIRECT_RULE_READY'
    regex = re.compile(default.replace('\\d', r'\d').replace('\\s', r'\s'))
    # A standard ready line never satisfies the default wait and vice versa;
    # the same holds for the legacy background-flow shape.
    assert not regex.search('EGRESS_CONTROL_READY')
    standard_re = re.compile(standard)
    for line in LEGACY_LINES:
        assert not standard_re.search(line)
        assert not regex.search(line), line


def test_production_function_carries_runs_root_seam_and_trace_fields():
    assert "$RunsRoot = 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs'" in PROBES
    assert 'Get-ChildItem -LiteralPath $RunsRoot -Directory' in PROBES
    assert "marker = $matched; marker_line = $matchedLine; run_id = $observed" in PROBES
    assert "LEGACY_REQUESTED_'" in PROBES
    # The launcher-after boundary is unchanged for every bucket.
    assert '$_.CreationTimeUtc -gt $LauncherStartUtc' in PROBES
