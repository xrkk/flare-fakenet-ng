#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""Real-traffic MCP scenario suite for the egress-policy acceptance matrix.

The command deliberately separates the deterministic, offline manifest from
the stateful Windows execution.  A manifest is an input contract, never a
claim that a scenario ran.  Every mutable action is bound to one controller,
one deterministic command id, and one scenario attempt; an interrupted run
therefore remains resumable without reclassifying a recorded pass or failure.

This implements the interface described by the SST plan v0.5:
``generate``, ``preflight``, ``run``, ``resume``, ``verify`` and ``summary``.
It uses only the two already deployed MCP HTTP endpoints.  No GUI automation
or product-code changes are involved.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.server
import importlib.util
import ipaddress
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
import time
import threading
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[3]
# Stdlib-only FNPR sentinel container used only when this host cannot bind
# privileged port 443 directly (non-root Linux runner).
FNPR_SENTINEL_IMAGE = 'python:3.12-alpine'
# Direct-file CLI execution starts sys.path at test/mcp/acceptance, not
# the repository root. Baseline capture imports the shared product module.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenario_clock as _sst_clock
DEFAULT_SUITE_ROOT = REPO_ROOT / 'Logs' / 'fakenetng-mcp' / 'scenario-suite-20260912'
SCHEMA = 'fakenetng.mcp-scenario-suite.v1'
SCENARIO_SCHEMA = 'fakenetng.mcp-scenario.v1'
STATE_SCHEMA = 'fakenetng.mcp-scenario-state.v1'
COVERAGE_SCHEMA = 'fakenetng.mcp-scenario-coverage.v1'
SUMMARY_SCHEMA = 'fakenetng.mcp-scenario-summary.v1'
FAULTS = ('policy_pause', 'listener_stop', 'diverter_stop', 'child_hang',
          'cleanup_error')
TOOLS = ('get_status', 'get_events', 'list_configs', 'validate_config',
         'read_config', 'list_artifacts', 'load_config', 'start', 'stop',
         'restart', 'create_config', 'import_config', 'edit_config',
         'rename_config', 'delete_config')
BUCKET_COUNTS = {'B1': 25, 'B2': 20, 'B3': 20, 'B4': 20, 'default': 15}
FAULT_BUCKETS = ('B1', 'B2', 'B3', 'B4')
EXIT_PASS, EXIT_USAGE, EXIT_FAIL, EXIT_BLOCKED = 0, 2, 3, 4
# 192 MiB bounds a single guest evidence transfer: a B3 pktmon text export
# legitimately reaches ~70 MiB (discovery100-10 sst-038) from a 5 MiB ETL.
MAX_GUEST_TRANSFER = 192 * 1024 * 1024
GUEST_ROOT = r'C:\ProgramData\FakeNet-NG-MCP\logs'
PKTMON_MODULE = Path(__file__).with_name('scenario_pktmon.py')
NIC_CAPTURE_SCHEMA = 'fakenetng.mcp-scenario-pktmon-nic.v1'


class SuiteError(RuntimeError):
    """A scenario failure whose evidence must be retained."""


class Blocked(SuiteError):
    """A precondition cannot be proved; callers must not continue."""


class HostOnlyFileTransfer:
    """Serve one immutable test input on the authorized host-only address."""

    def __init__(self, source: Path, public_name: str):
        self.source = source
        self.public_name = public_name
        self.payload = source.read_bytes()
        self.sha256 = hashlib.sha256(self.payload).hexdigest()
        self.requests: list[dict[str, Any]] = []
        self.server: http.server.ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.stopped = False
        self.port: int | None = None

    @property
    def url(self) -> str:
        if self.port is None:
            raise RuntimeError('host-only transfer has not started')
        return 'http://192.168.204.1:%d/%s' % (self.port, self.public_name)

    def __enter__(self) -> 'HostOnlyFileTransfer':
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - base-class contract
                if self.path != '/' + outer.public_name:
                    outer.requests.append({'method': 'GET', 'path': self.path, 'status': 404})
                    self.send_error(404)
                    return
                outer.requests.append({'method': 'GET', 'path': self.path, 'status': 200,
                                       'bytes': len(outer.payload)})
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(outer.payload)))
                self.end_headers()
                self.wfile.write(outer.payload)

            def log_message(self, _format: str, *args: Any) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(('192.168.204.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name='scenario-probe-hostonly-transfer', daemon=True)
        self.thread.start()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=10)
        self.stopped = True

    def record(self) -> dict[str, Any]:
        return {'bind': '192.168.204.1', 'url': self.url, 'name': self.public_name,
                'sha256': self.sha256, 'bytes': len(self.payload),
                'requests': list(self.requests), 'stopped': self.stopped}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':')) + '\n').encode('utf-8')


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_record(path: Path, root: Path | None = None) -> dict[str, Any]:
    raw = path.read_bytes()
    return {'path': str(path.relative_to(root) if root else path),
            'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def write_new_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(canonical_bytes(value))


def replace_json(path: Path, value: Any) -> None:
    """Only mutable state files use replace; verdicts and evidence use x."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp-' + uuid.uuid4().hex)
    with temporary.open('xb') as stream:
        stream.write(canonical_bytes(value))
    os.replace(temporary, path)


def write_distinct_json(path: Path, value: Any) -> Path:
    """Retain prior verification verdicts instead of overwriting evidence."""
    if not path.exists():
        write_new_json(path, value)
        return path
    suffix = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    alternate = path.with_name('%s-%s-%s%s' %
                               (path.stem, suffix, uuid.uuid4().hex[:8], path.suffix))
    write_new_json(alternate, value)
    return alternate


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def endpoint(url: str) -> str:
    value = url.rstrip('/')
    return value if value.endswith('/mcp') else value + '/mcp'


def quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _pktmon_module() -> Any:
    """Load the byte-addressed pktmon decoder without relying on sys.path.

    The suite is also imported by offline tests, so a plain sibling import is
    not reliable.  This loader keeps the capture decoder independently
    testable while making its failure an evidence failure at run time.
    """
    spec = importlib.util.spec_from_file_location('scenario_pktmon_runtime', PKTMON_MODULE)
    if spec is None or spec.loader is None:
        raise SuiteError('pktmon evidence decoder is unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _normal_mac(value: Any) -> str:
    raw = str(value or '').strip().upper().replace(':', '-').replace(' ', '')
    if not re.fullmatch(r'(?:[0-9A-F]{2}-){5}[0-9A-F]{2}', raw):
        raise SuiteError('uncanonical NIC MAC evidence')
    return raw


def pktmon_nic_binding(value: dict[str, Any]) -> dict[str, Any]:
    """Bind current pktmon component ids to a live adapter, fail closed.

    Pktmon's component id is ephemeral.  A component is accepted only when
    the same capture records a numeric component id, adapter MAC and exact
    adapter description, and the Windows adapter inventory has exactly one
    live adapter with that MAC/description pair.  The r4 native sample uses
    the Chinese ``网络适配器`` listing, so no locale-specific heading is used.
    """
    if value.get('schema') != NIC_CAPTURE_SCHEMA:
        raise SuiteError('pktmon NIC metadata schema mismatch')
    catalogue = value.get('pktmon_list')
    adapters = value.get('adapters')
    if not isinstance(catalogue, str) or not isinstance(adapters, list):
        raise SuiteError('pktmon NIC metadata is incomplete')
    rows: list[dict[str, Any]] = []
    for line in catalogue.splitlines():
        match = re.match(r'^\s*(\d+)\s+((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})\s+(.+?)\s*$', line)
        if not match:
            continue
        rows.append({'component': int(match.group(1)), 'mac': _normal_mac(match.group(2)),
                     'description': match.group(3).strip()})
    if not rows:
        raise SuiteError('pktmon component catalogue has no adapter rows')
    bound: list[dict[str, Any]] = []
    for row in rows:
        matching = []
        for adapter in adapters:
            if not isinstance(adapter, dict):
                continue
            try:
                adapter_mac = _normal_mac(adapter.get('MacAddress'))
            except SuiteError:
                continue
            if (adapter_mac == row['mac'] and
                    str(adapter.get('InterfaceDescription') or '').strip() == row['description'] and
                    str(adapter.get('Status') or '').strip().lower() == 'up'):
                matching.append(adapter)
        if len(matching) != 1:
            raise SuiteError('pktmon component cannot be uniquely bound to an active adapter')
        adapter = matching[0]
        index = adapter.get('ifIndex')
        if not isinstance(index, int) or index <= 0:
            raise SuiteError('pktmon adapter has no positive ifIndex')
        bound.append({'component': row['component'], 'mac': row['mac'],
                      'description': row['description'], 'if_index': index,
                      'name': str(adapter.get('Name') or '')})
    if len({item['component'] for item in bound}) != len(bound):
        raise SuiteError('pktmon component catalogue repeats an adapter id')
    return {'schema': NIC_CAPTURE_SCHEMA, 'bound_adapters': bound,
            'component_ids': sorted(item['component'] for item in bound)}


def pktmon_capture_issues(value: dict[str, Any], packet_export: bytes | str | None = None) -> list[str]:
    """Require a stopped, loss-free native pktmon capture before use.

    ``pktmon etl2txt`` writes the authoritative ETW loss counters into its
    MSNT_SystemTrace header.  Network-policy Drop counters are traffic
    outcomes, not recorder loss, so they deliberately have no bearing here.
    """
    problems: list[str] = []
    if value.get('schema') != NIC_CAPTURE_SCHEMA:
        return ['pktmon NIC metadata schema mismatch']
    status = value.get('pktmon_status_after')
    if not isinstance(status, str) or not re.search(r'(?i)\b(?:stopped|not\s+running)\b|数据包监视器没有运行', status):
        problems.append('pktmon did not report stopped after export')
    if isinstance(packet_export, bytes):
        try:
            text = packet_export.decode('utf-16' if packet_export.startswith(b'\xff\xfe') else 'utf-8-sig')
        except UnicodeDecodeError:
            text = ''
    else:
        text = packet_export if isinstance(packet_export, str) else ''
    counters = {name: int(number) for name, number in
                re.findall(r'(?im)\b(EventsLost|BuffersLost)\s*:\s*(\d+)\b', text)}
    if set(counters) != {'EventsLost', 'BuffersLost'}:
        problems.append('pktmon exported trace loss header is absent/incomplete')
    elif any(counters.values()):
        problems.append('pktmon exported trace reports lost ETW events/buffers')
    try:
        pktmon_nic_binding(value)
    except SuiteError as exc:
        problems.append(str(exc))
    return problems


def profile_for_bucket(bucket: str, ordinal: int, in_bucket: int | None = None) -> dict[str, Any]:
    """Return a material profile: traffic cadence and boundary vary by ordinal.

    The manifest retains all parameters which select real probe behaviour, so a
    changed ``scenario_id`` alone can never manufacture a distinct scenario.
    ``in_bucket`` is the row's bucket-relative position; the default bucket
    rotates its four application case kinds on it (a global ordinal modulo
    would skip kinds because the bucket's slots are seed-rotated).
    """
    tempos = ('hold', 'burst', 'stagger', 'drip', 'overlap')
    interleaves = ('before-start', 'during-start', 'after-healthy', 'restart-window', 'stop-window')
    group, position = divmod(ordinal, len(tempos))
    # Rotate cadence across B4 policy variants instead of fixing allow to
    # burst and UDP deny to stagger for every occurrence.
    tempo = tempos[(position + group) % len(tempos)] if bucket == 'B4' else tempos[position]
    common = {'bucket': bucket, 'ordinal': ordinal, 'tempo': tempo,
              'interleave': interleaves[(group + position) % len(interleaves)],
              # These fields are passed into the guest probe and retained in
              # its raw JSONL.  They are behaviour, not labels used to pad a
              # scenario count.  B3 additionally consumes cadence in its
              # native child client (see scenario_probes.ps1).
              'cadence_ms': {'hold': 250, 'burst': 25, 'stagger': 700,
                             'drip': 1100, 'overlap': 75}[tempo],
              'connection_window_seconds': 90,
              # This input controls the native B3 client's bounded retry
              # window; generic probes retain it as their own traffic window.
              'startup_retry_seconds': 70}
    def target(host: str, port: int, protocol: str, expectation: str,
               process_mode: str = 'match', tls_server_name: str | None = None,
               fnpr_role: str | None = None, application: str | None = None) -> dict[str, Any]:
        value = {'host': host, 'port': port, 'protocol': protocol,
                 'expectation': expectation, 'process_mode': process_mode}
        if tls_server_name:
            value['tls_server_name'] = tls_server_name
        if fnpr_role:
            value['fnpr_role'] = fnpr_role
        if application:
            value['application'] = application
        return value
    if bucket == 'B1':
        modes = (
            ('deepseek-tls', target('api.deepseek.com', 443, 'tls', 'relay_allow')),
            ('domain-deny', target('example.com', 443, 'tls', 'deny')),
            ('direct-ip-deny', target('198.51.100.77', 1337, 'tcp', 'deny')),
            ('udp443-deny', target('api.deepseek.com', 443, 'udp', 'deny')),
            ('sni-deny', target('api.deepseek.com', 443, 'tls', 'deny', tls_server_name='example.com')),
        )
        variant, probe_target = modes[(ordinal // len(tempos)) % len(modes)]
        return dict(common, template='egress_control_windows.ini',
                    variant=variant + '-' + common['tempo'], traffic_profile='egress_control',
                    probe_target=probe_target,
                    negative_cases=(
                        target('example.com', 443, 'tls', 'deny'),
                        target('198.51.100.77', 1337, 'tcp', 'deny'),
                        target('api.deepseek.com', 443, 'udp', 'deny'),
                        target('api.deepseek.com', 443, 'tls', 'deny', tls_server_name='example.com'),
                    ))
    if bucket == 'B2':
        variants = ('sink-and-reviewed', 'sink-and-reviewed-stagger',
                    'sink-and-reviewed-drip', 'sink-and-reviewed-overlap')
        variant = variants[(ordinal // len(tempos)) % len(variants)]
        probe_target = target('__P4_API_IPV4__', 443, 'tls', 'reviewed_allow',
                              tls_server_name='api.deepseek.com')
        return dict(common, template='domain_takeover_windows.ini',
                    variant=variant + '-%02d-%s' % (ordinal % 10, common['tempo']),
                    traffic_profile='reviewed_private', probe_target=probe_target,
                    probe_cases=(
                        target('192.168.204.1', 443, 'tcp', 'takeover_allow', fnpr_role='target'),
                        target('10.20.30.41', 1337, 'tcp', 'deny'),
                    ))
    if bucket == 'B3':
        group = ordinal // len(tempos)
        process_mode = 'match' if group % 2 == 0 else 'nonmatch'
        # The native child consumes this bound on a real retry loop.  The two
        # values per process mode prevent an ordinal-only duplicate while
        # preserving the existing bounded-start contract.
        retry_seconds = (55, 70, 85, 100)[group % 4]
        return dict(common, template='process_redirect_windows.ini',
                    variant='process-redirect-%s-%02d-%s' % (process_mode, ordinal % 10, common['tempo']),
                    traffic_profile='process_redirect',
                    startup_retry_seconds=retry_seconds,
                    connection_window_seconds=retry_seconds + 20,
                    probe_target=target('198.51.100.77', 443, 'tcp',
                                        'redirect_allow' if process_mode == 'match' else 'ordinary_path', process_mode,
                                        fnpr_role='target' if process_mode == 'match' else None))
    if bucket == 'B4':
        variants = (
            ('nonallowed-divert', target('198.51.100.77', 1337, 'tcp', 'deny')),
            ('allow-443', target('api.deepseek.com', 443, 'tls', 'relay_allow')),
            ('nonallowed-drop', target('api.deepseek.com', 443, 'udp', 'deny')),
            ('sni-boundary', target('api.deepseek.com', 443, 'tls', 'deny', tls_server_name='example.com')),
            ('domain-boundary', target('example.com', 443, 'tls', 'deny')),
        )
        variant, probe_target = variants[ordinal % len(variants)]
        return dict(common, template='egress_control_windows.ini',
                    variant=variant, traffic_profile='egress_boundary', probe_target=probe_target,
                    negative_cases=(
                        target('example.com', 443, 'tls', 'deny'),
                        target('198.51.100.77', 1337, 'tcp', 'deny'),
                    ))
    if bucket == 'default':
        import scenario_application as applications
        kinds = applications.APPLICATION_KINDS
        position = in_bucket if in_bucket is not None else ordinal
        kind = kinds[position % len(kinds)]
        return dict(common, template='default.ini',
                    variant='full-takeover-%s' % common['tempo'], traffic_profile='default_takeover',
                    probe_target=target('198.51.100.77', 1337, 'tcp', 'local_fake'),
                    application_kind=kind,
                    probe_cases=(target(applications.DEFAULT_SINK,
                                        applications.APPLICATION_PORTS[kind],
                                        applications.APPLICATION_PROTOCOLS[kind],
                                        'local_fake', application=kind),))
    raise ValueError('unknown bucket: ' + bucket)


def plan_for(index: int, fault: str | None, *, restart: bool | None = None) -> list[dict[str, str]]:
    """Full call contract, including one deliberately stale mutation."""
    prefix = ('list_configs', 'validate_config', 'create_config', 'create_config',
              'read_config', 'edit_config', 'read_config', 'rename_config',
              'import_config', 'read_config', 'delete_config', 'load_config', 'start')
    entries = [{'tool': name, 'expect': ('reject_state_conflict' if pos == 3 else 'success')}
               for pos, name in enumerate(prefix)]
    if restart is None:
        restart = fault is None and index < 20
    if restart:
        # The first run's artifact writer can lag a restart.  Query and bind
        # its exact PCAP while its run id is still current, then restart.
        entries.extend({'tool': name, 'expect': 'success'}
                       for name in ('get_events', 'list_artifacts', 'restart'))
        suffix = ('get_status', 'get_status', 'get_status', 'get_events', 'list_artifacts', 'stop')
    elif fault == 'diverter_stop':
        # Stopping the diverter during the start rendezvous fails the start
        # itself, so no health sampling and no trailing stop exist (sst-002).
        suffix = ('get_status', 'get_events', 'list_artifacts')
    elif fault == 'listener_stop':
        # The fault stops the listener providers before the start reply's
        # own probe, so the start itself fails (discovery100-115 sst-035
        # actual flow) and no health sampling or trailing stop exists.
        suffix = ('get_status', 'get_events', 'list_artifacts')
    elif fault == 'child_hang':
        # A hung fault child does not fail the start: the run reaches
        # healthy (discovery100-109 sst-016, -114/-115 sst-003), so the
        # driver samples health and stops.
        suffix = ('get_status', 'get_status', 'get_status', 'get_events', 'list_artifacts', 'stop')
    else:
        suffix = ('get_status', 'get_status', 'get_status', 'get_events', 'list_artifacts', 'stop')
    entries.extend({'tool': name, 'expect': 'success'} for name in suffix)
    return entries


def build_manifest(seed: int, count: int = 100) -> dict[str, Any]:
    if count != 100:
        raise ValueError('the accepted matrix is exactly 100 scenarios')
    if sum(BUCKET_COUNTS.values()) != count:
        raise AssertionError('bucket constants no longer total 100')
    slots: list[str] = []
    for bucket, size in BUCKET_COUNTS.items():
        slots.extend([bucket] * size)
    # A stable rotation avoids accidental dependence on dict ordering while
    # preserving exact bucket counts and seed reproducibility.
    rotation = seed % count
    slots = slots[rotation:] + slots[:rotation]
    fault_slots: list[tuple[str, str]] = []
    for fault in FAULTS:
        for image in range(3):
            bucket = FAULT_BUCKETS[(FAULTS.index(fault) + image) % len(FAULT_BUCKETS)]
            fault_slots.append((bucket, fault))
    assigned_faults: dict[int, str] = {}
    used: set[int] = set()
    for desired_bucket, fault in fault_slots:
        candidate = next(i for i, bucket in enumerate(slots)
                         if bucket == desired_bucket and i not in used)
        used.add(candidate)
        assigned_faults[candidate] = fault
    scenarios: list[dict[str, Any]] = []
    benign_ordinals: dict[str, int] = {}
    bucket_ordinals: dict[str, int] = {}
    for index, bucket in enumerate(slots):
        fault = assigned_faults.get(index)
        sid = 'sst-%03d' % (index + 1)
        bucket_ordinal = bucket_ordinals.get(bucket, 0)
        bucket_ordinals[bucket] = bucket_ordinal + 1
        profile = profile_for_bucket(bucket, index, in_bucket=bucket_ordinal)
        # A start-injection receipt is valid only when its one target session
        # spans engine preparation and the product rendezvous.  The remaining
        # fault classes act after health or at stop, respectively.
        if fault in ('listener_stop', 'diverter_stop', 'child_hang'):
            profile['interleave'] = 'during-start'
        elif fault == 'policy_pause':
            profile['interleave'] = 'after-healthy'
        elif fault == 'cleanup_error':
            profile['interleave'] = 'stop-window'
        # Allocate real restarts within each bucket, not only the first
        # twenty global IDs. Every restart-window label schedules restart.
        benign_ordinal = benign_ordinals.get(bucket, 0)
        restart = fault is None and (profile['interleave'] == 'restart-window'
                                     or benign_ordinal % 5 == 0)
        if fault is None:
            benign_ordinals[bucket] = benign_ordinal + 1
        scenarios.append({
            'scenario_id': sid,
            'seed': seed,
            'config_profile': profile,
            'lifecycle_chain': 'restart' if restart else 'start-stop',
            'traffic_profile': profile['traffic_profile'],
            'interleave_pattern': ('fault-' + fault if fault else
                                   ('contract-restart' if restart else 'serial')),
            'fault_class': fault,
            'interface_call_plan': plan_for(index, fault, restart=restart),
        })
    manifest = {'schema': SCHEMA, 'application_observation_contract': 'con008', 'seed': seed, 'count': count,
                'created_by': 'scenario_suite.py', 'scenarios': scenarios}
    problems = manifest_issues(manifest)
    if problems:
        raise AssertionError('generated invalid manifest: ' + '; '.join(problems))
    return manifest


def manifest_issues(manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    scenarios = manifest.get('scenarios')
    if manifest.get('schema') != SCHEMA or not isinstance(scenarios, list):
        return ['invalid manifest schema']
    if manifest.get('application_observation_contract') != 'con008':
        failures.append('manifest lacks current application observation contract')
    if len(scenarios) != 100:
        failures.append('scenario count is not 100')
    ids = [row.get('scenario_id') for row in scenarios]
    if len(set(ids)) != len(ids) or any(not isinstance(item, str) for item in ids):
        failures.append('scenario ids are not unique')
    buckets: dict[str, int] = {}
    fault_count: dict[str, int] = {fault: 0 for fault in FAULTS}
    tool_coverage: dict[str, set[str]] = {tool: set() for tool in TOOLS}
    actual_behaviours: dict[str, str] = {}
    for row in scenarios:
        sid = row.get('scenario_id')
        profile = row.get('config_profile') or {}
        bucket = profile.get('bucket')
        buckets[bucket] = buckets.get(bucket, 0) + 1
        fault = row.get('fault_class')
        if fault is not None:
            if fault not in FAULTS:
                failures.append('unknown fault class in ' + str(sid))
            else:
                fault_count[fault] += 1
            if bucket not in FAULT_BUCKETS:
                failures.append('fault assigned outside B1-B4: ' + str(sid))
        planned = row.get('interface_call_plan') or []
        names = [item.get('tool') for item in planned if isinstance(item, dict)]
        restart = row.get('lifecycle_chain') == 'restart'
        if restart != ('restart' in names):
            failures.append('restart lifecycle/call mismatch: ' + str(sid))
        if profile.get('interleave') == 'restart-window' and not restart:
            failures.append('restart-window without restart operation: ' + str(sid))
        if len(set(names)) < 10:
            failures.append('fewer than 10 distinct tools: ' + str(sid))
        for tool in set(names):
            if tool in tool_coverage:
                tool_coverage[tool].add(sid)
        # IDs, ordinals and display variants cannot manufacture coverage.  A
        # duplicate check is therefore calculated from inputs that reach the
        # rendered config, lifecycle scheduler or actual probe command.
        profile_for_key = {key: value for key, value in profile.items()
                           if key not in ('ordinal', 'variant', 'traffic_profile')}
        behaviour = {'profile': profile_for_key, 'lifecycle_chain': row.get('lifecycle_chain'),
                     'traffic_profile': row.get('traffic_profile'),
                     'interleave_pattern': row.get('interleave_pattern'),
                     'fault_class': fault, 'interface_call_plan': planned}
        key = digest(behaviour)
        if key in actual_behaviours:
            failures.append('duplicate actual behaviour: %s and %s' % (actual_behaviours[key], sid))
        actual_behaviours[key] = str(sid)
    for bucket, minimum in (('B1', 25), ('B2', 15), ('B3', 15), ('B4', 15)):
        if buckets.get(bucket, 0) < minimum:
            failures.append('bucket below minimum: ' + bucket)
    if buckets.get('default', 0) > 15:
        failures.append('default bucket exceeds 15')
    if sum(fault_count.values()) != 15 or any(value != 3 for value in fault_count.values()):
        failures.append('fault matrix is not five classes x three')
    for tool, seen in tool_coverage.items():
        if len(seen) < 5:
            failures.append('tool coverage below five: ' + tool)
    return failures


class RawMcp:
    """Small, fresh-session MCP client used because the VM session is volatile."""

    def __init__(self, url: str, controller_id: str | None = None):
        self.url = endpoint(url)
        self.controller_id = controller_id or str(uuid.uuid4())
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @staticmethod
    def _decode_event_stream(raw: str) -> str:
        """Return the one JSON payload from an SSE response.

        Win10VM emits legal heartbeat comment lines (``: ping``) before the
        result event.  They are transport framing, never JSON payloads.
        Multiple result events or an unterminated event are ambiguous and are
        rejected rather than silently choosing a response.
        """
        events: list[str] = []
        data: list[str] = []
        saw_sse = False
        for line in raw.splitlines():
            if not line:
                if data:
                    events.append('\n'.join(data))
                    data = []
                continue
            if line.startswith(':'):
                saw_sse = True
                continue
            if line.startswith('event:') or line.startswith('id:') or line.startswith('retry:'):
                saw_sse = True
                continue
            if line.startswith('data:'):
                saw_sse = True
                data.append(line[5:].lstrip(' '))
                continue
            if saw_sse:
                raise SuiteError('malformed SSE response line: ' + line[:160])
            return raw
        if data:
            events.append('\n'.join(data))
        if not saw_sse:
            return raw
        if len(events) != 1:
            raise SuiteError('SSE response does not contain exactly one result event')
        return events[0]

    def _post(self, body: dict[str, Any], headers: dict[str, str] | None = None,
              timeout: int = 120) -> tuple[dict[str, Any], dict[str, str]]:
        header = {'Content-Type': 'application/json',
                  'Accept': 'application/json, text/event-stream'}
        header.update(headers or {})
        request = urllib.request.Request(self.url, canonical_bytes(body), headers=header)
        try:
            with self.opener.open(request, timeout=timeout) as response:
                raw = response.read().decode('utf-8')
                response_headers = dict(response.headers)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode('utf-8')
            response_headers = dict(exc.headers)
        raw = self._decode_event_stream(raw)
        if not raw:
            return {}, response_headers
        try:
            return json.loads(raw), response_headers
        except ValueError as exc:
            raise SuiteError('non-JSON MCP response: ' + raw[:500]) from exc

    @staticmethod
    def _tool_value(response: dict[str, Any]) -> dict[str, Any]:
        if response.get('error'):
            raise SuiteError('MCP protocol error: ' + repr(response['error']))
        result = response.get('result') or {}
        content = result.get('content') or []
        text = '\n'.join(item.get('text', '') for item in content
                         if isinstance(item, dict) and item.get('type') == 'text')
        if result.get('isError'):
            raise SuiteError('MCP tool error: ' + text[:500])
        try:
            parsed = json.loads(text)
        except ValueError as exc:
            raise SuiteError('tool returned non-JSON content: ' + text[:500]) from exc
        if not isinstance(parsed, dict):
            raise SuiteError('tool returned non-object JSON')
        return parsed

    def tool_outcome(self, name: str, arguments: dict[str, Any] | None = None,
                     timeout: int = 120) -> dict[str, Any]:
        """Return a lossless tool attempt, including a typed rejection.

        Scenario replay needs the actual wire arguments and response for failed
        mutations too.  The convenience ``tool`` wrapper below still raises for
        callers (such as preflight) that require immediate success.
        """
        sent = dict(arguments or {})
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                'params': {'name': name, 'arguments': sent,
                           '_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                                     'io.modelcontextprotocol/clientInfo': {
                                         'name': 'scenario-suite', 'version': '1'},
                                     'io.modelcontextprotocol/clientCapabilities': {}}}}
        response, headers = self._post(body, {
            'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/call',
            'Mcp-Name': name, 'X-FakeNet-Controller-ID': self.controller_id}, timeout)
        value: dict[str, Any] | None = None
        error: Any = None
        try:
            value = self._tool_value(response)
            if value.get('error'):
                error = value['error']
        except SuiteError as exc:
            error = str(exc)
            result = response.get('result') or {}
            text = '\n'.join(item.get('text', '') for item in result.get('content', [])
                             if isinstance(item, dict) and item.get('type') == 'text')
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    value = parsed
                    error = parsed.get('error', error)
            except ValueError:
                pass
        return {'ok': error is None, 'sent_arguments': sent, 'response': response,
                'response_headers': headers, 'value': value, 'error': error}

    def tool(self, name: str, arguments: dict[str, Any] | None = None,
             timeout: int = 120) -> dict[str, Any]:
        outcome = self.tool_outcome(name, arguments, timeout)
        if not outcome['ok'] or not isinstance(outcome['value'], dict):
            raise SuiteError('%s rejected: %r' % (name, outcome['error']))
        return outcome['value']


class VmMcp(RawMcp):
    """The Win10VM MCP server requires a new initialize session per command."""

    def powershell(self, command: str, timeout: int = 120) -> dict[str, Any]:
        initialized, headers = self._post({
            'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
            'params': {'protocolVersion': '2025-03-26', 'capabilities': {},
                       'clientInfo': {'name': 'scenario-suite', 'version': '1'}}},
            timeout=timeout)
        if initialized.get('error'):
            raise SuiteError('VM initialize error: ' + repr(initialized['error']))
        session = next((value for key, value in headers.items()
                        if key.lower() == 'mcp-session-id'), None)
        if not session:
            raise SuiteError('VM MCP did not provide a session id')
        header = {'mcp-session-id': session}
        self._post({'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                   header, timeout=timeout)
        response, _ = self._post({
            'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
            'params': {'name': 'PowerShell', 'arguments': {'command': command,
                                                             'timeout': timeout}}},
            header, timeout=timeout + 30)
        if response.get('error'):
            raise SuiteError('VM PowerShell protocol error: ' + repr(response['error']))
        result = response.get('result') or {}
        content = result.get('content') or []
        raw = '\n'.join(item.get('text', '') for item in content
                         if isinstance(item, dict) and item.get('type') == 'text')
        marker = 'Status Code:'
        index = raw.rfind(marker)
        exit_code: int | None = None
        output = raw
        if index >= 0:
            output = raw[:index]
            try:
                exit_code = int(raw[index + len(marker):].strip().splitlines()[0])
            except (ValueError, IndexError):
                exit_code = None
        output = output.removeprefix('Response:').strip()
        record = {'command': command, 'timeout': timeout, 'raw': raw,
                  'output': output, 'exit_code': exit_code,
                  'is_error': bool(result.get('isError'))}
        if record['is_error'] or exit_code != 0:
            raise SuiteError('VM PowerShell failed: ' + raw[-800:])
        return record


@dataclass
class Identity:
    candidate_id: str
    source_commit: str
    package_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {'candidate_id': self.candidate_id,
                'source_commit': self.source_commit,
                'package_sha256': self.package_sha256}


class Evidence:
    def __init__(self, root: Path):
        self.root = root
        self.items: list[dict[str, Any]] = []

    def add(self, path: Path) -> dict[str, Any]:
        record = file_record(path, self.root)
        if record not in self.items:
            self.items.append(record)
        return record

    def write(self, name: str, value: Any) -> Path:
        path = self.root / name
        write_new_json(path, value)
        self.add(path)
        return path


def runtime_pcap_required(profile: dict[str, Any]) -> bool:
    """Extra product PCAP exists only when the unchanged template enables it."""
    content = (REPO_ROOT / 'fakenet/configs' / profile['template']).read_text(encoding='utf-8')
    values = re.findall(r'(?im)^DumpPackets[ \t]*:[ \t]*(Yes|No)[ \t]*$', content)
    if len(values) != 1:
        raise SuiteError('template must declare one DumpPackets setting')
    return values[0].lower() == 'yes'


def profile_content(profile: dict[str, Any], external_dns_server: str,
                    process_image: dict[str, str] | None = None,
                    reviewed_ipv4: str | None = None) -> str:
    template = REPO_ROOT / 'fakenet' / 'configs' / profile['template']
    content = template.read_text(encoding='utf-8')
    bucket = profile['bucket']
    if bucket in ('B1', 'B2', 'B4'):
        content = content.replace('__EXTERNAL_DNS__', external_dns_server)
    if bucket == 'B2':
        if not isinstance(reviewed_ipv4, str) or not re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', reviewed_ipv4):
            raise Blocked('P4 API IPv4 is invalid for reviewed-IP profile')
        content = content.replace('ExternalAllowedTCPPorts: 443',
                                  'ExternalAllowedTCPPorts: 443\n'
                                  'ExternalAllowedIPv4Rules: TCP/%s/443' % reviewed_ipv4)
    if bucket == 'B3':
        if not process_image:
            raise Blocked('B3 requires the VM probe executable identity')
        replacements = {
            '__RUNTIME_EXTERNAL_DNS__': external_dns_server,
            '__RUNTIME_PROCESS_IMAGE_PATH__': process_image['path'],
            '__RUNTIME_PROCESS_IMAGE_SHA256__': process_image['sha256'],
            '__RUNTIME_PUBLIC_IPV4_A__': process_image['public_ipv4'],
            '__RUNTIME_PRIVATE_IPV4_B__': process_image['private_ipv4'],
        }
        for marker, value in replacements.items():
            content = content.replace(marker, value)
    if bucket == 'B4':
        variant = profile['variant']
        if variant == 'nonallowed-divert':
            content = content.replace('ExternalAllowedDomains: api.deepseek.com',
                                      'ExternalAllowedDomains: api.deepseek.com,example.invalid')
        elif variant == 'nonallowed-drop':
            content = content.replace('ExternalNonAllowedAction: Divert',
                                      'ExternalNonAllowedAction: Drop')
        elif variant == 'domain-boundary':
            content = content.replace('ExternalAllowedDomains: api.deepseek.com',
                                      'ExternalAllowedDomains: api.deepseek.com,example.net')
    if bucket == 'default':
        # The stock profile deliberately carries inert redirect placeholders.
        # Omit only those disabled optional fields; never enable redirect.
        if not re.search(r'(?im)^ExternalProcessRedirectEnabled:\s*No\s*$', content):
            raise Blocked('default redirect must remain disabled')
        content = re.sub(r'(?m)^ExternalProcessRedirect(?:ImagePath|ImageSHA256|OriginalIPv4|TargetIPv4):[^\n]*\n', '', content)
    if '__' in content:
        unresolved = sorted(set(re.findall(r'__[A-Z0-9_]+__', content)))
        if unresolved:
            raise Blocked('unresolved configuration markers: ' + ','.join(unresolved))
    return content


def materialize_probe_profile(profile: dict[str, Any], api_ipv4: str) -> dict[str, Any]:
    """Freeze runtime-only P4 endpoint substitution beside rendered config."""
    value = json.loads(json.dumps(profile))
    for target in [value.get('probe_target'), *(value.get('probe_cases') or [])]:
        if isinstance(target, dict) and target.get('host') == '__P4_API_IPV4__':
            target['host'] = api_ipv4
    return value


class FnprSentinel:
    """One bounded host-only receiver, owned by a single scenario attempt.

    Port 443 on the host-only address is privileged on Linux.  When this
    runner is not root the direct local bind is denied; the identical
    stdlib-only script is then relaunched in a pinned detached container with
    host networking, whose root may bind the same 192.168.204.1:443.  Both
    modes append to the same on-disk JSONL so the evidence stays byte-bound.
    """

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.log = self.root / 'fnpr-sentinel.jsonl'
        self.stdout = self.root / 'fnpr-sentinel.stdout'
        self._stream = self.stdout.open('xb')
        self.mode = 'local'
        self.container: str | None = None
        self.process = self._spawn_local()
        deadline = time.monotonic() + 15
        respawns = 3
        while time.monotonic() < deadline:
            if self.log.is_file():
                rows = self.rows()
                if any(row.get('event') == 'ready' and row.get('bind') == '192.168.204.1' and
                       row.get('port') == 443 for row in rows):
                    return
                denial = next((row for row in rows if row.get('event') == 'start_failed' and
                               row.get('reason') == 'PermissionError'), None)
                if denial is not None and self.mode == 'local':
                    self.process.terminate()
                    self.process.wait(timeout=5)
                    self.mode = 'container'
                    self.container = 'fnpr-sentinel-' + uuid.uuid4().hex[:12]
                    self.process = self._spawn_container()
                    deadline = time.monotonic() + 30
                    continue
            exited = self._exited()
            if exited and self.mode == 'local':
                break
            if exited and self.mode == 'container':
                # Rapid docker create/stop/remove cycles transiently report a
                # live container as gone, or fail its start outright.  Retry a
                # bounded number of times before declaring the sentinel dead.
                if respawns:
                    respawns -= 1
                    time.sleep(2)
                    self.container = 'fnpr-sentinel-' + uuid.uuid4().hex[:12]
                    self.process = self._spawn_container()
                    deadline = time.monotonic() + 30
                    continue
                break
            time.sleep(0.1)
        self.stop()
        raise SuiteError('controlled FNPR sentinel did not become ready on 192.168.204.1:443')

    def _spawn_local(self) -> subprocess.Popen:
        command = [sys.executable, str(REPO_ROOT / 'fnpr_sentinel.py'), '--log', str(self.log)]
        return subprocess.Popen(command, stdout=self._stream, stderr=subprocess.STDOUT,
                                cwd=str(REPO_ROOT))

    def _spawn_container(self) -> subprocess.Popen:
        command = ['docker', 'run', '--rm', '-d', '--name', self.container,
                   '--network', 'host',
                   '--mount', 'type=bind,source=%s,target=%s,readonly' % (REPO_ROOT, REPO_ROOT),
                   '--mount', 'type=bind,source=%s,target=%s' % (self.root, self.root),
                   FNPR_SENTINEL_IMAGE, 'python3', str(REPO_ROOT / 'fnpr_sentinel.py'),
                   '--log', str(self.log)]
        return subprocess.Popen(command, stdout=self._stream, stderr=subprocess.STDOUT)

    def _exited(self) -> bool:
        if self.mode == 'local':
            return self.process.poll() is not None
        probe = subprocess.run(['docker', 'inspect', '-f', '{{.State.Status}}', self.container],
                               capture_output=True, text=True)
        if probe.returncode == 0:
            return probe.stdout.strip() not in ('running', 'paused', 'restarting', 'created')
        # A removed container is confirmed dead; any other failure (daemon
        # contention, CLI error) must not be mistaken for container death.
        return 'No such object' in (probe.stderr or '')

    def rows(self) -> list[dict[str, Any]]:
        if not self.log.is_file():
            return []
        rows = []
        for line in self.log.read_text(encoding='utf-8').splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def receipt(self, nonce: str, role: str, transport: str = 'tcp') -> dict[str, Any] | None:
        matches = [row for row in self.rows()
                   if row.get('event') == 'probe_ok' and row.get('nonce') == nonce and
                   row.get('role') == role and row.get('transport') == transport and
                   str(row.get('peer', '')).startswith('192.168.204.233:')]
        return matches[-1] if matches else None

    def stop(self) -> dict[str, Any]:
        if self.container is not None:
            stopped = subprocess.run(['docker', 'stop', '-t', '10', self.container],
                                     capture_output=True, text=True)
            removal = 'unconfirmed'
            for _ in range(10):
                gone = subprocess.run(['docker', 'inspect', self.container],
                                      capture_output=True, text=True)
                if gone.returncode != 0:
                    removal = 'confirmed'
                    break
                subprocess.run(['docker', 'rm', '-f', self.container],
                               capture_output=True, text=True)
                time.sleep(0.5)
            self._stream.close()
            return {'mode': self.mode, 'container': self.container,
                    'returncode': 0 if (stopped.returncode == 0 and removal == 'confirmed') else 1,
                    'removal': removal,
                    'rows': self.rows(), 'log': file_record(self.log, self.root) if self.log.is_file() else None,
                    'stdout': file_record(self.stdout, self.root) if self.stdout.is_file() else None}
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self._stream.close()
        return {'mode': self.mode, 'pid': self.process.pid, 'returncode': self.process.returncode,
                'rows': self.rows(), 'log': file_record(self.log, self.root) if self.log.is_file() else None,
                'stdout': file_record(self.stdout, self.root) if self.stdout.is_file() else None}


class Suite:
    # The two pktmon file-size values already exercised by the master's
    # capacity contrast.  Validated here so directly-constructed Namespace
    # objects (offline callers) also obey the same contract; the default
    # keeps existing behavior.  Nothing VM-facing runs before this check.
    PKTMON_FILE_SIZE_MIB_CHOICES = (128, 1024)

    def __init__(self, args: argparse.Namespace):
        file_size = getattr(args, 'pktmon_file_size_mib', 128)
        if (isinstance(file_size, bool) or not isinstance(file_size, int)
                or file_size not in self.PKTMON_FILE_SIZE_MIB_CHOICES):
            raise SuiteError('pktmon file size must be one of %r, got %r'
                             % (self.PKTMON_FILE_SIZE_MIB_CHOICES, file_size))
        self.args = args
        self.pktmon_file_size_mib = file_size
        self.root = Path(args.suite_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.identity = Identity(args.candidate_id, args.source_commit,
                                 args.package_sha256)
        self.service = RawMcp(args.target_base_url) if args.target_base_url else None
        self.vm = VmMcp(args.win10vm_mcp) if args.win10vm_mcp else None
        # MCP binds a command id to the controller that first used it.  A
        # failed suite root must be preserved and a later root must therefore
        # never reuse the old root's deterministic command ids.
        self.command_namespace = digest(str(self.root))[:8]
        self.manifest_path = self.root / 'scenario-manifest.json'
        self.preflight_path = self.root / 'preflight.json'

    def _command_id(self, scenario_id: str, attempt: int, sequence: int,
                    suffix: str = '') -> str:
        return '%s-%s%s-%02d-%03d' % (self.command_namespace, scenario_id,
                                      suffix, attempt, sequence)

    def require_clients(self) -> None:
        if not self.service or not self.vm:
            raise Blocked('target-base-url and win10vm-mcp are required for this command')

    def manifest(self) -> dict[str, Any]:
        if not self.manifest_path.is_file():
            raise Blocked('scenario-manifest.json is absent; run generate first')
        manifest = read_json(self.manifest_path)
        issues = manifest_issues(manifest)
        if issues:
            raise Blocked('manifest invalid: ' + '; '.join(issues))
        return manifest

    def generate(self) -> dict[str, Any]:
        manifest = build_manifest(self.args.seed, self.args.count)
        if self.manifest_path.exists():
            current = self.manifest_path.read_bytes()
            candidate = canonical_bytes(manifest)
            if current != candidate:
                raise Blocked('manifest already exists with different seed/content')
        else:
            write_new_json(self.manifest_path, manifest)
        coverage = planned_coverage(manifest)
        coverage_path = self.root / 'planned-coverage-report.json'
        if not coverage_path.exists():
            write_new_json(coverage_path, coverage)
        if self.args.regen_check:
            regenerated = canonical_bytes(build_manifest(self.args.seed, self.args.count))
            if self.manifest_path.read_bytes() != regenerated:
                raise SuiteError('same seed did not regenerate byte-identical manifest')
        return {'output_dir': str(self.root), 'manifest': file_record(self.manifest_path, self.root),
                'coverage': coverage, 'passed': True}

    def _vm_json(self, command: str, timeout: int = 120) -> tuple[dict[str, Any], dict[str, Any]]:
        assert self.vm
        raw = self.vm.powershell(command, timeout)
        try:
            value = json.loads(raw['output'])
        except ValueError as exc:
            raise SuiteError('expected VM JSON: ' + raw['output'][:500]) from exc
        if not isinstance(value, dict):
            raise SuiteError('expected VM JSON object')
        return value, raw

    def _status(self, timeout: float = 120) -> dict[str, Any]:
        assert self.service
        return self.service.tool('get_status', timeout=timeout)

    def _identity_material(self) -> dict[str, Any]:
        """Bind the local package and the recorded remote switch to one candidate.

        The MCP status endpoint intentionally reports service/lifecycle state,
        not an installer hash.  Treating an open TCP port as candidate identity
        would permit a mixed-candidate matrix, so preflight requires the three
        immutable local records produced by build and controlled deployment.
        """
        required = (self.args.package_manifest, self.args.package_verification,
                    self.args.deployment_record)
        if any(not value for value in required):
            raise Blocked('preflight requires package manifest, verification, and deployment record')
        paths = [Path(value).resolve() for value in required]
        if any(not path.is_file() for path in paths):
            raise Blocked('candidate identity record missing')
        manifest, verification, deployment = [read_json(path) for path in paths]
        if (manifest.get('source_commit') != self.identity.source_commit or
                verification.get('zip_sha256') != self.identity.package_sha256 or
                verification.get('verdict') != 'PASS' or
                deployment.get('source') != self.identity.source_commit or
                deployment.get('candidate') != self.identity.candidate_id or
                deployment.get('zip_sha256') != self.identity.package_sha256):
            raise Blocked('candidate material does not bind the requested identity')
        return {'package_manifest': file_record(paths[0]),
                'package_verification': file_record(paths[1]),
                'deployment_record': file_record(paths[2]),
                'verified_members': deployment.get('verified_members')}

    def _mutate(self, scenario_id: str, attempt: int, sequence: int, name: str,
                arguments: dict[str, Any]) -> dict[str, Any]:
        assert self.service
        status = self._status()
        args = dict(arguments)
        args['command_id'] = self._command_id(scenario_id, attempt, sequence)
        args['expected_state_version'] = status['state_version']
        result = self.service.tool(name, args, timeout=480 if name in ('start', 'stop') else 120)
        if result.get('error'):
            raise SuiteError('%s rejected: %s' % (name, result['error']))
        return result

    def _stage_probe(self) -> dict[str, Any]:
        assert self.vm
        script = (Path(__file__).with_name('scenario_probes.ps1')).read_bytes()
        guest = GUEST_ROOT + r'\scenario-suite-20260912\scenario_probes.ps1'
        source = Path(__file__).with_name('scenario_probes.ps1')
        with HostOnlyFileTransfer(source, 'scenario_probes.ps1') as transfer:
            temporary = guest + '.download-' + uuid.uuid4().hex
            command = (
                "$ErrorActionPreference='Stop';$p=" + quote_ps(guest) + ";$tmp=" + quote_ps(temporary) +
                ";$uri=" + quote_ps(transfer.url) + ";"
                "New-Item -ItemType Directory -Force -Path (Split-Path $p) | Out-Null;"
                "try{$web=New-Object Net.WebClient;$web.Proxy=$null;$web.DownloadFile($uri,$tmp);"
                "$sha=(Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower();if($sha -ne " + quote_ps(hashlib.sha256(script).hexdigest()) +
                "){throw 'host-only scenario probe SHA-256 mismatch'};if(Test-Path $p){Remove-Item -LiteralPath $p -Force};[IO.File]::Move($tmp,$p);"
                "@{path=$p;sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower();bytes=(Get-Item $p).Length;uri=$uri}|ConvertTo-Json -Compress}"
                "finally{if(Test-Path $tmp){Remove-Item -LiteralPath $tmp -Force}}")
            value, raw = self._vm_json(command, 120)
        transfer_record = transfer.record()
        if transfer_record['requests'] != [{'method': 'GET', 'path': '/scenario_probes.ps1',
                                            'status': 200, 'bytes': len(script)}]:
            raise SuiteError('host-only probe transfer request is incomplete or ambiguous')
        value['host_only_transfer'] = transfer_record
        if value.get('sha256') != hashlib.sha256(script).hexdigest() or value.get('bytes') != len(script):
            raise SuiteError('guest probe staging hash mismatch')
        value['raw'] = raw
        return value

    def preflight(self) -> dict[str, Any]:
        self.require_clients()
        evidence = Evidence(self.root / 'preflight-evidence')
        checks: list[dict[str, Any]] = []
        def check(name: str, action) -> Any:
            try:
                result = action()
                checks.append({'id': name, 'passed': True, 'result': result})
                return result
            except Exception as exc:  # noqa: BLE001
                checks.append({'id': name, 'passed': False, 'reason': repr(exc)})
                raise
        try:
            identity, raw = check('P1-vm-identity', lambda: self._vm_json(
                "$ErrorActionPreference='Stop';$mac=@(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                "ForEach-Object {$_.MacAddress});@{computer=$env:COMPUTERNAME;mac=$mac}|ConvertTo-Json -Compress", 60))
            evidence.write('p1-vm-identity.json', {'value': identity, 'raw': raw})
            if identity.get('computer') != 'DESKTOP-3FI41GR' or '00-0C-29-C1-CA-49' not in identity.get('mac', []):
                raise Blocked('unexpected .233 VM identity')
            material = check('P2-candidate-material', self._identity_material)
            evidence.write('p2-candidate-material.json', material)
            service = check('P2-service-candidate', self._status)
            evidence.write('p2-service-status.json', service)
            if service.get('service') != 'fakenetng-mcp' or service.get('state') != 'stopped':
                raise Blocked('service is not a clean stopped fakenetng-mcp endpoint')
            p3, raw = check('P3-win10vm-mcp', lambda: self._vm_json(
                "@{computer=$env:COMPUTERNAME;version=[Environment]::OSVersion.Version.ToString()}|ConvertTo-Json -Compress", 60))
            evidence.write('p3-win10vm-mcp.json', {'value': p3, 'raw': raw})
            route, raw = check('P4-route-dns', lambda: self._vm_json(
                "$ErrorActionPreference='Stop';$route=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Select InterfaceAlias,InterfaceIndex,NextHop,RouteMetric|Sort-Object RouteMetric,InterfaceIndex);"
                "$dns=@($route|ForEach-Object {Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop|"
                "Select-Object -ExpandProperty ServerAddresses}|Where-Object {$_ -and $_ -notin @('0.0.0.0','127.0.0.1')}|Select-Object -First 1);"
                "if($dns.Count -ne 1){throw 'no selected external DNS server'};$api=Resolve-DnsName api.deepseek.com -Server $dns[0] -Type A -ErrorAction Stop|"
                "Where-Object {$_.IPAddress}|Select-Object -First 1 -ExpandProperty IPAddress;"
                "@{routes=$route;external_dns_server=$dns[0];api_ipv4=$api}|ConvertTo-Json -Depth 5 -Compress", 60))
            evidence.write('p4-route-dns.json', {'value': route, 'raw': raw})
            if not route.get('routes') or not route.get('external_dns_server') or not route.get('api_ipv4'):
                raise Blocked('default route or external DNS unavailable')
            if self.args.preflight_through == 'P4':
                result = {'schema': SCHEMA + '.preflight.v1', 'identity': self.identity.as_dict(),
                          'stage': 'P4', 'passed': True, 'checks': checks, 'evidence': evidence.items,
                          'external_dns_server': route['external_dns_server'], 'api_ipv4': route['api_ipv4'],
                          'created_at': utc_now()}
                partial = self.root / 'preflight-p1-p4.json'
                if partial.exists():
                    if read_json(partial) != result:
                        raise Blocked('P1-P4 record already exists with different evidence')
                else:
                    write_new_json(partial, result)
                return result
            stage = check('P5-probe-stage', self._stage_probe)
            evidence.write('p5-probe-stage.json', stage)
            # P5 intentionally proves the normal lifecycle before any traffic or fault.
            normal = check('P5-empty-cycle', lambda: self._clean_cycle('default.ini', 'preflight', 1))
            evidence.write('p5-empty-cycle.json', normal)
            # P6: TEST-NET is a positive observation that the VM can emit a packet;
            # it is not accepted as the DeepSeek relay proof.
            p6, raw = check('P6-test-net', lambda: self._vm_json(
                "$ErrorActionPreference='Stop';$x=Test-NetConnection 198.51.100.77 -Port 1337 -WarningAction SilentlyContinue;"
                "@{computer=$env:COMPUTERNAME;tcp=$x.TcpTestSucceeded;remote=[string]$x.RemoteAddress}|ConvertTo-Json -Compress", 60))
            evidence.write('p6-test-net.json', {'value': p6, 'raw': raw})
            b1 = profile_content(profile_for_bucket('B1', 0), route['external_dns_server'])
            p7 = check('P7-deepseek-relay', lambda: self._preflight_b1(b1, 'preflight-b1', 1))
            evidence.write('p7-deepseek-relay.json', p7)
        except Exception:
            result = {'schema': SCHEMA + '.preflight.v1', 'identity': self.identity.as_dict(),
                      'passed': False, 'checks': checks, 'evidence': evidence.items,
                      'created_at': utc_now()}
            if not self.preflight_path.exists():
                write_new_json(self.preflight_path, result)
            raise Blocked('preflight failed; no scenario may start')
        result = {'schema': SCHEMA + '.preflight.v1', 'identity': self.identity.as_dict(),
                  'passed': True, 'checks': checks, 'evidence': evidence.items,
                  'external_dns_server': route['external_dns_server'], 'api_ipv4': route['api_ipv4'],
                  'created_at': utc_now()}
        if self.preflight_path.exists():
            old = read_json(self.preflight_path)
            if old.get('identity') != result['identity'] or not old.get('passed'):
                raise Blocked('preflight file exists with another identity/result; use a new suite root')
        else:
            write_new_json(self.preflight_path, result)
        return result

    def _clean_cycle(self, config: str, scenario_id: str, attempt: int) -> dict[str, Any]:
        loaded = self._mutate(scenario_id, attempt, 1, 'load_config', {'name': config})
        started = self._mutate(scenario_id, attempt, 2, 'start', {})
        if started.get('state') != 'healthy':
            raise SuiteError('normal start did not publish healthy')
        samples = []
        for _ in range(3):
            time.sleep(2)
            sample = self._status()
            samples.append(sample)
            if sample.get('state') != 'healthy':
                raise SuiteError('health drift in normal cycle')
        stopped = self._mutate(scenario_id, attempt, 3, 'stop', {})
        if stopped.get('state') != 'stopped':
            raise SuiteError('normal stop did not converge')
        return {'loaded': loaded, 'started': started, 'health_samples': samples,
                'stopped': stopped}

    def _preflight_b1(self, content: str, scenario_id: str, attempt: int) -> dict[str, Any]:
        assert self.vm
        name = 'sst-preflight-b1.ini'
        created = self._mutate(scenario_id, attempt, 10, 'create_config',
                               {'name': name, 'content': content})
        try:
            loaded = self._mutate(scenario_id, attempt, 11, 'load_config', {'name': name})
            started = self._mutate(scenario_id, attempt, 12, 'start', {})
            if started.get('state') != 'healthy':
                raise SuiteError('B1 did not start healthy')
            probe, raw = self._vm_json(
                "$ErrorActionPreference='Stop';$p=" + quote_ps(GUEST_ROOT + r'\scenario-suite-20260912\scenario_probes.ps1') +
                ";$n='preflight-'+[guid]::NewGuid().ToString();& $p -Action preflight-b1 -Nonce $n;"
                "if($LASTEXITCODE -ne 0){throw 'B1 curl probe failed'}", 60)
            stopped = self._mutate(scenario_id, attempt, 13, 'stop', {})
            if stopped.get('state') != 'stopped' or probe.get('exit_code') != 0:
                raise SuiteError('B1 relay preflight failed')
            return {'created': created, 'loaded': loaded, 'started': started,
                    'probe': probe, 'probe_raw': raw, 'stopped': stopped}
        finally:
            status = self._status()
            if status.get('state') != 'stopped':
                self._mutate(scenario_id, attempt, 14, 'stop', {})
            current = self.service.tool('read_config', {'name': name}) if self.service else {}
            if not current.get('error'):
                self._mutate(scenario_id, attempt, 15, 'delete_config',
                             {'name': name, 'expected_sha256': current['sha256']})

    def _prune_scenario_configs(self, scenario_id: str) -> dict[str, Any]:
        """Delete this scenario's own leftover configs from aborted attempts.

        Retry roots re-derive identical scratch/active/import names; an
        attempt that aborted between rename and scenario end leaves the
        active name behind and turns this attempt's rename into a name
        conflict (discovery100-112 sst-003). The prune touches only names
        carrying this scenario's id prefix, never the loaded builtin, and is
        recorded as evidence rather than as interface calls so the call-plan
        contract stays the same.
        """
        assert self.service
        listing = self.service.tool('list_configs', timeout=60)
        leftovers = [str(row['name']) for row in listing.get('configs', [])
                     if str(row['name']).startswith(scenario_id + '-')]
        record = {'prefix': scenario_id + '-', 'leftovers': leftovers,
                  'deleted': [], 'rebound': None, 'failures': []}
        if not leftovers:
            return record
        status = self._status()
        for name in leftovers:
            try:
                # The service publishes config_identity as an explicit null
                # while no config is loaded; an absent-or-dict default would
                # still surface None.get (discovery100-117 sst-002).
                if (status.get('config_identity') or {}).get('name') == name:
                    self.service.tool('load_config', {
                        'name': 'default.ini',
                        'command_id': 'prune-rebind-' + uuid.uuid4().hex[:8],
                        'expected_state_version': status['state_version']}, timeout=60)
                    record['rebound'] = 'default.ini'
                    status = self._status()
                current = self.service.tool('read_config', {'name': name}, timeout=60)
                sha = current.get('sha256')
                if not sha:
                    raise ValueError('leftover config read returned no sha256')
                self.service.tool('delete_config', {
                    'name': name, 'expected_sha256': sha,
                    'command_id': 'prune-delete-' + uuid.uuid4().hex[:8],
                    'expected_state_version': status['state_version']}, timeout=60)
                record['deleted'].append(name)
                status = self._status()
            except Exception as exc:  # noqa: BLE001
                record['failures'].append({'name': name, 'error': repr(exc)})
        return record

    def _require_preflight(self) -> dict[str, Any]:
        if not self.preflight_path.is_file():
            raise Blocked('preflight.json absent')
        result = read_json(self.preflight_path)
        if not result.get('passed') or result.get('identity') != self.identity.as_dict():
            raise Blocked('preflight does not pass for this candidate identity')
        if not result.get('external_dns_server') or not result.get('api_ipv4'):
            raise Blocked('preflight lacks separate resolver and api IPv4 evidence')
        return result

    def _state_path(self, scenario_id: str) -> Path:
        return self.root / 'states' / ('scenario-%s.state.json' % scenario_id)

    def _result_path(self, scenario_id: str) -> Path:
        return self.root / 'results' / ('scenario-%s.json' % scenario_id)

    def _write_state(self, scenario_id: str, state: dict[str, Any]) -> None:
        replace_json(self._state_path(scenario_id), state)

    def _continuation_gate(self) -> dict[str, Any]:
        assert self.vm
        status = self._status()
        if status.get('state') != 'stopped' or status.get('run_id'):
            raise Blocked('managed service is not stopped before scenario')
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$fault='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json';"
            "$probe=@(Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {$_.Path -and $_.Path -like '*scenario*'});"
            "$pkt=(pktmon status | Out-String);@{fault=(Test-Path $fault);probe_count=$probe.Count;pktmon=$pkt}|ConvertTo-Json -Compress", 60)
        if value.get('fault') or value.get('probe_count') or 'Running' in str(value.get('pktmon')):
            raise Blocked('continuation gate found fault/probe/pktmon residue')
        return {'status': status, 'vm': value, 'raw': raw}

    def _guest_scenario_root(self, scenario_id: str, attempt: int) -> str:
        scope = hashlib.sha256(str(self.root.resolve()).encode()).hexdigest()[:12]
        return GUEST_ROOT + '\\scenario-suite-20260912\\' + scope + '-' + scenario_id + ('-a%d' % attempt)

    def _start_kernel_capture(self, run_root: str) -> dict[str, Any]:
        session = 'SST-Kernel-' + str(uuid.uuid4())
        command = (
            "$ErrorActionPreference='Stop';$r=" + quote_ps(run_root) + ";"
            "New-Item -ItemType Directory -Path $r -Force|Out-Null;$s=" + quote_ps(session) + ";"
            "$etl=Join-Path $r 'kernel-network.etl';if(Test-Path $etl){throw 'kernel capture collision'};" +
            _sst_clock.clock_sample_ps('clock') +
            "$meta=@{capture_mode='kernel-network-ipv4';session_name=$s;etl_path=$etl;events_path=(Join-Path $r 'kernel-network.events.jsonl');header_path=(Join-Path $r 'kernel-network.header.xml');summary_path=(Join-Path $r 'kernel-network.summary.txt');clock_before=$clock};"
            "$mp=Join-Path $r 'kernel-network.metadata.json';$meta|ConvertTo-Json -Depth 8|Set-Content $mp -Encoding UTF8;"
            "$start=(& logman start $s -ets -o $etl -p Microsoft-Windows-Kernel-Network 0x10 4|Out-String);"
            "if($LASTEXITCODE -ne 0){$query=(& logman query $s -ets|Out-String);if($LASTEXITCODE -eq 0){& logman stop $s -ets|Out-Null};throw ('kernel trace start failed: '+$start)};"
            "@{session_name=$s;metadata=$mp;guest=$r;start_output=$start}|ConvertTo-Json -Compress")
        try:
            value, raw = self._vm_json(command, 60)
        except Exception as original:
            cleanup = "$s=" + quote_ps(session) + ";$q=(& logman query $s -ets|Out-String);if($LASTEXITCODE -eq 0){& logman stop $s -ets|Out-Null;if($LASTEXITCODE -ne 0){throw 'owned kernel session could not stop'}};@{session=$s;query=$q}|ConvertTo-Json -Compress"
            try:
                self._vm_json(cleanup,60)
            except Exception as secondary:
                raise SuiteError('kernel capture start failed: %r; cleanup failed: %r' % (original,secondary)) from original
            raise
        value['raw'] = raw
        return value

    def _stop_kernel_capture(self, capture: dict[str, Any]) -> dict[str, Any]:
        command = (
            "$ErrorActionPreference='Stop';$mp=" + quote_ps(capture['metadata']) + ";$m=Get-Content $mp -Raw|ConvertFrom-Json;"
            "if($m.session_name -ne " + quote_ps(capture['session_name']) + "){throw 'kernel capture identity mismatch'};"
            "$q=(& logman query $m.session_name -ets|Out-String);$session_present=($LASTEXITCODE -eq 0);$stop='';"
            "if($session_present){$stop=(& logman stop $m.session_name -ets|Out-String);if($LASTEXITCODE -ne 0){throw ('kernel trace stop failed: '+$stop)}};"
            "$m|Add-Member -NotePropertyName session_present_at_stop -NotePropertyValue $session_present -Force;" +
            _sst_clock.clock_sample_ps('clock') +
            "$m|Add-Member -NotePropertyName clock_after -NotePropertyValue $clock -Force;$m|ConvertTo-Json -Depth 8|Set-Content $mp -Encoding UTF8;"
            "if(Test-Path $m.events_path){throw 'kernel conversion collision'};$writer=[IO.StreamWriter]::new($m.events_path,$false,[Text.UTF8Encoding]::new($false));"
            "$ordinal=0;try{Get-WinEvent -Path $m.etl_path -Oldest -ErrorAction Stop|ForEach-Object {$writer.WriteLine((@{ordinal=$ordinal;xml=$_.ToXml()}|ConvertTo-Json -Compress -Depth 4));$ordinal++}}finally{$writer.Dispose()};"
            "& tracerpt $m.etl_path -o $m.header_path -of XML -summary $m.summary_path -y|Out-Null;$exit=$LASTEXITCODE;"
            "$c=@{event_reader=('Get-WinEvent -Path '+$m.etl_path+' -Oldest | ForEach-Object { $_.ToXml() }');event_reader_exit_code=0;tracerpt_argv=@('tracerpt',$m.etl_path,'-o',$m.header_path,'-of','XML','-summary',$m.summary_path,'-y');tracerpt_exit_code=$exit};"
            "function Hash-Shared([string]$p){for($i=0;$i -lt 10;$i++){try{return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}catch{Start-Sleep -Milliseconds 500}};throw ('file remained shared: '+$p)};"
            "foreach($pair in @(@('etl',$m.etl_path),@('events',$m.events_path),@('header',$m.header_path),@('summary',$m.summary_path))){$c[($pair[0]+'_sha256')]=Hash-Shared $pair[1]};"
            "$m|Add-Member -NotePropertyName conversion -NotePropertyValue $c -Force;$m|ConvertTo-Json -Depth 8|Set-Content $mp -Encoding UTF8;if($exit -ne 0){throw 'kernel tracerpt failed'};"
            "@{files=@(@($m.etl_path,$m.events_path,$m.header_path,$m.summary_path,$mp)|ForEach-Object {$f=Get-Item $_;@{path=$f.FullName;bytes=$f.Length;sha256=(Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()}})}|ConvertTo-Json -Depth 5 -Compress")
        value, raw = self._vm_json(command, 120)
        return dict(files=value['files'], raw=raw)

    def _start_capture_and_probe(self, guest: str, profile: dict[str, Any], nonce: str,
                                 run_label: str) -> dict[str, Any]:
        """Start one independent pktmon/probe chain for exactly one run."""
        assert self.vm
        script = GUEST_ROOT + r'\scenario-suite-20260912\scenario_probes.ps1'
        run_root = guest + '\\' + run_label
        params = dict(Action='traffic', Profile=profile['bucket'], Nonce=nonce,
            Output=run_root + r'\probe.jsonl', StopFile=run_root + r'\probe.stop',
            StartFile=run_root + r'\probe.start', CaseFile=run_root + r'\probe.cases',
            Tempo=profile['tempo'], Variant=profile['variant'], Interleave=profile['interleave'],
            CadenceMilliseconds=int(profile['cadence_ms']), HoldSeconds=int(profile['connection_window_seconds']),
            TargetHost=profile['probe_target']['host'], TargetPort=int(profile['probe_target']['port']),
            TargetProtocol=profile['probe_target']['protocol'],
            ProcessMode=profile['probe_target'].get('process_mode', 'match'),
            TlsServerName=profile['probe_target'].get('tls_server_name', ''),
            FnprRole=profile['probe_target'].get('fnpr_role', ''),
            AdditionalTargetsJson=json.dumps(list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ())), separators=(',', ':')),
            StartupRetrySeconds=int(profile.get('startup_retry_seconds', 70)))
        splat = ';'.join(key + '=' + (str(value) if isinstance(value, int) else quote_ps(value)) for key, value in params.items())
        child = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$parameters=@{" + splat + "};try{& " + quote_ps(script) + " @parameters 1> " + quote_ps(run_root + r'\probe.stdout') + " 2> " + quote_ps(run_root + r'\probe.stderr') + "}catch{$_|Out-File -LiteralPath " + quote_ps(run_root + r'\probe.stderr') + ";exit 1}"
        encoded_child = base64.b64encode(child.encode('utf-16le')).decode('ascii')
        command = (
            "$ErrorActionPreference='Stop';$captureStarted=$false;$p=$null;try{$g=" + quote_ps(guest) + ";$r=Join-Path $g " + quote_ps(run_label) +
            ";New-Item -ItemType Directory -Path $r -Force|Out-Null;"
            "$etl=Join-Path $r 'pktmon.etl';$nic=Join-Path $r 'pktmon-nic.json';"
            "$list=(& pktmon list|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon list failed'};"
            "$adapters=@(Get-NetAdapter|Select-Object ifIndex,Name,InterfaceDescription,MacAddress,Status);"
            "$before=(& pktmon counters|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon counters before start failed'};" +
            _sst_clock.clock_sample_ps('clockBefore') +
            "@{capture_mode='all-components-tcpip';clock_before=$clockBefore;schema='" + NIC_CAPTURE_SCHEMA + "';captured_utc=[DateTime]::UtcNow.ToString('o');pktmon_list=$list;adapters=$adapters;pktmon_counters_before=$before}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $nic -Encoding UTF8;"
            "$pktmonStart=(& pktmon start --capture --comp all --pkt-size 0 --flags 0x1f --trace -p Microsoft-Windows-TCPIP -k 0xFF -l 4 --file-name $etl --file-size "
            + str(self.pktmon_file_size_mib) + "|Out-String);"
            "if($LASTEXITCODE -ne 0){throw 'pktmon start failed'};$captureStarted=$true;"
            "$out=Join-Path $r 'probe.jsonl';$start=Join-Path $r 'probe.start';$cases=Join-Path $r 'probe.cases';$stop=Join-Path $r 'probe.stop';$script=" + quote_ps(script) + ";"
            "$encoded=" + quote_ps(encoded_child) + ";"
            "$stdout=Join-Path $r 'probe.stdout';$stderr=Join-Path $r 'probe.stderr';"
            "$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=('powershell.exe -NoProfile -EncodedCommand '+$encoded);CurrentDirectory=$r};if($created.ReturnValue -ne 0){throw 'probe process creation failed'};$p=Get-Process -Id $created.ProcessId -ErrorAction Stop;$launchPid=$p.Id;$launchCreation=$p.StartTime.ToUniversalTime().Ticks;"
            "$deadline=[DateTime]::UtcNow.AddSeconds(20);while(!(Test-Path $out) -and -not $p.HasExited -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100};"
            "if(!(Test-Path $out) -or $p.HasExited){throw ('probe did not become ready: '+(Get-Content $stderr -Raw -ErrorAction SilentlyContinue))};"
            "$ready=Get-Content $out -TotalCount 1|ConvertFrom-Json;if($ready.event -ne 'ready' -or [int]$ready.pid -ne $p.Id -or [long]$ready.creation_ticks -ne $p.StartTime.ToUniversalTime().Ticks){throw 'probe ready identity mismatch'};"
            "@{guest=$r;run_label=" + quote_ps(run_label) + ";pid=$p.Id;etl=$etl;probe=$out;start=$start;case=$cases;stop=$stop;pktmon_nic=$nic;probe_creation_ticks=$ready.creation_ticks;stdout=$stdout;stderr=$stderr;capture_scope='all-components';requested_file_size_mib="
            + str(self.pktmon_file_size_mib) + ";tempo=" + quote_ps(profile['tempo']) + ";cadence_ms=" + str(int(profile['cadence_ms'])) + ";startup_retry_seconds=" + str(int(profile.get('startup_retry_seconds', 70))) + ";variant=" + quote_ps(profile['variant']) + ";probe_target=" + quote_ps(json.dumps(profile['probe_target'], separators=(',', ':'))) + ";interleave=" + quote_ps(profile['interleave']) + ";started=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress}catch{$failure=[string]$_;$cleanup=@();$coop=$null;$err2=@();$launchPidOut=$launchPid;$launchCreationOut=$launchCreation;if($stop){try{if(-not (Test-Path $stop)){[IO.File]::WriteAllText($stop,'stop',[Text.UTF8Encoding]::new($false))}}catch{$err2+=('stopfile: '+[string]$_)}};$procInfo=$null;try{$procInfo=Get-Process -Id $launchPidOut -ErrorAction SilentlyContinue}catch{$err2+=('query: '+[string]$_)};$actualCreation=$null;try{if($null -ne $procInfo){$actualCreation=$procInfo.StartTime.ToUniversalTime().Ticks}}catch{$err2+=('identity-read: '+[string]$_)};if($null -eq $procInfo){$coop='exited'}elseif(-not $launchCreationOut -or $launchCreationOut -le 0){$coop='identity-unknown';$err2+=('identity-unknown: no launch creation recorded')}elseif($null -eq $actualCreation){$coop='identity-unknown';$err2+=('identity-unknown: process present but creation unreadable')}elseif($actualCreation -ne $launchCreationOut){$coop='identity-mismatch(new process not touched)'}else{try{$deadlineW=[Diagnostics.Stopwatch]::StartNew();while(-not $procInfo.HasExited -and $deadlineW.ElapsedMilliseconds -lt 30000){Start-Sleep -Milliseconds 200};if($procInfo.HasExited){$coop='exited'}else{$coop='timeout'}}catch{$err2+=('wait: '+[string]$_);if(-not $coop){$coop='wait-error'}}};if($captureStarted){try{$captureStop=(& pktmon stop|Out-String);if($LASTEXITCODE -ne 0){$cleanup+='pktmon stop exit '+$LASTEXITCODE}}catch{$cleanup+='pktmon stop error: '+[string]$_}}else{$cleanup+='pktmon not started; no capture cleanup owed'};@{startup_failed=$true;error=$failure;cleanup_errors=$cleanup;cooperative_errors=$err2;capture_started=$captureStarted;guest=$r;cooperative_exit=$coop;probe_pid=$launchPidOut;probe_creation_ticks=$launchCreationOut}|ConvertTo-Json -Compress}")
        kernel = self._start_kernel_capture(run_root)
        try:
            value, raw = self._vm_json(command, 60)
            if value.get('startup_failed'):
                raise SuiteError('capture/probe startup failed: %r' % dict(value, raw=raw))
        except BaseException as original:
            try:
                self._stop_kernel_capture(kernel)
            except Exception as secondary:
                raise SuiteError('probe capture start failed: %r; kernel cleanup failed: %r' % (original,secondary)) from original
            raise
        value['raw'] = raw
        value['kernel_capture'] = kernel
        return value

    def _probe_cooperative_cleanup_command(self, pid, creation_ticks, stop_path,
                                            status_path, pktmon_stop_command,
                                            wait_seconds=30):
        """Production command body for bounded cooperative probe cleanup.

        Identity-bound (pid + creation ticks captured at launch): PID reuse is
        recorded, never acted on; a missing identity fails closed as
        identity-unknown without waiting on or touching any process.  Every
        failure is collected separately, the owned pktmon cleanup always runs
        (in a finally), and the outcome JSON (with error list) is written to
        status_path and echoed on stdout so Python can fail the call.  Only
        the probe's own stop file is written; no process is ever killed.
        """
        return (
            "$ErrorActionPreference='Continue';"
            "$outcome=@{pid=" + str(int(pid)) + ";creation_ticks=" + str(int(creation_ticks or 0)) + ";cooperative_exit=$null;errors=@()}\n"
            "try{if(-not (Test-Path " + quote_ps(stop_path) + ")){[IO.File]::WriteAllText(" + quote_ps(stop_path) + ",'stop')}}catch{$outcome.errors+=('stopfile: '+[string]$_)}\n"
            "$p=$null;try{$p=Get-Process -Id " + str(int(pid)) + " -ErrorAction SilentlyContinue}catch{$outcome.errors+=('query: '+[string]$_)}\n"
            "$expected=" + str(int(creation_ticks or 0)) + ";\n"
            # the identity read is itself guarded: a process that exits between
            # Get-Process and StartTime surfaces as identity-read, never a crash
            # and never a wait on an unverified process.
            "$actual=$null;try{if($null -ne $p){$actual=$p.StartTime.ToUniversalTime().Ticks}}catch{$outcome.errors+=('identity-read: '+[string]$_)}\n"
            "if($null -eq $p){$outcome.cooperative_exit='exited'}\n"
            "elseif($expected -le 0){$outcome.cooperative_exit='identity-unknown';$outcome.errors+=('identity-unknown: pid '+(" + str(int(pid)) + ")+' has no recorded creation')}\n"
            "elseif($null -eq $actual){$outcome.cooperative_exit='identity-unknown';$outcome.errors+=('identity-unknown: process present but creation unreadable')}\n"
            "elseif($actual -ne $expected){$outcome.cooperative_exit='identity-mismatch(new process not touched)'}\n"
            "else{try{$deadline=[Diagnostics.Stopwatch]::StartNew();while(-not $p.HasExited -and $deadline.ElapsedMilliseconds -lt " + str(int(wait_seconds) * 1000) + "){Start-Sleep -Milliseconds 200};if($p.HasExited){$outcome.cooperative_exit='exited'}else{$outcome.cooperative_exit='timeout'}}catch{$outcome.errors+=('wait: '+[string]$_);if(-not $outcome.cooperative_exit){$outcome.cooperative_exit='wait-error'}}}\n"
            "try{$outcome.pktmon_stop=(& " + pktmon_stop_command + " 2>&1 | Out-String);$outcome.pktmon_exit=$LASTEXITCODE;if($LASTEXITCODE -ne 0){$outcome.errors+=('pktmon stop exit '+$LASTEXITCODE)}}catch{$outcome.pktmon_exit=-1;$outcome.errors+=('pktmon: '+[string]$_)}\n"
            "try{$prevEap=$ErrorActionPreference;$ErrorActionPreference='Stop';$outcome|ConvertTo-Json -Depth 4 -Compress|Set-Content -LiteralPath " + quote_ps(status_path) + " -Encoding UTF8}catch{$outcome.errors+=('status-write: '+[string]$_)}finally{if($prevEap){$ErrorActionPreference=$prevEap}}\n"
            "$outcome|ConvertTo-Json -Depth 4 -Compress")

    def _fail_closed_cooperative(self, value, capture_label):
        """Fail the call unless cooperative cleanup provably closed the probe.

        timeout, stopfile errors, identity-unknown/mismatch and any cleanup
        error are responsibilities, not successes; the original failure is
        never masked by a cleanup error.
        """
        if not isinstance(value, dict):
            raise SuiteError('cooperative cleanup returned no structure: %r (%s)' % (value, capture_label))
        status = value.get('cooperative_exit')
        errors = value.get('errors') or []
        if status != 'exited':
            raise SuiteError('probe did not cooperatively exit (status=%r errors=%r pid=%r creation=%r stop=%r)'
                             % (status, errors, value.get('pid'), value.get('creation_ticks'), capture_label))
        if errors:
            raise SuiteError('cooperative cleanup closed with errors (errors=%r pid=%r creation=%r stop=%r)'
                             % (errors, value.get('pid'), value.get('creation_ticks'), capture_label))
        return value

    def _release_probe(self, capture: dict[str, Any], phase: str) -> dict[str, Any]:
        """Open one probe gate at an independently recorded lifecycle phase."""
        assert self.vm
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p=" + quote_ps(capture['start']) + ";"
            "if(Test-Path $p){throw 'probe start control was already released'};"
            "[IO.File]::WriteAllText($p," + quote_ps(phase) + ",[Text.UTF8Encoding]::new($false));"
            "@{phase=" + quote_ps(phase) + ";path=$p;released_utc=[DateTimeOffset]::UtcNow.ToString('o');bytes=(Get-Item $p).Length}|ConvertTo-Json -Compress", 60)
        value['raw'] = raw
        return value

    def _release_probe_cases(self, capture: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any] | None:
        """Release auxiliary policy probes only after this run is healthy.

        The primary probe is independently released at its declared lifecycle
        phase.  Boundary cases need a real policy instance to test, so their
        separate control file is created only after the successful start (or
        restart) response.  The probe records consuming this file in JSONL.
        """
        cases = list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ()))
        if not cases:
            return None
        assert self.vm
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p=" + quote_ps(capture['case']) + ";"
            "if(Test-Path $p){throw 'probe case control was already released'};"
            "[IO.File]::WriteAllText($p,'after-healthy',[Text.UTF8Encoding]::new($false));"
            "@{phase='after-healthy';path=$p;released_utc=[DateTimeOffset]::UtcNow.ToString('o');bytes=(Get-Item $p).Length;case_count=" +
            str(len(cases)) + "}|ConvertTo-Json -Compress", 60)
        value['raw'] = raw
        return value

    def _await_probe_cases(self, capture: dict[str, Any], profile: dict[str, Any],
                           count: int) -> dict[str, Any] | None:
        """Observe the guest completing every separately released case."""
        if not count:
            return None
        assert self.vm
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p=" + quote_ps(capture['probe']) + ";"
            "$deadline=[DateTime]::UtcNow.AddSeconds(90);$result=$null;"
            "while([DateTime]::UtcNow -lt $deadline){if(Test-Path $p){$rows=@(Get-Content -LiteralPath $p -ErrorAction Stop|ForEach-Object {try{$_|ConvertFrom-Json}catch{$null}}|Where-Object {$_});"
            "$released=@($rows|Where-Object {$_.event -eq 'cases_released'});$closed=@($rows|Where-Object {$_.event -eq 'case_close'});$curl=@($rows|Where-Object {$_.event -eq 'curl_completed'});"
            "if($released.Count -eq 1 -and $closed.Count -ge " + str(count) + " -and (" +
            ('$curl.Count -eq 1' if profile['bucket'] in ('B1', 'B4') else '$true') +
            ")){$result=[ordered]@{released=$released[0];case_close_count=$closed.Count;curl_completed_count=$curl.Count;observed_utc=[DateTimeOffset]::UtcNow.ToString('o')};break}};Start-Sleep -Milliseconds 100};"
            "if($null -eq $result){throw 'released probe cases/curl did not complete within 90 seconds'};$result|ConvertTo-Json -Depth 6 -Compress", 105)
        value['raw'] = raw
        return value

    def _run_auxiliary_cases(self, run: dict[str, Any], capture: dict[str, Any],
                             profile: dict[str, Any]) -> None:
        """Release and observe every boundary case after this run is healthy.

        Boundary probes deliberately have their own control file: their
        ``after-healthy`` timing must not be coupled to the primary probe's
        declared lifecycle interleave.  Keeping the release and completion in
        one helper also makes the first and restart runs use the same contract.
        """
        cases = list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ()))
        run['case_release'] = self._release_probe_cases(capture, profile)
        if run['case_release'] is not None:
            run['case_completion'] = self._await_probe_cases(capture, profile, len(cases))

    def _stop_capture_and_probe(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Cooperatively stop THIS probe, then stop the owned captures.

        The probe stop runs through the shared cooperative helper: the stop
        file write, the identity-bound bounded wait, the owned pktmon stop
        and the status write all live in one guarded body whose JSON outcome
        fails this call closed on timeout / stopfile error / identity
        unknown / cleanup errors.  A probe that provably exited stays a
        success; a reused PID is recorded, never waited on or touched.
        """
        assert self.vm
        status_path = str(capture['probe']) + '.exit-status.json'
        coop_cmd = self._probe_cooperative_cleanup_command(
            capture['pid'], capture.get('probe_creation_ticks'), capture['stop'],
            status_path, 'pktmon stop', wait_seconds=30)
        clock_after = _sst_clock.clock_sample_ps('clockAfter')
        nic_update = (
            "$nic=Get-Content -LiteralPath " + quote_ps(capture['pktmon_nic']) + " -Raw|ConvertFrom-Json;"
            "$nic|Add-Member -NotePropertyName clock_after -NotePropertyValue $clockAfter -Force;"
            "$after=(& pktmon counters|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon counters after stop failed'};"
            "$status=(& pktmon status|Out-String);"
            "$nic|Add-Member -NotePropertyName pktmon_counters_after -NotePropertyValue $after -Force;"
            "$nic|Add-Member -NotePropertyName pktmon_status_after -NotePropertyValue $status -Force;")
        conversion = (
            "& pktmon etl2txt " + quote_ps(capture['etl']) +
            " --out " + quote_ps(str(capture['etl']).replace('.etl', '.txt')) + " | Out-Null;$conversionExit=$LASTEXITCODE;"
            "$conversion=@{exit_code=$conversionExit;argv=@('pktmon','etl2txt'," + quote_ps(capture['etl']) + ",'--out'," + quote_ps(str(capture['etl']).replace('.etl', '.txt')) + ");etl_sha256=(Get-FileHash -LiteralPath " + quote_ps(capture['etl']) + " -Algorithm SHA256).Hash.ToLower();text_sha256=(Get-FileHash -LiteralPath " + quote_ps(str(capture['etl']).replace('.etl', '.txt')) + " -Algorithm SHA256).Hash.ToLower()};"
            "$nic|Add-Member -NotePropertyName conversion -NotePropertyValue $conversion -Force;")
        nic_write = "$nic|ConvertTo-Json -Depth 8|Set-Content -LiteralPath " + quote_ps(capture['pktmon_nic']) + " -Encoding UTF8;"
        files_list = (
            "$files=@(" + quote_ps(capture['probe']) + ',' + quote_ps(capture['etl']) + ',' +
            quote_ps(str(capture['etl']).replace('.etl', '.txt')) + ',' + quote_ps(capture['pktmon_nic']) + ',' +
            quote_ps(capture['stdout']) + ',' + quote_ps(capture['stderr']) + ',' + quote_ps(status_path) + ");"
            "$clientOut=" + quote_ps(str(PureWindowsPath(capture['probe']).parent / 'probe-client.stdout')) + ";"
            "if(Test-Path $clientOut){$files=@($files+$clientOut)};"
            "@{files=@($files|ForEach-Object {$i=Get-Item $_ -ErrorAction Stop;@{path=$i.FullName;bytes=$i.Length;sha256=(Get-FileHash $i.FullName -Algorithm SHA256).Hash.ToLower()}})}|ConvertTo-Json -Depth 4 -Compress")
        # Guarded order: the cooperative body (stop file + bounded wait + owned
        # pktmon stop + status write) always completes its own cleanup; only
        # then do the nic/conversion/files steps run, each wrapped so a later
        # step cannot skip an earlier responsibility.
        command = ("$ErrorActionPreference='Stop';" +
                   "$coop=" + quote_ps(coop_cmd) + ";"
                   "$coopJson=& { Invoke-Expression $coop };"
                   "$coopValue=$coopJson|ConvertFrom-Json;"
                   + clock_after + nic_update + nic_write + conversion + nic_write +
                   "@{coop=$coopValue}|ConvertTo-Json -Depth 6 -Compress")
        primary_error = None
        value = None
        raw = None
        try:
            value, raw = self._vm_json(command, 180)
            coop = value.get('coop') if isinstance(value, dict) else None
            self._fail_closed_cooperative(coop, capture['stop'])
        except Exception as exc:  # noqa: BLE001
            primary_error = exc
        try:
            kernel = self._stop_kernel_capture(capture['kernel_capture'])
        except Exception as secondary:
            if primary_error is not None:
                raise SuiteError('packet capture stop failed: %r; kernel stop failed: %r' % (primary_error, secondary)) from primary_error
            raise
        if primary_error is not None:
            raise primary_error
        # files export runs only after cooperative closure succeeded; its own
        # failure is a new responsibility, raised after kernel cleanup.
        try:
            files_cmd = ("$ErrorActionPreference='Stop';" + files_list)
            files_value, files_raw = self._vm_json(files_cmd, 120)
        except Exception as exc:  # noqa: BLE001
            raise SuiteError('capture file export failed after cleanup: %r' % (exc,))
        if not isinstance(files_value.get('files'), list):
            raise SuiteError('capture metadata files not an array')
        return {'files': files_value['files'] + kernel['files'], 'raw': raw,
                'kernel_raw': kernel['raw'], 'run_label': capture['run_label'],
                'cooperative_exit': value.get('coop', {}).get('cooperative_exit'),
                'exit_status_path': status_path}


    def _transfer_guest_file(self, guest_path: str, size: int, sha256: str,
                             destination: Path) -> dict[str, Any]:
        assert self.vm
        if not 0 <= int(size) <= MAX_GUEST_TRANSFER:
            raise SuiteError('guest evidence outside transfer bound: ' + guest_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        actual = hashlib.sha256()
        with destination.open('xb') as stream:
            for offset in range(0, int(size), 1024 * 1024):
                length = min(1024 * 1024, int(size) - offset)
                command = (
                    "$ErrorActionPreference='Stop';$s=[IO.File]::OpenRead(" + quote_ps(guest_path) + ");"
                    "try{$null=$s.Seek(" + str(offset) + ",[IO.SeekOrigin]::Begin);$b=New-Object byte[] " + str(length) + ";"
                    "$n=$s.Read($b,0,$b.Length);if($n -ne $b.Length){throw 'short read'};[Convert]::ToBase64String($b)}finally{$s.Dispose()}")
                block = base64.b64decode(self.vm.powershell(command, 60)['output'], validate=True)
                if len(block) != length:
                    raise SuiteError('guest evidence short base64 block')
                stream.write(block)
                actual.update(block)
        if actual.hexdigest().lower() != str(sha256).lower():
            raise SuiteError('guest evidence SHA-256 mismatch: ' + guest_path)
        return file_record(destination, self.root)

    def _fault_mode(self, enabled: bool) -> dict[str, Any]:
        """Toggle fault mode while preserving original registry/config bytes.

        The snapshot is taken once inside the suite guest directory. Disable
        restores saved bytes and MultiString exactly; it never recreates a
        service.json from a parsed object or guesses the normal grace period.
        """
        assert self.vm
        guest = GUEST_ROOT + r'\scenario-suite-20260912'
        if enabled:
            body = """$g=""" + quote_ps(guest) + """;$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp';$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';
New-Item -ItemType Directory -Path $g -Force|Out-Null;$backup=Join-Path $g 'fault-mode-original-service.json';$envbackup=Join-Path $g 'fault-mode-original-environment.xml';
& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop;if($LASTEXITCODE -ne 0){throw 'controlled stop failed'};
if(!(Test-Path $backup)){[IO.File]::WriteAllBytes($backup,[IO.File]::ReadAllBytes($cfg));$v=Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue;$present=$null -ne $v -and $null -ne $v.Environment;[pscustomobject]@{present=$present;values=@($v.Environment)}|Export-Clixml $envbackup}
$original=[IO.File]::ReadAllBytes($backup);$before=Get-FileHash $cfg -Algorithm SHA256;$cfgObject=([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($cfg))|ConvertFrom-Json);$originalGrace=([Text.Encoding]::UTF8.GetString($original)|ConvertFrom-Json).stop_grace_seconds;$cfgObject.stop_grace_seconds=5;[IO.File]::WriteAllText($cfg,($cfgObject|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false));
$saved=Import-Clixml $envbackup;$values=@($saved.values|Where-Object {$_ -and $_ -notlike 'FAKENETNG_MCP_FAULT_INJECTION=*'});New-ItemProperty $key -Name Environment -PropertyType MultiString -Value @($values+'FAKENETNG_MCP_FAULT_INJECTION=1') -Force|Out-Null;Start-Service fakenetng-mcp;
@{enabled=$true;backup=$backup;backup_sha256=(Get-FileHash $backup -Algorithm SHA256).Hash.ToLower();original_grace=$originalGrace;before_sha256=$before.Hash.ToLower();state=(Get-Service fakenetng-mcp).Status.ToString()}|ConvertTo-Json -Compress"""
        else:
            body = """$g=""" + quote_ps(guest) + """;$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp';$cfg='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json';$backup=Join-Path $g 'fault-mode-original-service.json';$envbackup=Join-Path $g 'fault-mode-original-environment.xml';
if(!(Test-Path $backup) -or !(Test-Path $envbackup)){throw 'fault-mode original snapshot is absent'};& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop;if($LASTEXITCODE -ne 0){throw 'controlled stop failed'};
[IO.File]::WriteAllBytes($cfg,[IO.File]::ReadAllBytes($backup));$saved=Import-Clixml $envbackup;if($saved.present){New-ItemProperty $key -Name Environment -PropertyType MultiString -Value @($saved.values) -Force|Out-Null}else{Remove-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue};Start-Service fakenetng-mcp;
$currentProperty=Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue;$current=@($currentProperty.Environment);$currentPresent=$null -ne $currentProperty -and $null -ne $currentProperty.Environment;$same=if($saved.present){$currentPresent -and @(Compare-Object @($saved.values) $current).Count -eq 0}else{-not $currentPresent};@{enabled=$false;backup=$backup;config_bytes_restored=((Get-FileHash $cfg -Algorithm SHA256).Hash -eq (Get-FileHash $backup -Algorithm SHA256).Hash);environment_restored=$same;original_grace=(([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($backup))|ConvertFrom-Json).stop_grace_seconds);current_grace=(([Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($cfg))|ConvertFrom-Json).stop_grace_seconds);state=(Get-Service fakenetng-mcp).Status.ToString()}|ConvertTo-Json -Compress"""
        value, raw = self._vm_json("$ErrorActionPreference='Stop';" + body, 180)
        if enabled and value.get('state') != 'Running':
            raise SuiteError('fault-mode service did not restart')
        if not enabled and (not value.get('config_bytes_restored') or
                            not value.get('environment_restored') or
                            value.get('state') != 'Running'):
            raise SuiteError('fault-mode exact restoration failed')
        value['raw'] = raw
        value['enabled'] = enabled
        # SCM Running precedes HTTP startup and supervisor recovery. Do not
        # dispatch scenarios (or declare restoration) until both have settled.
        deadline = time.monotonic() + 60
        observations = []
        while time.monotonic() < deadline:
            try:
                status = self._status(timeout=max(0.01, deadline - time.monotonic()))
                observations.append(status)
                if (status.get('state') == 'stopped' and
                        not status.get('run_id') and not status.get('controller')):
                    value['endpoint_status'] = status
                    value['endpoint_observations'] = observations
                    return value
                if status.get('state') != 'recovering':
                    raise SuiteError('fault-mode endpoint unexpected state: %r' % status)
            except urllib.error.URLError as exc:
                observations.append({'transport_error': repr(exc)})
            time.sleep(0.25)
        raise SuiteError('fault-mode endpoint readiness deadline: %r' % observations)

    def _ipc_evidence_mode(self, enabled: bool) -> dict[str, Any]:
        """Arm only the service IPC-evidence environment for one matrix pass.

        The product records the ipc-parent/ipc-child run originals only while
        the service process carries FAKENETNG_MCP_FAULT_INJECTION=1; every
        fault hook additionally requires an explicitly armed fault file, so
        this environment alone cannot alter benign run behaviour.  Unlike
        _fault_mode this never modifies service.json or its stop grace.  The
        original Environment value is backed up once and restored exactly, so
        a fault scenario's own _fault_mode(False) snapshot keeps this armed
        state until the matrix pass ends.
        """
        assert self.vm
        guest = GUEST_ROOT + r'\scenario-suite-20260912'
        backup = guest + r'\ipc-evidence-original-environment.xml'
        if enabled:
            body = """$g=""" + quote_ps(guest) + """;$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp';$envbackup=""" + quote_ps(backup) + """;
New-Item -ItemType Directory -Path $g -Force|Out-Null;& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop;if($LASTEXITCODE -ne 0){throw 'controlled stop failed'};
if(!(Test-Path $envbackup)){$v=Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue;$present=$null -ne $v -and $null -ne $v.Environment;[pscustomobject]@{present=$present;values=@($v.Environment)}|Export-Clixml $envbackup};
$saved=Import-Clixml $envbackup;$values=@($saved.values|Where-Object {$_ -and $_ -notlike 'FAKENETNG_MCP_FAULT_INJECTION=*'});New-ItemProperty $key -Name Environment -PropertyType MultiString -Value @($values+'FAKENETNG_MCP_FAULT_INJECTION=1') -Force|Out-Null;Start-Service fakenetng-mcp;
@{enabled=$true;backup=$envbackup;state=(Get-Service fakenetng-mcp).Status.ToString()}|ConvertTo-Json -Compress"""
        else:
            body = """$g=""" + quote_ps(guest) + """;$key='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp';$envbackup=""" + quote_ps(backup) + """;
if(!(Test-Path $envbackup)){throw 'ipc-evidence original snapshot is absent'};$stopPath='controlled';
& 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe' stop;if($LASTEXITCODE -ne 0){throw 'ipc-evidence controlled stop failed'};
$saved=Import-Clixml $envbackup;if($saved.present){New-ItemProperty $key -Name Environment -PropertyType MultiString -Value @($saved.values) -Force|Out-Null}else{Remove-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue};Start-Service fakenetng-mcp;
$currentProperty=Get-ItemProperty $key -Name Environment -ErrorAction SilentlyContinue;$current=@($currentProperty.Environment);$currentPresent=$null -ne $currentProperty -and $null -ne $currentProperty.Environment;$same=if($saved.present){$currentPresent -and @(Compare-Object @($saved.values) $current).Count -eq 0}else{-not $currentPresent};@{enabled=$false;backup=$envbackup;environment_restored=$same;stop_path=$stopPath;state=(Get-Service fakenetng-mcp).Status.ToString()}|ConvertTo-Json -Compress"""
        value, raw = self._vm_json("$ErrorActionPreference='Stop';" + body, 180)
        if value.get('state') != 'Running':
            raise SuiteError('ipc-evidence service did not restart')
        if not enabled and not value.get('environment_restored'):
            raise SuiteError('ipc-evidence exact restoration failed')
        value['raw'] = raw
        value['enabled'] = enabled
        # SCM Running precedes HTTP startup and supervisor recovery; mirror
        # _fault_mode so no scenario observes a half-recovered endpoint.
        deadline = time.monotonic() + 60
        observations = []
        while time.monotonic() < deadline:
            try:
                status = self._status(timeout=max(0.01, deadline - time.monotonic()))
                observations.append(status)
                if (status.get('state') == 'stopped' and
                        not status.get('run_id') and not status.get('controller')):
                    value['endpoint_status'] = status
                    value['endpoint_observations'] = observations
                    return value
                if status.get('state') != 'recovering':
                    raise SuiteError('ipc-evidence endpoint unexpected state: %r' % status)
            except urllib.error.URLError as exc:
                observations.append({'transport_error': repr(exc)})
            time.sleep(0.25)
        raise SuiteError('ipc-evidence endpoint readiness deadline: %r' % observations)

    def _arm_fault(self, fault: str, nonce: str) -> dict[str, Any]:
        assert self.vm
        if fault not in FAULTS:
            raise ValueError('unknown fault')
        payload = json.dumps({'fault': fault, 'nonce': nonce}, separators=(',', ':'))
        gate = fault in ('listener_stop', 'diverter_stop', 'child_hang')
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json';"
            "$g='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection-gate.json';"
            "if((Test-Path $p) -or (Test-Path $g)){throw 'existing unconsumed fault or gate'};"
            "$json=" + quote_ps(payload) + ";[IO.File]::WriteAllText($p,$json,[Text.UTF8Encoding]::new($false));$receipt=Get-Item $p;" +
            ("[IO.File]::WriteAllText($g,$json,[Text.UTF8Encoding]::new($false));$gate=Get-Item $g;" if gate else "$gate=$null;") +
            "@{path=$p;gate_path=if($gate){$g}else{$null};fault=" + quote_ps(fault) + ";nonce=" + quote_ps(nonce) + ";"
            "receipt_created_utc=$receipt.CreationTimeUtc.ToString('o');receipt_modified_utc=$receipt.LastWriteTimeUtc.ToString('o');"
            "gate_created_utc=if($gate){$gate.CreationTimeUtc.ToString('o')}else{$null};"
            "receipt=(Get-Content $p -Raw|ConvertFrom-Json)}|ConvertTo-Json -Compress", 60)
        if value.get('receipt') != {'fault': fault, 'nonce': nonce}:
            raise SuiteError('fault arm identity did not round-trip')
        if gate and not value.get('gate_path'):
            raise SuiteError('startup fault did not create its rendezvous gate')
        value['raw'] = raw
        return value

    def _capture_sections(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Capture the product's five recovery sections as raw VM observations."""
        from fakenet.mcp.baseline import process_capture_script
        command = (
            "$ErrorActionPreference='Stop';$dns=(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop|"
            "Select-Object InterfaceAlias,ServerAddresses|ConvertTo-Json -Compress);"
            "$routes=(& route.exe print -4|Out-String);if($LASTEXITCODE -ne 0){throw 'route capture failed'};"
            "$listen=(& netstat.exe -ano|Out-String);if($LASTEXITCODE -ne 0){throw 'listen capture failed'};"
            "$wd=(& {" + process_capture_script() + "}|Out-String);"
            "$svc=(Get-Service dnscache,mpssvc|Select-Object Name,Status|ConvertTo-Json -Compress);"
            "@{dns_servers=$dns;routes=$routes;listen_ports=$listen;windivert_processes=$wd;services=$svc}|ConvertTo-Json -Depth 8 -Compress")
        return self._vm_json(command, 90)

    def _section_difference(self, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        from sst_fault_evidence import native_section_compare
        return native_section_compare(before, after)

    @staticmethod
    def _difference_is_residue(difference: dict[str, Any],
                               attribution: dict[str, Any] | None) -> bool:
        """Non-listen differences are always residue; listen-only ones use
        the endpoint-owner attribution (empty/failed attribution blocks)."""
        if not difference:
            return False
        if set(difference) - {'listen_ports'}:
            return True
        if difference.get('listen_ports') is not None:
            return not attribution or bool(attribution.get('residue'))
        return False

    def _restart_baseline(self, previous_run: dict[str, Any],
                          attribution: dict[str, Any] | None = None) -> dict[str, Any]:
        """Use the verified restored state between restart's stop and start."""
        if not previous_run.get('recovery_audit', {}).get('files'):
            raise SuiteError('restart baseline lacks same-run recovery evidence')
        restored = previous_run['five_sections_after']
        difference = self._section_difference(previous_run['five_sections_before'], restored)
        if difference:
            # Same five-section difference attribution as the body check: a
            # vanished or foreign-owned endpoint change is environmental.
            if attribution is None:
                attribution = self._attribute_section_difference(
                    previous_run['five_sections_before'], restored)
            if self._difference_is_residue(difference, attribution):
                raise SuiteError('restart run-01 five-section recovery difference: ' + repr(difference))
        return dict(restored)

    @staticmethod
    def _read_probe_events(path: Path) -> list[dict[str, Any]]:
        try:
            return [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
        except (OSError, ValueError) as exc:
            raise SuiteError('invalid complete probe JSONL: %s' % (exc,)) from exc

    @staticmethod
    def _read_pktmon_text(path: Path) -> str:
        raw = path.read_bytes()
        try:
            return raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig')
        except UnicodeDecodeError as exc:
            raise SuiteError('pktmon export is not decodable: %s' % (exc,)) from exc

    _STOP_DIVERTER_RE = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\s+INFO FakeNet '
        r'STOP_PHASE_BEGIN phase=diverter\b')
    _EGRESS_READY_RE = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\s+INFO Diverter '
        r'EGRESS_CONTROL_READY\b')
    _LEGACY_READY_RE = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\s+INFO Diverter '
        r'\S+ \(\d+\) requested (?:TCP|UDP) ')
    # The product's own completion-of-startup marker (FakeNet.start after a
    # clean legacy diverter.start()): preferred over both the policy marker
    # family ordering below and the old background-flow fallback, so a mixed
    # log resolves to the explicit new marker instead of the later first
    # background packet.
    _DEFAULT_READY_RE = re.compile(
        r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\s+INFO FakeNet '
        r'DEFAULT_INTERCEPTION_READY\b')

    @classmethod
    def _egress_ready_boundary(cls, run_log: str) -> str | None:
        """Local-time instant when the diverter began filtering, or None.

        During-start and before-start releases can put probe traffic on the
        wire before the product exists; those packets are environmental
        preamble, not leaks (discovery100-54 sst-058: 31 cadence payloads
        before EGRESS_CONTROL_READY reached the NIC).
        """
        for line in run_log.splitlines():
            match = cls._EGRESS_READY_RE.match(line)
            if match:
                return '%s.%s' % (match.group(1), match.group(2))
        # Policy boundary semantics stay first-priority.  Without a policy
        # marker, the product's explicit completion-of-startup line wins over
        # any background flow, so the responsibility boundary never slides to
        # a later first packet.
        for line in run_log.splitlines():
            match = cls._DEFAULT_READY_RE.match(line)
            if match:
                return '%s.%s' % (match.group(1), match.group(2))
        # Legacy templates never log EGRESS_CONTROL_READY; the diverter's
        # first intercepted flow marker is the equivalent readiness point
        # (historical originals only: current probes wait for the explicit
        # DEFAULT_INTERCEPTION_READY marker instead of background traffic).
        for line in run_log.splitlines():
            match = cls._LEGACY_READY_RE.match(line)
            if match:
                return '%s.%s' % (match.group(1), match.group(2))
        return None

    @classmethod
    def _diverter_stop_boundary(cls, run_log: str) -> str | None:
        """Local-time instant when diverter teardown began, or None.

        From this log instant the product can no longer filter packets.
        Scenarios whose stop wedges before the diverter phase (e.g. injected
        policy_pause) get no boundary and keep whole-capture accounting.
        """
        for line in run_log.splitlines():
            match = cls._STOP_DIVERTER_RE.match(line)
            if match:
                return '%s.%s' % (match.group(1), match.group(2))
        return None

    def _pktmon_observations(self, capture: dict[str, Any], src: str, dst: str,
                             protocol: str,
                             not_after_local: str | None = None,
                             not_before_local: str | None = None
                             ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        """Return all-stack and verified-NIC observations for one tuple.

        An all-components hit proves that the capture saw the application
        send.  It cannot prove an external leak: only the current, explicitly
        bound physical-NIC component list carries that meaning.

        ``not_after_local`` bounds the observation to the product's active
        interval.  In stop-window interleave the probe intentionally keeps
        sending while the service stops; once diverter teardown has begun
        the product can no longer filter, so packets observed after that
        boundary are neither positive evidence nor leaks.
        """
        path = self.root / str(capture.get('pktmon_path', ''))
        nic_path = self.root / str(capture.get('pktmon_nic_path', ''))
        if not path.is_file() or not nic_path.is_file():
            raise SuiteError('pktmon export or NIC metadata is missing')
        metadata = read_json(nic_path)
        raw = path.read_bytes()
        issues = pktmon_capture_issues(metadata, raw)
        if issues:
            raise SuiteError('pktmon capture incomplete: ' + '; '.join(issues))
        binding = pktmon_nic_binding(metadata)
        decoder = _pktmon_module()
        records = decoder.parse_packets(raw)
        if not_after_local is not None or not_before_local is not None:
            # A record without a parseable local timestamp stays counted:
            # excusing evidence requires proof that it is outside the
            # product's active interval (before EGRESS_CONTROL_READY or
            # after diverter teardown began).
            records = [packet for packet in records
                       if (packet.get('timestamp_local') is None or
                           ((not_after_local is None or
                             packet['timestamp_local'] <= not_after_local) and
                            (not_before_local is None or
                             packet['timestamp_local'] >= not_before_local)))]
        try:
            all_components = decoder.select_packets(records, src, dst, protocol, direction='Tx')
            nic_components = decoder.select_packets(
                records, src, dst, protocol, component_ids=binding['component_ids'], direction='Tx')
        except decoder.PacketEvidenceError as exc:
            raise SuiteError('pktmon tuple evidence is ambiguous/incomplete: %s' % (exc,)) from exc
        # A zero-length bare RST is TCP teardown signaling, not payload:
        # a half-open application TCB whose retransmission timer expires
        # after the deny decision emits exactly one such packet from the
        # local stack. It carries no data and is not a policy leak
        # (discovery100-30 sst-089 case-4: 19s after TLS_SNI_DENY).
        def is_bare_rst(packet):
            flags = str(packet.get('flags') or '').upper()
            size = packet.get('original_size') or packet.get('logged_size')
            # A bare RST (TCP teardown, no payload) is ≤ 60 bytes including
            # Ethernet/IP/TCP headers. The old size == 0 check never matched
            # because original_size includes protocol headers (typically 40+
            # bytes for IP+TCP alone).
            return 'R' in flags and size is not None and size <= 60
        nic_components = [p for p in nic_components if not is_bare_rst(p)]
        return all_components, nic_components, binding

    @staticmethod
    def _log_fields(line: str) -> dict[str, str]:
        """Extract structured egress fields without assuming logger ordering."""
        # Field keys may carry digits (source_ipv4, original_port): the
        # character class must include them or the mapping vocabulary never
        # parses (discovery100-71 sst-041/043).
        return {key: value for key, value in re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)', line)}

    def _sni_mismatch_deny_binding(self, run_log: str, log_path: Path, log_rel_path: str,
                                   case_events: list[dict[str, Any]], first: dict[str, Any],
                                   source: tuple[str, str], target: tuple[str, str],
                                   planned: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
        """Strictly bind one planned TLS SNI-deny case to its relay record.

        Master evidence contract (candidate08 sst-004 case 4): a planned
        deny case with an explicit ``tls_server_name`` whose exact
        PID/src/sport/dst/dport/proto flow uniformly took REDIRECT_TLS_RELAY
        can pass only through this case's own sni_mismatch record.  Binding
        requirements, all enforced here from the sealed originals:

        1. a valid con008 application observation must exist for the case
           (packet-only or older contracts never substitute);
        2. planned SNI == the case handshake's actual SNI == the record's
           parsed SNI, and that SNI differs from the mapped domain;
        3. exactly one TLS_SNI_DENY whose src/sport/original_ip/original_port
           equal this case, with a positive integer generation, reason
           ClientHelloError AND reason_code sni_mismatch, and the domain of
           this case's actual relay policy;
        4. no contradictory same-scope ALLOW and no second ambiguous deny;
        5. the record's timestamp classified inside this case's probe-row
           activity window under the existing clock contract (integer tick
           bounds with the resolution margin, the same policy_scope rule the
           curl allow line uses) -- never zero-error by default;
        6. the byte range of the record inside the sealed run.log is
           returned for independent offline comparison.

        Anything less leaves the case failing; no verdict is relaxed.
        """
        planned_sni = planned.get('tls_server_name')
        if (not planned_sni or planned.get('protocol') != 'tls'
                or not isinstance(planned_sni, str)):
            return None, None
        rows = [row for row in case_events
                if row.get('connection_id') == first.get('connection_id')
                and isinstance(row.get('utc_ticks'), int)]
        handshake = next((row for row in rows
                          if row.get('event') == 'case_tls_handshake_attempt'), None)
        if not rows or not handshake or handshake.get('sni') != planned_sni:
            return None, None
        # Integer activity window from this case's own probe rows; each row
        # is the 100ns instant plus the established +99ns display window.
        window = ((min(row['utc_ticks'] for row in rows) - 621355968000000000) * 100,
                  (max(row['utc_ticks'] for row in rows) - 621355968000000000) * 100 + 99)
        matched: tuple[str, dict[str, str], int] | None = None
        for line in run_log.splitlines():
            if 'TLS_SNI_DENY ' not in line and 'TLS_SNI_ALLOW ' not in line:
                continue
            fields = self._log_fields(line)
            # Same connection scope only: the relay record must carry this
            # case's client identity.  Legacy records without it (older
            # candidates) are not attributable and never lend evidence.
            if (fields.get('sport') != source[1] or fields.get('src') != source[0]):
                continue
            if 'TLS_SNI_ALLOW ' in line:
                return None, None
            try:
                generation = int(fields.get('generation', ''))
            except ValueError:
                return None, None
            if generation <= 0:
                return None, None
            if (fields.get('reason') != 'ClientHelloError'
                    or fields.get('reason_code') != 'sni_mismatch'):
                return None, None
            if (fields.get('original_ip') != target[0]
                    or fields.get('original_port') != target[1]):
                return None, None
            if (fields.get('sni') != planned_sni
                    or fields.get('domain') != planned.get('host')
                    or fields.get('domain') == planned_sni):
                return None, None
            # The guest log timestamp carries millisecond precision: the
            # record's true instant lies in [t, t+1ms).  Full containment in
            # the probe-provable activity window is required -- boundary
            # intersection or ambiguous attribution rejects, never a
            # zero-error assumption and never a snap tolerance.
            stamp = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) ', line)
            if not stamp:
                return None, None
            base = dt.datetime.strptime(stamp[1], '%Y-%m-%d %H:%M:%S') - dt.timedelta(hours=8)
            delta = base - dt.datetime(1970, 1, 1)
            record_lo = (delta.days * 86400 + delta.seconds) * 10**9 + int(stamp[2]) * 10**6
            record_hi = record_lo + 10**6
            if not (window[0] <= record_lo and record_hi <= window[1]):
                return None, None
            if matched is not None:
                return None, None
            matched = (line, fields, generation)
        if matched is None:
            return None, None
        line, fields, generation = matched
        raw = log_path.read_bytes()
        needle = line.encode('utf-8')
        offset = raw.find(needle)
        if offset < 0 or raw.find(needle, offset + 1) >= 0:
            return None, None
        binding = {'schema': 'sst.sni-mismatch-binding.v1',
                   'deny_log': line,
                   'deny_log_ref': {'path': log_rel_path,
                                    'byte_start': offset,
                                    'byte_end': offset + len(needle)},
                   'sni': planned_sni,
                   'domain': fields['domain'],
                   'generation': generation,
                   'window_ns': window,
                   'handshake_sni': handshake.get('sni')}
        return line, binding

    @staticmethod
    def _stored_binding_issues(stored_cases: list[dict[str, Any]],
                               recomputed_cases: list[dict[str, Any]]) -> list[str]:
        """Reject stored SNI-deny bindings that the originals disprove.

        Results written by older adjudicators carry no binding and stay
        comparable (no issue); a stored binding whose record text or byte
        reference differs from the independent recomputation is tampering.
        """
        issues: list[str] = []
        for stored in stored_cases:
            binding = stored.get('sni_binding') if isinstance(stored, dict) else None
            if not isinstance(binding, dict):
                continue
            index = stored.get('index')
            current = next((row for row in recomputed_cases
                            if row.get('index') == index), None)
            recomputed = current.get('sni_binding') if isinstance(current, dict) else None
            if not isinstance(recomputed, dict):
                issues.append('stored SNI deny binding has no recomputed counterpart (case %s)' % index)
            elif (binding.get('deny_log') != recomputed.get('deny_log')
                  or binding.get('deny_log_ref') != recomputed.get('deny_log_ref')):
                issues.append('stored SNI deny binding differs from recomputed evidence (case %s)' % index)
        return issues

    def _fault_primary_observation(self, run: dict[str, Any], event: dict[str, Any],
                                   nonce: str) -> dict[str, Any] | None:
        """Rejudge only the fault's exact primary session, never auxiliary flows."""
        record = run.get('fault_connection_case')
        if not record:
            return None
        path = (self.root / record['path']).resolve()
        if not path.is_relative_to(self.root.resolve()) or file_record(path, self.root) != record:
            raise SuiteError('fault primary case identity/hash mismatch')
        case = read_json(path)
        session = case.get('session', {})
        if (case.get('schema') != 'sst.fault-evidence.case.v2' or case.get('synthetic') is not False or
                case.get('run_id') != run.get('run_id') or case.get('nonce') != nonce or
                case.get('candidate_id') != self.identity.candidate_id or
                session.get('observation_kind') != 'tcpip_etw' or
                session.get('probe_pid') != event.get('pid') or
                session.get('connection_id') != '%s-%s-%s' % (event.get('pid'), event.get('worker'), event.get('seq')) or
                session.get('src') != event.get('src') or
                session.get('dst') != (event.get('actual_dst') or event.get('dst'))):
            raise SuiteError('ETW primary case is not this same-run target connection')
        spec = importlib.util.spec_from_file_location('sst_primary_rejudge', Path(__file__).with_name('sst_fault_evidence.py'))
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        verdict = oracle.assess(case, self.root, expected_candidate=self.identity.candidate_id)
        if not verdict.get('passed') or verdict.get('synthetic'):
            raise SuiteError('ETW primary raw re-adjudication failed')
        return {'kind': 'tcpip_etw', 'case': record, 'connection_id': session['connection_id'],
                'event_count': len(session['connection_event_refs'])}

    def _application_observation(self, run, origin, ends, nonce, src, dst, protocol,
                                 creation_ticks=None):
        """Rebuild one observation from hash-bound originals, online or on replay."""
        import scenario_tcpip as tcpip
        import scenario_kernel_network as kernel
        import sst_fault_evidence as fault
        capture = run['capture']
        records = capture['files'] + run['originals']['files']
        by_name = {}
        for record in records:
            name = Path(record['path']).name
            if name in by_name:
                raise SuiteError('ambiguous application original ' + name)
            by_name[name] = record
        def read(name):
            record = by_name[name]
            path = (self.root / record['path']).resolve()
            path.relative_to(self.root.resolve())
            raw = path.read_bytes()
            if len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
                raise SuiteError('application original hash mismatch: ' + name)
            return raw
        probe_raw = read('probe.jsonl')
        rows = [json.loads(line) for line in probe_raw.splitlines()]
        def probe_ref(row):
            matches = []
            offset = 0
            for raw in probe_raw.splitlines(keepends=True):
                if json.loads(raw) == row:
                    matches.append(dict(path=by_name['probe.jsonl']['path'], byte_start=offset,
                                        byte_end=offset+len(raw), event_key='json:'))
                offset += len(raw)
            if len(matches) != 1:
                raise SuiteError('application probe row missing/ambiguous')
            return matches[0]
        origin_ref = probe_ref(origin)
        end_refs = [probe_ref(row) for row in ends]
        if not end_refs or origin.get('nonce') != nonce or any(row.get('pid') != origin['pid'] or row.get('nonce') != nonce for row in ends):
            raise SuiteError('application terminal/nonce identity missing')
        if creation_ticks is None:
            # B3 process-redirect profiles originate from a native child: its
            # creation marker is process_ready (same creation_ticks payload),
            # while the launcher's ready row carries the launcher pid
            # (discovery100-65 sst-041..044).
            ready = [row for row in rows if row.get('event') in ('ready', 'process_ready')
                     and row.get('nonce') == nonce and row.get('pid') == origin['pid']]
            if len(ready) != 1:
                raise SuiteError('application native probe creation missing')
            creation_ticks = ready[0]['creation_ticks']
        log = read('run.log').decode('utf-8-sig')
        policy_window = None
        if origin.get('event') == 'curl_started':
            if (len(ends) != 1 or ends[0].get('event') != 'curl_completed' or
                    origin.get('creation_ticks') != creation_ticks or
                    tcpip.curl_tuple(log, origin) != (src, dst)):
                raise SuiteError('curl native process/tuple window is not unique')
            policy_window = ((creation_ticks-621355968000000000)*100 + 15624999,
                             fault.time_bounds(ends[0])[0] - 15624999)
            if policy_window[0] >= policy_window[1]:
                raise SuiteError('curl process window is not ordered')
        wanted = dict(pid=str(origin['pid']), proto=protocol, src=src.rsplit(':',1)[0],
                      sport=src.rsplit(':',1)[1], dst=dst.rsplit(':',1)[0], dport=dst.rsplit(':',1)[1])
        policies = []
        offset = 0
        for line in log.splitlines(keepends=True):
            # ESTABLISHED_BYPASS is the diverter's mid-stream flow
            # disposition: a during-start connection established before
            # capture has no PROCESS_FLOW, but its bypass is the policy
            # observation for that flow (P1 fix, discovery100-20 sst-006).
            if (('PROCESS_FLOW ' in line or 'ESTABLISHED_BYPASS' in line) and
                    all(tcpip.fields(line).get(k) == v for k,v in wanted.items())):
                policies.append(dict(path=by_name['run.log']['path'], byte_start=offset,
                                     byte_end=offset+len(line.encode()), event_key='text'))
            elif 'PROCESS_REDIRECT_MAPPING_CREATED' in line:
                # B3 process-redirect flows are audited under their own
                # field names (source_ipv4/source_port, original_ipv4/
                # original_port) instead of PROCESS_FLOW's tuple keys
                # (discovery100-66 sst-041..044).
                fields = tcpip.fields(line)
                if (fields.get('pid') == wanted['pid'] and
                        fields.get('source_ipv4') == wanted['src'] and
                        fields.get('source_port') == wanted['sport'] and
                        fields.get('original_ipv4') == wanted['dst'] and
                        fields.get('original_port') == wanted['dport']):
                    policies.append(dict(path=by_name['run.log']['path'], byte_start=offset,
                                         byte_end=offset+len(line.encode()), event_key='text'))
            offset += len(line.encode())
        if not policies:
            # Legacy FakeNet templates (default.ini) audit no egress
            # dispositions.  Their per-flow marker is the diverter's
            # "<process> (<pid>) requested <PROTO> <dst>:<dport>" line; the
            # full tuple is bound by the TCPIP connect event, so matching
            # pid+proto+destination is the policy observation for the flow.
            legacy = re.compile(
                r'Diverter \S+ \((\d+)\) requested ' + protocol.upper() +
                r' ' + re.escape(wanted['dst']) + r':' + re.escape(wanted['dport']) + r'\s*$')
            offset = 0
            for line in log.splitlines(keepends=True):
                if legacy.search(line) and legacy.search(line).group(1) == wanted['pid']:
                    policies.append(dict(path=by_name['run.log']['path'], byte_start=offset,
                                         byte_end=offset+len(line.encode()), event_key='text'))
                offset += len(line.encode())
        if not policies:
            raise SuiteError('application exact policy flow missing')
        result = dict(schema='sst.application-observation.v1', candidate_id=self.identity.candidate_id,
                      run_id=run['run_id'], nonce=nonce, case_index=origin.get('case_index'),
                      connection_id=origin.get('connection_id', 'curl'), pid=origin['pid'],
                      creation_ticks=creation_ticks, src=src, dst=dst, protocol=protocol,
                      probe_ref=origin_ref, end_refs=end_refs, policy_refs=policies)
        if protocol == 'UDP':
            meta = json.loads(read('kernel-network.metadata.json'))
            observed = kernel.validate_capture(read('kernel-network.events.jsonl'), read('kernel-network.etl'),
                read('kernel-network.header.xml'), read('kernel-network.summary.txt'), meta,
                by_name['kernel-network.events.jsonl']['path'])
            sends = [row for row in rows if row.get('nonce') == nonce and row.get('pid') == origin['pid'] and
                     row.get('connection_id') == origin.get('connection_id') and
                     row.get('event') in ('udp_sent', 'case_udp_sent')]
            refs = [kernel.match_send(observed['events'], row, creation_ticks)['ref'] for row in sends]
            if not refs or len({(x['byte_start'],x['byte_end']) for x in refs}) != len(refs):
                raise SuiteError('UDP sends reuse an independent event')
            result.update(observation_kind='kernel_udp_etw', connection_refs=refs)
        else:
            raw = read('pktmon.txt')
            lo, hi = tcpip.validate_capture(raw, read('pktmon.etl'), json.loads(read('pktmon-nic.json')),50000000)
            ipc = [json.loads(line) for line in read('ipc-parent.jsonl').splitlines()]
            managed_pid, managed_created = tcpip.managed_identity(ipc, run['run_id'])
            observed = tcpip.connection_events(raw, by_name['pktmon.txt']['path'], log,
                                               origin['pid'], src, dst, managed_pid,
                                               policy_window=policy_window, log_path=by_name['run.log']['path'])
            if policy_window:
                result['policy_refs'] = [row['ref'] for row in observed['policy_inside']]
                result['policy_context_refs'] = [row['ref'] for row in observed['policy_outside']]
            if observed['tuple_terminals']:
                tcpip.validate_tuple_probe(rows, origin, src, dst)
            for event in observed['events'] + observed['tuple_terminals']:
                event_lo, event_hi = fault.time_bounds(event['text'])
                if not lo <= event_lo <= event_hi <= hi + 99:
                    raise SuiteError('application event outside capture')
            connected = fault.time_bounds(observed['connect']['text'])[0]
            if connected < (creation_ticks-621355968000000000)*100:
                raise SuiteError('application connect precedes native creation')
            if observed['peer'] and fault.time_bounds(observed['peer']['text'])[0] < (managed_created-116444736000000000)*100:
                raise SuiteError('application peer precedes managed creation')
            uncertainty = 15625000 - 1
            policy_upper = max(fault.time_bounds(row['text'])[1] for row in observed['policy_inside']
                               if policy_window or tcpip.flow_matches(row['fields'], origin['pid'], src, dst)
                               or row['fields'].get('disposition') == 'LEGACY_SINKHOLE')
            begin = max(fault.time_bounds(observed['connect']['text'])[1],
                        fault.time_bounds(origin)[1], policy_upper) + uncertainty
            terminal = min(fault.time_bounds(e['text'])[0] for e in observed['termination'] + observed['tuple_terminals']) - uncertainty
            probe_end = min((row['utc_ticks']-621355968000000000)*100 for row in ends) - uncertainty
            if not lo <= connected <= min(terminal,probe_end) + uncertainty <= hi:
                raise SuiteError('application lifetime outside native/probe capture')
            # Application observations prove a complete connection, not the
            # fault-action overlap contract. Only the new unattributed negative
            # constraints add CON009's conservative pre-establishment rejection.
            if observed['tuple_terminals'] and min(fault.time_bounds(e['text'])[0]
                    for e in observed['tuple_terminals']) - uncertainty < begin:
                raise SuiteError('application lifetime constrained before establishment')
            result.update(observation_kind='tcpip_etw', connection_refs=[e['ref'] for e in observed['events']],
                          generation_manifest=observed['generation_manifest'],
                          tuple_terminal_refs=[e['ref'] for e in observed['tuple_terminals']],
                          end_lower_ns=min(terminal,probe_end))
        result['capture_refs'] = [record for name,record in by_name.items()
                                  if name.startswith(('pktmon.', 'kernel-network.'))]
        return result

    _QUIESCENCE_REFUSAL_MARKER = ('reviewed process image is already '
                                  'running before READY')

    def _is_quiescence_refusal_family(self, profile: dict[str, Any]) -> bool:
        target = profile.get('probe_target', {})
        return (profile.get('bucket') == 'B3' and
                target.get('process_mode') == 'match' and
                profile.get('interleave') == 'before-start')

    def _expected_quiescence_refusal(self, started: dict[str, Any],
                                     profile: dict[str, Any]) -> dict[str, Any] | None:
        """Return the recorded refusal when it is this family's exact outcome."""
        if not self._is_quiescence_refusal_family(profile):
            return None
        status = self._status()
        reason = str(status.get('failure_reason') or '')
        if (started.get('state') != 'healthy' and
                self._QUIESCENCE_REFUSAL_MARKER in reason):
            return {'reason': reason,
                    'state': status.get('state'),
                    'run_id': status.get('run_id'),
                    'marker': self._QUIESCENCE_REFUSAL_MARKER}
        return None

    @staticmethod
    def _cases_verdict(planned: int, releases: int, case_results: list[dict[str, Any]],
                       fault_window: bool) -> bool:
        """Auxiliary boundary cases are demanded in every mode.

        A fault label alone proves nothing about auxiliary execution: the
        same single-release and per-case verdict demand applies inside a
        fault window (2026-09-20 VFY-003 rollback of the global waiver that
        accepted discovery100-118/121 sst-034 without case proof).
        ``fault_window`` stays in the signature for call compatibility and
        must never change this verdict.
        """
        return not planned or (releases == 1 and all(row['passed'] for row in case_results))

    def _traffic_oracle(self, run: dict[str, Any], profile: dict[str, Any], nonce: str,
                        sentinel: dict[str, Any] | None = None,
                        fault_window: bool = False) -> dict[str, Any]:
        """Check the same-run probe → PROCESS_FLOW → pktmon chain.

        This deliberately accepts no label supplied by the probe.  A probe
        must identify one established connection, the native run log must map
        its PID/source tuple, and pktmon must hold that exact directional
        tuple.  Positive relay profiles also require a TLS request event and
        the egress-control ready record from the native log.

        ``fault_window`` is accepted for call compatibility and is inert:
        the online fault call and the offline recheck share this one verdict
        path and its identity inputs (2026-09-20 VFY-003/004 fix).
        """
        import scenario_tcpip as tcpip
        capture = run.get('capture') or {}
        probe_path = self.root / str(capture.get('probe_path', ''))
        pktmon_path = self.root / str(capture.get('pktmon_path', ''))
        originals = run.get('originals') or {}
        originals_files = originals.get('files') or []
        log_record = next((item for item in originals_files
                           if Path(str(item.get('path', ''))).name == 'run.log'), None)
        if not probe_path.is_file() or not pktmon_path.is_file() or not log_record:
            return {'passed': False, 'reason': 'probe/pktmon/complete run.log missing'}
        log_path = self.root / str(log_record['path'])
        if not log_path.is_file():
            return {'passed': False, 'reason': 'run.log path escapes or is missing'}
        events = self._read_probe_events(probe_path)
        ready = [row for row in events if row.get('event') == 'ready' and row.get('nonce') == nonce]
        released = [row for row in events if row.get('event') == 'released' and row.get('nonce') == nonce]
        expected_schedule = {'profile': profile['bucket'], 'variant': profile['variant'],
                             'tempo': profile['tempo'], 'interleave': profile['interleave'],
                             'cadence_ms': profile['cadence_ms'],
                             'target_host': profile['probe_target']['host'],
                             'target_port': profile['probe_target']['port'],
                             'target_protocol': profile['probe_target']['protocol'],
                             'process_mode': profile['probe_target'].get('process_mode', 'match'),
                             'fnpr_role': profile['probe_target'].get('fnpr_role', ''),
                             'startup_retry_seconds': profile.get('startup_retry_seconds', 70),
                             'additional_targets': (list(profile.get('negative_cases', ())) +
                                                    list(profile.get('probe_cases', ())))}
        if len(ready) != 1 or any(ready[0].get(key) != value for key, value in expected_schedule.items()):
            return {'passed': False, 'reason': 'probe raw schedule does not match manifest',
                    'expected_schedule': expected_schedule, 'ready_count': len(ready)}
        if len(released) != 1 or released[0].get('interleave') != profile['interleave']:
            return {'passed': False, 'reason': 'probe did not record exactly one declared lifecycle release',
                    'expected_schedule': expected_schedule, 'release_count': len(released)}
        run_log = log_path.read_text(encoding='utf-8-sig')
        def numeric_endpoint(value: Any) -> tuple[str, str] | None:
            if not isinstance(value, str) or ':' not in value:
                return None
            address, port = value.rsplit(':', 1)
            try:
                ipaddress.IPv4Address(address)
                if not 1 <= int(port) <= 65535:
                    return None
            except ValueError:
                return None
            return address, port

        udp_primary = profile['probe_target']['protocol'] == 'udp'
        primary = [item for item in events if item.get('nonce') == nonce and
                   item.get('event') == ('udp_sent' if udp_primary else 'established')]
        if udp_primary:
            primary = [item for item in primary if item.get('connection_id') == nonce + '-udp-1' and
                       item.get('seq') == 1]
        elif len(primary) > 1 and profile['probe_target'].get(
                'expectation') in ('deny', 'relay_allow', 'ordinary_path',
                                   'local_fake', 'reviewed_allow'):
            # Reconnections are part of the contract: a denied primary is
            # sinkholed and closed (RawListener timeout) and the probe
            # retries; a relay-allowed primary can equally be closed by the
            # real remote server (keepalive/idle policy, discovery100-48
            # sst-004) and the client reconnects through a fresh mapping;
            # a reviewed-allowed direct upstream closes on fast cadence the
            # same way (discovery100-73 sst-020/022).
            # Prefer the first origin the product actually observed: a
            # connection established in the before-start/restart gap that
            # died before capture is environmental preamble (discovery100-49
            # sst-005 run-02: the first origin had no policy line at all,
            # the reconnect was ESTABLISHED_BYPASS-bound).
            bound_keys = set()
            for line in run_log.splitlines():
                if 'PROCESS_FLOW ' in line or 'ESTABLISHED_BYPASS' in line:
                    fields = self._log_fields(line)
                    bound_keys.add((fields.get('pid'), fields.get('src'),
                                    fields.get('sport'), fields.get('dst'),
                                    fields.get('dport')))
            def policy_bound(row):
                source = numeric_endpoint(row.get('src'))
                target = (numeric_endpoint(row.get('dst')) or
                          numeric_endpoint(row.get('actual_dst')))
                if not source or not target:
                    return False
                return (str(row.get('pid')), source[0], source[1],
                        target[0], target[1]) in bound_keys
            primary = (next((row for row in primary if policy_bound(row)),
                            primary[0]),)
            primary = list(primary)
        if len(primary) != 1:
            return {'passed': False, 'reason': 'expected exactly one primary connection origin',
                    'primary_count': len(primary)}
        event = primary[0]
        source_tuple = numeric_endpoint(event.get('src'))
        # A regular probe's RemoteEndPoint is the policy destination.  B3
        # records a numeric input destination because its socket is rewritten
        # to the controlled receiver; the original is the policy tuple.
        target_tuple = numeric_endpoint(event.get('dst')) or numeric_endpoint(event.get('actual_dst'))
        if source_tuple is None or target_tuple is None:
            return {'passed': False, 'reason': 'probe lacks numeric source/original destination tuple'}
        src = ':'.join(source_tuple)
        dst = ':'.join(target_tuple)
        address, port = source_tuple
        ends = [row for row in events if row.get('event') in ('eof', 'error', 'close') and
                row.get('nonce') == nonce and row.get('connection_id') == event.get('connection_id') and
                row.get('pid') == event.get('pid')]
        if not ends:
            return {'passed': False, 'reason': 'same connection has no terminal probe event'}
        flow = []
        for line in run_log.splitlines():
            if 'PROCESS_REDIRECT_MAPPING_CREATED' in line:
                # The product audits process-redirect matched flows under
                # this vocabulary only; no PROCESS_FLOW line exists for
                # them (discovery100-70 sst-041/042/044).
                fields = self._log_fields(line)
                if (fields.get('pid') == str(event.get('pid')) and
                        fields.get('source_ipv4') == address and
                        fields.get('source_port') == port and
                        fields.get('original_ipv4') == target_tuple[0] and
                        fields.get('original_port') == target_tuple[1]):
                    flow.append(line)
                continue
            if 'PROCESS_FLOW ' not in line:
                continue
            fields = self._log_fields(line)
            if (fields.get('pid') == str(event.get('pid')) and fields.get('src') == address and
                    fields.get('sport') == port and fields.get('dst') == target_tuple[0] and
                    fields.get('dport') == target_tuple[1] and
                    fields.get('proto') == ('UDP' if udp_primary else 'TCP')):
                flow.append(line)
        protocol = 'UDP' if profile['probe_target']['protocol'] == 'udp' else 'TCP'
        stop_boundary = self._diverter_stop_boundary(run_log)
        ready_boundary = self._egress_ready_boundary(run_log)
        try:
            packet_records, nic_original_packets, binding = self._pktmon_observations(
                capture, src, dst, protocol, not_after_local=stop_boundary,
                not_before_local=ready_boundary)
        except (OSError, ValueError, SuiteError) as exc:
            return {'passed': False, 'reason': 'pktmon evidence unavailable: %r' % (exc,)}
        try:
            connection_observation = (self._application_observation(run,event,ends,nonce,src,dst,protocol)
                if capture.get('observation_contract') == 'con008' else self._fault_primary_observation(run,event,nonce))
        except (KeyError, OSError, ValueError, SuiteError) as exc:
            return {'passed': False, 'reason': 'fault primary binding failed: ' + str(exc)}
        expectation = profile['probe_target']['expectation']
        tls_request = any(row.get('event') == 'request_sent' and row.get('nonce') == nonce for row in events)
        payloads = [row for row in events if row.get('event') in
                    ('request_sent', 'send', 'tls_handshake_attempt', 'udp_sent') and
                    row.get('nonce') == nonce and
                    (row.get('connection_id') == event.get('connection_id'))]
        cadence_payloads = [row for row in events if row.get('event') in
                            ('request_sent', 'send', 'tls_handshake_attempt', 'udp_sent') and
                            row.get('nonce') == nonce and row.get('cadence_ms') == profile['cadence_ms']]
        cadence_ticks = sorted(int(row['utc_ticks']) for row in cadence_payloads
                               if isinstance(row.get('utc_ticks'), int))
        cadence_intervals = [(later - earlier) / 10_000
                             for earlier, later in zip(cadence_ticks, cadence_ticks[1:])]
        expected_cadence = int(profile['cadence_ms'])
        cadence_valid = [value for value in cadence_intervals
                         if max(1, expected_cadence * 0.35) <= value <= max(2000, expected_cadence * 6)]
        cadence_ok = len(cadence_ticks) >= 2 and bool(cadence_valid)
        egress_ready = 'EGRESS_CONTROL_READY' in run_log
        target_ip, target_port = dst.rsplit(':', 1)

        def log_event(name: str, window=None, unique_fields=None, **wanted: str) -> str | None:
            return tcpip.scoped_log_event(run_log, name, wanted, window, unique_fields)

        sentinel_rows = sentinel.get('rows', []) if isinstance(sentinel, dict) else []
        def sentinel_receipt(peer: str, role: str) -> dict[str, Any] | None:
            return next((row for row in reversed(sentinel_rows) if isinstance(row, dict) and
                         row.get('event') == 'probe_ok' and row.get('nonce') == nonce and
                         row.get('role') == role and row.get('transport') == 'tcp' and
                         row.get('peer') == peer), None)
        primary_receipt = sentinel_receipt(src, str(profile['probe_target'].get('fnpr_role') or 'target'))
        relay: dict[str, Any] | None = None
        branch_log: str | None = None
        branch_packets: list[dict[str, Any]] = []
        branch_ok = False
        if expectation == 'relay_allow':
            allowed = log_event('TLS_SNI_ALLOW', domain='api.deepseek.com', original_ip=target_ip)
            upstream = log_event('ALLOW_INTERNAL_UPSTREAM', kind='tls_relay', ip=target_ip,
                                 port=target_port)
            if allowed and upstream:
                allow_fields, upstream_fields = self._log_fields(allowed), self._log_fields(upstream)
                remote = allow_fields.get('original_ip')
                upstream_ip, upstream_port, upstream_sport = (
                    upstream_fields.get('ip'), upstream_fields.get('port'), upstream_fields.get('sport'))
                if not remote or not upstream_ip or not upstream_port or not upstream_sport:
                    return {'passed': False, 'reason': 'TLS relay log fields are incomplete'}
                outer_src = address + ':' + upstream_sport
                outer_dst = upstream_ip + ':' + upstream_port
                try:
                    _, branch_packets, _ = self._pktmon_observations(
                        capture, outer_src, outer_dst, 'TCP',
                        not_after_local=stop_boundary)
                except (OSError, ValueError, SuiteError):
                    branch_packets = []
                relay = {'allow_log': allowed, 'upstream_log': upstream, 'outer_src': outer_src,
                         'outer_dst': outer_dst, 'outer_packet_count': len(branch_packets),
                         'application_socket_dst': dst, 'mapped_original_ip': remote}
                branch_log = allowed
                branch_ok = (bool(flow) and bool(branch_packets) and not nic_original_packets and
                             tls_request and egress_ready)
        elif expectation == 'reviewed_allow':
            branch_log = log_event('ALLOW_REVIEWED_IP_FIRST_FLOW', src=address,
                                   sport=port, ip=target_ip, dport=target_port,
                                   pid=str(event.get('pid')))
            branch_ok = bool(flow and branch_log and nic_original_packets)
        elif expectation == 'takeover_allow':
            branch_log = log_event('ALLOW_TAKEOVER_SINK', ip=target_ip, sport=port,
                                   dport=target_port)
            branch_ok = bool(flow and branch_log and primary_receipt and nic_original_packets)
        elif expectation == 'redirect_allow':
            branch_log = log_event('PROCESS_REDIRECT_MAPPING_CREATED', original_ipv4=target_ip,
                                   original_port=target_port, source_ipv4=address,
                                   source_port=port, pid=str(event.get('pid')),
                                   target_ipv4='192.168.204.1', target_port='443')
            try:
                _, branch_packets, _ = self._pktmon_observations(
                    capture, src, '192.168.204.1:443', 'TCP',
                    not_after_local=stop_boundary)
            except (OSError, ValueError, SuiteError):
                branch_packets = []
            branch_ok = bool(flow and branch_log and branch_packets and primary_receipt and not nic_original_packets)
        elif expectation == 'ordinary_path':
            branch_log = (log_event('DIVERT_FAKE', original_ip=target_ip, original_port=target_port) or
                          log_event('DROP_EXTERNAL', original_ip=target_ip, original_port=target_port))
            branch_ok = bool(flow and branch_log and not log_event('PROCESS_REDIRECT_MAPPING_CREATED',
                                                     source_ipv4=address, source_port=port) and
                             not nic_original_packets)
        elif expectation == 'deny':
            branch_log = (log_event('DIVERT_FAKE', original_ip=target_ip, original_port=target_port) or
                          log_event('DROP_EXTERNAL', original_ip=target_ip, original_port=target_port))
            if not branch_log:
                # An SNI-based deny primary reaches the TLS relay first: the
                # diverter logs REDIRECT_TLS_RELAY for its tuple and the
                # relay's TLS_SNI_DENY is the deny decision itself
                # (discovery100-53 sst-059: 54/54 fast denies yet the branch
                # had no DIVERT_FAKE/DROP line to bind).
                redirect_line = log_event('REDIRECT_TLS_RELAY',
                                          original_ip=target_ip)
                sni_deny_line = log_event('TLS_SNI_DENY')
                if redirect_line and sni_deny_line:
                    branch_log = sni_deny_line
            branch_ok = bool(flow and branch_log and not nic_original_packets)
        elif expectation == 'local_fake':
            branch_log = (log_event('DIVERT_FAKE', original_ip=target_ip, original_port=target_port) or
                          log_event('DROP_EXTERNAL', original_ip=target_ip, original_port=target_port))
            branch_ok = bool(flow and branch_log and not nic_original_packets)
            if not branch_ok and profile.get('template') == 'default.ini':
                # Legacy template: the sinked flow's marker is the
                # "requested <PROTO> <dst>:<dport>" line (no egress
                # dispositions exist); the TCPIP peer accept in the
                # connection observation proves the local sink took it.
                legacy_requested = next(
                    (line for line in run_log.splitlines()
                     if re.search(r'requested (?:TCP|UDP) ' +
                                  re.escape(target_ip) + r':' + target_port + r'\s*$', line)), None)
                branch_ok = bool(legacy_requested and not nic_original_packets)
                if branch_ok:
                    branch_log = legacy_requested
        else:
            return {'passed': False, 'reason': 'unknown traffic expectation: ' + str(expectation)}
        if not branch_ok:
            # A primary established before the diverter opened (before-start
            # release, during-start race, or the restart gap between runs)
            # is passed through untouched by design: its SYN was never seen,
            # so no deny/relay disposition can exist for it.  The diverter's
            # own ESTABLISHED_BYPASS record for this exact tuple+pid is the
            # policy observation for such a flow, and its original tuple on
            # the NIC is the bypass passthrough, not a leak (discovery100-49
            # sst-005 run-01: 580 pre-stop packets of a before-start relay
            # primary that connected ~34s before EGRESS_CONTROL_READY).
            bypass_line = log_event('ESTABLISHED_BYPASS',
                                    original_ip=target_ip,
                                    original_port=target_port,
                                    src=address, sport=port,
                                    pid=str(event.get('pid')))
            if bypass_line:
                branch_log = bypass_line
                branch_ok = True
        planned_cases = list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ()))
        releases = [row for row in events if row.get('event') == 'cases_released' and row.get('nonce') == nonce]
        case_results: list[dict[str, Any]] = []
        for index, planned in enumerate(planned_cases, 1):
            case_events = [row for row in events if row.get('nonce') == nonce and
                           row.get('case_index') == index]
            first = next((row for row in case_events if row.get('event') in
                          ('case_established', 'case_udp_sent')), None)
            if first is None and planned['expectation'] == 'deny':
                # A silently dropped SYN (Drop policy) never establishes;
                # the recorded attempt tuple plus the terminal timeout is
                # the attempt evidence (discovery100-54 sst-058/063 case-2).
                first = next((row for row in case_events if row.get('event') ==
                              'case_connect_attempt' and row.get('src')), None)
                if (first is not None and
                        str(first.get('src', '')).startswith('0.0.0.0:')):
                    # The pre-connect bind records Any:port; the routing
                    # decision fills the real source IP only in the stack.
                    # The diverter's PROCESS_FLOW line for the same
                    # pid+sport+destination carries the real src.
                    attempt_port = str(first.get('src', '')).split(':', 1)[1]
                    for line in run_log.splitlines():
                        if 'PROCESS_FLOW ' not in line:
                            continue
                        fields = self._log_fields(line)
                        if (fields.get('pid') == str(first.get('pid')) and
                                fields.get('sport') == attempt_port and
                                fields.get('proto') == 'TCP'):
                            first = dict(first, src='%s:%s' % (
                                fields.get('src'), attempt_port))
                            break
            source = numeric_endpoint(first.get('src')) if first else None
            target = (numeric_endpoint('%s:%s' % (planned['host'], planned['port']))
                      if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', str(planned['host'])) else
                      (numeric_endpoint(first.get('actual_dst')) if first else None))
            close = [row for row in case_events if first and row.get('event') == 'case_close' and
                     row.get('connection_id') == first.get('connection_id')]
            payload = [row for row in case_events if first and
                       row.get('connection_id') == first.get('connection_id') and
                       row.get('event') in ('case_send', 'case_request_sent',
                                            'case_tls_handshake_attempt', 'case_udp_sent')]
            terminal = [row for row in case_events if first and
                        row.get('event') == 'case_error' and
                        row.get('connection_id') == first.get('connection_id')]
            case_flow: list[str] = []
            case_packets: list[dict[str, Any]] = []
            case_nic: list[dict[str, Any]] = []
            case_log: str | None = None
            case_sni_binding: dict[str, Any] | None = None
            case_receipt: dict[str, Any] | None = None
            case_observation = None
            case_observation_error = None
            dropped_attempt = bool(first and first.get('event') == 'case_connect_attempt')
            case_ok = bool(first and source and target and close and
                           (payload if not dropped_attempt else terminal))
            if case_ok and first and source and target:
                case_protocol = 'UDP' if planned['protocol'] == 'udp' else 'TCP'
                case_flow = [line for line in run_log.splitlines() if 'PROCESS_FLOW ' in line and
                             (lambda fields: fields.get('pid') == str(first.get('pid')) and
                              fields.get('src') == source[0] and fields.get('sport') == source[1] and
                              fields.get('dst') == target[0] and fields.get('dport') == target[1] and
                              fields.get('proto') == case_protocol)(self._log_fields(line))]
                try:
                    case_packets, case_nic, _ = self._pktmon_observations(
                        capture, ':'.join(source), ':'.join(target), case_protocol,
                        not_after_local=stop_boundary)
                except (OSError, ValueError, SuiteError):
                    case_ok = False
                if dropped_attempt and not case_packets:
                    # A silently dropped SYN never reaches the captured
                    # stack components; the TCPIP connect lifecycle
                    # (bound/requested/proceeding with the exact tuple) is
                    # the local proof the application attempted the flow
                    # (discovery100-56 sst-058/063 case-2: zero pktmon wire
                    # records, full TCPIP connect lifecycle present).
                    try:
                        raw_case = (self.root / str(capture.get('pktmon_path', ''))).read_bytes()
                        text_case = raw_case.decode(
                            'utf-16' if raw_case.startswith(b'\xff\xfe') else 'utf-8-sig',
                            errors='replace')
                        marker_case = 'local=%s remote=%s' % (':'.join(source), ':'.join(target))
                        case_packets = [
                            {'lifecycle': line.strip()} for line in
                            text_case.splitlines()
                            if marker_case in line and 'connect' in line][:4] or []
                    except OSError:
                        case_packets = []
                if capture.get('observation_contract') == 'con008' and not dropped_attempt:
                    # A silently dropped attempt has no completed TCP connect
                    # by construction; the pktmon send records plus the drop
                    # policy line are its whole evidence.
                    try:
                        terminals=[row for row in case_events if row.get('connection_id')==first.get('connection_id') and row.get('event') in ('case_error','case_eof','case_close')]
                        case_observation=self._application_observation(run,first,terminals,nonce,':'.join(source),':'.join(target),case_protocol)
                    except (KeyError,OSError,ValueError,SuiteError) as exc:
                        case_ok=False
                        case_observation_error=str(exc)
                        case_log='application evidence failed: '+str(exc)
                if planned['expectation'] == 'deny':
                    # A destination-only marker may belong to another
                    # protocol or client. The exact PID/tuple/protocol flow
                    # must independently select that same deny disposition.
                    dispositions = {self._log_fields(line).get('disposition')
                                    for line in case_flow}
                    case_log = None
                    if dispositions in ({'DIVERT_FAKE'}, {'DROP_EXTERNAL'}):
                        case_log = log_event(next(iter(dispositions)),
                                             original_ip=target[0], original_port=target[1])
                    elif dispositions == {'REDIRECT_TLS_RELAY'} and case_observation is not None:
                        # A planned TLS SNI-deny case reaches the relay; only
                        # its own independently bound sni_mismatch record can
                        # prove the planned rejection (master contract,
                        # candidate08 sst-004 case 4), and only with a valid
                        # con008 application observation for this case --
                        # packet-only evidence never substitutes. Generic
                        # ClientHelloError/relay_error substitutes, borrowed
                        # markers, ambiguity or contradiction are rejected.
                        case_log, case_sni_binding = self._sni_mismatch_deny_binding(
                            run_log, log_path, str(log_record['path']), case_events,
                            first, source, target, planned)
                    case_ok = bool(case_ok and case_flow and (case_packets or case_observation) and case_log and not case_nic)
                elif planned['expectation'] == 'takeover_allow':
                    case_log = log_event('ALLOW_TAKEOVER_SINK', ip=target[0], sport=source[1],
                                         dport=target[1])
                    case_receipt = sentinel_receipt(':'.join(source), str(planned.get('fnpr_role') or 'target'))
                    response = next((row for row in case_events if row.get('event') == 'case_response' and
                                     row.get('connection_id') == first.get('connection_id') and
                                     row.get('response') == 'FNPR/1|%s|OK\n' % nonce), None)
                    case_ok = bool(case_ok and case_flow and (case_packets or case_observation) and case_log and case_receipt and
                                   response and case_nic)
                elif planned['expectation'] == 'local_fake' and planned.get('application'):
                    # Default-bucket application cases: one real wire exchange
                    # (echo/HTTP/DNS against the taken-over sink) verified
                    # from its recorded raw bytes, the con008 connection or
                    # UDP-send observation, the pid-bound traditional
                    # "requested <PROTO> <dst>:<dport>" log line (the legacy
                    # default template audits no PROCESS_FLOW) and no
                    # original-target packet on the physical NIC.
                    import scenario_application as applications
                    exchange = [row for row in case_events if
                                row.get('event') == 'case_application_exchange' and
                                row.get('connection_id') == first.get('connection_id')]
                    request_rows = [row for row in case_events if
                                    row.get('connection_id') == first.get('connection_id') and
                                    row.get('event') in ('case_send', 'case_request_sent',
                                                         'case_udp_sent')]
                    error_rows = [row for row in case_events if
                                  row.get('event') == 'case_error' and
                                  row.get('connection_id') == first.get('connection_id')]
                    verified = None
                    if error_rows:
                        case_log = ('application case error recorded: %s'
                                    % error_rows[0].get('error_type'))
                    elif len(exchange) == 1 and len(request_rows) == 1 and close:
                        try:
                            applications.validate_exchange_record(
                                exchange[0], first, request_rows[0], close[0],
                                planned, nonce, index)
                            verified = applications.verify_exchange(
                                str(planned['application']),
                                applications.unb64(exchange[0].get('request_b64', '')),
                                applications.unb64(exchange[0].get('response_b64', '')),
                                nonce, index,
                                REPO_ROOT / 'fakenet' / 'defaultFiles' / 'FakeNet.html')
                        except (ValueError, KeyError, TypeError) as exc:
                            case_log = 'application exchange rejected: %s' % exc
                    else:
                        case_log = 'application exchange record missing or ambiguous'
                    legacy_case = re.search(
                        r'Diverter \S+ \(' + re.escape(str(first.get('pid'))) + r'\) requested ' +
                        case_protocol + r' ' + re.escape(target[0]) + r':' + re.escape(target[1]) + r'\s*$',
                        run_log, re.M)
                    if verified and not legacy_case:
                        case_log = 'application case requested-line missing for exact target'
                    case_ok = bool(case_ok and verified and case_observation and
                                   legacy_case and not case_nic)
                else:
                    case_ok = False
            case_results.append({'index': index, 'expectation': planned['expectation'], 'passed': case_ok,
                                 'process_flow': case_flow[-1] if case_flow else None,
                                 'observation_error': case_observation_error, 'packet_record_count': len(case_packets), 'connection_observation': case_observation, 'nic_packet_count': len(case_nic),
                                 'branch_log': case_log, 'sentinel_receipt': case_receipt,
                                 'sni_binding': case_sni_binding})
        cases_ok = self._cases_verdict(planned_cases, len(releases), case_results, fault_window)
        curl: dict[str, Any] | None = None
        curl_ok = True
        if profile['bucket'] in ('B1', 'B4'):
            curl_started = [row for row in events if row.get('event') == 'curl_started' and
                            row.get('nonce') == nonce]
            curl_completed = [row for row in events if row.get('event') == 'curl_completed' and
                              row.get('nonce') == nonce]
            curl_ok = len(curl_started) == 1 and len(curl_completed) == 1
            curl_flow: list[str] = []
            curl_packets: list[dict[str, Any]] = []
            curl_nic: list[dict[str, Any]] = []
            curl_outer: list[dict[str, Any]] = []
            curl_observation = None
            curl_observation_error = None
            curl_positive_flow = None
            curl_allowed = curl_upstream = None
            if curl_ok:
                started, completed = curl_started[0], curl_completed[0]
                curl_ok = (started.get('pid') == completed.get('pid') and completed.get('exit_code') == 0 and
                           bool(re.fullmatch(r'\d{3}', str(completed.get('http_code', '')))))
                curl_flow = [line for line in run_log.splitlines() if 'PROCESS_FLOW ' in line and
                             (lambda fields: fields.get('pid') == str(started.get('pid')) and
                              fields.get('proto') == 'TCP' and fields.get('dport') == '443')(
                                  self._log_fields(line))]
                selected_flow = curl_flow[0] if len(curl_flow) == 1 else None
                if capture.get('observation_contract') == 'con008':
                    try:
                        app_tuple = tcpip.curl_tuple(run_log, started)
                        selected_flow = next(line for line in curl_flow
                            if (self._log_fields(line)['src']+':'+self._log_fields(line)['sport'],
                                self._log_fields(line)['dst']+':'+self._log_fields(line)['dport']) == app_tuple)
                    except (KeyError,ValueError,StopIteration) as exc:
                        selected_flow = None
                        curl_observation_error = str(exc)
                if selected_flow is not None:
                    fields = self._log_fields(selected_flow)
                    curl_positive_flow = selected_flow
                    curl_src, curl_sport, curl_dst = (fields.get('src'), fields.get('sport'),
                                                       fields.get('dst'))
                    if curl_src and curl_sport and curl_dst and fields.get('dport'):
                        app_src = curl_src + ':' + curl_sport
                        app_dst = curl_dst + ':' + fields['dport']
                        try:
                            curl_packets, curl_nic, _ = self._pktmon_observations(
                                capture, app_src, app_dst, 'TCP',
                                not_after_local=stop_boundary)
                        except (OSError, ValueError, SuiteError):
                            curl_ok = False
                        if capture.get('observation_contract') == 'con008':
                            try:
                                if curl_dst not in started['dns_ipv4'] or started['dns_before_ticks'] > started['creation_ticks']:
                                    raise SuiteError('curl destination not in prior native DNS set')
                                curl_observation=self._application_observation(run,started,[completed],nonce,app_src,app_dst,'TCP',started['creation_ticks'])
                                raw_log = log_path.read_bytes()
                                positive = [raw_log[ref['byte_start']:ref['byte_end']].decode('utf-8').strip()
                                            for ref in curl_observation['policy_refs']]
                                curl_positive_flow = next(line for line in positive if tcpip.flow_matches(
                                    tcpip.fields(line), started['pid'], app_src, app_dst))
                            except (KeyError,OSError,ValueError,SuiteError) as exc:
                                curl_ok=False
                                curl_observation_error=str(exc)
                        curl_window = None
                        if capture.get('observation_contract') == 'con008':
                            curl_window = ((started['creation_ticks']-621355968000000000)*100+15624999,
                                           (completed['utc_ticks']-621355968000000000)*100-15624999)
                        allowed = log_event('TLS_SNI_ALLOW', window=curl_window, domain='api.deepseek.com', original_ip=curl_dst)
                        upstream = log_event('ALLOW_INTERNAL_UPSTREAM', window=curl_window, unique_fields=('ip','port','sport','kind'), kind='tls_relay', ip=curl_dst,
                                             port=fields['dport'])
                        curl_allowed, curl_upstream = allowed, upstream
                        if upstream:
                            upstream_fields = self._log_fields(upstream)
                            upstream_sport = upstream_fields.get('sport')
                            if upstream_sport:
                                try:
                                    _, curl_outer, _ = self._pktmon_observations(
                                        capture, curl_src + ':' + upstream_sport, app_dst, 'TCP',
                                        not_after_local=stop_boundary)
                                except (OSError, ValueError, SuiteError):
                                    curl_outer = []
                        curl_ok = bool(curl_ok and (curl_packets or curl_observation) and not curl_nic and allowed and upstream and curl_outer)
                    else:
                        curl_ok = False
                else:
                    curl_ok = False
            curl = {'passed': curl_ok, 'started': curl_started, 'completed': curl_completed,
                    'process_flow': curl_positive_flow, 'allow_log': curl_allowed, 'upstream_log': curl_upstream,
                    'observation_error': curl_observation_error, 'application_packet_count': len(curl_packets), 'connection_observation': curl_observation,
                    'application_nic_packet_count': len(curl_nic),
                    'outer_nic_packet_count': len(curl_outer)}
        # A local stack observation establishes that the application attempted
        # the named flow; it never upgrades an all-components observation into
        # proof of physical egress.  Authorised direct/takeover paths are the
        # only branches which require that exact tuple on the verified NIC.
        # There is no fault-window waiver: the branch legs (policy log event,
        # branch packets, sentinel receipt, and above all "no original-tuple
        # packets on the physical NIC") apply identically inside a fault run
        # (2026-09-20 VFY-003 rollback; discovery100-121 sst-034 stored a
        # pass over one forbidden NIC original).  The only tuple-precise
        # exception remains ESTABLISHED_BYPASS above, which is proven per
        # flow, not excused by a label.  A fault run whose own effect makes
        # positive branch evidence genuinely absent fails honestly with the
        # failed leg named below.
        core_chain = bool((packet_records or connection_observation) and payloads and cadence_ok)
        passed = bool(core_chain and branch_ok and cases_ok and curl_ok)
        if passed:
            reason = None
        else:
            failed_legs = []
            if not core_chain:
                failed_legs.append('core probe/payload/cadence chain')
            if not branch_ok:
                failed_legs.append('branch criteria for %s (policy log, branch/NIC packets, '
                                   'sentinel receipt)' % expectation)
            if not cases_ok:
                failed_legs.append('auxiliary cases (single release plus per-case verdicts)')
            if not curl_ok:
                failed_legs.append('curl observation')
            reason = ('same-run primary/case probe→policy flow→NIC pktmon chain incomplete: '
                      'failed legs: ' + '; '.join(failed_legs))
        return {'passed': passed, 'connection_id': '%s-%s-%s' % (event.get('pid'), event.get('worker'), event.get('seq')),
                'src': src, 'dst': dst, 'process_flow': flow[-1] if flow else None,
                'packet_record_count': len(packet_records), 'connection_observation': connection_observation,
                'nic_original_packet_count': len(nic_original_packets),
                'nic_binding': binding, 'terminal_event': ends[0].get('event'),
                'tls_request_sent': tls_request, 'cadence': {'expected_ms': expected_cadence,
                                                              'payload_count': len(cadence_payloads),
                                                              'interval_ms': cadence_intervals,
                                                              'valid_interval_count': len(cadence_valid),
                                                              'passed': cadence_ok},
                'egress_control_ready': egress_ready, 'relay': relay, 'expected_schedule': expected_schedule,
                'expectation': expectation, 'branch_log': branch_log, 'branch_packet_count': len(branch_packets),
                'sentinel_receipt': primary_receipt, 'case_release_count': len(releases), 'cases': case_results,
                'curl': curl,
                'reason': reason}

    @staticmethod
    def _benign_log_issues(run: dict[str, Any], root: Path) -> list[str]:
        originals = run.get('originals') or {}
        files = originals.get('files') or []
        record = next((item for item in files if Path(str(item.get('path', '')).replace('\\', '/')).name == 'run.log'), None)
        if not record:
            return ['complete run.log missing']
        path = root / str(record.get('path', ''))
        try:
            text = path.read_text(encoding='utf-8-sig')
        except OSError:
            return ['complete run.log missing']
        return [marker for marker in ('Traceback (most recent call last)', 'Unhandled exception') if marker in text]

    def _adjudicate_fault(self, scenario: dict[str, Any], run: dict[str, Any], nonce: str,
                          root: Path, evidence: Evidence, fault_evidence: dict[str, Any]) -> dict[str, Any]:
        """Build a descriptor from transferred originals and run the fail-closed oracle."""
        fault = str(scenario['fault_class'])
        originals = run.get('originals') or {}
        names = {Path(str(item.get('path', '')).replace('\\', '/')).name: str(item['path'])
                 for item in originals.get('files', []) if isinstance(item, dict) and item.get('path')}
        required = ('fault-triggered.json', 'ipc-parent.jsonl', 'run.log')
        missing = [name for name in required if name not in names]
        if missing:
            raise SuiteError('fault originals missing: ' + ','.join(missing))
        capture = run.get('capture') or {}
        probe, pktmon = capture.get('probe_path'), capture.get('pktmon_path')
        if not isinstance(probe, str) or not isinstance(pktmon, str):
            raise SuiteError('fault run capture has no probe/pktmon paths')
        baseline = root / 'fault-baseline-sections.json'
        if not baseline.exists():
            write_new_json(baseline, {'sections': run.get('five_sections_before')})
            evidence.add(baseline)
        terminal = root / 'fault-terminal-status.json'
        if not terminal.exists():
            write_new_json(terminal, fault_evidence.get('terminal_status'))
            evidence.add(terminal)
        cleanup = root / 'fault-cleanup-native.json'
        if not cleanup.exists():
            write_new_json(cleanup, fault_evidence.get('cleanup_native'))
            evidence.add(cleanup)
        recovery = root / 'fault-recovery-healthy.json'
        if not recovery.exists():
            write_new_json(recovery, {'health': fault_evidence.get('recovery_cycle', {}).get('health_samples', [])})
            evidence.add(recovery)
        recovery_audit = fault_evidence.get('recovery_audit', {}).get('files', [])
        if not recovery_audit:
            raise SuiteError('fault run has no product recovery audit')
        # An offline adjudicator cannot query endpoint owners; capture the
        # live attribution now when the recovery audit differs from the
        # baseline, so external lifecycle residue (Edge mDNS :5353, record
        # 56 / discovery100-99 sst-014) is provable from evidence alone.
        attribution_path = root / 'recovery-attribution.json'
        if not attribution_path.exists():
            try:
                audit_rows = [json.loads(line) for line in
                              (self.root / str(recovery_audit[-1]['path'])).read_text(
                                  encoding='utf-8-sig').splitlines() if line.strip()]
                audit_value = audit_rows[-1] if audit_rows else {}
                sections = (audit_value.get('sections') or
                            audit_value.get('current') or audit_value)
                base_sections = run.get('five_sections_before') or read_json(baseline).get('sections')
                difference = self._section_difference(base_sections, sections)
                attribution = (self._attribute_section_difference(base_sections, sections)
                               if difference else None)
                write_new_json(attribution_path, {
                    'difference': difference, 'attribution': attribution,
                    'blocking': bool(difference) and self._difference_is_residue(
                        difference, attribution)})
                evidence.add(attribution_path)
            except Exception as exc:  # noqa: BLE001
                write_new_json(attribution_path, {'difference': None, 'attribution': None,
                                                  'blocking': True, 'capture_error': repr(exc)})
                evidence.add(attribution_path)
        source_path: Path | None = None
        if fault == 'policy_pause':
            source_path = root / 'faultinject-source.py'
            if not source_path.exists():
                with source_path.open('xb') as output:
                    output.write((REPO_ROOT / 'fakenet' / 'mcp' / 'faultinject.py').read_bytes())
                evidence.add(source_path)
        child_path: Path | None = None
        if fault == 'child_hang':
            child_path = root / 'child-hang-processes-native.json'
            gate = fault_evidence.get('gate') or {}
            if not child_path.exists():
                child = gate.get('child')
                parent = gate.get('child_parent')
                if not child or not parent:
                    raise SuiteError('child_hang native parent/creation observation absent')
                write_new_json(child_path, {'run_id': run['run_id'], 'fault': fault, 'nonce': nonce,
                                            'processes': [parent, child]})
                evidence.add(child_path)
        raw = {
            'receipt': names['fault-triggered.json'],
            'receipt_metadata': str(originals.get('metadata', {}).get('path', '')),
            'ipc': names['ipc-parent.jsonl'], 'run_log': names['run.log'], 'probe': probe, 'pktmon': pktmon,
            'pktmon_etl': capture.get('pktmon_etl_path'), 'pktmon_metadata': capture.get('pktmon_nic_path'),
            'baseline': str(baseline.relative_to(self.root)),
            'recovery_audit': str(recovery_audit[-1]['path']),
            'recovery_healthy': str(recovery.relative_to(self.root)),
            'cleanup': str(cleanup.relative_to(self.root)), 'terminal': str(terminal.relative_to(self.root)),
            'recovery_attribution': str(attribution_path.relative_to(self.root)),
        }
        if fault == 'diverter_stop':
            raw['fault_action'] = names.get('fault-action.json')
        if fault == 'child_hang':
            raw['native_processes'] = str(child_path.relative_to(self.root)) if child_path else None
        if fault == 'policy_pause':
            raw['thread_stacks'] = names.get('stop-thread-stacks.txt')
            raw['fault_source'] = str(source_path.relative_to(self.root)) if source_path else None
        if any(not isinstance(value, str) or not value for value in raw.values()):
            raise SuiteError('fault adapter raw descriptor has an unavailable required observation')
        descriptor = {'scenario_id': scenario['scenario_id'], 'case_id': 'scenario-' + scenario['scenario_id'],
                      'candidate_id': self.identity.candidate_id, 'run_id': run['run_id'], 'fault': fault,
                      'nonce': nonce, 'clock_resolution_ns': 15625000, 'observation_kind': 'tcpip_etw', 'raw': raw}
        descriptor_path = root / 'fault-capture-descriptor.json'
        if not descriptor_path.exists():
            write_new_json(descriptor_path, descriptor)
            evidence.add(descriptor_path)
        output = root / 'fault-evidence-result.json'
        command = [sys.executable, str(Path(__file__).with_name('scenario_fault_evidence.py')),
                   '--evidence-root', str(self.root), '--capture', str(descriptor_path), '--output', str(output)]
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   check=False, timeout=180)
        stdout = root / 'fault-evidence-adapter.stdout'
        if not stdout.exists():
            with stdout.open('xb') as stream:
                stream.write(completed.stdout.encode('utf-8'))
            evidence.add(stdout)
        if not output.is_file():
            raise SuiteError('fault evidence adapter produced no result')
        evidence.add(output)
        case_path = output.with_suffix('.case.json')
        if case_path.is_file():
            evidence.add(case_path)
        validator_stdout = output.with_suffix('.validator.stdout')
        if validator_stdout.is_file():
            evidence.add(validator_stdout)
        result = read_json(output)
        return {'descriptor': file_record(descriptor_path, self.root),
                'case': file_record(case_path, self.root) if case_path.is_file() else None,
                'result': file_record(output, self.root), 'adapter_stdout': file_record(stdout, self.root),
                'validator_stdout': file_record(validator_stdout, self.root) if validator_stdout.is_file() else None,
                'exit_code': completed.returncode, 'passed': bool(result.get('passed')),
                'checks': result.get('checks', [])}

    @staticmethod
    def _outcome_code(outcome: dict[str, Any]) -> str | None:
        error = outcome.get('error')
        if isinstance(error, dict):
            return str(error.get('code') or '') or None
        value = outcome.get('value')
        if isinstance(value, dict) and isinstance(value.get('error'), dict):
            return str(value['error'].get('code') or '') or None
        text = str(error or '')
        return 'state_conflict' if 'state_conflict' in text else None

    def _transfer_runtime_pcap(self, artifacts: dict[str, Any], run_id: str, destination: Path) -> dict[str, Any]:
        """Transfer the listed runtime PCAP by the authorized host-only channel."""
        candidates = []
        for item in artifacts.get('artifacts', []):
            path = str(item.get('path', '')).replace('\\', '/')
            if (item.get('type') == 'pcap' or path.lower().endswith('.pcap')) and run_id in path:
                # A pcap still being written lists without a completion hash;
                # the bounded wait retries instead of failing on a None field.
                if item.get('sha256'):
                    candidates.append(item)
        if not candidates:
            raise SuiteError('same-run runtime PCAP is absent from list_artifacts')
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from artifact_transfer import receive_artifact
        chosen = sorted(candidates, key=lambda item: str(item['path']))[0]
        transferred = receive_artifact(self.vm, chosen, destination)  # type: ignore[arg-type]
        if transferred['sha256'].lower() != str(chosen['sha256']).lower():
            raise SuiteError('runtime PCAP transfer hash differs from list_artifacts')
        return transferred

    def _transfer_runtime_pcap_direct(self, run_id: str, destination: Path) -> dict[str, Any]:
        """Transfer the run's pcap by hashing it directly when listing lagged.

        Registration flips an artifact's listing entry complete only after the
        stop-side diagnostic finishes; a wait deadline can expire while the
        bytes are already final on disk.  Stat and hash the file directly and
        transfer byte-bound, so evidence stays verifiable either way.
        """
        assert self.vm
        command = (
            "$ErrorActionPreference='Stop';$d='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "';"
            "if(!(Test-Path -LiteralPath $d)){throw 'run directory absent'};"
            "$f=@(Get-ChildItem -LiteralPath $d -File -Filter '*.pcap' | Sort-Object Name | Select-Object -First 1);"
            "if(-not $f){throw 'no pcap in run directory'};"
            "@{path=$f[0].FullName;bytes=[int64]$f[0].Length;"
            "sha256=(Get-FileHash -LiteralPath $f[0].FullName -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
        value, raw = self._vm_json(command, 120)
        transferred = self._transfer_guest_file(str(value['path']), int(value['bytes']),
                                                str(value['sha256']), destination)
        transferred['direct'] = True
        transferred['vm_raw'] = raw
        return transferred

    def _wait_runtime_pcap(self, run_id: str, destination: Path) -> dict[str, Any]:
        """Wait briefly for the exact run's runtime PCAP to become listable.

        A restart can finish its first run before its artifact writer publishes
        the PCAP.  The retry is bounded and records the successful list result
        with the run rather than silently accepting an unrelated later PCAP.
        """
        deadline = time.monotonic() + 30
        last: Exception | None = None
        last_run_entries: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            try:
                artifacts = self.service.tool('list_artifacts')  # type: ignore[union-attr]
                last_run_entries = [item for item in (artifacts or {}).get('artifacts', [])
                                    if isinstance(item, dict) and run_id in str(item.get('path', ''))
                                    and str(item.get('path', '')).lower().endswith('.pcap')]
                result = self._transfer_runtime_pcap(artifacts, run_id, destination)
                result['list_artifacts'] = artifacts
                return result
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(1)
        if last_run_entries:
            # Evidence for the publication-timing diagnosis; never silent.
            self._last_pcap_listing = last_run_entries
        try:
            return self._transfer_runtime_pcap_direct(run_id, destination)
        except Exception as direct_exc:  # noqa: BLE001
            last = last or direct_exc
        if last is not None:
            raise SuiteError('same-run runtime PCAP was not published: %s' % (last,))
        raise SuiteError('same-run runtime PCAP was not published: '
                         'no complete listing entry; last run entries: %r' % (last_run_entries[-3:],))

    def _collect_runtime_pcaps(self, runs: list[dict[str, Any]], root: Path,
                               evidence: Evidence, runtime_profile: dict[str, Any]) -> None:
        """Collect each healthy run's runtime PCAP after the final stop.

        Both pcap writers hold the file open for the whole run and only
        publish after the stop, so this runs once the final stop converged;
        every healthy run binds its own run id to its own label's pcap and a
        later run's bytes never stand in for an earlier one.
        """
        if not runtime_pcap_required(runtime_profile):
            return
        for item in runs:
            if item.get('start_response', {}).get('state') == 'healthy':
                item['runtime_pcap'] = self._wait_runtime_pcap(
                    item['run_id'], root / item['label'] / 'runtime.pcap')
                evidence.add(root / item['label'] / 'runtime.pcap')

    def _prune_scenario_vm_footprint(self, runs: list[dict[str, Any]], guest: str,
                                     fault: str | None, *,
                                     scenario_passed: bool = False) -> dict[str, Any]:
        """Remove this scenario's redundant VM artifacts after host export.

        Every run's originals are already byte-bound on the host before this
        runs; the VM copies are working data.  Benign runs are pruned from
        artifacts/runs entirely; fault runs keep their incident evidence
        VM-side.  The guest probe directory is always transient.  Without
        this, repeated acceptance scenarios exhaust the VM disk
        (discovery100-11: pktmon stop failed on a full disk).

        Pruning is additionally gated on ``scenario_passed`` (default false):
        a failed or exceptional scenario keeps its whole guest probe
        directory and every run VM-side, because its originals are the only
        failure evidence - an exported summary never replaces the actual
        bytes (fakenet100 T005-R02: the R01 failure lost its PCAPs to this
        prune).  A non-empty run.originals export is not by itself a
        sufficient condition for deletion.
        """
        assert self.vm
        # A run still bound by the service (failed/recovering stop) keeps its
        # VM artifacts: the product recovery needs the run's endpoint
        # observation evidence, and deleting it wedges recovery forever
        # (discovery100-13 sst-080).
        status = self._status()
        released = (status.get('state') == 'stopped' and
                    not status.get('run_id') and not status.get('controller'))
        if not scenario_passed:
            return {'pruned_runs': [], 'guest_removed': False,
                    'service_released_runs': released,
                    'prune_skipped_reason': 'scenario not passed; failure originals kept',
                    'kept_guest': guest,
                    'kept_runs': [run.get('run_id') for run in runs]}
        pruned_runs = []
        if not fault and released:
            for run in runs:
                run_id = run.get('run_id')
                if run_id and run.get('originals'):
                    pruned_runs.append(run_id)
        command = (
            "$ErrorActionPreference='Stop';$removed=@();"
            "$runs='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs';"
            + ''.join(
                "if(Test-Path -LiteralPath (Join-Path $runs " + repr_id + "))"
                "{Remove-Item -LiteralPath (Join-Path $runs " + repr_id + ") -Recurse -Force;$removed+=" + repr_id + "};" for repr_id in
                ["'%s'" % run_id for run_id in pruned_runs]) +
            "$guest=" + quote_ps(guest) + ";"
            "if(Test-Path -LiteralPath $guest){Remove-Item -LiteralPath $guest -Recurse -Force};"
            "@{pruned_runs=$removed;guest_removed=(Test-Path -LiteralPath $guest)}|ConvertTo-Json -Compress")
        value, raw = self._vm_json(command, 120)
        value['raw'] = raw
        value['service_released_runs'] = released
        return value

    def _export_run_originals(self, run_id: str, destination: Path,
                              evidence: Evidence) -> dict[str, Any]:
        """Transfer complete, byte-addressed VM originals for one service run.

        The local suite may summarize them, but a verdict always points back to
        these immutable VM files.  The allow-list prevents this executor from
        exporting arbitrary guest data while covering every file used by the
        traffic and fault oracles.
        """
        assert self.vm
        names = ('run.log', 'stdout_stderr.log', 'ipc-parent.jsonl', 'ipc-child.jsonl',
                 'creation.jsonl', 'fault-triggered.json', 'fault-action.json',
                 'published.json', 'managed-thread-stacks.json', 'stop-thread-stacks.txt',
                 'endpoint-lifetimes.json')
        quoted_names = ','.join(quote_ps(name) for name in names)
        command = (
            "$ErrorActionPreference='Stop';$run=" + quote_ps(run_id) + ";"
            "$base='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs';$dir=Join-Path $base $run;"
            "if(!(Test-Path $dir)){throw 'run directory absent'};"
            "$items=@(Get-ChildItem -LiteralPath $dir -File | Where-Object {$_.Name -in @("
            + quoted_names + ")} | ForEach-Object {@{name=$_.Name;path=$_.FullName;bytes=$_.Length;"
            "created_utc=$_.CreationTimeUtc.ToString('o');modified_utc=$_.LastWriteTimeUtc.ToString('o');"
            "sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()}});"
            "@{files=$items}|ConvertTo-Json -Depth 5 -Compress")
        value, raw = self._vm_json(command, 120)
        rows = value.get('files')
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise SuiteError('run-original exporter did not return a file list')
        required = {'run.log', 'ipc-parent.jsonl'}
        found = {str(item.get('name')) for item in rows if isinstance(item, dict)}
        missing = required - found
        if missing:
            raise SuiteError('complete VM run originals missing: ' + ','.join(sorted(missing)))
        destination.mkdir(parents=True, exist_ok=True)
        transfers: list[dict[str, Any]] = []
        metadata: list[dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                raise SuiteError('invalid VM run-original item')
            name = str(item.get('name', ''))
            if name not in names:
                raise SuiteError('unexpected VM run-original item: ' + name)
            transferred = self._transfer_guest_file(str(item['path']), int(item['bytes']),
                                                    str(item['sha256']), destination / name)
            evidence.add(destination / name)
            transfers.append(transferred)
            metadata.append({key: item.get(key) for key in
                             ('name', 'path', 'bytes', 'created_utc', 'modified_utc', 'sha256')})
        metadata_path = destination / 'vm-file-metadata.json'
        write_new_json(metadata_path, metadata)
        evidence.add(metadata_path)
        return {'run_id': run_id, 'files': transfers, 'metadata': file_record(metadata_path, self.root),
                'vm_raw': raw}

    _PRODUCT_ENDPOINT_OWNERS = frozenset((
        'fakenetng-mcp.exe', 'fakenetng-mcp-managed.exe',
        'fakenetng-mcp-exit-monitor.exe'))

    @staticmethod
    def _listen_endpoint_set(sections: dict[str, Any]) -> set[tuple[str, str]]:
        result: set[tuple[str, str]] = set()
        for line in str(sections.get('listen_ports') or '').splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ('TCP', 'UDP'):
                # The section difference compares listening sockets only;
                # transient ESTABLISHED/TIME_WAIT rows are lifecycle noise
                # and must not enter the ownership attribution.
                if parts[0] == 'TCP' and 'LISTENING' not in line:
                    continue
                result.add((parts[0], parts[1].replace('[', '').replace(']', '')))
        return result

    def _listening_endpoint_owners(self) -> list[dict[str, Any]]:
        """One read-only ownership table for every current listening endpoint."""
        assert self.vm
        command = (
            "$ErrorActionPreference='Stop';"
            "$eps=@();"
            "foreach($e in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)){$eps+=,[pscustomobject]@{proto='TCP';local=('{0}:{1}' -f $e.LocalAddress,$e.LocalPort);pid=$e.OwningProcess}};"
            "foreach($e in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)){$eps+=,[pscustomobject]@{proto='UDP';local=('{0}:{1}' -f $e.LocalAddress,$e.LocalPort);pid=$e.OwningProcess}};"
            "$pids=@($eps|Select-Object -ExpandProperty pid -Unique);"
            "$procs=@{};foreach($p in $pids){$procs[[int]$p]=(Get-CimInstance Win32_Process -Filter ('ProcessId='+$p) -ErrorAction SilentlyContinue)};"
            "$rows=@(foreach($e in $eps){$cmd=$procs[[int]$e.pid];[pscustomobject]@{proto=$e.proto;local=$e.local;pid=$e.pid;name=if($cmd){$cmd.Name};command=if($cmd){$cmd.CommandLine};created_dmtf=if($cmd){$cmd.CreationDate}}});"
            "@{endpoints=$rows}|ConvertTo-Json -Depth 4 -Compress")
        value, raw = self._vm_json(command, 90)
        rows = value.get('endpoints')
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise SuiteError('listening endpoint ownership query failed')
        return rows

    def _attribute_section_difference(self, before: dict[str, Any],
                                      after: dict[str, Any]) -> dict[str, Any]:
        """Split a listen-ports difference into residue versus external change.

        A fresh endpoint is product/test residue only while a live ownership
        query still sees it owned by the service tree or the suite probe.
        Endpoints that already vanished, or belong to unrelated processes,
        are recorded as external environment evidence and must not fail
        product recovery.  Any attribution failure keeps the difference
        blocking; this never widens an exemption by string matching on the
        difference itself.
        """
        fresh = sorted(self._listen_endpoint_set(after) -
                       self._listen_endpoint_set(before))
        if not fresh:
            return {'fresh_endpoints': [], 'residue': [], 'external': [], 'vanished': []}
        try:
            owners = self._listening_endpoint_owners()
        except Exception as exc:  # noqa: BLE001
            return {'fresh_endpoints': [list(item) for item in fresh],
                    'residue': [list(item) for item in fresh],
                    'external': [], 'vanished': [], 'attribution_error': repr(exc)}
        table: dict[tuple[str, str], dict[str, Any]] = {}
        for row in owners:
            if not isinstance(row, dict):
                continue
            local = str(row.get('local', '')).replace('[', '').replace(']', '')
            table[(str(row.get('proto', '')), local)] = row
        residue: list[dict[str, Any]] = []
        external: list[dict[str, Any]] = []
        vanished: list[dict[str, Any]] = []
        for proto, local in fresh:
            owner = table.get((proto, local))
            if owner is None:
                vanished.append({'proto': proto, 'local': local})
                continue
            name = str(owner.get('name') or '').lower()
            command = str(owner.get('command') or '')
            if (name in self._PRODUCT_ENDPOINT_OWNERS or
                    'scenario-suite-20260912' in command or
                    name.startswith('scenario-probe-client')):
                residue.append({'proto': proto, 'local': local, 'owner': owner})
            else:
                external.append({'proto': proto, 'local': local, 'owner': owner})
        return {'fresh_endpoints': [list(item) for item in fresh], 'residue': residue,
                'external': external, 'vanished': vanished}

    def _export_recovery_audit(self, run_id: str, destination: Path,
                               evidence: Evidence) -> dict[str, Any]:
        """Transfer the product-created, same-run recovery audit JSONL."""
        assert self.vm
        command = (
            "$ErrorActionPreference='Stop';$logs='C:\\ProgramData\\FakeNet-NG-MCP\\logs';"
            "$items=@(Get-ChildItem -LiteralPath $logs -File -Filter " +
            quote_ps('recovery-audit-' + run_id + '-*.jsonl') +
            " | Sort-Object LastWriteTimeUtc | ForEach-Object {@{path=$_.FullName;bytes=$_.Length;"
            "sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower();"
            "created_utc=$_.CreationTimeUtc.ToString('o')}});@{files=$items}|ConvertTo-Json -Depth 4 -Compress")
        value, raw = self._vm_json(command, 120)
        rows = value.get('files')
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list) or not rows:
            raise SuiteError('same-run product recovery audit is absent: ' + run_id)
        destination.mkdir(parents=True, exist_ok=True)
        records = []
        for index, item in enumerate(rows):
            if not isinstance(item, dict):
                raise SuiteError('invalid recovery audit metadata')
            local = destination / ('recovery-audit-%02d.jsonl' % index)
            records.append(self._transfer_guest_file(str(item['path']), int(item['bytes']),
                                                     str(item['sha256']), local))
            evidence.add(local)
        return {'files': records, 'vm_raw': raw}

    def _run_recovery_sections(self, run_id: str, destination: Path,
                               evidence: Evidence) -> tuple[dict[str, Any], dict[str, Any]]:
        """Bind the product's same-run post-stop five-section snapshot."""
        audit = self._export_recovery_audit(run_id, destination, evidence)
        entries: list[dict[str, Any]] = []
        for item in audit['files']:
            path = self.root / item['path']
            entries.extend(json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines()
                           if line.strip())
        current = next((item.get('current') for item in reversed(entries)
                        if isinstance(item, dict) and isinstance(item.get('current'), dict)), None)
        required = {'dns_servers', 'routes', 'listen_ports', 'windivert_processes', 'services'}
        if not isinstance(current, dict) or not required <= current.keys():
            raise SuiteError('same-run recovery audit lacks five original sections: ' + run_id)
        return audit, current

    def _recorded_probe_identities(self, run: dict[str, Any], nonce: str) -> list[dict[str, Any]]:
        """Return the PID/UTC-creation tuples sealed in this attempt's JSONL.

        A PID can be reused, so the post-stop residue query must compare the
        raw PID and ``StartTime.ToUniversalTime().Ticks``.  ``ready`` binds
        the launcher, ``process_ready`` the B3 native child, and
        ``curl_started`` any explicitly recorded curl child.
        """
        capture = run.get('capture') or {}
        relative = capture.get('probe_path')
        if not isinstance(relative, str) or not relative:
            raise SuiteError('fault cleanup has no transferred probe JSONL')
        path = (self.root / relative).resolve()
        if not path.is_relative_to(self.root.resolve()) or not path.is_file():
            raise SuiteError('fault cleanup probe JSONL is missing/escaping')
        identities: list[dict[str, Any]] = []
        for event in self._read_probe_events(path):
            if event.get('nonce') != nonce or event.get('event') not in {
                    'ready', 'process_ready', 'curl_started'}:
                continue
            pid, ticks = event.get('pid'), event.get('creation_ticks')
            if type(pid) is not int or type(ticks) is not int or pid <= 0 or ticks <= 0:
                raise SuiteError('probe identity lacks exact PID/creation ticks: ' + str(event.get('event')))
            identities.append({'pid': pid, 'creation_ticks': ticks, 'event': event['event']})
        if not identities or not any(item['event'] == 'ready' for item in identities):
            raise SuiteError('fault cleanup lacks the probe wrapper identity')
        launcher = capture.get('probe_launcher_pid')
        ready = [item for item in identities if item['event'] == 'ready']
        if type(launcher) is not int or len(ready) != 1 or ready[0]['pid'] != launcher:
            raise SuiteError('probe wrapper identity does not bind the launcher PID')
        keys = [(item['pid'], item['creation_ticks']) for item in identities]
        if len(keys) != len(set(keys)):
            raise SuiteError('probe identity PID/creation tuple is duplicated')
        return sorted(identities, key=lambda item: (item['pid'], item['creation_ticks'], item['event']))

    def _cleanup_native(self, run: dict[str, Any], nonce: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Collect fault residue against exact probe/native process identities.

        The restored SCM service host is permitted only when its PID matches
        the service record and its command ends in ``fakenetng-mcp.exe run``.
        Every recorded probe or related unknown process is emitted in
        ``probe_processes`` for the fault oracle to reject.  A PID reused by
        an unrelated process is not residue once its native start-time tuple
        proves that the original probe has exited.
        """
        expected = self._recorded_probe_identities(run, nonce)
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$fault='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json';"
            "$state='C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json';$selfPid=$PID;$selfTicks=[Int64][Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks;$query_identity=[pscustomobject]@{ProcessId=[Int32]$selfPid;creation_ticks=[Int64]$selfTicks;Name=[Diagnostics.Process]::GetCurrentProcess().ProcessName};$expected=" +
            quote_ps(json.dumps(expected, separators=(',', ':'))) + "|ConvertFrom-Json;"
            "$service=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"|Select-Object -First 1 Name,ProcessId,State,PathName;"
            "$snapshots=@(Get-CimInstance Win32_Process);$processes=@();$process_identity_races=@();foreach($snapshot in $snapshots){$native=Get-Process -Id $snapshot.ProcessId -ErrorAction SilentlyContinue;if($null -eq $native){$process_identity_races+=@([pscustomobject]@{ProcessId=[Int32]$snapshot.ProcessId;ParentProcessId=[Int32]$snapshot.ParentProcessId;CreationDate=$snapshot.CreationDate;Name=$snapshot.Name;CommandLine=$snapshot.CommandLine;reason='vanished_before_native_starttime'});continue};try{$nativeTicks=[Int64]$native.StartTime.ToUniversalTime().Ticks;$snapshotCimTicks=[Int64]$snapshot.CreationDate.ToUniversalTime().Ticks;$confirm=Get-CimInstance Win32_Process -Filter ('ProcessId='+$snapshot.ProcessId)|Select-Object -First 1;if($null -eq $confirm){throw 'vanished_before_cim_confirmation'};$confirmCimTicks=[Int64]$confirm.CreationDate.ToUniversalTime().Ticks}catch{$process_identity_races+=@([pscustomobject]@{ProcessId=[Int32]$snapshot.ProcessId;ParentProcessId=[Int32]$snapshot.ParentProcessId;CreationDate=$snapshot.CreationDate;Name=$snapshot.Name;CommandLine=$snapshot.CommandLine;reason=('native_or_confirmation_unavailable:'+$_);});continue};if($confirm.Name -ne $snapshot.Name -or $confirmCimTicks -ne $snapshotCimTicks){$process_identity_races+=@([pscustomobject]@{ProcessId=[Int32]$snapshot.ProcessId;ParentProcessId=[Int32]$snapshot.ParentProcessId;CreationDate=$snapshot.CreationDate;Name=$snapshot.Name;CommandLine=$snapshot.CommandLine;reason='changed_between_cim_snapshots'});continue};$processes+=@([pscustomobject]@{ProcessId=[Int32]$confirm.ProcessId;ParentProcessId=[Int32]$confirm.ParentProcessId;CreationDate=$confirm.CreationDate;creation_ticks=$nativeTicks;Name=$confirm.Name;CommandLine=$confirm.CommandLine})};"
            "$managed=@($processes|Where-Object {$_.Name -like 'fakenetng-mcp-managed*'});$probes=@();$unknown=@();$allowed=@();$pidReuse=@();"
            "foreach($process in $processes){$samePid=@($expected|Where-Object {[Int32]$_.pid -eq $process.ProcessId});$exact=@($samePid|Where-Object {[Int64]$_.creation_ticks -eq $process.creation_ticks});"
            "$cmd=[string]$process.CommandLine;$serviceHost=($process.Name -eq 'fakenetng-mcp.exe' -and $service -and $process.ProcessId -eq $service.ProcessId -and $cmd -match '(?i)fakenetng-mcp\\.exe\"?\\s+run\\s*$');"
            "$related=($process.Name -like 'fakenetng-mcp*' -or $cmd -match '(?i)(scenario-suite-20260912|scenario_probes\\.ps1|scenario-probe-client\\.exe|probe-client\\.json|managed-(?:child|fault-hang))');"
            "$selfQuery=($process.ProcessId -eq $selfPid -and $process.creation_ticks -eq $selfTicks);if($selfQuery){continue};if($serviceHost){$allowed+=@($process);continue};if($exact.Count){$process|Add-Member -NotePropertyName residue_reason -NotePropertyValue 'recorded_probe_pid_and_creation' -Force;$probes+=@($process)}elseif($related){$process|Add-Member -NotePropertyName residue_reason -NotePropertyValue 'related_unknown_command_or_native_identity' -Force;$unknown+=@($process)}elseif($samePid.Count){$process|Add-Member -NotePropertyName residue_reason -NotePropertyValue 'pid_reuse_nonresidue' -Force;$pidReuse+=@($process)}};"
            "$relevant_identity_races=@();foreach($race in $process_identity_races){$raceExpected=@($expected|Where-Object {[Int32]$_.pid -eq $race.ProcessId});$raceCmd=[string]$race.CommandLine;$raceServiceHost=($race.Name -eq 'fakenetng-mcp.exe' -and $service -and $race.ProcessId -eq $service.ProcessId -and $raceCmd -match '(?i)fakenetng-mcp\\.exe\"?\\s+run\\s*$');$raceRelated=($race.Name -like 'fakenetng-mcp*' -or $raceCmd -match '(?i)(scenario-suite-20260912|scenario_probes\\.ps1|scenario-probe-client\\.exe|probe-client\\.json|managed-(?:child|fault-hang))');if(-not $raceServiceHost -and ($raceExpected.Count -or $raceRelated)){$race|Add-Member -NotePropertyName residue_reason -NotePropertyValue 'relevant_process_identity_race' -Force;$relevant_identity_races+=@($race)}};$probes=@($probes+$unknown+$relevant_identity_races);$needs=$false;if(Test-Path $state){$needs=(Get-Content $state -Raw|ConvertFrom-Json).needs_recovery};"
            "@{state=@{needs_recovery=$needs};expected_probes=@($expected);query_identity=$query_identity;process_identity_races=$process_identity_races;relevant_identity_races=$relevant_identity_races;managed_processes=$managed;probe_processes=$probes;unknown_related_processes=$unknown;pid_reuse_nonresidue=$pidReuse;query_process=@($processes|Where-Object {$_.ProcessId -eq $selfPid -and $_.creation_ticks -eq $selfTicks});service_host=@($allowed);fault_exists=(Test-Path $fault);pktmon=(& pktmon status|Out-String);computer=$env:COMPUTERNAME}|ConvertTo-Json -Depth 8 -Compress", 90)
        if value.get('expected_probes') != expected:
            raise SuiteError('fault cleanup did not echo the exact recorded probe identities')
        query = value.get('query_identity')
        query_processes = value.get('query_process')
        if (not isinstance(query, dict) or type(query.get('ProcessId')) is not int or
                type(query.get('creation_ticks')) is not int or
                not isinstance(query_processes, list) or len(query_processes) != 1 or
                query_processes[0].get('ProcessId') != query['ProcessId'] or
                query_processes[0].get('creation_ticks') != query['creation_ticks'] or
                not isinstance(value.get('process_identity_races'), list) or
                not isinstance(value.get('relevant_identity_races'), list) or
                not isinstance(value.get('probe_processes'), list) or
                not isinstance(value.get('service_host'), list)):
            raise SuiteError('fault cleanup native process observations are incomplete')
        return value, raw

    def _fault_recovery_cycle(self, scenario_id: str, attempt: int) -> dict[str, Any]:
        """Run and record the required distinct normal recovery lifecycle."""
        assert self.service
        calls: list[dict[str, Any]] = []
        sequence = 0

        def invoke(tool: str, arguments: dict[str, Any] | None = None, mutation: bool = False) -> dict[str, Any]:
            nonlocal sequence
            sequence += 1
            sent = dict(arguments or {})
            if mutation:
                status = self._status()
                sent.update(command_id=self._command_id(scenario_id, attempt, sequence, '-recovery'),
                            expected_state_version=status['state_version'])
            outcome = self.service.tool_outcome(tool, sent, timeout=480 if tool in ('start', 'stop') else 120)
            entry = {'tool': tool, 'sent_arguments': outcome['sent_arguments'],
                     'response': outcome['response'], 'ok': bool(outcome['ok']), 'error': outcome['error'],
                     'command_id': sent.get('command_id'), 'response_digest': digest(outcome['response'])}
            calls.append(entry)
            if not outcome['ok'] or not isinstance(outcome.get('value'), dict):
                raise SuiteError('fault recovery %s rejected: %r' % (tool, outcome['error']))
            return outcome['value']

        before = self._capture_sections()[0]
        loaded = invoke('load_config', {'name': 'default.ini'}, mutation=True)
        started = invoke('start', mutation=True)
        if started.get('state') != 'healthy' or not started.get('run_id'):
            raise SuiteError('fault recovery did not publish a distinct healthy run')
        health_samples = []
        for _ in range(3):
            time.sleep(2)
            status = invoke('get_status')
            if status.get('state') != 'healthy' or status.get('run_id') != started['run_id']:
                raise SuiteError('fault recovery health drift')
            health_samples.append(status)
        stopped = invoke('stop', mutation=True)
        if stopped.get('state') != 'stopped':
            raise SuiteError('fault recovery stop did not converge')
        after = self._capture_sections()[0]
        difference = self._section_difference(before, after)
        if difference:
            # Same attribution rule as the benign body check: an external
            # process's natural endpoint lifecycle (e.g. Edge mDNS :5353,
            # record 56 / discovery100-99 sst-014) is environmental, not a
            # product recovery failure.
            attribution = self._attribute_section_difference(before, after)
            if self._difference_is_residue(difference, attribution):
                raise SuiteError('fault recovery five-section difference: ' + repr(difference))
        return {'before_sections': before, 'after_sections': after, 'loaded': loaded, 'started': started,
                'health_samples': health_samples, 'stopped': stopped, 'calls': calls}

    def _run_gate(self, fault: str, nonce: str, capture: dict[str, Any]) -> dict[str, Any]:
        """Release a gated start only after one real probe maps to PROCESS_FLOW."""
        assert self.vm
        command = (
            "$ErrorActionPreference='Stop';$logs='C:\\ProgramData\\FakeNet-NG-MCP\\logs';$ready=Join-Path $logs 'fault-injection-ready.json';if(Test-Path $ready){throw 'stale fault ready rendezvous exists'};"
            "$probe=" + quote_ps(capture['probe']) + ";$launcher=" + str(int(capture['pid'])) + ";$started=[DateTimeOffset]::UtcNow;$deadline=[DateTime]::UtcNow.AddSeconds(60);"
            "$answer=[ordered]@{fault=" + quote_ps(fault) + ";nonce=" + quote_ps(nonce) + ";ready=$false;launcher_pid=$launcher;probe_pid=$null;run_id=$null;established=$null;process_flow=$null;ready_published_utc=$null;child=$null;child_parent=$null;observer_started_utc=$started.ToString('o');observer_deadline_utc=[DateTimeOffset]::UtcNow.AddSeconds(60).ToString('o')};"
            "while([DateTime]::UtcNow -lt $deadline){$est=$null;if(Test-Path $probe){foreach($line in @(Get-Content $probe -Tail 200 -ErrorAction SilentlyContinue)){try{$x=$line|ConvertFrom-Json;if($x.event -eq 'established' -and $x.nonce -eq " + quote_ps(nonce) + "){$est=$x;break}}catch{}}};"
            "if($est){$probePid=[int]$est.pid;$answer.probe_pid=$probePid;$port=($est.src -split ':')[-1];$source=($est.src -split ':')[0];foreach($run in @(Get-ChildItem 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' -Directory|Sort-Object CreationTimeUtc -Descending|Select-Object -First 8)){$log=Join-Path $run.FullName 'run.log';$flow=@();if(Test-Path -LiteralPath $log){$flow=@(Select-String -LiteralPath $log -SimpleMatch -Pattern @('PROCESS_FLOW ','PROCESS_REDIRECT_MAPPING_CREATED') -ErrorAction SilentlyContinue|Where-Object {$line=$_.Line;($line -match ('(?:^|\\s)pid='+[regex]::Escape([string]$probePid)+'(?:\\s|$)')) -and ((($line -match '(?:^|\\s)sport=') -and ($line -match ('(?:^|\\s)sport='+[regex]::Escape($port)+'(?:\\s|$)')) -and ($line -match ('(?:^|\\s)src='+[regex]::Escape($source)+'(?:\\s|$)'))) -or ((($line -match '(?:^|\\s)source_port=') -and ($line -match ('(?:^|\\s)source_port='+[regex]::Escape($port)+'(?:\\s|$)')) -and ($line -match ('(?:^|\\s)source_ipv4='+[regex]::Escape($source)+'(?:\\s|$)')))))}|Select-Object -Last 1)};if($flow.Count){$payload=[ordered]@{fault=" + quote_ps(fault) + ";nonce=" + quote_ps(nonce) + ";run_id=$run.Name};$temporary=Join-Path $logs ('.fault-injection-ready-'+[guid]::NewGuid().ToString('N')+'.json');[IO.File]::WriteAllText($temporary,($payload|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false));[IO.File]::Move($temporary,$ready);$answer.ready=$true;$answer.run_id=$run.Name;$answer.established=$est;$answer.process_flow=$flow[0].Line;$answer.ready_published_utc=[DateTimeOffset]::UtcNow.ToString('o');if(" + quote_ps(fault) + " -eq 'child_hang'){$parent=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'fakenetng-mcp-managed.exe' -and $_.CommandLine -match ('managed-child '+[regex]::Escape($run.Name))}|Select-Object -First 1);if($parent.Count){$child=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'fakenetng-mcp.exe' -and $_.CommandLine -match 'managed-fault-hang' -and $_.ParentProcessId -eq $parent[0].ProcessId}|Select-Object ProcessId,ParentProcessId,@{Name='CreationDate';Expression={$_.CreationDate.ToUniversalTime().ToString('o')}},Name,CommandLine -First 1);if($child.Count){$answer.child=$child[0];$answer.child_parent=$parent[0]|Select-Object ProcessId,ParentProcessId,@{Name='CreationDate';Expression={$_.CreationDate.ToUniversalTime().ToString('o')}},Name,CommandLine}}};break}}};if($answer.ready){break};Start-Sleep -Milliseconds 10};"
            "$answer.finished_utc=[DateTimeOffset]::UtcNow.ToString('o');$answer|ConvertTo-Json -Depth 8 -Compress")
        value, raw = self._vm_json(command, 75)
        value['raw'] = raw
        if not value.get('ready'):
            raise SuiteError('fault gate did not observe one nonce-bound managed outbound connection')
        return value

    def _settle_start_worker(self, worker: threading.Thread, start_box: dict[str, Any],
                             timeout_seconds: int = 510) -> dict[str, Any]:
        """Wait out the *same* start operation before any later mutation.

        Start can synchronously collect an incident and perform its own stop.
        A gate-observer failure cannot shorten that operation: issuing cleanup
        into it would manufacture a controller conflict and lose the original
        terminal evidence.  Status samples are read-only reconciliation facts.
        """
        deadline = time.monotonic() + timeout_seconds
        samples: list[dict[str, Any]] = []
        while worker.is_alive() and time.monotonic() < deadline:
            worker.join(2)
            try:
                samples.append({'at': utc_now(), 'status': self._status()})
            except Exception as exc:  # noqa: BLE001
                samples.append({'at': utc_now(), 'status_error': repr(exc)})
        if worker.is_alive():
            return {'settled': False, 'reason': 'start RPC exceeded reconciliation budget',
                    'samples': samples}
        try:
            terminal = self._status()
        except Exception as exc:  # noqa: BLE001
            return {'settled': False, 'reason': 'start RPC returned but status is unreadable: %r' % (exc,),
                    'samples': samples}
        samples.append({'at': utc_now(), 'status': terminal})
        # A returned start is safe to follow only when it published health or
        # completed the service's own failure-stop path.
        state = terminal.get('state')
        terminal_ok = state == 'healthy' or (state == 'stopped' and not terminal.get('run_id') and
                                               not terminal.get('controller'))
        return {'settled': terminal_ok, 'returned': True, 'terminal_status': terminal,
                'samples': samples,
                'reason': None if terminal_ok else 'start RPC returned before a terminal service state'}

    def _run_one(self, scenario: dict[str, Any], attempt: int) -> dict[str, Any]:
        """Execute one manifest row and retain every oracle input, pass or fail."""
        self.require_clients()
        preflight = self._require_preflight()
        scenario_id = scenario['scenario_id']
        result_path = self._result_path(scenario_id)
        if result_path.exists():
            return read_json(result_path)
        gate = self._continuation_gate()
        nonce = '%s-a%d-%s' % (scenario_id, attempt, uuid.uuid4().hex)
        root = self.root / 'evidence' / scenario_id / ('attempt-%02d' % attempt)
        evidence = Evidence(root)
        fault = scenario.get('fault_class')
        runtime_profile = materialize_probe_profile(scenario['config_profile'], preflight['api_ipv4'])
        scratch, active, imported = (scenario_id + '-%s-a%d.ini' % (label, attempt)
                                     for label in ('scratch', 'active', 'import'))
        calls: list[dict[str, Any]] = []
        cleanup_calls: list[dict[str, Any]] = []
        runs: list[dict[str, Any]] = []
        status_samples: list[dict[str, Any]] = []
        cleanup_errors: list[str] = []
        sequence = 0
        captures: dict[str, dict[str, Any]] = {}
        sentinel: FnprSentinel | None = None
        sentinel_evidence: dict[str, Any] | None = None
        sentinel_record: dict[str, Any] | None = None
        fault_evidence: dict[str, Any] = {}
        fault_mode_attempted = False
        before_sections: dict[str, Any] | None = None
        after_sections: dict[str, Any] | None = None
        failure: str | None = None
        operation_unsettled = False
        first_run_release: dict[str, Any] | None = None
        state = {'schema': STATE_SCHEMA, 'scenario_id': scenario_id, 'phase': 'running',
                 'controller_id': self.service.controller_id if self.service else None,
                 'attempt': attempt, 'run_chain': runs, 'started_at': utc_now(),
                 'updated_at': utc_now(), 'identity': self.identity.as_dict()}
        self._write_state(scenario_id, state)

        def call(tool: str, arguments: dict[str, Any] | None = None, *, mutation: bool = False,
                 expect: str = 'success', forced_version: int | None = None) -> dict[str, Any]:
            """Append the exact sent arguments and response before asserting it."""
            nonlocal sequence
            sequence += 1
            sent = dict(arguments or {})
            command_id = None
            if mutation:
                status = self._status()
                command_id = self._command_id(scenario_id, attempt, sequence)
                sent.update(command_id=command_id,
                            expected_state_version=(status['state_version'] if forced_version is None else forced_version))
            began = time.monotonic()
            outcome = self.service.tool_outcome(tool, sent, timeout=480 if tool in ('start', 'stop') else 120)  # type: ignore[union-attr]
            finished = time.monotonic()
            entry = {'tool': tool, 'expect': expect, 'mutation': mutation, 'command_id': command_id,
                     'sent_arguments': outcome['sent_arguments'], 'args_digest': digest(outcome['sent_arguments']),
                     'response': outcome['response'], 'response_digest': digest(outcome['response']),
                     'ok': bool(outcome['ok']), 'error': outcome['error'],
                     'response_headers': outcome['response_headers'], 'duration_seconds': finished - began}
            calls.append(entry)
            if expect == 'reject_state_conflict':
                before_version = forced_version
                after = self._status()
                code = self._outcome_code(outcome)
                entry['rejection_oracle'] = {'expected_code': 'state_conflict', 'observed_code': code,
                                             'before_version': before_version,
                                             'after_version': after.get('state_version'),
                                             'side_effect_free': before_version is not None and
                                             after.get('state_version') == before_version + 1}
                # The prior successful create advanced the state exactly once;
                # the stale attempt itself must not advance it.
                if outcome['ok'] or code != 'state_conflict' or not entry['rejection_oracle']['side_effect_free']:
                    raise SuiteError('stale optimistic-lock rejection is not typed and side-effect free')
                return after
            if not outcome['ok'] or not isinstance(outcome['value'], dict):
                raise SuiteError('%s rejected: %r' % (tool, outcome['error']))
            return outcome['value']

        def cleanup_mutation(label: str, tool: str, args: dict[str, Any]) -> dict[str, Any] | None:
            nonlocal sequence
            sequence += 1
            status = self._status()
            sent = dict(args, command_id=self._command_id(scenario_id, attempt, sequence),
                        expected_state_version=status['state_version'])
            outcome = self.service.tool_outcome(tool, sent, timeout=480 if tool == 'stop' else 120)  # type: ignore[union-attr]
            entry = {'label': label, 'tool': tool, 'command_id': sent['command_id'],
                     'sent_arguments': sent, 'args_digest': digest(sent), 'response': outcome['response'],
                     'response_digest': digest(outcome['response']), 'ok': bool(outcome['ok']), 'error': outcome['error']}
            cleanup_calls.append(entry)
            if not outcome['ok'] or not isinstance(outcome['value'], dict):
                raise SuiteError('cleanup %s rejected: %r' % (label, outcome['error']))
            return outcome['value']

        def finish_capture(label: str, run: dict[str, Any]) -> None:
            capture = captures.pop(label, None)
            if not capture:
                return
            stopped = self._stop_capture_and_probe(capture)
            evidence.write('%s-capture-stop.json' % label, stopped)
            transfers = []
            for item in stopped['files']:
                local = root / label / PureWindowsPath(item['path']).name
                transfers.append(self._transfer_guest_file(item['path'], item['bytes'], item['sha256'], local))
                evidence.add(local)
            evidence.write('%s-capture-transfer.json' % label, {'files': transfers})
            nic_record = next((item for item in transfers
                               if PureWindowsPath(str(item['path'])).name == 'pktmon-nic.json'), None)
            if not nic_record:
                raise SuiteError('pktmon NIC metadata was not transferred')
            nic_path = self.root / str(nic_record['path'])
            pktmon_record = next((item for item in transfers
                                  if PureWindowsPath(str(item['path'])).name == 'pktmon.txt'), None)
            if not pktmon_record:
                raise SuiteError('pktmon text export was not transferred')
            pktmon_path = self.root / str(pktmon_record['path'])
            try:
                nic_metadata = read_json(nic_path)
                nic_issues = pktmon_capture_issues(nic_metadata, pktmon_path.read_bytes())
                binding = pktmon_nic_binding(nic_metadata) if not nic_issues else None
            except (OSError, ValueError, SuiteError) as exc:
                nic_metadata, nic_issues, binding = None, ['pktmon NIC metadata invalid: %r' % (exc,)], None
            evidence.write('%s-pktmon-nic-verdict.json' % label, {
                'metadata': nic_record, 'passed': not nic_issues, 'issues': nic_issues,
                'binding': binding,
            })
            run['capture'] = {'observation_contract': 'con008', 'label': label, 'files': transfers, 'all_components': True,
                              'requested_file_size_mib': capture.get('requested_file_size_mib'),
                              'probe_launcher_pid': capture['pid'],
                              'probe_path': next((x['path'] for x in transfers if x['path'].endswith('probe.jsonl')), None),
                              'pktmon_path': pktmon_record['path'],
                              'pktmon_etl_path': next((x['path'] for x in transfers if x['path'].endswith('pktmon.etl')), None),
                              'pktmon_nic_path': nic_record['path'], 'pktmon_binding': binding,
                              'pktmon_capture_issues': nic_issues}
            run['capture_stopped_at'] = utc_now()

        try:
            evidence.write('continuation-gate.json', gate)
            before_sections, before_raw = self._capture_sections()
            evidence.write('five-sections-before.json', {'sections': before_sections, 'raw': before_raw})
            process_image = self._probe_image_identity() if runtime_profile['bucket'] == 'B3' else None
            content = profile_content(runtime_profile, preflight['external_dns_server'], process_image,
                                      preflight['api_ipv4'])
            evidence.write('rendered-config.json', {'manifest_profile': scenario['config_profile'],
                                                    'runtime_profile': runtime_profile,
                                                    'sha256': hashlib.sha256(content.encode()).hexdigest(), 'content': content})
            if runtime_profile['bucket'] in ('B2', 'B3'):
                sentinel = FnprSentinel(root)
                evidence.write('fnpr-sentinel-start.json', {
                    'pid': sentinel.process.pid, 'bind': '192.168.204.1', 'port': 443,
                    'mode': sentinel.mode, 'container': sentinel.container,
                    'ready_rows': sentinel.rows(),
                })
            if fault:
                # Own restoration before entry: enable can mutate then raise.
                fault_mode_attempted = True
                fault_evidence['mode_enabled'] = self._fault_mode(True)
                evidence.write('fault-mode-enabled.json', fault_evidence['mode_enabled'])
            try:
                pruned = self._prune_scenario_configs(scenario_id)
                evidence.write('scenario-config-prune.json', pruned)
            except Exception as exc:  # noqa: BLE001
                evidence.write('scenario-config-prune.json', {'error': repr(exc)})
            call('list_configs')
            call('validate_config', {'content': content})
            stale_version = self._status()['state_version']
            call('create_config', {'name': scratch, 'content': content}, mutation=True)
            # A never-created name makes the version gate, rather than a name
            # collision, the only acceptable reason for this rejection.
            call('create_config', {'name': scratch + '-stale', 'content': content}, mutation=True,
                 expect='reject_state_conflict', forced_version=stale_version)
            read_scratch = call('read_config', {'name': scratch})
            call('edit_config', {'name': scratch, 'content': content, 'expected_sha256': read_scratch['sha256']}, mutation=True)
            read_scratch = call('read_config', {'name': scratch})
            call('rename_config', {'name': scratch, 'new_name': active, 'expected_sha256': read_scratch['sha256']}, mutation=True)
            call('import_config', {'name': imported, 'content': content}, mutation=True)
            read_imported = call('read_config', {'name': imported})
            call('delete_config', {'name': imported, 'expected_sha256': read_imported['sha256']}, mutation=True)
            call('load_config', {'name': active}, mutation=True)
            guest = self._guest_scenario_root(scenario_id, attempt)
            first_label = 'run-01'
            captures[first_label] = self._start_capture_and_probe(guest, runtime_profile, nonce, first_label)
            evidence.write(first_label + '-capture-start.json', captures[first_label])
            if fault in ('listener_stop', 'diverter_stop', 'child_hang'):
                fault_evidence['arm'] = self._arm_fault(fault, nonce)
                evidence.write('fault-arm.json', fault_evidence['arm'])
            def start_in_worker() -> tuple[threading.Thread, dict[str, Any]]:
                start_box: dict[str, Any] = {}

                def invoke_start() -> None:
                    try:
                        start_box['value'] = call('start', {}, mutation=True)
                    except BaseException as exc:  # capture the original RPC error for immutable evidence
                        start_box['error'] = repr(exc)

                worker = threading.Thread(target=invoke_start, name='scenario-start-' + scenario_id)
                worker.start()
                return worker, start_box

            interleave = runtime_profile['interleave']
            if fault in ('listener_stop', 'diverter_stop', 'child_hang'):
                # The probe must be active for the entire startup preparation
                # interval as well as the product's ten-second rendezvous.
                fault_evidence['probe_release'] = self._release_probe(
                    captures[first_label], 'during-start-gate')
                worker, start_box = start_in_worker()
                gate_error: Exception | None = None
                try:
                    fault_evidence['gate'] = self._run_gate(fault, nonce, captures[first_label])
                except Exception as exc:  # settle below before any cleanup mutation
                    gate_error = exc
                    fault_evidence['gate_error'] = repr(exc)
                settlement = self._settle_start_worker(worker, start_box)
                fault_evidence['start_settlement'] = settlement
                if not settlement.get('settled'):
                    operation_unsettled = True
                    raise SuiteError('gated start remains unsafe to mutate: ' + str(settlement.get('reason')))
                if start_box.get('error'):
                    raise SuiteError('gated start RPC failed: ' + str(start_box['error']))
                if 'value' not in start_box:
                    raise SuiteError('gated start returned without a response')
                if gate_error is not None:
                    raise SuiteError('fault gate failed after start settlement: %r' % (gate_error,))
                started = start_box['value']
            elif interleave == 'during-start':
                worker, start_box = start_in_worker()
                first_run_release = self._release_probe(captures[first_label], 'during-start')
                settlement = self._settle_start_worker(worker, start_box)
                if not settlement.get('settled'):
                    operation_unsettled = True
                    raise SuiteError('start remains unsafe to mutate: ' + str(settlement.get('reason')))
                if start_box.get('error') or 'value' not in start_box:
                    raise SuiteError('during-start RPC failed: ' + str(start_box.get('error')))
                started = start_box['value']
            else:
                if interleave == 'before-start':
                    first_run_release = self._release_probe(captures[first_label], 'before-start')
                started = call('start', {}, mutation=True)
            run_id = started.get('run_id') or fault_evidence.get('gate', {}).get('run_id')
            first_run = {'run_id': run_id, 'label': first_label, 'start_response': started,
                         'started_at': utc_now(), 'five_sections_before': before_sections}
            if first_run_release is not None:
                first_run['probe_release'] = first_run_release
            runs.append(first_run)
            self._write_state(scenario_id, dict(state, updated_at=utc_now()))
            if started.get('state') == 'healthy':
                if interleave in ('after-healthy', 'restart-window'):
                    first_run['probe_release'] = self._release_probe(
                        captures[first_label], interleave)
                if interleave != 'stop-window':
                    self._run_auxiliary_cases(first_run, captures[first_label], runtime_profile)
                if scenario.get('lifecycle_chain') == 'restart':
                    # Bind the first run before restart changes current-run
                    # identity.  Its probe/ETL is independent of run-02.  The
                    # runtime PCAP is NOT collected here: the pcap writers stay
                    # open for the whole run and only publish after the stop,
                    # so every healthy run's pcap is collected once after the
                    # final stop converged (fakenet100 T005-R02 fix of the
                    # restart-branch wait that read an unclosed file).
                    first_run['events'] = call('get_events', {'limit': 100})
                    first_run['artifacts'] = call('list_artifacts')
                    finish_capture(first_label, first_run)
                    second_label = 'run-02'
                    captures[second_label] = self._start_capture_and_probe(guest, runtime_profile, nonce, second_label)
                    evidence.write(second_label + '-capture-start.json', captures[second_label])
                    restart_context, restart_context_raw = self._capture_sections()
                    evidence.write(second_label + '-pre-restart-context.json',
                                   {'sections': restart_context, 'raw': restart_context_raw,
                                    'role': 'active-run-context-not-recovery-baseline'})
                    # The second session is released immediately before the
                    # restart mutation; its record proves the restart window,
                    # rather than merely carrying that label in the manifest.
                    second_release = self._release_probe(captures[second_label], 'restart-window')
                    restarted = call('restart', {}, mutation=True)
                    first_run['recovery_audit'], first_run['five_sections_after'] = self._run_recovery_sections(
                        first_run['run_id'], root / first_label / 'recovery-audits', evidence)
                    restart_difference = self._section_difference(first_run['five_sections_before'],
                                                                   first_run['five_sections_after'])
                    restart_attribution = (
                        self._attribute_section_difference(first_run['five_sections_before'],
                                                           first_run['five_sections_after'])
                        if restart_difference else None)
                    evidence.write(first_label + '-five-sections-product-after.json', {
                        'sections': first_run['five_sections_after'], 'difference': restart_difference,
                        'difference_attribution': restart_attribution,
                        'recovery_audit': first_run['recovery_audit']})
                    if self._difference_is_residue(restart_difference, restart_attribution):
                        raise SuiteError('restart run-01 five-section recovery difference: ' + repr(restart_difference))
                    second_before = self._restart_baseline(first_run, restart_attribution)
                    evidence.write(second_label + '-five-sections-before.json', {
                        'sections': second_before, 'source_run_id': first_run['run_id'],
                        'source_recovery_audit': first_run['recovery_audit'],
                        'role': 'verified-restored-state-before-restart-start'})
                    run_id = restarted.get('run_id')
                    active_run = {'run_id': run_id, 'label': second_label, 'start_response': restarted,
                                  'started_at': utc_now(), 'five_sections_before': second_before,
                                  'probe_release': second_release}
                    runs.append(active_run)
                    if restarted.get('state') != 'healthy':
                        raise SuiteError('restart did not publish healthy')
                    self._run_auxiliary_cases(active_run, captures[second_label], runtime_profile)
                else:
                    active_run = first_run
                for sample_index in range(3):
                    time.sleep(2)
                    sample = call('get_status')
                    status_samples.append({'sample': sample_index + 1, 'at': utc_now(), 'status': sample,
                                           'run_id': run_id})
                    if sample.get('state') != 'healthy' or sample.get('run_id') != run_id:
                        raise SuiteError('continuous health changed during active run')
                if fault in ('policy_pause', 'cleanup_error'):
                    fault_evidence['arm'] = self._arm_fault(fault, nonce)
                    evidence.write('fault-arm.json', fault_evidence['arm'])
                events = call('get_events', {'limit': 100})
                artifacts = call('list_artifacts')
                active_run['events'] = events
                active_run['artifacts'] = artifacts
                if interleave == 'stop-window':
                    active_run['probe_release'] = self._release_probe(
                        captures[active_run['label']], 'stop-window')
                    self._run_auxiliary_cases(active_run, captures[active_run['label']], runtime_profile)
                    # Give the independently-launched client an observable
                    # connection interval before stop begins.
                    time.sleep(1)
                stopped = call('stop', {}, mutation=True)
                active_run['stop_response'] = stopped
                if stopped.get('state') != 'stopped':
                    raise SuiteError('stop did not converge')
                # Runtime PCAP is independent from the all-components pktmon
                # trace; both must bind to this exact run.  The dual pcap
                # writers hold the file open for the whole run, so its
                # publication only completes after the stop; waiting during
                # the healthy window always timed out (discovery100-10/13).
                # Every healthy run in this scenario collects its OWN pcap by
                # its own run id after both writers closed; a later run's
                # bytes never stand in for an earlier run.
                self._collect_runtime_pcaps(runs, root, evidence, runtime_profile)
                finish_capture(active_run['label'], active_run)
                run_after, run_after_raw = self._capture_sections()
                active_run['five_sections_after'] = run_after
                run_difference = self._section_difference(active_run['five_sections_before'], run_after)
                run_attribution = (self._attribute_section_difference(
                    active_run['five_sections_before'], run_after) if run_difference else None)
                evidence.write(active_run['label'] + '-five-sections-after.json', {
                    'sections': run_after, 'raw': run_after_raw, 'difference': run_difference,
                    'difference_attribution': run_attribution})
                if self._difference_is_residue(run_difference, run_attribution):
                    raise SuiteError('%s five-section recovery difference: %r' %
                                     (active_run['label'], run_difference))
            else:
                # Start-injection faults use their receipt run id; no healthy
                # publication is manufactured by the test runner.
                benign_refusal = (not fault and self._is_quiescence_refusal_family(
                    runtime_profile))
                if benign_refusal:
                    # The refusal family's benign plan tail is sampled in
                    # order: get_status x3, then get_events, list_artifacts,
                    # stop (strict prefix semantics).
                    call('get_status')
                    call('get_status')
                    call('get_status')
                else:
                    call('get_status')
                call('get_events', {'limit': 100})
                call('list_artifacts')
                finish_capture(first_label, first_run)
                if not fault:
                    refusal = self._expected_quiescence_refusal(
                        started, runtime_profile)
                    if refusal is None:
                        raise SuiteError('benign scenario did not publish healthy')
                    # A B3 match image released before start is BY DESIGN
                    # already running when the product validates quiescence;
                    # the refusal is the correct product outcome for this
                    # interleave and the scenario verifies exactly it
                    # (discovery100-68 sst-051..053).
                    first_run['expected_refusal'] = refusal
                    evidence.write(first_label + '-expected-refusal.json', refusal)
                    # The stop is idempotent on the already-stopped service.
                    call('stop', {}, mutation=True)
            final = self._status()
            evidence.write('final-status.json', final)
            if final.get('state') != 'stopped':
                raise SuiteError('service did not reach stopped before cleanup')
        except Exception as exc:  # noqa: BLE001
            failure = repr(exc)
        finally:
            if operation_unsettled:
                # Do not send a stop, config delete, registry edit, capture
                # stop or any other mutable command while the original start
                # RPC may still own the controller.  Preserve this explicit
                # failed attempt for a later human/continuation-gate recovery.
                cleanup_errors.append('no cleanup mutation: start operation was not terminal')
            else:
                for label, capture in list(captures.items()):
                    try:
                        owner = next((item for item in runs if item.get('label') == label), {'label': label})
                        finish_capture(label, owner)
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append('capture %s: %r' % (label, exc))
                try:
                    current = self._status()
                    if current.get('state') != 'stopped':
                        cleanup_mutation('stop-managed-service', 'stop', {})
                except Exception as exc:  # noqa: BLE001
                    cleanup_errors.append('service stop: %r' % (exc,))
                for name in (imported, scratch, active):
                    try:
                        current = self.service.tool_outcome('read_config', {'name': name})  # type: ignore[union-attr]
                        value = current.get('value') or {}
                        if current.get('ok') and not value.get('error'):
                            cleanup_mutation('delete-' + name, 'delete_config',
                                             {'name': name, 'expected_sha256': value['sha256']})
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append('config %s: %r' % (name, exc))
                if fault_mode_attempted:
                    try:
                        fault_evidence['terminal_status'] = self._status()
                        evidence.write('fault-terminal-primary.json', fault_evidence['terminal_status'])
                    except Exception as exc:
                        cleanup_errors.append('primary fault terminal capture: %r' % (exc,))
                    try:
                        fault_evidence['mode_disabled'] = self._fault_mode(False)
                        evidence.write('fault-mode-disabled.json', fault_evidence['mode_disabled'])
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append('fault-mode restore: %r' % (exc,))
                try:
                    after_sections, after_raw = self._capture_sections()
                    diff = self._section_difference(before_sections or {}, after_sections)
                    attribution = (self._attribute_section_difference(before_sections or {}, after_sections)
                                   if diff else None)
                    evidence.write('five-sections-after.json', {
                        'sections': after_sections, 'raw': after_raw, 'difference': diff,
                        'difference_attribution': attribution})
                    if self._difference_is_residue(diff, attribution):
                        cleanup_errors.append('five-section environment difference: ' + repr(diff))
                except Exception as exc:  # noqa: BLE001
                    cleanup_errors.append('five-section recovery capture: %r' % (exc,))
            if sentinel is not None:
                try:
                    sentinel_evidence = sentinel.stop()
                    sentinel_path = evidence.write('fnpr-sentinel-stop.json', sentinel_evidence)
                    sentinel_record = file_record(sentinel_path, self.root)
                    if sentinel.log.is_file():
                        evidence.add(sentinel.log)
                    if sentinel.stdout.is_file():
                        evidence.add(sentinel.stdout)
                    if sentinel_evidence.get('returncode') not in (0, -15):
                        cleanup_errors.append('FNPR sentinel ended unexpectedly: %r' %
                                              (sentinel_evidence.get('returncode'),))
                except Exception as exc:  # noqa: BLE001
                    cleanup_errors.append('FNPR sentinel stop: %r' % (exc,))
        final_status = self._status() if self.service else {}
        # Finalize every run only after its capture has stopped and the managed
        # process has reached its terminal state.  A missing original is a
        # scenario failure; it is never replaced by a host-side summary.
        try:
            for run in runs:
                run_id = run.get('run_id')
                if not run_id:
                    if run.get('expected_refusal'):
                        # The product refused this start by design; no run
                        # existed, so there are no run originals to export.
                        continue
                    raise SuiteError('run has no immutable run_id')
                original_root = root / run['label'] / 'originals'
                run['originals'] = self._export_run_originals(run_id, original_root, evidence)
                if 'five_sections_after' not in run:
                    run['five_sections_after'] = after_sections
                if not fault and run.get('start_response', {}).get('state') == 'healthy':
                    run['traffic_oracle'] = self._traffic_oracle(
                        run, runtime_profile, nonce, sentinel_evidence)
                    if not fault:
                        run['log_clean_issues'] = self._benign_log_issues(run, self.root)
            if fault and not operation_unsettled:
                primary = runs[0]
                fault_evidence['recovery_audit'], primary['five_sections_after'] = self._run_recovery_sections(
                    primary['run_id'], root / 'recovery-audits', evidence)
                fault_evidence['recovery_cycle'] = self._fault_recovery_cycle(scenario_id, attempt)
                evidence.write('fault-recovery-cycle.json', fault_evidence['recovery_cycle'])
                cleanup_native, cleanup_raw = self._cleanup_native(primary, nonce)
                cleanup_native['raw'] = cleanup_raw
                fault_evidence['cleanup_native'] = cleanup_native
                evidence.write('fault-cleanup-native.json', cleanup_native)
                fault_evidence['adjudication'] = self._adjudicate_fault(
                    scenario, primary, nonce, root, evidence, fault_evidence)
                primary['fault_connection_case'] = fault_evidence['adjudication'].get('case')
                if primary.get('start_response', {}).get('state') == 'healthy':
                    # Same verdict path and identity inputs as the offline
                    # _traffic_recheck_issues re-adjudication: no fault-window
                    # waiver, no divergent parameters (2026-09-20 VFY-004 fix).
                    primary['traffic_oracle'] = self._traffic_oracle(primary, runtime_profile,
                                                                     nonce, sentinel_evidence)
        except Exception as exc:  # noqa: BLE001
            if failure is None:
                failure = repr(exc)
        refusal_recorded = any(item.get('expected_refusal') for item in runs)
        plan_tools = [item['tool'] for item in scenario['interface_call_plan']]
        call_tools = [item['tool'] for item in calls]
        verdict = {'interface_semantics': (call_tools == plan_tools or
                   (bool(refusal_recorded) and plan_tools[:len(call_tools)] == call_tools)),
                   'stale_lock_rejection': any(item.get('expect') == 'reject_state_conflict' and
                                               item.get('rejection_oracle', {}).get('side_effect_free')
                                               for item in calls),
                   'continuous_health': (bool(fault) or bool(refusal_recorded) or
                                         (len(status_samples) == 3 and
                                         all(item['status'].get('state') == 'healthy' for item in status_samples))),
                   'per_run_dual_capture': bool(runs) and all(item.get('capture', {}).get('all_components') and
                                                               (not runtime_pcap_required(runtime_profile) or item.get('runtime_pcap')) for item in runs if
                                                               item.get('start_response', {}).get('state') == 'healthy'),
                   'five_section_recovery': not cleanup_errors and after_sections is not None,
                   'traffic_oracle': bool(runs) and all(
                       item.get('traffic_oracle', {}).get('passed') for item in runs
                       if item.get('start_response', {}).get('state') == 'healthy'),
                   'log_clean': (bool(fault) or all(not item.get('log_clean_issues') for item in runs
                                                     if item.get('start_response', {}).get('state') == 'healthy')),
                   'cleanup_recorded': bool(cleanup_calls) or final_status.get('state') == 'stopped',
                   'fault_oracle': not fault}
        if fault:
            # A fault result is accepted only after scenario_fault_evidence.py
            # creates and passes a byte-addressed case. The raw descriptor is
            # retained now; a missing adapter is an honest failed scenario.
            terminal = fault_evidence.get('terminal_status') or {}
            verdict['fault_terminal'] = (terminal.get('state') == 'stopped' and
                                         terminal.get('last_run_outcome') == 'failed' and
                                         terminal.get('run_id') is None and terminal.get('controller') is None)
            recovery = fault_evidence.get('recovery_cycle') or {}
            verdict['fault_recovery'] = (recovery.get('started', {}).get('state') == 'healthy' and
                                         len(recovery.get('health_samples', [])) == 3 and
                                         recovery.get('stopped', {}).get('state') == 'stopped')
            verdict['fault_oracle'] = bool(fault_evidence.get('adjudication', {}).get('passed'))
        scenario_passed = failure is None and all(verdict.values())
        try:
            vm_footprint = self._prune_scenario_vm_footprint(
                runs, guest, fault, scenario_passed=scenario_passed)
            evidence.write('vm-footprint-prune.json', vm_footprint)
        except Exception as exc:  # noqa: BLE001
            evidence.write('vm-footprint-prune.json', {'error': repr(exc)})
        scenario_state = 'pass' if scenario_passed else 'fail'
        if failure is None and scenario_state != 'pass':
            failure = 'scenario verdict false: ' + repr([key for key, value in verdict.items() if not value])
        state.update({'phase': scenario_state, 'updated_at': utc_now()})
        self._write_state(scenario_id, state)
        result = {'schema': SCENARIO_SCHEMA, 'identity': self.identity.as_dict(),
                  'scenario_id': scenario_id, 'state': scenario_state, 'scenario': scenario,
                  'attempt': attempt, 'seed': scenario['seed'], 'interface_calls': calls,
                  'cleanup_calls': cleanup_calls,
                  'traffic_evidence': {'nonce': nonce, 'runtime_profile': runtime_profile,
                                       'fnpr_sentinel_record': sentinel_record,
                                       'capture_views': [file_record(root / item['path'], self.root)
                                           for item in evidence.items]},
                  'health_trace': {'window': 'W-traffic', 'samples': status_samples,
                                   'all_healthy': bool(status_samples) and all(x['status'].get('state') == 'healthy' for x in status_samples)},
                  'five_section_audit': {'before': before_sections, 'after': after_sections},
                  'fault_evidence': fault_evidence, 'verdict': verdict, 'run_chain': runs,
                  'recovery': {'final_status': final_status, 'cleanup_errors': cleanup_errors},
                  'failure': failure, 'created_at': utc_now()}
        if result_path.exists():
            raise Blocked('immutable result unexpectedly exists: ' + scenario_id)
        write_new_json(result_path, result)
        return result

    def _probe_image_identity(self) -> dict[str, str]:
        assert self.vm
        script = GUEST_ROOT + r'\scenario-suite-20260912\scenario_probes.ps1'
        value, _ = self._vm_json(
            "$ErrorActionPreference='Stop';& " + quote_ps(script) + " -Action ensure-client -Output " +
            quote_ps(GUEST_ROOT + r'\scenario-suite-20260912\probe-client.json') + ";"
            "Get-Content " + quote_ps(GUEST_ROOT + r'\scenario-suite-20260912\probe-client.json') + " -Raw", 120)
        required = ('path', 'sha256', 'public_ipv4', 'private_ipv4')
        if any(not value.get(key) for key in required):
            raise Blocked('B3 probe executable identity incomplete')
        return {key: str(value[key]) for key in required}

    @staticmethod
    def _spike_file(root: Path, reference: dict[str, Any]) -> Path:
        path = (root / reference['path']).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('Spike evidence missing or outside root')
        raw = path.read_bytes()
        if len(raw) != reference['size'] or hashlib.sha256(raw).hexdigest() != reference['sha256']:
            raise ValueError('Spike evidence bytes differ')
        return path

    def _validate_fault_spike(self, path: Path) -> None:
        """Bind the five executed cases and rejudge their original bytes."""
        root = path.resolve().parent
        try:
            report = read_json(path)
            if (report.get('schema') != 'sst.fault-spike.v1' or
                    report.get('identity') != self.identity.as_dict() or
                    report.get('passed') is not True or report.get('synthetic')):
                raise ValueError('Spike schema/candidate/result mismatch')
            if root == self.root:
                raise ValueError('Spike and actual matrix require distinct roots')
            manifest_path = self._spike_file(root, report['manifest'])
            manifest = read_json(manifest_path)
            if manifest_issues(manifest) or manifest != self.manifest():
                raise ValueError('Spike manifest differs from actual matrix')
            cases = report['cases']
            if (not isinstance(cases, list) or len(cases) != len(FAULTS) or
                    sorted(report['five_classes']) != sorted(FAULTS) or
                    sorted(case['fault_class'] for case in cases) != sorted(FAULTS)):
                raise ValueError('Spike requires exactly one case per fault class')
            seen_runs = set()
            for case in cases:
                selected = sorted((row for row in manifest['scenarios']
                    if row['fault_class'] == case['fault_class'] and
                    row['config_profile']['bucket'] != 'default'), key=lambda row: row['scenario_id'])[0]
                result = read_json(self._spike_file(root, case['result']))
                if (case['scenario_id'] != selected['scenario_id'] or result.get('scenario') != selected or
                        result.get('scenario_id') != selected['scenario_id'] or
                        result.get('identity') != self.identity.as_dict()):
                    raise ValueError('Spike case/scenario/candidate mismatch')
                run_ids = [row['run_id'] for row in result.get('run_chain', [])]
                if not run_ids or case['run_ids'] != run_ids or seen_runs.intersection(run_ids):
                    raise ValueError('Spike run identity absent/reused/different')
                seen_runs.update(run_ids)
                adjudication = result.get('fault_evidence', {}).get('adjudication', {})
                if case['evidence'] != adjudication.get('result'):
                    raise ValueError('Spike evidence result reference differs')
                evidence_result = read_json(self._spike_file(root, case['evidence']))
                sealed_case = read_json(self._spike_file(root, adjudication['case']))
                if (case.get('synthetic') or result.get('synthetic') or
                        evidence_result.get('synthetic') is not False or
                        sealed_case.get('synthetic') is not False):
                    raise ValueError('synthetic or unclassified Spike evidence')
                descriptor = read_json(self._spike_file(root, adjudication['descriptor']))
                if (descriptor.get('synthetic') or
                        descriptor.get('candidate_id') != self.identity.candidate_id or
                        descriptor.get('fault') != case['fault_class'] or
                        descriptor.get('scenario_id') != case['scenario_id'] or
                        descriptor.get('run_id') not in run_ids):
                    raise ValueError('Spike raw descriptor identity differs')
                calls = [(x.get('tool'), x.get('expect')) for x in result.get('interface_calls', [])]
                if calls != [(x['tool'], x['expect']) for x in selected['interface_call_plan']]:
                    raise ValueError('Spike interface call contract differs')
                issues = result_issues(result, root) + fault_recheck_issues(result, root)
                if issues:
                    raise ValueError('; '.join(issues))
        except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
            raise Blocked('fault run requires bound five-class Spike evidence: ' + str(exc)) from exc

    def _require_fault_spike(self):
        path = getattr(self.args, 'fault_spike_result', None)
        if not path:
            raise Blocked('fault run requires bound five-class Spike evidence')
        self._validate_fault_spike(Path(path))

    def fault_spike(self) -> dict[str, Any]:
        manifest = self.manifest()
        if 'spike' not in self.root.name.lower():
            raise Blocked('fault-spike requires a distinct root named spike')
        output = self.root / 'fault-spike-result.json'
        if output.exists() or list((self.root / 'results').glob('scenario-*.json')):
            raise Blocked('fault-spike requires an unused execution root')
        selected = [sorted((row for row in manifest['scenarios'] if
                    row['fault_class'] == fault and row['config_profile']['bucket'] != 'default'),
                    key=lambda row: row['scenario_id'])[0] for fault in FAULTS]
        self.require_clients()
        self._require_preflight()
        cases, problems = [], []
        for scenario in selected:
            result = self._run_one(scenario, 1)
            adjudication = result.get('fault_evidence', {}).get('adjudication', {})
            cases.append(dict(fault_class=scenario['fault_class'], scenario_id=scenario['scenario_id'],
                run_ids=[row['run_id'] for row in result.get('run_chain', [])],
                result=file_record(self._result_path(scenario['scenario_id']), self.root),
                evidence=adjudication.get('result')))
            problems.extend(result_issues(result, self.root))
            problems.extend(fault_recheck_issues(result, self.root))
            try:
                for key in ('case', 'result'):
                    sealed = read_json(self._spike_file(self.root, adjudication[key]))
                    if sealed.get('synthetic') is not False:
                        problems.append('synthetic or unclassified Spike evidence')
            except (OSError, ValueError, KeyError, TypeError) as exc:
                problems.append('missing sealed Spike evidence: ' + str(exc))
            if problems:
                break
        report = dict(schema='sst.fault-spike.v1', identity=self.identity.as_dict(),
            manifest=file_record(self.manifest_path, self.root),
            five_classes=[case['fault_class'] for case in cases], cases=cases,
            passed=len(cases) == len(FAULTS) and not problems, problems=problems,
            not_executed=[row['scenario_id'] for row in selected[len(cases):]])
        write_new_json(output, report)
        return report

    def _ipc_evidence_pass(self, enabled_name: str, disabled_name: str, body):
        """Execute body() under the matrix-pass IPC evidence responsibility.

        The responsibility starts before the arming call itself: once enable
        is attempted, every exit path — including a partially applied arming
        or an unwritable enabled record — attempts exactly one controlled
        disable and independently records the recovery outcome.  Scenarios
        run only after the arming and its record both succeeded; a raised
        body exception propagates unchanged after the cleanup, and the
        recovery error never replaces the original one.
        """
        ipc_evidence: dict[str, Any] = {'attempted': True}
        outcome = None
        try:
            try:
                ipc_evidence['enabled'] = self._ipc_evidence_mode(True)
            except Exception as exc:  # noqa: BLE001
                ipc_evidence['enabled'] = {'error': repr(exc)}
            else:
                try:
                    replace_json(self.root / enabled_name, ipc_evidence['enabled'])
                except Exception as exc:  # noqa: BLE001
                    ipc_evidence['enabled_write_error'] = repr(exc)
            if (isinstance(ipc_evidence.get('enabled'), dict)
                    and 'error' not in ipc_evidence['enabled']
                    and 'enabled_write_error' not in ipc_evidence):
                outcome = body()
        finally:
            try:
                ipc_evidence['disabled'] = self._ipc_evidence_mode(False)
            except Exception as exc:  # noqa: BLE001
                ipc_evidence['disabled'] = {'error': repr(exc)}
            try:
                replace_json(self.root / disabled_name, ipc_evidence['disabled'])
            except Exception as exc:  # noqa: BLE001
                ipc_evidence['disabled_write_error'] = repr(exc)
        return outcome, ipc_evidence

    @staticmethod
    def _ipc_evidence_recovered(ipc_evidence: dict[str, Any]) -> bool:
        enabled = ipc_evidence.get('enabled')
        disabled = ipc_evidence.get('disabled')
        return (isinstance(enabled, dict) and 'error' not in enabled
                and 'enabled_write_error' not in ipc_evidence
                and isinstance(disabled, dict) and 'error' not in disabled
                and disabled.get('enabled') is False
                and 'disabled_write_error' not in ipc_evidence)

    def run(self, filter_name: str) -> dict[str, Any]:
        manifest = self.manifest()
        if filter_name == 'fault':
            self._require_fault_spike()
        self.require_clients()
        self._require_preflight()
        selected = [row for row in manifest['scenarios'] if
                    (row['fault_class'] is None if filter_name == 'benign' else row['fault_class'] is not None)]

        def execute() -> list[dict[str, Any]]:
            # Every scenario exports ipc-parent.jsonl, but only fault scenarios
            # arm the evidence environment themselves; arm it for the whole pass.
            results = []
            for scenario in selected:
                result_path = self._result_path(scenario['scenario_id'])
                if result_path.exists():
                    result = read_json(result_path)
                    if result.get('state') in ('pass', 'fail'):
                        results.append(result)
                        if result.get('state') != 'pass' and getattr(self.args, 'stop_on_first_failure', False):
                            break
                        continue
                results.append(self._run_one(scenario, 1))
                if results[-1]['state'] != 'pass':
                    if getattr(self.args, 'stop_on_first_failure', False):
                        break
                    # Preserve this failure and enforce the continuation gate before
                    # any following scenario.  A failed gate exits blocked, not pass.
                    self._continuation_gate()
            return results

        results, ipc_evidence = self._ipc_evidence_pass(
            'ipc-evidence-%s-enabled.json' % filter_name,
            'ipc-evidence-%s-disabled.json' % filter_name, execute)
        results = results if results is not None else []
        passed = (self._ipc_evidence_recovered(ipc_evidence)
                  and all(row.get('state') == 'pass' for row in results))
        return {'output_dir': str(self.root), 'filter': filter_name, 'count': len(results),
                'passed': passed, 'ipc_evidence': ipc_evidence,
                'states': {row['scenario_id']: row['state'] for row in results}}

    def resume(self) -> dict[str, Any]:
        manifest = self.manifest()
        pending = [row for row in manifest['scenarios']
                   if self._state_path(row['scenario_id']).exists() and
                   read_json(self._state_path(row['scenario_id'])).get('phase') in
                   ('pending', 'blocked', 'running')]
        if any(row['fault_class'] for row in pending):
            self._require_fault_spike()
        self.require_clients()
        self._require_preflight()

        def execute() -> list[dict[str, Any]]:
            rerun = []
            for scenario in manifest['scenarios']:
                path = self._state_path(scenario['scenario_id'])
                if not path.exists():
                    continue
                state = read_json(path)
                if state.get('phase') in ('pending', 'blocked', 'running'):
                    self._continuation_gate()
                    rerun.append(self._run_one(scenario, int(state.get('attempt', 0)) + 1))
                    if rerun[-1].get('state') != 'pass' and getattr(self.args, 'stop_on_first_failure', False):
                        break
            return rerun

        rerun, ipc_evidence = self._ipc_evidence_pass(
            'ipc-evidence-resume-enabled.json', 'ipc-evidence-resume-disabled.json', execute)
        rerun = rerun if rerun is not None else []
        return {'output_dir': str(self.root), 'resumed': len(rerun),
                'ipc_evidence': ipc_evidence,
                'passed': (self._ipc_evidence_recovered(ipc_evidence)
                           and all(row.get('state') == 'pass' for row in rerun))}

    def _traffic_recheck_issues(self, result: dict[str, Any], expected: dict[str, Any]) -> list[str]:
        """Re-adjudicate healthy-run traffic from the byte-bound originals."""
        traffic = result.get('traffic_evidence') or {}
        nonce = traffic.get('nonce')
        runtime = traffic.get('runtime_profile')
        if not isinstance(nonce, str) or not isinstance(runtime, dict):
            return ['traffic recheck lacks nonce/runtime profile']
        planned = expected.get('config_profile') or {}
        for key, value in planned.items():
            if key == 'probe_target':
                continue
            if runtime.get(key) != value:
                return ['traffic runtime profile differs from manifest at ' + key]
        planned_target, runtime_target = planned.get('probe_target') or {}, runtime.get('probe_target') or {}
        if not isinstance(planned_target, dict) or not isinstance(runtime_target, dict):
            return ['traffic runtime target is malformed']
        for key, value in planned_target.items():
            if key == 'host' and value == '__P4_API_IPV4__':
                try:
                    ipaddress.IPv4Address(str(runtime_target.get(key)))
                except ValueError:
                    return ['traffic runtime P4 target is not an IPv4 address']
            elif runtime_target.get(key) != value:
                return ['traffic runtime target differs from manifest at ' + key]
        sentinel: dict[str, Any] | None = None
        record = traffic.get('fnpr_sentinel_record')
        if record is not None:
            try:
                path = (self.root / record['path']).resolve()
                if not path.is_relative_to(self.root.resolve()):
                    raise ValueError('sentinel record escapes suite root')
                sentinel = read_json(path)
            except (KeyError, OSError, ValueError):
                return ['traffic sentinel record is unreadable']
        issues = []
        for run in result.get('run_chain') or []:
            if run.get('start_response', {}).get('state') != 'healthy':
                continue
            if run.get('capture', {}).get('observation_contract') != 'con008':
                issues.append('current execution cannot downgrade application observation contract')
                continue
            verdict = self._traffic_oracle(run, runtime, nonce, sentinel)
            if not verdict.get('passed'):
                issues.append('traffic raw re-adjudication failed: ' + str(verdict.get('reason')))
            issues.extend(self._stored_binding_issues(
                (run.get('traffic_oracle') or {}).get('cases') or [],
                verdict.get('cases') or []))
            def observations(value):
                return dict(primary=value.get('connection_observation'),
                            cases=[row.get('connection_observation') for row in value.get('cases', [])],
                            curl=(value.get('curl') or {}).get('connection_observation'),
                            curl_policy={key:(value.get('curl') or {}).get(key)
                                         for key in ('process_flow','allow_log','upstream_log')})
            if observations(run.get('traffic_oracle') or {}) != observations(verdict):
                issues.append('stored application observations differ from full raw reconstruction')
        return issues

    def verify(self, replay: str | None = None) -> dict[str, Any]:
        manifest = self.manifest()
        problems = manifest_issues(manifest)
        results: dict[str, dict[str, Any]] = {}
        result_paths = sorted((self.root / 'results').glob('scenario-*.json')) if (self.root / 'results').exists() else []
        expected_ids = {row['scenario_id'] for row in manifest['scenarios']}
        seen_ids: set[str] = set()
        for path in result_paths:
            try:
                item = read_json(path)
            except (OSError, ValueError) as exc:
                problems.append('unreadable result %s: %s' % (path.name, exc))
                continue
            sid = item.get('scenario_id')
            if not isinstance(sid, str):
                problems.append('result has no string scenario id: ' + path.name)
                continue
            if sid in seen_ids:
                problems.append('duplicate actual scenario id: ' + sid)
                continue
            seen_ids.add(sid)
            if sid not in expected_ids:
                problems.append('extra actual scenario: ' + sid)
            if path.name != 'scenario-%s.json' % sid:
                problems.append('result filename/id mismatch: ' + path.name)
            if item.get('identity') != self.identity.as_dict():
                problems.append('result candidate identity differs: ' + sid)
            expected = next((row for row in manifest['scenarios'] if row['scenario_id'] == sid), None)
            if expected is not None:
                if item.get('scenario') != expected:
                    problems.append('result scenario contract differs: ' + sid)
                expected_calls = [(entry['tool'], entry['expect'])
                                  for entry in expected['interface_call_plan']]
                observed_calls = [(entry.get('tool'), entry.get('expect'))
                                  for entry in item.get('interface_calls', [])]
                if observed_calls != expected_calls:
                    problems.append('result call contract differs: ' + sid)
            results[sid] = item
            problems.extend('%s: %s' % (sid, issue) for issue in result_issues(item, self.root))
            problems.extend('%s: %s' % (sid, issue) for issue in fault_recheck_issues(item, self.root))
            if expected is not None:
                problems.extend('%s: %s' % (sid, issue)
                                for issue in self._traffic_recheck_issues(item, expected))
        for sid in sorted(expected_ids - seen_ids):
            problems.append('missing actual scenario: ' + sid)
        if replay:
            expected = next((row for row in manifest['scenarios'] if row['scenario_id'] == replay), None)
            actual = results.get(replay)
            if not expected or not actual:
                problems.append('replay scenario missing')
            else:
                planned = [item['tool'] for item in expected['interface_call_plan']]
                observed = [item['tool'] for item in actual.get('interface_calls', [])]
                if planned != observed:
                    problems.append('replay call order differs from manifest')
                if any(not item.get('command_id') and item['tool'] in TOOLS[6:]
                       for item in actual.get('interface_calls', [])):
                    problems.append('replay mutation command id absent')
        output = {'schema': SCHEMA + '.verify.v1', 'identity': self.identity.as_dict(),
                  'passed': not problems, 'problems': problems, 'scenario_count': len(results),
                  'replay': replay, 'created_at': utc_now()}
        path = self.root / ('verify-%s.json' % (replay or 'integrity'))
        write_distinct_json(path, output)
        return output

    def summary(self) -> dict[str, Any]:
        manifest = self.manifest()
        records = []
        for path in sorted((self.root / 'results').glob('scenario-*.json')) if (self.root / 'results').exists() else []:
            try:
                records.append(read_json(path))
            except (OSError, ValueError):
                # The integrity result below carries the exact parse failure;
                # coverage sees a missing planned result and cannot pass.
                continue
        coverage = actual_coverage(manifest, records)
        # Summary is an acceptance verdict, not a coverage counter.  Re-run
        # the full byte-integrity, identity and raw-fault adjudication pass.
        integrity = self.verify()
        output = {'schema': SUMMARY_SCHEMA, 'identity': self.identity.as_dict(),
                  'planned': planned_coverage(manifest), 'actual': coverage,
                  'passed': (coverage['pass'] == 100 and coverage['fail'] == 0 and
                             coverage['blocked'] == 0 and not coverage['problems'] and
                             integrity.get('passed') and integrity.get('scenario_count') == 100),
                  'integrity': integrity,
                  'created_at': utc_now()}
        coverage_path = self.root / 'coverage-report.json'
        summary_path = self.root / 'summary.json'
        write_distinct_json(coverage_path, coverage)
        write_distinct_json(summary_path, output)
        return output


def planned_coverage(manifest: dict[str, Any]) -> dict[str, Any]:
    rows = manifest['scenarios']
    bucket = {key: 0 for key in BUCKET_COUNTS}
    fault = {key: 0 for key in FAULTS}
    tools = {key: 0 for key in TOOLS}
    for row in rows:
        bucket[row['config_profile']['bucket']] += 1
        if row['fault_class']:
            fault[row['fault_class']] += 1
        for tool in {item['tool'] for item in row['interface_call_plan']}:
            tools[tool] += 1
    return {'schema': COVERAGE_SCHEMA, 'kind': 'planned', 'scenario_count': len(rows),
            'bucket': bucket, 'fault': fault, 'tool_distinct_scenarios': tools,
            'problems': manifest_issues(manifest)}


def result_issues(result: dict[str, Any], root: Path) -> list[str]:
    """Re-evaluate stored scenario predicates without trusting its verdict bit."""
    root = root.resolve()
    failures: list[str] = []
    if result.get('schema') != SCENARIO_SCHEMA:
        failures.append('wrong scenario result schema')
    if result.get('state') != 'pass':
        failures.append('scenario not pass: ' + str(result.get('scenario_id')))
    calls = result.get('interface_calls') or []
    if len({item.get('tool') for item in calls}) < 10:
        failures.append('fewer than ten actual tools')
    for call in calls:
        if not isinstance(call.get('sent_arguments'), dict) or 'response' not in call:
            failures.append('call lacks exact sent arguments/response')
            break
        if call.get('mutation') and (not call.get('command_id') or
                                     call['sent_arguments'].get('command_id') != call['command_id'] or
                                     'expected_state_version' not in call['sent_arguments']):
            failures.append('mutation lacks bound command/version')
            break
    stale = [item for item in calls if item.get('expect') == 'reject_state_conflict']
    if len(stale) != 1 or stale[0].get('ok') or not stale[0].get('rejection_oracle', {}).get('side_effect_free'):
        failures.append('stale optimistic-lock rejection is not preserved/proved')
    def bound_file(item: Any, label: str) -> str | None:
        try:
            if not isinstance(item, dict):
                raise ValueError('file record is not an object')
            path = (root / item['path']).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise ValueError('evidence path absent/outside root')
            raw = path.read_bytes()
            if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('evidence hash differs')
        except (KeyError, ValueError, OSError) as exc:
            return '%s: %s' % (label, exc)
        return None

    capture_views = result.get('traffic_evidence', {}).get('capture_views', [])
    if not isinstance(capture_views, list) or not capture_views:
        failures.append('bound evidence manifest missing')
    for item in capture_views if isinstance(capture_views, list) else []:
        issue = bound_file(item, 'capture-view')
        if issue:
            failures.append(issue)
    runs = result.get('run_chain') or []
    if not runs:
        failures.append('run chain missing')
    try:
        product_pcap = runtime_pcap_required(result['scenario']['config_profile'])
    except (KeyError, OSError, ValueError, SuiteError):
        failures.append('cannot derive product PCAP requirement from configuration')
        product_pcap = True
    for run in runs:
        capture = run.get('capture') or {}
        if (not capture.get('all_components') or not capture.get('probe_path') or
                not capture.get('pktmon_path') or not capture.get('pktmon_nic_path')):
            failures.append('per-run independent probe/pktmon evidence missing')
            break
        if capture.get('pktmon_capture_issues') or not capture.get('pktmon_binding', {}).get('component_ids'):
            failures.append('pktmon physical-NIC capture completeness/binding missing')
            break
        for item in capture.get('files', []):
            issue = bound_file(item, 'run capture')
            if issue:
                failures.append(issue)
                break
        if (run.get('start_response', {}).get('state') == 'healthy' and
                product_pcap and not run.get('runtime_pcap')):
            failures.append('healthy run lacks second runtime PCAP view')
            break
        if run.get('runtime_pcap'):
            issue = bound_file(run['runtime_pcap'], 'runtime PCAP')
            if issue:
                failures.append(issue)
                break
        if not run.get('originals', {}).get('files'):
            failures.append('complete VM run originals missing')
            break
        originals = run['originals']
        for item in originals.get('files', []):
            issue = bound_file(item, 'VM original')
            if issue:
                failures.append(issue)
                break
        metadata = originals.get('metadata')
        if metadata:
            issue = bound_file(metadata, 'VM original metadata')
            if issue:
                failures.append(issue)
                break
        required_sections = {'dns_servers', 'routes', 'listen_ports', 'windivert_processes', 'services'}
        if (not isinstance(run.get('five_sections_before'), dict) or
                not isinstance(run.get('five_sections_after'), dict) or
                not required_sections <= run['five_sections_before'].keys() or
                not required_sections <= run['five_sections_after'].keys()):
            failures.append('per-run five-section timing missing')
            break
        if run.get('start_response', {}).get('state') == 'healthy' and not run.get('traffic_oracle', {}).get('passed'):
            failures.append('probe PROCESS_FLOW pktmon traffic oracle missing/failed')
            break
        if not result.get('scenario', {}).get('fault_class') and run.get('log_clean_issues'):
            failures.append('benign complete run.log contains exception marker')
            break
        if not result.get('scenario', {}).get('fault_class'):
            log = next((item for item in originals.get('files', [])
                        if Path(str(item.get('path', ''))).name == 'run.log'), None)
            if not log:
                failures.append('benign complete run.log missing')
                break
            try:
                text = (root / str(log['path'])).read_text(encoding='utf-8-sig')
                if any(marker in text for marker in ('Traceback (most recent call last)', 'Unhandled exception')):
                    failures.append('benign complete run.log contains exception marker')
                    break
            except OSError:
                failures.append('benign complete run.log missing')
                break
    audit = result.get('five_section_audit') or {}
    if not isinstance(audit.get('before'), dict) or not isinstance(audit.get('after'), dict):
        failures.append('five-section before/after recovery audit missing')
    recovery = result.get('recovery') or {}
    if recovery.get('cleanup_errors'):
        failures.append('cleanup errors recorded')
    if recovery.get('final_status', {}).get('state') != 'stopped':
        failures.append('final stopped state absent')
    if result.get('scenario', {}).get('fault_class'):
        if not result.get('fault_evidence', {}).get('adjudication', {}).get('passed'):
            failures.append('fault raw-evidence adjudication absent/not pass')
        terminal = result.get('fault_evidence', {}).get('terminal_status') or {}
        if (terminal.get('state') != 'stopped' or terminal.get('last_run_outcome') != 'failed' or
                terminal.get('run_id') is not None or terminal.get('controller') is not None):
            failures.append('fault terminal stopped/failed/unlocked state absent')
        recovery_cycle = result.get('fault_evidence', {}).get('recovery_cycle') or {}
        if (recovery_cycle.get('started', {}).get('state') != 'healthy' or
                len(recovery_cycle.get('health_samples', [])) != 3 or
                recovery_cycle.get('stopped', {}).get('state') != 'stopped'):
            failures.append('fault distinct healthy recovery cycle missing')
    else:
        health = result.get('health_trace', {}).get('samples') or []
        if len(health) != 3 or not all(item.get('status', {}).get('state') == 'healthy' for item in health):
            failures.append('continuous healthy trace missing')
        if recovery.get('final_status', {}).get('last_run_outcome') != 'ok':
            failures.append('benign final outcome is not ok')
    return failures


def fault_recheck_issues(result: dict[str, Any], root: Path) -> list[str]:
    """Rebuild and assess a fault case from its recorded raw originals."""
    if not result.get('scenario', {}).get('fault_class'):
        return []
    root = root.resolve()
    try:
        adjudication = result.get('fault_evidence', {}).get('adjudication') or {}
        descriptor = adjudication.get('descriptor') or {}
        path = (root / str(descriptor['path'])).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError('fault descriptor missing/escaping')
        raw = path.read_bytes()
        if len(raw) != int(descriptor['size']) or hashlib.sha256(raw).hexdigest() != descriptor['sha256']:
            raise ValueError('fault descriptor bytes differ')
        adapter_spec = importlib.util.spec_from_file_location('scenario_fault_recheck_adapter',
                                                               Path(__file__).with_name('scenario_fault_evidence.py'))
        oracle_spec = importlib.util.spec_from_file_location('scenario_fault_recheck_oracle',
                                                              Path(__file__).with_name('sst_fault_evidence.py'))
        if not adapter_spec or not adapter_spec.loader or not oracle_spec or not oracle_spec.loader:
            raise ValueError('fault recheck modules unavailable')
        adapter = importlib.util.module_from_spec(adapter_spec)
        oracle = importlib.util.module_from_spec(oracle_spec)
        adapter_spec.loader.exec_module(adapter)
        oracle_spec.loader.exec_module(oracle)
        capture = json.loads(raw)
        case = adapter.build_case(root, capture)
        verdict = oracle.assess(case, root, capture['candidate_id'])
        if not verdict.get('passed'):
            return ['fault raw-evidence re-adjudication failed']
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return ['fault raw-evidence re-adjudication failed: ' + str(exc)]
    return []


def actual_coverage(manifest: dict[str, Any], records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(records)
    result_by_id = {row.get('scenario_id'): row for row in rows}
    tool_ids = {tool: set() for tool in TOOLS}
    bucket = {key: 0 for key in BUCKET_COUNTS}
    faults = {key: 0 for key in FAULTS}
    passed = failed = blocked = 0
    problems: list[str] = []
    ids = [row.get('scenario_id') for row in rows]
    duplicates = {item for item in ids if isinstance(item, str) and ids.count(item) > 1}
    for sid in sorted(duplicates):
        problems.append('duplicate actual scenario id: ' + sid)
    planned_ids = {row['scenario_id'] for row in manifest['scenarios']}
    for sid in sorted({item for item in ids if isinstance(item, str)} - planned_ids):
        problems.append('extra actual scenario: ' + sid)
    for planned in manifest['scenarios']:
        sid = planned['scenario_id']
        row = result_by_id.get(sid)
        if not row:
            problems.append('missing actual scenario: ' + sid)
            continue
        state = row.get('state')
        if state == 'pass':
            passed += 1
        elif state == 'blocked':
            blocked += 1
        else:
            failed += 1
        if row.get('scenario') != planned:
            problems.append('actual plan differs: ' + sid)
        expected_calls = [(item.get('tool'), item.get('expect'))
                          for item in planned.get('interface_call_plan', [])]
        observed_calls = [(item.get('tool'), item.get('expect'))
                          for item in row.get('interface_calls', [])]
        if observed_calls != expected_calls:
            problems.append('actual call plan differs: ' + sid)
        bucket[planned['config_profile']['bucket']] += 1
        if planned['fault_class']:
            faults[planned['fault_class']] += 1
        for call in row.get('interface_calls', []):
            if call.get('ok') and call.get('tool') in tool_ids:
                tool_ids[call['tool']].add(sid)
    tool_counts = {tool: len(ids) for tool, ids in tool_ids.items()}
    for tool, amount in tool_counts.items():
        if amount < 5:
            problems.append('actual tool coverage below five: ' + tool)
    if bucket['B1'] < 25 or bucket['B2'] < 15 or bucket['B3'] < 15 or bucket['B4'] < 15 or bucket['default'] > 15:
        problems.append('actual bucket distribution invalid')
    if sum(faults.values()) != 15 or any(amount != 3 for amount in faults.values()):
        problems.append('actual fault distribution invalid')
    return {'schema': COVERAGE_SCHEMA, 'kind': 'actual', 'scenario_count': len(rows),
            'pass': passed, 'fail': failed, 'blocked': blocked, 'bucket': bucket,
            'fault': faults, 'tool_distinct_scenarios': tool_counts,
            'problems': problems}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('generate', 'preflight', 'run', 'resume', 'fault-spike', 'verify', 'summary'))
    parser.add_argument('--target-base-url')
    parser.add_argument('--win10vm-mcp')
    parser.add_argument('--suite-root', default=str(DEFAULT_SUITE_ROOT))
    parser.add_argument('--candidate-id', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--package-manifest')
    parser.add_argument('--package-verification')
    parser.add_argument('--deployment-record')
    parser.add_argument('--seed', type=int, default=20260912)
    parser.add_argument('--count', type=int, default=100)
    parser.add_argument('--regen-check', action='store_true')
    parser.add_argument('--preflight-through', choices=('P4', 'P7'), default='P7')
    # Capture capacity setting only (not a scenario dimension): the two
    # values already exercised by the master's capacity contrast runs.
    parser.add_argument('--pktmon-file-size-mib', type=int, choices=(128, 1024),
                        default=128)
    parser.add_argument('--filter', choices=('benign', 'fault'))
    parser.add_argument('--fault-spike-result')
    parser.add_argument('--stop-on-first-failure', action='store_true')
    parser.add_argument('--integrity', action='store_true')
    parser.add_argument('--replay-dry-run')
    args = parser.parse_args(argv)
    if args.command == 'run' and not args.filter:
        parser.error('run requires --filter benign|fault')
    if args.command == 'verify' and not (args.integrity or args.replay_dry_run):
        parser.error('verify requires --integrity and/or --replay-dry-run')
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    suite = Suite(args)
    try:
        if args.command == 'generate':
            result = suite.generate()
        elif args.command == 'preflight':
            result = suite.preflight()
        elif args.command == 'run':
            result = suite.run(args.filter)
        elif args.command == 'resume':
            result = suite.resume()
        elif args.command == 'fault-spike':
            result = suite.fault_spike()
        elif args.command == 'verify':
            result = suite.verify(args.replay_dry_run)
        else:
            result = suite.summary()
    except Blocked as exc:
        result = {'output_dir': str(suite.root), 'passed': False, 'blocked': True,
                  'reason': str(exc)}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return EXIT_BLOCKED
    except (SuiteError, OSError, ValueError) as exc:
        result = {'output_dir': str(suite.root), 'passed': False, 'blocked': False,
                  'reason': str(exc)}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return EXIT_FAIL
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return EXIT_PASS if result.get('passed') else EXIT_FAIL


if __name__ == '__main__':
    raise SystemExit(main())
