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
import ntpath
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
import zipfile
import xml.etree.ElementTree as ET
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
from scenario_qpc_contract import MODE as QPC_MODE

AUX_QPC_MODE = 'native-qpc-zero-tcb-v1'
AUX_QPC_V2_MODE = 'native-qpc-zero-tcb-single-pass-v2'
AUX_QPC_MODES = (AUX_QPC_MODE, AUX_QPC_V2_MODE)
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
# Shared all-components capture covers two runs. PktMon text can expand well
# beyond its ETL (R55: 213,867,814 bytes from 78,303,357 bytes). Keep this
# separate from the bound for arbitrary guest evidence and QPC ZIP members.
MAX_SHARED_PKTMON_TEXT_TRANSFER = 512 * 1024 * 1024
# R55's complete auxiliary v2 export is 221,311,163 compressed bytes and
# 2,076,097,607 expanded bytes. This exception belongs only to that program.
MAX_AUX_V2_ZIP_TRANSFER = 256 * 1024 * 1024
MAX_AUX_V2_MEMBER = 1024 * 1024 * 1024
MAX_AUX_V2_EXPANDED = 3 * 1024 * 1024 * 1024
QPC_EXPORT_WAIT_SECONDS = 600
QPC_EXPORT_RPC_SECONDS = 900
GUEST_ROOT = r'C:\ProgramData\FakeNet-NG-MCP\logs'
E_GUEST_WORK_ROOT = r'E:\FakeNet-NG-MCP-test-work'
CAPTURE_CONTRACTS = ('per-run-v1', 'scenario-shared-v2')
PKTMON_MODULE = Path(__file__).with_name('scenario_pktmon.py')
NIC_CAPTURE_SCHEMA = 'fakenetng.mcp-scenario-pktmon-nic.v1'


class SuiteError(RuntimeError):
    """A scenario failure whose evidence must be retained."""


class VmCommandError(SuiteError):
    """A VM command failure retaining its complete wire response."""

    def __init__(self, message: str, record: dict[str, Any]):
        super().__init__(message)
        self.record = record


class Blocked(SuiteError):
    """A precondition cannot be proved; callers must not continue."""


class UnsettledCaptureStart(SuiteError):
    """A probe may still own a socket; retain the physical writer."""


class UnsettledCaptureStop(SuiteError):
    """A probe/kernel close is unproved; retain the physical writer."""


class RecoveredCaptureStart(SuiteError):
    """An unknown start was reconciled and its exact writer was closed."""

    def __init__(self, record: dict[str, Any]):
        super().__init__('capture start response lost; exact writer recovered')
        self.record = record


def extract_qpc_archive(output_zip: Path, destination: Path, evidence,
                        *, auxiliary_v2: bool = False) -> None:
    """Extract complete native views under separate member and aggregate limits.

    A diagnostic export contains raw, default-clock and paired full-event views.
    Each member retains the single-transfer limit; the aggregate allows those
    three views plus one limit's worth of metadata (768 MiB at current settings).
    Validate every header before creating files, then let ZipFile verify CRCs.
    """
    member_limit = MAX_AUX_V2_MEMBER if auxiliary_v2 else MAX_GUEST_TRANSFER
    total_limit = MAX_AUX_V2_EXPANDED if auxiliary_v2 else 4 * MAX_GUEST_TRANSFER
    stage = destination.with_name(destination.name + '.extract-' + uuid.uuid4().hex)
    if auxiliary_v2 and output_zip.stat().st_size > MAX_AUX_V2_ZIP_TRANSFER:
        raise SuiteError('QPC native output ZIP exceeds transfer bound')
    if auxiliary_v2 and destination.exists():
        raise SuiteError('QPC native output destination collision')
    with zipfile.ZipFile(output_zip) as archive:
        members = archive.infolist()
        if len(members) > 128:
            raise SuiteError('QPC output archive has too many members')
        total, targets, folded = 0, {}, set()
        for member in members:
            relative = Path(member.filename)
            target = (destination / relative).resolve()
            if (relative.is_absolute() or '..' in relative.parts or
                    '\\' in member.filename or ':' in member.filename or
                    not member.filename or '\x00' in member.filename or
                    (auxiliary_v2 and relative.as_posix().rstrip('/') !=
                     member.filename.rstrip('/')) or
                    not target.is_relative_to(destination.resolve()) or
                    target in targets or (auxiliary_v2 and
                    member.filename.casefold() in folded) or target.exists() or
                    (member.external_attr >> 16) & 0o170000 == 0o120000 or
                    not 0 <= member.file_size <= member_limit):
                raise SuiteError('QPC output archive path or size invalid')
            folded.add(member.filename.casefold())
            if member.is_dir():
                continue
            total += member.file_size
            if total > total_limit:
                raise SuiteError('QPC output archive exceeds expanded bound')
            targets[target] = member
        if not auxiliary_v2:
            for target, member in targets.items():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream, archive.open(member) as source:
                    shutil.copyfileobj(source, stream, 1024 * 1024)
                evidence.add(target)
            return
        stage.mkdir(parents=True, exist_ok=False)
        try:
            for target, member in targets.items():
                staged = stage / target.relative_to(destination)
                staged.parent.mkdir(parents=True, exist_ok=True)
                with staged.open('xb') as stream, archive.open(member) as source:
                    shutil.copyfileobj(source, stream, 1024 * 1024)
                if staged.stat().st_size != member.file_size:
                    raise SuiteError('QPC output archive member short extraction')
            os.replace(stage, destination)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        for target in targets:
            evidence.add(target)


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


def lifecycle_rpc_timeout(tool: str) -> int:
    """Cover 420s server stop + 5s settle + 480s start with 55s margin."""
    return 960 if tool == 'restart' else 480 if tool in ('start', 'stop') else 120


def reconcile_timed_out_command(service: Any, command_id: str, operation: str,
                                controller_id: str, budget_seconds: float = 120) -> dict[str, Any]:
    """Observe the original command only; never resubmit an ambiguous mutation."""
    deadline = time.monotonic() + budget_seconds
    samples: list[dict[str, Any]] = []
    while True:
        sample: dict[str, Any] = {'at': utc_now()}
        try:
            events = service.tool('get_events', {'limit': 500}, timeout=15)['events']
            status = service.tool('get_status', timeout=15)
            sample['status'] = status
            accepted = any(e.get('kind') == 'command.accepted' and
                           e.get('command_id') == command_id and
                           e.get('operation') == operation and
                           e.get('controller') == controller_id for e in events)
            terminal = next((e for e in reversed(events)
                             if e.get('kind') in ('command.completed', 'command.failed') and
                             e.get('command_id') == command_id and
                             e.get('operation') == operation), None)
            sample['accepted'] = accepted
            sample['terminal_event'] = terminal
            terminal_status_ok = (isinstance(status, dict) and
                                  status.get('state') in ('healthy', 'stopped', 'failed') and
                                  status.get('controller') in (None, controller_id))
            sample['terminal_status_ok'] = terminal_status_ok
            samples.append(sample)
            if accepted and terminal is not None and terminal_status_ok:
                return {'settled': True, 'command_id': command_id,
                        'operation': operation, 'samples': samples}
        except Exception as exc:  # read-only observation may itself be unavailable
            sample['read_error'] = repr(exc)
            samples.append(sample)
        if time.monotonic() >= deadline:
            return {'settled': False, 'command_id': command_id,
                    'operation': operation, 'samples': samples}
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def file_record(path: Path, root: Path | None = None) -> dict[str, Any]:
    size = path.stat().st_size
    hashed = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hashed.update(block)
    return {'path': path.relative_to(root).as_posix() if root else str(path),
            'size': size, 'sha256': hashed.hexdigest()}


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
            raise VmCommandError('VM PowerShell failed: ' + raw[-800:], record)
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


def p7_capture_begin(suite_root: Path, scenario_id: str, attempt: int) -> Path | None:
    """Optional bounded rendezvous; an external owner starts pktmon before P7 start."""
    location = os.environ.get('SST_P7_CAPTURE_CONTROL_DIR')
    if not location:
        return None
    control = Path(location)
    if not control.is_dir():
        raise SuiteError('P7 capture control directory absent')
    write_p7_control(control / 'request.json', {
        'suite_root': str(suite_root), 'scenario_id': scenario_id,
        'attempt': attempt, 'requested_at': utc_now()})
    deadline = time.monotonic() + 90
    while not (control / 'ack.json').is_file():
        if time.monotonic() >= deadline:
            raise SuiteError('P7 capture start acknowledgement timed out')
        time.sleep(0.05)
    ack = read_json(control / 'ack.json')
    if (ack.get('status') != 'ready' or not ack.get('owner') or
            not ack.get('etl') or not ack.get('started')):
        raise SuiteError('P7 capture start failed: ' + repr(ack))
    return control


def p7_capture_end(control: Path | None, run_id: str | None,
                   probe: dict[str, Any] | None, cleanup: dict[str, Any]) -> None:
    if control is not None:
        write_p7_control(control / 'done.json', {
            'run_id': run_id, 'probe_started_at': (probe or {}).get('started_at'),
            'probe_ended_at': (probe or {}).get('ended_at'),
            'cleanup': cleanup, 'completed_at': utc_now()})


def write_p7_control(path: Path, value: dict[str, Any]) -> None:
    """Publish a complete JSON rendezvous record without replacing old evidence."""
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    try:
        temporary.write_bytes(canonical_bytes(value))
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
    native_clock_diagnostic = False
    guest_work_root = GUEST_ROOT
    capture_contract = 'per-run-v1'
    # The two pktmon file-size values already exercised by the master's
    # capacity contrast.  Validated here so directly-constructed Namespace
    # objects (offline callers) also obey the same contract; the default
    # keeps existing behavior.  Nothing VM-facing runs before this check.
    PKTMON_FILE_SIZE_MIB_CHOICES = (128, 1024)

    @staticmethod
    def _pktmon_stopped(status: Any) -> bool:
        return isinstance(status, str) and bool(re.search(
            r'\b(?:stopped|not\s+running)\b|数据包监视器没有运行',
            status, re.IGNORECASE))

    @classmethod
    def _pktmon_running(cls, status: Any) -> bool:
        return isinstance(status, str) and not cls._pktmon_stopped(status) and bool(
            re.search(r'\brunning\b|正在运行', status, re.IGNORECASE))

    @staticmethod
    def _shared_pktmon_owner_active(status: Any, exit_code: Any, etl: str) -> bool:
        """Accept only one complete active status bound to the exact owner ETL."""
        if not isinstance(status, str) or exit_code != 0 or not isinstance(etl, str):
            return False
        if re.search(r'数据包监视器没有运行|\bnot\s+running\b|\bstopped\b',
                     status, re.IGNORECASE):
            return False
        lines = [line.strip() for line in status.splitlines() if line.strip()]
        if not lines or not re.fullmatch(r'收集的数据:|Collected data:', lines[0], re.I):
            return False

        def values(label: str) -> list[str]:
            return [match.group(1).strip() for match in
                    re.finditer(r'^[ \t]*(?:' + label + r')[ \t]*:[ \t]*(.*?)[ \t]*$',
                                status, re.I | re.M)]

        data = values(r'收集的数据|Collected data')
        capture = values(r'捕获类型|Capture type')
        logging = values(r'记录程序参数|Logging parameters')
        logger = values(r'记录程序名称|Logger name')
        files = values(r'日志文件|Log file')
        max_size = values(r'最大文件大小|Maximum file size')
        if (len(data) != 1 or len(capture) != 1 or len(logging) != 1 or
                len(logger) != 1 or len(files) != 1 or len(max_size) != 1):
            return False
        if (not re.search(r'(?m)^[ \t]*(?:收集的数据|Collected data)[ \t]*:[ \t]*\r?\n'
                         r'[ \t]*[^\r\n]*(?:数据包捕获|packet capture)', status, re.I) or
                not re.search(r'(?m)^[ \t]*(?:捕获类型|Capture type)[ \t]*:[ \t]*\r?\n'
                              r'[ \t]*[^\r\n]*(?:所有数据包|all packets)', status, re.I) or
                logger[0].casefold() != 'pktmon' or
                not re.fullmatch(r'\d+\s*MB', max_size[0], re.I)):
            return False
        # Status values are absolute Windows paths, never prefixes or substrings.
        if not all(re.match(r'^[A-Za-z]:[\\/]', path) for path in (files[0], etl)):
            return False
        return ntpath.normcase(ntpath.normpath(files[0])) == ntpath.normcase(ntpath.normpath(etl))

    @staticmethod
    def _shared_pktmon_owner_gate_ps() -> str:
        """Pure PowerShell 5.1 twin of the offline status/owner predicate."""
        return (
            "function Test-SharedPktMonOwner([string]$text,[int]$exitCode,[string]$ownerEtl){"
            "if($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($text) -or "
            "[string]::IsNullOrWhiteSpace($ownerEtl)){return $false};"
            "if($text -match '数据包监视器没有运行|(?i:not\\s+running|\\bstopped\\b)'){return $false};"
            "$lines=@($text -split '\\r?\\n'|ForEach-Object{$_.Trim()}|Where-Object{$_});"
            "if($lines.Count -eq 0 -or $lines[0] -notmatch '^(收集的数据|Collected data):$'){return $false};"
            "$data=@([regex]::Matches($text,'(?im)^[ \\t]*(收集的数据|Collected data)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "$capture=@([regex]::Matches($text,'(?im)^[ \\t]*(捕获类型|Capture type)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "$logging=@([regex]::Matches($text,'(?im)^[ \\t]*(记录程序参数|Logging parameters)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "$logger=@([regex]::Matches($text,'(?im)^[ \\t]*(记录程序名称|Logger name)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "$files=@([regex]::Matches($text,'(?im)^[ \\t]*(日志文件|Log file)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "$max=@([regex]::Matches($text,'(?im)^[ \\t]*(最大文件大小|Maximum file size)[ \\t]*:[ \\t]*(.*?)[ \\t]*$'));"
            "if($data.Count -ne 1 -or $capture.Count -ne 1 -or $logging.Count -ne 1 -or "
            "$logger.Count -ne 1 -or $files.Count -ne 1 -or $max.Count -ne 1){return $false};"
            "if($text -notmatch '(?im)^[ \\t]*(收集的数据|Collected data)[ \\t]*:[ \\t]*\\r?\\n[ \\t]*[^\\r\\n]*(数据包捕获|packet capture)' -or "
            "$text -notmatch '(?im)^[ \\t]*(捕获类型|Capture type)[ \\t]*:[ \\t]*\\r?\\n[ \\t]*[^\\r\\n]*(所有数据包|all packets)' -or "
            "$logger[0].Groups[2].Value.Trim() -ine 'PktMon' -or "
            "$max[0].Groups[2].Value.Trim() -notmatch '^(?i:\\d+\\s*MB)$'){return $false};"
            "$actual=$files[0].Groups[2].Value.Trim();"
            "if($actual -notmatch '^[A-Za-z]:[\\\\/]' -or "
            "$ownerEtl -notmatch '^[A-Za-z]:[\\\\/]'){return $false};"
            "try{$a=[IO.Path]::GetFullPath($actual.Replace('/','\\'));"
            "$b=[IO.Path]::GetFullPath($ownerEtl.Replace('/','\\'));"
            "return [string]::Equals($a,$b,[StringComparison]::OrdinalIgnoreCase)}"
            "catch{return $false}};"
        )

    @staticmethod
    def _tool_identity() -> dict[str, Any]:
        """Freeze the complete acceptance tool source set for a new suite root."""
        directory = Path(__file__).resolve().parent
        files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(directory.iterdir())
                 if path.is_file() and path.suffix in ('.py', '.ps1')}
        return {'schema': 'sst.acceptance-tool-set.v1', 'files': files,
                'sha256': digest(files)}

    def __init__(self, args: argparse.Namespace):
        file_size = getattr(args, 'pktmon_file_size_mib', 128)
        if (isinstance(file_size, bool) or not isinstance(file_size, int)
                or file_size not in self.PKTMON_FILE_SIZE_MIB_CHOICES):
            raise SuiteError('pktmon file size must be one of %r, got %r'
                             % (self.PKTMON_FILE_SIZE_MIB_CHOICES, file_size))
        self.args = args
        self.pktmon_file_size_mib = file_size
        self.capture_contract = getattr(args, 'capture_contract', 'per-run-v1')
        if self.capture_contract not in CAPTURE_CONTRACTS:
            raise SuiteError('unsupported capture contract')
        self.guest_work_root = getattr(args, 'guest_work_root', GUEST_ROOT)
        if self.guest_work_root not in (GUEST_ROOT, E_GUEST_WORK_ROOT):
            raise SuiteError('guest work root must be the frozen C or E absolute local root')
        self.fault_clock_evidence = getattr(args, 'fault_clock_evidence', 'utc-v2')
        if self.fault_clock_evidence not in ('utc-v2', QPC_MODE):
            raise SuiteError('unsupported fault clock evidence mode')
        self.auxiliary_clock_evidence = getattr(args, 'auxiliary_clock_evidence', 'utc-v1')
        if self.auxiliary_clock_evidence not in ('utc-v1', *AUX_QPC_MODES):
            raise SuiteError('unsupported auxiliary clock evidence mode')
        self.requested_native_clock_diagnostic = bool(getattr(args, 'native_clock_diagnostic', False))
        self.native_clock_diagnostic = self.requested_native_clock_diagnostic
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
            failure = SuiteError('expected VM JSON: ' + raw['output'][:500])
            failure.vm_record = raw
            raise failure from exc
        if not isinstance(value, dict):
            failure = SuiteError('expected VM JSON object')
            failure.vm_record = raw
            raise failure
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
        result = self.service.tool(name, args, timeout=lifecycle_rpc_timeout(name))
        if result.get('error'):
            raise SuiteError('%s rejected: %s' % (name, result['error']))
        return result

    def _stage_probe(self) -> dict[str, Any]:
        assert self.vm
        script = (Path(__file__).with_name('scenario_probes.ps1')).read_bytes()
        guest = self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1'
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

    def _guest_work_root_gate(self) -> dict[str, Any]:
        """Read only: bind the selected drive and reject reparse ancestors."""
        root = self.guest_work_root
        command = (
            "$ErrorActionPreference='Stop';$r=" + quote_ps(root) + ";"
            "$parts=@();$p=$r;while($p){$parts+=,$p;$parent=Split-Path -Parent $p;"
            "if(!$parent -or $parent -eq $p){break};$p=$parent};"
            "$existing=@();foreach($part in $parts){if(Test-Path -LiteralPath $part){"
            "$item=Get-Item -LiteralPath $part -Force;"
            "if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw ('reparse work root: '+$part)};"
            "$existing+=@{path=$part;full=$item.FullName}}};"
            "$c=(Get-PSDrive C).Free;$e=$null;$eType=$null;"
            + ("$e=(Get-PSDrive E).Free;$eType=(Get-CimInstance Win32_LogicalDisk "
               "-Filter \"DeviceID='E:'\").DriveType;" if root == E_GUEST_WORK_ROOT else '') +
            "@{computer=$env:COMPUTERNAME;root=$r;existing=$existing;c_free=$c;e_free=$e;e_drive_type=$eType;"
            "utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5 -Compress")
        value, raw = self._vm_json(command, 60)
        if (value.get('computer') != 'DESKTOP-3FI41GR' or value.get('root') != root or
                type(value.get('c_free')) is not int or value['c_free'] < 2 * 2**30 or
                (root == E_GUEST_WORK_ROOT and
                 (type(value.get('e_free')) is not int or value['e_free'] < 3 * 2**30 or
                  value.get('e_drive_type') != 3))):
            raise Blocked('guest work root identity or C/E space gate failed')
        return {'value': value, 'raw': raw}

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
            work_root = check('P1-guest-work-root', self._guest_work_root_gate)
            evidence.write('p1-guest-work-root.json', work_root)
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
                          'guest_work_root': self.guest_work_root, 'capture_contract': self.capture_contract,
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
            p7 = check('P7-deepseek-relay', lambda: self._preflight_b1(b1, 'preflight-b1', 1,
                                                                       evidence))
            evidence.write('p7-deepseek-relay.json', p7)
        except Exception:
            result = {'schema': SCHEMA + '.preflight.v1', 'identity': self.identity.as_dict(),
                      'guest_work_root': self.guest_work_root, 'capture_contract': self.capture_contract,
                      'tool_identity': self._tool_identity(),
                      'passed': False, 'checks': checks, 'evidence': evidence.items,
                      'created_at': utc_now()}
            if not self.preflight_path.exists():
                write_new_json(self.preflight_path, result)
            raise Blocked('preflight failed; no scenario may start')
        result = {'schema': SCHEMA + '.preflight.v1', 'identity': self.identity.as_dict(),
                  'guest_work_root': self.guest_work_root, 'capture_contract': self.capture_contract,
                  'tool_identity': self._tool_identity(),
                  'passed': True, 'checks': checks, 'evidence': evidence.items,
                  'external_dns_server': route['external_dns_server'], 'api_ipv4': route['api_ipv4'],
                  'created_at': utc_now()}
        if self.preflight_path.exists():
            old = read_json(self.preflight_path)
            if (old.get('identity') != result['identity'] or not old.get('passed') or
                    old.get('guest_work_root', GUEST_ROOT) != self.guest_work_root or
                    old.get('capture_contract', 'per-run-v1') != self.capture_contract or
                    ((self.capture_contract == 'scenario-shared-v2' or
                      self.guest_work_root == E_GUEST_WORK_ROOT) and
                     old.get('tool_identity') != result['tool_identity'])):
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

    def _preflight_b1(self, content: str, scenario_id: str, attempt: int,
                      evidence: Evidence) -> dict[str, Any]:
        assert self.vm
        name = 'sst-preflight-b1.ini'
        created = self._mutate(scenario_id, attempt, 10, 'create_config',
                               {'name': name, 'content': content})
        result = None
        failure = None
        cleanup: dict[str, Any] = {'actions': [], 'errors': []}
        capture_control = None
        started = None
        probe = None
        try:
            loaded = self._mutate(scenario_id, attempt, 11, 'load_config', {'name': name})
            capture_control = p7_capture_begin(self.root, scenario_id, attempt)
            started = self._mutate(scenario_id, attempt, 12, 'start', {})
            if started.get('state') != 'healthy':
                raise SuiteError('B1 did not start healthy')
            command = ("$ErrorActionPreference='Stop';$p=" +
                       quote_ps(self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1') +
                       ";$n='preflight-'+[guid]::NewGuid().ToString();" +
                       "& $p -Action preflight-b1 -Nonce $n")
            try:
                probe, raw = self._vm_json(command, 60)
            except Exception as exc:
                evidence.write('p7-probe-wire.json', {
                    'run_id': started.get('run_id'), 'command': command,
                    'error': repr(exc),
                    'vm_record': getattr(exc, 'record', getattr(exc, 'vm_record', None))})
                raise
            evidence.write('p7-probe-wire.json', {
                'run_id': started.get('run_id'), 'command': command,
                'probe': probe, 'vm_record': raw})
            for stream_name in ('stdout', 'stderr'):
                guest_path = probe.get(stream_name + '_path')
                size = probe.get(stream_name + '_size')
                sha256 = probe.get(stream_name + '_sha256')
                if not guest_path or type(size) is not int or not sha256 or size > 1024 * 1024:
                    raise SuiteError('B1 curl %s original unavailable or over 1 MiB' % stream_name)
                destination = evidence.root / ('p7-curl.' + stream_name + '.raw')
                self._transfer_guest_file(guest_path, size, sha256, destination)
                evidence.add(destination)
            if (probe.get('exit_code') != 0 or probe.get('actual_curl_exit') != 0 or
                    probe.get('native_error') or
                    not probe.get('nonce') or not probe.get('url') or
                    probe.get('http_code') in ('', '000')):
                raise SuiteError('B1 relay preflight failed')
            result = {'created': created, 'loaded': loaded, 'started': started,
                      'probe': probe, 'probe_raw': raw}
        except Exception as exc:
            failure = exc
        finally:
            try:
                status = self._status()
                cleanup['before'] = status
                if status.get('state') != 'stopped':
                    owner = status.get('controller')
                    if owner and owner != self.service.controller_id:
                        raise SuiteError('B1 cleanup found another controller')
                    cleanup['actions'].append({'stop': self._mutate(scenario_id, attempt, 14,
                                                                     'stop', {})})
            except Exception as exc:
                cleanup['errors'].append('stop: ' + repr(exc))
            try:
                status = self._status()
                if status.get('state') != 'stopped' or status.get('run_id') or status.get('controller'):
                    raise SuiteError('B1 cleanup did not reach owner-free stopped')
                if (status.get('config_identity') or {}).get('name') != 'default.ini':
                    cleanup['actions'].append({'load_default': self._mutate(
                        scenario_id, attempt, 15, 'load_config', {'name': 'default.ini'})})
            except Exception as exc:
                cleanup['errors'].append('default: ' + repr(exc))
            try:
                status = self._status()
                if (status.get('state') != 'stopped' or status.get('run_id') or
                        status.get('controller') or
                        (status.get('config_identity') or {}).get('name') != 'default.ini'):
                    raise SuiteError('B1 config still active; deletion withheld')
                current = self.service.tool('read_config', {'name': name})
                if current.get('error') or not current.get('sha256'):
                    raise SuiteError('B1 temporary config could not be read for deletion')
                cleanup['actions'].append({'delete': self._mutate(
                    scenario_id, attempt, 16, 'delete_config',
                    {'name': name, 'expected_sha256': current['sha256']})})
            except Exception as exc:
                cleanup['errors'].append('delete: ' + repr(exc))
            try:
                cleanup['final'] = self._status()
            except Exception as exc:
                cleanup['errors'].append('final-status: ' + repr(exc))
            try:
                p7_capture_end(capture_control, (started or {}).get('run_id'), probe, cleanup)
            except Exception as exc:
                cleanup['errors'].append('capture-done: ' + repr(exc))
            evidence.write('p7-cleanup.json', cleanup)
        if cleanup['errors']:
            raise SuiteError('B1 cleanup failed: ' + '; '.join(cleanup['errors']) +
                             ('; probe: ' + repr(failure) if failure else '')) from failure
        if failure:
            raise failure
        result['cleanup'] = cleanup
        return result

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
        if (result.get('guest_work_root', GUEST_ROOT) != self.guest_work_root or
                result.get('capture_contract', 'per-run-v1') != self.capture_contract):
            raise Blocked('preflight work root/capture contract differs')
        if ((self.capture_contract == 'scenario-shared-v2' or
             self.guest_work_root == E_GUEST_WORK_ROOT) and
                result.get('tool_identity') != self._tool_identity()):
            raise Blocked('preflight tool source identity differs')
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
        for owner in (self.root / 'evidence').rglob('qpc-process-responsibility.json'):
            terminal = owner.with_name('qpc-process-terminal.json')
            if not terminal.is_file():
                raise Blocked('QPC diagnostic process responsibility remains unsettled: ' + str(owner))
            state = read_json(terminal)
            responsibility = read_json(owner)
            if (state.get('schema') != 'sst.qpc-host-process-terminal.v1' or
                    state.get('run_id') != responsibility.get('run_id') or
                    state.get('guest_root') != responsibility.get('guest_root') or
                    state.get('input_sha256') != responsibility.get('input_sha256') or
                    state.get('exit_proven') is not True):
                raise Blocked('QPC diagnostic process exit is unproven: ' + str(terminal))
        status = self._status()
        if status.get('state') != 'stopped' or status.get('run_id'):
            raise Blocked('managed service is not stopped before scenario')
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$fault='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json';"
            "$probe=@(Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {$_.Path -and $_.Path -like '*scenario*'});"
            "$pkt=(pktmon status | Out-String);@{fault=(Test-Path $fault);probe_count=$probe.Count;pktmon=$pkt}|ConvertTo-Json -Compress", 60)
        if (value.get('fault') or value.get('probe_count') or
                not self._pktmon_stopped(value.get('pktmon'))):
            raise Blocked('continuation gate found fault/probe/pktmon residue')
        capacity = self._guest_work_root_gate()
        return {'status': status, 'vm': value, 'raw': raw,
                'guest_work_root_capacity': capacity}

    def _guest_scenario_root(self, scenario_id: str, attempt: int) -> str:
        scope = hashlib.sha256(str(self.root.resolve()).encode()).hexdigest()[:12]
        return self.guest_work_root + '\\scenario-suite-20260912\\' + scope + '-' + scenario_id + ('-a%d' % attempt)

    def _start_kernel_capture(self, run_root: str) -> dict[str, Any]:
        session = 'SST-Kernel-' + str(uuid.uuid4())
        command = (
            "$ErrorActionPreference='Stop';$r=" + quote_ps(run_root) + ";"
            "if(Test-Path -LiteralPath $r){throw 'kernel run root collision'};"
            "$a=Split-Path -Parent $r;while($a){if(Test-Path -LiteralPath $a){"
            "$item=Get-Item -LiteralPath $a -Force;"
            "if($item.Attributes -band [IO.FileAttributes]::ReparsePoint)"
            "{throw ('reparse run ancestor: '+$a)}};"
            "$next=Split-Path -Parent $a;if(!$next -or $next -eq $a){break};$a=$next};"
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
            # logman stop can fail once with a transient WMI error ("The GUID
            # passed was not recognized as valid by a WMI data provider")
            # while the session is real and stops on the next attempt
            # (fakenet100 r09-run-19 sst-010: the stop threw, the session
            # stayed running, and the capture export lost the whole run).
            "if($session_present){for($attempt=0;$attempt -lt 3;$attempt++){if($attempt -gt 0){Start-Sleep -Seconds 2};$stop=(& logman stop $m.session_name -ets|Out-String);if($LASTEXITCODE -eq 0){break}};if($LASTEXITCODE -ne 0){throw ('kernel trace stop failed: '+$stop)}};"
            "$m|Add-Member -NotePropertyName session_present_at_stop -NotePropertyValue $session_present -Force;" +
            _sst_clock.clock_sample_ps('clock') +
            "$m|Add-Member -NotePropertyName clock_after -NotePropertyValue $clock -Force;$m|ConvertTo-Json -Depth 8|Set-Content $mp -Encoding UTF8;"
            "if(Test-Path $m.events_path){throw 'kernel conversion collision'};$writer=[IO.StreamWriter]::new($m.events_path,$false,[Text.UTF8Encoding]::new($false));"
            "$ordinal=0;try{Get-WinEvent -Path $m.etl_path -Oldest -ErrorAction Stop|ForEach-Object {$writer.WriteLine((@{ordinal=$ordinal;xml=$_.ToXml()}|ConvertTo-Json -Compress -Depth 4));$ordinal++}}finally{$writer.Dispose()};"
            "& tracerpt $m.etl_path -o $m.header_path -of XML -summary $m.summary_path -y|Out-Null;$exit=$LASTEXITCODE;"
            "$c=@{event_reader=('Get-WinEvent -Path '+$m.etl_path+' -Oldest | ForEach-Object { $_.ToXml() }');event_reader_exit_code=0;tracerpt_argv=@('tracerpt',$m.etl_path,'-o',$m.header_path,'-of','XML','-summary',$m.summary_path,'-y');tracerpt_exit_code=$exit};"
            "function Hash-Shared([string]$p){for($i=0;$i -lt 60;$i++){try{return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}catch{Start-Sleep -Milliseconds 500}};throw ('file remained shared: '+$p)};"
            "foreach($pair in @(@('etl',$m.etl_path),@('events',$m.events_path),@('header',$m.header_path),@('summary',$m.summary_path))){$c[($pair[0]+'_sha256')]=Hash-Shared $pair[1]};"
            "$m|Add-Member -NotePropertyName conversion -NotePropertyValue $c -Force;$m|ConvertTo-Json -Depth 8|Set-Content $mp -Encoding UTF8;if($exit -ne 0){throw 'kernel tracerpt failed'};"
            "@{files=@(@($m.etl_path,$m.events_path,$m.header_path,$m.summary_path,$mp)|ForEach-Object {$f=Get-Item $_;@{path=$f.FullName;bytes=$f.Length;sha256=(Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()}})}|ConvertTo-Json -Depth 5 -Compress")
        value, raw = self._vm_json(command, 120)
        return dict(files=value['files'], raw=raw)

    def _capture_start_snapshot(self, run_root: str, etl: str,
                                nonce: str, run_label: str) -> dict[str, Any]:
        """Read only snapshot after an RPC whose start response was lost."""
        command = (
            "$ErrorActionPreference='Stop';$r=" + quote_ps(run_root) + ";"
            "$out=Join-Path $r 'probe.jsonl';$ready=$null;$process=$null;"
            "$receipt=$null;$receiptPath=Join-Path $r 'probe-launch.json';"
            "if(Test-Path -LiteralPath $receiptPath -PathType Leaf){"
            "try{$receipt=Get-Content -LiteralPath $receiptPath -Raw|ConvertFrom-Json}"
            "catch{$receipt=$null}};"
            "if(Test-Path -LiteralPath $out -PathType Leaf){"
            "$line=Get-Content -LiteralPath $out -TotalCount 1;"
            "try{$ready=$line|ConvertFrom-Json}catch{$ready=$null}};"
            "$origin=if($ready){$ready}else{$receipt};"
            "if($origin -and $origin.pid){$p=Get-Process -Id ([int]$origin.pid) "
            "-ErrorAction SilentlyContinue;if($p){$process=@{pid=$p.Id;"
            "creation_ticks=$p.StartTime.ToUniversalTime().Ticks}}};"
            "$status=(& pktmon status|Out-String);"
            "@{run_root=$r;probe_ready=$ready;launch_receipt=$receipt;process=$process;"
            "etl_exists=(Test-Path -LiteralPath " + quote_ps(etl) +
            " -PathType Leaf);pktmon_status=$status;pktmon_exit=$LASTEXITCODE}"
            "|ConvertTo-Json -Depth 8 -Compress")
        try:
            value, raw = self._vm_json(command, 60)
            ready = value.get('probe_ready') or value.get('launch_receipt') or {}
            process = value.get('process') or {}
            native = ready.get('native_identity') or {}
            identity_match = (ready.get('nonce') == nonce and
                              ready.get('pid') == process.get('pid') and
                              ready.get('creation_ticks') == process.get('creation_ticks') and
                              native.get('supported') is True and
                              native.get('run_id') == nonce + ':' + run_label and
                              native.get('candidate_id') == self.identity.candidate_id)
            return {'value': value, 'raw': raw, 'identity_match': identity_match}
        except Exception as exc:
            return {'snapshot_error': repr(exc), 'run_root': run_root, 'etl': etl}

    def _reconcile_capture_start(self, snapshot: dict[str, Any], kernel: dict[str, Any],
                                 run_root: str, etl: str, nic: str, nonce: str,
                                 run_label: str, owner_id: str | None) -> dict[str, Any] | None:
        """Close only a positively identified probe, never infer from an absent reply."""
        value = snapshot.get('value') or {}
        ready = value.get('probe_ready') or value.get('launch_receipt') or {}
        status = str(value.get('pktmon_status', ''))
        if (snapshot.get('identity_match') is not True or
                value.get('etl_exists') is not True or
                not (self._shared_pktmon_owner_active(status, value.get('pktmon_exit'), etl)
                     if owner_id else
                     value.get('pktmon_exit') == 0 and self._pktmon_running(status))):
            return None
        capture = {'guest': run_root, 'run_label': run_label,
                   'pid': ready['pid'], 'probe_creation_ticks': ready['creation_ticks'],
                   'probe': run_root + r'\probe.jsonl',
                   'start': run_root + r'\probe.start',
                   'case': run_root + r'\probe.cases',
                   'stop': run_root + r'\probe.stop',
                   'stdout': run_root + r'\probe.stdout',
                   'stderr': run_root + r'\probe.stderr',
                   'etl': etl, 'pktmon_nic': nic,
                   'kernel_capture': kernel, 'capture_run_id': nonce + ':' + run_label,
                   'nonce': nonce, 'physical_owner_id': owner_id}
        if owner_id and run_label == 'run-02':
            capture['shared_physical'] = True
            capture['startup_recovery'] = not bool(value.get('probe_ready'))
        stopped = self._stop_capture_and_probe(capture)
        return {'snapshot': snapshot, 'capture': capture, 'stop': stopped}

    @staticmethod
    def _shared_start_failure_ps() -> str:
        """Fail closed while the same command still owns its launch receipt."""
        return (
            "catch{$failure=[string]$_;$errors=@();$stopOutput=$null;"
            "$probeTerminal='not-created';$physicalTerminal='not-started';"
            "$launchPidOut=$launchPid;$launchCreationOut=$launchCreation;"
            "if($probeCreateAttempted){$probeTerminal='identity-unknown';"
            "if($launchPidOut -and $launchCreationOut -gt 0){"
            "$procInfo=$null;try{$procInfo=Get-Process -Id $launchPidOut -ErrorAction SilentlyContinue}"
            "catch{$errors+=('probe query: '+[string]$_)};"
            "if(!$procInfo){$probeTerminal='exited'}else{"
            "$actual=$null;try{$actual=$procInfo.StartTime.ToUniversalTime().Ticks}"
            "catch{$errors+=('probe identity: '+[string]$_)};"
            "if($actual -eq $launchCreationOut){"
            "try{if(-not(Test-Path -LiteralPath $stop)){"
            "[IO.File]::WriteAllText($stop,'stop',[Text.UTF8Encoding]::new($false))}}"
            "catch{$errors+=('stopfile: '+[string]$_)};"
            "if($errors.Count -eq 0){$wait=[Diagnostics.Stopwatch]::StartNew();"
            "while(-not $procInfo.HasExited -and $wait.ElapsedMilliseconds -lt 30000)"
            "{Start-Sleep -Milliseconds 200};"
            "if($procInfo.HasExited){$probeTerminal='exited'}"
            "else{$probeTerminal='timeout'}}}"
            "elseif($null -ne $actual){$probeTerminal='identity-mismatch'}}}};"
            "if($captureStarted){$physicalTerminal='retained';"
            "if($probeTerminal -eq 'exited' -or $probeTerminal -eq 'not-created'){"
            "if($errors.Count -eq 0){try{$stopOutput=(& pktmon stop|Out-String);"
            "if($LASTEXITCODE -eq 0){$after=(& pktmon status|Out-String);"
            "if($LASTEXITCODE -eq 0 -and $after -match '没有运行|(?i:not running|stopped)')"
            "{$physicalTerminal='stopped'}else{$errors+='pktmon stop status uncertain'}}"
            "else{$errors+=('pktmon stop exit '+$LASTEXITCODE)}}"
            "catch{$errors+=('pktmon stop error: '+[string]$_)}}}}"
            "elseif($pktmonStartAttempted){$physicalTerminal='start-unknown'};"
            "@{startup_failed=$true;error=$failure;cooperative_errors=$errors;"
            "capture_started=$captureStarted;pktmon_start_attempted=$pktmonStartAttempted;"
            "probe_create_attempted=$probeCreateAttempted;guest=$r;"
            "cooperative_exit=$probeTerminal;physical_terminal=$physicalTerminal;"
            "probe_pid=$launchPidOut;probe_creation_ticks=$launchCreationOut;"
            "pktmon_start_output=$pktmonStart;pktmon_stop_output=$stopOutput}"
            "|ConvertTo-Json -Depth 6 -Compress}")

    def _start_capture_and_probe(self, guest: str, profile: dict[str, Any], nonce: str,
                                 run_label: str, *, exit_driven: bool = False) -> dict[str, Any]:
        """Start one independent pktmon/probe chain for exactly one run."""
        assert self.vm
        script = self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1'
        run_root = guest + '\\' + run_label
        capture_run_id = nonce + ':' + run_label
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
        if exit_driven:
            if (run_label != 'run-01' or profile['bucket'] != 'B3' or
                    profile['interleave'] != 'stop-window' or
                    profile['probe_target'].get('process_mode') != 'nonmatch' or
                    profile['probe_target']['protocol'] != 'tcp'):
                raise SuiteError('exit-driven stop is limited to run-01 B3 nonmatch TCP stop-window')
            params['ExitControlFile'] = run_root + r'\probe.managed-exit.json'
        if self.native_clock_diagnostic:
            params.update(CaptureRunId=capture_run_id,
                          CandidateId=self.identity.candidate_id,
                          DiagnosticIdentity=True)
        if (run_label == 'run-02' and profile['bucket'] in ('B3', 'B4') and
                profile['interleave'] in ('restart-window', 'during-start', 'after-healthy', 'before-start')):
            # Only this probe is released before the restart while the engine
            # is going down; it must hold its first connection until the
            # launcher's signal (sst-041/048 option A follow-up, 2026-09-29).
            params['EngineWait'] = True
        splat = ';'.join(key + '=' + ('$true' if value is True else '$false' if value is False
                                     else str(value) if isinstance(value, int) else quote_ps(value))
                         for key, value in params.items())
        child = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$parameters=@{" + splat + "};try{& " + quote_ps(script) + " @parameters 1> " + quote_ps(run_root + r'\probe.stdout') + " 2> " + quote_ps(run_root + r'\probe.stderr') + "}catch{$_|Out-File -LiteralPath " + quote_ps(run_root + r'\probe.stderr') + ";exit 1}"
        encoded_child = base64.b64encode(child.encode('utf-16le')).decode('ascii')
        command = (
            "$ErrorActionPreference='Stop';$captureStarted=$false;$pktmonStartAttempted=$false;$probeCreateAttempted=$false;$p=$null;try{$g=" + quote_ps(guest) + ";$r=Join-Path $g " + quote_ps(run_label) +
            ";foreach($n in @('probe.jsonl','probe.stop','probe.start','probe.cases','probe.managed-exit.json','pktmon.etl','pktmon-nic.json'))"
            "{if(Test-Path -LiteralPath (Join-Path $r $n)){throw ('capture file collision: '+$n)}};"
            "$etl=Join-Path $r 'pktmon.etl';$nic=Join-Path $r 'pktmon-nic.json';"
            "$list=(& pktmon list|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon list failed'};"
            # pktmon runs one capture session at a time and its stop returns
            # before the session fully tears down; a back-to-back start then
            # fails or silently never writes the ETL (fakenet100 r09-run-10
            # sst-008: run-02's pktmon.etl missing after run-01's stop).
            # Wait bounded for a quiet session before starting.
            "$quiet=[DateTime]::UtcNow.AddSeconds(15);while([DateTime]::UtcNow -lt $quiet){$running=(& pktmon status|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon status failed'};if($running -match '没有运行|(?i:not running|stopped)'){break};Start-Sleep -Milliseconds 200};"
            "if($running -notmatch '没有运行|(?i:not running|stopped)'){throw 'pktmon previous owner remains active or status unknown'};"
            "$adapters=@(Get-NetAdapter|Select-Object ifIndex,Name,InterfaceDescription,MacAddress,Status);"
            "$before=(& pktmon counters|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon counters before start failed'};" +
            _sst_clock.clock_sample_ps('clockBefore') +
            ("$identityBefore=(& " + quote_ps(script) + " -Action identity -CaptureRunId " + quote_ps(capture_run_id) +
             " -Nonce " + quote_ps(nonce) + " -CandidateId " + quote_ps(self.identity.candidate_id) +
             ")|ConvertFrom-Json;" if self.native_clock_diagnostic else '') +
            "@{capture_mode='all-components-tcpip';clock_before=$clockBefore;schema='" + NIC_CAPTURE_SCHEMA + "';captured_utc=[DateTime]::UtcNow.ToString('o');pktmon_list=$list;adapters=$adapters;pktmon_counters_before=$before" +
            (";native_identity_before=$identityBefore;capture_run_id=" + quote_ps(capture_run_id) + ";nonce=" + quote_ps(nonce) + ";candidate_id=" + quote_ps(self.identity.candidate_id) if self.native_clock_diagnostic else '') +
            "}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $nic -Encoding UTF8;"
            "$pktmonStartAttempted=$true;$pktmonStart=(& pktmon start --capture --comp all --pkt-size 0 --flags 0x1f --trace -p Microsoft-Windows-TCPIP -k 0xFF -l 4 --file-name $etl --file-size "
            + str(self.pktmon_file_size_mib) + "|Out-String);"
            "if($LASTEXITCODE -ne 0){throw 'pktmon start failed'};$captureStarted=$true;"
            # A start that returns 0 immediately after the previous session's
            # stop can silently fail to begin: no ETL ever materializes and
            # the later etl2txt finds nothing (fakenet100 r09-run-10/12
            # sst-008: run-02 pktmon.etl missing). Verify the file appears,
            # retrying the whole start once after a forced stop.
            "$etlDeadline=[DateTime]::UtcNow.AddSeconds(10);while(-not (Test-Path $etl) -and [DateTime]::UtcNow -lt $etlDeadline){Start-Sleep -Milliseconds 200};"
            + ("if(-not (Test-Path $etl)){throw 'physical owner ETL did not materialize'}"
               if self.capture_contract == 'scenario-shared-v2' else
               "if(-not (Test-Path $etl)){& pktmon stop 2>&1|Out-Null;Start-Sleep -Seconds 2;"
            "$pktmonStart=(& pktmon start --capture --comp all --pkt-size 0 --flags 0x1f --trace -p Microsoft-Windows-TCPIP -k 0xFF -l 4 --file-name $etl --file-size "
            + str(self.pktmon_file_size_mib) + "|Out-String);"
            "if($LASTEXITCODE -ne 0){throw 'pktmon retry start failed'};"
            "$etlDeadline=[DateTime]::UtcNow.AddSeconds(10);while(-not (Test-Path $etl) -and [DateTime]::UtcNow -lt $etlDeadline){Start-Sleep -Milliseconds 200};"
            "if(-not (Test-Path $etl)){throw 'pktmon etl did not materialize'}}")
            + "$out=Join-Path $r 'probe.jsonl';$start=Join-Path $r 'probe.start';$cases=Join-Path $r 'probe.cases';$stop=Join-Path $r 'probe.stop';$script=" + quote_ps(script) + ";"
            "$encoded=" + quote_ps(encoded_child) + ";"
            "$stdout=Join-Path $r 'probe.stdout';$stderr=Join-Path $r 'probe.stderr';"
            "$probeCreateAttempted=$true;$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=('powershell.exe -NoProfile -EncodedCommand '+$encoded);CurrentDirectory=$r};if($created.ReturnValue -ne 0){throw 'probe process creation failed'};$p=Get-Process -Id $created.ProcessId -ErrorAction Stop;$launchPid=$p.Id;$launchCreation=$p.StartTime.ToUniversalTime().Ticks;"
            "$deadline=[DateTime]::UtcNow.AddSeconds(20);while(!(Test-Path $out) -and -not $p.HasExited -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100};"
            "if(!(Test-Path $out) -or $p.HasExited){throw ('probe did not become ready: '+(Get-Content $stderr -Raw -ErrorAction SilentlyContinue))};"
            "$ready=Get-Content $out -TotalCount 1|ConvertFrom-Json;if($ready.event -ne 'ready' -or [int]$ready.pid -ne $p.Id -or [long]$ready.creation_ticks -ne $p.StartTime.ToUniversalTime().Ticks){throw 'probe ready identity mismatch'};"
            "@{guest=$r;run_label=" + quote_ps(run_label) + ";pid=$p.Id;etl=$etl;probe=$out;start=$start;case=$cases;stop=$stop;pktmon_nic=$nic;probe_creation_ticks=$ready.creation_ticks;stdout=$stdout;stderr=$stderr;pktmon_status_before=$running;pktmon_start_output=$pktmonStart;capture_scope='all-components';requested_file_size_mib="
            + str(self.pktmon_file_size_mib) + ";tempo=" + quote_ps(profile['tempo']) + ";cadence_ms=" + str(int(profile['cadence_ms'])) + ";startup_retry_seconds=" + str(int(profile.get('startup_retry_seconds', 70))) + ";variant=" + quote_ps(profile['variant']) + ";probe_target=" + quote_ps(json.dumps(profile['probe_target'], separators=(',', ':'))) + ";interleave=" + quote_ps(profile['interleave']) + ";exit_control=" + quote_ps(params.get('ExitControlFile', '')) + ";started=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress}" + (self._shared_start_failure_ps() if self.capture_contract == 'scenario-shared-v2' else "catch{$failure=[string]$_;$cleanup=@();$coop=$null;$err2=@();$launchPidOut=$launchPid;$launchCreationOut=$launchCreation;if($stop){try{if(-not (Test-Path $stop)){[IO.File]::WriteAllText($stop,'stop',[Text.UTF8Encoding]::new($false))}}catch{$err2+=('stopfile: '+[string]$_)}};$procInfo=$null;try{$procInfo=Get-Process -Id $launchPidOut -ErrorAction SilentlyContinue}catch{$err2+=('query: '+[string]$_)};$actualCreation=$null;try{if($null -ne $procInfo){$actualCreation=$procInfo.StartTime.ToUniversalTime().Ticks}}catch{$err2+=('identity-read: '+[string]$_)};if($null -eq $procInfo){$coop='exited'}elseif(-not $launchCreationOut -or $launchCreationOut -le 0){$coop='identity-unknown';$err2+=('identity-unknown: no launch creation recorded')}elseif($null -eq $actualCreation){$coop='identity-unknown';$err2+=('identity-unknown: process present but creation unreadable')}elseif($actualCreation -ne $launchCreationOut){$coop='identity-mismatch(new process not touched)'}else{try{$deadlineW=[Diagnostics.Stopwatch]::StartNew();while(-not $procInfo.HasExited -and $deadlineW.ElapsedMilliseconds -lt 30000){Start-Sleep -Milliseconds 200};if($procInfo.HasExited){$coop='exited'}else{$coop='timeout'}}catch{$err2+=('wait: '+[string]$_);if(-not $coop){$coop='wait-error'}}};if($captureStarted){try{$captureStop=(& pktmon stop|Out-String);if($LASTEXITCODE -ne 0){$cleanup+='pktmon stop exit '+$LASTEXITCODE}}catch{$cleanup+='pktmon stop error: '+[string]$_}}else{$cleanup+='pktmon not started; no capture cleanup owed'};@{startup_failed=$true;error=$failure;cleanup_errors=$cleanup;cooperative_errors=$err2;capture_started=$captureStarted;guest=$r;cooperative_exit=$coop;probe_pid=$launchPidOut;probe_creation_ticks=$launchCreationOut}|ConvertTo-Json -Compress}"))
        kernel = self._start_kernel_capture(run_root)
        response_received = False
        try:
            value, raw = self._vm_json(command, 60)
            response_received = True
            if value.get('startup_failed'):
                if self.capture_contract == 'scenario-shared-v2' and (
                    value.get('cooperative_exit') not in ('exited', 'not-created') or
                    value.get('physical_terminal') not in ('stopped', 'not-started') or
                    value.get('cooperative_errors')):
                    raise UnsettledCaptureStart(
                        'physical start returned with live/unknown writer: %r' %
                        dict(value, raw=raw))
                raise SuiteError('capture/probe startup failed: %r' % dict(value, raw=raw))
        except BaseException as original:
            if isinstance(original, UnsettledCaptureStart):
                raise
            if (self.capture_contract == 'scenario-shared-v2' and not response_received):
                snapshot = self._capture_start_snapshot(
                    run_root, run_root + r'\pktmon.etl', nonce, run_label)
                try:
                    recovered = self._reconcile_capture_start(
                        snapshot, kernel, run_root, run_root + r'\pktmon.etl',
                        run_root + r'\pktmon-nic.json', nonce, run_label,
                        nonce + ':pktmon')
                except Exception as recovery_error:
                    raise UnsettledCaptureStart('physical owner start/recovery uncertain: '
                        'original=%r; snapshot=%r; recovery=%r' %
                        (original, snapshot, recovery_error)) from original
                if recovered is not None:
                    raise RecoveredCaptureStart(recovered) from original
                raise UnsettledCaptureStart('physical owner start response uncertain: %r; '
                    'read-only snapshot=%r; kernel session retained=%s' %
                    (original, snapshot, kernel['session_name'])) from original
            try:
                self._stop_kernel_capture(kernel)
            except Exception as secondary:
                raise SuiteError('probe capture start failed: %r; kernel cleanup failed: %r' % (original,secondary)) from original
            raise
        value['raw'] = raw
        value['kernel_capture'] = kernel
        if self.capture_contract == 'scenario-shared-v2' and (
                value.get('guest') != run_root or value.get('run_label') != run_label or
                value.get('etl') != run_root + r'\pktmon.etl' or
                value.get('probe') != run_root + r'\probe.jsonl' or
                (exit_driven and value.get('exit_control') != params['ExitControlFile']) or
                not isinstance(value.get('pid'), int) or value['pid'] <= 0 or
                not isinstance(value.get('probe_creation_ticks'), int) or
                value['probe_creation_ticks'] <= 0):
            snapshot = self._capture_start_snapshot(
                run_root, run_root + r'\pktmon.etl', nonce, run_label)
            try:
                recovered = self._reconcile_capture_start(
                    snapshot, kernel, run_root, run_root + r'\pktmon.etl',
                    run_root + r'\pktmon-nic.json', nonce, run_label,
                    nonce + ':pktmon')
            except Exception as recovery_error:
                raise UnsettledCaptureStart('physical owner response/recovery invalid: '
                    'response=%r; snapshot=%r; recovery=%r' %
                    (value, snapshot, recovery_error)) from recovery_error
            if recovered is not None:
                raise RecoveredCaptureStart(recovered)
            raise UnsettledCaptureStart('physical owner response invalid; writer retained: '
                'response=%r snapshot=%r' % (value, snapshot))
        if self.native_clock_diagnostic:
            value['capture_run_id'] = capture_run_id
            value['nonce'] = nonce
        return value

    def _start_probe_on_shared_capture(self, guest: str, profile: dict[str, Any], nonce: str,
                                       run_label: str, owner: dict[str, Any]) -> dict[str, Any]:
        """Start this run's probe/kernel trace while retaining one pktmon owner."""
        if (owner.get('run_label') != 'run-01' or not owner.get('etl') or
                not owner.get('pktmon_nic') or owner.get('physical_owner_id') != nonce + ':pktmon'):
            raise SuiteError('shared capture owner identity incomplete')
        script = self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1'
        run_root = guest + '\\' + run_label
        capture_run_id = nonce + ':' + run_label
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
        if self.native_clock_diagnostic:
            params.update(CaptureRunId=capture_run_id, CandidateId=self.identity.candidate_id,
                          DiagnosticIdentity=True)
        if (run_label == 'run-02' and profile['bucket'] in ('B3', 'B4') and
                profile['interleave'] in ('restart-window', 'during-start', 'after-healthy', 'before-start')):
            # Only this probe is released before the restart while the engine
            # is going down; it must hold its first connection until the
            # launcher's signal (sst-041/048 option A follow-up, 2026-09-29).
            params['EngineWait'] = True
        splat = ';'.join(key + '=' + ('$true' if value is True else '$false' if value is False
                                     else str(value) if isinstance(value, int) else quote_ps(value))
                         for key, value in params.items())
        child = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$parameters=@{" + splat +
                 "};try{& " + quote_ps(script) + " @parameters 1> " + quote_ps(run_root + r'\probe.stdout') +
                 " 2> " + quote_ps(run_root + r'\probe.stderr') + "}catch{$_|Out-File -LiteralPath " +
                 quote_ps(run_root + r'\probe.stderr') + ";exit 1}")
        encoded_child = base64.b64encode(child.encode('utf-16le')).decode('ascii')
        command = (
            "$ErrorActionPreference='Stop';$r=" + quote_ps(run_root) + ";"
            "if(!(Test-Path -LiteralPath (Join-Path $r 'kernel-network.metadata.json')))"
            "{throw 'shared probe kernel root absent'};"
            "foreach($n in @('probe.jsonl','probe.stop','probe.start','probe.cases'))"
            "{if(Test-Path -LiteralPath (Join-Path $r $n)){throw ('shared probe file collision: '+$n)}};"
            "$etl=" + quote_ps(owner['etl']) + ";$nic=" + quote_ps(owner['pktmon_nic']) + ";"
            "if(!(Test-Path -LiteralPath $etl -PathType Leaf) -or !(Test-Path -LiteralPath $nic -PathType Leaf))"
            "{throw 'physical owner files absent'};"
            + self._shared_pktmon_owner_gate_ps() +
            "$status=(& pktmon status|Out-String);$statusExit=$LASTEXITCODE;"
            "if(-not(Test-SharedPktMonOwner $status $statusExit $etl))"
            "{throw 'physical pktmon owner not running'};"
            "$encoded=" + quote_ps(encoded_child) + ";"
            "$out=Join-Path $r 'probe.jsonl';$start=Join-Path $r 'probe.start';"
            "$cases=Join-Path $r 'probe.cases';$stop=Join-Path $r 'probe.stop';"
            "$stdout=Join-Path $r 'probe.stdout';$stderr=Join-Path $r 'probe.stderr';"
            "$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
            "-Arguments @{CommandLine=('powershell.exe -NoProfile -EncodedCommand '+$encoded);CurrentDirectory=$r};"
            "if($created.ReturnValue -ne 0){throw 'shared probe process creation failed'};"
            "$p=Get-Process -Id $created.ProcessId -ErrorAction Stop;"
            "$launchPid=$p.Id;$launchCreation=$p.StartTime.ToUniversalTime().Ticks;"
            "$receipt=Join-Path $r 'probe-launch.json';"
            "$native=(& " + quote_ps(script) + " -Action identity -IdentityPid $launchPid"
            " -CaptureRunId " + quote_ps(capture_run_id) +
            " -Nonce " + quote_ps(nonce) + " -CandidateId " +
            quote_ps(self.identity.candidate_id) + ")|ConvertFrom-Json;"
            "@{pid=$launchPid;creation_ticks=$launchCreation;nonce=" + quote_ps(nonce) +
            ";capture_run_id=" + quote_ps(capture_run_id) +
            ";candidate_id=" + quote_ps(self.identity.candidate_id) +
            ";native_identity=$native}|ConvertTo-Json -Depth 8"
            "|Set-Content -LiteralPath $receipt -Encoding UTF8;"
            "$deadline=[DateTime]::UtcNow.AddSeconds(20);"
            "while(!(Test-Path $out) -and -not $p.HasExited -and [DateTime]::UtcNow -lt $deadline)"
            "{Start-Sleep -Milliseconds 100};"
            "if(!(Test-Path $out) -or $p.HasExited){throw 'shared probe did not become ready'};"
            "$ready=Get-Content $out -TotalCount 1|ConvertFrom-Json;"
            "if($ready.event -ne 'ready' -or [int]$ready.pid -ne $p.Id -or "
            "[long]$ready.creation_ticks -ne $launchCreation){throw 'shared probe ready identity mismatch'};"
            "@{guest=$r;run_label=" + quote_ps(run_label) + ";pid=$p.Id;etl=$etl;probe=$out;"
            "start=$start;case=$cases;stop=$stop;pktmon_nic=$nic;probe_creation_ticks=$launchCreation;"
            "stdout=$stdout;stderr=$stderr;capture_scope='all-components';shared_physical=$true;"
            "physical_owner_id=" + quote_ps(owner['physical_owner_id']) + ";"
            "physical_status_before=$status;capture_run_id=" + quote_ps(capture_run_id) + ";"
            "nonce=" + quote_ps(nonce) + ";started=[DateTimeOffset]::UtcNow.ToString('o')}"
            "|ConvertTo-Json -Compress")
        kernel = self._start_kernel_capture(run_root)
        try:
            value, raw = self._vm_json(command, 60)
        except Exception as original:
            # The RPC can fail after creating the process. Without an exact
            # launch identity it is unsafe to close either the writer or the
            # per-run kernel trace. Preserve both for guarded reconciliation.
            snapshot = self._capture_start_snapshot(run_root, owner['etl'], nonce, run_label)
            try:
                recovered = self._reconcile_capture_start(
                    snapshot, kernel, run_root, owner['etl'], owner['pktmon_nic'],
                    nonce, run_label, owner['physical_owner_id'])
            except Exception as recovery_error:
                raise UnsettledCaptureStart('shared probe start/recovery uncertain: '
                    'original=%r; snapshot=%r; recovery=%r' %
                    (original, snapshot, recovery_error)) from original
            if recovered is not None:
                raise RecoveredCaptureStart(recovered) from original
            raise UnsettledCaptureStart('shared probe start response uncertain: %r; '
                'read-only snapshot=%r; kernel session retained: %s' %
                (original, snapshot, kernel['session_name'])) from original
        value['raw'] = raw
        value['kernel_capture'] = kernel
        if (value.get('physical_owner_id') != owner['physical_owner_id'] or
                value.get('etl') != owner['etl'] or value.get('pktmon_nic') != owner['pktmon_nic'] or
                value.get('guest') != run_root or value.get('run_label') != run_label or
                value.get('nonce') != nonce or value.get('capture_run_id') != capture_run_id or
                value.get('probe') != run_root + r'\probe.jsonl' or
                not isinstance(value.get('pid'), int) or value['pid'] <= 0 or
                not isinstance(value.get('probe_creation_ticks'), int) or
                value['probe_creation_ticks'] <= 0):
            snapshot = self._capture_start_snapshot(run_root, owner['etl'], nonce, run_label)
            try:
                recovered = self._reconcile_capture_start(
                    snapshot, kernel, run_root, owner['etl'], owner['pktmon_nic'],
                    nonce, run_label, owner['physical_owner_id'])
            except Exception as recovery_error:
                raise UnsettledCaptureStart('shared probe response/recovery identity differs: '
                    'response=%r; snapshot=%r; recovery=%r' %
                    (value, snapshot, recovery_error)) from recovery_error
            if recovered is not None:
                raise RecoveredCaptureStart(recovered)
            raise UnsettledCaptureStart('shared probe response changed physical owner; '
                'writer retained: response=%r snapshot=%r' % (value, snapshot))
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
            + ("try{$outcome.pktmon_stop=(& " + pktmon_stop_command + " 2>&1 | Out-String);$outcome.pktmon_exit=$LASTEXITCODE;if($LASTEXITCODE -ne 0){$outcome.errors+=('pktmon stop exit '+$LASTEXITCODE)}}catch{$outcome.pktmon_exit=-1;$outcome.errors+=('pktmon: '+[string]$_)}\n"
             if pktmon_stop_command else "$outcome.pktmon_stop='retained-by-scenario-owner';$outcome.pktmon_exit=$null;\n")
            + "try{$prevEap=$ErrorActionPreference;$ErrorActionPreference='Stop';$outcome|ConvertTo-Json -Depth 4 -Compress|Set-Content -LiteralPath " + quote_ps(status_path) + " -Encoding UTF8}catch{$outcome.errors+=('status-write: '+[string]$_)}finally{if($prevEap){$ErrorActionPreference=$prevEap}}\n"
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

    def _release_restart_engine(self, restarted: dict[str, Any],
                                profile: dict[str, Any], capture: dict[str, Any]) -> dict[str, Any] | None:
        """Release the same held run-02 probes selected at the launch sites."""
        if (restarted.get('state') == 'healthy' and
                profile.get('bucket') in ('B3', 'B4') and
                profile.get('interleave') in ('restart-window', 'during-start',
                                              'after-healthy', 'before-start')):
            return self._signal_engine_ok(capture)
        return None

    def _signal_engine_ok(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Release the restart-window probe's held first connection.

        The restarted engine's run.log is held open by the managed process
        and concurrent readers are refused until it exits, so the probe
        cannot observe the rule marker itself.  Write probe.engine-ok beside
        the probe's stop control once the restart RPC returned healthy: by
        then the quiescence gate has adopted the held image and the engine
        is serving, so the probe's connections are redirected, not leaked.
        """
        assert self.vm
        engine_ok = PureWindowsPath(str(capture['stop'])).with_name('probe.engine-ok')
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p=" +
            quote_ps(str(engine_ok)) + ";"
            "if(Test-Path $p){throw 'engine-ok signal already exists'};"
            "[IO.File]::WriteAllText($p,'ok',[Text.UTF8Encoding]::new($false));"
            "@{path=$p;written_utc=[DateTimeOffset]::UtcNow.ToString('o')}"
            "|ConvertTo-Json -Compress", 60)
        value['raw'] = raw
        return value

    def _pre_restart_probe_stop(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Cooperatively end run-01's probe before a restart adopts the image.

        Writes only this probe's stop control and waits (identity-bound) for
        the probe launcher to observe it; the capture stays open for its
        normal post-restart finish.  A probe that does not provably exit is a
        responsibility, not a success: its live A rows would then refuse the
        restart the scenario is trying to drive.
        """
        assert self.vm
        status_path = str(capture['probe']) + '.pre-restart-stop-status.json'
        command = self._probe_cooperative_cleanup_command(
            capture['pid'], capture.get('probe_creation_ticks'), capture['stop'],
            status_path, None, wait_seconds=30)
        value, raw = self._vm_json(command, 60)
        value['raw'] = raw
        self._fail_closed_cooperative(value, str(capture.get('label', 'run-01')))
        return value

    def _arm_managed_exit_probe(self, capture: dict[str, Any], run_id: str,
                                nonce: str) -> dict[str, Any]:
        """Bind the old managed HANDLE before releasing run-01 stop traffic."""
        if not capture.get('exit_control') or not run_id:
            raise SuiteError('managed exit observer has no owned control or run')
        creation = ('C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\' +
                    run_id + r'\creation.jsonl')
        command = (
            "$ErrorActionPreference='Stop';$rows=@(Get-Content -LiteralPath " + quote_ps(creation) +
            "|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.stage -eq 'after_api' -and $_.run_id -eq " + quote_ps(run_id) + "});"
            "if($rows.Count -ne 1 -or $null -eq $rows[0].child){throw 'managed creation identity missing or ambiguous'};"
            "$pid0=[int]$rows[0].child.pid;$created=[long]$rows[0].child.creation_time;"
            "$p=Get-Process -Id $pid0 -ErrorAction Stop;try{$handle=$p.Handle;"
            "if($p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $created -or $p.WaitForExit(0)){throw 'old managed identity changed or exited'};"
            "$value=@{run_id=" + quote_ps(run_id) + ";nonce=" + quote_ps(nonce) +
            ";pid=$pid0;creation_filetime=$created};$path=" + quote_ps(capture['exit_control']) + ";"
            "if(Test-Path -LiteralPath $path){throw 'managed exit control collision'};"
            "[IO.File]::WriteAllText($path,($value|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false));"
            "$value|ConvertTo-Json -Compress}finally{$p.Dispose()}")
        value, raw = self._vm_json(command, 60)
        value['raw'] = raw
        return value

    def _await_managed_exit_observer(self, capture: dict[str, Any],
                                     armed: dict[str, Any], nonce: str) -> dict[str, Any]:
        """Do not submit restart until the exact handle observer is ready and traffic began."""
        command = (
            "$ErrorActionPreference='Stop';$path=" + quote_ps(capture['probe']) + ";"
            "$deadline=[DateTime]::UtcNow.AddSeconds(20);$ready=$null;$attempt=$null;"
            "while([DateTime]::UtcNow -lt $deadline){"
            "$rows=@(Get-Content -LiteralPath $path -ErrorAction Stop|ForEach-Object {try{$_|ConvertFrom-Json}catch{$null}}|Where-Object {$_});"
            "$ready=@($rows|Where-Object {$_.event -eq 'managed_exit_observer_ready' -and $_.nonce -eq " + quote_ps(nonce) + "});"
            "$attempt=@($rows|Where-Object {$_.event -eq 'connect_attempt' -and $_.nonce -eq " + quote_ps(nonce) + "});"
            "if(@($rows|Where-Object {$_.event -eq 'finished' -or $_.event -eq 'managed_exit_observed'}).Count -gt 0){throw 'probe ended before restart'};"
            "if($ready.Count -eq 1 -and $attempt.Count -gt 0){break};Start-Sleep -Milliseconds 50};"
            "if($ready.Count -ne 1 -or $attempt.Count -eq 0){throw 'managed exit observer/traffic not ready before restart'};"
            "if([int]$ready[0].managed_pid -ne " + str(int(armed['pid'])) +
            " -or [long]$ready[0].managed_creation_filetime -ne " + str(int(armed['creation_filetime'])) +
            " -or $ready[0].run_id -ne " + quote_ps(armed['run_id']) +
            "){throw 'managed exit observer identity differs'};"
            "$probe=Get-Process -Id " + str(int(capture['pid'])) + " -ErrorAction Stop;try{$handle=$probe.Handle;"
            "if($probe.StartTime.ToUniversalTime().Ticks -ne " + str(int(capture['probe_creation_ticks'])) +
            " -or $probe.WaitForExit(0)){throw 'probe identity changed or exited before restart'}}finally{$probe.Dispose()};"
            "@{observer_ready=$ready[0];first_attempt=$attempt[0];observed_utc=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 6 -Compress")
        value, raw = self._vm_json(command, 35)
        value['raw'] = raw
        return value

    def _managed_run_creation(self, run_id: str) -> dict[str, Any]:
        creation = ('C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\' +
                    run_id + r'\creation.jsonl')
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$rows=@(Get-Content -LiteralPath " + quote_ps(creation) +
            "|ForEach-Object {$_|ConvertFrom-Json}|Where-Object {$_.stage -eq 'before_job' -and $_.run_id -eq " + quote_ps(run_id) + "});"
            "if($rows.Count -ne 1){throw 'new run before_job is missing or ambiguous'};"
            "@{run_id=" + quote_ps(run_id) + ";before_job_unix_seconds=[double]$rows[0].time}|ConvertTo-Json -Compress", 60)
        value['raw'] = raw
        return value

    def _managed_stop_window(self, run_id: str) -> dict[str, Any]:
        log = ('C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\' +
               run_id + r'\run.log')
        command = (
            "$ErrorActionPreference='Stop';$lines=@(Get-Content -LiteralPath " + quote_ps(log) + ");"
            "$begin=@($lines|Where-Object {$_ -match 'INFO FakeNet STOP_PHASE_BEGIN phase=complete'});"
            "$end=@($lines|Where-Object {$_ -match 'INFO FakeNet STOP_PHASE_END phase=complete'});"
            "if($begin.Count -ne 1 -or $end.Count -ne 1){throw 'old run stop window ambiguous'};"
            "$fmt='yyyy-MM-dd HH:mm:ss,fff';$culture=[Globalization.CultureInfo]::InvariantCulture;"
            "$b=[DateTime]::ParseExact($begin[0].Substring(0,23),$fmt,$culture,[Globalization.DateTimeStyles]::AssumeLocal).ToUniversalTime().Ticks;"
            "$e=[DateTime]::ParseExact($end[0].Substring(0,23),$fmt,$culture,[Globalization.DateTimeStyles]::AssumeLocal).ToUniversalTime().Ticks;"
            "if($e -le $b){throw 'old run stop window reversed'};"
            "@{run_id=" + quote_ps(run_id) + ";begin_ticks=$b;end_ticks=$e;begin=$begin[0];end=$end[0]}|ConvertTo-Json -Compress")
        value, raw = self._vm_json(command, 60)
        value['raw'] = raw
        return value

    @staticmethod
    def _check_exit_driven_order(events: list[dict[str, Any]], nonce: str,
                                 managed_pid: int, probe_pid: int,
                                 probe_creation_ticks: int, new_run_before_job: float,
                                 stop_begin_ticks: int, stop_end_ticks: int) -> dict[str, Any]:
        selected = [row for row in events if row.get('nonce') == nonce]
        probe_ready = [row for row in selected if row.get('event') == 'ready']
        if (len(probe_ready) != 1 or probe_ready[0].get('pid') != probe_pid or
                probe_ready[0].get('creation_ticks') != probe_creation_ticks or
                any(row.get('pid') != probe_pid for row in selected)):
            raise SuiteError('exit-driven probe PID/creation identity differs')
        ready = [row for row in selected if row.get('event') == 'managed_exit_observer_ready'
                 and row.get('managed_pid') == managed_pid]
        attempts = [row for row in selected if row.get('event') == 'connect_attempt']
        observed = [row for row in selected if row.get('event') == 'managed_exit_observed'
                    and row.get('managed_pid') == managed_pid]
        finished = [row for row in selected if row.get('event') == 'finished']
        if len(ready) != 1 or not attempts or len(observed) != 1 or len(finished) != 1:
            raise SuiteError('exit-driven probe observer/attempt/exit/finish evidence incomplete')
        for attempt in attempts:
            cid = attempt.get('connection_id')
            if not cid or not re.fullmatch(r'192\.168\.204\.233:\d+', str(attempt.get('src', ''))):
                raise SuiteError('exit-driven attempt has no exact guest tuple')
            requested = [row for row in selected if row.get('connection_id') == cid and
                         row.get('event') == 'close_requested']
            closed = [row for row in selected if row.get('connection_id') == cid and
                      row.get('event') == 'close_completed']
            if len(requested) != 1 or len(closed) != 1 or not (
                    attempt['utc_ticks'] <= requested[0]['utc_ticks'] <= closed[0]['utc_ticks']):
                raise SuiteError('exit-driven socket close receipt missing or out of order')
        last_closed = max(row['utc_ticks'] for row in selected
                          if row.get('event') == 'close_completed')
        new_start_ticks = round(new_run_before_job * 10_000_000 + 621355968000000000)
        stop_sends = [row for row in selected if row.get('event') == 'send' and
                      stop_begin_ticks <= row.get('utc_ticks', 0) <= stop_end_ticks]
        if not stop_sends:
            raise SuiteError('old probe has no real send in product stop window')
        if not (ready[0]['utc_ticks'] < attempts[0]['utc_ticks'] and
                last_closed <= observed[0]['utc_ticks'] <= finished[0]['utc_ticks'] < new_start_ticks):
            raise SuiteError('old probe close/exit receipt did not precede new managed start')
        return {'probe_ready': probe_ready[0], 'ready': ready[0], 'first_attempt': attempts[0],
                'stop_window_send_count': len(stop_sends), 'stop_window': [stop_begin_ticks, stop_end_ticks],
                'last_close_ticks': last_closed, 'exit_observed': observed[0],
                'finished': finished[0], 'new_run_before_job_ticks': new_start_ticks}

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
        if capture.get('shared_physical'):
            return self._stop_shared_probe_and_kernel(capture)
        if capture.get('physical_owner_id'):
            return self._stop_owned_shared_physical(capture)
        status_path = str(capture['probe']) + '.exit-status.json'
        coop_cmd = self._probe_cooperative_cleanup_command(
            capture['pid'], capture.get('probe_creation_ticks'), capture['stop'],
            status_path, 'pktmon stop', wait_seconds=30)
        clock_after = _sst_clock.clock_sample_ps('clockAfter')
        identity_after = (
            "$identityAfter=(& " + quote_ps(self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1') +
            " -Action identity -CaptureRunId " + quote_ps(capture['capture_run_id']) +
            " -Nonce " + quote_ps(capture['nonce']) + " -CandidateId " + quote_ps(self.identity.candidate_id) +
            ")|ConvertFrom-Json;" if self.native_clock_diagnostic else '')
        nic_update = (
            "$nic=Get-Content -LiteralPath " + quote_ps(capture['pktmon_nic']) + " -Raw|ConvertFrom-Json;"
            "$nic|Add-Member -NotePropertyName clock_after -NotePropertyValue $clockAfter -Force;"
            + ("$nic|Add-Member -NotePropertyName native_identity_after -NotePropertyValue $identityAfter -Force;" if self.native_clock_diagnostic else '') +
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
                   + clock_after + identity_after + nic_update + nic_write + conversion + nic_write +
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
        # The probe's cooperative exit closes its sockets; the kernel close/
        # RST events land moments later. Stopping the kernel trace in the
        # next breath sometimes missed them, leaving the primary TCB with no
        # terminal event (fakenet100 r09-run-13 sst-010: 710 lifecycle rows,
        # zero terminals). Give the teardown a bounded settle window first.
        time.sleep(3.0)
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

    def _stop_shared_probe_and_kernel(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Stop only this probe and its kernel session; keep pktmon with owner."""
        status_path = str(capture['probe']) + '.exit-status.json'
        coop_cmd = self._probe_cooperative_cleanup_command(
            capture['pid'], capture.get('probe_creation_ticks'), capture['stop'],
            status_path, None, wait_seconds=30)
        primary_error = None
        value = None
        raw = None
        try:
            value, raw = self._vm_json("$ErrorActionPreference='Stop';$coop=" +
                quote_ps(coop_cmd) + ";$result=& {Invoke-Expression $coop};"
                "@{coop=($result|ConvertFrom-Json)}|ConvertTo-Json -Depth 5 -Compress", 90)
            self._fail_closed_cooperative(value.get('coop'), capture['stop'])
        except Exception as exc:
            primary_error = exc
        if primary_error is not None:
            # The same run's kernel writer can still be recording a live
            # socket. Keep it for identity-bound continuation.
            raise UnsettledCaptureStop('shared probe cooperative close uncertain: %r' %
                                       (primary_error,)) from primary_error
        time.sleep(3.0)
        try:
            kernel = self._stop_kernel_capture(capture['kernel_capture'])
        except Exception as exc:
            raise UnsettledCaptureStop('shared probe kernel close uncertain: %r' %
                                       (exc,)) from exc
        paths = [capture['probe'], capture['stdout'], capture['stderr'], status_path,
                 str(PureWindowsPath(capture['probe']).parent / 'probe-launch.json')]
        client_out = str(PureWindowsPath(capture['probe']).parent / 'probe-client.stdout')
        file_list = ','.join(quote_ps(path) for path in paths)
        command = ("$ErrorActionPreference='Stop';$files=@(" + file_list + ");"
                   + ("$files=@($files|Where-Object{Test-Path -LiteralPath $_ -PathType Leaf});"
                      if capture.get('startup_recovery') else '') +
                   "$optional=" + quote_ps(client_out) + ";"
                   "if(Test-Path -LiteralPath $optional){$files=@($files+$optional)};"
                   "@{files=@($files|ForEach-Object{$f=Get-Item -LiteralPath $_ -ErrorAction Stop;"
                   "@{path=$f.FullName;bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName "
                   "-Algorithm SHA256).Hash.ToLower()}})}|ConvertTo-Json -Depth 5 -Compress")
        files_value, files_raw = self._vm_json(command, 120)
        if not isinstance(files_value.get('files'), list):
            raise SuiteError('shared probe file manifest missing')
        return {'files': files_value['files'] + kernel['files'], 'raw': raw,
                'file_raw': files_raw, 'kernel_raw': kernel['raw'],
                'run_label': capture['run_label'], 'shared_physical': True,
                'physical_owner_id': capture['physical_owner_id'],
                'cooperative_exit': value['coop']['cooperative_exit'],
                'exit_status_path': status_path}

    def _stop_owned_shared_physical(self, capture: dict[str, Any]) -> dict[str, Any]:
        """Close an owned shared writer in separate, evidenced terminal stages."""
        status_path = str(capture['probe']) + '.exit-status.json'
        coop_cmd = self._probe_cooperative_cleanup_command(
            capture['pid'], capture.get('probe_creation_ticks'), capture['stop'],
            status_path, None, wait_seconds=30)
        try:
            coop_value, coop_raw = self._vm_json(
                "$ErrorActionPreference='Stop';$c=" + quote_ps(coop_cmd) +
                ";$r=& {Invoke-Expression $c};@{coop=($r|ConvertFrom-Json)}"
                "|ConvertTo-Json -Depth 5 -Compress", 90)
            coop = self._fail_closed_cooperative(coop_value.get('coop'), capture['stop'])
        except Exception as exc:
            raise UnsettledCaptureStop('physical owner probe close uncertain: %r' %
                                       (exc,)) from exc
        # A separate RPC returns the exact native stop output before any
        # conversion. An unknown response retains the still possibly active
        # physical writer and its kernel trace for later identity recovery.
        stop_cmd = (
            "$ErrorActionPreference='Stop';$output=(& pktmon stop|Out-String);"
            "$exit=$LASTEXITCODE;$status=(& pktmon status|Out-String);"
            "$statusExit=$LASTEXITCODE;@{output=$output;exit=$exit;"
            "status=$status;status_exit=$statusExit;owner_id=" +
            quote_ps(capture['physical_owner_id']) + "}|ConvertTo-Json -Compress")
        try:
            stopped, stop_raw = self._vm_json(stop_cmd, 90)
        except Exception as exc:
            raise UnsettledCaptureStop('physical pktmon stop response unknown: %r' %
                                       (exc,)) from exc
        if (stopped.get('owner_id') != capture['physical_owner_id'] or
                stopped.get('exit') != 0 or stopped.get('status_exit') != 0 or
                not self._pktmon_stopped(stopped.get('status'))):
            raise UnsettledCaptureStop('physical pktmon terminal status unproved: %r' %
                                       (stopped,))
        time.sleep(3.0)
        try:
            kernel = self._stop_kernel_capture(capture['kernel_capture'])
        except Exception as exc:
            raise UnsettledCaptureStop('shared owner kernel terminal unproved: %r' %
                                       (exc,)) from exc
        text_path = str(capture['etl']).replace('.etl', '.txt')
        clock_after = _sst_clock.clock_sample_ps('clockAfter')
        identity_after = (
            "$identityAfter=(& " + quote_ps(self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1') +
            " -Action identity -CaptureRunId " + quote_ps(capture['capture_run_id']) +
            " -Nonce " + quote_ps(capture['nonce']) +
            " -CandidateId " + quote_ps(self.identity.candidate_id) +
            ")|ConvertFrom-Json;" if self.native_clock_diagnostic else '')
        conversion_cmd = (
            "$ErrorActionPreference='Stop';$etl=" + quote_ps(capture['etl']) +
            ";$txt=" + quote_ps(text_path) + ";$mp=" + quote_ps(capture['pktmon_nic']) + ";"
            "if(Test-Path -LiteralPath $txt){throw 'pktmon conversion collision'};"
            "$nic=Get-Content -LiteralPath $mp -Raw|ConvertFrom-Json;" +
            clock_after + identity_after +
            "$nic|Add-Member -NotePropertyName clock_after -NotePropertyValue $clockAfter -Force;" +
            ("$nic|Add-Member -NotePropertyName native_identity_after -NotePropertyValue $identityAfter -Force;"
             if self.native_clock_diagnostic else '') +
            "$counters=(& pktmon counters|Out-String);if($LASTEXITCODE -ne 0)"
            "{throw 'pktmon counters after stop failed'};"
            "$status=(& pktmon status|Out-String);if($LASTEXITCODE -ne 0 -or $status -notmatch '没有运行|(?i:not running|stopped)')"
            "{throw 'pktmon running before conversion'};"
            "$nic|Add-Member -NotePropertyName pktmon_counters_after -NotePropertyValue $counters -Force;"
            "$nic|Add-Member -NotePropertyName pktmon_status_after -NotePropertyValue $status -Force;"
            "$nic|Add-Member -NotePropertyName pktmon_stop_output -NotePropertyValue " +
            quote_ps(str(stopped['output'])) + " -Force;"
            "& pktmon etl2txt $etl --out $txt | Out-Null;$exit=$LASTEXITCODE;"
            "if($exit -ne 0){throw ('pktmon etl2txt failed: '+$exit)};"
            "$conversion=@{exit_code=$exit;argv=@('pktmon','etl2txt',$etl,'--out',$txt);"
            "etl_sha256=(Get-FileHash -LiteralPath $etl -Algorithm SHA256).Hash.ToLower();"
            "text_sha256=(Get-FileHash -LiteralPath $txt -Algorithm SHA256).Hash.ToLower()};"
            "$nic|Add-Member -NotePropertyName conversion -NotePropertyValue $conversion -Force;"
            "$nic|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $mp -Encoding UTF8;"
            "@{conversion=$conversion;status=$status}|ConvertTo-Json -Depth 7 -Compress")
        try:
            conversion, conversion_raw = self._vm_json(conversion_cmd, 180)
        except Exception as exc:
            raise SuiteError('physical writer stopped; conversion incomplete: %r; '
                             'stop=%r' % (exc, stopped)) from exc
        paths = [capture['probe'], capture['etl'], text_path, capture['pktmon_nic'],
                 capture['stdout'], capture['stderr'], status_path]
        optional = str(PureWindowsPath(capture['probe']).parent / 'probe-client.stdout')
        files_cmd = (
            "$ErrorActionPreference='Stop';$files=@(" +
            ','.join(quote_ps(path) for path in paths) + ");$optional=" + quote_ps(optional) +
            ";if(Test-Path -LiteralPath $optional){$files=@($files+$optional)};"
            "@{files=@($files|ForEach-Object{$f=Get-Item -LiteralPath $_ -ErrorAction Stop;"
            "@{path=$f.FullName;bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName "
            "-Algorithm SHA256).Hash.ToLower()}})}|ConvertTo-Json -Depth 5 -Compress")
        files_value, files_raw = self._vm_json(files_cmd, 120)
        if not isinstance(files_value.get('files'), list):
            raise SuiteError('shared physical files manifest missing')
        return {'files': files_value['files'] + kernel['files'],
                'run_label': capture['run_label'], 'physical_owner_id': capture['physical_owner_id'],
                'cooperative_exit': coop['cooperative_exit'],
                'coop_raw': coop_raw, 'stop': stopped, 'stop_raw': stop_raw,
                'conversion': conversion, 'conversion_raw': conversion_raw,
                'files_raw': files_raw, 'kernel_raw': kernel['raw']}


    def _transfer_guest_file(self, guest_path: str, size: int, sha256: str,
                             destination: Path, *, auxiliary_v2_output: bool = False
                             ) -> dict[str, Any]:
        assert self.vm
        guest = PureWindowsPath(guest_path)
        guest_root = PureWindowsPath(self.guest_work_root)
        if (not guest.is_absolute() or '..' in guest.parts or
                not destination.resolve().is_relative_to(self.root.resolve())):
            raise SuiteError('guest evidence path outside transfer scope: ' + guest_path)
        guest_parts = tuple(part.casefold() for part in guest.parts)
        root_parts = tuple(part.casefold() for part in guest_root.parts)
        shared_text = (self.capture_contract == 'scenario-shared-v2' and
                       guest_parts[:len(root_parts)] == root_parts and
                       len(guest_parts) == len(root_parts) + 4 and
                       guest_parts[len(root_parts)] == 'scenario-suite-20260912' and
                       guest_parts[-2:] == ('run-01', 'pktmon.txt') and
                       PureWindowsPath(destination).name == 'pktmon.txt' and
                       destination.parent.name == 'run-01')
        native_zip = (auxiliary_v2_output and
                      guest_parts[:len(root_parts)] == root_parts and
                      len(guest_parts) == len(root_parts) + 2 and
                      guest_parts[len(root_parts)].startswith('qpc-contract-') and
                      guest_parts[-1] == 'output.zip' and
                      destination.name == 'qpc-output.zip' and
                      destination.parent.name == 'auxiliary-qpc')
        if auxiliary_v2_output and not native_zip:
            raise SuiteError('auxiliary v2 output transfer scope differs')
        limit = (MAX_SHARED_PKTMON_TEXT_TRANSFER if shared_text else
                 MAX_AUX_V2_ZIP_TRANSFER if native_zip else MAX_GUEST_TRANSFER)
        if not 0 <= int(size) <= limit:
            raise SuiteError('guest evidence outside transfer bound: ' + guest_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise SuiteError('guest evidence destination collision: ' + str(destination))
        temporary = destination.with_name(destination.name + '.transfer-' + uuid.uuid4().hex)
        actual = hashlib.sha256()
        try:
            with temporary.open('xb') as stream:
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
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return file_record(destination, self.root)

    def _fault_mode(self, enabled: bool) -> dict[str, Any]:
        """Toggle fault mode while preserving original registry/config bytes.

        The snapshot is taken once inside the suite guest directory. Disable
        restores saved bytes and MultiString exactly; it never recreates a
        service.json from a parsed object or guesses the normal grace period.
        """
        assert self.vm
        guest = self.guest_work_root + r'\scenario-suite-20260912'
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
        guest = self.guest_work_root + r'\scenario-suite-20260912'
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
        receipt = getattr(self, 'ipc_cycle_receipt', None)
        if receipt:
            prefix = ("$receipt=" + quote_ps(receipt) + ";"
                      "if(Test-Path $receipt){throw 'IPC receipt collision'};"
                      "New-Item -ItemType Directory -Force (Split-Path $receipt)|Out-Null;"
                      "function Write-IpcPhase($stage,$answer){"
                      "$v=@{stage=$stage;enabled=" + ("$true" if enabled else "$false") +
                      ";utc=[DateTime]::UtcNow.ToString('o');observer_pid=$PID;"
                      "observer_filetime=[string](Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc();answer=$answer};"
                      "$tmp=$receipt+'.tmp';[IO.File]::WriteAllText($tmp,($v|ConvertTo-Json -Depth 8 -Compress));"
                      "Move-Item -LiteralPath $tmp -Destination $receipt -Force};Write-IpcPhase 'entered' $null;")
            body = body.replace(";& 'C:", ";Write-IpcPhase 'stop_intent' $null;& 'C:")
            body = body.replace("\n& 'C:", "\nWrite-IpcPhase 'stop_intent' $null;& 'C:")
            body = body.replace("throw 'controlled stop failed'};", "throw 'controlled stop failed'};Write-IpcPhase 'stop_completed' $null;")
            body = body.replace("throw 'ipc-evidence controlled stop failed'};", "throw 'ipc-evidence controlled stop failed'};Write-IpcPhase 'stop_completed' $null;")
            body = body.replace(";Start-Service fakenetng-mcp;", ";Write-IpcPhase 'environment_completed' $null;Write-IpcPhase 'start_intent' $null;Start-Service fakenetng-mcp;Write-IpcPhase 'start_completed' $null;")
            body = body.replace("@{enabled=$true;backup=", "$answer=@{enabled=$true;backup=").replace("@{enabled=$false;backup=", "$answer=@{enabled=$false;backup=")
            body = body.replace("}|ConvertTo-Json -Compress", "};Write-IpcPhase 'completed' $answer;$answer|ConvertTo-Json -Compress")
            body = prefix + body
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
        from bounded_mcp import TransportUnknown
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
            except (urllib.error.URLError, TransportUnknown) as exc:
                observations.append({'transport_error': repr(exc)})
            time.sleep(0.25)
        raise SuiteError('ipc-evidence endpoint readiness deadline: %r' % observations)

    def _arm_fault(self, fault: str, nonce: str,
                   probe: str | None = None) -> dict[str, Any]:
        assert self.vm
        if fault not in FAULTS:
            raise ValueError('unknown fault')
        payload = json.dumps({'fault': fault, 'nonce': nonce}, separators=(',', ':'))
        gate = fault in ('listener_stop', 'diverter_stop', 'child_hang')
        # The child waits on the probe conditions itself (see
        # faultinject.wait_for_start_gate); the gate names the probe file so
        # the in-child rendezvous needs no external observer latency.
        gate_payload = payload
        if gate and probe and fault in ('listener_stop', 'diverter_stop'):
            gate_payload = json.dumps(
                {'fault': fault, 'nonce': nonce, 'probe': probe},
                separators=(',', ':'))
        value, raw = self._vm_json(
            "$ErrorActionPreference='Stop';$p='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json';"
            "$g='C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection-gate.json';"
            "if((Test-Path $p) -or (Test-Path $g)){throw 'existing unconsumed fault or gate'};"
            "$json=" + quote_ps(payload) + ";[IO.File]::WriteAllText($p,$json,[Text.UTF8Encoding]::new($false));$receipt=Get-Item $p;" +
            ("[IO.File]::WriteAllText($g," + quote_ps(gate_payload) + ",[Text.UTF8Encoding]::new($false));$gate=Get-Item $g;" if gate else "$gate=$null;") +
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
                                   planned: dict[str, Any],
                                   case_observation: dict[str, Any] | None,
                                   ) -> tuple[str | None, dict[str, Any] | None]:
        """Strictly bind one planned TLS SNI-deny case to its relay record.

        Master evidence contract (candidate08 sst-004 case 4): a planned
        deny case with an explicit ``tls_server_name`` whose exact
        PID/src/sport/dst/dport/proto flow uniformly took REDIRECT_TLS_RELAY
        can pass only through this case's own sni_mismatch record.  Binding
        requirements, all enforced here from the sealed originals:

        1. a valid con008 application observation for this exact case
           (identity checked per field) must exist; packet-only or older
           contracts never substitute;
        2. planned SNI == the case handshake's actual SNI == the record's
           parsed SNI, and that SNI differs from the mapped domain;
        3. exactly one TLS_SNI_DENY whose src/sport/original_ip/original_port
           equal this case, with a positive integer generation, reason
           ClientHelloError AND reason_code sni_mismatch, and the domain of
           this case's actual relay policy;
        4. no contradictory ALLOW and no second ambiguous deny.  The relay's
           TLS_SNI_ALLOW carries no client identity (real product format):
           a relevant record (same original destination) is only excluded
           when its conservative interval is provably disjoint from this
           case's own connection bounds; overlapping or boundary-uncertain
           records stay ambiguous rejections;
        5. the record's timestamp, under the frozen capture clock resolution
           (integer conservative interval, the same 15,625,000ns uncertainty
           the application observation uses), must fit entirely after the
           native/policy/probe-established conservative upper bound and before the observation's
           native/probe earliest-termination lower bound ``end_lower_ns`` --
           probe min/max never widen that bound;
        6. the byte range of the record inside the sealed run.log is
           returned with an explicit contract version for sealed comparison.

        Anything less leaves the case failing; no verdict is relaxed.
        """
        planned_sni = planned.get('tls_server_name')
        if (not isinstance(planned_sni, str) or planned.get('protocol') != 'tls'
                or not isinstance(case_observation, dict)):
            return None, None
        if not (case_observation.get('schema') == 'sst.application-observation.v1'
                and case_observation.get('nonce') == first.get('nonce')
                and case_observation.get('pid') == first.get('pid')
                and case_observation.get('case_index') == first.get('case_index')
                and case_observation.get('connection_id') == first.get('connection_id')
                and case_observation.get('src') == ':'.join(source)
                and case_observation.get('dst') == ':'.join(target)
                and case_observation.get('protocol') == 'TCP'
                and isinstance(case_observation.get('begin_upper_ns'), int)
                and isinstance(case_observation.get('end_lower_ns'), int)):
            return None, None
        case_rows = [row for row in case_events
                     if row.get('connection_id') == first.get('connection_id')]
        rows = [row for row in case_rows if isinstance(row.get('utc_ticks'), int)]
        handshake = next((row for row in rows
                          if row.get('event') == 'case_tls_handshake_attempt'), None)
        if not rows or not handshake or handshake.get('sni') != planned_sni:
            return None, None
        # Frozen conservative clock rule shared with the application
        # observation: resolution 15,625,000ns, uncertainty resolution-1.
        uncertainty = 15625000 - 1
        begin_bound = case_observation['begin_upper_ns']
        end_bound = case_observation['end_lower_ns']

        def line_ns(line):
            stamp = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) ', line)
            if not stamp:
                return None
            try:
                base = dt.datetime.strptime(stamp[1], '%Y-%m-%d %H:%M:%S') - dt.timedelta(hours=8)
            except ValueError:
                return None
            delta = base - dt.datetime(1970, 1, 1)
            return (delta.days * 86400 + delta.seconds) * 10**9 + int(stamp[2]) * 10**6

        matched: tuple[str, dict[str, str], int] | None = None
        for line in run_log.splitlines():
            if 'TLS_SNI_DENY ' not in line:
                continue
            fields = self._log_fields(line)
            # Same connection scope only: the relay record must carry this
            # case's client identity.  Legacy records without it (older
            # candidates) are not attributable and never lend evidence.
            if (fields.get('sport') != source[1] or fields.get('src') != source[0]):
                continue
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
            moment = line_ns(line)
            if moment is None:
                return None, None
            native = None
            if not (begin_bound <= moment - uncertainty
                    and moment + uncertainty <= end_bound):
                # A deny session shorter than twice the frozen wall-timer
                # uncertainty inverts the conservative interval structurally;
                # the product's native terminal record judges the same
                # decision in one clock domain when it exists.
                native = self._native_deny_contained(
                    log_path, generation, source, target, planned_sni,
                    case_observation)
                if native is None:
                    return None, None
            if matched is not None:
                return None, None
            matched = (line, fields, generation, native)
        if matched is None:
            return None, None
        line, fields, generation, native = matched
        # In either deny path the wall begin/end are inner containment bounds,
        # so neither proves that an ALLOW happened outside the connection.
        # The probe records connect_attempt before BeginConnect and case_close
        # after the case's TLS work.  Their same-identity UTC ticks supply the
        # outer bounds used only for ALLOW disambiguation.
        outer_start = outer_end = None
        attempts = [row for row in case_rows
                    if row.get('event') == 'case_connect_attempt']
        closes = [row for row in case_rows if row.get('event') == 'case_close']
        if len(attempts) == len(closes) == 1:
            attempt, close = attempts[0], closes[0]
            start_tick, end_tick = attempt.get('utc_ticks'), close.get('utc_ticks')
            if (type(start_tick) is int and type(end_tick) is int
                    and all(row.get('nonce') == first.get('nonce')
                            and row.get('pid') == first.get('pid')
                            and row.get('case_index') == first.get('case_index')
                            for row in (attempt, close))
                    and attempt.get('src') in (':'.join(source), '0.0.0.0:' + source[1])
                    and start_tick <= end_tick):
                outer_start = (start_tick - 621355968000000000) * 100 - uncertainty
                outer_end = (end_tick - 621355968000000000) * 100 + uncertainty

        # Identity-free ALLOW can be ignored only when its whole uncertain
        # interval is disjoint from the possible connection interval.  This
        # check does not establish either version's positive DENY containment.
        for allow_line in run_log.splitlines():
            if 'TLS_SNI_ALLOW ' not in allow_line:
                continue
            allow_fields = self._log_fields(allow_line)
            if allow_fields.get('src') and allow_fields.get('sport'):
                if (allow_fields.get('src') == source[0]
                        and allow_fields.get('sport') == source[1]):
                    return None, None
                continue
            if allow_fields.get('original_ip') != target[0]:
                continue
            allow_ns = line_ns(allow_line)
            if allow_ns is None:
                return None, None
            if (outer_start is not None and outer_end is not None
                    and (allow_ns + uncertainty < outer_start
                         or allow_ns - uncertainty > outer_end)):
                continue
            return None, None
        raw = log_path.read_bytes()
        needle = line.encode('utf-8')
        offset = raw.find(needle)
        if offset < 0 or raw.find(needle, offset + 1) >= 0:
            return None, None
        binding = {'schema': 'sst.sni-mismatch-binding.v1',
                   'contract_version': 2 if native else 1,
                   'native_deny': native,
                   'deny_log': line,
                   'deny_log_ref': {'path': log_rel_path,
                                    'byte_start': offset,
                                    'byte_end': offset + len(needle)},
                   'sni': planned_sni,
                   'domain': fields['domain'],
                   'generation': generation,
                   'begin_bound_ns': begin_bound,
                   'end_bound_ns': end_bound,
                   'handshake_sni': handshake.get('sni')}
        return line, binding

    def _native_deny_contained(self, log_path, generation, source, target,
                                planned_sni, case_observation):
        """Native-clock containment for a deny the wall margins cannot judge.

        Short-lived deny sessions live shorter than twice the frozen
        15,625,000ns wall-timer uncertainty, so the conservative wall
        interval inverts structurally (candidate10-12 sst-004 case-4).  The
        product's native terminal record carries this deny in the FILETIME
        domain with a QPC bracket; the case's own ETW connect/terminal
        instants are the same-domain bounds.  Identity (generation, tuple,
        SNI) plus one-record uniqueness replace timestamp disambiguation;
        containment still requires the deny instant inside the ETW window.
        Absent, unsupported, ambiguous or out-of-window records leave the
        case failing exactly as before.
        """
        native_path = log_path.parent / 'relay-native-events.jsonl'
        try:
            rows = [json.loads(line) for line in
                    native_path.read_text(encoding='utf-8').splitlines()
                    if line.strip()]
        except (OSError, ValueError):
            return None
        candidates = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            if (row.get('schema') != 'fakenetng.relay-native-terminal.v1'
                    or row.get('outcome') != 'deny'
                    or row.get('reason_code') != 'sni_mismatch'
                    or row.get('generation') != generation
                    or str(row.get('sport')) != str(source[1])
                    or row.get('src') != source[0]
                    or row.get('original_ip') != target[0]
                    or str(row.get('original_port')) != str(target[1])
                    or row.get('sni') != planned_sni):
                continue
            clock = row.get('clock') if isinstance(row.get('clock'), dict) else {}
            if clock.get('supported') is not True:
                continue
            candidates.append(clock)
        if len(candidates) != 1:
            return None
        clock = candidates[0]
        try:
            moment_ns = int(clock['filetime_100ns']) * 100 - 11644473600000000000
        except (KeyError, TypeError, ValueError):
            return None
        lo = case_observation.get('etw_connect_upper_ns')
        hi = case_observation.get('etw_terminal_lower_ns')
        if not (isinstance(lo, int) and isinstance(hi, int)):
            return None
        if not lo <= moment_ns <= hi:
            return None
        return {'generation': generation, 'filetime_ns': moment_ns,
                'qpc_before': clock.get('qpc_before'),
                'qpc_after': clock.get('qpc_after'),
                'qpc_frequency': clock.get('qpc_frequency'),
                'etw_connect_upper_ns': lo, 'etw_terminal_lower_ns': hi}

    SNI_BINDING_FIELDS = ('schema', 'contract_version', 'native_deny',
                           'deny_log', 'deny_log_ref',
                           'sni', 'domain', 'generation', 'begin_bound_ns',
                           'end_bound_ns', 'handshake_sni')

    @staticmethod
    def _binding_normalized(value):
        if isinstance(value, tuple):
            return [Suite._binding_normalized(item) for item in value]
        if isinstance(value, list):
            return [Suite._binding_normalized(item) for item in value]
        if isinstance(value, dict):
            return {key: Suite._binding_normalized(item) for key, item in value.items()}
        return value

    @staticmethod
    def _stored_binding_issues(stored_cases: list[dict[str, Any]],
                               recomputed_cases: list[dict[str, Any]]) -> list[str]:
        """Reject stored SNI-deny bindings that the originals disprove.

        Results carry ``contract_version`` 1 (conservative wall interval) or
        2 (strict native terminal) bindings. Every
        binding field is compared against the independent recomputation
        (JSON-normalized so list/tuple spellings agree); a required case
        that is missing, a duplicated case index, a binding that is absent,
        null or scalar, an unknown contract version, an sni_mismatch branch
        row without its sealed binding, and any tampered field or moved byte
        reference are all rejected.  Results written before the contract
        carry no binding cannot satisfy a newly required binding; legacy
        evidence is preserved but does not silently become a verified pass.
        """
        issues: list[str] = []
        indexes = [row.get('index') for row in stored_cases if isinstance(row, dict)]
        for index in sorted({item for item in indexes if indexes.count(item) > 1}):
            issues.append('duplicate stored case index %s' % index)
        for stored in stored_cases:
            if not isinstance(stored, dict):
                continue
            index = stored.get('index')
            binding = stored.get('sni_binding')
            branch = stored.get('branch_log')
            if binding is not None and not isinstance(binding, dict):
                issues.append('stored SNI deny binding is not a record (case %s)' % index)
                continue
            if isinstance(binding, dict):
                version = binding.get('contract_version')
                if type(version) is not int or version not in (1, 2):
                    issues.append('stored SNI deny binding contract version missing/unknown (case %s)' % index)
                    continue
                if (binding.get('schema') != 'sst.sni-mismatch-binding.v1' or
                        (version == 1 and binding.get('native_deny') is not None) or
                        (version == 2 and not isinstance(binding.get('native_deny'), dict))):
                    issues.append('stored SNI deny binding version/native shape differs (case %s)' % index)
                    continue
                current = next((row for row in recomputed_cases
                                if row.get('index') == index), None)
                recomputed = current.get('sni_binding') if isinstance(current, dict) else None
                if (not isinstance(recomputed, dict) or
                        type(recomputed.get('contract_version')) is not int or
                        recomputed.get('contract_version') != version or
                        (version == 2 and not isinstance(recomputed.get('native_deny'), dict))):
                    issues.append('stored SNI deny binding has no recomputed counterpart (case %s)' % index)
                    continue
                if (branch != binding.get('deny_log') or
                        branch != current.get('branch_log')):
                    issues.append('stored SNI deny branch differs from sealed binding (case %s)' % index)
                for field in Suite.SNI_BINDING_FIELDS:
                    if (Suite._binding_normalized(binding.get(field)) !=
                            Suite._binding_normalized(recomputed.get(field))):
                        issues.append('stored SNI deny binding field %s differs (case %s)' % (field, index))
            elif any(row.get('index') == index and isinstance(row.get('sni_binding'), dict)
                     for row in recomputed_cases if isinstance(row, dict)):
                issues.append('recomputed SNI deny case lacks stored binding (case %s)' % index)
            elif (isinstance(branch, str) and 'TLS_SNI_DENY ' in branch
                    and 'reason_code=sni_mismatch' in branch):
                # A new-version adjudicator always seals the binding next to
                # such a branch row; deleting it strips the sealed evidence.
                issues.append('stored sni_mismatch branch lacks its sealed binding (case %s)' % index)
        for recomputed in recomputed_cases:
            if not isinstance(recomputed, dict):
                continue
            binding = recomputed.get('sni_binding')
            if (isinstance(binding, dict) and binding.get('contract_version') in (1, 2)
                    and not any(row.get('index') == recomputed.get('index')
                                for row in stored_cases if isinstance(row, dict))):
                issues.append('recomputed SNI deny case missing from stored rows (case %s)'
                              % recomputed.get('index'))
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
                                 creation_ticks=None, include_begin_bound=False,
                                 auxiliary_qpc=None):
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
            old_zero_ok = not observed['tuple_terminals'] or min(
                fault.time_bounds(e['text'])[0] for e in observed['tuple_terminals']) - uncertainty >= begin
            is_aux_qpc = (getattr(self, 'auxiliary_clock_evidence', 'utc-v1') in AUX_QPC_MODES and
                          origin.get('event') == 'case_established')
            if is_aux_qpc:
                proof = next((row for row in (auxiliary_qpc or {}).get('cases', [])
                              if row['case_index'] == origin.get('case_index') and
                              row['connection_id'] == origin.get('connection_id')), None)
                if (not proof or proof['pid'] != origin['pid'] or proof['src'] != src or
                        proof['dst'] != dst or proof['tuple_terminal_refs'] !=
                        [e['ref'] for e in observed['tuple_terminals']] or
                        proof['zero_constraint'] != ('VERIFIED' if observed['tuple_terminals']
                                                      else 'NO_ZERO_TCB') or
                        any(gap <= 1 for gap in proof['gaps_ticks'])):
                    raise SuiteError('auxiliary QPC proof/case/zero-TCB lifetime differs')
                result['auxiliary_native_qpc'] = proof
                result['legacy_utc_zero_constraint_passed'] = old_zero_ok
            if not is_aux_qpc and not old_zero_ok:
                raise SuiteError('application lifetime constrained before establishment')
            if include_begin_bound:
                result['begin_upper_ns'] = begin
            # Native ETW instants without the conservative wall-clock margin:
            # the relay's native terminal records compare against these so a
            # short-lived deny session is judged in one clock domain (the
            # margin exists for wall-vs-native comparisons only).
            result['etw_connect_upper_ns'] = fault.time_bounds(observed['connect']['text'])[1]
            result['etw_terminal_lower_ns'] = terminal + uncertainty
            result.update(observation_kind='tcpip_etw', connection_refs=[e['ref'] for e in observed['events']],
                          generation_manifest=observed['generation_manifest'],
                          tuple_terminal_refs=[e['ref'] for e in observed['tuple_terminals']],
                          end_lower_ns=min(terminal,probe_end))
        result['capture_refs'] = [record for name,record in by_name.items()
                                  if name.startswith(('pktmon.', 'kernel-network.'))]
        return result

    _QUIESCENCE_REFUSAL_MARKER = ('reviewed process image is already '
                                  'running before READY')
    _ACTIVE_A_REFUSAL_MARKER = ('fakenet.diverters.egresspolicy.PolicyConfigError: '
                                'an existing TCP row already targets process redirect A')

    @classmethod
    def _branch_verdict(cls, runs: list[dict[str, Any]], profile: dict[str, Any],
                        plan_tools: list[str], call_tools: list[str],
                        fault: str | None) -> tuple[dict[str, Any], bool]:
        """Keep the approved refusal exception out of pre-existing fault gates."""
        refusal_recorded = any(item.get('expected_refusal') for item in runs)
        approved = (not fault and len(runs) == 1 and
                    runs[0].get('expected_refusal', {}).get('marker') == cls._ACTIVE_A_REFUSAL_MARKER and
                    runs[0].get('expected_refusal', {}).get('proof', {}).get('kind') ==
                        'approved-active-a-refusal-v2' and
                    profile.get('bucket') == 'B3' and
                    profile.get('interleave') == 'before-start' and
                    profile.get('probe_target', {}).get('process_mode') == 'nonmatch')
        return ({
            'interface_semantics': (call_tools == plan_tools or
                (refusal_recorded and not approved and
                 plan_tools[:len(call_tools)] == call_tools)),
            'per_run_dual_capture': bool(runs) and (
                (not approved or all(item.get('capture', {}).get('all_components')
                                     for item in runs)) and
                all(item.get('capture', {}).get('all_components') and
                    (not runtime_pcap_required(profile) or item.get('runtime_pcap'))
                    for item in runs
                    if item.get('start_response', {}).get('state') == 'healthy')),
            'traffic_oracle': ('NOT_EXECUTED' if approved else
                bool(runs) and all(item.get('traffic_oracle', {}).get('passed')
                                   for item in runs
                                   if item.get('start_response', {}).get('state') == 'healthy')),
        }, approved)

    @staticmethod
    def _scenario_passed(failure: str | None, verdict: dict[str, Any],
                         approved_refusal: bool) -> bool:
        if failure is not None:
            return False
        if approved_refusal:
            return (verdict.get('traffic_oracle') == 'NOT_EXECUTED' and
                    all(value is True for key, value in verdict.items()
                        if key != 'traffic_oracle'))
        return all(value is True for value in verdict.values())

    @staticmethod
    def _is_quiescence_refusal_family(profile: dict[str, Any]) -> bool:
        target = profile.get('probe_target', {})
        return (profile.get('bucket') == 'B3' and
                target.get('process_mode') in ('match', 'nonmatch') and
                profile.get('interleave') == 'before-start')

    @staticmethod
    def _active_a_refusal_proof(root: Path, profile: dict[str, Any], nonce: str,
                                run: dict[str, Any]) -> dict[str, Any]:
        """Bind the approved nonmatch refusal to this attempt's native TCP activity.

        ETW establishes a live PID/tuple during start. The product's exact
        rejection establishes its MIB decision; ETW cannot identify the unique
        row read by that decision, and this proof does not claim it can.
        """
        root = root.resolve()
        target = profile.get('probe_target') or {}
        if (profile.get('bucket'), profile.get('interleave'), target.get('process_mode'),
                target.get('protocol'), target.get('host'), target.get('port'),
                target.get('expectation')) != ('B3', 'before-start', 'nonmatch',
                                               'tcp', '198.51.100.77', 443, 'ordinary_path'):
            raise ValueError('not the approved B3 nonmatch A tuple')
        capture = run.get('capture') or {}
        records = {Path(str(item.get('path', ''))).name: item
                   for item in capture.get('files') or []}
        if len(records) != len(capture.get('files') or []):
            raise ValueError('duplicate native original name')
        def original(name: str) -> Path:
            item = records.get(name)
            if not item:
                raise ValueError('missing native original: ' + name)
            path = (root / item['path']).resolve()
            if (not path.is_relative_to(root.resolve()) or not path.is_file() or
                    file_record(path, root) != item):
                raise ValueError('changed native original: ' + name)
            return path
        probe_path = original('probe.jsonl')
        etw_path = original('kernel-network.events.jsonl')
        original('kernel-network.etl')
        metadata_path = original('kernel-network.metadata.json')
        summary_path = original('kernel-network.summary.txt')
        original('pktmon.etl')
        pktmon_path = original('pktmon.txt')
        original('pktmon-nic.json')
        metadata = read_json(metadata_path)
        summary = summary_path.read_text(encoding='utf-8-sig', errors='replace')
        conversion = metadata.get('conversion') or {}
        if (conversion.get('etl_sha256') != records['kernel-network.etl']['sha256'] or
                conversion.get('events_sha256') != records['kernel-network.events.jsonl']['sha256'] or
                conversion.get('tracerpt_exit_code') != 0 or
                conversion.get('event_reader_exit_code') != 0 or
                not re.search(r'Total Events\s+Lost\s+0\b', summary)):
            raise ValueError('native TCP trace is incomplete')
        if (not capture.get('all_components') or capture.get('pktmon_capture_issues') or
                not (capture.get('pktmon_binding') or {}).get('component_ids')):
            raise ValueError('physical capture is incomplete')
        # The capture-start original is located alongside the bound probe.
        start_path = probe_path.parent.parent / (run['label'] + '-capture-start.json')
        start = read_json(start_path)
        start_target = start.get('probe_target')
        if isinstance(start_target, str):
            start_target = json.loads(start_target)
        events = Suite._read_probe_events(probe_path)
        ready = [row for row in events if row.get('event') == 'ready']
        released = [row for row in events if row.get('event') == 'released']
        if len(ready) != 1 or len(released) != 1:
            raise ValueError('probe ready/release identity is incomplete')
        ready, released = ready[0], released[0]
        pid, creation = ready.get('pid'), ready.get('creation_ticks')
        native = ready.get('native_identity') or {}
        if (not isinstance(nonce, str) or not nonce or
                any(row.get('nonce') != nonce for row in events) or
                type(pid) is not int or pid <= 0 or type(creation) is not int or creation <= 0 or
                start.get('nonce') != nonce or start.get('pid') != pid or
                start.get('probe_creation_ticks') != creation or
                start.get('capture_run_id') != nonce + ':' + run['label'] or
                start.get('run_label') != run['label'] or
                start.get('interleave') != 'before-start' or
                start_target != target or
                capture.get('probe_launcher_pid') != pid or
                native.get('pid') != pid or native.get('nonce') != nonce or
                native.get('run_id') != nonce + ':' + run['label'] or
                native.get('creation_filetime_100ns') != creation - 504911232000000000 or
                ready.get('target_host') != target['host'] or
                ready.get('target_port') != target['port'] or
                ready.get('target_protocol') != 'tcp' or
                ready.get('process_mode') != 'nonmatch' or
                ready.get('interleave') != 'before-start' or
                run.get('probe_release', {}).get('phase') != 'before-start'):
            raise ValueError('probe nonce/PID/creation/A identity differs')
        def instant(value: str) -> dt.datetime:
            return dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        release_at = instant(run['probe_release']['released_utc'])
        start_end = instant(run['started_at'])
        failure_at = instant(run.get('refusal_failure_utc') or run['started_at'])
        if not instant(ready['utc']) <= release_at <= instant(released['utc']) <= start_end:
            raise ValueError('probe release is outside startup order')
        attempts = [row for row in events if row.get('event') == 'connect_attempt' and
                    row.get('pid') == pid and row.get('dst') == '198.51.100.77:443' and
                    str(row.get('connection_id', '')).startswith(nonce + '-') and
                    release_at <= instant(row['utc']) <= min(start_end, failure_at)]
        if not attempts:
            raise ValueError('no same-probe A connect during startup')
        native_rows = []
        for line in etw_path.read_text(encoding='utf-8-sig').splitlines():
            row = json.loads(line)
            xml = ET.fromstring(row['xml'])
            provider = xml.find('.//{*}Provider')
            if (provider is None or provider.get('Name') != 'Microsoft-Windows-Kernel-Network' or
                    xml.findtext('.//{*}Task') != '10'):
                continue
            data = {item.get('Name'): item.text for item in xml.findall('.//{*}EventData/{*}Data')}
            if not all(data.get(key) for key in ('PID', 'daddr', 'dport', 'sport')):
                continue
            dst = str(ipaddress.IPv4Address(int(data['daddr']).to_bytes(4, 'little')))
            port = int.from_bytes(int(data['dport']).to_bytes(2, 'little'), 'big')
            source_port = int.from_bytes(int(data['sport']).to_bytes(2, 'little'), 'big')
            when = instant(xml.find('.//{*}TimeCreated').get('SystemTime'))
            if (int(data['PID']) == pid and dst == target['host'] and port == 443 and
                    0 < source_port < 65536 and any(instant(attempt['utc']) <= when <= min(start_end, failure_at)
                                                    for attempt in attempts)):
                native_rows.append({'ordinal': row['ordinal'], 'pid': pid,
                                    'source_port': source_port, 'target': dst + ':443',
                                    'utc': when.isoformat()})
        if not native_rows:
            raise ValueError('no same-PID native A TCP event during startup')
        from scenario_tcpip import (byte_records, parse_line, reconstruct_generations,
                                    validate_capture)
        from sst_fault_evidence import time_bounds
        pktmon = _pktmon_module()
        pktmon_raw = pktmon_path.read_bytes()
        pktmon_etl = (root / records['pktmon.etl']['path']).read_bytes()
        nic = read_json(root / records['pktmon-nic.json']['path'])
        nic_issues = pktmon_capture_issues(nic, pktmon_raw)
        if nic_issues or pktmon_nic_binding(nic) != capture.get('pktmon_binding'):
            raise ValueError('bound physical NIC capture is incomplete or differs')
        validate_capture(pktmon_raw, pktmon_etl, nic, 50_000_000)
        packet_rows = pktmon.parse_packets(pktmon_raw)
        native_lines = [(text, ref) for text, ref in byte_records(pktmon_raw,
                        records['pktmon.txt']['path']) if '[Microsoft-Windows-TCPIP] TCP:' in text]
        request_events = []
        for text, ref in native_lines:
            if 'requested to connect.' not in text or 'remote=198.51.100.77:443' not in text:
                continue
            event = parse_line(text, ref)
            if event and event.get('kind') == 'requested to connect':
                request_events.append(event)
        if not request_events:
            raise ValueError('no native A TCP request')
        release_ns = time_bounds(run['probe_release']['released_utc'])[0]
        failure_ns = time_bounds(run.get('refusal_failure_utc') or run['started_at'])[1]
        creation_ns = (creation - 621355968000000000) * 100
        finished = [row for row in events if row.get('event') == 'finished' and row.get('pid') == pid]
        if len(finished) != 1:
            raise ValueError('probe process terminal identity is missing')
        finished_ns = time_bounds(finished[0]['utc'])[0]
        if not creation_ns <= release_ns < failure_ns < finished_ns:
            raise ValueError('probe process lifetime does not contain refusal')
        native_proofs = []
        for request in request_events:
            source_port = int(request['local'].rsplit(':', 1)[1])
            matching_etw = [row for row in native_rows if row['source_port'] == source_port]
            if not matching_etw:
                continue
            tcb = request['tcb']
            tcb_events = [parse_line(text, ref) for text, ref in native_lines
                          if tcb.lower() in text.lower()]
            groups = reconstruct_generations(tcb_events)
            selected = [group for group in groups if request in group['events']]
            if len(selected) != 1:
                raise ValueError('A request has ambiguous TCB generation')
            group = selected[0]
            if (group['identity'] != {'local': request['local'],
                                     'remote': '198.51.100.77:443', 'pid': pid} or
                    group['birth_ref'] is None):
                raise ValueError('A request lacks exact PID/tuple/native TCB birth')
            syns = [row for row in group['events'] if
                    ' is going to output SYN with ISN = ' in row['text']]
            if len(syns) != 1:
                raise ValueError('A generation lacks unique native output SYN')
            syn = syns[0]
            if not (group['birth_ref']['byte_start'] < request['ref']['byte_start'] <
                    syn['ref']['byte_start'] and
                    (group['closed_ref'] is None or syn['ref']['byte_start'] <
                     group['closed_ref']['byte_start'])):
                raise ValueError('A TCB birth/request/SYN lifecycle order differs')
            request_ns = time_bounds(request['text'])[0]
            syn_ns = time_bounds(syn['text'])[0]
            if not (creation_ns <= release_ns <= request_ns <= syn_ns <= failure_ns):
                raise ValueError('A TCB SYN is outside live pre-refusal window')
            if not any(time_bounds(item['utc'])[0] <= request_ns for item in attempts):
                raise ValueError('A TCB request lacks preceding probe connect intent')
            etw = next((row for row in matching_etw if
                        syn_ns <= time_bounds(row['utc'])[0] <= failure_ns and
                        time_bounds(row['utc'])[0] < finished_ns), None)
            if etw is None:
                raise ValueError('A TCB SYN lacks same-port live-PID ETW corroboration')
            isn = re.search(r'output SYN with ISN = (\d+)', syn['text'])
            if isn is None:
                raise ValueError('native output SYN lacks ISN')
            try:
                packets = pktmon.select_packets(packet_rows, request['local'],
                    request['remote'], 'TCP',
                    component_ids=capture['pktmon_binding']['component_ids'], direction='Tx')
            except pktmon.PacketEvidenceError as exc:
                raise ValueError('A SYN NIC tuple is ambiguous') from exc
            matched_packets = []
            for packet in packets:
                if packet.get('flags') != 'S' or not packet.get('timestamp_local'):
                    continue
                packet_ns = time_bounds('::' + packet['timestamp_local'])[0]
                if not syn_ns <= packet_ns <= min(syn_ns + 50_000_000, failure_ns):
                    continue
                block = pktmon_raw[packet['byte_start']:packet['byte_end']].decode(
                    'utf-16-le' if pktmon_raw.startswith(b'\xff\xfe') else 'utf-8')
                if not re.search(r'\bseq ' + re.escape(isn[1]) + r'\b', block):
                    continue
                matched_packets.append(packet)
            if not matched_packets:
                raise ValueError('A TCB SYN has no same-ISN bound-NIC packet')
            packet = matched_packets[0]
            native_proofs.append({'tcb': tcb, 'generation_ordinal': group['ordinal'],
                                  'source': request['local'], 'target': request['remote'],
                                  'birth_ref': group['birth_ref'], 'request_ref': request['ref'],
                                  'syn_ref': syn['ref'], 'syn_isn': int(isn[1]),
                                  'syn_utc_ns': syn_ns, 'etw': etw,
                                  'nic_packet_ref': {'path': records['pktmon.txt']['path'],
                                                     'byte_start': packet['byte_start'],
                                                     'byte_end': packet['byte_end']}})
        if not native_proofs:
            raise ValueError('no same-generation native A SYN/ETW/NIC packet')
        return {'kind': 'approved-active-a-refusal-v2', 'nonce': nonce, 'pid': pid,
                'creation_ticks': creation, 'probe': records['probe.jsonl'],
                'native_events': records['kernel-network.events.jsonl'],
                'native_etl': records['kernel-network.etl'],
                'native_tcp_count': len(native_rows), 'syn_proofs': native_proofs,
                'traffic_status': 'NOT_EXECUTED', 'mib_row_uniqueness': 'NOT_OBSERVED'}

    def _expected_quiescence_refusal(self, started: dict[str, Any],
                                     profile: dict[str, Any], *, run: dict[str, Any] | None = None,
                                     nonce: str | None = None) -> dict[str, Any] | None:
        """Return the recorded refusal when it is this family's exact outcome."""
        if not self._is_quiescence_refusal_family(profile):
            return None
        status = self._status()
        reason = str(status.get('failure_reason') or '')
        if profile.get('probe_target', {}).get('process_mode') == 'nonmatch':
            if (started.get('state') != 'stopped' or started.get('run_id') is not None or
                    started.get('last_run_outcome') != 'failed' or
                    status.get('state') != 'stopped' or status.get('run_id') is not None or
                    status.get('controller') is not None or status.get('last_run_outcome') != 'failed' or
                    not reason.startswith('managed start failed: RuntimeError(') or
                    self._ACTIVE_A_REFUSAL_MARKER not in reason or run is None or nonce is None):
                return None
            samples = run.get('refusal_status_samples') or []
            if (len(samples) != 3 or any(
                    item.get('state') != 'stopped' or item.get('run_id') is not None or
                    item.get('controller') is not None or item.get('last_run_outcome') != 'failed' or
                    self._ACTIVE_A_REFUSAL_MARKER not in str(item.get('failure_reason') or '')
                    for item in samples)):
                return None
            try:
                proof = self._active_a_refusal_proof(self.root, profile, nonce, run)
            except (ValueError, KeyError, OSError, TypeError, ET.ParseError):
                return None
            return {'reason': reason, 'state': status['state'], 'run_id': None,
                    'marker': self._ACTIVE_A_REFUSAL_MARKER, 'proof': proof,
                    'traffic_status': 'NOT_EXECUTED'}
        if (started.get('state') != 'healthy' and
                self._QUIESCENCE_REFUSAL_MARKER in reason):
            if run is not None:
                samples = run.get('refusal_status_samples') or []
                if (status.get('state') != 'stopped' or status.get('run_id') is not None or
                        len(samples) != 3 or any(item.get('state') != 'stopped' or
                        item.get('run_id') is not None for item in samples)):
                    return None
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
        auxiliary_qpc = None
        if getattr(self, 'auxiliary_clock_evidence', 'utc-v1') in AUX_QPC_MODES:
            try:
                import scenario_aux_qpc_contract as aux_contract
                planned_auxiliary = (list(profile.get('negative_cases', ())) +
                                     list(profile.get('probe_cases', ())))
                if any(case.get('protocol') != 'udp' for case in planned_auxiliary):
                    auxiliary_qpc = aux_contract.evaluate(run, self.root,
                        expected_candidate=self.identity.candidate_id, expected_nonce=nonce,
                        expected_mode=self.auxiliary_clock_evidence)
                else:
                    auxiliary_qpc = aux_contract.no_tcp_applicability(run, self.root, profile,
                        expected_candidate=self.identity.candidate_id, expected_nonce=nonce)
            except Exception as exc:  # noqa: BLE001 - native proof fails closed
                return {'passed': False, 'reason': 'auxiliary native QPC original rejected: ' + str(exc)}
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
                if capture.get('observation_contract') in ('con008', 'con008-shared-v2') else self._fault_primary_observation(run,event,nonce))
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
                if capture.get('observation_contract') in ('con008', 'con008-shared-v2') and not dropped_attempt:
                    # A silently dropped attempt has no completed TCP connect
                    # by construction; the pktmon send records plus the drop
                    # policy line are its whole evidence.
                    try:
                        terminals=[row for row in case_events if row.get('connection_id')==first.get('connection_id') and row.get('event') in ('case_error','case_eof','case_close')]
                        case_observation=self._application_observation(run,first,terminals,nonce,':'.join(source),':'.join(target),case_protocol, include_begin_bound=(planned['expectation'] == 'deny' and planned['protocol'] == 'tls'), **({'auxiliary_qpc': auxiliary_qpc} if auxiliary_qpc is not None else {}))
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
                            first, source, target, planned, case_observation)
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
                if capture.get('observation_contract') in ('con008', 'con008-shared-v2'):
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
                        if capture.get('observation_contract') in ('con008', 'con008-shared-v2'):
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
                        if capture.get('observation_contract') in ('con008', 'con008-shared-v2'):
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
        legacy_utc_passed = passed and all(
            (row.get('connection_observation') or {}).get(
                'legacy_utc_zero_constraint_passed', True)
            for row in case_results)
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
                'auxiliary_native_qpc': auxiliary_qpc,
                'legacy_utc_traffic_passed': legacy_utc_passed if auxiliary_qpc else None,
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

    def _require_qpc_guest_python(self) -> None:
        """Check the real guest interpreter before any scenario mutation."""
        value, _ = self._vm_json(
            "$ErrorActionPreference='Stop';$p='C:\\Python313\\python.exe';"
            "if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw 'QPC Python313 absent'};"
            "$v=(& $p -c 'import sys;print(sys.version_info[:2])' | Out-String).Trim();"
            "@{path=$p;version=$v;computer=$env:COMPUTERNAME}|ConvertTo-Json -Compress", 60)
        if value.get('path') != r'C:\Python313\python.exe' or value.get('version') != '(3, 13)' or \
                value.get('computer') != 'DESKTOP-3FI41GR':
            raise Blocked('QPC diagnostic guest interpreter or VM identity differs')

    def _recover_qpc_guest_process(self, guest: str, run_id: str, source_sha: str,
                                   program_name: str = 'scenario_qpc_diagnostic.py') -> dict[str, Any]:
        """Reconcile only the diagnostic launched under this unique guest root."""
        program = guest + '\\input\\tools\\' + program_name
        output = guest + r'\export'
        command = (
            "$ErrorActionPreference='Stop';# qpc-responsibility-recover\n"
            "$r=" + quote_ps(guest) + ";$run=" + quote_ps(run_id) +
            ";$sha=" + quote_ps(source_sha) + ";$program=" + quote_ps(program) +
            ";$out=" + quote_ps(output) + ";$p='C:\\Python313\\python.exe';"
            "$ownerPath=Join-Path $r 'process-responsibility.json';"
            "$owner=$null;if(Test-Path -LiteralPath $ownerPath){"
            "$owner=Get-Content -LiteralPath $ownerPath -Raw|ConvertFrom-Json;"
            "if($owner.run_id -ne $run -or $owner.input_sha256 -ne $sha -or"
            " $owner.program -ne $program -or $owner.output -ne $out){throw 'QPC owner mismatch'}};"
            "$target=$null;"
            "if($owner){$current=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $owner.pid);"
            "if(!$current -or $current.CreationDate.ToUniversalTime().ToFileTimeUtc()"
            " -ne $owner.creation_filetime_100ns)"
            "{@{state='recovered_exited';exit_proven=$true;"
            "pid=$owner.pid;creation_filetime_100ns=$owner.creation_filetime_100ns;"
            "guest_root=$r;reason='original PID/creation no longer running'}|ConvertTo-Json -Compress;return};"
            "if($current.ExecutablePath -ne $p -or !$current.CommandLine -or"
            " !$current.CommandLine.Contains($program) -or !$current.CommandLine.Contains($out)"
            " -or $current.CommandLine -ne $owner.command_line)"
            "{@{state='unknown';exit_proven=$false;guest_root=$r;"
            "reason='owner command differs'}|ConvertTo-Json -Compress;return};"
            "$target=$current}else{$matches=@(Get-CimInstance Win32_Process|Where-Object {"
            "$_.ExecutablePath -eq $p -and $_.CommandLine -and"
            " $_.CommandLine.Contains($program) -and $_.CommandLine.Contains($out)});"
            "if($matches.Count -ne 1){@{state='unknown';exit_proven=$false;"
            "reason='no unique exact diagnostic process';guest_root=$r}|ConvertTo-Json -Compress;return};"
            "$target=$matches[0]};$pidValue=[int]$target.ProcessId;"
            "$created=[int64]$target.CreationDate.ToUniversalTime().ToFileTimeUtc();"
            "Stop-Process -Id $pidValue -Force -ErrorAction Stop;"
            "$still=@(Get-CimInstance Win32_Process -Filter ('ProcessId=' + $pidValue)|"
            "Where-Object {$_.CreationDate.ToUniversalTime().ToFileTimeUtc() -eq $created});"
            "@{state=$(if($still.Count -eq 0){'recovered_terminated'}else{'unknown'});"
            "exit_proven=($still.Count -eq 0);pid=$pidValue;creation_filetime_100ns=$created;"
            "guest_root=$r;reason='exact diagnostic process reconciliation'}|ConvertTo-Json -Compress")
        try:
            value, raw = self._vm_json(command, 120)
            value['recovery_raw'] = raw
            return value
        except Exception as exc:  # noqa: BLE001 - unproven exit blocks continuation
            return {'state': 'unknown', 'exit_proven': False, 'guest_root': guest,
                    'recovery_error': repr(exc)}

    def _collect_qpc_export(self, base_path: Path, base: dict[str, Any], root: Path,
                            evidence: Evidence, run_id: str,
                            program_name: str = 'scenario_qpc_diagnostic.py') -> None:
        """Export complete ETL after cleanup; seal guest output before verdict."""
        bundle = root / 'qpc-input.zip'
        if program_name not in ('scenario_qpc_diagnostic.py', 'scenario_aux_qpc_diagnostic.py',
                                'scenario_aux_qpc_v2.py'):
            raise SuiteError('unsupported QPC diagnostic program')
        scripts = ('scenario_qpc_diagnostic.py', 'scenario_aux_qpc_diagnostic.py',
                   'scenario_qpc_identity.py',
                   'etl_raw_clock.py', 'tdh_metadata.py', 'scenario_tcpip.py',
                   'scenario_clock.py', 'sst_fault_evidence.py')
        if program_name in ('scenario_aux_qpc_diagnostic.py', 'scenario_aux_qpc_v2.py'):
            scripts += ('scenario_qpc_offline.py',)
        if program_name == 'scenario_aux_qpc_v2.py':
            scripts += ('scenario_aux_qpc_v2.py', 'scenario_aux_qpc_single_pass.py', 'scenario_aux_qpc_offline.py',
                        'scenario_aux_qpc_contract.py')
        with zipfile.ZipFile(bundle, 'x', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=False) as archive:
            for item in base['files']:
                path = (self.root / item['path']).resolve()
                if not path.is_relative_to(self.root) or not path.is_file():
                    raise SuiteError('QPC base input path missing or escaping')
                archive.write(path, 'evidence/' + item['path'])
            archive.write(base_path, 'evidence/' + str(base_path.relative_to(self.root)))
            for name in scripts:
                archive.write(Path(__file__).with_name(name), 'tools/' + name)
        evidence.add(bundle)
        if bundle.stat().st_size > MAX_GUEST_TRANSFER:
            raise SuiteError('QPC input exceeds host-only transfer bound')
        scope_key = str(self.root) + run_id + (
            program_name if program_name != 'scenario_qpc_diagnostic.py' else '')
        scope = hashlib.sha256(scope_key.encode()).hexdigest()[:20]
        guest = self.guest_work_root + r'\qpc-contract-' + scope
        guest_case = guest + '\\input\\evidence\\' + str(base_path.relative_to(self.root)).replace('/', '\\')
        source_sha = file_record(bundle, self.root)['sha256']
        responsibility = root / 'qpc-process-responsibility.json'
        write_new_json(responsibility, {
            'schema': 'sst.qpc-process-responsibility.v1', 'run_id': run_id,
            'guest_root': guest, 'input_sha256': source_sha,
            'program': guest + '\\input\\tools\\' + program_name,
            'output': guest + r'\export', 'python': r'C:\Python313\python.exe',
            'inner_wait_seconds': QPC_EXPORT_WAIT_SECONDS,
            'rpc_timeout_seconds': QPC_EXPORT_RPC_SECONDS,
            'state': 'pending', 'created_at': utc_now()})
        evidence.add(responsibility)
        guest_error: Exception | None = None
        value: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        with HostOnlyFileTransfer(bundle, 'qpc-input.zip') as transfer:
            command = (
                "$ErrorActionPreference='Stop';$r=" + quote_ps(guest) +
                ";if(Test-Path -LiteralPath $r){throw 'QPC guest evidence collision'};"
                "[void](New-Item -ItemType Directory -Path $r);"
                "$zip=Join-Path $r 'input.zip';$web=New-Object Net.WebClient;$web.Proxy=$null;"
                "$web.DownloadFile(" + quote_ps(transfer.url) + ",$zip);"
                "if((Get-FileHash $zip -Algorithm SHA256).Hash.ToLower() -ne " + quote_ps(source_sha) +
                "){throw 'QPC input hash mismatch'};"
                "Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $r 'input');"
                "$p='C:\\Python313\\python.exe';if(!(Test-Path -LiteralPath $p -PathType Leaf))"
                "{throw 'QPC Python313 absent'};"
                "$program=Join-Path $r " + quote_ps('input\\tools\\' + program_name) + ";"
                "$out=Join-Path $r 'export';$stdout=Join-Path $r 'stdout.txt';"
                "$stderr=Join-Path $r 'stderr.txt';"
                "$run=" + quote_ps(run_id) + ";$sha=" + quote_ps(source_sha) + ";"
                "$proc=Start-Process -FilePath $p -ArgumentList @($program,'--case'," + quote_ps(guest_case) +
                ",'--evidence-root',(Join-Path $r 'input\\evidence'),'--output',$out)"
                " -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr;"
                "$native=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $proc.Id);"
                "if(!$native -or $native.ExecutablePath -ne $p -or !$native.CommandLine -or"
                " !$native.CommandLine.Contains($program) -or !$native.CommandLine.Contains($out))"
                "{throw 'QPC child native identity/command unavailable'};"
                "$created=[int64]$native.CreationDate.ToUniversalTime().ToFileTimeUtc();"
                "$owner=[ordered]@{schema='sst.qpc-guest-process.v1';run_id=$run;"
                "input_sha256=$sha;pid=[int]$proc.Id;creation_filetime_100ns=$created;"
                "executable_path=$native.ExecutablePath;command_line=$native.CommandLine;"
                "program=$program;output=$out;started_utc=[DateTime]::UtcNow.ToString('o')};"
                "$ownerPath=Join-Path $r 'process-responsibility.json';"
                "$owner|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ownerPath;"
                "$deadline=[DateTime]::UtcNow.AddSeconds(" + str(QPC_EXPORT_WAIT_SECONDS) + ");"
                "while(!$proc.HasExited -and [DateTime]::UtcNow -lt $deadline)"
                "{$null=$proc.WaitForExit(1000);$proc.Refresh()};"
                "$timedOut=!$proc.HasExited;"
                "if($timedOut){$current=Get-CimInstance Win32_Process -Filter ('ProcessId=' + $proc.Id);"
                "if($current -and $current.CreationDate.ToUniversalTime().ToFileTimeUtc() -eq $created"
                " -and $current.ExecutablePath -eq $p -and $current.CommandLine -eq $native.CommandLine)"
                "{Stop-Process -Id $proc.Id -Force;$null=$proc.WaitForExit(10000);$proc.Refresh()}};"
                "$exited=[bool]$proc.HasExited;"
                "$state=if(!$exited){'unknown'}elseif($timedOut){'timeout_terminated'}else{'exited'};"
                "$code=if($exited){$proc.ExitCode}else{$null};"
                "$terminal=[ordered]@{schema='sst.qpc-guest-terminal.v1';"
                "computer=$env:COMPUTERNAME;run_id=$run;input_sha256=$sha;"
                "pid=[int]$proc.Id;creation_filetime_100ns=$created;"
                "executable_path=$native.ExecutablePath;command_line=$native.CommandLine;"
                "program=$program;output=$out;state=$state;exit_proven=$exited;"
                "timed_out=$timedOut;exit_code=$code;utc=[DateTime]::UtcNow.ToString('o')};"
                "$terminal|ConvertTo-Json -Depth 8|Set-Content (Join-Path $r 'terminal.json');"
                "$outputZip=Join-Path $r 'output.zip';"
                "Compress-Archive -Path $out,$stdout,$stderr,$ownerPath,(Join-Path $r 'terminal.json')"
                " -DestinationPath $outputZip;"
                "@{computer=$env:COMPUTERNAME;exit_code=$code;process=$terminal;"
                "bytes=(Get-Item $outputZip).Length;sha256=(Get-FileHash $outputZip -Algorithm SHA256).Hash.ToLower();"
                "path=$outputZip;input_sha256=(Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()}"
                "|ConvertTo-Json -Compress")
            try:
                value, raw = self._vm_json(command, QPC_EXPORT_RPC_SECONDS)
            except Exception as exc:  # noqa: BLE001 - preserve transfer evidence
                guest_error = exc
        transfer_record = transfer.record()
        write_new_json(root / 'qpc-transfer.json', {'guest': value, 'raw': raw,
                                                    'error': repr(guest_error) if guest_error else None,
                                                    'host_only_transfer': transfer_record})
        evidence.add(root / 'qpc-transfer.json')
        process = value.get('process')
        expected_program = guest + '\\input\\tools\\' + program_name
        expected_output = guest + r'\export'
        normal_exit = (isinstance(process, dict)
            and process.get('schema') == 'sst.qpc-guest-terminal.v1'
            and process.get('computer') == 'DESKTOP-3FI41GR'
            and process.get('run_id') == run_id
            and process.get('input_sha256') == source_sha
            and process.get('program') == expected_program
            and process.get('output') == expected_output
            and process.get('executable_path') == r'C:\Python313\python.exe'
            and type(process.get('pid')) is int and process['pid'] > 0
            and type(process.get('creation_filetime_100ns')) is int
            and process['creation_filetime_100ns'] > 0
            and isinstance(process.get('command_line'), str)
            and expected_program in process['command_line']
            and expected_output in process['command_line']
            and process.get('state') in ('exited', 'timeout_terminated')
            and process.get('exit_proven') is True)
        settlement = (process if normal_exit else
                      self._recover_qpc_guest_process(guest, run_id, source_sha,
                                                      program_name))
        exit_proven = (normal_exit or
            (settlement.get('exit_proven') is True
             and settlement.get('guest_root') == guest
             and settlement.get('state') in ('recovered_exited', 'recovered_terminated')))
        process_terminal = root / 'qpc-process-terminal.json'
        write_new_json(process_terminal, {
            'schema': 'sst.qpc-host-process-terminal.v1', 'run_id': run_id,
            'guest_root': guest, 'input_sha256': source_sha,
            'exit_proven': exit_proven, 'settlement': settlement,
            'guest_error': repr(guest_error) if guest_error else None,
            'recorded_at': utc_now()})
        evidence.add(process_terminal)
        if not exit_proven:
            raise SuiteError('QPC diagnostic process exit unproven; guest-only root: ' + guest)
        if guest_error:
            raise guest_error
        if (transfer_record['stopped'] is not True or
                len(transfer_record['requests']) != 1 or
                transfer_record['requests'][0].get('status') != 200 or
                value.get('computer') != 'DESKTOP-3FI41GR' or
                value.get('input_sha256') != source_sha):
            raise SuiteError('QPC guest identity or host-only input transfer differs')
        output_zip = root / 'qpc-output.zip'
        if program_name == 'scenario_aux_qpc_v2.py':
            self._transfer_guest_file(str(value['path']), int(value['bytes']),
                                      str(value['sha256']), output_zip,
                                      auxiliary_v2_output=True)
        else:
            self._transfer_guest_file(str(value['path']), int(value['bytes']),
                                      str(value['sha256']), output_zip)
        evidence.add(output_zip)
        destination = root / 'qpc-native'
        if program_name != 'scenario_aux_qpc_v2.py':
            destination.mkdir(exist_ok=False)
        extract_qpc_archive(output_zip, destination, evidence,
                            auxiliary_v2=program_name == 'scenario_aux_qpc_v2.py')
        terminal = read_json(destination / 'terminal.json')
        owner = read_json(destination / 'process-responsibility.json')
        manifest = read_json(destination / 'export' / 'manifest.json')
        if (terminal != process or owner.get('pid') != terminal.get('pid') or
                owner.get('creation_filetime_100ns') != terminal.get('creation_filetime_100ns') or
                owner.get('command_line') != terminal.get('command_line') or
                owner.get('run_id') != run_id or owner.get('input_sha256') != source_sha):
            raise SuiteError('QPC guest owner/terminal original differs from VM response')
        if (value.get('exit_code') != 0 or terminal.get('exit_code') != 0 or
                terminal.get('state') != 'exited' or
                manifest.get('status') != 'COMPLETE_DIAGNOSTIC_ONLY'):
            raise SuiteError('QPC Windows export incomplete: ' + repr(manifest.get('error')))

    def _collect_auxiliary_qpc(self, run: dict[str, Any], nonce: str,
                               root: Path, evidence: Evidence,
                               profile: dict[str, Any]) -> None:
        """Seal one run's exact auxiliary generations and native proof."""
        planned = list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ()))
        if not any(case.get('protocol') != 'udp' for case in planned):
            import scenario_aux_qpc_contract as aux_contract
            aux_contract.no_tcp_applicability(run, self.root, profile,
                expected_candidate=self.identity.candidate_id, expected_nonce=nonce)
            return
        import scenario_tcpip as tcpip
        files = run['capture']['files'] + run['originals']['files']
        shared_capture = None
        if run['capture'].get('observation_contract') == 'con008-shared-v2':
            owner = run['capture'].get('physical_owner')
            view = run['capture'].get('run_view')
            if not owner or not view:
                raise SuiteError('auxiliary QPC shared owner/view absent')
            files += [owner, view]
            shared_capture = {'owner': owner, 'view': view}
            if run['label'] == 'run-02':
                receipts = [item for item in files
                            if Path(item['path']).name == 'probe-launch.json']
                if len(receipts) != 1:
                    raise SuiteError('auxiliary QPC shared second launch absent/ambiguous')
                shared_capture['launch'] = receipts[0]
        by_name = {Path(item['path']).name: item for item in files}
        required = ('probe.jsonl', 'pktmon.txt', 'pktmon.etl', 'pktmon-nic.json',
                    'run.log', 'ipc-parent.jsonl')
        if len(by_name) != len(files) or any(name not in by_name for name in required):
            raise SuiteError('auxiliary QPC original file set missing/ambiguous')
        def payload(name: str) -> bytes:
            record = by_name[name]
            path = (self.root / record['path']).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise SuiteError('auxiliary QPC original path invalid')
            raw = path.read_bytes()
            if len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
                raise SuiteError('auxiliary QPC original hash changed: ' + name)
            return raw
        probe = payload('probe.jsonl')
        raw_text = payload('pktmon.txt')
        log = payload('run.log').decode('utf-8-sig')
        ipc = [json.loads(line) for line in payload('ipc-parent.jsonl').splitlines()]
        managed_pid, _ = tcpip.managed_identity(ipc, run['run_id'])
        cases = []
        position = 0
        probe_records = []
        for line in probe.splitlines(keepends=True):
            row = json.loads(line)
            ref = {'path': by_name['probe.jsonl']['path'], 'byte_start': position,
                   'byte_end': position + len(line), 'event_key': 'json:'}
            probe_records.append((row, ref))
            if row.get('event') == 'case_established' and row.get('nonce') == nonce:
                src, dst = row.get('src'), row.get('actual_dst') or row.get('dst')
                if not src or not dst or not row.get('connection_id'):
                    raise SuiteError('auxiliary QPC probe tuple/connection missing')
                observed = tcpip.connection_events(raw_text, by_name['pktmon.txt']['path'], log,
                    row['pid'], src, dst, managed_pid, log_path=by_name['run.log']['path'])
                cases.append({'case_index': row['case_index'],
                    'connection_id': row['connection_id'], 'pid': row['pid'],
                    'src': src, 'dst': dst,
                    'probe_ref': ref,
                    'connection_refs': [event['ref'] for event in observed['events']],
                    'tuple_terminal_refs': [event['ref'] for event in observed['tuple_terminals']],
                    'generation_manifest': observed['generation_manifest']})
            position += len(line)
        for item in cases:
            item['end_refs'] = [ref for row, ref in probe_records
                if row.get('nonce') == nonce and row.get('pid') == item['pid']
                and row.get('connection_id') == item['connection_id']
                and row.get('event') in ('case_error', 'case_eof', 'case_close')]
            if not item['end_refs']:
                raise SuiteError('auxiliary QPC probe terminal missing')
        if not cases:
            raise SuiteError('auxiliary QPC established TCP case absent')
        if len({(item['case_index'], item['connection_id']) for item in cases}) != len(cases):
            raise SuiteError('auxiliary QPC duplicate established case')
        native_root = root / run['label'] / 'auxiliary-qpc'
        native_root.mkdir(parents=True, exist_ok=False)
        meta = by_name['pktmon-nic.json']
        descriptor = {'schema': 'sst.aux-qpc-input.v1',
                      'candidate_id': self.identity.candidate_id,
                      'run_id': run['run_id'], 'nonce': nonce,
                      'files': [{'path': item['path'], 'bytes': item['size'],
                                 'sha256': item['sha256']} for item in files],
                      'capture': {'etl_path': by_name['pktmon.etl']['path'],
                                  'text_path': by_name['pktmon.txt']['path'],
                                  'metadata_ref': {'path': meta['path'], 'byte_start': 0,
                                                   'byte_end': meta['size'], 'event_key': 'json:'}},
                      'run_log_path': by_name['run.log']['path'],
                      'ipc_path': by_name['ipc-parent.jsonl']['path'],
                      'cases': cases}
        if shared_capture is not None:
            descriptor['shared_capture'] = shared_capture
        descriptor_path = native_root / 'auxiliary-qpc-input.json'
        write_new_json(descriptor_path, descriptor)
        evidence.add(descriptor_path)
        try:
            program = ('scenario_aux_qpc_v2.py' if getattr(
                       self, 'auxiliary_clock_evidence', AUX_QPC_MODE) ==
                       AUX_QPC_V2_MODE else 'scenario_aux_qpc_diagnostic.py')
            self._collect_qpc_export(descriptor_path, descriptor, native_root, evidence,
                                     run['run_id'], program)
            import scenario_aux_qpc_offline as auxiliary_offline
            derived_root = native_root / 'qpc-rejudge'
            auxiliary_offline.derive(descriptor_path, self.root,
                                     native_root / 'qpc-native/export', derived_root)
            proof_path = derived_root / 'derived.json'
            evidence.add(proof_path)
            run['auxiliary_qpc_proof'] = file_record(proof_path, self.root)
        finally:
            run['auxiliary_qpc_process'] = {
                name: file_record(native_root / name, self.root)
                for name in ('qpc-process-responsibility.json',
                             'qpc-process-terminal.json', 'qpc-transfer.json')
                if (native_root / name).is_file()}

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
        if fault == 'diverter_stop' and self.fault_clock_evidence == QPC_MODE:
            import scenario_fault_evidence as adapter
            base = adapter.build_case(self.root, descriptor)
            if base.get('schema') != 'sst.fault-evidence.case.v2':
                raise SuiteError('QPC export requires frozen tcpip_etw base-v2 case')
            base_path = root / 'fault-evidence-base-v2.case.json'
            write_new_json(base_path, base)
            evidence.add(base_path)
            try:
                self._collect_qpc_export(base_path, base, root, evidence, run['run_id'])
            finally:
                run['qpc_export_process'] = {
                    name: file_record(root / name, self.root)
                    for name in ('qpc-process-responsibility.json',
                                 'qpc-process-terminal.json', 'qpc-transfer.json')
                    if (root / name).is_file()}
            descriptor['clock_evidence_mode'] = QPC_MODE
            descriptor['base_case_path'] = str(base_path.relative_to(self.root))
            descriptor['qpc_export_prefix'] = str((root / 'qpc-native' / 'export').relative_to(self.root))
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
                 'endpoint-lifetimes.json', 'relay-native-events.jsonl')
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
            outcome = self.service.tool_outcome(tool, sent, timeout=lifecycle_rpc_timeout(tool))
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
            "$probe=" + quote_ps(capture['probe']) + ";$launcher=" + str(int(capture['pid'])) + ";$started=[DateTimeOffset]::UtcNow;$deadline=[DateTime]::UtcNow.AddSeconds(60);$latched=$null;$seen=0;$iter=0;$names=@();$estAt=$null;"
            "$answer=[ordered]@{fault=" + quote_ps(fault) + ";nonce=" + quote_ps(nonce) + ";ready=$false;launcher_pid=$launcher;probe_pid=$null;run_id=$null;established=$null;process_flow=$null;ready_published_utc=$null;child=$null;child_parent=$null;observer_started_utc=$started.ToString('o');observer_deadline_utc=[DateTimeOffset]::UtcNow.AddSeconds(60).ToString('o');iterations=0;est_detected_utc=$null;names_refreshes=0;scan_attempts=0;scan_started_utc=$null};"
            # Re-parsing the probe tail on every poll made one observer
            # iteration cost ~250ms (Get-Content -Tail 200 + a ConvertFrom-Json
            # per line), so the gate released up to a quarter second after the
            # established event existed.  sst-002's server-closed upstream
            # connection lives only ~230-300ms; the diverter_stop injection
            # then fired after the relay peer teardown and the conservative
            # action interval could never sit inside the session.  Parse each
            # probe line exactly once, and enumerate the newest run dirs via
            # cmd's date-sorted dir (C-speed, ~tens of ms even with hundreds
            # of accumulated run dirs) instead of Get-ChildItem+Sort, which
            # alone cost 150-400ms per discovery on the acceptance VM.
            # Incremental byte-offset tail: read only the newly appended
            # bytes each poll instead of re-reading and re-parsing the whole
            # probe file. Whole-file ReadAllLines every 10ms over the 60s
            # window reparsed the file thousands of times and the accumulated
            # object allocations exhausted the 4GB VM's PowerShell session
            # (candidate26 fault-spike sst-015: OutOfMemoryException in the
            # gate observer).
            "$offset=0;$carry='';" +
            "while([DateTime]::UtcNow -lt $deadline){$est=$latched;"
            "if($null -eq $est -and (Test-Path -LiteralPath $probe)){"
            "try{"
            "$fs=[IO.FileStream]::new($probe,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);"
            "if($fs.Length -gt $offset){"
            "$fs.Seek($offset,[IO.SeekOrigin]::Begin)|Out-Null;"
            "$sr=[IO.StreamReader]::new($fs);"
            "$chunk=$carry+$sr.ReadToEnd();"
            "$offset=$fs.Position;"
            "$sr.Dispose();"
            "$parts=$chunk -split \"`n\";"
            "$carry=$parts[-1];"
            "for($i=0;$i -lt $parts.Count-1;$i++){"
            "$line=$parts[$i].Trim();"
            "if(-not $line){continue};"
            "try{$x=$line|ConvertFrom-Json}catch{$x=$null};"
            "if($null -ne $x -and $x.event -eq 'established' -and $x.nonce -eq " + quote_ps(nonce) + "){$est=$x;$latched=$x;break}}"
            "}else{$fs.Dispose()}}catch{}};"
            
            "$answer.iterations=$iter+1;$iter=$iter+1;if($null -ne $est -and $null -eq $estAt){$estAt=[DateTimeOffset]::UtcNow.ToString('o')};$answer.est_detected_utc=$estAt;if($null -eq $est){if(($iter % 25) -eq 1){$names=@(cmd /c dir /b /ad /o-d 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' 2>$null|Select-Object -First 8)}}elseif($names.Count -eq 0){$names=@(cmd /c dir /b /ad /o-d 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs' 2>$null|Select-Object -First 8)};""if($est){$answer.scan_attempts=$answer.scan_attempts+1;if($null -eq $answer.scan_started_utc){$answer.scan_started_utc=[DateTimeOffset]::UtcNow.ToString('o')};$probePid=[int]$est.pid;$answer.probe_pid=$probePid;$port=($est.src -split ':')[-1];$source=($est.src -split ':')[0];foreach($name in $names){$run=$name;$log='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\'+$name+'\\run.log';$flow=@();if(Test-Path -LiteralPath $log){$flow=@(Select-String -LiteralPath $log -SimpleMatch -Pattern @('PROCESS_FLOW ','PROCESS_REDIRECT_MAPPING_CREATED') -ErrorAction SilentlyContinue|Where-Object {$line=$_.Line;($line -match ('(?:^|\\s)pid='+[regex]::Escape([string]$probePid)+'(?:\\s|$)')) -and ((($line -match '(?:^|\\s)sport=') -and ($line -match ('(?:^|\\s)sport='+[regex]::Escape($port)+'(?:\\s|$)')) -and ($line -match ('(?:^|\\s)src='+[regex]::Escape($source)+'(?:\\s|$)'))) -or ((($line -match '(?:^|\\s)source_port=') -and ($line -match ('(?:^|\\s)source_port='+[regex]::Escape($port)+'(?:\\s|$)')) -and ($line -match ('(?:^|\\s)source_ipv4='+[regex]::Escape($source)+'(?:\\s|$)')))))}|Select-Object -Last 1)};if($flow.Count){$payload=[ordered]@{fault=" + quote_ps(fault) + ";nonce=" + quote_ps(nonce) + ";run_id=$name};"
            + ("$temporary=Join-Path $logs ('.fault-injection-ready-'+[guid]::NewGuid().ToString('N')+'.json');[IO.File]::WriteAllText($temporary,($payload|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false));[IO.File]::Move($temporary,$ready);"
               if fault == 'child_hang' else "") +
            "$answer.ready=$true;$answer.run_id=$name;$answer.established=$est;$answer.process_flow=$flow[0].Line;$answer.ready_published_utc=[DateTimeOffset]::UtcNow.ToString('o');if(" + quote_ps(fault) + " -eq 'child_hang'){$parent=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'fakenetng-mcp-managed.exe' -and $_.CommandLine -match ('managed-child '+[regex]::Escape($name))}|Select-Object -First 1);if($parent.Count){$child=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -eq 'fakenetng-mcp.exe' -and $_.CommandLine -match 'managed-fault-hang' -and $_.ParentProcessId -eq $parent[0].ProcessId}|Select-Object ProcessId,ParentProcessId,@{Name='CreationDate';Expression={$_.CreationDate.ToUniversalTime().ToString('o')}},Name,CommandLine -First 1);if($child.Count){$answer.child=$child[0];$answer.child_parent=$parent[0]|Select-Object ProcessId,ParentProcessId,@{Name='CreationDate';Expression={$_.CreationDate.ToUniversalTime().ToString('o')}},Name,CommandLine}}};break}}};if($answer.ready){break};Start-Sleep -Milliseconds 10};"
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
        self.native_clock_diagnostic = (self.requested_native_clock_diagnostic or
            (scenario.get('fault_class') == 'diverter_stop' and
             self.fault_clock_evidence == QPC_MODE) or
            self.auxiliary_clock_evidence in AUX_QPC_MODES)
        self.require_clients()
        preflight = self._require_preflight()
        tool_identity = self._tool_identity()
        scenario_id = scenario['scenario_id']
        result_path = self._result_path(scenario_id)
        if result_path.exists():
            previous = read_json(result_path)
            previous_mode = (previous.get('traffic_evidence') or {}).get(
                'auxiliary_clock_evidence', 'utc-v1')
            if previous_mode != self.auxiliary_clock_evidence:
                raise SuiteError('existing result uses another auxiliary clock evidence mode')
            return previous
        if ((scenario.get('fault_class') == 'diverter_stop' and self.fault_clock_evidence == QPC_MODE)
                or self.auxiliary_clock_evidence in AUX_QPC_MODES):
            self._require_qpc_guest_python()
        gate = self._continuation_gate()
        nonce = '%s-a%d-%s' % (scenario_id, attempt, uuid.uuid4().hex)
        root = self.root / 'evidence' / scenario_id / ('attempt-%02d' % attempt)
        evidence = Evidence(root)
        fault = scenario.get('fault_class')
        runtime_profile = materialize_probe_profile(scenario['config_profile'], preflight['api_ipv4'])
        shared_physical = (self.capture_contract == 'scenario-shared-v2' and
                           scenario.get('lifecycle_chain') == 'restart' and
                           runtime_profile['interleave'] != 'stop-window')
        exit_driven = (scenario.get('lifecycle_chain') == 'restart' and
                       runtime_profile['interleave'] == 'stop-window' and
                       runtime_profile['bucket'] in ('B3', 'B4') and
                       runtime_profile['probe_target'].get('process_mode') == 'nonmatch' and
                       runtime_profile['probe_target']['protocol'] == 'tcp')
        if shared_physical:
            # A run view must bind its probe to the native capture identity.
            self.native_clock_diagnostic = True
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
            nonlocal sequence, operation_unsettled
            sequence += 1
            sent = dict(arguments or {})
            command_id = None
            if mutation:
                status = self._status()
                command_id = self._command_id(scenario_id, attempt, sequence)
                sent.update(command_id=command_id,
                            expected_state_version=(status['state_version'] if forced_version is None else forced_version))
            began = time.monotonic()
            try:
                outcome = self.service.tool_outcome(  # type: ignore[union-attr]
                    tool, sent, timeout=lifecycle_rpc_timeout(tool))
            except (TimeoutError, urllib.error.URLError, ConnectionError) as exc:
                if not mutation:
                    raise
                # The request may already be executing. Bind the failed RPC
                # to its original identity before any possible cleanup.
                operation_unsettled = True
                entry = {'tool': tool, 'expect': expect, 'mutation': True,
                         'command_id': command_id, 'sent_arguments': sent,
                         'args_digest': digest(sent), 'response': None,
                         'response_digest': None, 'response_headers': None,
                         'ok': False, 'error': {'code': 'transport_unknown',
                                               'message': repr(exc)},
                         'transport_error': repr(exc),
                         'duration_seconds': time.monotonic() - began}
                calls.append(entry)
                reconciliation = reconcile_timed_out_command(
                    self.service, command_id, tool, self.service.controller_id)  # type: ignore[union-attr]
                entry['reconciliation'] = reconciliation
                evidence.write('command-timeout-%s.json' % command_id, entry)
                operation_unsettled = not reconciliation['settled']
                raise SuiteError('%s transport timed out; original command %s %s' %
                                 (tool, command_id, 'settled' if reconciliation['settled']
                                  else 'remains unknown')) from exc
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
            outcome = self.service.tool_outcome(tool, sent, timeout=lifecycle_rpc_timeout(tool))  # type: ignore[union-attr]
            entry = {'label': label, 'tool': tool, 'command_id': sent['command_id'],
                     'sent_arguments': sent, 'args_digest': digest(sent), 'response': outcome['response'],
                     'response_digest': digest(outcome['response']), 'ok': bool(outcome['ok']), 'error': outcome['error']}
            cleanup_calls.append(entry)
            if not outcome['ok'] or not isinstance(outcome['value'], dict):
                raise SuiteError('cleanup %s rejected: %r' % (label, outcome['error']))
            return outcome['value']

        def retain_recovered_start(label: str, record: dict[str, Any]) -> None:
            evidence.write(label + '-start-reconciliation.json', record)
            transferred = []
            for item in record['stop']['files']:
                destination = root / label / 'start-reconciliation' / PureWindowsPath(item['path']).name
                transferred.append(self._transfer_guest_file(
                    item['path'], item['bytes'], item['sha256'], destination))
                evidence.add(destination)
            evidence.write(label + '-start-reconciliation-transfer.json',
                           {'files': transferred})

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
            if capture.get('shared_physical'):
                run['_shared_probe_files'] = transfers
                run['probe_stopped_at'] = utc_now()
                return
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

        def seal_shared_capture(first: dict[str, Any], second: dict[str, Any]) -> None:
            """Bind two run views to the same stopped physical ETL, without changing old v1."""
            if self._tool_identity() != tool_identity:
                raise SuiteError('acceptance tool source changed during shared capture')
            primary = first.get('capture') or {}
            probe_files = second.pop('_shared_probe_files', None)
            if not isinstance(probe_files, list) or not probe_files:
                raise SuiteError('shared second probe did not close and export')
            physical_names = {'pktmon.etl', 'pktmon.txt', 'pktmon-nic.json'}
            physical = [x for x in primary.get('files', [])
                        if Path(x['path']).name in physical_names]
            if len(physical) != 3 or len({Path(x['path']).name for x in physical}) != 3:
                raise SuiteError('shared physical ETL/text/metadata incomplete')
            # The owner may already have been popped by finish_capture; its
            # start record remains immutable beside this attempt.
            start_path = root / (first['label'] + '-capture-start.json')
            owner_start = read_json(start_path)
            if (owner_start.get('physical_owner_id') != nonce + ':pktmon' or
                    not owner_start.get('etl') or owner_start.get('run_label') != 'run-01'):
                raise SuiteError('shared capture start owner identity differs')
            second_start = read_json(root / (second['label'] + '-capture-start.json'))
            if (not second_start.get('shared_physical') or
                    second_start.get('physical_owner_id') != owner_start['physical_owner_id'] or
                    second_start.get('etl') != owner_start['etl']):
                raise SuiteError('shared second probe owner/ETL differs')
            second_files = probe_files + physical
            second['capture'] = {
                'observation_contract': 'con008-shared-v2', 'label': second['label'],
                'files': second_files, 'all_components': True,
                'requested_file_size_mib': owner_start['requested_file_size_mib'],
                'probe_launcher_pid': second_start['pid'],
                'probe_path': next((x['path'] for x in probe_files
                                    if x['path'].endswith('probe.jsonl')), None),
                'pktmon_path': next(x['path'] for x in physical if x['path'].endswith('pktmon.txt')),
                'pktmon_etl_path': next(x['path'] for x in physical if x['path'].endswith('pktmon.etl')),
                'pktmon_nic_path': next(x['path'] for x in physical if x['path'].endswith('pktmon-nic.json')),
                'pktmon_binding': primary['pktmon_binding'],
                'pktmon_capture_issues': primary['pktmon_capture_issues'],
            }
            primary['observation_contract'] = 'con008-shared-v2'
            owner = {'schema': 'sst.scenario-physical-capture-owner.v2',
                     'owner_id': nonce + ':pktmon', 'nonce': nonce,
                     'scenario_id': scenario_id, 'epoch': attempt,
                     'capture_contract': self.capture_contract,
                     'guest_work_root': self.guest_work_root,
                     'tool_sha256': tool_identity['sha256'],
                     'physical_files': physical,
                     'run_ids': [first['run_id'], second['run_id']],
                     'started_utc': owner_start.get('started'),
                     'stopped_utc': first.get('capture_stopped_at')}
            owner_path = evidence.write('physical-capture-owner.json', owner)
            owner_record = file_record(owner_path, self.root)
            for run, start in ((first, owner_start), (second, second_start)):
                probe_record = next((x for x in run['capture']['files']
                                     if x['path'] == run['capture']['probe_path']), None)
                if probe_record is None:
                    raise SuiteError('shared run probe file absent')
                view = {'schema': 'sst.scenario-run-capture-view.v2',
                        'owner': owner_record, 'owner_id': owner['owner_id'],
                        'scenario_id': scenario_id, 'attempt': attempt,
                        'run_id': run['run_id'], 'label': run['label'],
                        'nonce': nonce, 'capture_run_id': nonce + ':' + run['label'],
                        'guest_work_root': self.guest_work_root,
                        'tool_sha256': owner['tool_sha256'],
                        'probe_pid': start['pid'],
                        'probe_creation_ticks': start['probe_creation_ticks'],
                        'probe': probe_record, 'physical_files': physical,
                        'capture_started_utc': owner['started_utc'],
                        'capture_stopped_utc': owner['stopped_utc']}
                path = evidence.write(run['label'] + '-capture-view.json', view)
                run['capture']['run_view'] = file_record(path, self.root)
                run['capture']['physical_owner'] = owner_record
                run['capture']['owner_id'] = owner['owner_id']
                run['capture_stopped_at'] = owner['stopped_utc']
            from scenario_capture_view import validate_shared_views
            validate_shared_views({
                'scenario_id': scenario_id, 'attempt': attempt,
                'identity': self.identity.as_dict(),
                'guest_work_root': self.guest_work_root,
                'tool_identity': tool_identity,
                'traffic_evidence': {'nonce': nonce, 'capture_views': [
                    file_record(root / item['path'], self.root) for item in evidence.items]},
                'run_chain': [first, second],
            }, self.root)

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
            try:
                captures[first_label] = (self._start_capture_and_probe(
                    guest, runtime_profile, nonce, first_label, exit_driven=True)
                    if exit_driven else self._start_capture_and_probe(
                        guest, runtime_profile, nonce, first_label))
            except RecoveredCaptureStart as recovered:
                retain_recovered_start(first_label, recovered.record)
                raise SuiteError('first capture start response lost; exact writer closed') from recovered
            except UnsettledCaptureStart:
                operation_unsettled = True
                raise
            if shared_physical:
                captures[first_label]['physical_owner_id'] = nonce + ':pktmon'
            evidence.write(first_label + '-capture-start.json', captures[first_label])
            if fault in ('listener_stop', 'diverter_stop', 'child_hang'):
                fault_evidence['arm'] = self._arm_fault(
                    fault, nonce, captures[first_label]['probe'])
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
                    if interleave == 'stop-window':
                        # run-01's stop portion lives inside the restart
                        # mutation: release its probe and boundary cases so
                        # they overlap the restart transition, and keep the
                        # capture open through it -- stopping the capture
                        # before the restart cut the probe off after one
                        # payload and the cadence chain could never hold
                        # (fakenet100 r09-run-06 sst-038). finish_capture
                        # runs after the restart converges below.
                        if exit_driven:
                            first_run['managed_exit_arm'] = self._arm_managed_exit_probe(
                                captures[first_label], first_run['run_id'], nonce)
                            evidence.write('run-01-managed-exit-arm.json', first_run['managed_exit_arm'])
                        first_run['probe_release'] = self._release_probe(
                            captures[first_label], 'stop-window')
                    second_label = 'run-02'
                    if interleave != 'stop-window':
                        try:
                            captures[second_label] = (self._start_probe_on_shared_capture(
                                guest, runtime_profile, nonce, second_label, captures[first_label])
                                if shared_physical else self._start_capture_and_probe(
                                    guest, runtime_profile, nonce, second_label))
                        except RecoveredCaptureStart as recovered:
                            retain_recovered_start(second_label, recovered.record)
                            raise SuiteError('second capture start response lost; exact writer closed') from recovered
                        except UnsettledCaptureStart:
                            operation_unsettled = True
                            raise
                        evidence.write(second_label + '-capture-start.json', captures[second_label])
                    restart_context, restart_context_raw = self._capture_sections()
                    evidence.write(second_label + '-pre-restart-context.json',
                                   {'sections': restart_context, 'raw': restart_context_raw,
                                    'role': 'active-run-context-not-recovery-baseline'})
                    # The pre-restart release depends on the interleave: for
                    # restart-window the SECOND session is released here to
                    # overlap the restart mutation; for stop-window the FIRST
                    # session's probe is the one whose release must precede
                    # run-01's stop portion inside the restart, while run-02's
                    # probe is released later at its own stop window (the
                    # stop-window branch below) -- releasing both here made
                    # the stop-window branch throw 'probe start control was
                    # already released' (fakenet100 r09 sst-005: restart +
                    # stop-window combination).
                    second_release = None if interleave == 'stop-window' else \
                        self._release_probe(captures[second_label], 'restart-window')
                    if (interleave in ('restart-window', 'during-start', 'after-healthy') and
                            runtime_profile.get('bucket') in ('B3', 'B4')):
                        # The first run's probe keeps targeting the network
                        # through the restart gap: B3 leaves live SYN rows
                        # that the quiescence gate refuses (sst-041/048), B4
                        # leaves a live UDP socket that the stop-phase
                        # restoration audit reports as dirty listen_ports
                        # (sst-058, 2026-10-01).  Its run-01 traffic evidence
                        # is already complete, so stop it cooperatively
                        # BEFORE the restart while the engine can still close
                        # its held connection.
                        first_stop = self._pre_restart_probe_stop(captures[first_label])
                        evidence.write('run-01-probe-pre-restart-stop.json', first_stop)
                    if interleave == 'stop-window':
                        # run-01's boundary cases must complete BEFORE the
                        # restart tears its session down: their policy
                        # dispositions land in run-01's own run.log, and the
                        # oracle binds them there (fakenet100 r09-run-09
                        # sst-005: post-restart cases landed in run-02's log
                        # and run-01's oracle found no policy flow).
                        self._run_auxiliary_cases(
                            first_run, captures[first_label], runtime_profile)
                        if exit_driven:
                            first_run['managed_exit_observer'] = self._await_managed_exit_observer(
                                captures[first_label], first_run['managed_exit_arm'], nonce)
                            evidence.write('run-01-managed-exit-observer.json',
                                           first_run['managed_exit_observer'])
                    # The product's health loop may be mid-protective-stop at
                    # this instant (before-start probes end their lifecycle
                    # inside the restart window; the internal stop is a
                    # legitimate concurrent transition), and the busy gate
                    # rejects the restart outright (fakenet100 r09-run-20
                    # sst-010: operation_busy, own command never registered).
                    # Retry bounded on that specific rejection -- the rejected
                    # command was never registered, so resubmitting the same
                    # command_id is a clean fresh submission.
                    restarted = None
                    for restart_attempt in range(3):
                        try:
                            restarted = call('restart', {}, mutation=True)
                            break
                        except SuiteError as restart_exc:
                            if ("'code': 'operation_busy'" not in repr(restart_exc)
                                    and 'operation_busy' not in repr(restart_exc)):
                                raise
                            if restart_attempt == 2:
                                raise
                            time.sleep(30)
                    engine_signal = self._release_restart_engine(
                        restarted, runtime_profile, captures[second_label])
                    if engine_signal is not None:
                        evidence.write('run-02-engine-ok.json', engine_signal)
                    if interleave == 'stop-window':
                        # The probe has now overlapped run-01's stop portion
                        # (the restart). Close run-01's capture BEFORE
                        # starting run-02's: pktmon runs a single capture
                        # session at a time, so an overlapping start died
                        # with the first 'pktmon stop' (fakenet100 r09-run-08
                        # sst-005: run-02 never got its pktmon.etl). run-02's
                        # active window lies entirely after the restart, so
                        # its capture starts right after this close.
                        if exit_driven:
                            first_run['managed_exit_probe_creation_ticks'] = (
                                captures[first_label]['probe_creation_ticks'])
                        finish_capture(first_label, first_run)
                        if exit_driven and restarted.get('state') == 'healthy':
                            creation = self._managed_run_creation(restarted['run_id'])
                            stop_window = self._managed_stop_window(first_run['run_id'])
                            evidence.write('run-02-managed-creation-boundary.json', creation)
                            evidence.write('run-01-managed-stop-window.json', stop_window)
                            first_run['managed_exit_order'] = self._check_exit_driven_order(
                                self._read_probe_events(self.root / first_run['capture']['probe_path']),
                                nonce, first_run['managed_exit_arm']['pid'],
                                first_run['capture']['probe_launcher_pid'],
                                first_run['managed_exit_probe_creation_ticks'],
                                creation['before_job_unix_seconds'],
                                stop_window['begin_ticks'], stop_window['end_ticks'])
                            evidence.write('run-01-managed-exit-order.json',
                                           first_run['managed_exit_order'])
                        captures[second_label] = self._start_capture_and_probe(
                            guest, runtime_profile, nonce, second_label)
                        evidence.write(second_label + '-capture-start.json', captures[second_label])
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
                    if interleave != 'stop-window':
                        # stop-window runs its auxiliary cases in the stop
                        # branch below; running them here as well released
                        # the case controls twice and the second completion
                        # wait expired (fakenet100 r09-run-03 sst-005).
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
                    fault_evidence['arm'] = self._arm_fault(
                    fault, nonce, captures[first_label]['probe'])
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
                try:
                    finish_capture(active_run['label'], active_run)
                except UnsettledCaptureStop:
                    operation_unsettled = True
                    raise
                if shared_physical:
                    try:
                        finish_capture(first_label, first_run)
                    except UnsettledCaptureStop:
                        operation_unsettled = True
                        raise
                    seal_shared_capture(first_run, active_run)
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
                refusal_continuation = (benign_refusal and
                                        scenario.get('lifecycle_chain') == 'restart')
                if refusal_continuation:
                    # The frozen plan continues a refused before-start start
                    # through the restart: the before-start probe ends its
                    # lifecycle inside the restart window by design, and the
                    # second start then succeeds (adopting a held B3 match
                    # image or ignoring a dead nonmatch one).  Follow the
                    # plan order exactly -- get_events, list_artifacts,
                    # restart, get_status x3, get_events, list_artifacts,
                    # stop -- so the strict prefix verdict holds; the refusal
                    # samples are captured as internal status reads while the
                    # service is still stopped, before the restart (sst-043,
                    # 2026-09-29).
                    pass
                elif benign_refusal:
                    # The start-stop refusal family's plan tail is sampled in
                    # order: get_status x3, then get_events, list_artifacts,
                    # stop (strict prefix semantics).
                    first_run['refusal_status_samples'] = [call('get_status') for _ in range(3)]
                else:
                    call('get_status')
                event_receipt = call('get_events', {'limit': 100})
                call('list_artifacts')
                if benign_refusal and runtime_profile['probe_target']['process_mode'] == 'nonmatch':
                    release_at = dt.datetime.fromisoformat(first_run['probe_release']['released_utc'].replace('Z', '+00:00'))
                    current_events = [item for item in event_receipt.get('events', [])
                                      if isinstance(item.get('timestamp'), (int, float)) and
                                      item['timestamp'] >= release_at.timestamp()]
                    failed_events = [item for item in current_events
                                     if item.get('kind') == 'health' and item.get('state') == 'failed' and
                                     self._ACTIVE_A_REFUSAL_MARKER in str(item.get('failure_reason') or '')]
                    if (len(failed_events) != 1 or any(item.get('state') == 'healthy' or
                            item.get('run_id') for item in current_events)):
                        raise SuiteError('nonmatch refusal lacks unique failed event or published healthy')
                    first_run['refusal_failure_utc'] = dt.datetime.fromtimestamp(
                        failed_events[0]['timestamp'], dt.timezone.utc).isoformat()
                if refusal_continuation:
                    # The refused start leaves no active run, so the plan's
                    # restart is deterministically refused by the product's
                    # own contract ('restart requires an active run'); the
                    # call is recorded and the plan tail continues, exactly
                    # as the start-stop refusal family records its refused
                    # start (sst-043, 2026-09-29).
                    first_run['refusal_status_samples'] = [self._status() for _ in range(3)]
                    # Validate and store the refusal NOW: the plan's trailing
                    # stop is an idempotent cleanup that clears the service's
                    # failure_reason, after which the marker is no longer
                    # observable (sst-043, 2026-09-30).
                    refusal = self._expected_quiescence_refusal(
                        started, runtime_profile, run=first_run, nonce=nonce)
                    if refusal is None:
                        raise SuiteError('benign scenario did not publish healthy')
                    first_run['expected_refusal'] = refusal
                    evidence.write(first_label + '-expected-refusal.json', refusal)
                    evidence.write('run-01-probe-pre-restart-stop.json',
                                   self._pre_restart_probe_stop(captures[first_label]))
                    try:
                        call('restart', {}, mutation=True)
                    except SuiteError as restart_exc:
                        if 'not_allowed_in_state' not in repr(restart_exc):
                            raise
                        evidence.write('restart-refused-expected.json',
                                       {'reason': repr(restart_exc)})
                    for _ in range(3):
                        call('get_status')
                    call('get_events', {'limit': 100})
                    call('list_artifacts')
                    first_run['stop_response'] = call('stop', {}, mutation=True)
                finish_capture(first_label, first_run)
                if not fault and not refusal_continuation:
                    refusal = self._expected_quiescence_refusal(
                        started, runtime_profile, run=first_run, nonce=nonce)
                    if refusal is None:
                        raise SuiteError('benign scenario did not publish healthy')
                    # A B3 match image released before start is BY DESIGN
                    # already running when the product validates quiescence;
                    # the refusal is the correct product outcome for this
                    # interleave and the scenario verifies exactly it
                    # (discovery100-68 sst-051..053).
                    first_run['expected_refusal'] = refusal
                    evidence.write(first_label + '-expected-refusal.json', refusal)
                    if not refusal_continuation:
                        # The stop is idempotent on the already-stopped service.
                        first_run['stop_response'] = call('stop', {}, mutation=True)
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
                cleanup_errors.append('no cleanup mutation: lifecycle/capture ownership was not terminal')
            else:
                pending = list(captures.items())
                if shared_physical:
                    pending.sort(key=lambda pair: 0 if pair[1].get('shared_physical') else 1)
                for label, capture in pending:
                    try:
                        owner = next((item for item in runs if item.get('label') == label), {'label': label})
                        finish_capture(label, owner)
                    except UnsettledCaptureStop as exc:
                        operation_unsettled = True
                        cleanup_errors.append('capture %s unsettled: %r' % (label, exc))
                        break
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append('capture %s: %r' % (label, exc))
                if operation_unsettled:
                    cleanup_errors.append('no further cleanup mutation: capture writer retained')
                else:
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
                        run['five_sections_after'] = after_sections
                        run['traffic_oracle'] = {'status': 'NOT_EXECUTED', 'passed': None}
                        continue
                    raise SuiteError('run has no immutable run_id')
                original_root = root / run['label'] / 'originals'
                run['originals'] = self._export_run_originals(run_id, original_root, evidence)
                if 'five_sections_after' not in run:
                    run['five_sections_after'] = after_sections
                if not fault and run.get('start_response', {}).get('state') == 'healthy':
                    if self.auxiliary_clock_evidence in AUX_QPC_MODES:
                        self._collect_auxiliary_qpc(run, nonce, root, evidence, runtime_profile)
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
                    if self.auxiliary_clock_evidence in AUX_QPC_MODES:
                        self._collect_auxiliary_qpc(primary, nonce, root, evidence, runtime_profile)
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
        branch_verdict, approved_refusal = self._branch_verdict(
            runs, runtime_profile, plan_tools, call_tools, fault)
        verdict = {'interface_semantics': branch_verdict['interface_semantics'],
                   'stale_lock_rejection': any(item.get('expect') == 'reject_state_conflict' and
                                               item.get('rejection_oracle', {}).get('side_effect_free')
                                               for item in calls),
                   'continuous_health': (bool(fault) or bool(refusal_recorded) or
                                         (len(status_samples) == 3 and
                                         all(item['status'].get('state') == 'healthy' for item in status_samples))),
                   'per_run_dual_capture': branch_verdict['per_run_dual_capture'],
                   'five_section_recovery': not cleanup_errors and after_sections is not None,
                   'traffic_oracle': branch_verdict['traffic_oracle'],
                   'log_clean': (bool(fault) or all(not item.get('log_clean_issues') for item in runs
                                                     if item.get('start_response', {}).get('state') == 'healthy')),
                   'cleanup_recorded': bool(cleanup_calls) or final_status.get('state') == 'stopped',
                   'refusal_recovery': (not approved_refusal or
                                        (final_status.get('state') == 'stopped' and
                                         final_status.get('run_id') is None and
                                         final_status.get('controller') is None and
                                         final_status.get('last_run_outcome') == 'failed' and
                                         not cleanup_errors and after_sections is not None)),
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
        scenario_passed = self._scenario_passed(failure, verdict, approved_refusal)
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
                  'capture_contract': ('scenario-shared-v2' if shared_physical else 'per-run-v1'),
                  'guest_work_root': self.guest_work_root,
                  'tool_identity': tool_identity,
                  'attempt': attempt, 'seed': scenario['seed'], 'interface_calls': calls,
                  'cleanup_calls': cleanup_calls,
                  'traffic_evidence': {'nonce': nonce, 'runtime_profile': runtime_profile,
                                       'auxiliary_clock_evidence': self.auxiliary_clock_evidence,
                                       'fnpr_sentinel_record': sentinel_record,
                                       'capture_views': [file_record(root / item['path'], self.root)
                                           for item in evidence.items]},
                  'health_trace': {'window': ('W-start-refusal' if refusal_recorded else 'W-traffic'),
                                   'traffic_status': ('NOT_EXECUTED' if refusal_recorded else 'EXECUTED'),
                                   'samples': status_samples,
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
        script = self.guest_work_root + r'\scenario-suite-20260912\scenario_probes.ps1'
        value, _ = self._vm_json(
            "$ErrorActionPreference='Stop';& " + quote_ps(script) + " -Action ensure-client -Output " +
            quote_ps(self.guest_work_root + r'\scenario-suite-20260912\probe-client.json') + ";"
            "Get-Content " + quote_ps(self.guest_work_root + r'\scenario-suite-20260912\probe-client.json') + " -Raw", 120)
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
        spike_view = Suite.__new__(Suite)
        spike_view.root = root
        spike_view.identity = self.identity
        spike_view.fault_clock_evidence = self.fault_clock_evidence
        spike_view.auxiliary_clock_evidence = self.auxiliary_clock_evidence
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
                expected_mode = (QPC_MODE if case['fault_class'] == 'diverter_stop'
                                 and self.fault_clock_evidence == QPC_MODE else None)
                if descriptor.get('clock_evidence_mode') != expected_mode:
                    raise ValueError('Spike fault clock evidence mode differs')
                if (descriptor.get('synthetic') or
                        descriptor.get('candidate_id') != self.identity.candidate_id or
                        descriptor.get('fault') != case['fault_class'] or
                        descriptor.get('scenario_id') != case['scenario_id'] or
                        descriptor.get('run_id') not in run_ids):
                    raise ValueError('Spike raw descriptor identity differs')
                calls = [(x.get('tool'), x.get('expect')) for x in result.get('interface_calls', [])]
                if calls != [(x['tool'], x['expect']) for x in selected['interface_call_plan']]:
                    raise ValueError('Spike interface call contract differs')
                issues = (result_issues(result, root) + fault_recheck_issues(result, root) +
                          spike_view._traffic_recheck_issues(result, selected))
                if issues:
                    raise ValueError('; '.join(issues))
        except (OSError, ValueError, KeyError, TypeError, IndexError, SuiteError) as exc:
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
            problems.extend(self._traffic_recheck_issues(result, scenario))
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

        traffic_issues: dict[str, list[str]] = {}

        def execute() -> list[dict[str, Any]]:
            # Every scenario exports ipc-parent.jsonl, but only fault scenarios
            # arm the evidence environment themselves; arm it for the whole pass.
            results = []
            for scenario in selected:
                result_path = self._result_path(scenario['scenario_id'])
                result = read_json(result_path) if result_path.exists() else None
                if result is None or result.get('state') not in ('pass', 'fail'):
                    result = self._run_one(scenario, 1)
                results.append(result)
                issues = (self._traffic_recheck_issues(result, scenario)
                          if result.get('state') == 'pass' else [])
                if issues:
                    traffic_issues[scenario['scenario_id']] = issues
                if result.get('state') != 'pass' or issues:
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
                  and all(row.get('state') == 'pass' for row in results)
                  and not traffic_issues)
        return {'output_dir': str(self.root), 'filter': filter_name, 'count': len(results),
                'passed': passed, 'ipc_evidence': ipc_evidence,
                'traffic_recheck_issues': traffic_issues,
                'not_executed': [row['scenario_id'] for row in selected[len(results):]],
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

        traffic_issues: dict[str, list[str]] = {}

        def execute() -> list[dict[str, Any]]:
            rerun = []
            for scenario in manifest['scenarios']:
                path = self._state_path(scenario['scenario_id'])
                if not path.exists():
                    continue
                state = read_json(path)
                if state.get('phase') in ('pending', 'blocked', 'running'):
                    self._continuation_gate()
                    result = self._run_one(scenario, int(state.get('attempt', 0)) + 1)
                    rerun.append(result)
                    issues = (self._traffic_recheck_issues(result, scenario)
                              if result.get('state') == 'pass' else [])
                    if issues:
                        traffic_issues[scenario['scenario_id']] = issues
                    if (result.get('state') != 'pass' or issues) and getattr(
                            self.args, 'stop_on_first_failure', False):
                        break
            return rerun

        rerun, ipc_evidence = self._ipc_evidence_pass(
            'ipc-evidence-resume-enabled.json', 'ipc-evidence-resume-disabled.json', execute)
        rerun = rerun if rerun is not None else []
        return {'output_dir': str(self.root), 'resumed': len(rerun),
                'ipc_evidence': ipc_evidence,
                'traffic_recheck_issues': traffic_issues,
                'not_executed': [row['scenario_id'] for row in pending[len(rerun):]],
                'passed': (self._ipc_evidence_recovered(ipc_evidence)
                           and all(row.get('state') == 'pass' for row in rerun)
                           and not traffic_issues)}

    def _traffic_recheck_issues(self, result: dict[str, Any], expected: dict[str, Any]) -> list[str]:
        """Re-adjudicate healthy-run traffic from the byte-bound originals."""
        traffic = result.get('traffic_evidence') or {}
        nonce = traffic.get('nonce')
        runtime = traffic.get('runtime_profile')
        if not isinstance(nonce, str) or not isinstance(runtime, dict):
            return ['traffic recheck lacks nonce/runtime profile']
        if result.get('capture_contract', 'per-run-v1') == 'scenario-shared-v2':
            try:
                from scenario_capture_view import validate_shared_views
                validate_shared_views(result, self.root)
            except (ValueError, KeyError, OSError) as exc:
                return ['shared capture view invalid: ' + str(exc)]
        if traffic.get('auxiliary_clock_evidence', 'utc-v1') != getattr(
                self, 'auxiliary_clock_evidence', 'utc-v1'):
            return ['traffic auxiliary clock evidence mode differs from requested mode']
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
            if run.get('capture', {}).get('observation_contract') not in ('con008', 'con008-shared-v2'):
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
    if result.get('capture_contract', 'per-run-v1') == 'scenario-shared-v2':
        tool = result.get('tool_identity') or {}
        if (result.get('guest_work_root') not in (GUEST_ROOT, E_GUEST_WORK_ROOT) or
                tool.get('schema') != 'sst.acceptance-tool-set.v1' or
                not isinstance(tool.get('files'), dict) or
                tool.get('sha256') != digest(tool['files'])):
            failures.append('shared capture work root/tool identity missing')
        try:
            from scenario_capture_view import validate_shared_views
            validate_shared_views(result, root)
        except (ValueError, KeyError, OSError, TypeError) as exc:
            failures.append('shared capture view invalid: ' + str(exc))
    elif any((run.get('capture') or {}).get('observation_contract') == 'con008-shared-v2'
             for run in result.get('run_chain') or []):
        failures.append('shared run view without versioned capture contract')
    runs = result.get('run_chain') or []
    refusal_runs = [run for run in runs if run.get('expected_refusal')]
    if refusal_runs:
        if len(runs) != 1 or len(refusal_runs) != 1:
            failures.append('refusal must have exactly one attempted run')
        else:
            failures.extend(refusal_recheck_issues(result, root))
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
        refusal = bool(run.get('expected_refusal'))
        if refusal and run.get('run_id') is None:
            if run.get('originals') or run.get('runtime_pcap'):
                failures.append('refusal fabricated run originals')
                break
        elif not run.get('originals', {}).get('files'):
            failures.append('complete VM run originals missing')
            break
        originals = run.get('originals') or {}
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
        if not result.get('scenario', {}).get('fault_class') and not refusal:
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
        if not refusal_runs and (len(health) != 3 or not all(item.get('status', {}).get('state') == 'healthy' for item in health)):
            failures.append('continuous healthy trace missing')
        if not refusal_runs and recovery.get('final_status', {}).get('last_run_outcome') != 'ok':
            failures.append('benign final outcome is not ok')
    return failures


def refusal_recheck_issues(result: dict[str, Any], root: Path) -> list[str]:
    """Independently reconstruct an approved refusal from sealed originals."""
    try:
        run = result['run_chain'][0]
        profile = result['traffic_evidence']['runtime_profile']
        nonce = result['traffic_evidence']['nonce']
        refusal = run['expected_refusal']
        calls = result['interface_calls']
        planned = [(item['tool'], item['expect'])
                   for item in result['scenario']['interface_call_plan']]
        def value(item: dict[str, Any]) -> dict[str, Any]:
            return json.loads(item['response']['result']['content'][0]['text'])
        if len(result.get('run_chain') or []) != 1 or not Suite._is_quiescence_refusal_family(profile):
            raise ValueError('refusal attempted run/family differs')
        if [(item.get('tool'), item.get('expect')) for item in calls] != planned:
            raise ValueError('refusal interface plan was not fully executed')
        restart_calls = [item for item in calls if item.get('tool') == 'restart']
        continuation = result['scenario'].get('lifecycle_chain') == 'restart'
        if len(restart_calls) != int(continuation):
            raise ValueError('refusal restart plan differs')
        if continuation:
            receipt = value(restart_calls[0])
            if (restart_calls[0].get('ok') is not False or
                    receipt.get('state') != 'stopped' or receipt.get('run_id') is not None or
                    receipt.get('changed') is not False or receipt.get('command_id') is not None or
                    receipt.get('error') != {'code': 'not_allowed_in_state',
                        'message': 'restart requires an active run bound to its run_id'}):
                raise ValueError('refusal restart receipt differs')
        if any(item.get('ok') is not True for item in calls
               if item.get('expect') == 'success' and item.get('tool') != 'restart'):
            raise ValueError('refusal interface plan was not fully executed')
        starts = [value(item) for item in calls if item['tool'] == 'start']
        statuses = [value(item) for item in calls if item['tool'] == 'get_status']
        stops = [value(item) for item in calls if item['tool'] == 'stop']
        stored_statuses = run.get('refusal_status_samples') or []
        statuses_match = statuses == stored_statuses
        if continuation and len(statuses) == len(stored_statuses) == 3:
            restart_receipt = value(restart_calls[0])
            # Internal refusal samples precede the plan's rejected restart;
            # its state publication can advance only the version, not run,
            # config, failure, health, or controller identity.
            statuses_match = all(
                {k: v for k, v in actual.items() if k != 'state_version'} ==
                {k: v for k, v in before.items() if k != 'state_version'} and
                before.get('state_version') == starts[0].get('state_version') and
                actual.get('state_version') == restart_receipt.get('state_version') and
                isinstance(actual.get('state_version'), int) and
                actual['state_version'] >= before['state_version']
                for actual, before in zip(statuses, stored_statuses))
        if (len(starts) != 1 or starts[0] != run.get('start_response') or
                len(statuses) != 3 or not statuses_match or
                len(stops) != 1 or stops[0] != run.get('stop_response') or
                stops[0].get('state') != 'stopped'):
            raise ValueError('refusal start/status/stop receipts differ')
        approved_nonmatch = profile.get('probe_target', {}).get('process_mode') == 'nonmatch'
        if (run.get('run_id') is not None or starts[0].get('state') != 'stopped' or
                starts[0].get('last_run_outcome') != 'failed' or
                starts[0].get('run_id') is not None or
                any(item.get('state') != 'stopped' or item.get('run_id') is not None or
                    item.get('controller') is not None for item in statuses) or
                (result.get('health_trace') or {}).get('samples') or
                (result.get('health_trace') or {}).get('window') != 'W-start-refusal' or
                (result.get('health_trace') or {}).get('traffic_status') != 'NOT_EXECUTED' or
                (run.get('traffic_oracle') or {}).get('status') != 'NOT_EXECUTED' or
                (run.get('traffic_oracle') or {}).get('passed') is not None or
                result.get('verdict', {}).get('traffic_oracle') !=
                    ('NOT_EXECUTED' if approved_nonmatch else True)):
            raise ValueError('refusal incorrectly claimed healthy run or traffic')
        final = result.get('recovery', {}).get('final_status') or {}
        if (final.get('state') != 'stopped' or final.get('run_id') is not None or
                final.get('controller') is not None or final.get('last_run_outcome') != 'failed' or
                result.get('recovery', {}).get('cleanup_errors')):
            raise ValueError('refusal terminal/recovery is incomplete')
        audit = result.get('five_section_audit') or {}
        after_record = next((item for item in result.get('traffic_evidence', {}).get('capture_views', [])
                             if Path(str(item.get('path', ''))).name == 'five-sections-after.json'), None)
        if not after_record:
            raise ValueError('refusal five-section recovery original absent')
        after_path = (root.resolve() / after_record['path']).resolve()
        if (not after_path.is_relative_to(root.resolve()) or
                file_record(after_path, root.resolve()) != after_record):
            raise ValueError('refusal five-section recovery original differs')
        after = read_json(after_path)
        if (after.get('sections') != audit.get('after') or
                run.get('five_sections_before') != audit.get('before') or
                run.get('five_sections_after') != audit.get('after') or
                Suite._difference_is_residue(after.get('difference') or {},
                                              after.get('difference_attribution'))):
            raise ValueError('refusal five-section recovery differs or leaves residue')
        if profile.get('probe_target', {}).get('process_mode') == 'nonmatch':
            events = [value(item) for item in calls if item['tool'] == 'get_events']
            if len(events) != 1 or not isinstance(events[0].get('events'), list):
                raise ValueError('refusal event receipt absent')
            release_at = dt.datetime.fromisoformat(run['probe_release']['released_utc'].replace('Z', '+00:00'))
            current = [item for item in events[0]['events']
                       if isinstance(item.get('timestamp'), (int, float)) and
                       item['timestamp'] >= release_at.timestamp()]
            failed = [item for item in current if item.get('kind') == 'health' and
                      item.get('state') == 'failed' and
                      Suite._ACTIVE_A_REFUSAL_MARKER in str(item.get('failure_reason') or '')]
            if (len(failed) != 1 or any(item.get('state') == 'healthy' or
                    item.get('run_id') for item in current) or
                    run.get('refusal_failure_utc') != dt.datetime.fromtimestamp(
                        failed[0]['timestamp'], dt.timezone.utc).isoformat()):
                raise ValueError('refusal failure event/READY boundary differs')
            proof = Suite._active_a_refusal_proof(root, profile, nonce, run)
            if (refusal.get('proof') != proof or
                    refusal.get('marker') != Suite._ACTIVE_A_REFUSAL_MARKER or
                    refusal.get('traffic_status') != 'NOT_EXECUTED' or
                    any(not str(item.get('failure_reason') or '').startswith(
                            'managed start failed: RuntimeError(') or
                        Suite._ACTIVE_A_REFUSAL_MARKER not in str(item.get('failure_reason') or '')
                        or item.get('last_run_outcome') != 'failed' for item in statuses) or
                    refusal.get('reason') != statuses[-1].get('failure_reason')):
                raise ValueError('nonmatch refusal proof/reason differs')
        elif profile.get('probe_target', {}).get('process_mode') == 'match':
            if (profile.get('bucket') != 'B3' or profile.get('interleave') != 'before-start' or
                    Suite._QUIESCENCE_REFUSAL_MARKER not in refusal.get('reason', '') or
                    refusal.get('reason') != statuses[-1].get('failure_reason')):
                raise ValueError('match refusal family/reason differs')
        else:
            raise ValueError('unapproved refusal family')
    except (KeyError, ValueError, TypeError, OSError, ET.ParseError, IndexError) as exc:
        return ['refusal raw re-adjudication failed: ' + str(exc)]
    return []


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
        mode = capture.get('clock_evidence_mode')
        if mode == QPC_MODE:
            case = adapter.build_qpc_case(root, capture, case)
            sealed_case = adjudication.get('case') or {}
            sealed_result = adjudication.get('result') or {}
            case_path = (root / str(sealed_case['path'])).resolve()
            result_path = (root / str(sealed_result['path'])).resolve()
            if (not case_path.is_relative_to(root) or not result_path.is_relative_to(root)
                    or file_record(case_path, root) != sealed_case
                    or file_record(result_path, root) != sealed_result
                    or json.loads(case_path.read_text(encoding='utf-8')) != case):
                raise ValueError('sealed v3 case differs from independent reconstruction')
        elif mode is not None:
            raise ValueError('unknown fault clock evidence mode')
        verdict = oracle.assess(case, root, capture['candidate_id'])
        if mode == QPC_MODE and json.loads(result_path.read_text(encoding='utf-8')) != verdict:
            raise ValueError('stored v3 verdict differs from independent reconstruction')
        if not verdict.get('passed'):
            return ['fault raw-evidence re-adjudication failed']
    except Exception as exc:  # noqa: BLE001 - fail closed on malformed native exports
        return ['fault raw-evidence re-adjudication failed: ' + str(exc)]
    return []


def actual_coverage(manifest: dict[str, Any], records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(records)
    result_by_id = {row.get('scenario_id'): row for row in rows}
    tool_ids = {tool: set() for tool in TOOLS}
    bucket = {key: 0 for key in BUCKET_COUNTS}
    faults = {key: 0 for key in FAULTS}
    passed = failed = blocked = 0
    traffic_executed = traffic_not_executed = 0
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
            runs = row.get('run_chain') or []
            if runs and all(run.get('expected_refusal') and
                            (run.get('traffic_oracle') or {}).get('status') == 'NOT_EXECUTED'
                            for run in runs):
                traffic_not_executed += 1
            elif runs and all(run.get('start_response', {}).get('state') == 'healthy' and
                              (run.get('traffic_oracle') or {}).get('passed') is True
                              for run in runs):
                traffic_executed += 1
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
            'traffic_executed': traffic_executed,
            'traffic_not_executed': traffic_not_executed,
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
    parser.add_argument('--capture-contract', choices=CAPTURE_CONTRACTS,
                        default='per-run-v1')
    parser.add_argument('--guest-work-root', choices=(GUEST_ROOT, E_GUEST_WORK_ROOT),
                        default=GUEST_ROOT)
    parser.add_argument('--native-clock-diagnostic', action='store_true',
                        help='capture optional boot/process/QPC identity without changing verdicts')
    parser.add_argument('--fault-clock-evidence', choices=('utc-v2', QPC_MODE), default='utc-v2',
                        help='explicit diverter_stop clock proof; default retains v2 UTC verdict')
    parser.add_argument('--auxiliary-clock-evidence', choices=('utc-v1', *AUX_QPC_MODES),
                        default='utc-v1',
                        help='explicit auxiliary TCP native QPC proof for verified zero-TCB RST')
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
