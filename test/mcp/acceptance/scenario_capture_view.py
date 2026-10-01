"""Versioned shared pktmon owner and independent run-view verification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import scenario_tcpip


OWNER_SCHEMA = 'sst.scenario-physical-capture-owner.v2'
VIEW_SCHEMA = 'sst.scenario-run-capture-view.v2'
PHYSICAL_NAMES = frozenset(('pktmon.etl', 'pktmon.txt', 'pktmon-nic.json'))
KERNEL_NAMES = frozenset(('kernel-network.etl', 'kernel-network.events.jsonl',
                          'kernel-network.header.xml', 'kernel-network.summary.txt',
                          'kernel-network.metadata.json'))


def _bytes(root: Path, record: dict) -> bytes:
    if not isinstance(record, dict):
        raise ValueError('capture record is not an object')
    path = (root / record['path']).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('capture record missing or outside suite root')
    raw = path.read_bytes()
    if len(raw) != record['size'] or hashlib.sha256(raw).hexdigest() != record['sha256']:
        raise ValueError('capture record size/SHA changed')
    return raw


def validate_shared_views(result: dict, suite_root: Path) -> None:
    """Fail closed before the per-run traffic oracle consumes a shared ETL."""
    root = Path(suite_root).resolve()
    runs = result.get('run_chain') or []
    if len(runs) == 1 and runs[0].get('expected_refusal'):
        # A refused start publishes no run and therefore owns no second run
        # view. Require the complete approved raw refusal proof instead.
        from scenario_suite import refusal_recheck_issues
        issues = refusal_recheck_issues(result, root)
        if issues:
            raise ValueError('; '.join(issues))
        if (runs[0].get('label') != 'run-01' or
                runs[0].get('capture', {}).get('observation_contract') != 'con008'):
            raise ValueError('refusal independent capture contract differs')
        return
    if len(runs) != 2 or [x.get('label') for x in runs] != ['run-01', 'run-02']:
        raise ValueError('shared capture requires exactly two ordered run labels')
    traffic = result.get('traffic_evidence') or {}
    nonce = traffic.get('nonce')
    if not isinstance(nonce, str) or not nonce:
        raise ValueError('shared capture nonce absent')
    expected_owner = nonce + ':pktmon'
    owner_record = runs[0].get('capture', {}).get('physical_owner')
    if not owner_record or owner_record != runs[1].get('capture', {}).get('physical_owner'):
        raise ValueError('shared runs do not bind one owner record')
    owner = json.loads(_bytes(root, owner_record))
    if (owner.get('schema') != OWNER_SCHEMA or owner.get('owner_id') != expected_owner or
            owner.get('nonce') != nonce or owner.get('scenario_id') != result.get('scenario_id') or
            owner.get('epoch') != result.get('attempt') or
            owner.get('capture_contract') != 'scenario-shared-v2' or
            owner.get('guest_work_root') != result.get('guest_work_root') or
            owner.get('tool_sha256') != result.get('tool_identity', {}).get('sha256') or
            owner.get('run_ids') != [x.get('run_id') for x in runs] or
            owner['run_ids'][0] == owner['run_ids'][1]):
        raise ValueError('shared owner identity/epoch/run list differs')
    physical = owner.get('physical_files')
    if (not isinstance(physical, list) or len(physical) != 3 or
            {Path(x['path']).name for x in physical} != PHYSICAL_NAMES):
        raise ValueError('shared owner physical file set incomplete')
    physical_map = {Path(x['path']).name: x for x in physical}
    raw = {name: _bytes(root, record) for name, record in physical_map.items()}
    metadata = json.loads(raw['pktmon-nic.json'])
    lo, hi = scenario_tcpip.validate_capture(raw['pktmon.txt'], raw['pktmon.etl'],
        metadata, 50_000_000)
    before = metadata.get('native_identity_before') or {}
    after = metadata.get('native_identity_after') or {}
    boot = (before.get('boot') or {}).get('boot_identifier')
    machine = (before.get('vm_identity') or {}).get('machine_guid')
    if (before.get('supported') is not True or after.get('supported') is not True or
            not boot or not machine or
            (after.get('boot') or {}).get('boot_identifier') != boot or
            (after.get('vm_identity') or {}).get('machine_guid') != machine or
            before.get('candidate_id') != result.get('identity', {}).get('candidate_id') or
            after.get('candidate_id') != result.get('identity', {}).get('candidate_id')):
        raise ValueError('shared physical native boot/candidate boundary differs')
    seen_probes = set()
    seen_kernel_paths = set()
    for run in runs:
        capture = run.get('capture') or {}
        if (capture.get('observation_contract') != 'con008-shared-v2' or
                capture.get('owner_id') != expected_owner or
                capture.get('pktmon_path') != physical_map['pktmon.txt']['path'] or
                capture.get('pktmon_etl_path') != physical_map['pktmon.etl']['path'] or
                capture.get('pktmon_nic_path') != physical_map['pktmon-nic.json']['path'] or
                capture.get('pktmon_capture_issues')):
            raise ValueError('run view physical binding differs')
        files = capture.get('files') or []
        if len({x['path'] for x in files}) != len(files) or any(x not in files for x in physical):
            raise ValueError('run view physical member missing/duplicate')
        kernel_members = [x for x in files if Path(x['path']).name in KERNEL_NAMES]
        kernel = {Path(x['path']).name: x for x in kernel_members}
        if len(kernel_members) != len(KERNEL_NAMES) or set(kernel) != KERNEL_NAMES or any(
                record['path'] in seen_kernel_paths for record in kernel.values()):
            raise ValueError('run view independent kernel archive incomplete/borrowed')
        seen_kernel_paths.update(x['path'] for x in kernel.values())
        for record in kernel.values():
            _bytes(root, record)
        view_record = capture.get('run_view')
        if view_record not in (traffic.get('capture_views') or []):
            raise ValueError('run view is not in sealed evidence manifest')
        view = json.loads(_bytes(root, view_record))
        if (view.get('schema') != VIEW_SCHEMA or view.get('owner') != owner_record or
                view.get('owner_id') != expected_owner or view.get('physical_files') != physical or
                view.get('scenario_id') != result.get('scenario_id') or
                view.get('attempt') != result.get('attempt') or
                view.get('run_id') != run.get('run_id') or view.get('label') != run.get('label') or
                view.get('nonce') != nonce or
                view.get('guest_work_root') != owner.get('guest_work_root') or
                view.get('tool_sha256') != owner.get('tool_sha256') or
                view.get('capture_run_id') != nonce + ':' + run['label'] or
                view.get('capture_started_utc') != owner.get('started_utc') or
                view.get('capture_stopped_utc') != owner.get('stopped_utc')):
            raise ValueError('run view identity/epoch/clock binding differs')
        probe = view.get('probe')
        if (probe not in files or probe['path'] != capture.get('probe_path') or
                view.get('probe_pid') != capture.get('probe_launcher_pid') or
                (view.get('probe_pid'), view.get('probe_creation_ticks')) in seen_probes):
            raise ValueError('run view probe identity missing/duplicate')
        seen_probes.add((view['probe_pid'], view['probe_creation_ticks']))
        if run['label'] == 'run-02':
            receipts = [x for x in files if Path(x['path']).name == 'probe-launch.json']
            if len(receipts) != 1:
                raise ValueError('shared second probe launch receipt missing/ambiguous')
            receipt = json.loads(_bytes(root, receipts[0]))
            if (receipt.get('pid') != view['probe_pid'] or
                    receipt.get('creation_ticks') != view['probe_creation_ticks'] or
                    receipt.get('nonce') != nonce or
                    receipt.get('capture_run_id') != view['capture_run_id'] or
                    receipt.get('candidate_id') != result.get('identity', {}).get('candidate_id')):
                raise ValueError('shared second probe launch receipt identity differs')
        rows = [json.loads(line) for line in _bytes(root, probe).splitlines() if line.strip()]
        ready = [x for x in rows if x.get('event') == 'ready' and x.get('nonce') == nonce]
        if len(ready) != 1:
            raise ValueError('run view probe ready missing/ambiguous')
        native = ready[0].get('native_identity') or {}
        if (ready[0].get('pid') != view['probe_pid'] or
                ready[0].get('creation_ticks') != view['probe_creation_ticks'] or
                native.get('supported') is not True or
                native.get('run_id') != view['capture_run_id'] or
                native.get('nonce') != nonce or
                native.get('pid') != view['probe_pid'] or
                native.get('creation_filetime_100ns') !=
                    view['probe_creation_ticks'] - 504911232000000000 or
                (native.get('boot') or {}).get('boot_identifier') != boot or
                (native.get('vm_identity') or {}).get('machine_guid') != machine or
                native.get('candidate_id') != result.get('identity', {}).get('candidate_id')):
            raise ValueError('run view probe/native PID creation identity differs')
        closes = [x for x in rows if x.get('event') == 'close' and x.get('nonce') == nonce]
        if not closes:
            raise ValueError('run view probe close missing')
        for event in ready + closes:
            ticks = event.get('utc_ticks')
            if type(ticks) is not int or not lo <= (ticks - 621355968000000000) * 100 <= hi:
                raise ValueError('run view probe lifetime outside physical ETL window')
