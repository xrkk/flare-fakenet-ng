"""Formal auxiliary QPC application proof from the sealed run graph."""
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile

import etl_raw_clock as raw
import scenario_aux_qpc_offline as offline
import scenario_tcpip as tcpip


def _json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _record(root, record):
    path = (root / record['path']).resolve()
    if (not path.is_relative_to(root.resolve()) or not path.is_file() or
            raw.sha_file(path) != {'bytes': record['size'], 'sha256': record['sha256']}):
        raise raw.DiagnosticError('auxiliary QPC graph record missing/changed')
    return path


def no_tcp_applicability(run, suite_root, profile, *, expected_candidate, expected_nonce):
    """Prove that a planned auxiliary TCP branch is absent from sealed originals."""
    planned = list(profile.get('negative_cases', ())) + list(profile.get('probe_cases', ()))
    if any(case.get('protocol') != 'udp' for case in planned):
        raise raw.DiagnosticError('planned auxiliary TCP requires native QPC proof')
    if run.get('auxiliary_qpc_proof') or run.get('auxiliary_qpc_process'):
        raise raw.DiagnosticError('unexpected auxiliary QPC graph in no-TCP run')
    root = Path(suite_root).resolve()
    capture = run.get('capture') or {}
    originals = run.get('originals') or {}
    files = capture.get('files', []) + originals.get('files', [])
    names = [Path(item['path']).name for item in files]
    required = ('probe.jsonl', 'pktmon.txt', 'pktmon.etl', 'pktmon-nic.json',
                'run.log', 'ipc-parent.jsonl')
    if len(names) != len(set(names)) or any(name not in names for name in required):
        raise raw.DiagnosticError('no-TCP applicability original set missing/ambiguous')
    paths = {name: _record(root, files[names.index(name)]) for name in required}
    if (paths['probe.jsonl'] != (root / capture.get('probe_path', '')).resolve() or
            paths['pktmon.txt'] != (root / capture.get('pktmon_path', '')).resolve()):
        raise raw.DiagnosticError('no-TCP applicability capture paths differ')
    metadata = _json(paths['pktmon-nic.json'])
    tcpip.validate_capture(paths['pktmon.txt'].read_bytes(),
                           paths['pktmon.etl'].read_bytes(), metadata, 50_000_000)
    rows = [json.loads(line) for line in paths['probe.jsonl'].read_bytes().splitlines()]
    actual = [row for row in rows if row.get('nonce') == expected_nonce and
              row.get('event') in ('case_established', 'case_connect_attempt')]
    if actual:
        raise raw.DiagnosticError('unexpected auxiliary TCP case in no-TCP run')
    ipc = [json.loads(line) for line in paths['ipc-parent.jsonl'].read_bytes().splitlines()]
    tcpip.managed_identity(ipc, run['run_id'])
    after = {name: raw.sha_file(path) for name, path in paths.items()}
    if any(after[name] != {'bytes': files[names.index(name)]['size'],
                            'sha256': files[names.index(name)]['sha256']}
           for name in required):
        raise raw.DiagnosticError('no-TCP applicability originals changed during review')
    return {'schema': 'sst.aux-qpc-applicability.v1',
            'status': 'NOT_APPLICABLE_NO_TCP_AUXILIARY',
            'candidate_id': expected_candidate, 'run_id': run['run_id'],
            'nonce': expected_nonce, 'cases': [],
            'originals': after}


def evaluate(run, suite_root, *, expected_candidate, expected_nonce, expected_mode=None):
    """Recompute offline; an old INCOMPLETE Windows export can never pass."""
    root = Path(suite_root).resolve()
    records = run.get('auxiliary_qpc_process') or {}
    required = ('qpc-process-responsibility.json', 'qpc-process-terminal.json',
                'qpc-transfer.json')
    if any(name not in records for name in required) or not run.get('auxiliary_qpc_proof'):
        raise raw.DiagnosticError('auxiliary QPC graph/process proof missing')
    paths = {name: _record(root, records[name]) for name in required}
    stored_path = _record(root, run['auxiliary_qpc_proof'])
    native_root = paths[required[0]].parent
    owner, terminal, transfer = (_json(paths[name]) for name in required)
    if (owner.get('run_id') != run['run_id'] or
            terminal.get('run_id') != run['run_id'] or
            owner.get('input_sha256') != terminal.get('input_sha256') or
            owner.get('guest_root') != terminal.get('guest_root') or
            terminal.get('exit_proven') is not True or
            terminal.get('guest_error') is not None or
            transfer.get('error') is not None):
        raise raw.DiagnosticError('auxiliary QPC process responsibility incomplete')
    host = transfer.get('host_only_transfer') or {}
    guest = transfer.get('guest') or {}
    requests = host.get('requests') or []
    if (host.get('bind') != '192.168.204.1' or host.get('stopped') is not True or
            host.get('sha256') != owner['input_sha256'] or len(requests) != 1 or
            requests[0].get('status') != 200 or requests[0].get('bytes') != host.get('bytes') or
            guest.get('input_sha256') != owner['input_sha256'] or guest.get('exit_code') != 0 or
            guest.get('process', {}).get('exit_proven') is not True):
        raise raw.DiagnosticError('auxiliary QPC host-only transfer/guest exit incomplete')
    zip_path = native_root / 'qpc-output.zip'
    if raw.sha_file(zip_path) != {'bytes': guest.get('bytes'), 'sha256': guest.get('sha256')}:
        raise raw.DiagnosticError('auxiliary QPC returned ZIP identity differs')
    guest_root = native_root / 'qpc-native'
    with zipfile.ZipFile(zip_path) as archive:
        names = [member.filename for member in archive.infolist() if not member.is_dir()]
        if len(names) != len(set(names)) or not names:
            raise raw.DiagnosticError('auxiliary QPC ZIP has duplicate/empty member set')
        for name in names:
            relative = Path(name)
            target = (guest_root / relative).resolve()
            if (relative.is_absolute() or '..' in relative.parts or
                    not target.is_relative_to(guest_root.resolve()) or not target.is_file() or
                    hashlib.sha256(target.read_bytes()).digest() !=
                    hashlib.sha256(archive.read(name)).digest()):
                raise raw.DiagnosticError('auxiliary QPC ZIP/extracted original differs')
        if set(names) != {path.relative_to(guest_root).as_posix() for path in
                          guest_root.rglob('*') if path.is_file()}:
            raise raw.DiagnosticError('auxiliary QPC extracted member set differs')
    if (_json(guest_root / 'terminal.json') != guest.get('process') or
            _json(guest_root / 'process-responsibility.json').get('run_id') != run['run_id']):
        raise raw.DiagnosticError('auxiliary QPC guest original/terminal differs')
    case_path = native_root / 'auxiliary-qpc-input.json'
    export = guest_root / 'export'
    with tempfile.TemporaryDirectory() as tmp:
        proof = offline.derive(case_path, root, export, Path(tmp) / 'derived')
    stored = _json(stored_path)
    if stored != proof or proof['status'] != 'COMPLETE_FORMAL_INPUT':
        raise raw.DiagnosticError('auxiliary QPC online/offline graph proof differs')
    if (proof['run_id'] != run['run_id'] or proof['candidate_id'] != expected_candidate or
            proof['nonce'] != expected_nonce or not proof['cases'] or
            any(case['zero_constraint'] not in ('VERIFIED', 'NO_ZERO_TCB')
                for case in proof['cases'])):
        raise raw.DiagnosticError('auxiliary QPC run/candidate/nonce/cases differ')
    if expected_mode is not None and proof['schema'] != {
            'native-qpc-zero-tcb-v1': 'sst.aux-qpc-offline.v1',
            'native-qpc-zero-tcb-single-pass-v2': 'sst.aux-qpc-offline.v2',
            }.get(expected_mode):
        raise raw.DiagnosticError('auxiliary QPC evidence mode/proof version differs')
    if proof['schema'] == 'sst.aux-qpc-offline.v2':
        return {key: proof[key] for key in ('schema', 'status', 'source_windows_status',
            'candidate_id', 'run_id', 'nonce', 'identity', 'cases', 'single_pass',
            'legacy_v1_status')}
    return {key: proof[key] for key in ('schema', 'status', 'source_windows_status',
        'candidate_id', 'run_id', 'nonce', 'identity', 'cases', 'reason_map_sha256')}
