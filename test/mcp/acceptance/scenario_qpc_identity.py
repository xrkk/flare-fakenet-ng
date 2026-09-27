"""Diagnostic-only cross-source identity checks; never an acceptance clock."""
import uuid
import hashlib
import json
from pathlib import PurePosixPath

FILETIME_EPOCH_TICKS = 504911232000000000
BOOT_LAYOUT = 'phnt:SYSTEM_BOOT_ENVIRONMENT_INFORMATION:win10-19045-x64'


class DiagnosticIdentityError(ValueError):
    pass


def _require(test, reason):
    if not test:
        raise DiagnosticIdentityError(reason)


def _identity(value, label, run, nonce, candidate=None):
    _require(isinstance(value, dict) and value.get('schema') == 'sst.native-identity.v1'
             and value.get('supported') is True, label + ' native identity unsupported')
    _require(value.get('run_id') == run and value.get('nonce') == nonce,
             label + ' run/nonce mismatch')
    if candidate is not None:
        _require(value.get('candidate_id') == candidate, label + ' candidate mismatch')
    boot = value.get('boot') or {}
    _require(boot.get('information_class') == 90 and boot.get('ntstatus') == 0
             and boot.get('return_length') == boot.get('buffer_length') == 32
             and boot.get('layout') == value.get('boot_layout') == BOOT_LAYOUT
             and isinstance(boot.get('raw_hex'), str) and len(boot['raw_hex']) == 64
             and isinstance(boot.get('boot_identifier'), str) and boot['boot_identifier']
             and boot['boot_identifier'] != '00000000-0000-0000-0000-000000000000',
             label + ' boot API/layout evidence missing')
    try:
        raw = bytes.fromhex(boot['raw_hex'])
        _require(str(uuid.UUID(bytes_le=raw[:16])) == boot['boot_identifier'].lower()
                 and int.from_bytes(raw[16:20], 'little') == boot.get('firmware_type')
                 and int.from_bytes(raw[24:32], 'little') == boot.get('boot_flags'),
                 label + ' boot raw fields disagree')
    except (ValueError, TypeError) as exc:
        raise DiagnosticIdentityError(label + ' boot raw bytes invalid') from exc
    _require(isinstance(value.get('pid'), int) and value['pid'] > 0
             and isinstance(value.get('creation_filetime_100ns'), int)
             and value['creation_filetime_100ns'] > 0
             and isinstance(value.get('qpc_frequency'), int) and value['qpc_frequency'] > 0,
             label + ' process/frequency evidence missing')
    vm = value.get('vm_identity') or {}
    _require(bool(vm.get('computer_name')) and bool(vm.get('machine_guid')),
             label + ' VM identity missing')
    return value


def check_provenance(capture, ready, process_ready, established, action,
                     trace_header, candidate_id, managed_run_id, managed_pid,
                     managed_creation_filetime):
    """Require one boot, VM, frequency and PID/creation chain across sources.

    Capture/probe use a planned capture_run_id because managed_run_id is only
    published after start. The enclosing case binds both through nonce,
    candidate, complete original files and the native connection generation.
    ETL BootTime is retained as a separate FILETIME, never compared to GUID.
    """
    capture_run = capture.get('capture_run_id')
    nonce = capture.get('nonce')
    _require(bool(capture_run) and bool(nonce) and
             capture.get('candidate_id') == candidate_id,
             'capture run/nonce/candidate missing')
    _require(action.get('run_id') == managed_run_id and action.get('nonce') == nonce,
             'action managed run/nonce mismatch')
    items = [
        _identity(capture.get('native_identity_before'), 'capture before', capture_run, nonce, candidate_id),
        _identity(capture.get('native_identity_after'), 'capture after', capture_run, nonce, candidate_id),
        _identity(ready.get('native_identity'), 'probe ready', capture_run, nonce, candidate_id),
        _identity(action.get('native_identity', {}).get('before'), 'action before', managed_run_id, nonce),
        _identity(action.get('native_identity', {}).get('after'), 'action after', managed_run_id, nonce),
    ]
    if process_ready is not None:
        items.append(_identity(process_ready.get('native_identity'), 'probe child',
                               capture_run, nonce, candidate_id))
        probe = items[-1]
        _require(probe['pid'] == process_ready.get('pid') == established.get('pid'),
                 'B3 child PID differs from established; wrapper is not child')
        _require(probe['pid'] != items[2]['pid'] and
                 probe.get('collector_pid') == items[2]['pid'],
                 'B3 child identity is not independently queried')
    else:
        probe = items[2]
        _require(probe['pid'] == established.get('pid'), 'probe PID differs from established')
    _require(probe['creation_filetime_100ns'] ==
             ready_or_child(process_ready, ready)['creation_ticks'] - FILETIME_EPOCH_TICKS,
             'probe native creation differs from ready record')
    _require(ready.get('nonce') == established.get('nonce') == nonce,
             'probe ready/established nonce mismatch')
    _require(items[3]['pid'] == items[4]['pid'] == action.get('pid') == managed_pid,
             'action PID differs from managed ready identity')
    _require(items[3]['creation_filetime_100ns'] ==
             items[4]['creation_filetime_100ns'] == managed_creation_filetime,
             'action creation differs from managed ready identity')
    boot = items[0]['boot']['boot_identifier']
    vm = items[0]['vm_identity']
    frequency = items[0]['qpc_frequency']
    for item in items[1:]:
        _require(item['boot']['boot_identifier'] == boot, 'cross-source boot mismatch')
        _require(item['vm_identity'] == vm, 'cross-source VM mismatch')
        _require(item['qpc_frequency'] == frequency, 'cross-source QPC frequency mismatch')
    for name in ('clock_before', 'clock_after'):
        _require(capture.get(name, {}).get('stopwatch_frequency') == frequency,
                 name + ' Stopwatch frequency mismatch')
    for name in ('before', 'after'):
        clock = action.get('clock_observations', {}).get(name, {})
        _require(clock.get('supported') is True and clock.get('pid') == managed_pid
                 and clock.get('qpc_frequency') == frequency
                 and isinstance(clock.get('qpc_before'), int)
                 and isinstance(clock.get('qpc_after'), int)
                 and 0 < clock['qpc_before'] <= clock['qpc_after'],
                 'action ' + name + ' QPC/PID mismatch')
    _require(trace_header.get('ReservedFlags') == 1 and
             trace_header.get('PerfFreq') == frequency and
             isinstance(trace_header.get('BootTime'), int) and trace_header['BootTime'] > 0 and
             trace_header.get('EventsLost') == trace_header.get('BuffersLost') == 0,
             'ETL clock/frequency/boot-time/loss unsupported')
    return {'schema': 'sst.qpc-provenance-diagnostic.v1', 'status': 'IDENTITY_CONSISTENT_DIAGNOSTIC_ONLY',
            'boot_identifier': boot, 'vm_identity': vm, 'qpc_frequency': frequency,
            'etl_boot_time_filetime_100ns': trace_header['BootTime'],
            'capture_run_id': capture_run, 'managed_run_id': managed_run_id,
            'nonce': nonce, 'candidate_id': candidate_id,
            'probe_pid': probe['pid'], 'probe_creation_filetime_100ns': probe['creation_filetime_100ns'],
            'managed_pid': managed_pid, 'managed_creation_filetime_100ns': managed_creation_filetime}


def ready_or_child(process_ready, ready):
    return process_ready if process_ready is not None else ready


def _shared_aux_run(shared, capture, ready, managed_run_id, candidate_id):
    """Bind a logical probe to one immutable physical owner and ETL window."""
    case, evidence = shared['case'], shared['evidence']
    manifest = case.get('files') or []
    records = case.get('shared_capture') or {}
    _require(case.get('schema') == 'sst.aux-qpc-input.v1' and
             case.get('run_id') == managed_run_id and
             case.get('nonce') == capture.get('nonce') and
             case.get('candidate_id') == candidate_id and
             len({item.get('path') for item in manifest}) == len(manifest),
             'shared auxiliary descriptor identity/files differ')

    def listed(record):
        return (isinstance(record, dict) and any(
            item.get('path') == record.get('path') and
            item.get('bytes') == record.get('size') and
            item.get('sha256') == record.get('sha256') for item in manifest))

    def bound(record):
        _require(listed(record) and
                 isinstance(record.get('path'), str) and
                 isinstance(record.get('size'), int) and
                 isinstance(record.get('sha256'), str),
                 'shared auxiliary record absent from sealed inputs')
        raw = evidence.data.get(record['path'])
        _require(raw is not None and len(raw) == record['size'] and
                 hashlib.sha256(raw).hexdigest() == record['sha256'],
                 'shared auxiliary record SHA/size differs')
        return json.loads(raw.decode('utf-8-sig'))

    owner_ref, view_ref = records.get('owner'), records.get('view')
    owner, view = bound(owner_ref), bound(view_ref)
    nonce = case['nonce']
    _require(owner.get('schema') == 'sst.scenario-physical-capture-owner.v2' and
             owner.get('capture_contract') == 'scenario-shared-v2' and
             owner.get('owner_id') == nonce + ':pktmon' and
             owner.get('nonce') == nonce and
             isinstance(owner.get('scenario_id'), str) and owner['scenario_id'] and
             type(owner.get('epoch')) is int and owner['epoch'] > 0 and
             isinstance(owner.get('tool_sha256'), str) and len(owner['tool_sha256']) == 64 and
             isinstance(owner.get('guest_work_root'), str) and owner['guest_work_root'] and
             isinstance(owner.get('started_utc'), str) and owner['started_utc'] and
             isinstance(owner.get('run_ids'), list) and len(owner['run_ids']) == 2 and
             owner['run_ids'][0] != owner['run_ids'][1],
             'shared physical owner identity incomplete')
    prefix = ('evidence/' + owner['scenario_id'] + '/attempt-' +
              f"{owner['epoch']:02d}" + '/')
    _require(owner_ref['path'] == prefix + 'physical-capture-owner.json' and
             view_ref['path'] in (prefix + 'run-01-capture-view.json',
                                  prefix + 'run-02-capture-view.json') and
             view.get('schema') == 'sst.scenario-run-capture-view.v2' and
             view.get('owner') == owner_ref and
             view.get('owner_id') == owner['owner_id'] and
             view.get('scenario_id') == owner['scenario_id'] and
             view.get('attempt') == owner['epoch'] and
             view.get('nonce') == nonce and
             view.get('run_id') == managed_run_id and
             view.get('label') in ('run-01', 'run-02') and
             view_ref['path'] == prefix + view['label'] + '-capture-view.json' and
             owner['run_ids'][int(view['label'][-1]) - 1] == managed_run_id and
             view.get('capture_run_id') == nonce + ':' + view['label'] and
             view.get('guest_work_root') == owner['guest_work_root'] and
             view.get('tool_sha256') == owner['tool_sha256'] and
             view.get('capture_started_utc') == owner['started_utc'] and
             view.get('capture_stopped_utc') == owner.get('stopped_utc'),
             'shared logical view identity/epoch differs')
    physical = owner.get('physical_files')
    _require(isinstance(physical, list) and len(physical) == 3 and
             view.get('physical_files') == physical and
             {PurePosixPath(row.get('path', '')).name for row in physical} ==
                 {'pktmon.etl', 'pktmon.txt', 'pktmon-nic.json'} and
             all(listed(row) and row['path'].startswith(prefix + 'run-01/')
                 for row in physical),
             'shared physical member set differs')
    by_name = {PurePosixPath(row['path']).name: row for row in physical}
    metadata = case.get('capture') or {}
    metadata_ref = metadata.get('metadata_ref') or {}
    _require(metadata.get('etl_path') == by_name['pktmon.etl']['path'] and
             metadata.get('text_path') == by_name['pktmon.txt']['path'] and
             metadata_ref.get('path') == by_name['pktmon-nic.json']['path'] and
             metadata_ref.get('byte_start') == 0 and
             metadata_ref.get('byte_end') == by_name['pktmon-nic.json']['size'] and
             capture.get('capture_run_id') == nonce + ':run-01',
             'shared physical metadata/ETL binding differs')
    probe = view.get('probe')
    _require(listed(probe) and probe['path'].startswith(
        prefix + view['label'] + '/') and
        PurePosixPath(probe['path']).name == 'probe.jsonl' and
        view.get('probe_pid') == ready.get('pid') and
        view.get('probe_creation_ticks') == ready.get('creation_ticks') and
        ready.get('nonce') == nonce,
        'shared probe record/PID creation differs')
    if view['label'] == 'run-02':
        launch_ref = records.get('launch')
        _require(isinstance(launch_ref, dict) and
                 launch_ref.get('path') == prefix + 'run-02/probe-launch.json',
                 'shared second probe launch receipt missing')
        launch = bound(launch_ref)
        native = _identity(launch.get('native_identity'), 'probe launch',
                           view['capture_run_id'], nonce, candidate_id)
        _require(launch.get('capture_run_id') == view['capture_run_id'] and
                 launch.get('nonce') == nonce and
                 launch.get('candidate_id') == candidate_id and
                 launch.get('pid') == view['probe_pid'] == native['pid'] and
                 launch.get('creation_ticks') == view['probe_creation_ticks'] and
                 native['creation_filetime_100ns'] ==
                    view['probe_creation_ticks'] - FILETIME_EPOCH_TICKS and
                 native['boot'] == ready.get('native_identity', {}).get('boot') and
                 native['vm_identity'] == ready.get('native_identity', {}).get('vm_identity') and
                 native['qpc_frequency'] == ready.get('native_identity', {}).get('qpc_frequency'),
                 'shared second probe launch/native identity differs')
    lo, hi = shared.get('capture_interval') or (None, None)
    rows = shared.get('probe_rows') or []
    closes = [row for row in rows if row.get('event') == 'close' and row.get('nonce') == nonce]
    _require(type(lo) is int and type(hi) is int and lo < hi and closes and
             ready in rows and all(type(row.get('utc_ticks')) is int and
             lo <= (row['utc_ticks'] - 621355968000000000) * 100 <= hi
             for row in [ready, *closes]),
             'shared probe lifetime outside complete physical ETL window')
    return view['capture_run_id']


def check_aux_provenance(capture, ready, process_ready, established, trace_header,
                         candidate_id, managed_run_id, managed_pid,
                         managed_creation_filetime, *, shared=None):
    """Bind an auxiliary probe and complete ETL to one native boot and QPC.

    The managed PID/creation comes from the original start IPC. No fault
    action or fault-specific clock observation is borrowed for this path.
    """
    capture_run = capture.get('capture_run_id')
    nonce = capture.get('nonce')
    _require(bool(capture_run) and bool(nonce) and
             capture.get('candidate_id') == candidate_id,
             'auxiliary capture run/nonce/candidate missing')
    probe_run = (_shared_aux_run(shared, capture, ready, managed_run_id, candidate_id)
                 if shared is not None else capture_run)
    items = [
        _identity(capture.get('native_identity_before'), 'capture before',
                  capture_run, nonce, candidate_id),
        _identity(capture.get('native_identity_after'), 'capture after',
                  capture_run, nonce, candidate_id),
        _identity(ready.get('native_identity'), 'probe ready',
                  probe_run, nonce, candidate_id),
    ]
    if process_ready is not None:
        child = _identity(process_ready.get('native_identity'), 'probe child',
                          probe_run, nonce, candidate_id)
        items.append(child)
        probe = child
        _require(child['pid'] == process_ready.get('pid') == established.get('pid')
                 and child.get('collector_pid') == items[2]['pid'],
                 'auxiliary child native identity differs')
    else:
        probe = items[2]
        _require(probe['pid'] == ready.get('pid') == established.get('pid'),
                 'auxiliary probe PID differs')
    _require(ready.get('nonce') == established.get('nonce') == nonce and
             probe['creation_filetime_100ns'] ==
             ready_or_child(process_ready, ready).get('creation_ticks', 0) - FILETIME_EPOCH_TICKS,
             'auxiliary probe native creation/run differs')
    boot = items[0]['boot']['boot_identifier']
    vm = items[0]['vm_identity']
    frequency = items[0]['qpc_frequency']
    for item in items[1:]:
        _require(item['boot']['boot_identifier'] == boot and
                 item['vm_identity'] == vm and item['qpc_frequency'] == frequency,
                 'auxiliary cross-source boot/VM/frequency differs')
    for name in ('clock_before', 'clock_after'):
        _require(capture.get(name, {}).get('stopwatch_frequency') == frequency,
                 'auxiliary capture Stopwatch frequency differs')
    _require(trace_header.get('ReservedFlags') == 1 and
             trace_header.get('PerfFreq') == frequency and
             isinstance(trace_header.get('BootTime'), int) and
             trace_header['BootTime'] > 0 and
             trace_header.get('EventsLost') == trace_header.get('BuffersLost') == 0,
             'auxiliary ETL QPC clock/frequency/boot-time/loss unsupported')
    _require(type(managed_pid) is int and managed_pid > 0 and
             type(managed_creation_filetime) is int and managed_creation_filetime > 0,
             'auxiliary managed original process identity missing')
    cb, ca = capture.get('clock_before', {}), capture.get('clock_after', {})
    _require(all(type(x.get(key)) is int and x[key] > 0 for x in (cb, ca)
                 for key in ('q0', 'q1')) and
             cb['q0'] <= cb['q1'] <= ca['q0'] <= ca['q1'],
             'auxiliary capture QPC brackets missing/reversed')
    result = {'schema': 'sst.aux-qpc-provenance.v1', 'boot_identifier': boot,
            'vm_identity': vm, 'qpc_frequency': frequency,
            'etl_boot_time_filetime_100ns': trace_header['BootTime'],
            'capture_run_id': capture_run, 'managed_run_id': managed_run_id,
            'nonce': nonce, 'candidate_id': candidate_id,
            'probe_pid': probe['pid'],
            'probe_creation_filetime_100ns': probe['creation_filetime_100ns'],
            'managed_pid': managed_pid,
            'managed_creation_filetime_100ns': managed_creation_filetime,
            'capture_qpc': {'before': [cb['q0'], cb['q1']],
                            'after': [ca['q0'], ca['q1']]}}
    if shared is not None:
        result['probe_run_id'] = probe_run
    return result
