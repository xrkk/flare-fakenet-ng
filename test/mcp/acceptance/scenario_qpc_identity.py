"""Diagnostic-only cross-source identity checks; never an acceptance clock."""
import uuid

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
