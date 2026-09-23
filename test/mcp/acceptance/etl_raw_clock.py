#!/usr/bin/env python3
"""Read-only x64 Windows ETL raw/default timestamp export; no capture or adjudication."""
import argparse
import base64
from collections import Counter
import ctypes as C
import datetime as DT
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import sys
import traceback
import uuid

SCHEMA = 'fakenet.etl-raw-clock-diagnostic.v1'
RAW = 0x00001000
EVENT_RECORD_MODE = 0x10000000
CLOCKS = {1: 'qpc', 2: 'system_timer', 3: 'cpu_cycle'}

class DiagnosticError(Exception):
    pass

class GUID(C.Structure):
    _fields_ = [('Data1', C.c_uint32), ('Data2', C.c_uint16), ('Data3', C.c_uint16), ('Data4', C.c_uint8 * 8)]

class EVENT_DESCRIPTOR(C.Structure):
    _fields_ = [('Id', C.c_uint16), ('Version', C.c_uint8), ('Channel', C.c_uint8), ('Level', C.c_uint8), ('Opcode', C.c_uint8), ('Task', C.c_uint16), ('Keyword', C.c_uint64)]

class EVENT_HEADER(C.Structure):
    _fields_ = [('Size', C.c_uint16), ('HeaderType', C.c_uint16), ('Flags', C.c_uint16), ('EventProperty', C.c_uint16), ('ThreadId', C.c_uint32), ('ProcessId', C.c_uint32), ('TimeStamp', C.c_int64), ('ProviderId', GUID), ('EventDescriptor', EVENT_DESCRIPTOR), ('ProcessorTime', C.c_uint64), ('ActivityId', GUID)]

class ETW_BUFFER_CONTEXT(C.Structure):
    _fields_ = [('ProcessorNumber', C.c_uint8), ('Alignment', C.c_uint8), ('LoggerId', C.c_uint16)]

class EVENT_HEADER_EXTENDED_DATA_ITEM(C.Structure):
    _fields_ = [('Reserved1', C.c_uint16), ('ExtType', C.c_uint16), ('Reserved2', C.c_uint16), ('DataSize', C.c_uint16), ('DataPtr', C.c_uint64)]

class EVENT_RECORD(C.Structure):
    _fields_ = [('EventHeader', EVENT_HEADER), ('BufferContext', ETW_BUFFER_CONTEXT), ('ExtendedDataCount', C.c_uint16), ('UserDataLength', C.c_uint16), ('ExtendedData', C.POINTER(EVENT_HEADER_EXTENDED_DATA_ITEM)), ('UserData', C.c_void_p), ('UserContext', C.c_void_p)]

class EVENT_TRACE_HEADER(C.Structure):
    _fields_ = [('Size', C.c_uint16), ('FieldTypeFlags', C.c_uint16), ('Type', C.c_uint8), ('Level', C.c_uint8), ('Version', C.c_uint16), ('ThreadId', C.c_uint32), ('ProcessId', C.c_uint32), ('TimeStamp', C.c_int64), ('Guid', GUID), ('ProcessorTime', C.c_uint64)]

class EVENT_TRACE(C.Structure):
    _fields_ = [('Header', EVENT_TRACE_HEADER), ('InstanceId', C.c_uint32), ('ParentInstanceId', C.c_uint32), ('ParentGuid', GUID), ('MofData', C.c_void_p), ('MofLength', C.c_uint32), ('BufferContext', ETW_BUFFER_CONTEXT)]

class TIME_ZONE_INFORMATION(C.Structure):
    _fields_ = [('Bias', C.c_int32), ('StandardName', C.c_uint16 * 32), ('StandardDate', C.c_uint16 * 8), ('StandardBias', C.c_int32), ('DaylightName', C.c_uint16 * 32), ('DaylightDate', C.c_uint16 * 8), ('DaylightBias', C.c_int32)]

class TRACE_LOGFILE_HEADER(C.Structure):
    _fields_ = [('BufferSize', C.c_uint32), ('Version', C.c_uint32), ('ProviderVersion', C.c_uint32), ('NumberOfProcessors', C.c_uint32), ('EndTime', C.c_int64), ('TimerResolution', C.c_uint32), ('MaximumFileSize', C.c_uint32), ('LogFileMode', C.c_uint32), ('BuffersWritten', C.c_uint32), ('StartBuffers', C.c_uint32), ('PointerSize', C.c_uint32), ('EventsLost', C.c_uint32), ('CpuSpeedInMHz', C.c_uint32), ('LoggerName', C.c_void_p), ('LogFileName', C.c_void_p), ('TimeZone', TIME_ZONE_INFORMATION), ('BootTime', C.c_int64), ('PerfFreq', C.c_int64), ('StartTime', C.c_int64), ('ReservedFlags', C.c_uint32), ('BuffersLost', C.c_uint32)]

class EVENT_TRACE_LOGFILEW(C.Structure):
    _fields_ = [('LogFileName', C.c_void_p), ('LoggerName', C.c_void_p), ('CurrentTime', C.c_int64), ('BuffersRead', C.c_uint32), ('ProcessTraceMode', C.c_uint32), ('CurrentEvent', EVENT_TRACE), ('LogfileHeader', TRACE_LOGFILE_HEADER), ('BufferCallback', C.c_void_p), ('BufferSize', C.c_uint32), ('Filled', C.c_uint32), ('EventsLost', C.c_uint32), ('EventRecordCallback', C.c_void_p), ('IsKernelTrace', C.c_uint32), ('Context', C.c_void_p)]

EXPECTED_LAYOUT = {
    'EVENT_HEADER': (80, {'TimeStamp': 16, 'ProviderId': 24, 'EventDescriptor': 40, 'ActivityId': 64}),
    'EVENT_RECORD': (112, {'BufferContext': 80, 'ExtendedData': 88, 'UserData': 96}),
    'EVENT_TRACE': (88, {}),
    'TRACE_LOGFILE_HEADER': (280, {'TimeZone': 72, 'BootTime': 248, 'PerfFreq': 256, 'StartTime': 264, 'ReservedFlags': 272}),
    'EVENT_TRACE_LOGFILEW': (448, {'CurrentEvent': 32, 'LogfileHeader': 120, 'BufferCallback': 400, 'EventRecordCallback': 424}),
}

def layout_check():
    if C.sizeof(C.c_void_p) != 8:
        raise DiagnosticError('x64 Python is required')
    found = {}
    for name, (size, offsets) in EXPECTED_LAYOUT.items():
        cls = globals()[name]
        actual = {'size': C.sizeof(cls), 'offsets': {k: getattr(cls, k).offset for k in offsets}}
        found[name] = actual
        if actual['size'] != size or any(actual['offsets'][k] != v for k, v in offsets.items()):
            raise DiagnosticError('ABI layout mismatch: ' + name + ': ' + str(actual))
    return found

def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return {'bytes': path.stat().st_size, 'sha256': h.hexdigest()}

def verify_input_unchanged(before, after):
    if before != after:
        raise DiagnosticError('ETL input changed during export')

def guid(g):
    return str(uuid.UUID(bytes_le=C.string_at(C.addressof(g), 16)))

def header_dict(h):
    return {'BufferSize': h.BufferSize, 'Version': h.Version, 'VersionDetail': [(h.Version >> n) & 255 for n in (0, 8, 16, 24)], 'ProviderVersion': h.ProviderVersion, 'NumberOfProcessors': h.NumberOfProcessors, 'EndTime': h.EndTime, 'TimerResolution': h.TimerResolution, 'MaximumFileSize': h.MaximumFileSize, 'LogFileMode': h.LogFileMode, 'BuffersWritten': h.BuffersWritten, 'LogInstanceGuid_union_bytes': C.string_at(C.addressof(h) + 40, 16).hex(), 'StartBuffers': h.StartBuffers, 'PointerSize': h.PointerSize, 'EventsLost': h.EventsLost, 'CpuSpeedInMHz': h.CpuSpeedInMHz, 'TimeZone': {'Bias': h.TimeZone.Bias, 'StandardName': bytes(h.TimeZone.StandardName).decode('utf-16-le').split('\0')[0], 'StandardDate': list(h.TimeZone.StandardDate), 'StandardBias': h.TimeZone.StandardBias, 'DaylightName': bytes(h.TimeZone.DaylightName).decode('utf-16-le').split('\0')[0], 'DaylightDate': list(h.TimeZone.DaylightDate), 'DaylightBias': h.TimeZone.DaylightBias, 'raw_base64': base64.b64encode(C.string_at(C.addressof(h.TimeZone), C.sizeof(h.TimeZone))).decode('ascii')}, 'BootTime': h.BootTime, 'PerfFreq': h.PerfFreq, 'StartTime': h.StartTime, 'ReservedFlags': h.ReservedFlags, 'clock_type': CLOCKS.get(h.ReservedFlags, 'unknown'), 'BuffersLost': h.BuffersLost, 'LoggerName_pointer': h.LoggerName, 'LogFileName_pointer': h.LogFileName}

def clock_check(h):
    value = h['ReservedFlags']
    if value not in CLOCKS:
        raise DiagnosticError('unknown clock type ReservedFlags=' + str(value))
    if value != 1:
        raise DiagnosticError('clock is ' + CLOCKS[value] + ', not QPC; export is diagnostic only')
    if h['PerfFreq'] <= 0:
        raise DiagnosticError('QPC clock with nonpositive PerfFreq')
    if h['EventsLost'] or h['BuffersLost']:
        raise DiagnosticError('trace reports lost events/buffers')
    if h['PointerSize'] not in (4, 8):
        raise DiagnosticError('invalid trace pointer size')

def record_dict(rec):
    h = rec.EventHeader
    d = h.EventDescriptor
    if rec.UserDataLength and not rec.UserData:
        raise DiagnosticError('null UserData with nonzero length')
    if rec.ExtendedDataCount and not rec.ExtendedData:
        raise DiagnosticError('null ExtendedData with nonzero count')
    user = C.string_at(rec.UserData, rec.UserDataLength) if rec.UserDataLength else b''
    extensions = []
    for i in range(rec.ExtendedDataCount):
        x = rec.ExtendedData[i]
        if x.DataSize and not x.DataPtr:
            raise DiagnosticError('null extended DataPtr with nonzero length')
        raw = C.string_at(x.DataPtr, x.DataSize) if x.DataSize else b''
        extensions.append({'type': x.ExtType, 'size': x.DataSize, 'reserved1': x.Reserved1, 'reserved2': x.Reserved2, 'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode('ascii')})
    return {'timestamp': int(h.TimeStamp), 'provider': guid(h.ProviderId), 'id': d.Id, 'version': d.Version, 'channel': d.Channel, 'level': d.Level, 'opcode': d.Opcode, 'task': d.Task, 'keyword': d.Keyword, 'pid': h.ProcessId, 'tid': h.ThreadId, 'activity': guid(h.ActivityId), 'header_size': h.Size, 'header_type': h.HeaderType, 'header_flags': h.Flags, 'event_property': h.EventProperty, 'processor_time': h.ProcessorTime, 'processor_number': rec.BufferContext.ProcessorNumber, 'alignment': rec.BufferContext.Alignment, 'logger_id': rec.BufferContext.LoggerId, 'userdata_length': rec.UserDataLength, 'userdata_sha256': hashlib.sha256(user).hexdigest(), 'userdata_base64': base64.b64encode(user).decode('ascii'), 'extended_data': extensions}

def identity(row):
    return {k: v for k, v in row.items() if k not in ('timestamp', 'seq', 'pass')}

def identity_digest(row):
    return hashlib.sha256(json.dumps(identity(row), sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()

def pair_streams(raw_path, utc_path, paired_path):
    counts = 0
    identities, converted_times = Counter(), Counter()
    with raw_path.open('r', encoding='utf-8') as raw, utc_path.open('r', encoding='utf-8') as utc:
        while True:
            rline, uline = raw.readline(), utc.readline()
            if not rline and not uline:
                break
            if not rline or not uline:
                raise DiagnosticError('different event counts at seq=' + str(counts))
            r, u = json.loads(rline), json.loads(uline)
            if r['seq'] != counts or u['seq'] != counts:
                raise DiagnosticError('sequence mismatch at seq=' + str(counts))
            if identity(r) != identity(u):
                raise DiagnosticError('non-time event identity/payload mismatch at seq=' + str(counts))
            identities[identity_digest(r)] += 1
            converted_times[u['timestamp']] += 1
            counts += 1
    if not counts:
        raise DiagnosticError('trace delivered zero events')
    ambiguous_count = 0
    with raw_path.open('r', encoding='utf-8') as raw, utc_path.open('r', encoding='utf-8') as utc, paired_path.open('x', encoding='utf-8') as out:
        for rline, uline in zip(raw, utc):
            r, u = json.loads(rline), json.loads(uline)
            digest = identity_digest(r)
            reasons = []
            if identities[digest] != 1:
                reasons.append('duplicate_non_time_identity')
            if converted_times[u['timestamp']] != 1:
                reasons.append('duplicate_converted_filetime')
            ambiguous_count += bool(reasons)
            out.write(json.dumps({'seq': r['seq'], 'binding_status': 'unique' if not reasons else 'ambiguous',
                                  'ambiguity': reasons, 'identity_occurrences': identities[digest],
                                  'converted_time_occurrences': converted_times[u['timestamp']],
                                  'identity_sha256': digest, 'raw_timestamp': r['timestamp'],
                                  'default_filetime_100ns': u['timestamp'], **identity(r)}, sort_keys=True) + '\n')
    return {'events': counts, 'duplicate_identity_groups': sum(v > 1 for v in identities.values()),
            'duplicate_converted_time_groups': sum(v > 1 for v in converted_times.values()),
            'ambiguous_events': ambiguous_count}

def unique_target(rows, seq):
    matches = [row for row in rows if row['seq'] == seq]
    if len(matches) != 1 or matches[0]['binding_status'] != 'unique':
        raise DiagnosticError('target seq is missing or ambiguous: ' + str(seq))
    return matches[0]

def callback_guard(emit, errors):
    def callback(ptr):
        if errors:
            return
        try:
            emit(ptr)
        except BaseException as exc:
            errors.append({'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()})
    return callback

def trace_pass(path, out_path, raw, info):
    if os.name != 'nt':
        raise DiagnosticError('native Windows required for OpenTraceW/ProcessTrace')
    advapi = C.WinDLL('advapi32', use_last_error=True)
    advapi.OpenTraceW.argtypes = [C.POINTER(EVENT_TRACE_LOGFILEW)]
    advapi.OpenTraceW.restype = C.c_uint64
    advapi.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_uint32, C.c_void_p, C.c_void_p]
    advapi.ProcessTrace.restype = C.c_uint32
    advapi.CloseTrace.argtypes = [C.c_uint64]
    advapi.CloseTrace.restype = C.c_uint32
    cb_type = C.WINFUNCTYPE(None, C.POINTER(EVENT_RECORD))
    logfile = EVENT_TRACE_LOGFILEW()
    filename = C.create_unicode_buffer(str(path))
    logfile.LogFileName = C.cast(filename, C.c_void_p).value
    logfile.ProcessTraceMode = EVENT_RECORD_MODE | (RAW if raw else 0)
    errors = []
    count = 0
    with out_path.open('x', encoding='utf-8') as stream:
        def emit(ptr):
            nonlocal count
            row = record_dict(ptr.contents)
            row['seq'] = count
            stream.write(json.dumps(row, sort_keys=True) + '\n')
            count += 1
        callback = cb_type(callback_guard(emit, errors))
        logfile.EventRecordCallback = C.cast(callback, C.c_void_p).value
        C.set_last_error(0)
        handle = advapi.OpenTraceW(C.byref(logfile))
        open_error = C.get_last_error()
        info.update({'mode': 'raw' if raw else 'default', 'open_trace_handle': handle, 'open_trace_last_error': open_error, 'process_trace_return': None, 'process_trace_last_error': None, 'close_trace_return': None, 'close_trace_last_error': None, 'header': None, 'events': 0})
        if handle == 0xffffffffffffffff:
            raise DiagnosticError('OpenTraceW failed: last_error=' + str(open_error))
        try:
            info['header'] = header_dict(logfile.LogfileHeader)
            clock_check(info['header'])
            handle_array = (C.c_uint64 * 1)(handle)
            C.set_last_error(0)
            info['process_trace_return'] = advapi.ProcessTrace(handle_array, 1, None, None)
            info['process_trace_last_error'] = C.get_last_error()
            info['events'] = count
            info['buffers_read'] = logfile.BuffersRead
            info['events_lost_output'] = logfile.EventsLost
            if errors:
                raise DiagnosticError('callback failed: ' + json.dumps(errors[0]))
            if info['process_trace_return'] != 0:
                raise DiagnosticError('ProcessTrace failed: return=' + str(info['process_trace_return']))
            if logfile.EventsLost:
                raise DiagnosticError('logfile output reports lost events')
        finally:
            C.set_last_error(0)
            info['close_trace_return'] = advapi.CloseTrace(handle)
            info['close_trace_last_error'] = C.get_last_error()
            info['events'] = count
    if info['close_trace_return'] != 0:
        raise DiagnosticError('CloseTrace failed: return=' + str(info['close_trace_return']))
    return info

def prepare_output(path):
    path.mkdir(parents=True, exist_ok=False)

def export(etl, output):
    if not etl.is_file():
        raise DiagnosticError('ETL input is not a file: ' + str(etl))
    before = sha_file(etl)
    prepare_output(output)
    meta = {'schema': SCHEMA, 'status': 'FAILED', 'input': str(etl), 'input_before': before, 'input_after': None, 'host': {'system': platform.system(), 'machine': platform.machine(), 'python_bits': struct.calcsize('P') * 8, 'python_version': sys.version}, 'abi': None, 'passes': [], 'paired_events': None, 'error': None}
    try:
        meta['abi'] = layout_check()
        if os.name != 'nt':
            raise DiagnosticError('native Windows required; no Wine/Linux result is real ETW acceptance')
        raw_path, utc_path, paired_path = (output / x for x in ('raw.jsonl', 'default.jsonl', 'paired.jsonl'))
        for target, is_raw in ((raw_path, True), (utc_path, False)):
            info = {}
            meta['passes'].append(info)
            trace_pass(etl, target, is_raw, info)
        a, b = (p['header'] for p in meta['passes'])
        if {k: v for k, v in a.items() if not k.endswith('_pointer')} != {k: v for k, v in b.items() if not k.endswith('_pointer')}:
            raise DiagnosticError('trace headers differ between passes')
        meta['pairing'] = pair_streams(raw_path, utc_path, paired_path)
        meta['paired_events'] = meta['pairing']['events']
        if meta['passes'][0]['events'] != meta['paired_events'] or meta['passes'][1]['events'] != meta['paired_events']:
            raise DiagnosticError('pass event count mismatch')
        meta['status'] = 'COMPLETE_DIAGNOSTIC_ONLY'
    except BaseException as exc:
        meta['error'] = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
    finally:
        try:
            meta['input_after'] = sha_file(etl)
        except OSError as exc:
            meta['input_after'] = {'error': str(exc)}
        try:
            verify_input_unchanged(meta['input_before'], meta['input_after'])
        except DiagnosticError:
            meta['status'] = 'FAILED'
            meta['error'] = {'type': 'InputChanged', 'message': 'ETL input changed during export'}
        (output / 'manifest.json').write_text(json.dumps(meta, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if meta['status'] != 'COMPLETE_DIAGNOSTIC_ONLY':
        raise DiagnosticError(meta['error']['message'])
    return meta

def lookup(paired, filetime, tcb, radius):
    needle = int(tcb, 16).to_bytes(8, 'little') if tcb else None
    matches = 0
    with paired.open('r', encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if abs(row['default_filetime_100ns'] - filetime) > radius:
                continue
            user = base64.b64decode(row['userdata_base64'])
            row['tcb_little_endian_payload_match'] = (needle in user) if needle else None
            print(json.dumps(row, sort_keys=True))
            matches += 1
    print('candidate_count=' + str(matches), file=sys.stderr)

def pktmon_filetime(value):
    """Convert pktmon's explicit-offset timestamp to FILETIME ticks, integer only."""
    match = re.fullmatch(r'(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)\.(\d{1,9})(Z|[+-]\d\d:\d\d)', value)
    if not match:
        raise DiagnosticError('pktmon time requires date, fractional seconds and explicit UTC offset')
    day, clock, fraction, zone = match.groups()
    base = DT.datetime.fromisoformat(day + 'T' + clock + ('+00:00' if zone == 'Z' else zone))
    delta = base.astimezone(DT.timezone.utc) - DT.datetime(1601, 1, 1, tzinfo=DT.timezone.utc)
    ns = int(fraction.ljust(9, '0'))
    return (delta.days * 86400 + delta.seconds) * 10_000_000 + ns // 100

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    exp = sub.add_parser('export', help='two native Windows ProcessTrace passes; output directory must not exist')
    exp.add_argument('--etl', type=Path, required=True)
    exp.add_argument('--output', type=Path, required=True)
    loc = sub.add_parser('lookup', help='list paired records near pktmon timestamp, optional TCB 64-bit LE payload hint; inspect identity manually')
    loc.add_argument('--paired', type=Path, required=True)
    when = loc.add_mutually_exclusive_group(required=True)
    when.add_argument('--filetime', type=int, help='default FILETIME in 100ns ticks')
    when.add_argument('--pktmon-time', help='displayed pktmon timestamp with explicit offset, e.g. 2026-09-23T15:23:52.986531300+08:00')
    loc.add_argument('--radius-100ns', type=int, default=10000, help='search radius only, not acceptance tolerance')
    loc.add_argument('--tcb', help='TCB hex from pktmon.txt; reports payload byte hint, does not prove identity')
    args = parser.parse_args(argv)
    try:
        if args.command == 'export':
            print(json.dumps({'status': export(args.etl.resolve(), args.output.resolve())['status'], 'output': str(args.output.resolve())}))
        else:
            lookup(args.paired, args.filetime if args.filetime is not None else pktmon_filetime(args.pktmon_time), args.tcb, args.radius_100ns)
    except (DiagnosticError, OSError, ValueError) as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
