#!/usr/bin/env python3
"""Capture every TCPIP RST record's raw QPC and TDH in the same callback.

The sequence number is only a byte-reference locator in this export. It is
never a native identity or a binding to a pktmon text line.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import traceback

import etl_raw_clock as raw
import scenario_qpc_diagnostic as qpc
import tdh_metadata as tdh

SCHEMA = 'sst.aux-qpc-single-pass.v2'


def snapshot(ptr, seq, api):
    record = raw.record_dict(ptr.contents)
    if record['provider'] != qpc.TCPIP_PROVIDER or record['id'] != 1479:
        return None
    selector = {key: record[key] for key in
                ('provider', 'id', 'version', 'opcode', 'task', 'userdata_sha256')}
    selector.update(seq=seq, raw_qpc=record['timestamp'],
                    identity_sha256=raw.identity_digest(record))
    # decode_target uses this exact pointer while this callback is live.
    return tdh.decode_target(ptr, selector, api)


def native_walk(etl, emit):
    if os.name != 'nt':
        raise raw.DiagnosticError('native Windows required for single-pass ETW')
    raw.layout_check()
    if C.sizeof(tdh.PROPERTY_DATA_DESCRIPTOR) != 16:
        raise raw.DiagnosticError('PROPERTY_DATA_DESCRIPTOR ABI mismatch')
    adv = C.WinDLL('advapi32', use_last_error=True)
    adv.OpenTraceW.argtypes = [C.POINTER(raw.EVENT_TRACE_LOGFILEW)]
    adv.OpenTraceW.restype = C.c_uint64
    adv.ProcessTrace.argtypes = [C.POINTER(C.c_uint64), C.c_uint32, C.c_void_p, C.c_void_p]
    adv.ProcessTrace.restype = C.c_uint32
    adv.CloseTrace.argtypes = [C.c_uint64]
    adv.CloseTrace.restype = C.c_uint32
    api = tdh.configure_tdh()
    logfile = raw.EVENT_TRACE_LOGFILEW()
    name = C.create_unicode_buffer(str(etl))
    logfile.LogFileName = C.cast(name, C.c_void_p).value
    logfile.ProcessTraceMode = raw.EVENT_RECORD_MODE | raw.RAW
    errors, count = [], 0

    def callback(ptr):
        nonlocal count
        if errors:
            return
        try:
            emit(ptr, count, api)
            count += 1
        except BaseException as exc:
            errors.append({'error': repr(exc), 'traceback': traceback.format_exc()})

    callback_type = C.WINFUNCTYPE(None, C.POINTER(raw.EVENT_RECORD))
    keepalive = callback_type(callback)
    logfile.EventRecordCallback = C.cast(keepalive, C.c_void_p).value
    C.set_last_error(0)
    handle = adv.OpenTraceW(C.byref(logfile))
    if handle == 0xffffffffffffffff:
        raise raw.DiagnosticError('single-pass OpenTraceW failed: ' + str(C.get_last_error()))
    try:
        header = raw.header_dict(logfile.LogfileHeader)
        raw.clock_check(header)
        handles = (C.c_uint64 * 1)(handle)
        code = adv.ProcessTrace(handles, 1, None, None)
        if errors or code or logfile.EventsLost:
            raise raw.DiagnosticError('single-pass ProcessTrace incomplete: ' +
                                      repr({'callback': errors[:1], 'return': code,
                                            'events_lost': logfile.EventsLost}))
        return {'header': header, 'events': count, 'buffers_read': logfile.BuffersRead,
                'process_trace_return': code, 'events_lost_output': logfile.EventsLost}
    finally:
        if adv.CloseTrace(handle) != 0:
            raise raw.DiagnosticError('single-pass CloseTrace failed')


def export(etl, output, *, walk=native_walk):
    etl, output = Path(etl), Path(output)
    before = raw.sha_file(etl)
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'input_before': before,
                'input_after': None, 'scan': None, 'rst_records': 0, 'error': None}
    count = 0
    try:
        with (output / 'records.jsonl').open('xb') as stream, \
                (output / 'index.jsonl').open('x', encoding='utf-8') as index:
            def emit(ptr, seq, api):
                nonlocal count
                item = snapshot(ptr, seq, api)
                if item is None:
                    return
                if (item['tdh']['second_status'] != 0 or
                        any(prop['size_status'] != 0 or prop['property_status'] != 0
                            for prop in item['property_results'])):
                    raise raw.DiagnosticError('TCPIP RST TDH incomplete at callback seq ' + str(seq))
                line = (json.dumps(item, sort_keys=True) + '\n').encode('utf-8')
                start = stream.tell()
                stream.write(line)
                index.write(json.dumps({'seq': seq, 'byte_start': start,
                    'byte_end': start + len(line),
                    'sha256': hashlib.sha256(line).hexdigest()}, sort_keys=True) + '\n')
                count += 1
            scan = walk(etl, emit)
        if scan['events'] < count or scan['process_trace_return'] != 0 or scan['events_lost_output']:
            raise raw.DiagnosticError('single-pass scan count/status incomplete')
        raw.clock_check(scan['header'])
        manifest.update(scan=scan, rst_records=count, status='COMPLETE_DIAGNOSTIC_ONLY')
    except BaseException as exc:
        manifest['error'] = {'type': type(exc).__name__, 'message': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        manifest['input_after'] = raw.sha_file(etl)
        if manifest['input_after'] != before:
            manifest['status'] = 'INCOMPLETE'
            manifest['error'] = {'type': 'InputChanged', 'message': 'ETL changed during scan'}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--etl', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    result = export(args.etl.resolve(), args.output.resolve())
    print(json.dumps({'status': result['status'], 'rst_records': result['rst_records'],
                      'error': (result['error'] or {}).get('message')}))
    return 0 if result['status'] == 'COMPLETE_DIAGNOSTIC_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
