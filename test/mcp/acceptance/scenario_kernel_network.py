# Copyright 2026 Google LLC
"""Independent native IPv4 UDP send evidence. No sockets, VM calls or verdict labels."""
import datetime
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
GUID = '{7dd42a49-5329-4832-8dfd-43d979153a88}'
EPOCH_TICKS = 621355968000000000
FILETIME_EPOCH = 116444736000000000


def utc_ns(value):
    m = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z', value)
    if not m:
        raise ValueError('kernel event requires explicit UTC Z')
    seconds = int(datetime.datetime.fromisoformat(m[1]).replace(tzinfo=datetime.timezone.utc).timestamp())
    return seconds * 10**9 + int((m[2] or '').ljust(9, '0'))


def data_fields(event):
    nodes = event.findall('e:EventData/e:Data', NS)
    fields = {node.get('Name'): node.text for node in nodes}
    if len(fields) != len(nodes) or None in fields:
        raise ValueError('duplicate/unnamed native event field')
    return fields


def parse_event(xml, ref):
    event = ET.fromstring(xml)
    system = event.find('e:System', NS)
    provider = system.find('e:Provider', NS)
    if provider.get('Guid', '').lower() != GUID:
        return None
    if event.find('e:ProcessingErrorData', NS) is not None:
        raise ValueError('Kernel-Network event decoding failed')
    value = lambda key: system.findtext('e:' + key, namespaces=NS)
    if value('EventID') != '42':
        return None
    if tuple(value(x) for x in ('Version', 'Task', 'Opcode', 'Level', 'Keywords')) != ('0', '11', '42', '4', '0x8000000000000010'):
        raise ValueError('unsupported native UDP send schema')
    fields = data_fields(event)
    if set(fields) != {'PID', 'size', 'saddr', 'daddr', 'sport', 'dport', 'seqnum', 'connid'}:
        raise ValueError('native UDP payload fields differ')
    def integer(key, maximum):
        value = fields[key]
        if not re.fullmatch(r'\d+', value or '') or not 0 <= int(value) <= maximum:
            raise ValueError('invalid native UDP integer ' + key)
        return int(value)
    pid = integer('PID', 2**32-1)
    size = integer('size', 2**32-1)
    if not pid or not size or pid != int(system.find('e:Execution', NS).get('ProcessID')):
        raise ValueError('native UDP PID/size identity mismatch')
    def endpoint(addr, port):
        ip = str(ipaddress.IPv4Address(integer(addr, 2**32-1).to_bytes(4, 'little')))
        number = int.from_bytes(integer(port, 65535).to_bytes(2, 'little'), 'big')
        if not number:
            raise ValueError('native UDP zero port')
        return ip + ':' + str(number)
    integer('seqnum', 2**64-1); integer('connid', 2**64-1)
    return dict(pid=pid, size=size, src=endpoint('saddr', 'sport'), dst=endpoint('daddr', 'dport'),
                utc_ns=utc_ns(system.find('e:TimeCreated', NS).get('SystemTime')),
                ref=ref, kind='kernel_udp_send')


def validate_capture(raw, etl, header_raw, summary_raw, metadata, path, resolution_ns=15625000):
    if metadata.get('capture_mode') != 'kernel-network-ipv4':
        raise ValueError('wrong Kernel-Network capture mode')
    before, after = metadata['clock_before'], metadata['clock_after']
    freq = before['stopwatch_frequency']
    if (before['offset_minutes'] != 480 or after['offset_minutes'] != 480 or
            not isinstance(freq, int) or freq <= 0 or after['stopwatch_frequency'] != freq):
        raise ValueError('invalid Kernel-Network clock domain')
    wall = (after['utc_ticks'] - before['utc_ticks']) * 100
    mono = (after['mono'] - before['mono']) * 10**9 // freq
    if min(wall, mono) < 0 or abs(wall-mono) > resolution_ns:
        raise ValueError('Kernel-Network clock discontinuity')
    conversion = metadata['conversion']
    argv = conversion['tracerpt_argv']
    guest = metadata['etl_path']
    expected = ['tracerpt', guest, '-o', metadata['header_path'], '-of', 'XML', '-summary', metadata['summary_path'], '-y']
    if (argv != expected or conversion.get('tracerpt_exit_code') != 0 or
            conversion.get('event_reader_exit_code') != 0 or
            conversion.get('event_reader') != 'Get-WinEvent -Path ' + guest + ' -Oldest | ForEach-Object { $_.ToXml() }'):
        raise ValueError('Kernel-Network conversion command/exit mismatch')
    for name, data in [('etl', etl), ('events', raw), ('header', header_raw), ('summary', summary_raw)]:
        if conversion.get(name + '_sha256') != hashlib.sha256(data).hexdigest():
            raise ValueError('Kernel-Network ' + name + ' hash mismatch')
    header = ET.fromstring(header_raw)
    heads = [e for e in list(header) if 'StartTime' in data_fields(e) and 'EndTime' in data_fields(e)]
    if len(heads) != 1:
        raise ValueError('missing/ambiguous Kernel-Network header')
    fields = data_fields(heads[0])
    if int(fields['EventsLost']) or int(fields['BuffersLost']):
        raise ValueError('Kernel-Network trace loss')
    if fields['SessionNameString'] != metadata['session_name'] or fields['LogFileNameString'] != guest:
        raise ValueError('Kernel-Network header identity mismatch')
    summary = summary_raw.decode('utf-16' if summary_raw.startswith(b'\xff\xfe') else 'utf-8-sig')
    lost = re.findall(r'Total Events\s+Lost\s+(\d+)', summary)
    if lost != ['0']:
        raise ValueError('Kernel-Network summary loss/missing summary')
    lo, hi = [(int(fields[k])-FILETIME_EPOCH)*100 for k in ('StartTime', 'EndTime')]
    if not (before['utc_ticks']-EPOCH_TICKS)*100-resolution_ns <= lo <= hi <= (after['utc_ticks']-EPOCH_TICKS)*100+resolution_ns:
        raise ValueError('Kernel-Network trace outside VM clock window')
    events = []
    offset = 3 if raw.startswith(b'\xef\xbb\xbf') else 0
    for ordinal, line in enumerate(raw[offset:].splitlines(keepends=True)):
        row = json.loads(line)
        if set(row) != {'ordinal', 'xml'} or row['ordinal'] != ordinal:
            raise ValueError('Kernel-Network event order/schema mismatch')
        ref = dict(path=path, byte_start=offset, byte_end=offset+len(line), event_key='json:/xml')
        event = parse_event(row['xml'], ref)
        if event:
            if not lo <= event['utc_ns'] <= hi:
                raise ValueError('UDP event outside ETL window')
            events.append(event)
        offset += len(line)
    return dict(events=events, trace_begin_ns=lo, trace_end_ns=hi)


def match_send(events, probe, creation_ticks, resolution_ns=15625000):
    before, after = probe['send_before_ticks'], probe['send_after_ticks']
    if before > after or creation_ticks > before or min(probe['byte_count'], probe['pid']) <= 0:
        raise ValueError('invalid UDP probe creation/send interval')
    lo, hi = (before-EPOCH_TICKS)*100, (after-EPOCH_TICKS)*100
    matching = [e for e in events if e['pid'] == probe['pid'] and e['src'] == probe['src'] and
                e['dst'] == (probe.get('actual_dst') or probe['dst']) and e['size'] == probe['byte_count'] and
                lo-resolution_ns <= e['utc_ns'] <= hi+resolution_ns]
    if len(matching) != 1:
        raise ValueError('UDP send lacks unique independent PID/tuple/size/time event')
    if matching[0]['utc_ns'] < (creation_ticks-EPOCH_TICKS)*100:
        raise ValueError('UDP event precedes native process creation')
    return matching[0]
