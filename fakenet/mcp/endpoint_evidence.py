"""Reconstruct observed UDP socket lifetimes from Windows AFD events.

This module reports evidence only. It does not waive baseline differences.
An endpoint pointer may be reused even by the same process: every successful
socket creation starts a separate lifetime. Missing creation/bind/close events
remain missing evidence, rather than being borrowed from an earlier lifetime.
"""

import ipaddress
import xml.etree.ElementTree as ET


AFD_PROVIDER = 'Microsoft-Windows-Winsock-AFD'
EVENT_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def socket_address(value):
    raw = bytes.fromhex(value)
    family = int.from_bytes(raw[:2], 'little')
    if family == 2 and len(raw) == 16:
        address = str(ipaddress.IPv4Address(raw[4:8]))
    elif family == 23 and len(raw) == 28:
        address = str(ipaddress.IPv6Address(raw[8:24]))
        scope = int.from_bytes(raw[24:28], 'little')
        if scope:
            address += '%' + str(scope)
    else:
        raise ValueError('unsupported or incomplete socket address')
    return {'family': family, 'address': address,
            'port': int.from_bytes(raw[2:4], 'big')}


def udp_lifetimes(events):
    """Return raw event references and facts; never infer missing lifecycle."""
    active = {}
    lifetimes = []
    pending_sends = {}
    for index, event in enumerate(events):
        if event['provider'] != AFD_PROVIDER:
            continue
        kind = event['id']
        if kind not in (1000, 1030, 1007, 1013, 1001):
            continue
        xml = ET.fromstring(event['xml'])
        provider = xml.find('e:System/e:Provider', EVENT_NS)
        event_id = xml.find('e:System/e:EventID', EVENT_NS)
        if (provider is None or provider.get('Name') != AFD_PROVIDER or
                event_id is None or int(event_id.text) != kind):
            raise ValueError('AFD event identity does not match its raw XML')
        data = {item.attrib['Name']: item.text
                for item in xml.findall('e:EventData/e:Data', EVENT_NS)}
        key = (data['Process'], data['Endpoint'])
        entering = int(data['EnterExit']) == 0
        if int(data['EnterExit']) not in (0, 1):
            continue
        successful = int(data['Status'], 0) == 0
        if kind == 1000 and entering:
            previous = active.pop(key, None)
            pending_sends = {k: v for k, v in pending_sends.items() if k[:2] != key}
            if previous is not None and previous['closed'] is None:
                previous['superseded_without_close'] = True
            # Track non-UDP creation too: a reused pointer must invalidate the
            # previous association instead of inheriting its UDP attributes.
            if int(data['SocketType']) != 2 or int(data['Protocol']) != 17:
                continue
            item = {'process_pointer': key[0], 'endpoint_pointer': key[1],
                    'pid': int(data['ProcessId'], 0), 'created': index,
                    'creation_time': event['time'], 'creation_succeeded': False,
                    'requested_bind': None, 'bound': None, 'bind_event': None, 'bind_time': None,
                    'outbound': [], 'close_requested': None, 'closed': None,
                    'superseded_without_close': False}
            lifetimes.append(item)
            active[key] = item
            continue
        item = active.get(key)
        if item is None or item['closed'] is not None:
            continue
        if kind == 1000 and not entering:
            item['creation_succeeded'] = successful
        elif kind == 1030:
            address = socket_address(data['Address'])
            if entering:
                item['requested_bind'] = address
            elif successful and item['requested_bind'] is not None:
                item['bound'] = address
                item['bind_event'] = index
                item['bind_time'] = event['time']
        elif kind in (1007, 1013):
            # Completion may execute in a different process/thread. Match the
            # owning kernel process, socket generation and exact buffer call.
            send_key = key + (kind, data.get('Buffer'), data.get('BufferLength'), data['Address'])
            if entering:
                sent = {'event': index, 'time': event['time'],
                        'destination': socket_address(data['Address']),
                        'completed': None, 'succeeded': False}
                item['outbound'].append(sent)
                if send_key in pending_sends or not data.get('Buffer'):
                    pending_sends[send_key] = None  # ambiguous, never guess
                else:
                    pending_sends[send_key] = sent
            else:
                if send_key in pending_sends and pending_sends[send_key] is None:
                    # Once calls overlap with indistinguishable buffers, an
                    # exit cannot tell which call finished. Keep this key
                    # poisoned until a new socket generation starts.
                    continue
                sent = pending_sends.pop(send_key, None)
                if sent is not None:
                    sent.update(completed=index, completion_time=event['time'], succeeded=successful)
        elif kind == 1001:
            if entering:
                item['close_requested'] = index
            elif successful and item['close_requested'] is not None:
                item['closed'] = index
                item['close_time'] = event['time']
    return lifetimes
