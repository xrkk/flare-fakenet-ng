"""Independent paired-PCAP and Linux live-marker verification."""

import argparse
import json
import socket
import struct

import dpkt


SOURCE = b'\x02\x00\x00\x00\x00\x01'
DESTINATION = b'\x02\x00\x00\x00\x00\x02'


def _read(path):
    with open(path, 'rb') as stream:
        reader = dpkt.pcap.Reader(stream)
        return reader.datalink(), reader.snaplen, list(reader)


def verify_pair(raw_path, ethernet_path, minimum_records=1):
    raw_linktype, raw_snaplen, raw_records = _read(raw_path)
    eth_linktype, eth_snaplen, eth_records = _read(ethernet_path)
    if raw_linktype != dpkt.pcap.DLT_RAW or raw_linktype != 12:
        raise AssertionError('RAW linktype is not dpkt DLT_RAW=12')
    if eth_linktype != dpkt.pcap.DLT_EN10MB or eth_linktype != 1:
        raise AssertionError('Ethernet linktype is not DLT_EN10MB=1')
    if raw_snaplen != 262144 or eth_snaplen != 262144:
        raise AssertionError('paired snaplen is not 262144')
    if len(raw_records) != len(eth_records):
        raise AssertionError('paired record counts differ')
    if len(raw_records) < minimum_records:
        raise AssertionError('capture has too few records')
    versions = set()
    for index, ((raw_ts, raw), (eth_ts, ethernet)) in enumerate(
            zip(raw_records, eth_records)):
        if raw_ts != eth_ts:
            raise AssertionError('timestamp mismatch at %d' % index)
        if ethernet[:6] != DESTINATION or ethernet[6:12] != SOURCE:
            raise AssertionError('synthetic MAC mismatch at %d' % index)
        if ethernet[14:] != raw:
            raise AssertionError('payload mismatch at %d' % index)
        version = raw[0] >> 4
        if version not in (4, 6):
            raise AssertionError('unexpected IP version at %d' % index)
        versions.add(version)
        expected_type = 0x0800 if version == 4 else 0x86dd
        if struct.unpack('!H', ethernet[12:14])[0] != expected_type:
            raise AssertionError('EtherType mismatch at %d' % index)
    return raw_records, {
        'raw': raw_path,
        'ethernet': ethernet_path,
        'records': len(raw_records),
        'raw_linktype': raw_linktype,
        'ethernet_linktype': eth_linktype,
        'snaplen': raw_snaplen,
        'ip_versions': sorted(versions),
        'dpkt_version': dpkt.__version__,
        'dpkt_path': dpkt.__file__,
    }


def verify_live(raw_path, ethernet_path, marker, original_destination):
    records, result = verify_pair(raw_path, ethernet_path, minimum_records=2)
    marker_bytes = marker.encode('ascii')
    original = socket.inet_aton(original_destination)
    marker_destinations = []
    for unused_timestamp, raw in records:
        if raw[0] >> 4 != 4:
            continue
        try:
            packet = dpkt.ip.IP(raw)
        except (dpkt.UnpackError, ValueError):
            continue
        if packet.p != dpkt.ip.IP_PROTO_UDP:
            continue
        udp = packet.data
        if marker_bytes in bytes(udp.data):
            marker_destinations.append(bytes(packet.dst))
    if original not in marker_destinations:
        raise AssertionError('original marker packet is absent')
    if not any(destination != original for destination in marker_destinations):
        raise AssertionError('mangled marker packet is absent')
    result.update({
        'marker': marker,
        'marker_records': len(marker_destinations),
        'original_destination': original_destination,
        'mangled_destination_observed': True,
        'coverage': 'live Linux NFQUEUE IPv4 original and mangled packet',
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('raw')
    parser.add_argument('ethernet')
    parser.add_argument('--marker', required=True)
    parser.add_argument('--original-destination', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = verify_live(
        args.raw, args.ethernet, args.marker, args.original_destination)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(rendered + '\n')


if __name__ == '__main__':
    main()
