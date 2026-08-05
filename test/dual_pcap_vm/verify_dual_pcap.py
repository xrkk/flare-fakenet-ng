import argparse
import json
import struct

import dpkt


SOURCE = b'\x02\x00\x00\x00\x00\x01'
DESTINATION = b'\x02\x00\x00\x00\x00\x02'


def read_capture(path):
    with open(path, 'rb') as stream:
        reader = dpkt.pcap.Reader(stream)
        return reader.datalink(), reader.snaplen, list(reader)


def verify(raw_path, ethernet_path, minimum_records=1):
    raw_linktype, raw_snaplen, raw_records = read_capture(raw_path)
    eth_linktype, eth_snaplen, eth_records = read_capture(ethernet_path)
    assert raw_linktype == dpkt.pcap.DLT_RAW == 12
    assert eth_linktype == dpkt.pcap.DLT_EN10MB == 1
    assert raw_snaplen == eth_snaplen == 262144
    assert len(raw_records) == len(eth_records)
    assert len(raw_records) >= minimum_records
    versions = set()
    for index, ((raw_ts, raw), (eth_ts, ethernet)) in enumerate(
            zip(raw_records, eth_records)):
        assert raw_ts == eth_ts, 'timestamp mismatch at %d' % index
        assert ethernet[:6] == DESTINATION
        assert ethernet[6:12] == SOURCE
        assert ethernet[14:] == raw, 'payload mismatch at %d' % index
        version = raw[0] >> 4
        versions.add(version)
        expected = 0x0800 if version == 4 else 0x86dd
        assert version in (4, 6)
        assert struct.unpack('!H', ethernet[12:14])[0] == expected
    assert versions == {4, 6}, 'live capture must contain IPv4 and IPv6'
    return {
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('raw')
    parser.add_argument('ethernet')
    parser.add_argument('--minimum-records', type=int, default=1)
    parser.add_argument('--output')
    args = parser.parse_args()
    result = verify(args.raw, args.ethernet, args.minimum_records)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(rendered + '\n')
