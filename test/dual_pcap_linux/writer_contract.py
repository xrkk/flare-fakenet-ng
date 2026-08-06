"""Linux file-level IPv4/IPv6/truncation contract for DualPcapWriter."""

import argparse
import json
import os

from fakenet.diverters.pcapwriter import DualPcapWriter
from verify_capture import verify_pair


IPV4 = bytes.fromhex(
    '45000028000100004006f97bc0000201c6336402'
    'c35001bb0000000100000000500210006f3c0000')
IPV6 = bytes.fromhex(
    '6000000000083b4020010db8000000000000000000000001'
    '20010db8000000000000000000000002') + (b'\x00' * 8)


def run(output_directory):
    os.makedirs(output_directory, exist_ok=False)
    raw = os.path.join(output_directory, 'writer-contract.pcap')
    ethernet = os.path.join(
        output_directory, 'writer-contract-converted.pcap')
    writer = DualPcapWriter(raw, ethernet, clock=lambda: 100.5)
    payloads = (IPV4, IPV6, b'\x45', b'\x60\x00')
    for payload in payloads:
        writer.write_ip_packet(payload)
    summary = writer.close()
    records, pair = verify_pair(raw, ethernet, minimum_records=4)
    observed = [packet for unused_timestamp, packet in records]
    if observed != list(payloads):
        raise AssertionError('writer contract payload order changed')
    if not summary.healthy or summary.raw_write_count != 4 or \
            summary.ethernet_write_count != 4:
        raise AssertionError('writer contract summary is unhealthy')
    pair.update({
        'coverage': [
            'complete IPv4', 'complete IPv6',
            'truncated known-version IPv4',
            'truncated known-version IPv6',
            'normal readable EOF'],
        'summary_healthy': summary.healthy,
    })
    rendered = json.dumps(pair, indent=2, sort_keys=True)
    output = os.path.join(output_directory, 'writer-contract.json')
    with open(output, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(rendered + '\n')
    print(rendered)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    run(args.output_directory)
