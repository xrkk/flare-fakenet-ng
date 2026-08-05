"""Formal relative-throughput gate for the synchronous dual PCAP writer.

This harness performs file-only I/O. It does not start FakeNet-NG or alter
network state.
"""

import argparse
import json
import os
import platform
import shutil
import statistics
import tempfile
import time

import dpkt

from fakenet.diverters.pcapwriter import DualPcapWriter, PCAP_SNAPLEN


PACKET_COUNT = 100000
WARMUP_COUNT = 10000
RUN_COUNT = 3
MAX_RATIO = 2.5


def _packet(size):
    return b'\x45' + (b'\x00' * (size - 1))


def _count_records(path, expected_linktype):
    with open(path, 'rb') as stream:
        reader = dpkt.pcap.Reader(stream)
        if reader.datalink() != expected_linktype:
            raise AssertionError('unexpected linktype in %s' % path)
        count = sum(1 for unused_timestamp, unused_packet in reader)
    return count


def _single_trial(root, packet, count, label):
    path = os.path.join(root, '%s-single.pcap' % label)
    cpu_start = time.process_time()
    elapsed_start = time.perf_counter()
    with open(path, 'xb') as stream:
        writer = dpkt.pcap.Writer(
            stream, snaplen=PCAP_SNAPLEN, linktype=dpkt.pcap.DLT_RAW)
        for unused_index in range(count):
            writer.writepkt(packet, ts=1.0)
        writer.close()
    elapsed = time.perf_counter() - elapsed_start
    cpu = time.process_time() - cpu_start
    size = os.path.getsize(path)
    records = _count_records(path, dpkt.pcap.DLT_RAW)
    os.unlink(path)
    if records != count:
        raise AssertionError('single writer silently lost records')
    return {'elapsed_seconds': elapsed, 'cpu_seconds': cpu,
            'output_bytes': size, 'records': records}


def _dual_trial(root, packet, count, label):
    raw_path = os.path.join(root, '%s-dual-raw.pcap' % label)
    ethernet_path = os.path.join(root, '%s-dual-ethernet.pcap' % label)
    cpu_start = time.process_time()
    elapsed_start = time.perf_counter()
    writer = DualPcapWriter(raw_path, ethernet_path, clock=lambda: 1.0)
    for unused_index in range(count):
        writer.write_ip_packet(packet)
    summary = writer.close()
    elapsed = time.perf_counter() - elapsed_start
    cpu = time.process_time() - cpu_start
    output_size = os.path.getsize(raw_path) + os.path.getsize(ethernet_path)
    raw_records = _count_records(raw_path, dpkt.pcap.DLT_RAW)
    ethernet_records = _count_records(
        ethernet_path, dpkt.pcap.DLT_EN10MB)
    os.unlink(raw_path)
    os.unlink(ethernet_path)
    if (not summary.healthy or summary.raw_write_count != count or
            summary.ethernet_write_count != count or raw_records != count or
            ethernet_records != count):
        raise AssertionError('dual writer silently lost records')
    return {'elapsed_seconds': elapsed, 'cpu_seconds': cpu,
            'output_bytes': output_size, 'raw_records': raw_records,
            'ethernet_records': ethernet_records}


def run(output_path=None):
    result = {
        'machine': platform.node(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'dpkt_version': getattr(dpkt, '__version__', 'unknown'),
        'dpkt_path': os.path.abspath(dpkt.__file__),
        'dlt_raw': dpkt.pcap.DLT_RAW,
        'dlt_en10mb': dpkt.pcap.DLT_EN10MB,
        'packet_count': PACKET_COUNT,
        'warmup_count': WARMUP_COUNT,
        'runs': RUN_COUNT,
        'max_ratio': MAX_RATIO,
        'datasets': [],
    }
    if result['dpkt_version'] != '1.9.8' or result['dlt_raw'] != 12:
        raise RuntimeError('formal harness requires dpkt 1.9.8 and DLT_RAW=12')

    with tempfile.TemporaryDirectory(prefix='dual-pcap-benchmark-') as root:
        free_bytes = shutil.disk_usage(root).free
        result['volume'] = os.path.splitdrive(os.path.abspath(root))[0]
        result['free_bytes_before'] = free_bytes
        required = int(PACKET_COUNT * (1500 * 2 + 14 + 64) * 1.25)
        if free_bytes < required:
            raise RuntimeError(
                'insufficient free space: need %d, have %d' %
                (required, free_bytes))

        for packet_size in (64, 1500):
            packet = _packet(packet_size)
            _single_trial(root, packet, WARMUP_COUNT,
                          '%d-warmup' % packet_size)
            _dual_trial(root, packet, WARMUP_COUNT,
                        '%d-warmup' % packet_size)
            singles = []
            duals = []
            for index in range(RUN_COUNT):
                singles.append(_single_trial(
                    root, packet, PACKET_COUNT,
                    '%d-%d' % (packet_size, index)))
                duals.append(_dual_trial(
                    root, packet, PACKET_COUNT,
                    '%d-%d' % (packet_size, index)))
            single_median = statistics.median(
                item['elapsed_seconds'] for item in singles)
            dual_median = statistics.median(
                item['elapsed_seconds'] for item in duals)
            ratio = dual_median / single_median
            dataset = {
                'packet_bytes': packet_size,
                'input_bytes': packet_size * PACKET_COUNT,
                'single_trials': singles,
                'dual_trials': duals,
                'single_median_seconds': single_median,
                'dual_median_seconds': dual_median,
                'ratio': ratio,
                'passed': ratio <= MAX_RATIO,
            }
            result['datasets'].append(dataset)
    result['passed'] = all(item['passed'] for item in result['datasets'])

    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if output_path:
        with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(rendered + '\n')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output')
    args = parser.parse_args()
    raise SystemExit(run(args.output))
