"""VM-only, process-local capture fault injection launcher."""

import argparse
import sys

import dpkt

from fakenet.diverters import diverterbase
from fakenet.diverters.pcapwriter import DualPcapWriter
from fakenet import fakenet as fakenet_module


class FaultProxy(object):
    def __init__(self, delegate, fail_write=False, fail_close=False):
        self.delegate = delegate
        self.fail_write = fail_write
        self.fail_close = fail_close
        self.write_calls = 0

    def writepkt_time(self, packet, timestamp):
        self.write_calls += 1
        if self.fail_write and self.write_calls == 1:
            raise OSError('VM injected write failure')
        return self.delegate.writepkt_time(packet, timestamp)

    def writepkt(self, packet, ts=None):
        self.write_calls += 1
        if self.fail_write and self.write_calls == 1:
            raise OSError('VM injected write failure')
        return self.delegate.writepkt(packet, ts=ts)

    def close(self):
        if self.fail_close:
            raise OSError('VM injected close failure')
        return self.delegate.close()


def install_fault(mode):
    def dual_factory(raw_filename, ethernet_filename, logger):
        index = {'value': 0}

        def writer_factory(stream, snaplen, linktype):
            index['value'] += 1
            delegate = dpkt.pcap.Writer(
                stream, snaplen=snaplen, linktype=linktype)
            is_raw = index['value'] == 1
            return FaultProxy(
                delegate,
                fail_write=(mode == 'raw-write' and is_raw) or
                           (mode == 'ethernet-write' and not is_raw),
                fail_close=(mode == 'close' and not is_raw))

        return DualPcapWriter(
            raw_filename, ethernet_filename, logger,
            writer_factory=writer_factory)

    diverterbase.DualPcapWriter = dual_factory


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', required=True,
                        choices=('raw-write', 'ethernet-write', 'close'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--stop-flag', required=True)
    parser.add_argument('--log-file', required=True)
    args = parser.parse_args()
    install_fault(args.mode)
    sys.argv = [sys.argv[0], '--config-file', args.config,
                '--stop-flag', args.stop_flag, '--log-file', args.log_file,
                '--no-pause']
    fakenet_module.main()
