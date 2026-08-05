# Copyright 2026 Google LLC

import logging
import os
import threading
import time
from collections import namedtuple

import dpkt


PCAP_SNAPLEN = 262144
PCAP_WRITE_BUFFER_SIZE = 64 * 1024
_ETHERNET_SOURCE = b'\x02\x00\x00\x00\x00\x01'
_ETHERNET_DESTINATION = b'\x02\x00\x00\x00\x00\x02'
_ETHERNET_IPV4_HEADER = (
    _ETHERNET_DESTINATION + _ETHERNET_SOURCE + b'\x08\x00')
_ETHERNET_IPV6_HEADER = (
    _ETHERNET_DESTINATION + _ETHERNET_SOURCE + b'\x86\xdd')


def _open_capture_file(path, mode):
    return open(path, mode, buffering=PCAP_WRITE_BUFFER_SIZE)


class PcapWriteError(RuntimeError):
    """A permanent failure of the paired packet capture."""


PcapCloseSummary = namedtuple(
    'PcapCloseSummary',
    ('raw_filename', 'ethernet_filename', 'raw_write_count',
     'ethernet_write_count', 'rejected_input_count', 'write_error',
     'raw_close_error', 'ethernet_close_error', 'discard_error', 'discarded',
     'healthy'))


class DualPcapWriter(object):
    """Synchronously persist matching DLT_RAW and DLT_EN10MB captures."""

    def __init__(self, raw_filename, ethernet_filename, logger=None,
                 clock=None, writer_factory=None, opener=None,
                 snaplen=PCAP_SNAPLEN):
        self.raw_filename = str(raw_filename)
        self.ethernet_filename = str(ethernet_filename)
        self.logger = logger or logging.getLogger('Diverter')
        self._clock = clock or time.time
        self._use_dpkt_fast_path = writer_factory is None
        self._writer_factory = writer_factory or dpkt.pcap.Writer
        self._opener = opener or _open_capture_file
        self.snaplen = int(snaplen)
        self._lock = threading.Lock()
        self._raw_writer = None
        self._ethernet_writer = None
        self._raw_write = None
        self._ethernet_write = None
        self._raw_file = None
        self._ethernet_file = None
        self._created_paths = []
        self._raw_write_count = 0
        self._ethernet_write_count = 0
        self._rejected_input_count = 0
        self._last_rejection_log = None
        self._write_error = None
        self._closed = False
        self._summary = None
        self._open_pair()

    def _open_pair(self):
        try:
            self._raw_file = self._opener(self.raw_filename, 'xb')
            self._created_paths.append(self.raw_filename)
            self._raw_writer = self._writer_factory(
                self._raw_file, snaplen=self.snaplen,
                linktype=dpkt.pcap.DLT_RAW)
            self._ethernet_file = self._opener(self.ethernet_filename, 'xb')
            self._created_paths.append(self.ethernet_filename)
            self._ethernet_writer = self._writer_factory(
                self._ethernet_file, snaplen=self.snaplen,
                linktype=dpkt.pcap.DLT_EN10MB)
            # writepkt_time accepts an already immutable bytes object and
            # avoids dpkt.writepkt's duplicate bytes() conversion. Test
            # doubles and alternate compatible writers may expose writepkt
            # only, so retain that internal seam.
            self._raw_write = getattr(
                self._raw_writer, 'writepkt_time', None)
            if self._raw_write is None:
                self._raw_write = self._raw_writer.writepkt
            self._ethernet_write = getattr(
                self._ethernet_writer, 'writepkt_time', None)
            if self._ethernet_write is None:
                self._ethernet_write = self._ethernet_writer.writepkt
            if self._use_dpkt_fast_path:
                self._raw_pack_header = self._raw_writer._pack_hdr
                self._ethernet_pack_header = self._ethernet_writer._pack_hdr
                self._timestamp_multiplier = (
                    self._raw_writer._precision_multiplier)
        except Exception:
            self._rollback_initialization()
            raise

    def _rollback_initialization(self):
        for writer in (self._ethernet_writer, self._raw_writer):
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
        for stream in (self._ethernet_file, self._raw_file):
            if stream is not None and not getattr(stream, 'closed', False):
                try:
                    stream.close()
                except Exception:
                    pass
        for path in reversed(self._created_paths):
            try:
                os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def _ethernet_header(version):
        return (_ETHERNET_IPV4_HEADER if version == 4 else
                _ETHERNET_IPV6_HEADER)

    def write_ip_packet(self, raw_bytes):
        raw_bytes = bytes(raw_bytes)
        with self._lock:
            if self._closed:
                raise PcapWriteError('paired pcap writer is closed')
            if self._write_error is not None:
                raise self._write_error
            if not raw_bytes:
                self._reject_input('empty_packet')
                return False
            version = (raw_bytes[0] & 0xf0) >> 4
            if version not in (4, 6):
                self._reject_input('unknown_ip_version_%d' % version)
                return False
            ethernet_bytes = self._ethernet_header(version) + raw_bytes
            if (len(raw_bytes) > self.snaplen or
                    len(ethernet_bytes) > self.snaplen):
                self._write_error = PcapWriteError(
                    'pcap record exceeds snaplen %d' % self.snaplen)
                raise self._write_error
            timestamp = self._clock()
            try:
                if self._use_dpkt_fast_path:
                    seconds = int(timestamp)
                    subseconds = dpkt.pcap.intround(
                        timestamp % 1 * self._timestamp_multiplier)
                    raw_length = len(raw_bytes)
                    ethernet_length = len(ethernet_bytes)
                    self._raw_file.write(self._raw_pack_header(
                        seconds, subseconds, raw_length, raw_length) +
                        raw_bytes)
                else:
                    self._raw_write(raw_bytes, timestamp)
                self._raw_write_count += 1
                if self._use_dpkt_fast_path:
                    self._ethernet_file.write(self._ethernet_pack_header(
                        seconds, subseconds, ethernet_length,
                        ethernet_length) + ethernet_bytes)
                else:
                    self._ethernet_write(ethernet_bytes, timestamp)
                self._ethernet_write_count += 1
            except Exception as exc:
                self._write_error = PcapWriteError(
                    'paired pcap write failed: %s' % exc)
                raise self._write_error from exc
            return True

    def _reject_input(self, reason):
        self._rejected_input_count += 1
        now = self._clock()
        if (self._last_rejection_log is None or
                now - self._last_rejection_log >= 1.0):
            self.logger.warning(
                'PCAP_DUAL_PACKET_REJECTED reason=%s rejected_count=%d',
                reason, self._rejected_input_count)
            self._last_rejection_log = now

    def close(self, discard_if_empty=False):
        with self._lock:
            if self._summary is not None:
                return self._summary
            self._closed = True
            raw_close_error = self._close_side(
                self._raw_writer, self._raw_file)
            ethernet_close_error = self._close_side(
                self._ethernet_writer, self._ethernet_file)
            discard_error = None
            discarded = False
            if (discard_if_empty and self._raw_write_count == 0 and
                    self._ethernet_write_count == 0):
                try:
                    for path in self._created_paths:
                        if os.path.exists(path):
                            os.unlink(path)
                    discarded = True
                except Exception as exc:
                    discard_error = exc
            healthy = not any((
                self._write_error, raw_close_error, ethernet_close_error,
                discard_error)) and (
                    self._raw_write_count == self._ethernet_write_count)
            self._summary = PcapCloseSummary(
                self.raw_filename, self.ethernet_filename,
                self._raw_write_count, self._ethernet_write_count,
                self._rejected_input_count, self._write_error,
                raw_close_error, ethernet_close_error, discard_error,
                discarded, healthy)
            return self._summary

    @staticmethod
    def _close_side(writer, stream):
        first_error = None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:
                first_error = exc
        if stream is not None and not getattr(stream, 'closed', False):
            try:
                stream.close()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        return first_error
