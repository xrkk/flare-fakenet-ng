# Copyright 2026 Google LLC
"""Bound MiniDumpWriteDump I/O before any byte crosses the disk quota."""
import ctypes as c
import math
import os
import time


class DumpIO:
    def __init__(self, stream, quota, deadline, clock=time.monotonic):
        if type(quota) is not int or quota <= 0 or quota > 512 * 1024 * 1024:
            raise ValueError('invalid dump I/O quota')
        if not math.isfinite(deadline):
            raise ValueError('invalid dump I/O deadline')
        self.stream, self.quota, self.deadline, self.clock = stream, quota, deadline, clock
        self.started = self.finished = False
        self.high_water = self.writes = 0
        self.error = None

    def write(self, offset, data):
        if self.clock() >= self.deadline:
            raise TimeoutError('dump I/O deadline exceeded')
        if offset < 0 or offset + len(data) > self.quota:
            raise RuntimeError('dump I/O disk quota exceeded')
        self.stream.seek(offset)
        if self.stream.write(data) != len(data):
            raise OSError('partial dump I/O write')
        self.high_water = max(self.high_water, offset + len(data))
        self.writes += 1

    def callback(self):
        # Windows SDK minidumpapiset.h uses pack(4), including on Win64.
        class IO(c.Structure):
            _pack_ = 4
            _fields_ = [('handle', c.c_void_p), ('offset', c.c_uint64),
                        ('buffer', c.c_void_p), ('length', c.c_uint32)]

        class Input(c.Structure):
            _pack_ = 4
            _fields_ = [('pid', c.c_uint32), ('process', c.c_void_p),
                        ('kind', c.c_uint32), ('io', IO)]

        prototype = c.WINFUNCTYPE(c.c_int32, c.c_void_p, c.POINTER(Input), c.c_void_p)

        @prototype
        def invoke(parameter, input_pointer, output):
            item = input_pointer.contents
            status = c.cast(output, c.POINTER(c.c_int32))
            try:
                if item.kind == 11:  # IoStart: all output must use our callback.
                    self.started = True
                    status[0] = 1  # S_FALSE selects alternate I/O.
                elif item.kind == 12:  # IoWriteAll
                    io = item.io
                    if not self.started or io.offset + io.length > self.quota:
                        raise RuntimeError('dump I/O disk quota exceeded')
                    for start in range(0, io.length, 1024 * 1024):
                        count = min(1024 * 1024, io.length - start)
                        self.write(io.offset + start, c.string_at(io.buffer + start, count))
                    status[0] = 0
                elif item.kind == 13:  # IoFinish
                    self.stream.flush()
                    os.fsync(self.stream.fileno())
                    if self.clock() >= self.deadline:
                        raise TimeoutError('dump fsync deadline exceeded')
                    self.finished = True
                    status[0] = 0
                elif item.kind == 6:  # Cancel: ask DbgHelp to keep checking.
                    status[0] = 1
                    status[1] = int(self.clock() >= self.deadline)
                elif item.kind in (5, 7, 9, 14):
                    # No extra memory, kernel dump, removal regions, or ignored
                    # failed memory reads; leave standard target dump intact.
                    return 0
                return 1
            except BaseException as exc:
                self.error = repr(exc)[:256]
                status[0] = -2147467259  # E_FAIL, never hide partial I/O.
                return 0

        class Information(c.Structure):
            _pack_ = 4
            _fields_ = [('callback', prototype), ('parameter', c.c_void_p)]

        return Information(invoke, None)
