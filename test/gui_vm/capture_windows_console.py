# -*- coding: utf-8 -*-
"""Attach to one Windows console process and persist its final text buffer.

The v33 diagnostic core uses PyInstaller's debug bootloader.  Because the GUI
starts the elevated console executable through ShellExecuteExW, ordinary pipe
redirection cannot see the bootloader parent's final cleanup messages.  This
helper attaches read-only to that console from a separate process, waits for
the target PID to exit, then saves the retained screen buffer.
"""

import ctypes
from ctypes import wintypes
import datetime
import os
import sys
import time


TRACE_TAG = '[DEBUG-STOP03]'
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3


class COORD(ctypes.Structure):
    _fields_ = [('X', wintypes.SHORT), ('Y', wintypes.SHORT)]


class SMALL_RECT(ctypes.Structure):
    _fields_ = [
        ('Left', wintypes.SHORT), ('Top', wintypes.SHORT),
        ('Right', wintypes.SHORT), ('Bottom', wintypes.SHORT),
    ]


class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [
        ('dwSize', COORD),
        ('dwCursorPosition', COORD),
        ('wAttributes', wintypes.WORD),
        ('srWindow', SMALL_RECT),
        ('dwMaximumWindowSize', COORD),
    ]


def _utc_now_text():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        '+00:00', 'Z')


def _write_output(path, status, lines=()):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary = path + '.part'
    with open(temporary, 'w', encoding='utf-8', newline='') as handle:
        handle.write('%s status=%s captured_utc=%s\n' % (
            TRACE_TAG, status, _utc_now_text()))
        for line in lines:
            handle.write(line.rstrip('\r\n') + '\n')
    os.replace(temporary, path)


def capture_console(target_pid, output_path, stop_path=None,
                    attach_timeout=10.0, process_timeout=120.0):
    if os.name != 'nt':
        _write_output(output_path, 'refused-non-windows')
        return 2
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.FreeConsole.argtypes = []
    kernel32.FreeConsole.restype = wintypes.BOOL
    kernel32.AttachConsole.argtypes = [wintypes.DWORD]
    kernel32.AttachConsole.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL,
                                     wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetConsoleScreenBufferInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
    kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
    kernel32.ReadConsoleOutputCharacterW.argtypes = [
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, COORD,
        ctypes.POINTER(wintypes.DWORD)]
    kernel32.ReadConsoleOutputCharacterW.restype = wintypes.BOOL

    kernel32.FreeConsole()
    attach_deadline = time.monotonic() + attach_timeout
    while not kernel32.AttachConsole(target_pid):
        if time.monotonic() >= attach_deadline:
            _write_output(
                output_path,
                'attach-failed-winerror-%d' % ctypes.get_last_error())
            return 1
        time.sleep(0.1)

    access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
    process = kernel32.OpenProcess(access, False, target_pid)
    if not process:
        _write_output(
            output_path,
            'open-process-failed-winerror-%d' % ctypes.get_last_error())
        return 1
    try:
        wait_deadline = time.monotonic() + process_timeout
        wait_status = 'target-process-exited'
        while True:
            wait_result = kernel32.WaitForSingleObject(process, 250)
            if wait_result == WAIT_OBJECT_0:
                break
            if wait_result != WAIT_TIMEOUT:
                _write_output(
                    output_path,
                    'wait-failed-result-%d-winerror-%d' % (
                        wait_result, ctypes.get_last_error()))
                return 1
            if stop_path and os.path.isfile(stop_path):
                wait_status = 'capture-stop-requested-before-target-exit'
                break
            if time.monotonic() >= wait_deadline:
                wait_status = 'target-process-timeout'
                break
    finally:
        kernel32.CloseHandle(process)

    console = kernel32.CreateFileW(
        'CONOUT$', GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
    invalid_handle = ctypes.c_void_p(-1).value
    if not console or int(console) == invalid_handle:
        _write_output(
            output_path,
            'open-console-failed-winerror-%d' % ctypes.get_last_error())
        return 1
    try:
        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(console,
                                                    ctypes.byref(info)):
            _write_output(
                output_path,
                'console-info-failed-winerror-%d' % ctypes.get_last_error())
            return 1
        width = max(1, int(info.dwSize.X))
        height = max(1, int(info.dwSize.Y))
        rows = []
        for y in range(height):
            buffer = ctypes.create_unicode_buffer(width + 1)
            count = wintypes.DWORD()
            ok = kernel32.ReadConsoleOutputCharacterW(
                console, buffer, width, COORD(0, y), ctypes.byref(count))
            if not ok:
                continue
            line = buffer[:count.value].rstrip()
            if line:
                rows.append(line)
        _write_output(
            output_path,
            'captured target_pid=%d wait_status=%s width=%d height=%d' % (
                target_pid, wait_status, width, height),
            rows)
        return 0 if wait_status == 'target-process-exited' else 1
    finally:
        kernel32.CloseHandle(console)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) not in (2, 3):
        print('usage: capture_windows_console.py TARGET_PID OUTPUT_PATH '
              '[STOP_PATH]')
        return 2
    try:
        target_pid = int(argv[0])
    except ValueError:
        print('TARGET_PID must be an integer')
        return 2
    return capture_console(
        target_pid, argv[1], argv[2] if len(argv) == 3 else None)


if __name__ == '__main__':
    sys.exit(main())
