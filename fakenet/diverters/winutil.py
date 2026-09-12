# Copyright 2025 Google LLC

#!/usr/bin/env python
import logging
logging.basicConfig(format='%(asctime)s [%(name)18s] %(message)s',
                    datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

import ctypes
from ctypes import *
from ctypes.wintypes import *

import os
import sys
import socket
import struct
import hashlib
from . import diverterbase

import time

from winreg import *

import subprocess
from dataclasses import dataclass
from collections import OrderedDict

from .processredirect import (
    OwnerResolution, OwnerResolutionStatus, ProcessOwnerIdentity)


@dataclass(frozen=True)
class TcpOwnerRow:
    local_ipv4: str
    local_port: int
    remote_ipv4: str
    remote_port: int
    state: int
    pid: int


class StrictTcpOwnerResolver(object):
    """Resolve one captured TCP flow through an injected Windows API adapter."""

    IDENTITY_CACHE_SECONDS = 5
    IDENTITY_CACHE_MAX = 256

    def __init__(self, api, reviewed_file_identity=None, clock=None):
        self._api = api
        self._reviewed_file_identity = reviewed_file_identity
        self._clock = clock or time.monotonic
        self._identity_cache = OrderedDict()

    @staticmethod
    def _same_file_identity(left, right):
        if left is None or right is None:
            return False
        return bool(
            os.path.normcase(os.path.normpath(left.final_path)) ==
            os.path.normcase(os.path.normpath(right.final_path)) and
            int(left.volume_serial) == int(right.volume_serial) and
            int(left.file_id) == int(right.file_id))

    def _purge_identity_cache(self, now):
        for pid, item in list(self._identity_cache.items()):
            if item[0] <= now:
                self._identity_cache.pop(pid, None)

    def _get_process_identity(self, pid):
        now = self._clock()
        self._purge_identity_cache(now)
        cached = self._identity_cache.get(int(pid))
        if cached is not None:
            self._identity_cache.move_to_end(int(pid))
            return cached[1]
        identity = self._api.get_process_identity(pid)
        # Only the reviewed executable is reusable. Caching arbitrary owners
        # could turn PID reuse into an erroneous compatibility pass.
        if self._same_file_identity(
                identity, self._reviewed_file_identity):
            self._identity_cache[int(pid)] = (
                now + self.IDENTITY_CACHE_SECONDS, identity)
            self._identity_cache.move_to_end(int(pid))
            while len(self._identity_cache) > self.IDENTITY_CACHE_MAX:
                self._identity_cache.popitem(last=False)
        return identity

    def resolve_tcp_owner(self, packet):
        try:
            matches = [
                row for row in self._api.get_tcp_owner_rows()
                if (row.local_ipv4 == packet.source_ipv4 and
                    row.local_port == packet.source_port and
                    row.remote_ipv4 == packet.target_ipv4 and
                    row.remote_port == packet.target_port and
                    3 <= int(row.state) <= 12)
            ]
        except Exception as exc:
            return OwnerResolution(
                OwnerResolutionStatus.ERROR, detail=type(exc).__name__)
        if not matches:
            return OwnerResolution(OwnerResolutionStatus.NOT_FOUND)
        if len(matches) != 1:
            return OwnerResolution(OwnerResolutionStatus.AMBIGUOUS)
        try:
            identity = self._get_process_identity(matches[0].pid)
        except Exception as exc:
            return OwnerResolution(
                OwnerResolutionStatus.ERROR, detail=type(exc).__name__)
        if not isinstance(identity, ProcessOwnerIdentity):
            return OwnerResolution(
                OwnerResolutionStatus.ERROR,
                detail='invalid_process_identity')
        return OwnerResolution(OwnerResolutionStatus.RESOLVED, identity)

    def revalidate_process_identity(self, identity):
        try:
            current = self._api.get_process_identity(identity.pid)
        except Exception:
            self._identity_cache.pop(int(identity.pid), None)
            return False
        if current != identity:
            self._identity_cache.pop(int(identity.pid), None)
            return False
        if self._same_file_identity(current, self._reviewed_file_identity):
            self._identity_cache[int(identity.pid)] = (
                self._clock() + self.IDENTITY_CACHE_SECONDS, current)
            self._identity_cache.move_to_end(int(identity.pid))
            while len(self._identity_cache) > self.IDENTITY_CACHE_MAX:
                self._identity_cache.popitem(last=False)
        return True

    def revalidate_rule_file(self, identity):
        try:
            return self._api.revalidate_rule_file(identity)
        except Exception:
            return False


class InstrumentedProcessIdentityApi(object):
    """Best-effort timing wrapper around the Windows process-identity adapter.

    Delegates each call to the real adapter and measures wall-clock latency.
    Calls at or above ``threshold_ms`` are reported through ``on_slow_query``
    as ``(method, elapsed_ms)`` so the diverter can attribute receiver-thread
    stalls to a specific blocking syscall (GetExtendedTcpTable enumeration,
    OpenProcess, or file-identity queries). Timing never alters behavior: any
    instrumentation failure falls through to the delegated call so owner
    resolution stays correct even when a probe raises.
    """

    def __init__(self, api, on_slow_query=None, clock=None,
                 threshold_ms=500.0):
        self._api = api
        self._on_slow_query = on_slow_query
        self._clock = clock or time.monotonic
        self._threshold_ms = float(threshold_ms)
        # [total_ms, count, max_ms] for average-cost attribution.
        self._latency_stats = [0.0, 0, 0.0]

    def _invoke(self, method, target, *args):
        start = self._clock()
        try:
            return target(*args)
        finally:
            try:
                elapsed_ms = (self._clock() - start) * 1000.0
                self._latency_stats[0] += elapsed_ms
                self._latency_stats[1] += 1
                if elapsed_ms > self._latency_stats[2]:
                    self._latency_stats[2] = elapsed_ms
                if (self._on_slow_query is not None and
                        elapsed_ms >= self._threshold_ms):
                    self._on_slow_query(method, elapsed_ms)
            except Exception:
                pass

    def drain_latency_stats(self):
        """Return ``(count, avg_ms, max_ms)`` and reset the accumulator."""
        total, count, max_ms = self._latency_stats
        avg = (total / count) if count else 0.0
        self._latency_stats = [0.0, 0, 0.0]
        return (count, avg, max_ms)

    def get_tcp_owner_rows(self):
        return self._invoke(
            'get_tcp_owner_rows', self._api.get_tcp_owner_rows)

    def get_process_identity(self, pid):
        return self._invoke(
            'get_process_identity', self._api.get_process_identity, pid)

    def revalidate_rule_file(self, identity):
        # File revalidation is not on the per-SYN hot path; delegate directly.
        return self._api.revalidate_rule_file(identity)


NO_ERROR = 0
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122

AF_INET = 2
AF_INET6 = 23

ULONG64 = c_uint64
ULONG_PTR = c_size_t


##############################################################################
# Services related functions
##############################################################################

SC_MANAGER_ALL_ACCESS = 0xF003F

SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_STOP = 0x0020
SERVICE_QUERY_STATUS = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008

SC_STATUS_PROCESS_INFO = 0x0

SERVICE_STOPPED = 0x1
SERVICE_START_PENDING = 0x2
SERVICE_STOP_PENDING = 0x3
SERVICE_RUNNING = 0x4
SERVICE_CONTINUE_PENDING = 0x5
SERVICE_PAUSE_PENDING = 0x6
SERVICE_PAUSED = 0x7

SERVICE_CONTROL_STOP = 0x1
SERVICE_CONTROL_PAUSE = 0x2
SERVICE_CONTROL_CONTINUE = 0x3

SERVICE_NO_CHANGE = 0xffffffff

SERVICE_AUTO_START = 0x2
SERVICE_BOOT_START = 0x0
SERVICE_DEMAND_START = 0x3
SERVICE_DISABLED = 0x4
SERVICE_SYSTEM_START = 0x1


class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = [
        ("dwServiceType",             DWORD),
        ("dwCurrentState",            DWORD),
        ("dwControlsAccepted",        DWORD),
        ("dwWin32ExitCode",           DWORD),
        ("dwServiceSpecificExitCode", DWORD),
        ("dwCheckPoint",              DWORD),
        ("dwWaitHint",                DWORD),
        ("dwProcessId",               DWORD),
        ("dwServiceFlags",            DWORD),
    ]

##############################################################################
# Process related functions
##############################################################################

##############################################################################
# GetExtendedTcpTable constants and structures


TCP_TABLE_OWNER_PID_ALL = 5


class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState",      DWORD),
        ("dwLocalAddr",  DWORD),
        ("dwLocalPort",  DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid",  DWORD)
    ]


class MIB_TCPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        MIB_TCPROW_OWNER_PID * 512)
    ]


class BY_HANDLE_FILE_INFORMATION(Structure):
    _fields_ = [
        ('dwFileAttributes', DWORD),
        ('ftCreationTime', FILETIME),
        ('ftLastAccessTime', FILETIME),
        ('ftLastWriteTime', FILETIME),
        ('dwVolumeSerialNumber', DWORD),
        ('nFileSizeHigh', DWORD),
        ('nFileSizeLow', DWORD),
        ('nNumberOfLinks', DWORD),
        ('nFileIndexHigh', DWORD),
        ('nFileIndexLow', DWORD),
    ]


class PROCESSENTRY32W(Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ULONG_PTR),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', WCHAR * 260),
    ]


class WindowsProcessIdentityApi(object):
    """ctypes adapter for strict owner and reviewed-file identity queries."""

    GENERIC_READ = 0x80000000
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    INVALID_HANDLE_VALUE = c_void_p(-1).value
    HASH_CHUNK = 1024 * 1024
    TH32CS_SNAPPROCESS = 0x00000002

    def __init__(self):
        self._reviewed_handle = None
        self._configure_api_signatures()

    @staticmethod
    def _configure_api_signatures():
        kernel32 = windll.kernel32
        kernel32.CreateFileW.argtypes = [
            LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE]
        kernel32.CreateFileW.restype = HANDLE
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            HANDLE, LPWSTR, DWORD, DWORD]
        kernel32.GetFinalPathNameByHandleW.restype = DWORD
        kernel32.GetFileInformationByHandle.argtypes = [
            HANDLE, POINTER(BY_HANDLE_FILE_INFORMATION)]
        kernel32.GetFileInformationByHandle.restype = BOOL
        kernel32.ReadFile.argtypes = [
            HANDLE, LPVOID, DWORD, POINTER(DWORD), LPVOID]
        kernel32.ReadFile.restype = BOOL
        kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]
        kernel32.OpenProcess.restype = HANDLE
        kernel32.GetProcessTimes.argtypes = [
            HANDLE, POINTER(FILETIME), POINTER(FILETIME),
            POINTER(FILETIME), POINTER(FILETIME)]
        kernel32.GetProcessTimes.restype = BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [
            HANDLE, DWORD, LPWSTR, POINTER(DWORD)]
        kernel32.QueryFullProcessImageNameW.restype = BOOL
        kernel32.CloseHandle.argtypes = [HANDLE]
        kernel32.CloseHandle.restype = BOOL
        kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = HANDLE
        kernel32.Process32FirstW.argtypes = [
            HANDLE, POINTER(PROCESSENTRY32W)]
        kernel32.Process32FirstW.restype = BOOL
        kernel32.Process32NextW.argtypes = [
            HANDLE, POINTER(PROCESSENTRY32W)]
        kernel32.Process32NextW.restype = BOOL
        windll.iphlpapi.GetExtendedTcpTable.argtypes = [
            LPVOID, POINTER(DWORD), BOOL, ULONG, DWORD, ULONG]
        windll.iphlpapi.GetExtendedTcpTable.restype = DWORD

    @staticmethod
    def _raise_last_error(operation):
        error = int(windll.kernel32.GetLastError())
        raise OSError(error, '%s failed with Windows error %d' %
                      (operation, error))

    def _create_file(self, path, access, share):
        handle = windll.kernel32.CreateFileW(
            c_wchar_p(path), access, share, None, self.OPEN_EXISTING, 0, None)
        if handle in (None, 0, self.INVALID_HANDLE_VALUE):
            self._raise_last_error('CreateFileW')
        return handle

    def _final_path(self, handle):
        size = 512
        while size <= 32768:
            buffer = create_unicode_buffer(size)
            copied = windll.kernel32.GetFinalPathNameByHandleW(
                handle, buffer, size, 0)
            if copied == 0:
                self._raise_last_error('GetFinalPathNameByHandleW')
            if copied < size:
                value = buffer.value
                if value.startswith('\\\\?\\UNC\\'):
                    return '\\\\' + value[8:]
                if value.startswith('\\\\?\\'):
                    return value[4:]
                return value
            size = copied + 1
        raise OSError('final image path exceeds the reviewed limit')

    def _file_identity(self, handle):
        info = BY_HANDLE_FILE_INFORMATION()
        if not windll.kernel32.GetFileInformationByHandle(
                handle, byref(info)):
            self._raise_last_error('GetFileInformationByHandle')
        file_id = ((int(info.nFileIndexHigh) << 32) |
                   int(info.nFileIndexLow))
        return info, int(info.dwVolumeSerialNumber), file_id

    def _hash_handle(self, handle):
        digest = hashlib.sha256()
        while True:
            buffer = create_string_buffer(self.HASH_CHUNK)
            read = DWORD(0)
            if not windll.kernel32.ReadFile(
                    handle, buffer, self.HASH_CHUNK, byref(read), None):
                self._raise_last_error('ReadFile')
            if read.value == 0:
                return digest.hexdigest()
            digest.update(buffer.raw[:read.value])

    def review_rule_file(self, path, expected_sha256):
        if self._reviewed_handle is not None:
            raise ValueError('only one reviewed process image is supported')
        handle = self._create_file(
            path, self.GENERIC_READ, self.FILE_SHARE_READ)
        try:
            info, volume_serial, file_id = self._file_identity(handle)
            if info.dwFileAttributes & self.FILE_ATTRIBUTE_DIRECTORY:
                raise ValueError('reviewed process image must be a file')
            final_path = self._final_path(handle)
            sha256 = self._hash_handle(handle)
            if sha256.lower() != str(expected_sha256).lower():
                raise ValueError('reviewed process image SHA-256 mismatch')
            from .processredirect import FrozenFileIdentity
            identity = FrozenFileIdentity(
                final_path, volume_serial, file_id, sha256.lower())
        except BaseException:
            windll.kernel32.CloseHandle(handle)
            raise
        self._reviewed_handle = handle
        return identity

    def get_tcp_owner_rows(self):
        size = DWORD(0)
        result = windll.iphlpapi.GetExtendedTcpTable(
            None, byref(size), False, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0)
        if result not in (NO_ERROR, ERROR_INSUFFICIENT_BUFFER):
            raise OSError(result, 'GetExtendedTcpTable sizing failed')
        size.value = max(size.value, sizeof(DWORD))
        for unused_attempt in range(3):
            buffer = create_string_buffer(size.value)
            result = windll.iphlpapi.GetExtendedTcpTable(
                buffer, byref(size), False, AF_INET,
                TCP_TABLE_OWNER_PID_ALL, 0)
            if result == ERROR_INSUFFICIENT_BUFFER:
                continue
            if result != NO_ERROR:
                raise OSError(result, 'GetExtendedTcpTable failed')
            count = cast(buffer, POINTER(DWORD)).contents.value
            required = sizeof(DWORD) + count * sizeof(MIB_TCPROW_OWNER_PID)
            if required > len(buffer):
                raise OSError('GetExtendedTcpTable returned a short buffer')
            rows_type = MIB_TCPROW_OWNER_PID * count
            rows = rows_type.from_buffer(buffer, sizeof(DWORD))
            return tuple(TcpOwnerRow(
                socket.inet_ntoa(struct.pack('<L', item.dwLocalAddr)),
                socket.ntohs(item.dwLocalPort & 0xffff),
                socket.inet_ntoa(struct.pack('<L', item.dwRemoteAddr)),
                socket.ntohs(item.dwRemotePort & 0xffff),
                int(item.dwState), int(item.dwOwningPid))
                for item in rows)
        raise OSError(ERROR_INSUFFICIENT_BUFFER,
                      'GetExtendedTcpTable buffer kept changing')

    def revalidate_rule_file(self, identity):
        if self._reviewed_handle is None:
            return False
        unused_info, volume_serial, file_id = self._file_identity(
            self._reviewed_handle)
        return bool(
            self._final_path(self._reviewed_handle).lower() ==
            identity.final_path.lower() and
            volume_serial == identity.volume_serial and
            file_id == identity.file_id)

    def _identity_for_image_path(self, path):
        handle = self._create_file(
            path, self.FILE_READ_ATTRIBUTES,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE |
            self.FILE_SHARE_DELETE)
        try:
            unused_info, volume_serial, file_id = self._file_identity(handle)
            return self._final_path(handle), volume_serial, file_id
        finally:
            windll.kernel32.CloseHandle(handle)

    def get_process_identity(self, pid):
        handle = windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            self._raise_last_error('OpenProcess')
        try:
            created = FILETIME()
            exited = FILETIME()
            kernel = FILETIME()
            user = FILETIME()
            if not windll.kernel32.GetProcessTimes(
                    handle, byref(created), byref(exited),
                    byref(kernel), byref(user)):
                self._raise_last_error('GetProcessTimes')
            size = DWORD(32768)
            buffer = create_unicode_buffer(size.value)
            if not windll.kernel32.QueryFullProcessImageNameW(
                    handle, 0, buffer, byref(size)):
                self._raise_last_error('QueryFullProcessImageNameW')
            creation_time = ((int(created.dwHighDateTime) << 32) |
                             int(created.dwLowDateTime))
            final_path, volume_serial, file_id = (
                self._identity_for_image_path(buffer.value))
            return ProcessOwnerIdentity(
                int(pid), creation_time, final_path,
                volume_serial, file_id)
        finally:
            windll.kernel32.CloseHandle(handle)

    def find_reviewed_processes(self, reviewed_identity):
        """Return exact reviewed-image processes visible in a Toolhelp scan."""
        snapshot = windll.kernel32.CreateToolhelp32Snapshot(
            self.TH32CS_SNAPPROCESS, 0)
        if snapshot in (None, 0, self.INVALID_HANDLE_VALUE):
            self._raise_last_error('CreateToolhelp32Snapshot')
        matches = []
        target_name = os.path.normcase(os.path.basename(
            reviewed_identity.final_path))
        try:
            entry = PROCESSENTRY32W()
            entry.dwSize = sizeof(PROCESSENTRY32W)
            more = windll.kernel32.Process32FirstW(snapshot, byref(entry))
            if not more:
                self._raise_last_error('Process32FirstW')
            while more:
                if (entry.th32ProcessID and
                        os.path.normcase(str(entry.szExeFile)) == target_name):
                    identity = self.get_process_identity(
                        int(entry.th32ProcessID))
                    if StrictTcpOwnerResolver._same_file_identity(
                            identity, reviewed_identity):
                        matches.append(identity)
                entry.dwSize = sizeof(PROCESSENTRY32W)
                more = windll.kernel32.Process32NextW(
                    snapshot, byref(entry))
            return tuple(matches)
        finally:
            windll.kernel32.CloseHandle(snapshot)

    def close(self):
        if self._reviewed_handle is not None:
            windll.kernel32.CloseHandle(self._reviewed_handle)
            self._reviewed_handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

##############################################################################
# GetExtendedUdpTable constants and structures


UDP_TABLE_OWNER_PID = 1


class MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD)
    ]


class MIB_UDPTABLE_OWNER_PID(Structure):
    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table",        MIB_UDPROW_OWNER_PID * 512)
    ]

###############################################################################
# GetProcessImageFileName constants and structures


MAX_PATH = 260
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


###############################################################################
# Network interface related functions
###############################################################################

MIB_IF_TYPE_ETHERNET = 6
MIB_IF_TYPE_LOOPBACK = 28
IF_TYPE_IEEE80211 = 71

###############################################################################
# GetAdaptersAddresses constants and structures

MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130

IFOPERSTATUSUP = 1


class SOCKADDR(Structure):
    _fields_ = [
        ("sa_family",           c_ushort),
        ("sa_data",             c_char * 14),
    ]


class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ("Sockaddr",            POINTER(SOCKADDR)),
        ("SockaddrLength",      INT),
    ]


class IP_ADAPTER_PREFIX(Structure):
    pass


IP_ADAPTER_PREFIX._fields_ = [
    ("Length",              ULONG),
    ("Flags",               DWORD),
    ("Next",                POINTER(IP_ADAPTER_PREFIX)),
    ("Address",             SOCKET_ADDRESS),
    ("PrefixLength",        ULONG),
]


class IP_ADAPTER_ADDRESSES(Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length",                  ULONG),
    ("IfIndex",                 DWORD),
    ("Next",                    POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName",             LPSTR),
    ("FirstUnicastAddress",     c_void_p),  # Not used
    ("FirstAnycastAddress",     c_void_p),  # Not used
    ("FirstMulticastAddress",   c_void_p),  # Not used
    ("FirstDnsServerAddress",   c_void_p),  # Not used
    ("DnsSuffix",               LPWSTR),
    ("Description",             LPWSTR),
    ("FriendlyName",            LPWSTR),
    ("PhysicalAddress",         BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength",   DWORD),
    ("Flags",                   DWORD),
    ("Mtu",                     DWORD),
    ("IfType",                  DWORD),
    ("OperStatus",              DWORD),
    ("Ipv6IfIndex",             DWORD),
    ("ZoneIndices",             DWORD * 16),
    ("FirstPrefix",             POINTER(IP_ADAPTER_PREFIX)),
    ("TransmitLinkSpeed",       ULONG64),
    ("ReceiveLinkSpeed",        ULONG64),
    ("FirstWinsServerAddress",  c_void_p),  # Not used
    ("FirstGatewayAddress",     c_void_p),  # Not used
    ("Ipv4Metric",              ULONG),
    ("Ipv6Metric",              ULONG),
    ("Luid",                    ULONG64),
    ("Dhcpv4Server",            SOCKET_ADDRESS),
    ("CompartmentId",           DWORD),
    ("NetworkGuid",             BYTE * 16),
    ("ConnectionType",          DWORD),
    ("TunnelType",              DWORD),
    ("Dhcpv6Server",            SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid",        BYTE * MAX_DHCPV6_DUID_LENGTH),
    ("Dhcpv6ClientDuidLength",  ULONG),
    ("Dhcpv6Iaid",              ULONG),
    ("FirstDnsSuffix",          c_void_p),  # Not used
]

###############################################################################
# GetAdaptersInfo constants and structures

MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_LENGTH = 8

MIB_IF_TYPE_ETHERNET = 6
MIB_IF_TYPE_LOOPBACK = 28
IF_TYPE_IEEE80211 = 71


class IP_ADDRESS_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_MASK_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_ADDR_STRING(Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next",                POINTER(IP_ADDR_STRING)),
    ("IpAddress",           IP_ADDRESS_STRING),
    ("IpMask",              IP_MASK_STRING),
    ("Context",             DWORD),
]


class IP_ADAPTER_INFO(Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next",                POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex",          DWORD),
    ("AdapterName",         c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description",         c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength",       UINT),
    ("Address",             BYTE * MAX_ADAPTER_LENGTH),
    ("Index",               DWORD),
    ("Type",                UINT),
    ("DhcpEnabled",         UINT),
    ("CurrentIpAddress",    c_void_p),  # Not used
    ("IpAddressList",       IP_ADDR_STRING),
    ("GatewayList",         IP_ADDR_STRING),
    ("DhcpServer",          IP_ADDR_STRING),
    ("HaveWins",            BOOL),
    ("PrimaryWinsServer",   IP_ADDR_STRING),
    ("SecondaryWinsServer", IP_ADDR_STRING),
    ("LeaseObtained",       c_ulong),
    ("LeaseExpires",        c_ulong),

]

###############################################################################
# GetNetworkParams constants and structures

MAX_HOSTNAME_LEN = 128
MAX_DOMAIN_NAME_LEN = 128
MAX_SCOPE_ID_LEN = 256

###############################################################################
# ConvertInterface constants and structures

NDIS_IF_MAX_STRING_SIZE = 256


class IP_ADDRESS_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_MASK_STRING(Structure):
    _fields_ = [
        ("String",               c_char * 16),
    ]


class IP_ADDR_STRING(Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next",                POINTER(IP_ADDR_STRING)),
    ("IpAddress",           IP_ADDRESS_STRING),
    ("IpMask",              IP_MASK_STRING),
    ("Context",             DWORD),
]


class FIXED_INFO(Structure):
    _fields_ = [
        ("HostName",            c_char * (MAX_HOSTNAME_LEN + 4)),
        ("DomainName",          c_char * (MAX_DOMAIN_NAME_LEN + 4)),
        ("CurrentDnsServer",    c_void_p),  # Not used
        ("DnsServerList",       IP_ADDR_STRING),
        ("NodeType",            UINT),
        ("ScopeId",             c_char * (MAX_SCOPE_ID_LEN + 4)),
        ("EnableRouting",       UINT),
        ("EnableProxy",         UINT),
        ("EnableDns",           UINT),
    ]


class WinUtilMixin(diverterbase.DiverterPerOSDelegate):
    def getNewDestinationIp(self, src_ip):
        """Gets the IP to redirect to - loopback if loopback, external
        otherwise.

        On Windows, and possibly other operating systems, if you redirect
        external packets to a loopback address, they simply will not route.

        On Linux, FTP tests will fail if you do this, so it is overridden to
        return 127.0.0.1.
        """
        return self.loopback_ip if src_ip.startswith('127.') else self.external_ip

    def fix_gateway(self):
        """Check if there is a gateway configured on any of the Ethernet
        interfaces. If that's not the case, then locate configured IP address
        and set a gateway automatically. This is necessary for VMWare Host-Only
        DHCP server which leaves default gateway empty.
        """
        fixed = False

        for adapter in self.get_adapters_info():

            # Look for a DHCP interface with a set IP address but no gateway
            # (Host-Only)
            if self.check_ipaddresses_interface(adapter) and adapter.DhcpEnabled:

                (ip_address, netmask) = next(self.get_ipaddresses_netmask(adapter))
                # set the gateway ip address to be that of the virtual network adapter
                # https://docs.vmware.com/en/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-9831F49E-1A83-4881-BB8A-D4573F2C6D91.html
                gw_address = ip_address[:ip_address.rfind('.')] + '.1'

                interface_name = self.get_adapter_friendlyname(adapter.Index)

                # Don't set gateway on loopback interfaces (e.g. Npcap Loopback
                # Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dhcp_restore.append(interface_name)

                    cmd_set_gw = "netsh interface ip set address name=\"%s\" static %s %s %s" % (
                        interface_name, ip_address, netmask, gw_address)

                    # Configure gateway
                    try:
                        subprocess.check_call(cmd_set_gw, shell=True,
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError as e:
                        self.logger.error("         Failed to set gateway %s on interface %s."
                                          % (gw_address, interface_name))
                    else:
                        self.logger.info("         Setting gateway %s on interface %s"
                                % (gw_address, interface_name))
                        fixed = True

        return fixed

    def fix_dns(self):
        """Check if there is a DNS server on any of the Ethernet interfaces. If
        that's not the case, then locate configured IP address and set a DNS
        server automatically.
        """
        fixed = False

        for adapter in self.get_adapters_info():

            if self.check_ipaddresses_interface(adapter):

                ip_address = next(self.get_ipaddresses(adapter))
                dns_address = ip_address

                interface_name = self.get_adapter_friendlyname(adapter.Index)

                # Don't set DNS on loopback interfaces (e.g. Npcap Loopback
                # Adapter)
                if not "loopback" in interface_name.lower():

                    self.adapters_dns_restore.append(interface_name)

                    cmd_set_dns = "netsh interface ip set dns name=\"%s\" static %s" % (
                        interface_name, dns_address)

                    # Configure DNS server
                    try:
                        subprocess.check_output(cmd_set_dns,
                                              shell=True,
                                              stderr=subprocess.PIPE)
                    except subprocess.CalledProcessError as e:
                        self.logger.error("         Failed to set DNS %s on interface %s."
                                          % (dns_address, interface_name))
                        self.logger.error("         netsh failed with error: %s"
                                          % (e.output))
                    else:
                        self.logger.info("         Setting DNS %s on interface %s"
                                         % (dns_address, interface_name))
                        fixed = True

        return fixed

    def get_pid_comm(self, pkt):
        conn_pid, process_name = None, None
        if pkt.proto and pkt.sport:
            if pkt.proto == 'TCP':
                conn_pid = self._get_pid_port_tcp(pkt.sport)
            elif pkt.proto == 'UDP':
                conn_pid = self._get_pid_port_udp(pkt.sport)

            if conn_pid is not None:
                process_name = self.get_process_image_filename(conn_pid)
                if process_name is None:
                    self.logger.debug(f"Failed to get process name | PID {conn_pid} | source port {pkt.sport} {pkt.proto}")
        return conn_pid, process_name

    def check_gateways(self):

        for adapter in self.get_adapters_info():
            for gateway in self.get_gateways(adapter):
                if gateway != b'0.0.0.0':
                    return True
        else:
            return False

    def check_ipaddresses(self):

        for adapter in self.get_adapters_info():
            if self.check_ipaddresses_interface(adapter):
                return True
        else:
            return False

    def check_dns_servers(self):

        FixedInfo = self.get_network_params()

        if not FixedInfo:
            return

        ip_addr_string = FixedInfo.DnsServerList

        if ip_addr_string and ip_addr_string.IpAddress.String:
            return True

        else:
            return False

    ###########################################################################
    # Service related functions
    ###########################################################################

    ###########################################################################
    # Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database.
    #
    # SC_HANDLE WINAPI OpenSCManager(
    #   _In_opt_ LPCTSTR lpMachineName,
    #   _In_opt_ LPCTSTR lpDatabaseName,
    #   _In_     DWORD   dwDesiredAccess
    # );

    def open_sc_manager(self):

        sc_handle = windll.advapi32.OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS)
        if sc_handle == 0:
            self.logger.error("Failed to call OpenSCManager")
            return

        return sc_handle

    ###########################################################################
    # Closes a handle to a service control manager or service object
    #
    # BOOL WINAPI CloseServiceHandle(
    # _In_ SC_HANDLE hSCObject
    # );

    def close_service_handle(self, sc_handle):

        if windll.advapi32.CloseServiceHandle(sc_handle) == 0:
            self.logger.error('Failed to call CloseServiceHandle')
            return False

        return True

    ###########################################################################
    # Opens an existing service.
    #
    # SC_HANDLE WINAPI OpenService(
    #   _In_ SC_HANDLE hSCManager,
    #   _In_ LPCTSTR   lpServiceName,
    #   _In_ DWORD     dwDesiredAccess
    # );

    def open_service(self, sc_handle, service_name,
                     dwDesiredAccess=SERVICE_ALL_ACCESS):

        if not sc_handle:
            return

        service_handle = windll.advapi32.OpenServiceA(sc_handle, service_name,
                                                      dwDesiredAccess)

        if service_handle == 0:
            self.logger.error('OpenService failed for %s', service_name)
            return

        return service_handle

    ###########################################################################
    # Retrieves the current status of the specified service based on the specified information level.
    #
    # BOOL WINAPI QueryServiceStatusEx(
    #   _In_      SC_HANDLE      hService,
    #   _In_      SC_STATUS_TYPE InfoLevel,
    #   _Out_opt_ LPBYTE         lpBuffer,
    #   _In_      DWORD          cbBufSize,
    #   _Out_     LPDWORD        pcbBytesNeeded
    # );

    def query_service_status_ex(self, service_handle):

        lpBuffer = SERVICE_STATUS_PROCESS()
        cbBufSize = DWORD(sizeof(SERVICE_STATUS_PROCESS))
        pcbBytesNeeded = DWORD()

        if windll.advapi32.QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, byref(lpBuffer), cbBufSize, byref(pcbBytesNeeded)) == 0:
            self.logger.error('Failed to call QueryServiceStatusEx')
            return

        return lpBuffer

    ###########################################################################
    # Sends a control code to a service.
    #
    # BOOL WINAPI ControlService(
    #   _In_  SC_HANDLE        hService,
    #   _In_  DWORD            dwControl,
    #   _Out_ LPSERVICE_STATUS lpServiceStatus
    # );

    def control_service(self, service_handle, dwControl):

        lpServiceStatus = SERVICE_STATUS_PROCESS()

        if windll.advapi32.ControlService(service_handle, dwControl, byref(lpServiceStatus)) == 0:
            self.logger.error('Failed to call ControlService')
            return

        return lpServiceStatus

    ###########################################################################
    # Starts a service
    #
    # BOOL WINAPI StartService(
    #   _In_     SC_HANDLE hService,
    #   _In_     DWORD     dwNumServiceArgs,
    #   _In_opt_ LPCTSTR   *lpServiceArgVectors
    # );

    def start_service(self, service_handle):

        if windll.advapi32.StartServiceA(service_handle, 0, 0) == 0:
            self.logger.error('Failed to call StartService')
            return False

        else:
            return True

    ###########################################################################
    # Changes the configuration parameters of a service.
    #
    # BOOL WINAPI ChangeServiceConfig(
    #   _In_      SC_HANDLE hService,
    #   _In_      DWORD     dwServiceType,
    #   _In_      DWORD     dwStartType,
    #   _In_      DWORD     dwErrorControl,
    #   _In_opt_  LPCTSTR   lpBinaryPathName,
    #   _In_opt_  LPCTSTR   lpLoadOrderGroup,
    #   _Out_opt_ LPDWORD   lpdwTagId,
    #   _In_opt_  LPCTSTR   lpDependencies,
    #   _In_opt_  LPCTSTR   lpServiceStartName,
    #   _In_opt_  LPCTSTR   lpPassword,
    #   _In_opt_  LPCTSTR   lpDisplayName
    # );

    def change_service_config(self, service_handle,
                              dwStartType=SERVICE_DISABLED):

        if windll.advapi32.ChangeServiceConfigA(service_handle, SERVICE_NO_CHANGE, dwStartType, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0) == 0:
            self.logger.error('Failed to call ChangeServiceConfig')
            raise WinError(get_last_error())
            return False

        else:
            return True

    def start_service_helper(self, service_name='Dnscache'):

        sc_handle = None
        service_handle = None

        timeout = 5

        sc_handle = self.open_sc_manager()

        if not sc_handle:
            return

        service_handle = self.open_service(sc_handle, service_name)

        if not service_handle:
            self.close_service_handle(sc_handle)
            return

        # Enable the service
        if not self.change_service_config(service_handle, SERVICE_AUTO_START):

            # Backup enable the service
            try:
                subprocess.check_call("sc config %s start= auto" %
                                      service_name, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error(
                    'Failed to enable the service %s. (sc config)',
                    service_name)
            else:
                self.logger.debug(
                    'Successfully enabled the service %s. (sc config)',
                    service_name)

        else:
            self.logger.debug('Successfully enabled the service %s.',
                             service_name)

        service_status = self.query_service_status_ex(service_handle)

        if service_status:

            if not service_status.dwCurrentState in [SERVICE_RUNNING, SERVICE_START_PENDING]:

                    # Start service
                if self.start_service(service_handle):

                        # Wait for the service to start
                    while timeout:
                        timeout -= 1
                        time.sleep(1)

                        service_status = self.query_service_status_ex(
                            service_handle)
                        if service_status.dwCurrentState == SERVICE_RUNNING:
                            self.logger.debug(
                                'Successfully started the service %s.', service_name)
                            break
                    else:
                        self.logger.error(
                            'Timed out while trying to start the service %s.', service_name)
                else:
                    self.logger.error(
                        'Failed to start the service %s.', service_name)
            else:
                self.logger.debug(
                    'Service %s is already running.', service_name)

        # As a backup call net stop
        if service_status.dwCurrentState != SERVICE_RUNNING:

            try:
                subprocess.check_call("net start %s" % service_name,
                                      shell=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error(
                    'Failed to start the service %s. (net stop)', service_name)
            else:
                self.logger.debug('Successfully started the service %s.',
                                 service_name)

        self.close_service_handle(service_handle)
        self.close_service_handle(sc_handle)

    def stop_service_helper(self, service_name='Dnscache'):

        sc_handle = None
        service_handle = None

        Control = SERVICE_CONTROL_STOP
        dwControl = DWORD(Control)
        timeout = 5

        sc_handle = self.open_sc_manager()

        if not sc_handle:
            return

        service_handle = self.open_service(sc_handle, service_name)

        if not service_handle:
            self.close_service_handle(sc_handle)
            return

        # Disable the service
        if not self.change_service_config(service_handle, SERVICE_DISABLED):

            # Backup disable the service
            try:
                subprocess.check_call("sc config %s start= disabled" %
                                      service_name, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error(
                    'Failed to disable the service %s. (sc config)', service_name)
            else:
                self.logger.debug(
                    'Successfully disabled the service %s. (sc config)', service_name)

        else:
            self.logger.debug(
                'Successfully disabled the service %s.', service_name)

        service_status = self.query_service_status_ex(service_handle)

        if service_status:

            if service_status.dwCurrentState != SERVICE_STOPPED:

                # Send a stop code to the service
                if self.control_service(service_handle, dwControl):

                    # Wait for the service to stop
                    while timeout:
                        timeout -= 1
                        time.sleep(1)

                        service_status = self.query_service_status_ex(
                            service_handle)
                        if service_status.dwCurrentState == SERVICE_STOPPED:
                            self.logger.debug(
                                'Successfully stopped the service %s.', service_name)
                            break

                    else:
                        self.logger.error(
                            'Timed out while trying to stop the service %s.', service_name)
                else:
                    self.logger.error(
                        'Failed to stop the service %s.', service_name)
            else:
                self.logger.debug(
                    'Service %s is already stopped.', service_name)

        # As a backup call net stop
        if service_status.dwCurrentState != SERVICE_STOPPED:

            try:
                subprocess.check_call("net stop %s" % service_name,
                                      shell=True, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error(
                    'Failed to stop the service %s. (net stop)', service_name)
            else:
                self.logger.debug(
                    'Successfully stopped the service %s.', service_name)

        self.close_service_handle(service_handle)
        self.close_service_handle(sc_handle)

    ###########################################################################
    # Process related functions
    ###########################################################################

    ###########################################################################
    # The GetExtendedTcpTable function retrieves a table that contains a list of TCP endpoints available to the application.
    #
    # DWORD GetExtendedTcpTable(
    #  _Out_   PVOID           pTcpTable,
    #  _Inout_ PDWORD          pdwSize,
    #  _In_    BOOL            bOrder,
    #  _In_    ULONG           ulAf,
    #  _In_    TCP_TABLE_CLASS TableClass,
    #  _In_    ULONG           Reserved
    # );

    def get_extended_tcp_table(self):

        dwSize = DWORD(sizeof(MIB_TCPROW_OWNER_PID) * 512 + 4)

        TcpTable = MIB_TCPTABLE_OWNER_PID()

        if windll.iphlpapi.GetExtendedTcpTable(byref(TcpTable), byref(dwSize), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR:
            self.logger.error("Failed to call GetExtendedTcpTable")
            return

        for item in TcpTable.table[:TcpTable.dwNumEntries]:
            yield item

    def _get_pid_port_tcp(self, port):

        for item in self.get_extended_tcp_table():

            lPort = socket.ntohs(item.dwLocalPort)
            lAddr = socket.inet_ntoa(struct.pack('L', item.dwLocalAddr))
            pid = item.dwOwningPid

            if lPort == port:
                return pid
        else:
            return None

    ##########################################################################
    # The GetExtendedUdpTable function retrieves a table that contains a list of UDP endpoints available to the application.
    #
    # DWORD GetExtendedUdpTable(
    #   _Out_   PVOID           pUdpTable,
    #   _Inout_ PDWORD          pdwSize,
    #   _In_    BOOL            bOrder,
    #   _In_    ULONG           ulAf,
    #   _In_    UDP_TABLE_CLASS TableClass,
    #   _In_    ULONG           Reserved
    # );

    def get_extended_udp_table(self):

        dwSize = DWORD(sizeof(MIB_UDPROW_OWNER_PID) * 512 + 4)

        UdpTable = MIB_UDPTABLE_OWNER_PID()

        if windll.iphlpapi.GetExtendedUdpTable(byref(UdpTable), byref(dwSize), False,  AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR:
            self.logger.error("Failed to call GetExtendedUdpTable")
            return

        for item in UdpTable.table[:UdpTable.dwNumEntries]:
            yield item

    def _get_pid_port_udp(self, port):
        checked = 0
        for item in self.get_extended_udp_table():

            lPort = socket.ntohs(item.dwLocalPort)
            lAddr = socket.inet_ntoa(struct.pack('L', item.dwLocalAddr))
            pid = item.dwOwningPid

            checked += 1
            if lPort == port:
                return pid
        else:
            self.logger.debug(f"Couldn't find PID in {checked} entries for UDP sport {port}")
            return None

    ##########################################################################
    # Retrieves the name of the executable file for the specified process.
    #
    # DWORD WINAPI GetProcessImageFileName(
    #   _In_  HANDLE hProcess,
    #   _Out_ LPTSTR lpImageFileName,
    #   _In_  DWORD  nSize
    # );

    def get_process_image_filename(self, pid):

        process_name = None

        if pid in (0, 4):
            # Skip the inevitable errno 87, invalid parameter
            process_name = 'System'
        elif pid:
            hProcess = windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if hProcess:

                lpImageFileName = create_unicode_buffer(MAX_PATH)

                if windll.psapi.GetProcessImageFileNameW(
                        hProcess, lpImageFileName, MAX_PATH) > 0:
                    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/3f6cc0e2-1303-4088-a26b-fb9582f29197
                    process_name = os.path.basename(lpImageFileName.value)
                else:
                    self.logger.error('Failed to call GetProcessImageFileNameW, %d' %
                                      (ctypes.GetLastError()))

                windll.kernel32.CloseHandle(hProcess)

        return process_name

    def setLastErrorNull(self):
        """Workaround for WinDivert handle.send() LastError behavior.

        It looks a lot like WinDivert's handle.send(wdpkt) erroneously fails if
        LastError is non-zero before invoking the method. Hence, in case of ANY
        Windows APIs setting LastError to a nonzero value, this function is
        available for the Windows Diverter to NULL LastError before invoking
        handle.send().

        This was discovered in cases where GetProcessImageFileNameW() was
        called on PID 4 (System): GetProcessImageFileNameW returned an error
        value, and GetLastError() returned 87. Reliably when this happened,
        handle.send(wdpkt) raised an exception that, when printed as a string,
        read as follows:

            [Error 87] The parameter is incorrect.

        In these cases, calling SetLastError(0) before invoking handle.send()
        yielded normal operation.
        """
        ctypes.windll.kernel32.SetLastError(0)

    ##########################################################################
    # The GetAdaptersAddresses function retrieves the addresses associated with the adapters on the local computer.
    #
    # ULONG WINAPI GetAdaptersAddresses(
    #   _In_    ULONG                 Family,
    #   _In_    ULONG                 Flags,
    #   _In_    PVOID                 Reserved,
    #   _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses,
    #   _Inout_ PULONG                SizePointer
    # );

    def get_adapters_addresses(self):

        Size = ULONG(0)

        sizing_result = windll.iphlpapi.GetAdaptersAddresses(
            AF_INET, 0, None, None, byref(Size))
        self._last_get_adapters_addresses = {
            'sizing_result': int(sizing_result),
            'buffer_size': int(Size.value),
            'result': None,
        }

        AdapterAddresses = create_string_buffer(Size.value)
        pAdapterAddresses = cast(AdapterAddresses,
                                 POINTER(IP_ADAPTER_ADDRESSES))

        result = windll.iphlpapi.GetAdaptersAddresses(
            AF_INET, 0, None, pAdapterAddresses, byref(Size))
        self._last_get_adapters_addresses['result'] = int(result)
        if result != NO_ERROR:
            self.logger.error('Failed calling GetAdaptersAddresses')
            return

        while pAdapterAddresses:

            yield pAdapterAddresses.contents
            pAdapterAddresses = pAdapterAddresses.contents.Next

    def get_active_ethernet_adapters(self):

        for adapter in self.get_adapters_addresses():

            if adapter.IfType == MIB_IF_TYPE_ETHERNET and adapter.OperStatus == IFOPERSTATUSUP:
                yield adapter

    def check_active_ethernet_adapters(self):

        for adapter in self.get_adapters_addresses():

            if adapter.IfType == MIB_IF_TYPE_ETHERNET and adapter.OperStatus == IFOPERSTATUSUP:
                return True
        else:
            return False

    def get_adapter_friendlyname(self, if_index):

        for adapter in self.get_adapters_addresses():

            if adapter.IfIndex == if_index:
                return adapter.FriendlyName

        else:
            return None

    ###########################################################################
    # The GetAdaptersInfo function retrieves adapter information for the local computer.
    #
    # On Windows XP and later:  Use the GetAdaptersAddresses function instead of GetAdaptersInfo.
    #
    # DWORD GetAdaptersInfo(
    #   _Out_   PIP_ADAPTER_INFO pAdapterInfo,
    #   _Inout_ PULONG           pOutBufLen
    # );

    def get_adapters_info(self):

        OutBufLen = DWORD(0)

        sizing_result = windll.iphlpapi.GetAdaptersInfo(None, byref(OutBufLen))
        self._last_get_adapters_info = {
            'sizing_result': int(sizing_result),
            'buffer_size': int(OutBufLen.value),
            'result': None,
        }

        AdapterInfo = create_string_buffer(OutBufLen.value)
        pAdapterInfo = cast(AdapterInfo, POINTER(IP_ADAPTER_INFO))

        result = windll.iphlpapi.GetAdaptersInfo(byref(AdapterInfo), byref(OutBufLen))
        self._last_get_adapters_info['result'] = int(result)
        if result != NO_ERROR:
            self.logger.error('Failed calling GetAdaptersInfo')
            return

        while pAdapterInfo:

            yield pAdapterInfo.contents
            pAdapterInfo = pAdapterInfo.contents.Next

    def get_gateways(self, adapter):

        gateway = adapter.GatewayList

        while gateway:

            yield gateway.IpAddress.String
            gateway = gateway.Next

    def get_ipaddresses(self, adapter):

        ipaddress = adapter.IpAddressList

        while ipaddress:

            yield ipaddress.IpAddress.String.decode("utf-8")
            ipaddress = ipaddress.Next

    def get_ipaddresses_netmask(self, adapter):

        ipaddress = adapter.IpAddressList

        while ipaddress:

            yield (ipaddress.IpAddress.String.decode("utf-8"), ipaddress.IpMask.String.decode("utf-8"))
            ipaddress = ipaddress.Next

    def get_ipaddresses_index(self, index):

        for adapter in self.get_adapters_info():

            if adapter.Index == index:
                return self.get_ipaddresses(adapter)

    def get_ip_with_gateway(self):

        for adapter in self.get_adapters_info():
            for gateway in self.get_gateways(adapter):
                if gateway != '0.0.0.0':
                    return next(self.get_ipaddresses(adapter))
        else:
            return None

    def check_ipaddresses_interface(self, adapter):

        for ipaddress in self.get_ipaddresses(adapter):
            if ipaddress != '0.0.0.0':
                return True
        else:
            return False

    ###########################################################################
    # The GetNetworkParams function retrieves network parameters for the local computer.
    #
    # DWORD GetNetworkParams(
    #   _Out_ PFIXED_INFO pFixedInfo,
    #   _In_  PULONG      pOutBufLen
    # );

    def get_network_params(self):
        OutBufLen = ULONG(0)
        result = windll.iphlpapi.GetNetworkParams(None, byref(OutBufLen))
        if result not in (NO_ERROR, ERROR_BUFFER_OVERFLOW):
            self.logger.error(
                'Failed sizing GetNetworkParams buffer (error %d)', result)
            return None

        # FIXED_INFO ends with a linked DNS list, so sizeof(FIXED_INFO) is not
        # sufficient when Windows reports more than one resolver.
        OutBufLen.value = max(OutBufLen.value, sizeof(FIXED_INFO))
        FixedInfoBuffer = create_string_buffer(OutBufLen.value)
        pFixedInfo = cast(FixedInfoBuffer, POINTER(FIXED_INFO))
        result = windll.iphlpapi.GetNetworkParams(
            pFixedInfo, byref(OutBufLen))
        if result != NO_ERROR:
            self.logger.error(
                'Failed calling GetNetworkParams (error %d)', result)
            return None

        FixedInfo = pFixedInfo.contents
        # Keep the storage for linked IP_ADDR_STRING nodes alive while callers
        # traverse DnsServerList.
        FixedInfo._buffer = FixedInfoBuffer
        return FixedInfo

    def get_dns_servers(self):

        FixedInfo = self.get_network_params()

        if not FixedInfo:
            return

        ip_addr_string = FixedInfo.DnsServerList

        while ip_addr_string:
            # DnsServerList is an embedded IP_ADDR_STRING, but every Next
            # hop is a POINTER(IP_ADDR_STRING) that must be dereferenced;
            # hosts with two or more DNS servers crashed here before
            # (v1.24 §12.27).
            node = (ip_addr_string.contents
                    if hasattr(ip_addr_string, 'contents')
                    else ip_addr_string)
            yield node.IpAddress.String
            ip_addr_string = node.Next

    ###########################################################################
    # The GetBestInterface function retrieves the index of the interface that has the best route to the specified IPv4 address.
    #
    # DWORD GetBestInterface(
    #   _In_  IPAddr dwDestAddr,
    #   _Out_ PDWORD pdwBestIfIndex
    # );

    def get_best_interface(self, ip='8.8.8.8'):
        BestIfIndex = DWORD()
        DestAddr = socket.inet_aton(ip)

        if not windll.iphlpapi.GetBestInterface(DestAddr, byref(BestIfIndex)) == NO_ERROR:
            self.logger.error('Failed calling GetBestInterface')
            return None

        return BestIfIndex.value

    def check_best_interface(self, ip='8.8.8.8'):
        BestIfIndex = DWORD()
        DestAddr = socket.inet_aton(ip)

        if not windll.iphlpapi.GetBestInterface(DestAddr, byref(BestIfIndex)) == NO_ERROR:
            return False

        return True

    # Return the best local IP address to reach defined IP address
    def get_best_ipaddress(self, ip='8.8.8.8'):

        index = self.get_best_interface(ip)

        if index != None:
            addresses = self.get_ipaddresses_index(index)
            for address in addresses:
                return address
            else:
                return None
        else:
            return None

    ###########################################################################
    # Convert interface index to name
    #
    # NETIO_STATUS WINAPI ConvertInterfaceIndexToLuid(
    #   _In_  NET_IFINDEX InterfaceIndex,
    #   _Out_ PNET_LUID   InterfaceLuid
    # );
    #
    # NETIO_STATUS WINAPI ConvertInterfaceLuidToNameA(
    #   _In_  const NET_LUID *InterfaceLuid,
    #   _Out_       PSTR     InterfaceName,
    #   _In_        SIZE_T   Length
    # );

    def convert_interface_index_to_name(self, index):

        InterfaceLuid = ULONG64()

        if not windll.iphlpapi.ConvertInterfaceIndexToLuid(index, byref(InterfaceLuid)) == NO_ERROR:
            self.logger.error('Failed calling ConvertInterfaceIndexToLuid')
            return None

        InterfaceName = create_string_buffer(NDIS_IF_MAX_STRING_SIZE + 1)

        if not windll.iphlpapi.ConvertInterfaceLuidToNameA(byref(InterfaceLuid), InterfaceName, NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR:
            self.logger.error('Failed calling ConvertInterfaceLuidToName')
            return None

        return InterfaceName.value

    ###########################################################################
    # DnsFlushResolverCache
    #
    # DWORD APIENTRY DhcpNotifyConfigChange(
    #     LPWSTR lpwszServerName,
    #     LPWSTR lpwszAdapterName,
    #     BOOL fIsNewIPAddress,
    #     DWORD dwIPIndex,
    #     DWORD dwIPAddress,
    #     DWORD dwSubnetMask,
    #     int nServiceEnable );

    def notify_ip_change(self, adapter_name):

        if windll.dhcpcsvc.DhcpNotifyConfigChange(0, adapter_name, 0, 0, 0, 0, 0) == NO_ERROR:
            self.logger.debug(
                'Successfully performed adapter change notification on %s', adapter_name)
        else:
            self.logger.error('Failed to notify adapter change on %s',
                              adapter_name)

    ###########################################################################
    # DnsFlushResolverCache
    def flush_dns(self):

        try:
            subprocess.check_call(
                'ipconfig /flushdns', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.logger.error("Failed to flush DNS cache. Local machine may "
                              "use cached DNS results.")
        else:
            self.logger.debug('Flushed DNS cache.')

    def get_reg_value(self, key, sub_key, value, sam=KEY_READ):

        try:
            handle = OpenKey(key, sub_key, 0, sam)
            [data, regtype] = QueryValueEx(handle, value)
            CloseKey(handle)
            if data == '':
                raise WindowsError

            return data

        except WindowsError:
            self.logger.error('Failed getting registry value %s.', value)
            return None

    def set_reg_value(self, key, sub_key, value, data, type=REG_SZ, sam=KEY_WRITE):

        try:
            handle = CreateKeyEx(key, sub_key, 0, sam)
            SetValueEx(handle, value, 0, type, data)
            CloseKey(handle)

            return True

        except WindowsError:
            self.logger.error('Failed setting registry value %s', value)
            return False

    ###########################################################################
    # Set DNS Server

    def set_dns_server(self, dns_server='127.0.0.1'):

        key = HKEY_LOCAL_MACHINE
        sub_key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s"
        value = 'NameServer'

        for adapter in self.get_active_ethernet_adapters():
            adapter_name = adapter.AdapterName.decode("utf-8")
            # Preserve existing setting
            dns_server_backup = self.get_reg_value(key, sub_key %
                                                   adapter_name, value)

            # Restore previous value or a blank string if the key was not
            # present
            if dns_server_backup:
                self.adapters_dns_server_backup[adapter_name] = (
                    dns_server_backup, adapter.FriendlyName)
            else:
                self.adapters_dns_server_backup[adapter_name] = (
                    '', adapter.FriendlyName)

            # Set new dns server value
            if self.set_reg_value(key, sub_key % adapter_name, value, dns_server):
                self.logger.error('Set DNS server %s on the adapter: %s',
                                 dns_server, adapter.FriendlyName)
                self.notify_ip_change(adapter_name)
            else:
                self.logger.error(
                    'Failed to set DNS server %s on the adapter: %s', dns_server, adapter.FriendlyName)

    def restore_dns_server(self):

        key = HKEY_LOCAL_MACHINE
        sub_key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s"
        value = 'NameServer'

        for adapter_name in self.adapters_dns_server_backup:

            (dns_server,
             adapter_friendlyname) = self.adapters_dns_server_backup[adapter_name]

            # Restore dns server value
            if self.set_reg_value(key, sub_key % adapter_name, value, dns_server):
                self.logger.debug('Restored DNS server %s on the adapter: %s',
                                 dns_server, adapter_friendlyname)
            else:
                self.logger.error(
                    'Failed to restore DNS server %s on the adapter: %s', dns_server, adapter_friendlyname)


def test_process_list():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    pid = self._get_pid_port_tcp(135)
    if pid:
        self.logger.info('pid: %d name: %s', pid,
                         self.get_process_image_filename(pid))
    else:
        self.logger.error('failed to get pid for tcp port 135')

    pid = self._get_pid_port_udp(123)
    if pid:
        self.logger.info('pid: %d name: %s', pid,
                         self.get_process_image_filename(pid))
    else:
        self.logger.error('failed to get pid for udp port 123')

    pid = self._get_pid_port_tcp(1234)
    if not pid:
        self.logger.info('successfully returned None for unknown tcp port '
                         '1234')

    pid = self._get_pid_port_udp(1234)
    if not pid:
        self.logger.info('successfully returned None for unknown udp port '
                         '1234')


def test_interfaces_list():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    # for adapter in self.get_adapters_addresses():
    # self.logger.info('ethernet: %s enabled: %s index: %d friendlyname: %s name: %s', adapter.IfType == MIB_IF_TYPE_ETHERNET, adapter.OperStatus == IFOPERSTATUSUP, adapter.IfIndex, adapter.FriendlyName, adapter.AdapterName)

    for dns_server in self.get_dns_servers():
        self.logger.info('dns: %s', dns_server)

    for gateway in self.get_gateways():
        self.logger.info('gateway: %s', gateway)

    for adapter in self.get_active_ethernet_adapters():
        self.logger.info('active ethernet index: %s friendlyname: %s name: %s',
                         adapter.IfIndex, adapter.FriendlyName, adapter.AdapterName.decode('utf-8'))


def test_registry_nameserver():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    key = HKEY_LOCAL_MACHINE
    sub_key = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{cd17d5b5-bf83-44f5-8de7-d988e3db5451}'
    value = 'NameServer'
    data = '127.0.0.1'

    data_tmp = self.get_reg_value(key, sub_key, value)
    self.logger.info('NameServer: %s', data_tmp)

    if self.set_reg_value(key, sub_key, value, data):
        self.logger.info('Successfully set value %s to data %s', value, data)

        data_tmp = self.get_reg_value(key, sub_key, value)
        self.logger.info('Nameserver: %s', data_tmp)
    else:
        self.logger.info('Failed to set value %s to data %s', value, data)

    self.notify_ip_change('{cd17d5b5-bf83-44f5-8de7-d988e3db5451}')

    self.flush_dns()


def test_registry_gateway():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    key = HKEY_LOCAL_MACHINE
    sub_key = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{cd17d5b5-bf83-44f5-8de7-d988e3db5451}'
    #value = 'NameServer'
    #data = '127.0.0.1'

    if self.get_reg_value(key, sub_key, 'DhcpDefaultGateway'):
        self.logger.info('DefaultGateway is set')

    else:
        ip = self.get_reg_value(key, sub_key, 'Dhcp')
        # self.logger

    self.notify_ip_change('{cd17d5b5-bf83-44f5-8de7-d988e3db5451}')


def test_check_connectivity():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    if not self.check_gateways():
        self.logger.warning('No gateways found.')
    else:
        self.logger.info('Gateways PASS')

    if not self.check_active_ethernet_adapters():
        self.logger.warning('No active ethernet adapters found')
    else:
        self.logger.info('Active ethernet PASS')

    if not self.get_best_interface():
        self.logger.warning('No routable interface found.')
    else:
        self.logger.info('Routable interface PASS')

    if not self.check_dns_servers():
        self.logger.warning('No DNS servers configured')
    else:
        self.logger.info('DNS server PASS')


def test_stop_service():

    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    self.stop_service_helper('Dnscache')


def test_start_service():
    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    self.start_service_helper('Dnscache')


def test_get_best_ip():
    class Test(WinUtilMixin):
        def __init__(self, name='WinUtil'):
            self.logger = logging.getLogger(name)

    self = Test()

    ipaddress = self.get_best_ipaddress()
    self.logger.info("Best ip address: %s" % ipaddress)

    ipaddress = self.get_ip_with_gateway()
    self.logger.info("IP with gateway address: %s" % ipaddress)


def main():
    pass

    # test_process_list()

    # test_interfaces_list()

    # test_registry_gateway()

    # test_check_connectivity()

    # test_stop_service()
    # test_start_service()

    test_get_best_ip()


if __name__ == '__main__':
    main()
