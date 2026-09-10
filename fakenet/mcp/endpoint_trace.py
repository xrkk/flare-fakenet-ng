"""Owned, bounded Windows AFD trace control for endpoint audit evidence."""

import base64
import json
import uuid


# EVENT_TRACE_PROPERTIES / ControlTraceW layout and final loss counters:
# https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
# Keep the native helper shared by the service and real-VM acceptance probes.
TRACE_CONTROL_CS = r'''
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class FakeNetEndpointTraceV1 {
    [StructLayout(LayoutKind.Sequential)]
    struct Wnode {
        public uint BufferSize, ProviderId;
        public ulong HistoricalContext, TimeStamp;
        public Guid Guid;
        public uint ClientContext, Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Properties {
        public Wnode Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize;
        public uint LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten;
        public uint LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }
    public sealed class Info {
        public uint Code, EventsLost, LogBuffersLost, RealTimeBuffersLost;
        public uint LogFileMode, MaximumFileSize, BuffersWritten;
        public string SessionGuid, LogFileName;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint StartTraceW(out ulong handle, string name, IntPtr properties);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    static extern uint ControlTraceW(ulong handle, string name, IntPtr properties, uint code);
    [DllImport("advapi32.dll")]
    static extern uint EnableTraceEx2(ulong handle, ref Guid provider, uint control,
        byte level, ulong anyKeywords, ulong allKeywords, uint timeout, IntPtr parameters);

    const int Allocation = 8192;
    static IntPtr Allocate(Guid id, string path) {
        IntPtr memory = Marshal.AllocHGlobal(Allocation);
        Marshal.Copy(new byte[Allocation], 0, memory, Allocation);
        Properties p = new Properties();
        p.Wnode.BufferSize = Allocation;
        p.Wnode.Guid = id;
        p.Wnode.ClientContext = 1;
        p.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
        p.BufferSize = 64;
        p.MinimumBuffers = 8;
        p.MaximumBuffers = 32;
        p.MaximumFileSize = 16;
        // Sequential plus explicit stop-on-hybrid-shutdown. Otherwise Windows
        // adds a session-dependent shutdown flag, including in session zero.
        p.LogFileMode = 0x00400001;
        p.FlushTimer = 1;
        p.LoggerNameOffset = (uint)Marshal.SizeOf(typeof(Properties));
        p.LogFileNameOffset = p.LoggerNameOffset + 1024;
        Marshal.StructureToPtr(p, memory, false);
        if (path != null) {
            byte[] text = System.Text.Encoding.Unicode.GetBytes(path + "\0");
            if (text.Length > Allocation - p.LogFileNameOffset) {
                Marshal.FreeHGlobal(memory);
                throw new ArgumentException("trace path too long");
            }
            Marshal.Copy(text, 0, IntPtr.Add(memory, (int)p.LogFileNameOffset), text.Length);
        }
        return memory;
    }
    static Info ReadInfo(IntPtr memory, uint code) {
        Properties p = (Properties)Marshal.PtrToStructure(memory, typeof(Properties));
        if (p.LogFileNameOffset >= Allocation)
            throw new InvalidDataException("invalid trace filename offset");
        return new Info { Code=code, SessionGuid=p.Wnode.Guid.ToString(),
            LogFileName=p.LogFileNameOffset == 0 ? "" :
                Marshal.PtrToStringUni(IntPtr.Add(memory, (int)p.LogFileNameOffset)),
            EventsLost=p.EventsLost, LogBuffersLost=p.LogBuffersLost,
            RealTimeBuffersLost=p.RealTimeBuffersLost, LogFileMode=p.LogFileMode,
            MaximumFileSize=p.MaximumFileSize, BuffersWritten=p.BuffersWritten };
    }
    static Info Control(string name, uint code) {
        IntPtr memory = Allocate(Guid.Empty, null);
        try {
            uint result = ControlTraceW(0, name, memory, code);
            if (result != 0 && result != 4201 && result != 1168)
                throw new Win32Exception((int)result);
            return ReadInfo(memory, result);
        } finally { Marshal.FreeHGlobal(memory); }
    }
    public static Info Query(string name) { return Control(name, 0); }
    static void Verify(Info info, string path, string id) {
        if (info.Code != 0 || info.SessionGuid != new Guid(id).ToString() ||
            !String.Equals(Path.GetFullPath(info.LogFileName), Path.GetFullPath(path),
                           StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("trace ownership mismatch; no stop issued");
    }
    public static Info Stop(string name, string path, string id) {
        Info observed = Query(name);
        Verify(observed, path, id);
        return Control(name, 1);
    }
    public static Info Start(string name, string path, string id) {
        if (File.Exists(path)) throw new IOException("trace evidence already exists");
        IntPtr memory = Allocate(new Guid(id), Path.GetFullPath(path));
        ulong handle;
        try {
            uint result = StartTraceW(out handle, name, memory);
            if (result != 0) throw new Win32Exception((int)result);
        } finally { Marshal.FreeHGlobal(memory); }
        try {
            Guid provider = new Guid("e53c6823-7bb8-44bb-90dc-3f86090d48a6");
            uint result = EnableTraceEx2(handle, ref provider, 1, 255,
                                        UInt64.MaxValue, 0, 0, IntPtr.Zero);
            if (result != 0) throw new Win32Exception((int)result);
            Info info = Query(name);
            Verify(info, path, id);
            return info;
        } catch {
            // Only the just-created, identity-verified session is eligible.
            Stop(name, path, id);
            throw;
        }
    }
}
'''


def trace_action_script(action, run_id, path):
    if action not in ('start', 'query', 'stop'):
        raise ValueError('unsupported trace action')
    run_id = str(uuid.UUID(run_id))
    payload = base64.b64encode(json.dumps({
        'action': action, 'id': run_id, 'path': str(path),
        'name': 'fakenetng-mcp-udp-' + run_id}).encode()).decode()
    return ("$ErrorActionPreference='Stop'; Add-Type -TypeDefinition @'\n" +
            TRACE_CONTROL_CS + "\n'@; $p=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('" + payload + "'))|ConvertFrom-Json; "
            "switch($p.action){"
            "'start'{$r=[FakeNetEndpointTraceV1]::Start($p.name,$p.path,$p.id)}"
            "'query'{$r=[FakeNetEndpointTraceV1]::Query($p.name)}"
            "'stop'{$r=[FakeNetEndpointTraceV1]::Stop($p.name,$p.path,$p.id)}}; "
            "$r|ConvertTo-Json -Depth 5 -Compress")


def complete_trace(start, stop, after_stop, size):
    """A clean stop alone cannot establish complete event coverage."""
    required = ('EventsLost', 'LogBuffersLost', 'RealTimeBuffersLost')
    numeric = required + ('Code', 'LogFileMode', 'MaximumFileSize')
    return (all(type(info.get(field)) is int for info in (start, stop) for field in numeric) and
            type(after_stop.get('Code')) is int and type(size) is int and
            start.get('Code') == stop.get('Code') == 0 and
            after_stop.get('Code') in (4201, 1168) and
            bool(start.get('SessionGuid')) and
            start['SessionGuid'] == stop.get('SessionGuid') and
            bool(start.get('LogFileName')) and
            start['LogFileName'] == stop.get('LogFileName') and
            start.get('LogFileMode') == stop.get('LogFileMode') == 0x00400001 and
            all(start.get(field) == stop.get(field) == 0 for field in required) and
            start.get('MaximumFileSize') == stop.get('MaximumFileSize') == 16 and
            0 < size < 16 * 1024 * 1024)
