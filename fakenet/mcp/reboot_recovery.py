"""Attribute boot-ended endpoints without changing baseline or recovery authority."""
from collections import Counter
import json
import ntpath
import os
import re
import time

SCHEMA = 'fakenetng.reboot-context.v1'
FILETIME_EPOCH = 116444736000000000


def integer(value):
    if isinstance(value, bool) or not str(value).isdigit():
        raise ValueError('invalid integer identity')
    return int(value)


def filetime_ns(value):
    return (integer(value) - FILETIME_EPOCH) * 100


def address(value):
    import ipaddress
    return str(ipaddress.ip_address(str(value).strip('[]')))


def endpoint_rows(text):
    result = Counter()
    for line in str(text).splitlines():
        p = line.split()
        if not p or p[0].upper() in ('PROTO', 'ACTIVE') or p[0] in ('协议', '活动连接'):
            continue
        protocol = p[0].upper()
        if protocol == 'TCP' and len(p) == 5:
            if p[3].upper() != 'LISTENING':
                if p[3].upper() in ('ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT',
                                     'SYN_RECEIVED', 'FIN_WAIT_1', 'FIN_WAIT_2', 'LAST_ACK',
                                     'CLOSING', 'DELETE_TCB', 'CLOSED'):
                    continue
                raise ValueError('unknown TCP observation')
        elif protocol != 'UDP' or len(p) != 4 or p[2] != '*:*':
            raise ValueError('unknown endpoint observation')
        host, port = p[1].rsplit(':', 1)
        port, pid = integer(port), integer(p[-1])
        if not 0 < port <= 65535 or pid <= 0:
            raise ValueError('invalid endpoint')
        result[(protocol, address(host), port, pid)] += 1
    return result



def _project_counter(rows, width):
    result = Counter()
    for row, count in rows.items():
        result[row[:width]] += count
    return result


def _window(record):
    w = record['observation_windows']['listen_ports']
    start, end = integer(w['start_ns']), integer(w['end_ns'])
    if not 0 < start <= end:
        raise ValueError('invalid observation window')
    return start, end


def _start(baseline, proof):
    if proof['run_id'] != baseline['run_id'] or proof['start']['run_id'] != baseline['run_id']:
        raise ValueError('start proof run mismatch')
    stamp = integer(proof['start']['time_ns'])
    if not 0 < stamp <= _window(baseline)[0]:
        raise ValueError('start proof outside baseline')
    return proof['start']


def epoch_mode(baseline, sample, proof):
    """Unknown never grants access to the old PID-only UDP attribution paths."""
    try:
        start = _start(baseline, proof)
        context = sample['reboot_context']
        if context.get('schema') != SCHEMA or context.get('error'):
            return 'unknown'
        boot = integer(context['boot']['start_ns'])
        b0, b1 = _window(baseline)
        a0, _ = _window(sample)
        old_boot = (baseline.get('reboot_context') or {}).get('boot', {}).get('start_ns')
        if b1 < boot or integer(start['time_ns']) < boot or (old_boot is not None and integer(old_boot) != boot):
            return 'cross_boot'
        if boot <= integer(start['time_ns']) <= b0 <= b1 < a0:
            return 'same_boot'
    except (KeyError, TypeError, ValueError):
        pass
    return 'unknown'


def _owners(context):
    result = {}
    for owner in context['owners']:
        pid = integer(owner['pid'])
        if pid in result:
            raise ValueError('ambiguous current process identity')
        result[pid] = owner
    return result


def _image(value):
    path = ntpath.normcase(str(value or ''))
    if not ntpath.isabs(path) or not path.endswith('.exe') or '..' in path.split('\\'):
        raise ValueError('absolute process image unavailable')
    return ntpath.normpath(path)


def _service_image(command):
    match = re.match(r'^\s*(?:"([^"]+)"|(\S+))', str(command or ''))
    if not match:
        raise ValueError('SCM image unavailable')
    return _image(match.group(1) or match.group(2))


def _native_owner(owner, context, end_ns, product_root):
    if owner.get('alive') is not True or owner.get('error'):
        raise ValueError('current process handle unverified')
    born = filetime_ns(owner['birth_ticks'])
    if not integer(context['boot']['start_ns']) <= born <= end_ns:
        raise ValueError('current process birth outside boot/window')
    image = _image(owner['image'])
    root = ntpath.normcase(ntpath.normpath(str(product_root or ''))).rstrip('\\')
    if (root and (image == root or image.startswith(root + '\\'))) or ntpath.basename(image) in (
            'fakenet.exe', 'fakenetng-mcp.exe', 'fakenetng-mcp-managed.exe'):
        raise ValueError('product process owns endpoint')
    services = owner.get('services') or []
    if services:
        if any(integer(s['pid']) != integer(owner['pid']) or s['state'] != 'Running' or
               _service_image(s['command']) != image or not s.get('name') for s in services):
            raise ValueError('SCM/native process identity mismatch')
        return {'kind': 'scm_host', 'services': sorted(s['name'] for s in services),
                'image': image, 'birth_ticks': str(owner['birth_ticks'])}
    expected = _image(ntpath.join(context['system_root'], 'System32', 'services.exe'))
    if image != expected or owner.get('critical') is not True or owner.get('sid') != 'S-1-5-18':
        raise ValueError('non-service or unknown endpoint owner')
    return {'kind': 'scm_manager', 'image': image, 'birth_ticks': str(owner['birth_ticks'])}


def cross_boot_endpoint_changes(baseline, sample, proof):
    from fakenet.mcp.baseline import audit_compare
    result = {'accepted': False, 'mode': epoch_mode(baseline, sample, proof), 'attributed': []}
    try:
        if result['mode'] != 'cross_boot' or sample['run_id'] != baseline['run_id']:
            raise ValueError('cross-boot run not established')
        start = _start(baseline, proof)
        context = sample['reboot_context']
        boot = context['boot']
        event = boot['event']
        if (event['provider'] != 'Microsoft-Windows-Kernel-General' or integer(event['id']) != 12 or
                integer(event['record_id']) <= 0 or integer(event['start_ns']) != integer(boot['start_ns']) or
                str(event['computer']).lower() != str(boot['computer']).lower() or not boot['computer']):
            raise ValueError('current kernel boot event missing or contradictory')
        b0, b1 = _window(baseline)
        a0, a1 = _window(sample)
        if not b1 < integer(boot['start_ns']) < a0 <= a1:
            raise ValueError('boot observation windows invalid')
        if not a0 <= integer(context['started_ns']) <= integer(context['ended_ns']) <= a1:
            raise ValueError('native evidence outside sampling window')
        if context.get('boot_after') != boot['start_ns']:
            raise ValueError('boot changed during native observation')
        diff = audit_compare(baseline['sections'], sample['current'])
        if set(diff) != {'listen_ports'} or diff['listen_ports'].get('collection_failed'):
            raise ValueError('not an isolated complete endpoint difference')
        old, current = endpoint_rows(baseline['sections']['listen_ports']), endpoint_rows(sample['current']['listen_ports'])
        old_ep, new_ep = _project_counter(old, 3), _project_counter(current, 3)
        removed, added = old_ep - new_ep, new_ep - old_ep
        if _project_counter(removed, 2) != _project_counter(added, 2):
            raise ValueError('endpoint address/scope or multiplicity changed')
        if not (removed or added):
            raise ValueError('no identifiable endpoint delta')
        previous = {}
        for row in start['processes']:
            pid = integer(row['ProcessId'])
            if pid in previous:
                raise ValueError('ambiguous old process identity')
            previous[pid] = row['CreationTime']
        owners = _owners(context)
        native_rows = Counter((str(x['protocol']).upper(), address(x['address']),
                               integer(x['port']), integer(x['pid'])) for x in context['rows'])
        for direction, delta, raw in (('removed', removed, old), ('added', added, current)):
            for key, count in sorted(delta.items()):
                matches = [(row,n) for row,n in raw.items() if row[:3] == key]
                if count != 1 or len(matches) != 1 or matches[0][1] != 1:
                    raise ValueError('ambiguous endpoint ownership/multiplicity')
                row = matches[0][0]
                pid = row[3]
                if direction == 'removed':
                    if pid not in previous or not 0 < filetime_ns(previous[pid]) <= b0:
                        raise ValueError('old endpoint birth unavailable')
                    role = {'kind': 'instance_ended_with_boot', 'birth_ticks': str(previous[pid])}
                else:
                    if native_rows[row] != 1 or pid not in owners:
                        raise ValueError('current endpoint/native instance missing')
                    role = _native_owner(owners[pid], context, a1, baseline.get('managed_driver_root'))
                result['attributed'].append({'direction': direction, 'row': list(row), 'owner': role})
        result.update(accepted=True, reason='boot_reset_attributed_no_product_endpoints')
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        result.update(accepted=False, reason=str(exc))
    return result


def cross_boot_pair(baseline, samples, proof):
    from fakenet.mcp.baseline import audit_compare
    decisions = [cross_boot_endpoint_changes(baseline, s, proof) for s in samples]
    accepted = len(samples) == 2 and all(d['accepted'] for d in decisions)
    if accepted:
        accepted = (samples[0]['reboot_context']['boot'] == samples[1]['reboot_context']['boot'] and
                    not audit_compare(samples[0]['current'], samples[1]['current']) and
                    decisions[0]['attributed'] == decisions[1]['attributed'])
    return {'accepted': accepted, 'mode': 'cross_boot', 'samples': decisions,
            'reason': 'two_current_samples_match' if accepted else 'cross_boot_evidence_incomplete_or_changed'}


def same_boot_owner_proof(decision, sample, *, foreign=False):
    """A reused PID cannot carry a previous process's start-only proof."""
    try:
        context = sample['reboot_context']
        owners = _owners(context)
        for row in decision.get('attributed') or []:
            if not foreign and row.get('direction') != 'added':
                continue
            pid = integer(row['pid'])
            owner = owners[pid]
            if owner.get('alive') is not True or owner.get('error') or not owner.get('image'):
                return False
            if foreign:
                if str(owner['birth_ticks']) != str(row['creation_time']):
                    return False
            elif row.get('direction') == 'added':
                _native_owner(owner, context, _window(sample)[1], '')
        return bool(decision.get('attributed'))
    except (KeyError, TypeError, ValueError):
        return False


CONTEXT_SCRIPT = r'''
$ErrorActionPreference='Stop'
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString()
$e=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-General';Id=12} -MaxEvents 1
[xml]$xml=$e.ToXml();$start=@($xml.Event.EventData.Data|Where-Object Name -eq 'StartTime')[0].InnerText
$rows=@(Get-NetTCPConnection -State Listen|ForEach-Object {@{protocol='TCP';address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess}})
$rows+=@(Get-NetUDPEndpoint|ForEach-Object {@{protocol='UDP';address=$_.LocalAddress;port=$_.LocalPort;pid=$_.OwningProcess}})
$services=@(Get-CimInstance Win32_Service|Where-Object State -eq 'Running'|ForEach-Object {
 $m=[regex]::Match([string]$_.PathName,'^\s*(?:"([^"]+)"|(\S+))')
 $image=if($m.Success){if($m.Groups[1].Success){$m.Groups[1].Value}else{$m.Groups[2].Value}}else{''}
 @{name=$_.Name;pid=$_.ProcessId;state=$_.State;command=('"'+$image+'"')}
})
@{boot=$boot;computer=$env:COMPUTERNAME;system_root=$env:SystemRoot;event=@{provider=$e.ProviderName;id=$e.Id;record_id=$e.RecordId;computer=$e.MachineName;start_ticks=([DateTime]::Parse($start).ToUniversalTime().ToFileTimeUtc().ToString())};rows=$rows;services=$services;boot_after=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString()}|ConvertTo-Json -Depth 6 -Compress
'''


def native_process_identity(pid):
    """Keep image, creation and liveness pinned to one limited-query handle."""
    import ctypes as c
    from ctypes import wintypes as w
    k = c.WinDLL('kernel32', use_last_error=True)
    a = c.WinDLL('advapi32', use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]; k.CloseHandle.restype = w.BOOL
    k.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
    k.GetProcessTimes.restype = w.BOOL
    k.QueryFullProcessImageNameW.argtypes = [w.HANDLE,w.DWORD,w.LPWSTR,c.POINTER(w.DWORD)]
    k.QueryFullProcessImageNameW.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE,w.DWORD]; k.WaitForSingleObject.restype = w.DWORD
    handle = k.OpenProcess(0x1000 | 0x100000, False, int(pid))
    if not handle:
        raise OSError('limited process handle unavailable')
    token = w.HANDLE()
    try:
        image = c.create_unicode_buffer(32768); size = w.DWORD(len(image))
        times = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, *[c.byref(t) for t in times]) or not k.QueryFullProcessImageNameW(handle,0,image,c.byref(size)):
            raise OSError('native image/birth unavailable')
        critical = w.BOOL()
        critical_query = getattr(k, 'IsProcessCritical', None)
        role = None
        if critical_query is not None:
            critical_query.argtypes = [w.HANDLE, c.POINTER(w.BOOL)]
            critical_query.restype = w.BOOL
            if critical_query(handle, c.byref(critical)):
                role = bool(critical.value)
        sid = None
        a.OpenProcessToken.argtypes = [w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)]; a.OpenProcessToken.restype = w.BOOL
        a.GetTokenInformation.argtypes = [w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)]
        a.GetTokenInformation.restype = w.BOOL
        a.ConvertSidToStringSidW.argtypes = [c.c_void_p,c.POINTER(w.LPWSTR)]; a.ConvertSidToStringSidW.restype = w.BOOL
        k.LocalFree.argtypes = [c.c_void_p]; k.LocalFree.restype = c.c_void_p
        if a.OpenProcessToken(handle,8,c.byref(token)):
            needed = w.DWORD(); a.GetTokenInformation(token,1,None,0,c.byref(needed))
            if 0 < needed.value <= 65536:
                buf = c.create_string_buffer(needed.value)
                if a.GetTokenInformation(token,1,buf,len(buf),c.byref(needed)):
                    pointer = c.cast(buf,c.POINTER(c.c_void_p))[0]; text = w.LPWSTR()
                    if a.ConvertSidToStringSidW(pointer,c.byref(text)):
                        try: sid = text.value
                        finally: k.LocalFree(c.cast(text,c.c_void_p))
        return {'pid':int(pid), 'birth_ticks':str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime),
                'image':image.value, 'critical':role, 'sid':sid,
                'alive':k.WaitForSingleObject(handle,0) == 258}
    finally:
        if token.value: k.CloseHandle(token)
        k.CloseHandle(handle)


def capture_context(deadline=None, owner_pids=()):
    from fakenet.mcp.baseline import _run, COLLECTION_FAILED
    started = time.time_ns()
    if os.name != 'nt':
        return {'schema':SCHEMA, 'error':'native Windows context unavailable'}
    remaining = 60 if deadline is None else min(60,deadline-time.monotonic())
    if remaining <= 0:
        return {'schema':SCHEMA,'error':'native observation deadline expired'}
    raw = _run(['powershell','-NoProfile','-Command',CONTEXT_SCRIPT],timeout=remaining)
    if raw == COLLECTION_FAILED:
        return {'schema':SCHEMA, 'error':'boot/endpoint observation unavailable'}
    try:
        data = json.loads(raw); boot_ns = filetime_ns(data['boot']); e = data['event']
        boot = {'computer':data['computer'], 'start_ns':boot_ns, 'event':dict(e,start_ns=filetime_ns(e['start_ticks']))}
        pids = {integer(row['pid']) for row in data['rows']} | {integer(p) for p in owner_pids}
        owners = []
        for pid in sorted(pids):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError('native owner observation deadline')
            try:
                owner = native_process_identity(pid)
                owner['services'] = [s for s in data['services'] if integer(s['pid']) == pid]
            except (OSError, ValueError):
                owner = {'pid':pid,'error':'native process identity unavailable'}
            owners.append(owner)
        return {'schema':SCHEMA,'boot':boot,'boot_after':filetime_ns(data['boot_after']),
                'system_root':data['system_root'],'rows':data['rows'],'owners':owners,
                'started_ns':started,'ended_ns':time.time_ns()}
    except (KeyError,TypeError,ValueError,OSError,TimeoutError):
        return {'schema':SCHEMA,'error':'incomplete native boot/owner evidence'}
