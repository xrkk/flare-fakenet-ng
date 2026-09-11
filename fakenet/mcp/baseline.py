# Copyright 2026 Google LLC
"""Pre-start environment baseline capture and diff (P03 IMP-P03-04).

Frozen scope (sub-plan P03 §3, record 015): routing table, DNS servers,
process inventory (processes with WinDivert modules loaded plus
fakenetng-mcp/fakenet processes), listening ports and service states.
P03 captures and stores; the same schema is reused by P04's full recovery
audit.  Commands run via subprocess on the service host (Windows).
"""

import json
import os
import time
import base64
import tempfile
import csv
import subprocess
import sys
import uuid
import re
import ntpath
from pathlib import Path

BASELINE_FIELDS = ('routes', 'dns_servers', 'windivert_processes',
                   'listen_ports', 'services')
# P03 recovery-consistency sections: volatile outputs (netstat PIDs, service
# state races) never gate recovery in P03; the P04 audit matrix refines the
# listen/service comparison (sub-plan P03 IMP-P03-04 boundary).
RECOVERY_COMPARE_FIELDS = BASELINE_FIELDS


COLLECTION_FAILED = '__COLLECTION_FAILED__'


def is_control_client(process, service_command):
    """Recognize only this installed binary's local administrative client.

    Keep raw rows, including PID/creation/command/image, in every capture.
    A same-named foreign executable, engine entry, or unidentified process
    remains a managed-process difference. WinDivert module rows are separate
    and are never exempted by this classification.
    """
    pattern = r'\s*(?:"([^"]+)"|(\S+))\s+(\S+)(?:\s|$)'
    service = re.match(pattern, service_command or '')
    command = re.match(pattern, process.get('CommandLine') or '')
    if not service or not command or service.group(3) != 'run':
        return False
    if command.group(3) not in ('stop', 'uninstall', 'install'):
        return False
    image = ntpath.normcase(service.group(1) or service.group(2))
    return (ntpath.normcase(command.group(1) or command.group(2)) == image and
            ntpath.normcase(process.get('ExecutablePath') or '') == image)


def process_capture_script():
    return (
        "$ErrorActionPreference='Stop'; $modules=@(& tasklist.exe /m WinDivert* /fo csv /nh); "
        "if($LASTEXITCODE -ne 0){throw 'tasklist module observation failed'}; "
        "$service=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"; "
        "$managed=@(Get-CimInstance Win32_Process | Where-Object {"
        "$_.Name -in @('fakenetng-mcp.exe','fakenet.exe','fakenetng-mcp-managed.exe')} | Select-Object "
        "@{Name='ProcessName';Expression={$_.Name -replace '\\.exe$',''}},"
        "@{Name='Id';Expression={$_.ProcessId}},"
        "@{Name='StartTime';Expression={$_.CreationDate}},ExecutablePath,CommandLine); "
        "$drivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {"
        "$_.Name -like 'WinDivert*' -or $_.PathName -like '*WinDivert*'} | "
        "Select-Object Name,State,Started,PathName); "
        "@{modules=$modules;managed=$managed;drivers=$drivers;"
        "service_command=$service.PathName} | ConvertTo-Json -Depth 5 -Compress")


def _run(command, timeout=60):
    """Section capture primitive: text on success, the UNKNOWN sentinel
    when the command itself failed — the auditor must treat a failed
    section as unverifiable (never silently equal; CHK-018/CHK-042)."""
    try:
        encoding = 'utf-8'
        if os.name == 'nt':
            import ctypes
            encoding = 'cp%d' % ctypes.windll.kernel32.GetOEMCP()
            if str(command[0]).lower() in ('powershell', 'powershell.exe'):
                command = list(command)
                command[-1] = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); " + command[-1]
                encoding = 'utf-8'
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding=encoding, errors='strict')
    except (OSError, subprocess.TimeoutExpired):
        return COLLECTION_FAILED
    if completed.returncode != 0 or not (completed.stdout or '').strip():
        return COLLECTION_FAILED
    return completed.stdout or ''


def _normalize(section, value):
    """Canonicalize presentation without discarding observable differences.

    Endpoint owners may have different PIDs after SCM recovery. Keep endpoint
    multiplicity, protocol, address and port; only the PID column is omitted.
    Established TCP connections are not listening endpoints.
    """
    if value is None:
        return ''
    text = str(value)
    if section == 'windivert_processes':
        try:
            observed = json.loads(text)
            if isinstance(observed, dict) and set(observed) in (
                    {'modules', 'managed', 'drivers'},
                    {'modules', 'managed', 'drivers', 'service_command'}):
                modules = []
                for line in observed['modules']:
                    row = next(csv.reader([line]))
                    modules.append([row[0], row[2]] if len(row) == 3 else row)
                # Raw PID and creation time remain in the baseline. Comparing
                # identities across SCM restart permits PID replacement only,
                # never losing a process, module, driver or multiplicity.
                # Only the process instance may change across an approved
                # SCM restart: the image path and command line stay part of
                # the identity, so a same-named foreign image replacing a
                # managed one is a real difference rather than an erasure.
                managed = []
                for process in observed['managed']:
                    if is_control_client(process, observed.get('service_command')):
                        continue
                    managed.append([
                        process.get('ProcessName'),
                        ntpath.normcase(process.get('ExecutablePath') or ''),
                        process.get('CommandLine') or '',
                    ])
                observed = {'modules': sorted(modules),
                            'managed': sorted(managed),
                            'drivers': sorted(observed['drivers'], key=lambda p: p['Name'])}
                return json.dumps(observed, sort_keys=True, ensure_ascii=False)
        except (ValueError, TypeError, KeyError):
            pass
    if section in ('services', 'dns_servers'):
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            pass
        else:
            if isinstance(data, list):
                # Sort interface/service records, not ordered DNS addresses.
                data = sorted(data, key=lambda row: json.dumps(
                    row, sort_keys=True, ensure_ascii=False))
            return json.dumps(data, sort_keys=True, ensure_ascii=False)
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if section == 'listen_ports':
            protocol = parts[0].upper()
            if protocol == 'TCP':
                if len(parts) >= 4 and parts[3].upper() == 'LISTENING':
                    rows.append(' '.join(parts[:4]))
            elif protocol == 'UDP' and len(parts) >= 3:
                rows.append(' '.join(parts[:3]))
            # netstat headers contain no observation. Unrecognized payloads
            # remain visible rather than disappearing from the comparison.
            elif protocol not in ('PROTO', 'ACTIVE'):
                rows.append(' '.join(parts))
        else:
            rows.append(' '.join(parts))
    return '\n'.join(sorted(rows))


def audit_compare(baseline_sections, current_sections):
    """Compare every required section; absence/failure is never equality."""
    differences = {}
    for section in BASELINE_FIELDS:
        before_map = baseline_sections or {}
        after_map = current_sections or {}
        before = before_map.get(section)
        after = after_map.get(section)
        if (section not in before_map or section not in after_map or
                before is None or after is None or
                before == COLLECTION_FAILED or after == COLLECTION_FAILED):
            differences[section] = {
                'collection_failed': True, 'before': before, 'after': after}
            continue
        before = _normalize(section, before)
        after = _normalize(section, after)
        if before != after:
            differences[section] = {'before': before, 'after': after}
    return differences


class CapturedSections(dict):
    """Five raw sections plus directly observed command time intervals."""


def settle_dead_socket_rows(deadline=None):
    """Wait until netstat lists no UDP row whose owning process is gone.

    Product-spawned PowerShell helpers (endpoint observation control) end
    before the baseline is captured, but their resolver sockets stay
    listed for seconds during teardown. Recording such a row poisons the
    strict listen-port comparison with a shadow the closed-UDP attribution
    must refuse (its owner is no longer alive). Bounded; fails open."""
    import subprocess
    budget_end = time.monotonic() + (15 if deadline is None else min(15, deadline - time.monotonic()))
    while time.monotonic() < budget_end:
        try:
            table = subprocess.run(['netstat', '-ano'], capture_output=True,
                                   text=True, timeout=30).stdout
        except (OSError, subprocess.TimeoutExpired):
            return
        lingering = False
        for line in table.splitlines():
            parts = line.split()
            if (len(parts) >= 4 and parts[0].upper() == 'UDP' and
                    parts[-1].isdigit()):
                try:
                    from fakenet.mcp.jobobject import process_alive
                    if parts[-1] != '0' and not process_alive(int(parts[-1])):
                        lingering = True
                        break
                except Exception:
                    return
        if not lingering:
            return
        time.sleep(0.5)


def capture(deadline=None):
    """Collect the current environment baseline sections.

    Each value is ``text`` on success or ``'__COLLECTION_FAILED__'`` when
    the collection command itself failed — the auditor treats a failed
    section as UNKNOWN (never silently equal, CHK-018).

    The native netstat section runs FIRST: on teardown-lagging hosts the
    preceding PowerShell section's own ephemeral sockets can still be
    listed and would poison the strict listen-port comparison with a
    capture-induced shadow that the closed-UDP attribution must refuse
    (its owner process no longer exists at observation end)."""
    def collect(command):
        remaining = 60 if deadline is None else min(60, deadline - time.monotonic())
        return _run(command, timeout=remaining) if remaining > 0 else COLLECTION_FAILED

    def collect_ports():
        # Teardown on the acceptance VM family lags seconds, and resolver
        # helper sockets churn with every command: sockets of just-finished
        # commands and start-phase diagnostics stay listed after their
        # process is gone, and short-lived UDP quads never repeat their
        # ports. Record only rows present in three time-separated
        # observations, so both the baseline and the audit describe the
        # STABLY listening set. Persisting differences remain visible;
        # nothing is edited.
        def rows(text):
            return [line for line in text.splitlines() if line.strip()]
        stable, seen = None, 0
        budget_end = time.monotonic() + 12
        while time.monotonic() < budget_end and seen < 3:
            time.sleep(1.5)
            current = collect(['netstat', '-ano'])
            if current == COLLECTION_FAILED:
                continue
            current_rows = rows(current)
            if stable is None:
                stable = set(current_rows)
            else:
                stable &= set(current_rows)
            seen += 1
        if not stable:
            return collect(['netstat', '-ano'])
        return '\n'.join(sorted(stable))
    ports_start = time.time_ns()
    ports = collect_ports()
    ports_end = time.time_ns()
    routes = collect(['route', 'print', '-4'])
    dns = collect(['powershell', '-NoProfile', '-Command',
                'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                'Select-Object InterfaceAlias,ServerAddresses | '
                'ConvertTo-Json -Compress'])
    processes = collect(['powershell', '-NoProfile', '-Command', process_capture_script()])
    services = collect(['powershell', '-NoProfile', '-Command',
                     'Get-Service dnscache,mpssvc | '
                     'Select-Object Name,Status | '
                     'ConvertTo-Json -Compress'])
    result = CapturedSections({
        'routes': routes.strip(),
        'dns_servers': dns.strip(),
        'windivert_processes': processes.strip(),
        'listen_ports': ports.strip(),
        'services': services.strip(),
    })
    result.windows = {'listen_ports': {'start_ns': ports_start, 'end_ns': ports_end}}
    return result


class BaselineStore:

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, run_id, sections=None):
        runtime_capture = sections is None
        sections = sections or capture()
        if any(field not in sections or sections[field] in (None, COLLECTION_FAILED)
               for field in BASELINE_FIELDS):
            raise RuntimeError('pre-start baseline collection incomplete')
        firewall = None
        if runtime_capture:
            firewall = _run(['netsh', 'advfirewall', 'firewall', 'show',
                             'rule', 'name=FakeNet-NG MCP', 'verbose'])
            if firewall == COLLECTION_FAILED:
                raise RuntimeError('pre-start firewall evidence unavailable')
        payload = json.dumps({'run_id': run_id, 'sections': sections,
                              'observation_windows': getattr(sections, 'windows', {}),
                              'firewall': firewall,
                              'managed_driver_root': str(Path(sys.executable).parent)},
                             ensure_ascii=False, indent=2) + '\n'
        path = self.root / ('%s.json' % run_id)
        fd, temporary = tempfile.mkstemp(dir=self.root, prefix='.baseline-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return {'path': str(path),
                'fields': sorted(sections)}

    def load(self, run_id):
        path = self.root / ('%s.json' % run_id)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or data.get('run_id') != run_id or not isinstance(data.get('sections'), dict):
                return None
            return data
        except (OSError, ValueError):
            return None

    def diff(self, run_id):
        """Return per-field differences between baseline and now (or None
        when the baseline is unavailable)."""
        baseline = self.load(run_id)
        if baseline is None:
            return None
        return audit_compare(baseline.get('sections'), capture())

    def full_audit_diff(self, run_id, deadline=None, settle_seconds=0, observation=None):
        """Audit all five sections, preserving raw differences and requiring
        complete same-run proof for any closed ephemeral UDP exception."""
        baseline = self.load(run_id)
        if baseline is None:
            return {'__missing_baseline__': True}
        if settle_seconds:
            # Never adjust the baseline. Preserve every raw observation;
            # exact matches need two samples. Other differences need the
            # complete closed-lifecycle proof evaluated after tracing ends.
            audit_deadline = min(deadline or float('inf'), time.monotonic() + settle_seconds)
            log_root = self.root.parent / 'logs'
            log_root.mkdir(parents=True, exist_ok=True)
            log = log_root / ('recovery-audit-%s-%s.jsonl' % (run_id, uuid.uuid4()))
            clean = 0
            samples = []
            differences = {'__audit_deadline__': True}
            with log.open('x', encoding='utf-8') as stream:
                while time.monotonic() < audit_deadline:
                    # The settling interval controls when a sample may start.
                    # A started sample keeps its bounded outer operation budget;
                    # don't manufacture partial sections at the settling edge.
                    current = capture(deadline if observation is not None else audit_deadline)
                    differences = audit_compare(baseline.get('sections'), current)
                    sample = {'time': time.time(), 'run_id': run_id, 'current': current,
                              'differences': differences,
                              'observation_windows': getattr(current, 'windows', {})}
                    samples.append(sample)
                    samples = samples[-2:]
                    stream.write(json.dumps(sample, ensure_ascii=False) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                    clean = clean + 1 if not differences else 0
                    if clean == 2:
                        return {}
                    time.sleep(min(0.5, max(0, audit_deadline - time.monotonic())))
            if observation is not None and len(samples) == 2:
                from fakenet.mcp.endpoint_attribution import closed_udp_changes
                from fakenet.mcp.endpoint_observation import write_evidence
                try:
                    proof = observation.audit_proof(deadline)
                    decisions = [closed_udp_changes(baseline, sample, proof) for sample in samples]
                    accepted = all(row['accepted'] for row in decisions)
                    decision = {'run_id': run_id, 'raw_audit': str(log),
                                'accepted': accepted, 'samples': decisions}
                except Exception as exc:
                    accepted = False
                    decision = {'run_id': run_id, 'raw_audit': str(log),
                                'accepted': False, 'failure': repr(exc)}
                write_evidence(log.with_suffix('.attribution.json'), decision)
                if accepted:
                    return {}
            return differences or {'__audit_stability_unverified__': True}
        return audit_compare(baseline.get('sections'), capture() if deadline is None else capture(deadline))

    def compensate(self, run_id, deadline):
        """Restore recorded DNS and related service states before full audit.

        Unknown route/process/port differences are retained as failed audit;
        this never kills unrelated processes or deletes unexplained routes.
        """
        if os.name != 'nt':
            return  # Unit harness only; real supervisor refuses non-Windows.
        baseline = self.load(run_id)
        if baseline is None:
            raise RuntimeError('recovery baseline unavailable')
        sections = baseline.get('sections', {})
        # Parse observed data first; error output is never executable input.
        dns = json.loads(sections['dns_servers'])
        services = json.loads(sections['services'])
        if not isinstance(dns, list):
            dns = [dns]
        if not isinstance(services, list):
            services = [services]
        payload = base64.b64encode(json.dumps({'dns': dns, 'services': services}).encode()).decode()
        script = (
            "$ErrorActionPreference='Stop'; $b=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('" + payload + "')) | ConvertFrom-Json; "
            "foreach($d in $b.dns){ $a=@($d.ServerAddresses); "
            "$current=@(Get-DnsClientServerAddress -InterfaceAlias $d.InterfaceAlias -AddressFamily IPv4); "
            "if($current.Count -ne 1){throw 'DNS interface identity unavailable'}; "
            "if(($a -join ',') -cne (@($current[0].ServerAddresses) -join ',')){"
            "if($a.Count){Set-DnsClientServerAddress -InputObject $current[0] "
            "-ServerAddresses $a}else{Set-DnsClientServerAddress "
            "-InputObject $current[0] -ResetServerAddresses}}}; "
            "foreach($s in $b.services){if($s.Name -notin @('Dnscache','MpsSvc'))"
            "{throw 'unexpected service in baseline'}; "
            "if([int]$s.Status -notin @(1,4)){throw 'baseline service was transitional'}; "
            "$currentService=Get-Service -Name $s.Name; "
            "if([int]$currentService.Status -ne [int]$s.Status){"
            "if([int]$s.Status -eq 4){Start-Service -Name $s.Name}"
            "else{Stop-Service -Name $s.Name}}}; Write-Output 'restored'")
        remaining = min(60, deadline - time.monotonic())
        if remaining <= 0 or _run(['powershell', '-NoProfile', '-Command', script],
                                  timeout=remaining) == COLLECTION_FAILED:
            raise RuntimeError('baseline compensation failed or exceeded deadline')
        self._restore_owned_drivers(baseline, deadline)

    def _restore_owned_drivers(self, baseline, deadline):
        """Undo only a driver service introduced by this installed package.

        Pre-existing driver services and foreign image paths are untouched;
        the full audit retains their differences. Other module users block
        removal rather than risking another process's WinDivert handles.
        """
        observed = json.loads(baseline['sections']['windivert_processes'])
        if not isinstance(observed, dict) or 'drivers' not in observed:
            raise RuntimeError('driver baseline identity unavailable')
        payload = base64.b64encode(json.dumps({
            'drivers': observed['drivers'],
            'root': baseline['managed_driver_root'],
            'supervisor': os.getpid()}).encode()).decode()
        script = (
            "$ErrorActionPreference='Stop'; $b=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('" + payload + "')) | ConvertFrom-Json; "
            "$root=[IO.Path]::GetFullPath($b.root).TrimEnd('\\')+'\\'; "
            "$drivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -like 'WinDivert*'}); "
            "foreach($d in $drivers){ "
            "if(@($b.drivers | Where-Object {$_.Name -eq $d.Name}).Count){continue}; "
            r"$path=$d.PathName -replace '^\\\?\?\\',''; "
            "if(-not [IO.Path]::GetFullPath($path).StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){continue}; "
            "$rows=@(& tasklist.exe /m WinDivert* /fo csv /nh); "
            "if($LASTEXITCODE -ne 0){throw 'module user observation failed'}; "
            "$users=@($rows | Where-Object {$_.StartsWith([string][char]34)} | "
            "ConvertFrom-Csv -Header Image,Pid,Modules | Where-Object {[int]$_.Pid -ne $b.supervisor}); "
            "if($users.Count){throw 'other WinDivert module users prevent driver removal'}; "
            "& sc.exe stop $d.Name | Out-Null; if($LASTEXITCODE -notin @(0,1062)){throw 'owned driver stop failed'}; "
            "& sc.exe delete $d.Name | Out-Null; if($LASTEXITCODE -notin @(0,1060)){throw 'owned driver deletion failed'}; "
            "if(@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -eq $d.Name}).Count)"
            "{throw 'owned driver still registered'} }; "
            "Write-Output 'owned driver compensation complete'")
        remaining = min(60, deadline - time.monotonic())
        if remaining <= 0 or _run(['powershell', '-NoProfile', '-Command', script],
                                  timeout=remaining) == COLLECTION_FAILED:
            raise RuntimeError('owned driver compensation failed')
