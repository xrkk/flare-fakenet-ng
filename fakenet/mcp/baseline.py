# Copyright 2026 Google LLC
"""Pre-start environment baseline capture and diff (P03 IMP-P03-04).

Frozen scope (sub-plan P03 §3, record 015): routing table, DNS servers,
process inventory (processes with WinDivert modules loaded plus
fakenetng-mcp/fakenet processes), listening ports and service states.
P03 captures and stores; the same schema is reused by P04's full recovery
audit.  Commands run via subprocess on the service host (Windows).
"""

import json
import subprocess
from pathlib import Path

BASELINE_FIELDS = ('routes', 'dns_servers', 'windivert_processes',
                   'listen_ports', 'services')
# P03 recovery-consistency sections: volatile outputs (netstat PIDs, service
# state races) never gate recovery in P03; the P04 audit matrix refines the
# listen/service comparison (sub-plan P03 IMP-P03-04 boundary).
RECOVERY_COMPARE_FIELDS = BASELINE_FIELDS


COLLECTION_FAILED = '__COLLECTION_FAILED__'


def _run(command, timeout=60):
    """Section capture primitive: text on success, the UNKNOWN sentinel
    when the command itself failed — the auditor must treat a failed
    section as unverifiable (never silently equal; CHK-018/CHK-042)."""
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace')
    except (OSError, subprocess.TimeoutExpired):
        return COLLECTION_FAILED
    if completed.returncode != 0 and not (completed.stdout or '').strip():
        return COLLECTION_FAILED
    return completed.stdout or ''


def _normalize(section, value):
    """Section-specific normalization for the FULL audit comparison (P04):
    strip volatile rows (PIDs, non-LISTEN states, ordering, duplicates)."""
    if value is None:
        return ''
    text = str(value)
    if section == 'routes':
        keep = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or line.startswith('='):
                continue
            parts = stripped.split()
            if len(parts) == 5 and _is_ipv4(parts[0]) and _is_ipv4(parts[1]):
                # Route row: drop the auto-tuned interface METRIC column.
                # Windows re-evaluates metrics around adapter
                # reconfiguration (FakeNet's per-run DNS set/restore
                # cycles the adapter), so the metric flaps between the
                # pre-start baseline and the stop audit without any
                # actual routing change (r54 round-18 / r56 round-2
                # stop audits failed on exactly this). Only genuine
                # dest/mask rows are rewritten; other five-column
                # lines keep their full text.
                keep.append(' '.join(parts[:4]))
            else:
                keep.append(stripped)
        return '\n'.join(sorted(set(keep)))
    if section == 'dns_servers':
        return '\n'.join(sorted(set(
            line.strip() for line in text.splitlines() if line.strip())))
    if section == 'windivert_processes':
        return '\n'.join(sorted(set(
            line.strip() for line in text.splitlines()
            if line.strip() and '===' not in line and
            'Image Name' not in line and '=====' not in line)))
    if section == 'listen_ports':
        keep = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3].upper() == 'LISTENING':
                # TCP LISTENING only: FakeNet-NG's attributable listeners.
                # UDP has no state column and system UDP sockets fluctuate
                # on snapshots with extra services (r51 evidence: Snapshot
                # 185's Velociraptor deps caused false-positive diffs).
                keep.append(' '.join(parts[:3]))
        return '\n'.join(sorted(set(keep)))
    if section == 'services':
        keep = []
        for line in text.splitlines():
            if any(name in line for name in ('dnscache', 'mpssvc',
                                             'Dnscache', 'Mpssvc',
                                             'DNS Client', 'Windows '
                                             'Defender Firewall')):
                keep.append(line.strip().rstrip('RunningStopped'))
        return '\n'.join(sorted(set(keep)))
    return text.strip()


def _is_ipv4(token):
    parts = token.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def audit_compare(baseline_sections, current_sections):
    """Full five-section audit diff with per-section normalization; used by
    the P04 recovery auditor (the P03 startup path keeps its stable-section
    recovery equality). A section whose capture failed (UNKNOWN sentinel
    on either side) is unverifiable and always counts as a difference —
    never silently equal."""
    differences = {}
    for section in BASELINE_FIELDS:
        raw_before = (baseline_sections or {}).get(section) or ''
        raw_after = (current_sections or {}).get(section) or ''
        if raw_before == COLLECTION_FAILED or raw_after == COLLECTION_FAILED:
            differences[section] = {
                'collection_failed': True,
                'before': 'UNKNOWN' if raw_before == COLLECTION_FAILED
                else _normalize(section, raw_before)[:200],
                'after': 'UNKNOWN' if raw_after == COLLECTION_FAILED
                else _normalize(section, raw_after)[:200],
            }
            continue
        before = _normalize(section, raw_before)
        after = _normalize(section, raw_after)
        if section == 'listen_ports':
            delta = _listen_port_delta(before, after)
            if delta:
                differences[section] = delta
        elif before != after:
            differences[section] = {'before': before, 'after': after}
    return differences


# Windows dynamic/ephemeral port range start (RPC, WMI and friends flap
# transient listeners here with ordinary system activity).
DYNAMIC_PORT_RANGE_START = 49152


def _listen_port_local_port(row):
    parts = row.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1].rsplit(':', 1)[1])
    except (ValueError, IndexError):
        return None


def _listen_port_delta(before, after):
    """Directional, FakeNet-attributable listen-port comparison.

    An ADDED listening row is residue only when its port sits below the
    dynamic range (a FakeNet listener port); a VANISHED row matters only
    below 1024 (a system listener the run must not have killed). Rows in
    the dynamic range are OS noise: RPC/WMI endpoints appear and vanish
    with ordinary churn and are not FakeNet residue (r54 round-18 stop
    audit failed on exactly such a transient)."""
    def rows(text):
        return {line for line in text.splitlines() if line.strip()}

    appeared = rows(after) - rows(before)
    vanished = rows(before) - rows(after)
    residue = {row for row in appeared
               if (_listen_port_local_port(row) or 0) <
               DYNAMIC_PORT_RANGE_START}
    killed = {row for row in vanished
              if 0 < (_listen_port_local_port(row) or 0) < 1024}
    if residue or killed:
        return {'fakenet_added': sorted(residue),
                'below_1024_removed': sorted(killed)}
    return None


def capture():
    """Collect the current environment baseline sections.

    Each value is ``text`` on success or ``'__COLLECTION_FAILED__'`` when
    the collection command itself failed — the auditor treats a failed
    section as UNKNOWN (never silently equal, CHK-018)."""
    routes = _run(['route', 'print', '-4'])
    dns = _run(['powershell', '-NoProfile', '-Command',
                'Get-DnsClientServerAddress -AddressFamily IPv4 | '
                'Select-Object InterfaceAlias,ServerAddresses | '
                'ConvertTo-Json -Compress'])
    processes = _run(['powershell', '-NoProfile', '-Command',
                      '(tasklist /m WinDivert*.sys 2>$null) + '
                      '(Get-Process fakenetng-mcp,fakenet '
                      '-ErrorAction SilentlyContinue | '
                      'Select-Object -ExpandProperty ProcessName) | '
                      'Out-String'])
    ports = _run(['netstat', '-ano'])
    services = _run(['powershell', '-NoProfile', '-Command',
                     'Get-Service dnscache,mpssvc | '
                     'Select-Object Name,Status | '
                     'ConvertTo-Json -Compress'])
    return {
        'routes': routes.strip(),
        'dns_servers': dns.strip(),
        'windivert_processes': processes.strip(),
        'listen_ports': ports.strip(),
        'services': services.strip(),
    }


class BaselineStore:

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, run_id, sections=None):
        sections = sections or capture()
        payload = json.dumps({'run_id': run_id, 'sections': sections},
                             ensure_ascii=False, indent=2) + '\n'
        path = self.root / ('%s.json' % run_id)
        path.write_text(payload, encoding='utf-8')
        return {'path': str(path),
                'fields': sorted(sections)}

    def load(self, run_id):
        path = self.root / ('%s.json' % run_id)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except ValueError:
            return None

    def diff(self, run_id):
        """Return per-field differences between baseline and now (or None
        when the baseline is unavailable)."""
        baseline = self.load(run_id)
        if baseline is None:
            return None
        current = capture()
        differences = {}
        for field in RECOVERY_COMPARE_FIELDS:
            before = (baseline.get('sections') or {}).get(field, '')
            after = current.get(field, '')
            if before != after:
                differences[field] = {'before': before, 'after': after}
        return differences

    def full_audit_diff(self, run_id):
        """P04 full recovery audit: all five normalized sections must match
        the pre-start baseline."""
        baseline = self.load(run_id)
        if baseline is None:
            return {'__missing_baseline__': True}
        return audit_compare(baseline.get('sections'), capture())
