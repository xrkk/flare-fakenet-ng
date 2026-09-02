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
RECOVERY_COMPARE_FIELDS = ('routes', 'dns_servers', 'windivert_processes')


def _run(command, timeout=60):
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace')
        return completed.stdout or ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def _normalize(section, value):
    """Section-specific normalization for the FULL audit comparison (P04):
    strip volatile rows (PIDs, non-LISTEN states, ordering, duplicates)."""
    if value is None:
        return ''
    text = str(value)
    if section == 'routes':
        lines = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.startswith('=')]
        return '\n'.join(sorted(set(lines)))
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
                keep.append(' '.join(parts[:3]))  # proto/local/foreign
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


def audit_compare(baseline_sections, current_sections):
    """Full five-section audit diff with per-section normalization; used by
    the P04 recovery auditor (the P03 startup path keeps its stable-section
    recovery equality)."""
    differences = {}
    for section in BASELINE_FIELDS:
        before = _normalize(section,
                            (baseline_sections or {}).get(section))
        after = _normalize(section, (current_sections or {}).get(section))
        if before != after:
            differences[section] = {'before': before, 'after': after}
    return differences


def capture():
    """Collect the current environment baseline sections."""
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
                     'Select-Object Name,Status | ConvertTo-Json -Compress'])
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
