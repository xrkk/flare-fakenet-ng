# Copyright 2026 Google LLC
"""Idempotent Windows firewall rule management for the MCP control port.

One inbound allow rule scoped to ``localport=<listen_port>`` and
``remoteip=<allowed_host_ips>`` (REQ-002 / 记录 009).  ``install`` re-creates
the rule (delete-then-add, so repeated installs never duplicate or drift);
``uninstall`` removes it; the service verifies the rule exists at startup.
Command construction is pure so tests can assert on strings without netsh.
"""

import json
import ipaddress
import shutil
import subprocess

RULE_NAME = 'FakeNet-NG MCP'


def build_add_command(listen_port, allowed_host_ips):
    remote = ','.join(str(item) for item in allowed_host_ips)
    return [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        'name=%s' % RULE_NAME, 'dir=in', 'action=allow', 'protocol=TCP',
        'localport=%d' % int(listen_port), 'remoteip=%s' % remote,
    ]


def build_delete_command():
    return [
        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
        'name=%s' % RULE_NAME,
    ]


def build_show_command():
    return [
        'netsh', 'advfirewall', 'firewall', 'show', 'rule',
        'name=%s' % RULE_NAME, 'verbose',
    ]


def _run(command):
    if shutil.which(command[0]) is None:
        raise RuntimeError('required command not found: %s' % command[0])
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding='utf-8',
        errors='replace')
    return completed


def ensure_rule(listen_port, allowed_host_ips):
    """Idempotently (re)create the scoped inbound allow rule."""
    _run(build_delete_command())  # "not found" is a normal exit here
    completed = _run(build_add_command(listen_port, allowed_host_ips))
    if completed.returncode != 0:
        raise RuntimeError(
            'netsh add rule failed (%d): %s%s' % (
                completed.returncode, completed.stdout, completed.stderr))
    return completed.stdout


def remove_rule():
    completed = _run(build_delete_command())
    # A missing rule is not an error for uninstall.
    return completed.returncode, completed.stdout


def build_verify_command():
    # ActiveStore observes effective policy; enum strings avoid localized
    # netsh labels. Keep cardinality and address/port sets, not substrings.
    script = (
        "$ErrorActionPreference='Stop'; "
        "$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore "
        "-DisplayName 'FakeNet-NG MCP' -ErrorAction Stop); "
        "@($rules | ForEach-Object { $r=$_; "
        "$p=$r | Get-NetFirewallPortFilter -ErrorAction Stop; "
        "$a=$r | Get-NetFirewallAddressFilter -ErrorAction Stop; "
        "[pscustomobject]@{Enabled=[string]$r.Enabled; "
        "Direction=[string]$r.Direction; Action=[string]$r.Action; "
        "Profile=[string]$r.Profile; Protocol=[string]$p.Protocol; "
        "LocalPort=@($p.LocalPort); RemotePort=@($p.RemotePort); "
        "RemoteAddress=@($a.RemoteAddress)}}) | "
        "ConvertTo-Json -Depth 5 -Compress")
    return ['powershell', '-NoProfile', '-Command', script]


def verify_rule(listen_port, allowed_host_ips):
    """Return (ok, raw evidence/reason) for the exact effective rule."""
    completed = _run(build_verify_command())
    if completed.returncode != 0:
        return False, 'effective firewall query failed: %s' % completed.stderr
    try:
        rules = json.loads(completed.stdout)
        if isinstance(rules, dict):
            rules = [rules]
        if not isinstance(rules, list) or len(rules) != 1:
            return False, 'expected exactly one effective rule'
        rule = rules[0]
        expected = {'Enabled': 'True', 'Direction': 'Inbound',
                    'Action': 'Allow', 'Profile': 'Any', 'Protocol': 'TCP'}
        if any(rule.get(key) != value for key, value in expected.items()):
            return False, 'effective rule flags or protocol differ'
        if rule.get('LocalPort') != [str(int(listen_port))] or \
                rule.get('RemotePort') != ['Any']:
            return False, 'effective port scope differs'
        addresses = rule.get('RemoteAddress')
        if not isinstance(addresses, list) or not addresses:
            return False, 'remote address scope unavailable'
        def host(value):
            # Windows may print a host as /32 or /128. Networks and Any
            # are never accepted as equivalent to a single host address.
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses != 1:
                raise ValueError('address is wider than one host')
            return str(network.network_address)
        if {host(v) for v in addresses} != {host(v) for v in allowed_host_ips}:
            return False, 'effective remote host set differs'
    except (ValueError, TypeError, AttributeError):
        return False, 'effective rule evidence malformed or scope too wide'
    return True, completed.stdout
