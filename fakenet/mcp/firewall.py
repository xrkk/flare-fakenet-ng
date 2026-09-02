# Copyright 2026 Google LLC
"""Idempotent Windows firewall rule management for the MCP control port.

One inbound allow rule scoped to ``localport=<listen_port>`` and
``remoteip=<allowed_host_ips>`` (REQ-002 / 记录 009).  ``install`` re-creates
the rule (delete-then-add, so repeated installs never duplicate or drift);
``uninstall`` removes it; the service verifies the rule exists at startup.
Command construction is pure so tests can assert on strings without netsh.
"""

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


def verify_rule(listen_port, allowed_host_ips):
    """Return (ok, detail).

    ``netsh show rule name=...`` exits non-zero when no rule matches (the
    message text is locale-dependent, the exit code is not).  Scope values
    (port number, IP literals) are locale-independent substrings of the
    already name-filtered output.
    """
    completed = _run(build_show_command())
    if completed.returncode != 0:
        return False, 'rule absent (netsh exit %d)' % completed.returncode
    text = completed.stdout or ''
    if not text.strip():
        return False, 'rule output empty'
    if str(int(listen_port)) not in text:
        return False, 'listen port %d missing from rule' % listen_port
    missing = [str(ip) for ip in allowed_host_ips if str(ip) not in text]
    if missing:
        return False, 'allowed host ips missing from rule: %s' % ', '.join(missing)
    return True, text
