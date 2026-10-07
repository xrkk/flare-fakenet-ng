# Copyright 2026 Google LLC
"""LNX-FN net policy: verifiable IPv6 blocking, control-link exclusion,
isolation/real mode switching, and owned-rule bookkeeping for Linux.

Contract (MalTrace master plan 7.1 LNX-FN):
- IPv6 must be genuinely intercepted or verifiably blocked — no bypass.
- Management MCP/host traffic must be excluded from takeover and its
  identity must not be spoofable by an ordinary sample.
- Isolation vs real-network mode control with clean stop/restore and no
  orphaned rules after crash or restart.

Every rule inserted here is recorded with its exact argv; stop()/adopt()
reconciles leftovers so restart never inherits unowned rules.  All state
transitions return evidence snippets for acceptance review.
"""
import ipaddress
import subprocess

IP6_DEFAULT_CHAIN = 'OUTPUT'


def _run(argv):
    return subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=20)


class OwnedRule:
    def __init__(self, argv):
        self.argv = list(argv)

    def remove(self):
        """-I is replaced by -D for removal; idempotent (missing rule ok)."""
        argv = list(self.argv)
        try:
            pos = argv.index('-I')
        except ValueError:
            return False
        argv[pos] = '-D'
        return _run(argv).returncode == 0

    def exists(self):
        argv = list(self.argv)
        pos = argv.index('-I')
        check = [argv[0], '-C'] + argv[pos + 1:]
        return _run(check).returncode == 0


class NetPolicy:
    """IPv6 blocking + control-link exclusion + mode switch for one host.

    control_endpoints: list of (ip, port) management endpoints whose traffic
    must never be taken over (MCP/host control links).  Loopback is always
    excluded.  Rules are inserted BEFORE takeover rules by the diverter so
    the exclusion wins.
    """

    def __init__(self, control_endpoints=(), logger=None):
        self.logger = logger
        self.control_endpoints = []
        for ip, port in control_endpoints:
            ipaddress.ip_address(ip)  # raises on garbage
            if not (0 < int(port) < 65536):
                raise ValueError('bad control port %r' % (port,))
            self.control_endpoints.append((ip, int(port)))
        self._owned = []
        self.mode = None

    # -- evidence -------------------------------------------------------
    def evidence(self):
        """Verifiable rule state for acceptance review."""
        return {
            'mode': self.mode,
            'owned_rules': [r.argv for r in self._owned],
            'ip6tables_output': _run(
                ['ip6tables', '-S', IP6_DEFAULT_CHAIN]).stdout.decode(
                    'utf-8', 'replace'),
            'iptables_output': _run(
                ['iptables', '-S', 'OUTPUT']).stdout.decode('utf-8', 'replace'),
        }

    # -- control-link exclusion (IPv4) ----------------------------------
    def install_control_exclusions_v4(self):
        """ACCEPT rules placed ahead of NFQUEUE takeover for control links.

        OUTPUT: management responses to the controller host must not be
        captured.  INPUT (mangle, ahead of the diverter's NFQUEUE): packets
        FROM the controller host must reach sshd/the MCP service even while
        takeover is active — without this, a started run locks out all
        management access (field-verified twice).
        """
        added = 0
        # Loopback must never be captured: the MCP service itself listens
        # on 127.0.0.1 and its own traffic through lo was taken over (the
        # service stopped answering mid-run).  Both directions.
        for rule in (
            OwnedRule(['iptables', '-t', 'mangle', '-I', 'INPUT', '-i', 'lo',
                       '-j', 'ACCEPT']),
            OwnedRule(['iptables', '-t', 'raw', '-I', 'OUTPUT', '-o', 'lo',
                       '-j', 'ACCEPT']),
        ):
            if not rule.exists():
                _run(rule.argv)
            self._owned.append(rule)
            added += 1
        for ip, port in self.control_endpoints:
            if ipaddress.ip_address(ip).version != 4:
                continue
            # OUTPUT exclusion must sit in the raw table: the diverter's
            # NFQUEUE hook lives in raw OUTPUT, which is traversed BEFORE
            # filter — a filter ACCEPT cannot rescue management traffic.
            out_rule = OwnedRule(['iptables', '-t', 'raw', '-I', 'OUTPUT',
                                  '-p', 'tcp', '-d', ip,
                                  '--sport', str(port), '-j', 'ACCEPT'])
            in_rule = OwnedRule(['iptables', '-t', 'mangle', '-I', 'INPUT',
                                 '-s', ip, '-j', 'ACCEPT'])
            for rule in (out_rule, in_rule):
                if not rule.exists():
                    _run(rule.argv)
                self._owned.append(rule)
                added += 1
        return added

    # -- IPv6 verifiable blocking --------------------------------------
    def block_ipv6(self, allow=()):
        """Block all IPv6 egress except loopback and allowed control links.

        Returns the list of rule descriptions applied (evidence).
        """
        allowed_ips = {'::1'}
        for ip, _port in self.control_endpoints:
            if ipaddress.ip_address(ip).version == 6:
                allowed_ips.add(ip.lower())
        applied = []
        for ip in sorted(allowed_ips):
            rule = OwnedRule(['ip6tables', '-I', IP6_DEFAULT_CHAIN,
                              '-d', ip, '-j', 'ACCEPT'])
            if not rule.exists():
                _run(rule.argv)
            self._owned.append(rule)
            applied.append(rule.argv)
        block = OwnedRule(['ip6tables', '-I', IP6_DEFAULT_CHAIN,
                           '-j', 'DROP'])
        if not block.exists():
            _run(block.argv)
        self._owned.append(block)
        applied.append(block.argv)
        return applied

    # -- isolation vs real network -------------------------------------
    def set_mode(self, mode, takeover_pause=None, takeover_resume=None):
        """isolated: IPv6 blocked (+IPv4 takeover already active via diverter).
        real: remove IPv6 block and pause the IPv4 takeover rules.
        takeover_pause/resume: callables the diverter supplies to remove or
        re-install its own NFQUEUE rules."""
        mode = str(mode).lower()
        if mode not in ('isolated', 'real'):
            raise ValueError('mode must be isolated|real')
        if mode == self.mode:
            return self.evidence()
        if mode == 'real':
            self._remove_all_owned()
            if takeover_pause:
                takeover_pause()
        else:
            if takeover_resume:
                takeover_resume()
            self.install_control_exclusions_v4()
            self.block_ipv6()
        self.mode = mode
        return self.evidence()

    # -- cleanup --------------------------------------------------------
    def _remove_all_owned(self):
        for rule in self._owned:
            try:
                rule.remove()
            except Exception:
                if self.logger:
                    self.logger.exception('rule remove failed %s', rule.argv)
        self._owned = []

    def stop(self):
        """Remove every owned rule; report leftovers (no orphaned rules)."""
        self._remove_all_owned()
        leftover_block = _run(
            ['ip6tables', '-C', IP6_DEFAULT_CHAIN, '-j', 'DROP']).returncode == 0
        return {'stopped': True, 'ipv6_block_leftover': leftover_block}

    def adopt_leftovers(self):
        """After a crash/restart, drop any prior-generation policy rules.

        A previous unclean stop may have left ip6tables DROP or control
        ACCEPT rules.  We verify and remove them so a fresh start never
        inherits unowned state; the removals are reported as evidence.
        """
        adopted = []

        def probe_and_drop(check_argv, drop_argv, label):
            # -C/-D at the rule's real table; probing the wrong table finds
            # nothing and orphans survive a crash (field defect, AUD-006).
            if _run(check_argv).returncode == 0:
                _run(drop_argv)
                adopted.append(label)

        probe_and_drop(
            ['iptables', '-t', 'mangle', '-C', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            ['iptables', '-t', 'mangle', '-D', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
            'lo-input-mangle')
        probe_and_drop(
            ['iptables', '-t', 'raw', '-C', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
            ['iptables', '-t', 'raw', '-D', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
            'lo-output-raw')
        for ip, port in self.control_endpoints:
            if ipaddress.ip_address(ip).version != 4:
                continue
            probe_and_drop(
                ['iptables', '-t', 'raw', '-C', 'OUTPUT', '-p', 'tcp', '-d', ip,
                 '--sport', str(port), '-j', 'ACCEPT'],
                ['iptables', '-t', 'raw', '-D', 'OUTPUT', '-p', 'tcp', '-d', ip,
                 '--sport', str(port), '-j', 'ACCEPT'],
                'control-out-raw %s:%s' % (ip, port))
            probe_and_drop(
                ['iptables', '-t', 'mangle', '-C', 'INPUT', '-s', ip, '-j', 'ACCEPT'],
                ['iptables', '-t', 'mangle', '-D', 'INPUT', '-s', ip, '-j', 'ACCEPT'],
                'control-in-mangle %s' % ip)
        for ip, _port in self.control_endpoints:
            if ipaddress.ip_address(ip).version == 6:
                probe_and_drop(
                    ['ip6tables', '-C', IP6_DEFAULT_CHAIN, '-d', ip.lower(), '-j', 'ACCEPT'],
                    ['ip6tables', '-D', IP6_DEFAULT_CHAIN, '-d', ip.lower(), '-j', 'ACCEPT'],
                    'ipv6-allow %s' % ip)
        probe_and_drop(
            ['ip6tables', '-C', IP6_DEFAULT_CHAIN, '-d', '::1', '-j', 'ACCEPT'],
            ['ip6tables', '-D', IP6_DEFAULT_CHAIN, '-d', '::1', '-j', 'ACCEPT'],
            'ipv6-allow ::1')
        probe_and_drop(
            ['ip6tables', '-C', IP6_DEFAULT_CHAIN, '-j', 'DROP'],
            ['ip6tables', '-D', IP6_DEFAULT_CHAIN, '-j', 'DROP'],
            'ipv6-DROP')
        return adopted
