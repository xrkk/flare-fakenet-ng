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
POLICY_COMMENT = 'fakenet-ng-linux'


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
        check = argv[:pos] + ['-C'] + argv[pos + 1:]
        result = _run(check)
        if result.returncode not in (0, 1):
            raise RuntimeError('policy rule probe failed')
        return result.returncode == 0


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

    @staticmethod
    def _tagged(binary, table, chain, spec, target='ACCEPT'):
        return OwnedRule([binary, '-t', table, '-I', chain] + list(spec) +
                         ['-m', 'comment', '--comment', POLICY_COMMENT,
                          '-j', target])

    def _v4_rules(self):
        rules = [self._tagged('iptables', 'mangle', 'INPUT', ['-i', 'lo']),
                 self._tagged('iptables', 'raw', 'OUTPUT', ['-o', 'lo'])]
        for ip, port in self.control_endpoints:
            if ipaddress.ip_address(ip).version == 4:
                rules.extend([
                    self._tagged('iptables', 'raw', 'OUTPUT',
                                 ['-p', 'tcp', '-d', ip, '--sport', str(port)]),
                    self._tagged('iptables', 'mangle', 'INPUT',
                                 ['-p', 'tcp', '-s', ip, '--dport', str(port)]),
                ])
        return rules

    def _v6_rules(self):
        # -I inserts at the head: install the fallback FIRST, then exceptions.
        rules = [self._tagged('ip6tables', 'filter', IP6_DEFAULT_CHAIN, [], 'DROP'),
                 self._tagged('ip6tables', 'filter', IP6_DEFAULT_CHAIN,
                              ['-d', '::1'])]
        for ip, port in self.control_endpoints:
            if ipaddress.ip_address(ip).version == 6:
                rules.append(self._tagged('ip6tables', 'filter', IP6_DEFAULT_CHAIN,
                    ['-p', 'tcp', '-d', ip.lower(), '--sport', str(port)]))
        return rules

    def _refuse_legacy(self, family):
        # Untagged old broad rules cannot prove ownership. Never adopt them
        # or treat them as a successful new exact-endpoint rule.
        candidates = []
        if family == 4:
            candidates.append(['iptables', '-t', 'raw', '-I', 'OUTPUT',
                               '-p', 'tcp', '-j', 'ACCEPT'])
            for ip, _port in self.control_endpoints:
                if ipaddress.ip_address(ip).version == 4:
                    candidates.append(['iptables', '-t', 'mangle', '-I', 'INPUT',
                                       '-s', ip, '-j', 'ACCEPT'])
        else:
            candidates.append(['ip6tables', '-I', IP6_DEFAULT_CHAIN, '-j', 'DROP'])
            for ip, _port in self.control_endpoints:
                if ipaddress.ip_address(ip).version == 6:
                    candidates.append(['ip6tables', '-I', IP6_DEFAULT_CHAIN,
                                       '-d', ip.lower(), '-j', 'ACCEPT'])
        if any(OwnedRule(argv).exists() for argv in candidates):
            raise RuntimeError('unowned legacy policy rule; explicit recovery required')

    def _install(self, rules):
        for rule in rules:
            if not rule.exists() and _run(rule.argv).returncode != 0:
                raise RuntimeError('policy rule insertion failed')
            if not any(old.argv == rule.argv for old in self._owned):
                self._owned.append(rule)
        return [rule.argv for rule in rules]

    def install_control_exclusions_v4(self):
        """Only loopback and the exact management TCP endpoint precede NFQUEUE."""
        self._refuse_legacy(4)
        return len(self._install(self._v4_rules()))

    def block_ipv6(self, allow=()):
        """Loopback/exact TCP management replies precede the default DROP."""
        self._refuse_legacy(6)
        return self._install(self._v6_rules())

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
        remaining = []
        for rule in self._owned:
            try:
                if rule.exists():
                    rule.remove()
                if rule.exists():
                    remaining.append(rule)
            except Exception:
                remaining.append(rule)
                if self.logger:
                    self.logger.exception('rule remove failed %s', rule.argv)
        self._owned = remaining
        if remaining:
            raise RuntimeError('owned policy rules remain after cleanup')

    def stop(self):
        """Delete only exact tagged owned rules; cleanup errors remain failures."""
        self._remove_all_owned()
        leftover = self._v6_rules()[0].exists()
        return {'stopped': not leftover, 'ipv6_block_leftover': leftover}

    def adopt_leftovers(self):
        """Reconcile this policy's exact tagged rules; never remove legacy broad rules."""
        adopted = []
        for rule in self._v4_rules() + self._v6_rules():
            if rule.exists():
                if not rule.remove() or rule.exists():
                    raise RuntimeError('owned policy adoption failed')
                adopted.append(' '.join(rule.argv))
        return adopted
