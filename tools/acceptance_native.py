#!/usr/bin/env python3
"""Registered native acceptance drivers for the FakeNet v2 catalog.

A driver is a fixed argv array plus a fixed sub-check list and a single oracle.
Nothing here accepts a caller-supplied shell string.  Drivers that still need
the real VM/endpoints are registered as ``implemented: False`` with the exact
missing capability, so a full plan records them as blocked instead of silently
dropping them.

The current task may only run the offline fixture channel.  Native execution is
authorised by ``environment.allowed_actions`` containing ``native``; this
module never assumes that authority.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path, PurePosixPath

NATIVE_SCHEMA = 'fakenet.native-driver.v1'


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _read(path):
    return Path(path).read_text(encoding='utf-8', errors='replace')


UPSTREAM_PROTECTED_TCP_PORTS = (28787, 28790)


def validate_upstream_protected_tcp_ports(value):
    """Fixture-only forwarding whitelist for verified guest management ports.

    The optional field keeps MCP management connections on their original
    tuples through the existing Diverter TCP port blacklist instead of the
    ProxyTCPListener rewrite.  An absent value keeps the frozen legacy
    selection; present values must be exactly the verified management ports,
    integers (never booleans), in range and without duplicates.
    """
    if value is None:
        raise ValueError('upstream_protected_tcp_ports must be an explicit array, not null')
    if not isinstance(value, list):
        raise ValueError('upstream_protected_tcp_ports must be an array')
    ports = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError('upstream_protected_tcp_ports entries must be integers')
        if not 0 < item < 65536:
            raise ValueError('upstream_protected_tcp_ports entry out of range')
        if item in ports:
            raise ValueError('upstream_protected_tcp_ports duplicate entry')
        if item not in UPSTREAM_PROTECTED_TCP_PORTS:
            raise ValueError(
                'upstream_protected_tcp_ports entry is not a verified '
                'management port: %r' % (item,))
        ports.append(item)
    return ports


def attach_upstream_protection(request, environment):
    """Attach the optional protection field identically at both request
    construction and the independent judge's literal rebuild."""
    runtime = environment['native_runtime']
    if 'upstream_protected_tcp_ports' in runtime:
        request['upstream_protected_tcp_ports'] = \
            validate_upstream_protected_tcp_ports(
                runtime.get('upstream_protected_tcp_ports'))
    return request


def upstream_checks(root, platform='linux', singlehost=True):
    """Read only registered original callback definitions, respecting guards."""
    tree = ast.parse(_read(Path(root)/'test/test.py'))
    owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name=='FakeNetTester')
    suites = {'generalTests':'General', 'testNoRedirect':'No Redirect',
              'testBlacklistProcess':'Global process blacklist',
              'testWhitelistProcess':'Global process whitelist'}
    def enabled(test):
        if isinstance(test, ast.Attribute) and isinstance(test.value, ast.Attribute) and test.value.attr=='settings':
            if test.attr=='windows': return platform=='windows'
            if test.attr=='singlehost': return singlehost
        raise ValueError('unsupported guard in upstream callback collection')
    def visit(nodes, label):
        names=[]
        for node in nodes:
            if isinstance(node, ast.If):
                names.extend(visit(node.body if enabled(node.test) else node.orelse,label))
            elif isinstance(node, ast.Assign) and len(node.targets)==1:
                target=node.targets[0]
                if (isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and
                    target.value.id=='t' and isinstance(target.slice,ast.Constant) and isinstance(target.slice.value,str)):
                    names.append(label+'::'+target.slice.value)
        return names
    return [name for method in owner.body if isinstance(method,ast.FunctionDef) and method.name in suites
            for name in visit(method.body,suites[method.name])]


def ps1_checks(path):
    text = _read(path)
    names = []
    for pattern in (r"Add-Result\s+'([^']+)'",
                    r"Add-Result\s+([A-Za-z0-9_-]+)\s+(?:PASS|FAIL|OBSERVED)",
                    r"Invoke-LoggedCommand\s+-Name\s+'([^']+)'"):
        names.extend(re.findall(pattern, text))
    seen = []
    for name in names:
        if name not in seen:
            seen.append(name)
    return seen


def mcp_checks(path):
    path = Path(path)
    if not path.is_file():
        return []
    tree = ast.parse(_read(path), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument'):
            continue
        if not node.args or not (isinstance(node.args[0], ast.Constant)
                                 and node.args[0].value == '--acc'):
            continue
        for keyword in node.keywords:
            if keyword.arg == 'choices' and isinstance(keyword.value, (ast.List, ast.Tuple)):
                return [item.value for item in keyword.value.elts
                        if isinstance(item, ast.Constant)]
    return []


UPSTREAM_FILTERS = {
    'UPSTREAM-TCP-UDP': ('TCP ', 'UDP '),
    'UPSTREAM-DNS': ('DNS listener',),
    'UPSTREAM-HTTP-CUSTOM': ('HTTP ', 'HTTPS '),
    'UPSTREAM-FTP-POP-SMTP-IRC': ('FTP ', 'POP3 ', 'SMTP ', 'IRC '),
    'UPSTREAM-SMTP-SSL': ('SMTP SSL',),
    'UPSTREAM-PROXY-HIDDEN': ('Proxy ',),
    'UPSTREAM-BLACKLIST': ('blacklisted', 'blacklist'),
    'UPSTREAM-PROCESS-FILTERS': ('Global blacklisted', 'Global whitelisted'),
    'UPSTREAM-LISTENER-FILTERS': ('Listener process', 'Listener host'),
    'UPSTREAM-REDIRECTALL-OFF': ('RedirectAllTraffic',),
}

EGRESS_FILTERS = {
    'EGRESS-ALLOW-CHAIN': ('DnsAutoSelection', 'ExternalDnsServer', 'Dependencies',
                           'AllowedIPv4', 'positive-api-deepseek', 'Event-'),
    'EGRESS-NEGATIVES': ('negative-', 'Event-DROP_EXTERNAL', 'PolicyExceptions'),
    'EGRESS-RESTORE': ('FakeNetStop', 'IndependentCapture', 'DnsRestore',
                       'PolicyExceptions'),
}


def driver_table(root):
    root = Path(root)
    upstream = upstream_checks(root)
    egress_path = root / 'test/egress_control_vm/Run-EgressControlTests.ps1'
    ip_path = root / 'test/public_ipv4_allowlist_vm/Run-ReviewedIPv4Tests.ps1'
    exe_path = root / 'test/process_redirect_vm/Run-ProcessRedirectTests.ps1'
    egress = ps1_checks(egress_path) if egress_path.is_file() else []
    for event in ('EGRESS_CONTROL_READY', 'DNS_LEASE_ADD', 'REDIRECT_TLS_RELAY',
                  'TLS_SNI_ALLOW', 'ALLOW_INTERNAL_UPSTREAM', 'DROP_EXTERNAL',
                  'FakeNetStop', 'IndependentCaptureFile', 'DnsRestore',
                  'PolicyExceptions'):
        if event not in egress:
            egress.append('Event-' + event if event.isupper() else event)
    ipv4 = ps1_checks(ip_path) if ip_path.is_file() else []
    exe = ps1_checks(exe_path) if exe_path.is_file() else []
    drivers = {
        'upstream-singlehost': {
            'implemented': True, 'production_kind':'upstream-result',
            'platforms':['windows','linux'], 'modes':['singlehost'],
            'checks':upstream, 'checks_by_platform':{
                platform:upstream_checks(root,platform) for platform in ('windows','linux')},
            'check_filters':UPSTREAM_FILTERS, 'requires':['native'],
            'package_required':False, 'resources':['core','network'],
            'oracle':{'kind':'upstream-result','artifact':'driver/upstream.json'},
            'argv':['{python}','{root}/test/test.py','--mechanical-spec','{output}/request.json'],
        },
        'upstream-multihost': {
            'implemented':True,'production_kind':'upstream-multihost',
            'platforms':['linux'],'modes':['multihost'],
            'checks':upstream_checks(root,'windows',False),
            'checks_by_platform':{platform:upstream_checks(root,platform,False) for platform in ('linux','windows')},
            'requires':['native','multihost'],'package_required':False,'resources':['server-core','server-network','client-network'],
            'oracle':{'kind':'upstream-multihost','artifact':'orchestration.json'},
        },
        'egress-windows': {
            'implemented': False,
            'missing': 'original PS1 wrapper is not adapted: fixed paths, placeholder replacement and dependency installation',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/egress_control_vm/Run-EgressControlTests.ps1',
                     '-PythonPath', '{python}'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv',
                       'discover': r'Plain logs available at:\s*(.+)'},
            'checks': egress, 'check_filters': EGRESS_FILTERS,
            'requires': ['native'], 'package_required': False,
            'cleanup': 'runner owns stop/pktmon/DNS snapshot restore',
            'readiness': ['Windows VM', 'administrator', 'pktmon', 'external DNS'],
        },
        'reviewed-ipv4-windows': {
            'implemented': False,
            'missing': 'original PS1 wrapper is not adapted: fixed paths and pinned public address handling',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/public_ipv4_allowlist_vm/Run-ReviewedIPv4Tests.ps1',
                     '-PythonPath', '{python}'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv'},
            'checks': ipv4,
            'requires': ['native'], 'package_required': False,
            'cleanup': 'runner restores DNS/IP/route and keeps pcap',
            'readiness': ['Windows VM', 'administrator', 'pktmon', 'pinned DNS address'],
        },
        'process-redirect-windows': {
            'implemented': False,
            'missing': 'original PS1 wrapper is not adapted: fixed manifest/sentinel/10000-flow pressure',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'argv': ['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                     '-File', 'test/process_redirect_vm/Run-ProcessRedirectTests.ps1'],
            'oracle': {'kind': 'tsv', 'artifact': 'results.tsv'},
            'checks': exe,
            'requires': ['native'], 'package_required': True,
            'cleanup': 'runner stops clients/core and restores network',
            'readiness': ['Windows VM', 'administrator', 'sentinel', 'reviewed A/B'],
        },
        'pcap-windows-functional': {
            'implemented':True, 'production_kind':'dual-pcap-windows',
            'platforms':['windows'], 'modes':['singlehost'],
            'checks':['normal','raw-write','ethernet-write','close'],
            'requires':['native'], 'package_required':False, 'resources':['core','network','capture'],
            'oracle':{'kind':'dual-pcap-windows','artifact':'driver/results.tsv'},
            'argv':['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
                    '-File','{root}/test/dual_pcap_vm/Run-DualPcapTests.ps1','-Functional',
                    '-CaseSet','{modes}','-OutputDirectory','{output}/driver','-PythonPath','{python}'],
        },
        'pcap-linux-functional': {
            'implemented':True, 'production_kind':'dual-pcap-linux',
            'platforms':['linux'], 'modes':['singlehost'],
            'checks':['normal','raw-write','ethernet-write','close'],
            'requires':['native'], 'package_required':False, 'resources':['core','network','capture'],
            'oracle':{'kind':'dual-pcap-linux','artifact':'driver/summary.json'},
            'argv':['{python}','{root}/test/dual_pcap_linux/run_tests.py','--functional',
                    '--output-directory','{output}/driver'],
        },
        'policy-domain': {
            'implemented': True, 'production_kind': 'policy-domain',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'apex_denied',
                       'default_deny', 'tls_application', 'route_restore'],
            'check_filters': {
                'EGRESS-ALLOW-CHAIN': ['exact_domain', 'wildcard_domain',
                                       'tls_application'],
                'EGRESS-NEGATIVES': ['apex_denied', 'default_deny'],
                'EGRESS-RESTORE': ['route_restore'],
            },
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'domain', '--output', '{output}/driver',
                     '--python', '{python}', '--inputs', '{policy_inputs}',
                     '--checks', '{checks}'],
        },
        'policy-ipv4': {
            'implemented': True, 'production_kind': 'policy-ipv4',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['reviewed_ip_tls', 'port_80_denied', 'port_444_denied',
                       'udp443_denied', 'other_ip_denied'],
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'ipv4', '--output', '{output}/driver',
                     '--python', '{python}', '--inputs', '{policy_inputs}',
                     '--checks', '{checks}'],
        },
        'policy-combined': {
            'implemented': True, 'production_kind': 'policy-combined',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'reviewed_ip_tls',
                       'sink_tcp', 'sink_udp', 'route_restore'],
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'combined', '--output', '{output}/driver',
                     '--python', '{python}', '--inputs', '{policy_inputs}',
                     '--checks', '{checks}'],
        },
        'policy-takeover': {
            'implemented': True, 'production_kind': 'policy-takeover',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['sink_tcp', 'sink_udp', 'adjacent_denied', 'icmp_denied',
                       'ipv6_denied', 'route_restore'],
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'takeover', '--output', '{output}/driver',
                     '--python', '{python}', '--inputs', '{policy_inputs}',
                     '--checks', '{checks}'],
        },
        'policy-substitute-domain': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'apex_denied',
                       'default_deny', 'tls_application', 'route_restore'],
            'check_filters': {
                'EGRESS-ALLOW-CHAIN': ['exact_domain', 'wildcard_domain',
                                       'tls_application'],
                'EGRESS-NEGATIVES': ['apex_denied', 'default_deny'],
                'EGRESS-RESTORE': ['route_restore'],
            },
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result',
                       'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'domain', '--substitute',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'policy-substitute-ipv4': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['reviewed_ip_tls', 'port_80_denied',
                       'port_444_denied', 'udp443_denied', 'other_ip_denied'],
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result',
                       'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'ipv4', '--substitute',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'policy-substitute-takeover': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['sink_tcp', 'sink_udp', 'adjacent_denied',
                       'icmp_denied', 'ipv6_denied', 'route_restore'],
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result',
                       'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'takeover', '--substitute',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'policy-combo': {
            'implemented': True, 'production_kind': 'policy-combo',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'tls_application',
                       'reviewed_ip_tls', 'sink_tcp', 'sink_udp',
                       'port_80_denied', 'port_444_denied', 'udp443_denied',
                       'other_ip_denied', 'adjacent_denied', 'route_restore'],
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'combo', '--output', '{output}/driver',
                     '--python', '{python}', '--inputs', '{policy_inputs}',
                     '--checks', '{checks}'],
        },
        'policy-substitute-combo': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'tls_application',
                       'reviewed_ip_tls', 'sink_tcp', 'sink_udp',
                       'port_80_denied', 'port_444_denied', 'udp443_denied',
                       'other_ip_denied', 'adjacent_denied', 'route_restore'],
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result', 'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'combo', '--substitute',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'policy-substitute-combined': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['exact_domain', 'wildcard_domain', 'reviewed_ip_tls',
                       'sink_tcp', 'sink_udp', 'route_restore'],
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'policy-result',
                       'artifact': 'driver/policy-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_policy.py',
                     '--scenario', 'combined', '--substitute',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'policy-headless': {
            'implemented': False,
            'missing': 'headless policy driver (core INI + sink + no GUI config writer) '
                       'is not implemented in this round',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'process-redirect-headless': {
            'implemented': True, 'production_kind': 'process-redirect',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['identity', 'target-positive', 'non-target-negative',
                       'owner-bounded', 'budget', 'pcap-restore'],
            'check_filters': {
                'PR-REDIRECT-POSITIVE': ['identity', 'target-positive',
                                         'non-target-negative'],
                'PR-OWNER-BOUNDED': ['owner-bounded', 'budget'],
                'PR-PCAP-RESTORE': ['pcap-restore'],
            },
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture', 'process'],
            'oracle': {'kind': 'headless-result',
                       'artifact': 'driver/headless-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_headless.py',
                     '--mode', 'process', '--inputs', '{headless_inputs}',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'payload-headless': {
            'implemented': True, 'production_kind': 'payload-three-way',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['integrity', 'report', 'reassembly'],
            'requires': ['native'], 'package_required': False,
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'headless-result',
                       'artifact': 'driver/headless-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_headless.py',
                     '--mode', 'payload', '--inputs', '{headless_inputs}',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'process-substitute': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['identity', 'target-positive', 'non-target-negative',
                       'owner-bounded', 'budget', 'pcap-restore'],
            'check_filters': {
                'PR-REDIRECT-POSITIVE': ['identity', 'target-positive',
                                         'non-target-negative'],
                'PR-OWNER-BOUNDED': ['owner-bounded', 'budget'],
                'PR-PCAP-RESTORE': ['pcap-restore'],
            },
            'resources': ['core', 'network', 'capture', 'process'],
            'oracle': {'kind': 'headless-result',
                       'artifact': 'driver/headless-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_headless.py',
                     '--mode', 'process', '--memory',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'payload-substitute': {
            'implemented': True, 'fixture': True,
            'platforms': ['linux', 'windows'], 'modes': ['singlehost'],
            'checks': ['integrity', 'report', 'reassembly'],
            'resources': ['core', 'network', 'capture'],
            'oracle': {'kind': 'headless-result',
                       'artifact': 'driver/headless-result.json'},
            'argv': ['{python}', '{root}/tools/acceptance_headless.py',
                     '--mode', 'payload', '--memory',
                     '--output', '{output}/driver', '--checks', '{checks}'],
        },
        'mcp-headless': {
            'implemented': True, 'production_kind': 'mcp-controller',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': sorted({name for names in __import__('acceptance_mcp').SELECTABLE_CHECKS.values() for name in names}),
            'check_filters': __import__('acceptance_mcp').SELECTABLE_CHECKS,
            'exact_filters': True, 'requires': ['native'], 'package_required': True,
            'resources': ['windows-vm','mcp-service','controller'],
            'oracle': {'kind':'mcp-result','artifact':'driver/mcp-result.json'},
            'argv': ['{python}','{root}/tools/acceptance_mcp.py','--case','{case_id}',
                     '--inputs','{mcp_inputs}','--output','{output}/driver','--checks','{checks}'],
        },
        'mcp-p01': {
            'implemented': False,
            'missing': 'P01 needs candidate/package/plan/Vm identity arguments and a live MCP channel',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p01_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p02': {
            'implemented': False,
            'missing': 'P02 needs candidate/package/plan/Vm identity arguments and a live MCP channel',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p02_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p03': {
            'implemented': False,
            'missing': 'P03 still contains GUI co-control; headless split not implemented',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p03_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-p04': {
            'implemented': False,
            'missing': 'P04 still imports the P05 release object for fault rounds',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': mcp_checks(root / 'test/mcp/acceptance/run_p04_acc.py'),
            'requires': ['native'], 'package_required': True,
        },
        'mcp-special': {
            'implemented': False,
            'missing': 'SPECIAL IPC/control/init cases need live MCP channel and destructive-scope split',
            'platforms': ['windows'], 'modes': ['native'],
            'checks': [], 'requires': ['native'], 'package_required': True,
        },
        'linux-runtime': {
            'implemented': True, 'production_kind': 'linux-runtime',
            'missing': 'SingleHost still requires an independent MultiHost target; accepted-base deployment is connected',
            'partial': 'SingleHost and deployment update originals are connected; MultiHost remains blocked',
            'platforms': ['linux'], 'modes': ['singlehost', 'multihost', 'native'],
            'checks': [], 'requires': ['native'], 'package_required': True,
            'resources': ['linux-vm', 'root'],
            'argv': ['{python}', '{root}/tools/acceptance_linux_runtime.py',
                     '--case', '{case_id}', '--inputs', '{linux_inputs}', '--output', '{output}/driver'],
        },
        'manual-headless': {
            'implemented': False,
            'missing': 'headless_manual.py feature drivers not implemented',
            'platforms': ['windows', 'linux'], 'modes': ['singlehost'],
            'checks': [], 'requires': ['native'], 'package_required': False,
        },
        'manual-ncsi': {
            'implemented': True, 'production_kind': 'manual-ncsi',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['ncsi-ipv4','other-domain','dns-evidence'],
            'resources': ['owned-loopback-listeners'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-raw-date': {
            'implemented': True, 'production_kind': 'manual-raw-date',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['raw-date','preserved-bytes'],
            'resources': ['owned-loopback-listeners'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-list-mutex': {
            'implemented': True, 'production_kind': 'manual-list-mutex',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['blacklist','whitelist','mutex'],
            'resources': ['original-listener-list-validation'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-executecmd': {
            'implemented': True, 'production_kind': 'manual-executecmd',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['command','first-connection','non-connection'],
            'resources': ['original-execute-cmd-parser-and-trigger'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-diverter-switch': {
            'implemented': True, 'production_kind': 'manual-diverter-switch',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['on','off','restore'],
            'resources': ['original-fakenet-start-stop'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-dumppackets': {
            'implemented': True, 'production_kind': 'manual-dumppackets',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['enabled','disabled','prefix','content'],
            'resources': ['original-dual-pcap-writer'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-syslog-icmp': {
            'implemented': True, 'production_kind': 'manual-syslog-icmp',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['syslog','icmp','owner'],
            'resources': ['original-syslog-formatter-and-icmp-logging'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-ctrlc-ipc': {
            'implemented': True, 'production_kind': 'manual-ctrlc-ipc',
            'platforms': ['windows'], 'modes': ['singlehost'],
            'checks': ['ctrlc','ipc-stop','owned-exit'],
            'resources': ['original-main-wait-stop-flag-and-runtime-stop'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-linux-flush-interface': {
            'implemented': True, 'production_kind': 'manual-linux-flush-interface',
            'platforms': ['linux'], 'modes': ['singlehost'],
            'checks': ['flush-iptables','flush-dns','restrict-interface'],
            'resources': ['original-linux-start-stop-iptables-nfqueue'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-network-fix': {
            'implemented': True, 'production_kind': 'manual-network-fix',
            'platforms': ['windows','linux'], 'modes': ['singlehost'],
            'checks': ['fix-gateway','fix-dns','modify-local-dns','stop-dns'],
            'resources': ['original-winutil-linutil-network-fix'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'manual-standalone': {
            'implemented': True, 'production_kind': 'manual-standalone',
            'platforms': ['windows','linux'], 'modes': ['singlehost'],
            'checks': ['listener-bytes','listener-close'],
            'resources': ['original-nine-standalone-listeners'],
            'requires': ['native'], 'package_required': False,
            'argv': ['{python}','{root}/tools/acceptance_manual.py','--case','{case_id}',
                     '--inputs','{manual_inputs}','--output','{output}/driver'],
        },
        'build-identity': {
            'implemented': True, 'production_kind': 'package-identity',
            'platforms': ['windows', 'linux'], 'modes': ['offline'],
            'checks': __import__('acceptance_package').CHECKS,
            'requires': [], 'package_required': True,
            'formats': ['fakenet.mcp-candidate-manifest.v1'],
        },
    }
    return drivers


def select_checks(driver, case, environment=None):
    if driver.get('production_kind') == 'linux-runtime':
        return list(__import__('acceptance_linux_runtime').CHECKS[case['id']])
    if driver.get('production_kind','').startswith('dual-pcap-'):
        if case.get('stress'):
            return []
        data=case.get('input') or {}
        return data.get('cases') or data.get('modes') or [data.get('case')]
    target=(environment or {}).get('native_runtime') or {}
    platform=((target.get('client') or {}).get('identity') or target.get('identity') or {}).get('platform','linux')
    checks=(driver.get('checks_by_platform') or {}).get(platform,driver.get('checks') or [])
    if driver.get('production_kind')=='upstream-result':
        # Every original callback belongs to one family; ICMP positives remain
        # in the general packet family. Do not silently lose them from full.
        def family(identity):
            suite,name=identity.split('::',1)
            if suite=='No Redirect':return 'UPSTREAM-REDIRECTALL-OFF'
            if suite.startswith('Global process'):return 'UPSTREAM-PROCESS-FILTERS'
            if name.startswith('Listener '):return 'UPSTREAM-LISTENER-FILTERS'
            if 'blacklisted' in name:return 'UPSTREAM-BLACKLIST'
            if name.startswith(('TCP ','UDP ','ICMP ')):return 'UPSTREAM-TCP-UDP'
            if name.startswith('DNS '):return 'UPSTREAM-DNS'
            if name.startswith(('HTTP ','HTTPS ')):return 'UPSTREAM-HTTP-CUSTOM'
            if name.startswith('SMTP SSL'):return 'UPSTREAM-SMTP-SSL'
            if name.startswith(('FTP ','POP3 ','SMTP ','IRC ')):return 'UPSTREAM-FTP-POP-SMTP-IRC'
            if name.startswith('Proxy '):return 'UPSTREAM-PROXY-HIDDEN'
            raise ValueError('unmapped original upstream check: '+identity)
        return [name for name in checks if family(name)==case['id']]
    filters=(driver.get('check_filters') or {}).get(case['id'])
    if filters and driver.get('exact_filters'):
        if driver.get('production_kind')=='mcp-controller':
            selected=(environment or {}).get('mcp_checks',{}).get(case['id'],__import__('acceptance_mcp').CHECKS[case['id']])
            if not selected or len(selected)!=len(set(selected)) or any(x not in filters for x in selected):raise ValueError('unknown MCP original unit selection')
            return list(selected)
        return list(filters)
    return [name for name in checks if any(token in name for token in filters)] if filters else list(checks)


def validate_case(case, root, environment=None):
    drivers=driver_table(root)
    name=case.get('native_driver')
    if not name or name not in drivers:
        raise ValueError('%s has an unknown native driver' % case['id'])
    driver=drivers[name]
    if not driver.get('implemented'):
        if driver.get('production_kind')=='linux-runtime':
            return driver,list(__import__('acceptance_linux_runtime').CHECKS[case['id']])
        return driver,[]
    checks=select_checks(driver,case,environment)
    if not checks and not case.get('stress'):
        raise ValueError('%s driver has no declared checks' % case['id'])
    return driver,checks


def manual_fixture_block(environment, candidate):
    from acceptance_runtime import target_identity
    if candidate.get('offline_fixture') is not True:
        return 'manual loopback fixture requires explicit offline_fixture'
    if 'native' not in environment.get('allowed_actions',[]):
        return 'manual loopback fixture action is not authorized'
    runtime=environment.get('native_runtime') or {}
    if runtime.get('transport')!='manual-loopback-fixture' or runtime.get('identity')!=target_identity():
        return 'manual loopback fixture must bind actual local host identity'
    if candidate.get('deployed_identity')!=runtime['identity']:
        return 'manual candidate differs from actual fixture identity'
    return None


MANUAL_REMOTE_DRIVERS = ('manual-ncsi', 'manual-raw-date', 'manual-executecmd', 'manual-standalone',
                          'manual-ctrlc-ipc', 'manual-diverter-switch', 'manual-syslog-icmp',
                          'manual-dumppackets', 'manual-list-mutex')
MANUAL_REMOTE_CASES = ('GAP-NCSI', 'GAP-RAW-DATE', 'GAP-EXECUTECMD', 'GAP-STANDALONE-LISTENERS',
                       'GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG',
                       'GAP-DUMPPACKETS', 'GAP-LIST-MUTEX')


def manual_options(environment):
    """Shared frozen manual options; carrying them never grants remote authority."""
    import socket
    options=(environment or {}).get('manual')
    if not isinstance(options,dict) or options.get('schema')!='fakenet.manual-options.v1' or set(options)-{'schema','responsea'}:
        raise ValueError('explicit fixed manual options required')
    try:
        socket.inet_pton(socket.AF_INET,options.get('responsea','192.0.2.55'))
    except OSError as exc:
        raise ValueError('manual responsea address is invalid') from exc
    return options


def _source_deployment_identity_from_request(request, root=None, case=None):
    """SD-01/02/05/08 + G1/G2: the COMPLETE pre-effect source gate.  Mode,
    package fields, commit form, identity shape and the FULL registered
    closure M are all verified here - callers invoke it before any VM write,
    output.mkdir or producer launch.  When root+case are supplied the closure
    is re-derived from the registered selection (native pins UNION case
    sources with live byte hashes), never from the received subset."""
    import hashlib
    import re as _re
    candidate=request['candidate']
    # G1: exact mode + package-field nullity + Dump case binding.
    if candidate.get('deployment_kind')!='source':
        raise ValueError('source gate requires deployment_kind=source')
    for field in ('package_path','package_manifest','package_sha256'):
        if candidate.get(field) is not None:
            raise ValueError('source candidate carries package field %s'%field)
    if request['case_id']!='GAP-DUMPPACKETS':
        raise ValueError('source deployment is fixed to GAP-DUMPPACKETS')
    commit=candidate.get('source_commit')
    if not isinstance(commit,str) or not _re.fullmatch('[0-9a-f]{40}',commit):
        raise ValueError('source candidate source_commit must be 40 lowercase hex')
    identity=candidate.get('source_deployment_identity')
    if not isinstance(identity,dict) or set(identity)!={'schema','source_commit','case_id','source_hashes_sha256'}:
        raise ValueError('candidate source deployment identity missing/invalid')
    if (identity['schema']!='fakenet.source-deployment-identity.v1' or
            identity['case_id']!=request['case_id'] or
            identity['source_commit']!=commit or
            not isinstance(identity['source_hashes_sha256'],str) or
            not _re.fullmatch('[0-9a-f]{64}',identity['source_hashes_sha256'])):
        raise ValueError('candidate source deployment identity shape/values invalid')
    # G2: the closure must equal the FULL registered M when root+case given;
    # otherwise it is checked for internal form only (subset refusal below).
    closure=dict(request['source_hashes'])
    if not closure:raise ValueError('source deployment identity requires a nonempty closure')
    for name,digest in closure.items():
        parts=PurePosixPath(name).parts if isinstance(name,str) else ()
        if (not isinstance(name,str) or not name or name.startswith('/') or
                any(part in ('','.','..') for part in parts) or '\\' in name or
                not isinstance(digest,str) or not _re.fullmatch('[0-9a-f]{64}',digest)):
            raise ValueError('source closure member invalid: %r'%name)
    if root is not None and case is not None:
        expected=_registered_source_closure(root,case)
        if closure!=expected:
            missing=sorted(set(expected)-set(closure))
            extra=sorted(set(closure)-set(expected))
            if missing or extra:
                raise ValueError('source closure is not the registered selection M '
                                 '(missing=%d extra=%d)'%(len(missing),len(extra)))
            raise ValueError('source closure digests differ from the live registered bytes')
    payload=json.dumps(closure,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
    if identity['source_hashes_sha256']!=hashlib.sha256(payload).hexdigest():
        raise ValueError('candidate source deployment identity differs from the request closure')
    return identity


def _registered_source_closure(root,case):
    """G2/SD-03: the complete M re-derived from the registered selection -
    native pins UNION the case's registered sources, hashed from LIVE bytes."""
    root=Path(root)
    closure=native_source_pins(root)
    import acceptance as _acceptance
    for name in _acceptance.case_sources(case):
        path=root/name
        if not path.is_file():
            raise ValueError('registered source missing: %s'%name)
        closure[name]=sha256(path)
    return closure


def _manual_input_value(plan,case,options,owned_root,config):
    candidate=plan['candidate']
    # SD-06: the Dump-only explicit source branch derives manual-input.v3 with
    # package_sha256 null and the frozen source identity; every other case
    # keeps the original v1 value.
    if (case['id']=='GAP-DUMPPACKETS' and
            candidate.get('deployment_kind')=='source'):
        closure={}
        native_pins=plan.get('native_source_hashes') or {}
        case_entry=(plan.get('source_hashes') or {}).get(case['id']) or {}
        for source_map in (native_pins, case_entry):
            for name, digest in source_map.items():
                if name in closure and closure[name] != digest:
                    raise ValueError('source closure conflict: %s' % name)
                closure[name] = digest
        shadow=plan.get('source_deployment_closure') or {}
        if shadow and shadow != closure:
            raise ValueError('plan shadow closure differs from the frozen selection M')
        if not closure:raise ValueError('source branch requires the frozen closure M')
        import hashlib
        payload=json.dumps(dict(closure),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
        identity={'schema':'fakenet.source-deployment-identity.v1',
                  'source_commit':candidate['source_commit'],
                  'case_id':'GAP-DUMPPACKETS',
                  'source_hashes_sha256':hashlib.sha256(payload).hexdigest()}
        frozen=candidate.get('source_deployment_identity')
        if frozen is not None and frozen!=identity:
            raise ValueError('plan source deployment identity differs from the closure')
        return dict(schema='fakenet.manual-input.v3',case=case['id'],candidate_id='manual-candidate',
                    source_commit=candidate['source_commit'],package_sha256=None,
                    execution_id=plan['execution_id'],owned_root=owned_root,config=config,
                    responsea=options.get('responsea','192.0.2.55'),
                    fixture=candidate.get('offline_fixture') is True,
                    source_deployment_identity=identity)
    if case['id']=='GAP-DUMPPACKETS' and candidate.get('package_sha256') is None and \
            candidate.get('deployment_kind')!='source':
        # SD-01: undeclared null-package manual candidate refused before VM work
        raise ValueError('manual candidate requires a package identity or the explicit source deployment kind')
    return dict(schema='fakenet.manual-input.v1',case=case['id'],candidate_id='manual-candidate',
                source_commit=candidate['source_commit'],package_sha256=candidate['package_sha256'],
                execution_id=plan['execution_id'],owned_root=owned_root,config=config,
                responsea=options.get('responsea','192.0.2.55'),
                fixture=candidate.get('offline_fixture') is True)


def manual_remote_inputs(plan,case,output_root):
    """Derive the guest-side manual inputs with guest path semantics.

    The host Path type cannot normalize a Windows owned root, so the remote
    request carries only the shared options and the guest derives its own
    owned_root; this host rebuild uses the same single value builder."""
    from pathlib import PureWindowsPath, PurePosixPath
    if case['id'] not in MANUAL_REMOTE_CASES:
        raise ValueError('remote manual inputs are fixed to GAP-NCSI/GAP-RAW-DATE')
    runtime=plan['environment']['native_runtime']
    path_type=PureWindowsPath if runtime['identity']['platform']=='windows' else PurePosixPath
    options=manual_options(plan['environment'])
    directory=path_type(output_root)/'driver'
    value=_manual_input_value(plan,case,options,str(directory),str(directory/'config'))
    for key in ('owned_root','config'):
        path=path_type(value[key])
        if not path.is_absolute() or '..' in path.parts:
            raise ValueError('remote manual path must be absolute and bounded: '+key)
    return value


def manual_inputs(plan,case,output_dir):
    import acceptance_manual
    options=plan['environment'].get('manual')
    if case['id']=='GAP-NETWORK-FIX' and isinstance(options,dict) and options.get('schema')=='fakenet.manual-options.v2':
        if set(options)!={'schema','network'}:raise ValueError('exact network-fix options required')
        target=plan['environment']['native_runtime'].get('identity',{})
        candidate=plan['candidate'];directory=Path(output_dir).resolve()/'driver'
        pins=['tools/acceptance_manual.py','tools/acceptance_manual_oracles.py','tools/acceptance_linux_recovery.py','fakenet/diverters/diverterbase.py']
        pins += ['fakenet/diverters/'+name+'.py' for name in (('winutil','windows') if target.get('platform')=='windows' else ('linutil','linux'))]
        source=Path(__file__).resolve().parents[1]
        value=dict(schema='fakenet.manual-input.v2',case=case['id'],candidate_id=candidate.get('candidate_id') or 'manual-candidate',source_commit=candidate['source_commit'],package_sha256=candidate['package_sha256'],execution_id=plan['execution_id'],owned_root=str(directory),config=str(directory/'config'),fixture=candidate.get('offline_fixture') is True,platform=target.get('platform'),network=dict(options['network']),source_hashes={name:sha256(source/name) for name in pins})
        acceptance_manual.validate_inputs(case['id'],value)
        return value
    options=manual_options(plan['environment'])
    directory=Path(output_dir).resolve()/'driver'
    value=_manual_input_value(plan,case,options,str(directory),str(directory/'config'))
    acceptance_manual.validate_inputs(case['id'],value)
    return value


def linux_inputs(plan, case, output_dir, root=None):
    import acceptance_linux_runtime as linux
    options = plan['environment'].get('linux')
    if not isinstance(options, dict):
        raise ValueError('explicit fixed Linux runtime options required')
    if case['id'] not in linux.CASES:
        raise ValueError('unknown Linux deployment case')
    runtime_value = plan['environment']['native_runtime']
    if options.get('schema') == 'fakenet.linux-composite-options.v1':
        target = options.get('singlehost', {}).get('target')
        if not isinstance(target, dict) or set(target) != {'platform', 'hostname'}:
            raise ValueError('explicit composite SingleHost target required')
    else:
        target = runtime_value.get('identity')
    candidate = plan['candidate']; source_root = Path(root) if root else Path(__file__).resolve().parents[1]
    pins = ['fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
            'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
            'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py',
            'tools/acceptance_linux_composite.py', 'tools/acceptance_orchestration.py',
            'tools/acceptance_multihost.py', 'tools/acceptance_linux.py',
            'tools/acceptance_guest.py', 'tools/acceptance_collection.py',
            'test/test.py', 'test/template.ini', 'test/custom_responses.ini',
            'test/CustomProviderExample.py', 'test/sample_raw_response.txt',
            'test/sample_raw_tcp_response.txt']
    if not candidate.get('package_sha256'):
        raise ValueError('bound Linux candidate package SHA-256 required')
    common = dict(schema=linux.INPUT_SCHEMA, case=case['id'],
                  candidate_id=candidate.get('candidate_id') or 'linux-candidate',
                  source_commit=candidate['source_commit'], package_sha256=candidate['package_sha256'],
                  execution_id=plan['execution_id'], target=target,
                  source_hashes={rel: sha256(source_root/rel) for rel in pins})
    if options.get('schema') == 'fakenet.linux-composite-options.v1':
        if set(options) != {'schema', 'singlehost', 'multihost'}:
            raise ValueError('unknown Linux composite options')
        import acceptance_linux_composite as composite_schema
        single = dict(options['singlehost']); single['target'] = target
        value = dict(common, schema=composite_schema.INPUT_SCHEMA,
                     owned_root=str(Path(output_dir)/'driver'),
                     deployed_identity=candidate.get('deployed_identity'),
                     singlehost=single, multihost=options['multihost'])
        if candidate.get('offline_fixture') is True:
            value['fixture'] = True
        return value
    if case['id'] == 'LINUX-DEPLOY-UPDATE' and options.get('schema') == 'fakenet.linux-deploy-options.v2':
        fields={'schema','system_root','install_package','install_manifest_sha256','update_template','update_template_sha256','operation','fault','binding'}
        if set(options)!=fields:
            raise ValueError('exact phase deployment options and execution operation required')
        pins=pins[:6]+['tools/acceptance_linux_recovery.py']
        return dict(common,schema='fakenet.linux-runtime-input.v3',
                    source_hashes={rel:sha256(source_root/rel) for rel in pins},
                    owned_root=str(Path(output_dir)/'driver'),
                    fixture=candidate.get('offline_fixture') is True,
                    actions=list(plan['environment'].get('allowed_actions',[])),
                    **{key:options[key] for key in fields-{'schema'}})
    if case['id'] == 'LINUX-DEPLOY-UPDATE':
        if options.get('schema') != 'fakenet.linux-deploy-options.v1':
            raise ValueError('explicit fixed Linux deployment options required')
        if set(options) != {'schema', 'accepted_update_root', 'install_package',
                            'install_manifest_sha256', 'update_package',
                            'update_manifest_sha256', 'operation'}:
            raise ValueError('unknown Linux deployment options')
        value = dict(common, fresh_root=str(Path(output_dir)/'driver'),
                     **{key: options[key] for key in ('accepted_update_root', 'install_package',
                                                      'install_manifest_sha256', 'update_package',
                                                      'update_manifest_sha256', 'operation')})
        if candidate.get('offline_fixture') is True:
            value['fixture'] = True
        return value
    if options.get('schema') != 'fakenet.linux-runtime-options.v2':
        raise ValueError('explicit fixed Linux runtime options required')
    if set(options) != {'schema', 'config', 'config_sha256', 'mode', 'probe'}:
        raise ValueError('unknown Linux runtime options')
    if options['mode'] != 'singlehost':
        raise NotImplementedError('Linux MultiHost second-target original producer not connected')
    return dict(common, owned_root=str(Path(output_dir)/'driver'),
                **{k: options[k] for k in ('config', 'config_sha256', 'mode', 'probe')})


def runtime_block(case, environment):
    if case.get('native_driver') == 'linux-runtime':
        options = environment.get('linux') or {}
        if options.get('schema') == 'fakenet.linux-composite-options.v1':
            if set(options) != {'schema', 'singlehost', 'multihost'}:
                return 'explicit exact Linux composite options required'
            return None
        if case['id'] == 'LINUX-DEPLOY-UPDATE':
            if options.get('schema') == 'fakenet.linux-deploy-options.v2':
                fields={'schema','system_root','install_package','install_manifest_sha256','update_template','update_template_sha256','operation','fault','binding'}
                if set(options)!=fields:
                    return 'explicit exact phase deployment options required'
                if not environment.get('native_runtime',{}).get('transport')=='local-target':
                    return 'phase deployment requires explicit local-target execution'
                return None
            if options.get('schema') != 'fakenet.linux-deploy-options.v1' or set(options) != {
                    'schema', 'accepted_update_root', 'install_package', 'install_manifest_sha256',
                    'update_package', 'update_manifest_sha256', 'operation'}:
                return 'explicit exact Linux deployment options required'
            return None
        if case['id'] != 'LINUX-SINGLEHOST':
            return 'unknown Linux runtime case'
        if options.get('schema') != 'fakenet.linux-runtime-options.v2' or set(options) != {'schema','config','config_sha256','mode','probe'}:
            return 'explicit exact Linux runtime options required'
        if options.get('mode') != 'singlehost':
            return 'Linux MultiHost requires an independent second target; local probe is insufficient'
        return 'SingleHost remains blocked until an independently observed MultiHost target is available'
    if case.get('native_driver') in ('manual-ncsi','manual-raw-date','manual-list-mutex','manual-executecmd','manual-diverter-switch','manual-dumppackets','manual-syslog-icmp','manual-ctrlc-ipc','manual-linux-flush-interface','manual-network-fix','manual-standalone'):
        runtime=environment.get('native_runtime') or {}
        if runtime.get('transport')=='manual-loopback-fixture':
            return None  # Full fixture/candidate/observed-host gate in expected_block and run_production.
        if runtime.get('transport')=='windows-mcp-velo' and case.get('native_driver') in MANUAL_REMOTE_DRIVERS:
            # Only GAP-NCSI/GAP-RAW-DATE may ride the existing Windows channel;
            # the frozen options stay mandatory and are checked before effects.
            try:
                manual_options(environment)
            except ValueError as exc:
                return str(exc)
            # The shared existing-channel gate below re-checks identity,
            # authorized actions, absolute remote paths and case platforms.
        elif runtime.get('transport')!='local-target':
            return 'manual listeners require installed source on explicit local-target VM; no remote fallback'
    if case.get('native_driver') == 'build-identity':
        return None  # Host-side read-only package check; no target channel.
    if case.get('native_driver')=='mcp-headless':
        try:
            import acceptance_mcp
            inputs=environment.get('mcp')
            acceptance_mcp.validate_inputs(inputs,case['id'],environment.get('mcp_checks',{}).get(case['id']))
            if not {'native','vm-execute'}.issubset(environment.get('allowed_actions',[])):
                return 'MCP existing-channel execute is not authorized'
            runtime=environment.get('native_runtime') or {}
            if runtime.get('transport')!='windows-mcp-velo' or runtime.get('identity',{}).get('platform')!='windows':
                return 'MCP requires the existing explicit Windows channel'
            if any(runtime.get(k)!=inputs['channel'].get(k) for k in ('mcp_config_ref','mcp_server')):
                return 'MCP channel differs from frozen environment'
            if any(inputs['target'][k]!=runtime['identity'].get(k) for k in ('platform','hostname')):
                return 'MCP target differs from frozen Windows target'
            return None
        except (OSError,ValueError,KeyError,TypeError) as exc:return 'MCP original input refused: '+str(exc)
    if case.get('stress'):
        return 'functional native driver does not run stress'
    runtime=environment.get('native_runtime')
    if isinstance(runtime,dict) and runtime.get('transport')=='windows-mcp-velo':
        if runtime.get('identity',{}).get('platform')!='windows':
            return 'Windows MCP channel requires a Windows target'
        required={'mcp_config_ref','mcp_server','python','source_root','work_root','transfer'}
        if not required.issubset(runtime):
            return 'existing Windows channel references are incomplete'
        if not {'native','vm-execute','vm-transfer'}.issubset(environment.get('allowed_actions',[])):
            return 'environment does not authorize VM execute and transfer'
        from pathlib import PureWindowsPath
        for key in ('python','source_root','work_root'):
            if not PureWindowsPath(runtime[key]).is_absolute():
                return 'remote Windows paths must be absolute'
        if PureWindowsPath(runtime['work_root']).drive.upper() not in ('E:','D:'):
            return 'new Windows work root requires a recorded E/D location'
        if 'windows' not in case['platforms'] or case.get('stress'):
            return 'case does not support this Windows functional target'
        return None
    if case.get('native_driver')=='upstream-multihost':
        if not isinstance(runtime,dict) or runtime.get('transport')!='remnux-multihost':
            return 'MultiHost requires an explicit two-target existing-channel runtime'
        from acceptance_orchestration import multi_runtime_block
        return multi_runtime_block(runtime,case,environment)
    if isinstance(runtime,dict) and runtime.get('transport')=='remnux-sdk':
        from acceptance_orchestration import linux_runtime_block
        return linux_runtime_block(runtime,case,environment)
    if not isinstance(runtime,dict) or runtime.get('transport')!='local-target':
        return 'native_runtime requires an explicit local-target channel on the selected VM'
    identity=runtime.get('identity')
    if not isinstance(identity,dict) or set(identity)!={'platform','hostname'} or not identity.get('hostname'):
        return 'native_runtime.identity requires exact platform and hostname'
    if identity['platform'] not in ('linux','windows'):
        return 'unsupported native target platform'
    if identity['platform'] not in case['platforms']:
        return 'native target platform does not match case'
    # local-target never treats a host platform label as remote VM authority.
    return None


def is_fixture(case, root):
    driver, unused = validate_case(case, root)
    return bool(driver.get('fixture'))


def fixed_argv(driver, context):
    argv = []
    for item in driver['argv']:
        if not isinstance(item, str):
            raise ValueError('native driver argv must be strings')
        value = item
        for key, replacement in context.items():
            value = value.replace('{%s}' % key, str(replacement))
        if re.search(r'[<>|;&]', value):
            raise ValueError('native argv token contains a shell metacharacter: %r' % value)
        argv.append(value)
    return argv


def run_driver(root, case, plan, output_dir, python):
    driver, unused=validate_case(case,root,plan['environment'])
    import acceptance_linux_composite as composite
    if composite.selected(plan, case):
        return composite.run_controller(root, case, plan, output_dir)
    if driver.get('production_kind') == 'package-identity':
        return __import__('acceptance_package').run(root,case,plan,output_dir)
    if driver.get('production_kind')=='mcp-controller':return run_mcp_controller(root,case,plan,output_dir,python)
    if driver.get('production_kind')=='upstream-multihost':
        from acceptance_orchestration import run_multihost
        return run_multihost(root,case,plan,output_dir)
    if driver.get('production_kind'):
        if plan['environment'].get('native_runtime',{}).get('transport')=='windows-mcp-velo':
            return run_remote(root,case,plan,output_dir,python)
        if plan['environment'].get('native_runtime',{}).get('transport')=='remnux-sdk':
            from acceptance_orchestration import run_linux
            return run_linux(root,case,plan,output_dir)
        return run_production(root,case,plan,output_dir,python)
    root = Path(root)
    driver, checks = validate_case(case, root)
    if not driver.get('implemented'):
        raise ValueError(driver.get('missing') or 'driver is not implemented')
    candidate = plan.get('candidate') or {}
    if driver.get('package_required'):
        for key in ('package_manifest', 'package_sha256', 'deployed_identity'):
            if not candidate.get(key):
                raise ValueError('candidate.%s is required by %s' % (key, case['id']))
    context = {
        'python': python,
        'output': output_dir,
        'root': root,
        'package_manifest': candidate.get('package_manifest') or '',
        'package_sha256': candidate.get('package_sha256') or '',
        'case_id': case['id'], 'checks': ','.join(checks),
    }
    argv = fixed_argv(driver, context)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / 'stdout.log'
    stderr_path = output_dir / 'stderr.log'
    from datetime import datetime, timezone
    start_dt = datetime.now(timezone.utc)
    timed_out = False
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            process = subprocess.Popen(argv, cwd=root, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
            try:
                returncode = process.wait(timeout=case['timeout'])
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    process.kill()
                process.wait()
                returncode = None
    except OSError as error:
        raise ValueError('cannot start native driver: %s' % error) from error
    end_dt = datetime.now(timezone.utc)
    started = start_dt.isoformat()
    ended = end_dt.isoformat()
    artifacts = []
    rows = []
    status = 'unknown'
    detail = ''
    oracle = driver['oracle']
    artifact = _discover_artifact(oracle, output_dir)
    if artifact is None:
        detail = 'oracle artifact was not produced'
    else:
        artifacts.append({'path': str(artifact.resolve()), 'sha256': sha256(artifact),
                          'format': oracle['kind']})
        try:
            rows = _read_oracle(oracle['kind'], artifact)
            evaluation = _judge_rows(rows, checks)
            status = evaluation['verdict']
            detail = json.dumps(evaluation, ensure_ascii=False)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            detail = 'oracle parse failed: %s' % error
    if returncode not in (0, None) and status == 'pass':
        status = 'fail'
        detail = 'driver rc=%s; %s' % (returncode, detail)
    if timed_out:
        status = 'unknown'
        detail = 'timeout after %ss' % case['timeout']
    artifacts.append({'path': str(stdout_path.resolve()), 'sha256': sha256(stdout_path),
                      'format': 'log'})
    artifacts.append({'path': str(stderr_path.resolve()), 'sha256': sha256(stderr_path),
                      'format': 'log'})
    return {
        'status': status,
        'detail': detail,
        'returncode': returncode,
        'command': argv,
        'started_at': started,
        'ended_at': ended,
        'duration_seconds': (end_dt - start_dt).total_seconds(),
        'required_checks': checks,
        'artifacts': artifacts,
        'cleanup': {'source': 'driver',
                    'resources': list(driver.get('resources') or []),
                    'process_exit': {'exited': True, 'returncode': returncode,
                                     'timed_out': timed_out},
                    'temp_roots': [str(output_dir.resolve())]},
    }


def judge_driver(case, receipt, plan, root):
    driver,unused=validate_case(case,root,plan['environment'])
    import acceptance_linux_composite as composite
    if composite.selected(plan, case):
        return composite.judge_controller(root, case, receipt, plan)
    if driver.get('production_kind') == 'package-identity':
        return __import__('acceptance_package').judge(root,case,receipt,plan)
    if driver.get('production_kind')=='mcp-controller':return judge_mcp_controller(case,receipt,plan,root)
    if driver.get('production_kind')=='upstream-multihost':
        from acceptance_orchestration import judge_multihost
        return judge_multihost(case,receipt,plan,root)
    if driver.get('production_kind'):
        if plan['environment'].get('native_runtime',{}).get('transport') in ('windows-mcp-velo','remnux-sdk'):
            return judge_remote(case,receipt,plan,root)
        return judge_production(case,receipt,plan,root)
    driver, checks = validate_case(case, root)
    if not driver.get('implemented'):
        return {'status': 'blocked', 'reason': driver.get('missing') or 'not implemented'}
    expected_argv = fixed_argv(driver, {
        'python': plan['environment']['interpreters']['python'],
        'output': str(Path(plan['run_dir']) / 'results' / case['id']),
        'root': str(root),
        'package_manifest': plan.get('candidate', {}).get('package_manifest') or '',
        'package_sha256': plan.get('candidate', {}).get('package_sha256') or '',
        'case_id': case['id'], 'checks': ','.join(checks)})
    if receipt.get('command') != expected_argv:
        return {'status': 'fail', 'reason': 'receipt argv differs from the registered driver'}
    if receipt.get('required_checks') != checks:
        return {'status': 'fail', 'reason': 'receipt checks differ from the registered table'}
    artifacts = receipt.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts:
        return {'status': 'unknown', 'reason': 'receipt has no artifacts'}
    formats = []
    for item in artifacts:
        path = Path(item.get('path', ''))
        if not path.is_absolute() or not path.is_file() or sha256(path) != item.get('sha256'):
            return {'status': 'unknown', 'reason': 'artifact missing or changed: %s' % path}
        formats.append(item.get('format'))
    if formats.count('log') < 2:
        return {'status': 'unknown', 'reason': 'stdout/stderr logs are not both indexed'}
    oracle = driver['oracle']
    oracle_paths = [item for item in artifacts if item.get('format') == oracle['kind']]
    if len(oracle_paths) != 1:
        return {'status': 'unknown', 'reason': 'expected exactly one native oracle artifact'}
    artifact = Path(oracle_paths[0]['path'])
    rows = _read_oracle(oracle['kind'], artifact)
    evaluation = _judge_rows(rows, checks)
    receipt_status = receipt.get('status')
    if evaluation['verdict'] == 'fail' or receipt_status == 'fail':
        status = 'fail'
    elif evaluation['verdict'] != 'pass' or receipt_status != 'pass':
        status = 'unknown'
    else:
        status = 'pass'
    returncode = receipt.get('returncode')
    cleanup = receipt.get('cleanup')
    cleanup_ok = True
    reason = ''
    if not isinstance(cleanup, dict) or cleanup.get('source') != 'driver':
        cleanup_ok = False
        reason = 'cleanup was not derived by the driver'
    elif cleanup.get('resources') != list(driver.get('resources') or []):
        cleanup_ok = False
        reason = 'cleanup resource scope differs from the driver'
    else:
        process_exit = cleanup.get('process_exit') or {}
        timed_out = process_exit.get('timed_out')
        if process_exit.get('exited') is not True:
            cleanup_ok = False
            reason = 'process exit was not observed'
        elif timed_out is True and returncode is not None:
            cleanup_ok = False
            reason = 'timeout and a real returncode are contradictory'
        elif timed_out is not True and returncode is None:
            cleanup_ok = False
            reason = 'missing returncode without a timeout'
        elif process_exit.get('returncode') != returncode:
            cleanup_ok = False
            reason = 'cleanup returncode differs from receipt'
        if not isinstance(receipt.get('duration_seconds'), (int, float)) or receipt.get('duration_seconds') <= 0:
            cleanup_ok = False
            reason = 'duration was not observed'
    if returncode is None or returncode != 0:
        status = 'fail' if status != 'unknown' else 'unknown'
        if returncode is None and (cleanup.get('process_exit') or {}).get('timed_out') is not True:
            status = 'unknown'
        elif returncode not in (None, 0):
            status = 'fail'
    if not cleanup_ok:
        if status == 'pass':
            status = 'unknown'
        reason = reason or 'cleanup is not valid'
    return {'status': status, 'evaluation': evaluation,
            'cleanup_ok': cleanup_ok, 'reason': reason}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _discover_artifact(oracle, output_dir):
    name = oracle.get('artifact')
    if not name:
        return None
    path = Path(output_dir) / name
    if path.is_file():
        return path
    pattern = oracle.get('discover')
    if pattern:
        log = Path(output_dir) / 'stdout.log'
        if log.is_file():
            match = re.search(pattern, _read(log))
            if match:
                candidate = Path(match.group(1).strip().strip('"')) / name
                if candidate.is_file():
                    return candidate
    return None


def _read_oracle(kind, path):
    if kind == 'tsv':
        rows = []
        for number, line in enumerate(_read(path).splitlines(), 1):
            if not line.strip():
                continue
            fields = line.split('\t')
            if len(fields) < 2:
                raise ValueError('invalid TSV line %d' % number)
            first, second = fields[:2]
            if number==1 and first.lstrip('\ufeff').lower()=='status' and second.lower() in ('name','test','id'):
                continue
            if first.lower() in ('pass', 'fail', 'unknown', 'not_run', 'blocked',
                                 'skip', 'observed') or first.upper() in ('FAILED', 'REFUSED'):
                status, name = first.lower(), second
            else:
                name, status = first, second.lower()
            status = {'failed': 'fail', 'refused': 'blocked'}.get(status, status)
            rows.append({'id': name, 'status': status})
        return rows
    if kind == 'mcp-result':
        raise ValueError('MCP original judgment requires frozen inputs and selection')
    if kind == 'headless-result':
        import acceptance_headless_oracles
        value = json.loads(_read(path))
        mode = 'process' if value.get('mode') == 'process' else 'payload'
        ids = value.get('selection') or []
        rows, unused, unused_detail = acceptance_headless_oracles.evaluate(
            Path(__file__).resolve().parents[1], Path(path).parent, mode, ids,
            allow_fixture=True)
        return rows
    if kind == 'policy-result':
        import acceptance_policy_oracles
        value = json.loads(_read(path))
        ids = [item.get('id') for item in value.get('checks') or []
               if isinstance(item, dict) and isinstance(item.get('id'), str)]
        rows, unused = acceptance_policy_oracles.evaluate(
            Path(path).parent, value.get('scenario'), ids, allow_fixture=True)
        return rows
    if kind in ('json', 'native-json'):
        value = json.loads(_read(path))
        if not isinstance(value, dict):
            raise ValueError('native JSON oracle must be an object')
        return value.get('checks') or []
    raise ValueError('unknown native oracle kind: %r' % kind)


def _judge_rows(rows, required):
    if not required or len(required) != len(set(required)):
        raise ValueError('a nonempty unique native check list is required')
    by_id = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), str):
            raise ValueError('invalid native result row')
        if row.get('status') not in ('pass', 'fail', 'unknown', 'not_run',
                                     'blocked', 'skip', 'observed'):
            raise ValueError('invalid native result status')
        by_id.setdefault(row['id'], []).append(row)
    missing = [key for key in required if key not in by_id]
    duplicate = sorted(key for key, values in by_id.items() if len(values) != 1)
    nonpass = [key for key in required if key in by_id
               and any(row.get('status') != 'pass' for row in by_id[key])]
    failed = sorted(key for key, values in by_id.items()
                    if any(row.get('status') == 'fail' for row in values))
    extra = sorted(set(by_id) - set(required))
    verdict = ('fail' if failed else
               'unknown' if missing or duplicate or nonpass or extra else 'pass')
    return {'verdict': verdict, 'missing': missing, 'duplicate': duplicate,
            'nonpass': nonpass, 'failed': failed, 'extra': extra}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-package', nargs=2, metavar=('MANIFEST', 'SHA256'))
    args = parser.parse_args(argv)
    if args.check_package:
        manifest, expected = args.check_package
        path = Path(manifest)
        if not path.is_file() or sha256(path) != expected:
            return 1
        print(json.dumps({'source_commit': None, 'package_manifest': str(path),
                          'package_sha256': expected}))
        return 0
    parser.print_help()
    return 2


if __name__ == '__main__':
    raise SystemExit(main())


def policy_inputs(environment, fixture=False, scenario="domain"):
    value=environment.get('policy')
    if not isinstance(value,dict):
        raise ValueError('environment.policy inputs are required for policy drivers')
    import acceptance_policy
    acceptance_policy._validate_inputs(scenario,value,strict=not fixture)
    return value


def headless_inputs(environment, driver, checks):
    import acceptance_headless
    mode='process' if driver['production_kind']=='process-redirect' else 'payload'
    value=environment.get('headless')
    acceptance_headless.validate_inputs(mode,value,checks)
    return value


def headless_service_policy(environment):
    value=environment['headless']
    return {'sink_ip':value['target_ip'],'sink_port':value['port'],
            'local_source':value['source_ip'],'host_service':environment.get('headless_service')}


def production_command(root,case,plan,output_dir,python):
    driver,checks=validate_case(case,root,plan['environment'])
    context={'root':str(Path(root).resolve()),'python':str(python),
             'output':str(Path(output_dir).resolve()),'modes':','.join(checks),
             'policy_inputs':str(Path(output_dir).resolve()/'policy-inputs.json'),
             'headless_inputs':str(Path(output_dir).resolve()/'headless-inputs.json'),
             'mcp_inputs':str(Path(output_dir).resolve()/'mcp-inputs.json'),
             'case_id':case['id'], 'checks':','.join(checks),
             'manual_inputs':str(Path(output_dir).resolve()/'manual-inputs.json'),
             'linux_inputs':str(Path(output_dir).resolve()/'linux-inputs.json')}
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        headless_inputs(plan['environment'],driver,checks)
    if driver['production_kind'].startswith('policy-'):
        policy_inputs(plan['environment'],plan.get('candidate',{}).get('offline_fixture') is True,driver['production_kind'].split('-',1)[1])
    if driver['production_kind'].startswith('manual-'):manual_inputs(plan,case,output_dir)
    argv=fixed_argv(driver,context)
    if driver['production_kind']=='dual-pcap-linux':
        for mode in checks:argv.extend(['--case',mode])
    if driver['production_kind'].startswith('policy-') and plan.get('candidate',{}).get('offline_fixture') is True:
        argv.append('--substitute')
    if driver['production_kind'] in ('process-redirect','payload-three-way') and plan.get('candidate',{}).get('offline_fixture') is True:
        argv.append('--memory')
    return argv


def original_evaluation(root,case,plan,output_dir):
    import acceptance_oracles
    driver,checks=validate_case(case,root,plan['environment'])
    directory=Path(output_dir)/'driver'
    if driver['production_kind'] == 'linux-runtime':
        import acceptance_linux_runtime_oracles as linux_oracle
        expected = linux_inputs(plan, case, output_dir, root)
        if json.loads(_read(Path(output_dir)/'linux-inputs.json')) != expected:
            raise ValueError('Linux frozen request changed')
        rows, clean, detail = linux_oracle.evaluate(root, directory, case['id'], checks,
            allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True, expected_inputs=expected)
        evaluation = _judge_rows(rows, checks); evaluation['details'] = detail
        return evaluation, clean
    if driver['production_kind'].startswith('manual-'):
        import acceptance_manual_oracles
        expected=manual_inputs(plan,case,output_dir)
        if json.loads(_read(Path(output_dir)/'manual-inputs.json'))!=expected:
            raise ValueError('manual inputs changed since plan')
        rows,clean,detail=acceptance_manual_oracles.evaluate(root,directory,case['id'],expected,allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True)
        result=_judge_rows(rows,checks);result['details']=detail
        return result,clean
    elif driver['production_kind']=='upstream-result':

        rows,clean=acceptance_oracles.upstream(root,directory,checks)
    elif driver['production_kind'].startswith('policy-'):
        import acceptance_policy_oracles
        rows,clean=acceptance_policy_oracles.evaluate(
            directory,driver['production_kind'].split('-',1)[1],checks,
            expected_inputs=plan['environment'].get('policy'),
            allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True)
    elif driver['production_kind'] in ('process-redirect','payload-three-way'):
        import acceptance_headless_oracles
        mode=('process' if driver['production_kind']=='process-redirect'
              else 'payload')
        rows,clean,detail=acceptance_headless_oracles.evaluate(
            root,directory,mode,checks,
            allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True,
            expected_inputs=plan['environment'].get('headless'))
        evaluation=_judge_rows(rows,checks);evaluation['details']=rows
        return evaluation,clean
    else:
        platform=driver['production_kind'].rsplit('-',1)[1]
        rows,clean=acceptance_oracles.dual_pcap(root,directory,checks,platform)
    return _judge_rows(rows,checks),clean


def _closure_inventory(output_root):
    """Canonical closed inventory of every regular file under output_root,
    together with a SOURCE-ONLY physical snapshot (st_dev/st_ino/st_mtime_ns/
    st_size).  The content rows never mix physical facts into their equality
    semantics; the physical snapshot is compared separately so a same-bytes
    physical replacement between the strict pass and the post scan refuses
    the closure.  Each file is lstat'ed around its read: read-time identity
    drift is refused on the spot."""
    import hashlib
    output_root=Path(output_root)
    rows={};physical={};seen={};casefold={}
    for path in sorted(output_root.rglob('*')):
        if path.is_symlink():raise ValueError('closure inventory contains a symlink: %s'%path)
        if not path.is_file():continue
        relative=path.relative_to(output_root).as_posix()
        parts=relative.split('/')
        if (not relative or any(part in ('','..','.') for part in parts) or
                '\\' in relative or relative!=path.relative_to(output_root).as_posix()):
            raise ValueError('closure inventory path is not canonical: %s'%relative)
        if relative in seen:raise ValueError('closure inventory duplicate: %s'%relative)
        fold=relative.casefold()
        if fold in casefold:raise ValueError('closure inventory case alias: %s'%relative)
        seen[relative]=True;casefold[fold]=relative
        before=os.lstat(path)
        data=path.read_bytes()
        after=os.lstat(path)
        identity=('st_dev','st_ino','st_mtime_ns','st_size')
        if any(getattr(before,name)!=getattr(after,name) for name in identity):
            raise ValueError('closure member changed while being read: %s'%relative)
        rows[relative]={'relative_path':relative,'size':after.st_size,
                        'sha256':hashlib.sha256(data).hexdigest()}
        physical[relative]=[getattr(after,name) for name in identity]
    return rows,physical


def finalize_dump_evidence(root,request,request_sha256,output_root):
    """DC-02 source finalization: after the Dump producer exited, re-run the
    strict source oracle in place, freeze a stable closed inventory around it,
    and return the data-only closure for the fixed entry's stdout.  Never
    re-runs the producer, never reseals, never fabricates stability."""
    root=Path(root);output_root=Path(request['output_root'])
    if request.get('case_id')!='GAP-DUMPPACKETS':
        raise ValueError('dump source closure is fixed to GAP-DUMPPACKETS')
    # G1/G2: the finalizer re-runs the complete source gate (full registered
    # M) before any inventory work.
    root_argument = root
    if request['candidate'].get('deployment_kind') == 'source':
        _catalog = json.loads(_read(Path(root)/'docs/acceptance/catalog.json'))
        _case = next(c for suite in _catalog['suites'] for c in suite.get('cases', [])
                     if c['id'] == 'GAP-DUMPPACKETS')
        _source_deployment_identity_from_request(request, root_argument, _case)
    result_path=output_root/'guest-result.json'
    if not result_path.is_file():
        raise ValueError('dump source closure requires a closed guest result')
    result=json.loads(_read(result_path))
    receipt=result.get('receipt') or {}
    cleanup=receipt.get('cleanup') or {};process=cleanup.get('process_exit') or {}
    if (result.get('case_id')!=request['case_id'] or
            result.get('request')!=request or
            receipt.get('status')!='pass' or cleanup.get('recovered') is not True or
            process.get('exited') is not True):
        raise ValueError('dump source closure requires a passing recovered guest result')
    environment={'native_runtime':{'transport':'local-target','identity':request['target']}}
    for key in ('policy','headless','mcp','linux','manual'):
        if key in request:environment[key]=request[key]
    if 'upstream_protected_tcp_ports' in request:
        environment['native_runtime']['upstream_protected_tcp_ports']=validate_upstream_protected_tcp_ports(request['upstream_protected_tcp_ports'])
    catalog=json.loads(_read(Path(root)/'docs/acceptance/catalog.json'))
    case=next(item for suite in catalog['suites'] for item in suite.get('cases',[]) if item['id']==request['case_id'])
    plan={'candidate':request['candidate'],'environment':environment,'execution_id':request['execution_id'],
          # SD-05/F1: the finalizer derives the source identity from the
          # VERIFIED request closure M - the same frozen inputs the guest used.
          'source_deployment_closure':dict(request['source_hashes']),
          'native_source_hashes':{},'source_hashes':{'GAP-DUMPPACKETS':dict(request['source_hashes'])}}
    pre,pre_physical=_closure_inventory(output_root)
    if not pre:raise ValueError('dump source closure inventory is empty')
    evaluation,clean=original_evaluation(root,case,plan,output_root)
    if evaluation.get('verdict')!='pass' or clean is not True:
        raise ValueError('dump source closure requires a clean strict source pass: %s'%evaluation.get('verdict'))
    # The same enabled-capture selection the oracle uses; the strict loader
    # re-confirms the seal and capture id on the still-source-resident files.
    folder=output_root/'driver'/'enabled'
    files=sorted(path.name for path in folder.glob('*.pcap'))
    raw=folder/next(name for name in files if not name.endswith('-converted.pcap'))
    converted=folder/next(name for name in files if name.endswith('-converted.pcap'))
    from fakenet.payload_report import load_capture_originals
    loaded=load_capture_originals(raw,converted)
    capture={'raw':raw.relative_to(output_root).as_posix(),
             'converted':converted.relative_to(output_root).as_posix(),
             'seal':Path(str(raw)+'.capture-originals.json').relative_to(output_root).as_posix(),
             'capture_id':loaded.capture_id}
    post,post_physical=_closure_inventory(output_root)
    if pre!=post:
        raise ValueError('output set changed during source finalization')
    if pre_physical!=post_physical:
        raise ValueError('output physical identity changed during source finalization')
    for member in (capture['raw'],capture['converted'],capture['seal']):
        if member not in post:raise ValueError('capture member missing from closure inventory: %s'%member)
    closure={
        'schema':'fakenet.dump-source-closure.v1',
        'request_sha256':request_sha256,
        'execution_id':request['execution_id'],
        'case_id':request['case_id'],
        'candidate':request['candidate'],
        'source_hashes':request['source_hashes'],
        'target':request['target'],
        'output_root':request['output_root'],
        'source_verdict':'pass',
        'cleanup_recovered':True,
        'capture':capture,
        'files':[post[key] for key in sorted(post)],
    }
    closure['inventory_sha256']=hashlib.sha256(json.dumps(
        closure['files'],ensure_ascii=False,sort_keys=True,
        separators=(',',':')).encode('utf-8')).hexdigest()
    return closure



def run_production(root,case,plan,output_dir,python):
    """Run only on the explicitly bound target, never host fallback.

    Drivers own cleanup. An outer timeout requests cooperative interruption on
    POSIX, then preserves an unresolved owner instead of claiming kill=restore.
    """
    from datetime import datetime,timezone
    from acceptance_runtime import require_target,write_json
    output_dir=Path(output_dir)
    reason=runtime_block(case,plan['environment'])
    partial_guest = (case.get('id') == 'LINUX-SINGLEHOST' and
                     plan['environment'].get('native_runtime',{}).get('transport') == 'local-target' and
                     'allowed_actions' not in plan['environment'] and
                     plan['environment'].get('linux',{}).get('schema') == 'fakenet.linux-runtime-options.v2')
    if reason and not partial_guest:raise ValueError(reason)
    runtime=plan['environment']['native_runtime']
    if 'upstream_protected_tcp_ports' in runtime:
        validate_upstream_protected_tcp_ports(runtime['upstream_protected_tcp_ports'])
    selected_driver,selected_checks=validate_case(case,root,plan['environment'])
    if selected_driver.get('production_kind','').startswith('policy-'):
        policy_inputs(plan['environment'],plan.get('candidate',{}).get('offline_fixture') is True,selected_driver['production_kind'].split('-',1)[1])
    if selected_driver.get('production_kind') in ('process-redirect','payload-three-way'):
        headless_inputs(plan['environment'],selected_driver,selected_checks)
    if selected_driver['production_kind'].startswith('manual-') and runtime.get('transport')=='manual-loopback-fixture':
        reason=manual_fixture_block(plan['environment'],plan.get('candidate',{}))
        if reason:raise ValueError(reason)
        from acceptance_runtime import target_identity
        actual=target_identity()
    elif __import__('acceptance_linux_composite').selected(plan, case):
        raise ValueError('composite requires registered host controller dispatch')
    else:
        actual=require_target(runtime['identity'])

    candidate_identity=(plan.get('candidate') or {}).get('deployed_identity')
    if selected_driver['production_kind']=='linux-runtime' and isinstance(plan.get('environment',{}).get('linux'),dict) and plan['environment']['linux'].get('schema')=='fakenet.linux-composite-options.v1':
        expected_roles={'singlehost':actual['server'],'server':actual['server'],
                        'client':runtime['client']['identity']}
        if candidate_identity!=expected_roles:
            raise ValueError('candidate.deployed_identity differs from observed composite targets')
    elif candidate_identity!=actual:
        raise ValueError('candidate.deployed_identity differs from observed native target')
    driver,checks=validate_case(case,root,plan['environment'])
    argv=production_command(root,case,plan,output_dir,python)
    output_dir.mkdir(parents=True,exist_ok=True)
    request=attach_upstream_protection({'schema':'fakenet.upstream-selection.v1','target':actual,
             'checks':checks,'work_root':str(output_dir/'driver')},plan['environment'])
    if driver['production_kind'].startswith('policy-'):
        write_json(output_dir/'policy-inputs.json',policy_inputs(plan['environment'],plan.get('candidate',{}).get('offline_fixture') is True,driver['production_kind'].split('-',1)[1]))
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        write_json(output_dir/'headless-inputs.json',headless_inputs(plan['environment'],driver,checks))
    if driver['production_kind'].startswith('manual-'):write_json(output_dir/'manual-inputs.json',manual_inputs(plan,case,output_dir))
    if driver['production_kind']=='linux-runtime':write_json(output_dir/'linux-inputs.json',linux_inputs(plan,case,output_dir,root))
    write_json(output_dir/'request.json',request)
    write_json(output_dir/'target.json',actual)
    started=datetime.now(timezone.utc)
    timed_out=False; exited=False; code=None; process=None
    env=os.environ.copy();env['PYTHONPATH']=os.pathsep.join(filter(None,[env.get('PYTHONPATH',''),str(Path(root).resolve())])) if driver['production_kind'].startswith('manual-') else str(Path(root).resolve())
    with (output_dir/'stdout.log').open('xb') as stdout,(output_dir/'stderr.log').open('xb') as stderr:
        options={'start_new_session':True} if os.name!='nt' else {'creationflags':subprocess.CREATE_NEW_PROCESS_GROUP}
        process=subprocess.Popen(argv,cwd=root,env=env,stdout=stdout,stderr=stderr,shell=False,**options)
        try:
            code=process.wait(timeout=case['timeout']);exited=True
        except subprocess.TimeoutExpired:
            timed_out=True
            if os.name!='nt':
                process.send_signal(signal.SIGINT)
                try:code=process.wait(timeout=90);exited=True
                except subprocess.TimeoutExpired:pass
    ended=datetime.now(timezone.utc)
    evaluation={'verdict':'unknown'};clean=False;detail=''
    if exited:
        try:evaluation,clean=original_evaluation(root,case,plan,output_dir)
        except (OSError,ValueError,AssertionError,KeyError,TypeError) as error:
            detail='original native oracle refused: %s: %s' % (type(error).__name__,error)
    else:detail='recovery_required: original driver has not exited; preserve owned process and evidence'
    if timed_out:detail='driver timeout; '+detail
    status=evaluation['verdict']
    if code not in (0,None):status='fail'
    if timed_out or not clean:
        status='unknown' if status!='fail' else status
    # If an owner remains, do not hash its changing logs as stable evidence.
    artifacts=[]
    if exited:
        for path in sorted(output_dir.rglob('*')):
            if path.is_symlink():raise ValueError('native artifact is a symlink')
            if path.is_file():
                fmt='pcap' if path.suffix=='.pcap' else 'log' if path.name in ('stdout.log','stderr.log') else 'native-evidence'
                artifacts.append({'path':str(path.resolve()),'sha256':sha256(path),'format':fmt})
    return {'status':status,'detail':detail,'returncode':code,'command':argv,
            'started_at':started.isoformat(),'ended_at':ended.isoformat(),
            'duration_seconds':(ended-started).total_seconds(),'required_checks':checks,
            'artifacts':artifacts,'native_target':actual,
            'cleanup':{'source':'driver','resources':driver['resources'],'recovered':clean and exited,
                       'process_exit':{'exited':exited,'returncode':code,'timed_out':timed_out},
                       'owner_pid':process.pid,'temp_roots':[str(output_dir.resolve())]}}


def judge_production(case,receipt,plan,root):
    driver,checks=validate_case(case,root,plan['environment'])
    output_dir=Path(plan['run_dir'])/'results'/case['id']
    if receipt.get('command')!=production_command(root,case,plan,output_dir,plan['environment']['interpreters']['python']):
        return {'status':'fail','cleanup_ok':False,'reason':'production argv mismatch'}
    if receipt.get('required_checks')!=checks:
        return {'status':'fail','cleanup_ok':False,'reason':'production check set mismatch'}
    expected_target=plan['environment']['native_runtime'].get('identity')
    if expected_target is None and isinstance(plan.get('environment',{}).get('linux'),dict) and plan['environment']['linux'].get('schema')=='fakenet.linux-composite-options.v1':
        runtime=plan['environment']['native_runtime']
        expected_target={'singlehost':runtime['server']['identity'],'server':runtime['server']['identity'],'client':runtime['client']['identity']}
    if receipt.get('native_target')!=expected_target:
        return {'status':'fail','cleanup_ok':False,'reason':'production target identity mismatch'}
    if isinstance(expected_target,dict) and plan.get('candidate',{}).get('deployed_identity')!=expected_target:
        return {'status':'fail','cleanup_ok':False,'reason':'candidate composite role identity mismatch'}
    artifacts=receipt.get('artifacts') or []
    paths=[]
    for item in artifacts:
        path=Path(item.get('path',''))
        if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
            not path.resolve().is_relative_to(output_dir.resolve()) or sha256(path)!=item.get('sha256')):
            return {'status':'unknown','cleanup_ok':False,'reason':'production artifact missing/changed/outside case'}
        paths.append(str(path.resolve()))
    actual={str(path.resolve()) for path in output_dir.rglob('*') if path.is_file() and path.resolve()!=(output_dir/'receipt.json').resolve()}
    if len(paths)!=len(set(paths)) or set(paths)!=actual:
        return {'status':'unknown','cleanup_ok':False,'reason':'production evidence index is not exact'}
    if not all(str(output_dir/name) in paths for name in ('stdout.log','stderr.log','request.json','target.json')):
        return {'status':'unknown','cleanup_ok':False,'reason':'production execution logs/request/target missing'}
    try:
        if json.loads(_read(output_dir/'target.json'))!=expected_target:
            raise ValueError('observed target differs')
        request=json.loads(_read(output_dir/'request.json'))
        expected_request=attach_upstream_protection({'schema':'fakenet.upstream-selection.v1','target':expected_target,'checks':checks,'work_root':str(output_dir/'driver')},plan['environment'])
        if request!=expected_request:
            raise ValueError('original native request differs from plan')
        evaluation,clean=original_evaluation(root,case,plan,output_dir)
    except (OSError,ValueError,AssertionError,KeyError,TypeError) as error:
        return {'status':'fail' if receipt.get('status')=='fail' or receipt.get('returncode') not in (None,0) else 'unknown','cleanup_ok':False,'reason':'original native oracle refused: %s' % error}
    cleanup=receipt.get('cleanup') or {};process=cleanup.get('process_exit') or {}
    clean=(clean and cleanup.get('source')=='driver' and cleanup.get('resources')==driver['resources'] and
           cleanup.get('recovered') is True and process.get('exited') is True and
           process.get('timed_out') is False and process.get('returncode')==receipt.get('returncode'))
    status=evaluation['verdict']
    if receipt.get('returncode')!=0 or receipt.get('status')=='fail':status='fail'
    if not clean or receipt.get('status') not in ('pass','fail'):
        status='unknown' if status!='fail' else status
    return {'status':status,'evaluation':evaluation,'cleanup_ok':clean,
            'reason':'' if clean else 'native cleanup not established by original observations'}



def remote_guest_command(driver,runtime,output_root,checks,fixture=False,case_id=None):
    from pathlib import PureWindowsPath, PurePosixPath
    target_path=PureWindowsPath if runtime['identity']['platform']=='windows' else PurePosixPath
    context={'root':runtime['source_root'],'python':runtime['python'],
             'output':output_root,'modes':','.join(checks),
             'policy_inputs':str(target_path(output_root)/'policy-inputs.json'),
             'headless_inputs':str(target_path(output_root)/'headless-inputs.json'),
             'manual_inputs':str(target_path(output_root)/'manual-inputs.json'),
             'checks':','.join(checks), 'case_id':case_id or driver.get('case_id','LINUX-SINGLEHOST'),
             'linux_inputs':str(target_path(output_root)/'linux-inputs.json')}
    argv=fixed_argv(driver,context)
    if driver.get('production_kind')=='dual-pcap-linux':
        for mode in checks:argv.extend(['--case',mode])
    if fixture and driver.get('production_kind') in ('process-redirect','payload-three-way'):argv.append('--memory')
    return argv


def run_remote(root,case,plan,output_dir,python):
    from pathlib import PureWindowsPath
    from acceptance_windows import ExistingWindowsChannel,ChannelError,write_new,digest
    from datetime import datetime,timezone
    driver,checks=validate_case(case,root,plan['environment'])
    runtime=plan['environment']['native_runtime'];output_dir=Path(output_dir)
    # Reject an illegal protection field before mkdir/Popen/channel side effects.
    if 'upstream_protected_tcp_ports' in runtime:
        validate_upstream_protected_tcp_ports(runtime['upstream_protected_tcp_ports'])
    remote_base=PureWindowsPath(runtime['work_root'])/plan['execution_id']/case['id']
    remote_output=str(remote_base/'output')
    source_hashes=dict(plan['native_source_hashes'])
    source_hashes.update(plan['source_hashes'][case['id']])
    request={'schema':'fakenet.native-guest-request.v1','case_id':case['id'],
             'case':{key:value for key,value in case.items() if key not in ('required_checks','run_nodes')},
             'checks':checks,'source_hashes':source_hashes,'candidate':plan['candidate'],
             'target':runtime['identity'],'output_root':remote_output,
             'execution_id':plan['execution_id'],'actions':['native']}
    attach_upstream_protection(request,plan['environment'])
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        request['headless']=headless_inputs(plan['environment'],driver,checks)
    if driver['production_kind'].startswith('policy-'):
        request['policy']=policy_inputs(plan['environment'],scenario=driver['production_kind'].split('-',1)[1])
    if driver['production_kind'].startswith('manual-'):
        if case['id'] not in MANUAL_REMOTE_CASES:
            raise ValueError('remote manual transport is fixed to the nine Windows manual-v1 cases')
        request['manual']=manual_options(plan['environment'])
    # Planned records also carry derived 'sources'; compare using the actual
    # registered catalog object instead of sending derived plan-only metadata.
    catalog=json.loads(_read(Path(root)/'docs/acceptance/catalog.json'))
    request['case']=next(item for suite in catalog['suites'] for item in suite.get('cases',[]) if item['id']==case['id'])
    # G1: the complete pre-effect source gate runs BEFORE any channel side
    # effect (push/execute/transfer) for source-deployment candidates.
    if request['candidate'].get('deployment_kind')=='source':
        _source_deployment_identity_from_request(request, root, case)
    request_path=output_dir/'guest-request.json';write_new(request_path,request)
    services=None
    if driver['production_kind'].startswith('policy-') and {'sink_tcp','sink_udp'}&set(checks):
        from acceptance_policy import HostServices
        HostServices.validate(request['policy'],checks,plan['environment']['allowed_actions'])
        services=HostServices(request['policy'],checks,plan['environment']['allowed_actions'],output_dir/'host-services')
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        from acceptance_policy import HostServices
        service_policy=headless_service_policy(plan['environment'])
        HostServices.validate(service_policy,['sink_tcp','sink_udp'],plan['environment']['allowed_actions'])
        services=HostServices(service_policy,['sink_tcp','sink_udp'],plan['environment']['allowed_actions'],output_dir/'host-services')
    channel=ExistingWindowsChannel(root,runtime,output_dir/'transport')
    started=datetime.now(timezone.utc);terminal=None;status='unknown';detail='';clean=False
    try:
        if channel.identity()!=runtime['identity']:
            raise ChannelError('MCP target identity differs from selected VM')
        if services is not None:services.start()
        channel.transfer('push-request','push',[{'absolute_path':str(request_path.resolve()),'relative_path':'request.json'}],str(remote_base/'input'),producer_reference=str(request_path))
        execute_arguments=(str(remote_base/'input/request.json'),digest(request_path),remote_output,source_hashes,case['timeout'])
        if case['id']=='GAP-DUMPPACKETS':
            terminal=channel.execute(*execute_arguments,capture_stdout=True)
        else:
            terminal=channel.execute(*execute_arguments)
        if terminal.get('process_exited') is not True:
            raise ChannelError('recovery_required: remote producer has not exited; no pull or replay')
        # Only the stopped driver output is requested, not a scan of guest Logs.
        channel.transfer('pull-originals','pull',[{'absolute_path':remote_output,'relative_path':'originals'}],str((output_dir/'incoming').resolve()),producer_reference='guest-result.json process_exited=true; '+str(output_dir/'transport/execute-response.json'))
        original=output_dir/'incoming/originals'
        guest=json.loads(_read(original/'guest-result.json'))
        relocation=None
        if case['id']=='GAP-DUMPPACKETS':
            try:relocation=dump_relocation_context(root,case,plan,output_dir)
            except (OSError,ValueError,KeyError,TypeError) as error:
                detail+='; relocation context refused: %s: %s'%(type(error).__name__,error)
        rows,clean=_remote_original_evaluation(root,case,plan,request,guest,original,relocation_context=relocation)
        status=rows['verdict']
        if terminal.get('returncode')!=0:status='fail'
        if not clean and status=='pass':status='unknown'
    except (ChannelError,OSError,ValueError,KeyError,AssertionError,TypeError) as error:
        detail='%s: %s' % (type(error).__name__,error)
        if terminal and terminal.get('returncode') not in (None,0):status='fail'
    finally:
        if services is not None:services.stop()
    if services is not None and terminal and terminal.get('process_exited') is True:
        try:
            if driver['production_kind'] in ('process-redirect','payload-three-way'):
                from acceptance_headless_oracles import verify_services
                verify_services(output_dir/'incoming/originals/driver',output_dir/'host-services',request['headless'])
            else:
                from acceptance_policy_oracles import verify_host_services
                verify_host_services(output_dir/'incoming/originals/driver',output_dir/'host-services',checks,request['policy'])
        except (OSError,ValueError,KeyError,TypeError) as exc:
            clean=False;status='fail';detail+='; owned host endpoint original refused: '+str(exc)
    ended=datetime.now(timezone.utc)
    artifacts=[]
    for path in sorted(output_dir.rglob('*')):
        if path.is_symlink():raise ValueError('remote result symlink')
        if path.is_file():artifacts.append({'path':str(path.resolve()),'sha256':sha256(path),'format':'remote-evidence'})
    return {'status':status,'detail':detail,'returncode':None if terminal is None else terminal.get('returncode'),
            'command':None if terminal is None else remote_guest_command(driver,runtime,remote_output,checks,plan.get('candidate',{}).get('offline_fixture') is True,case_id=case['id']),
            'started_at':started.isoformat(),'ended_at':ended.isoformat(),'duration_seconds':(ended-started).total_seconds(),
            'required_checks':checks,'native_target':runtime['identity'],'artifacts':artifacts,
            'cleanup':{'source':'driver','resources':driver['resources'],'recovered':clean,
                       'process_exit':{'exited':bool(terminal and terminal.get('process_exited')),'returncode':None if terminal is None else terminal.get('returncode'),'timed_out':terminal is None},
                       'remote_output':remote_output,'temp_roots':[str(output_dir.resolve())]}}


def _expected_remote_request(root,case,plan):
    """The single frozen expected-request derivation shared by the remote
    first pass, the offline rejudge, and the dump relocation context."""
    driver,checks=validate_case(case,root,plan['environment'])
    runtime=plan['environment']['native_runtime']
    from pathlib import PureWindowsPath, PurePosixPath
    path_type=PureWindowsPath if runtime['identity']['platform']=='windows' else PurePosixPath
    expected_output=str(path_type(runtime['work_root'])/plan['execution_id']/case['id']/'output')
    hashes=dict(plan['native_source_hashes']);hashes.update(plan['source_hashes'][case['id']])
    catalog=json.loads(_read(Path(root)/'docs/acceptance/catalog.json'))
    registered=next(c for suite in catalog['suites'] for c in suite.get('cases',[]) if c['id']==case['id'])
    expected_request=attach_upstream_protection({'schema':'fakenet.native-guest-request.v1','case_id':case['id'],'case':registered,'checks':checks,'source_hashes':hashes,'candidate':plan['candidate'],'target':runtime['identity'],'output_root':expected_output,'execution_id':plan['execution_id'],'actions':['native']},plan['environment'])
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        expected_request['headless']=headless_inputs(plan['environment'],driver,checks)
    if driver['production_kind'].startswith('policy-'):
        expected_request['policy']=policy_inputs(plan['environment'],scenario=driver['production_kind'].split('-',1)[1])
    if driver['production_kind'].startswith('manual-'):
        expected_request['manual']=manual_options(plan['environment'])
    if driver['production_kind']=='linux-runtime':
        expected_request['linux']=plan['environment']['linux']
    identity=(expected_request['candidate'] or {}).get('source_deployment_identity')
    if identity is not None:
        import hashlib as _hl
        payload=json.dumps(dict(hashes),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
        if (identity.get('schema')!='fakenet.source-deployment-identity.v1' or
                identity.get('case_id')!=case['id'] or
                identity.get('source_commit')!=expected_request['candidate']['source_commit'] or
                identity.get('source_hashes_sha256')!=_hl.sha256(payload).hexdigest()):
            raise ValueError('candidate source identity differs from the frozen selection M')
    return driver,checks,expected_request



def _closure_files_valid(closure):
    files=closure.get('files')
    if not isinstance(files,list) or not files:raise ValueError('closure files missing/empty')
    seen=set();folded=set()
    for item in files:
        if not isinstance(item,dict) or set(item)!={'relative_path','size','sha256'}:
            raise ValueError('closure file entry shape invalid')
        rel=item['relative_path'];parts=rel.split('/') if isinstance(rel,str) else ['','..']
        if (not isinstance(rel,str) or not rel or any(part in ('','..','.') for part in parts) or
                '\\' in rel or rel.startswith('/') or (isinstance(item['size'],bool) or
                not isinstance(item['size'],int) or item['size']<0) or
                not isinstance(item['sha256'],str) or len(item['sha256'])!=64 or
                any(c not in '0123456789abcdef' for c in item['sha256'])):
            raise ValueError('closure file entry invalid: %r'%rel)
        if rel in seen or rel.casefold() in folded:raise ValueError('closure duplicate/alias: %s'%rel)
        seen.add(rel);folded.add(rel.casefold())
    if [i['relative_path'] for i in files]!=sorted(i['relative_path'] for i in files):
        raise ValueError('closure files not sorted')
    if hashlib.sha256(json.dumps(files,ensure_ascii=False,sort_keys=True,
            separators=(',',':')).encode('utf-8')).hexdigest()!=closure.get('inventory_sha256'):
        raise ValueError('closure inventory digest differs from its files')


def dump_relocation_context(root,case,plan,output_dir):
    """DC-05: the ONE host-side builder/validator for the dump relocation
    context.  Both run_remote's first pass and judge_remote's independent
    rejudge call this same function; it reads only the frozen plan, the
    executed request, and THIS case's host-side transport journal plus the
    pulled incoming set - never a file planted inside the copy.  Any failure
    raises with a specific reason; the caller then keeps the strict entry."""
    from acceptance_windows import ExistingWindowsChannel,ChannelError
    from pathlib import PureWindowsPath
    output_dir=Path(output_dir);transport=output_dir/'transport'
    runtime=plan['environment']['native_runtime']
    driver,checks,expected_request=_expected_remote_request(root,case,plan)
    request=json.loads(_read(output_dir/'guest-request.json'))
    if request!=expected_request:raise ValueError('relocation: request differs from frozen plan')
    request_digest=sha256(output_dir/'guest-request.json')
    intent=json.loads(_read(transport/'execute-intent.json'))
    response=json.loads(_read(transport/'execute-response.json'))
    if intent.get('operation')!='execute':raise ValueError('relocation: execute intent missing')
    if response.get('exit_code')!=0 or response.get('is_error'):raise ValueError('relocation: outer MCP execute failed')
    from pathlib import PurePosixPath
    entry_type=PureWindowsPath if runtime['identity']['platform']=='windows' else PurePosixPath
    if 'tools/acceptance_guest.py' not in request.get('source_hashes',{}):
        raise ValueError('relocation: guest entry not pinned in request')
    remote_request=str(entry_type(runtime['work_root'])/plan['execution_id']/case['id']/'input'/'request.json')
    expected_command=ExistingWindowsChannel.build_execute_command(
        runtime,remote_request,request_digest,request['output_root'],
        request['source_hashes'],case.get('timeout',30),capture_stdout=True)
    if intent.get('command')!=expected_command:
        raise ValueError('relocation: execute command differs from the pinned construction')
    if intent.get('timeout')!=case.get('timeout',30)+120:
        raise ValueError('relocation: execute intent timeout differs')
    try:payload=json.loads(response['output'])
    except ValueError:raise ValueError('relocation: execute response output is not JSON') from None
    if (payload.get('returncode')!=0 or payload.get('process_exited') is not True or
            payload.get('recovered') is not True):
        raise ValueError('relocation: execute response is not a clean inner pass')
    try:
        closure=ExistingWindowsChannel.parse_source_closure({'guest_stdout':payload.get('guest_stdout')})
    except ChannelError as error:
        raise ValueError('relocation: guest stdout closure invalid: %s'%error) from None
    if (closure.get('request_sha256')!=request_digest or
            closure.get('execution_id')!=request['execution_id'] or
            closure.get('case_id')!=request['case_id'] or
            closure.get('candidate')!=request['candidate'] or
            closure.get('source_hashes')!=request['source_hashes'] or
            closure.get('target')!=request['target'] or
            closure.get('output_root')!=request['output_root'] or
            closure.get('source_verdict')!='pass' or
            closure.get('cleanup_recovered') is not True or
            closure.get('schema')!='fakenet.dump-source-closure.v1'):
        raise ValueError('relocation: closure identity differs from the frozen request')
    _closure_files_valid(closure)
    capture=closure.get('capture')
    if (not isinstance(capture,dict) or set(capture)!={'raw','converted','seal','capture_id'} or
            not isinstance(capture.get('capture_id'),str)):
        raise ValueError('relocation: capture block shape invalid')
    import uuid as _uuid
    try:_uuid.UUID(capture['capture_id'])
    except (ValueError,AttributeError,TypeError):raise ValueError(
        'relocation: capture id is not a valid uuid') from None
    members=[capture['raw'],capture['converted'],capture['seal']]
    if len(set(members))!=3:raise ValueError('relocation: capture members are not distinct')
    for member in members:
        if member not in {f['relative_path'] for f in closure['files']}:
            raise ValueError('relocation: capture member missing from closure inventory')
    if 'guest-result.json' not in {f['relative_path'] for f in closure['files']}:
        raise ValueError('relocation: guest result missing from closure inventory')
    # The capture must be exactly the pair the oracle selects from the pulled
    # copy's enabled directory, with the seal's own capture id confirmed by
    # the same strict loader in non-physical mode on this copy.
    incoming=output_dir/'incoming/originals'
    enabled=incoming/'driver/enabled'
    pcaps=sorted(path.name for path in enabled.glob('*.pcap')) if enabled.is_dir() else []
    raw_name=next((name for name in pcaps if not name.endswith('-converted.pcap')),None)
    converted_name=next((name for name in pcaps if name.endswith('-converted.pcap')),None)
    if raw_name is None or converted_name is None:
        raise ValueError('relocation: pulled enabled capture pair missing')
    expected_capture={'raw':'driver/enabled/'+raw_name,
                      'converted':'driver/enabled/'+converted_name,
                      'seal':'driver/enabled/'+raw_name+'.capture-originals.json'}
    if {k:capture[k] for k in expected_capture}!=expected_capture:
        raise ValueError('relocation: capture selection differs from the pulled enabled pair')
    from fakenet.payload_report import load_capture_originals
    loaded_copy=load_capture_originals(enabled/raw_name,enabled/converted_name,
                                       verify_physical=False)
    if loaded_copy.capture_id!=capture['capture_id']:
        raise ValueError('relocation: capture id differs from the pulled seal')
    ident=json.loads(_read(transport/'identity-response.json'))
    try:identity=json.loads(ident['output'])
    except ValueError:raise ValueError('relocation: identity response output is not JSON') from None
    if ({k:identity.get(k) for k in ('platform','hostname')}!=runtime['identity'] or
            identity.get('vm_uuid')!=runtime['transfer']['expected_vm_identity']['vm_uuid']):
        raise ValueError('relocation: MCP identity differs from the frozen target')
    spec_path=transport/'pull-originals-spec.json'
    spec_bytes=spec_path.read_bytes()
    spec=json.loads(spec_bytes.decode('utf-8'))
    pull_intent=json.loads(_read(transport/'pull-originals-intent.json'))
    pull_exit=json.loads(_read(transport/'pull-originals-exit.json'))
    terminal_record=json.loads(_read(transport/'pull-originals-terminal.json'))
    expected_source=str(entry_type(runtime['work_root'])/plan['execution_id']/case['id']/'output')
    expected_destination=str((output_dir/'incoming').resolve())
    if (spec.get('schema')!='velo.transfer.request.v1' or spec.get('direction')!='pull' or
            spec.get('expected_vm_identity')!=runtime['transfer']['expected_vm_identity'] or
            spec.get('sources')!=[{'absolute_path':expected_source,'relative_path':'originals'}] or
            spec.get('destination_directory')!=expected_destination):
        raise ValueError('relocation: pull spec differs from the frozen batch')
    pinned_transfer_python=runtime.get('transfer',{}).get('python')
    if not isinstance(pinned_transfer_python,str) or not pinned_transfer_python:
        raise ValueError('relocation: pinned transfer interpreter missing from the frozen runtime')
    expected_argv=[pinned_transfer_python,'-I','-B','-m','velo_transfer',
                   '--spec',str(spec_path.resolve())]
    if (pull_intent.get('argv')!=expected_argv or
            pull_intent.get('spec_sha256')!=hashlib.sha256(spec_bytes).hexdigest()):
        raise ValueError('relocation: pull intent differs from the journaled spec')
    if pull_exit.get('returncode')!=0:
        raise ValueError('relocation: pull operation exited nonzero')
    if (not isinstance(terminal_record.get('spec_path'),str) or
            Path(terminal_record['spec_path']).resolve()!=spec_path.resolve()):
        raise ValueError('relocation: pull terminal spec path differs')
    # S61-R01: the SDK writes per-transfer results into its OWN evidence
    # layout spec.parent/.velo-transfer/tasks/<transfer_id>/evidence/<name>.json
    # (host_journal._evidence_path + storage._task_dir + coordinator
    # write_evidence('result-<digest32>')).  Bind the terminal result to that
    # exact owned directory with symlink-free ancestors; foreign roots and
    # parent-dir symlinks refuse.
    result_path=Path(terminal_record['result_path'])
    evidence_dir=transport/'.velo-transfer'/'tasks'/str(spec['transfer_id'])/'evidence'
    if result_path.parent!=evidence_dir:
        raise ValueError('relocation: pull result outside the SDK owned evidence directory')
    probe=result_path
    while True:
        if probe.is_symlink():
            raise ValueError('relocation: pull result ancestor is a symlink: %s'%probe)
        if probe==transport:break
        probe=probe.parent
        if probe==probe.parent:
            raise ValueError('relocation: pull result escapes the journal root')
    if (not result_path.is_file() or sha256(result_path)!=terminal_record.get('sha256')):
        raise ValueError('relocation: pull terminal result record differs')
    # The real channel anchors the SDK result through the transfer stdout
    # summary; the journaled summary must point at the same result file.
    summary_path=transport/'pull-originals-stdout.log'
    try:
        summary=json.loads(summary_path.read_text(encoding='utf-8'))
    except (OSError,ValueError):
        raise ValueError('relocation: pull stdout summary missing/invalid') from None
    if (not isinstance(summary,dict) or
            summary.get('result_path')!=terminal_record.get('result_path')):
        raise ValueError('relocation: pull stdout summary anchor differs')
    result=json.loads(_read(result_path))
    destination_identity=result.get('destination_identity') or {}
    if (result.get('schema')!='velo.transfer.result.v1' or
            result.get('transfer_id')!=spec.get('transfer_id') or result.get('direction')!='pull' or
            result.get('phase')!='COMPLETE' or result.get('outcome')!='complete' or
            result.get('published_ever') is not True or result.get('destination_verified') is not True or
            result.get('cleanup')!={'host':True,'guest':True} or
            result.get('source_vm_identity')!=runtime['transfer']['expected_vm_identity'] or
            destination_identity.get('endpoint')!='host' or
            destination_identity.get('canonical_path')!=expected_destination):
        raise ValueError('relocation: Velo pull result contract missing')
    pulled={}
    seen_pull=set();seen_pull_fold=set()
    # Guest source paths keep the frozen guest semantics (PureWindowsPath for
    # a Windows guest); the RECEIVING destination is a real host path and is
    # derived with the host pathlib (POSIX on Ubuntu, Windows on a Windows
    # host) - exactly how the SDK records it.
    source_root=entry_type(expected_source)
    destination_root=Path(expected_destination)/'originals'
    for item in result.get('files') or []:
        if not isinstance(item,dict) or set(item)!={'relative_path','size','sha256','source','destination'}:
            raise ValueError('relocation: pull file entry shape invalid')
        rel=item.get('relative_path')
        if (not isinstance(rel,str) or not rel.startswith('originals/') or len(rel)<=len('originals/') or
                '\\' in rel or '..' in rel.split('/') or (isinstance(item['size'],bool) or
                not isinstance(item['size'],int) or item['size']<0) or
                not isinstance(item['sha256'],str) or len(item['sha256'])!=64 or
                any(c not in '0123456789abcdef' for c in item['sha256'])):
            raise ValueError('relocation: pull file entry invalid: %r'%rel)
        inner=rel[len('originals/'):]
        if rel in seen_pull:raise ValueError('relocation: pull member duplicated: %s'%rel)
        fold=rel.casefold()
        if fold in seen_pull_fold:raise ValueError('relocation: pull member case alias: %s'%rel)
        seen_pull.add(rel);seen_pull_fold.add(fold)
        if item['source']!=str(source_root.joinpath(*Path(inner).parts)):
            raise ValueError('relocation: pull member source path differs: %s'%rel)
        if item['destination']!=str(destination_root.joinpath(*Path(inner).parts)):
            raise ValueError('relocation: pull member destination path differs: %s'%rel)
        pulled[inner]={'relative_path':inner,'size':item['size'],'sha256':item['sha256']}
    closure_files={f['relative_path']:f for f in closure['files']}
    if pulled!=closure_files:
        raise ValueError('relocation: pulled set differs from the source closure inventory')
    incoming=output_dir/'incoming/originals'
    actual={}
    for path in sorted(incoming.rglob('*')):
        if path.is_symlink():raise ValueError('relocation: incoming set contains a symlink')
        if not path.is_file():continue
        rel=path.relative_to(incoming).as_posix()
        actual[rel]={'relative_path':rel,'size':path.stat().st_size,'sha256':sha256(path)}
    if actual!=closure_files:
        raise ValueError('relocation: incoming set differs from the source closure inventory')
    return closure


def _remote_original_evaluation(root,case,plan,request,guest,original,relocation_context=None):
    import acceptance_oracles
    if (guest.get('schema')!='fakenet.native-guest-result.v1' or guest.get('request')!=request or
        guest.get('case_id')!=case['id'] or guest.get('execution_id')!=plan['execution_id']):
        raise ValueError('guest result/request/execution identity mismatch')
    receipt=guest['receipt'];driver,checks,expected_request=_expected_remote_request(root,case,plan)
    runtime=plan['environment']['native_runtime']
    from pathlib import PureWindowsPath, PurePosixPath
    path_type=PureWindowsPath if runtime['identity']['platform']=='windows' else PurePosixPath
    if request!=expected_request:raise ValueError('remote original request differs from frozen plan')
    expected=remote_guest_command(driver,plan['environment']['native_runtime'],request['output_root'],checks,plan.get('candidate',{}).get('offline_fixture') is True,case_id=case['id'])
    if receipt.get('command')!=expected or receipt.get('native_target')!=request['target'] or receipt.get('required_checks')!=checks:
        raise ValueError('guest command/target/checks mismatch')
    # Verify every original remote artifact using its preserved relative mapping.
    # Raw guest receipt bytes are never rewritten to pretend they were local.
    from pathlib import PureWindowsPath
    base=path_type(request['output_root']);seen=set()
    for artifact in receipt.get('artifacts') or []:
        remote=path_type(artifact['path'])
        relative=remote.relative_to(base)
        if not relative.parts or '..' in relative.parts:raise ValueError('guest artifact escaped output root')
        local=Path(original).joinpath(*relative.parts)
        if relative.as_posix() in seen or not local.is_file() or local.is_symlink() or sha256(local)!=artifact['sha256']:
            raise ValueError('guest original artifact changed/missing/duplicate')
        seen.add(relative.as_posix())
    actual={p.relative_to(original).as_posix() for p in Path(original).rglob('*') if p.is_file() and p.name!='guest-result.json'}
    if not seen or seen!=actual:raise ValueError('guest original artifact set is not exact')
    if not {'stdout.log','stderr.log','request.json','target.json'}.issubset(seen):
        raise ValueError('guest execution originals missing')
    if driver['production_kind']=='linux-runtime':
        import acceptance_linux_runtime_oracles as linux_oracle
        expected_inputs=linux_inputs(plan,case,request['output_root'],root)
        if json.loads(_read(Path(original)/'linux-inputs.json'))!=expected_inputs:
            raise ValueError('remote Linux original request differs')
        rows,clean,detail=linux_oracle.evaluate(root,Path(original)/'driver',case['id'],checks,
            expected_inputs=expected_inputs,allow_fixture=plan['candidate'].get('offline_fixture') is True)
    elif driver['production_kind']=='upstream-result':
        rows,clean=acceptance_oracles.upstream(root,Path(original)/'driver',checks)
    elif driver['production_kind'].startswith('policy-'):
        import acceptance_policy_oracles
        rows,clean=acceptance_policy_oracles.evaluate(
            Path(original)/'driver',driver['production_kind'].split('-',1)[1],
            checks,expected_inputs=plan['environment'].get('policy'))
    elif driver['production_kind'] in ('process-redirect','payload-three-way'):
        import acceptance_headless_oracles
        mode='process' if driver['production_kind']=='process-redirect' else 'payload'
        rows,clean,detail=acceptance_headless_oracles.evaluate(root,Path(original)/'driver',mode,checks,
            allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True,expected_inputs=plan['environment']['headless'],producer_directory=str(path_type(request['output_root'])/'driver'),source_root=runtime['source_root'])
    elif driver['production_kind'].startswith('manual-'):
        import acceptance_manual_oracles
        expected_inputs=manual_remote_inputs(plan,case,request['output_root'])
        if json.loads(_read(Path(original)/'manual-inputs.json'))!=expected_inputs:
            raise ValueError('remote manual inputs differ from frozen options/guest output root')
        rows,clean,detail=acceptance_manual_oracles.evaluate(root,Path(original)/'driver',case['id'],expected_inputs,
            allow_fixture=plan.get('candidate',{}).get('offline_fixture') is True,
            producer_directory=str(path_type(request['output_root'])/'driver'),
            relocated_context=(relocation_context if case['id']=='GAP-DUMPPACKETS' else None))
    else:
        rows,clean=acceptance_oracles.dual_pcap(root,Path(original)/'driver',checks,runtime['identity']['platform'])
    if driver['production_kind'].startswith('policy-') and {'sink_tcp','sink_udp'}&set(checks):
        from acceptance_policy_oracles import verify_host_services
        # During initial execution the host writer can still be active; only
        # closed lifecycle evidence is granted final controller credit.
        service_dir=Path(original).parents[1]/'host-services'
        if (service_dir/'lifecycle.json').exists():
            verify_host_services(Path(original)/'driver',service_dir,checks,plan['environment']['policy'])
    cleanup=receipt.get('cleanup') or {};process=cleanup.get('process_exit') or {}
    clean=(clean and cleanup.get('source')=='driver' and cleanup.get('resources')==driver['resources'] and
           cleanup.get('recovered') is True and process.get('exited') is True and process.get('timed_out') is False and
           process.get('returncode')==receipt.get('returncode'))
    result=_judge_rows(rows,checks)
    if driver['production_kind'] in ('process-redirect','payload-three-way'):result['details']=rows
    if driver['production_kind'].startswith('manual-'):result['details']=detail
    if receipt.get('returncode')!=0 or receipt.get('status')=='fail':result['verdict']='fail'
    return result,clean


def judge_remote(case,receipt,plan,root):
    driver,checks=validate_case(case,root,plan['environment'])
    output=Path(plan['run_dir'])/'results'/case['id'];paths=[]
    for artifact in receipt.get('artifacts') or []:
        path=Path(artifact.get('path',''))
        if (not path.is_absolute() or not path.is_file() or path.is_symlink() or
            not path.resolve().is_relative_to(output.resolve()) or sha256(path)!=artifact.get('sha256')):
            return {'status':'unknown','cleanup_ok':False,'reason':'remote evidence changed/missing/escaped'}
        paths.append(str(path.resolve()))
    actual={str(p.resolve()) for p in output.rglob('*') if p.is_file() and p.resolve()!=(output/'receipt.json').resolve()}
    if not paths or len(paths)!=len(set(paths)) or set(paths)!=actual:
        return {'status':'unknown','cleanup_ok':False,'reason':'remote evidence index not exact'}
    try:
        request=json.loads(_read(output/'guest-request.json'))
        original=output/'incoming/originals'
        guest=json.loads(_read(original/'guest-result.json'))
        relocation=None
        if case['id']=='GAP-DUMPPACKETS':
            try:relocation=dump_relocation_context(root,case,plan,output)
            except (OSError,ValueError,KeyError,TypeError):relocation=None
        evaluation,clean=_remote_original_evaluation(root,case,plan,request,guest,original,relocation_context=relocation)
        if driver['production_kind'].startswith('policy-') and {'sink_tcp','sink_udp'}&set(checks):
            from acceptance_policy_oracles import verify_host_services
            verify_host_services(original/'driver',output/'host-services',checks,plan['environment']['policy'])
        if driver['production_kind'] in ('process-redirect','payload-three-way'):
            from acceptance_headless_oracles import verify_services
            verify_services(original/'driver',output/'host-services',plan['environment']['headless'])
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as error:
        return {'status':'fail' if receipt.get('status')=='fail' else 'unknown','cleanup_ok':False,'reason':'remote original oracle refused: %s' % error}
    if receipt.get('command')!=guest['receipt'].get('command') or receipt.get('native_target')!=request['target']:
        return {'status':'fail','cleanup_ok':False,'reason':'remote receipt command/target mismatch'}
    clean=clean and receipt.get('cleanup',{}).get('recovered') is True
    status=evaluation['verdict']
    if receipt.get('returncode')!=0 or receipt.get('status')=='fail':status='fail'
    process=receipt.get('cleanup',{}).get('process_exit') or {}
    if process.get('returncode')!=receipt.get('returncode') or process.get('exited') is not True or process.get('timed_out') is not False:
        clean=False
    if (not clean or receipt.get('status')!='pass') and status=='pass':status='unknown'
    return {'status':status,'evaluation':evaluation,'cleanup_ok':clean,'reason':'' if clean else 'remote recovery unverified'}



def native_source_pins(root):
    root=Path(root)
    paths=set((root/'fakenet').rglob('*.py'))
    # Windows policy code invokes these non-Python files directly, including
    # the process checker's two dot-sourced libraries. Pin the complete closure.
    if (root/'fakenet/diverters/windows.py').is_file():
        for name in ('Test-ProcessRedirectRoutes.ps1','Test-ReviewedIPv4Routes.ps1',
                     'test/process_redirect_vm/RouteTargetTools.ps1',
                     'test/process_redirect_vm/RouteResultTools.ps1'):
            path=root/name
            if not path.is_file() or path.is_symlink():
                raise ValueError('required Windows runtime source missing: '+name)
            paths.add(path)
    import acceptance_mcp
    for relative in acceptance_mcp.source_paths(root):
        path=root/relative
        if path.is_file():paths.add(path)
    for name in ('acceptance.py','acceptance_native.py','acceptance_runtime.py','acceptance_oracles.py',
                 'acceptance_guest.py','acceptance_windows.py','acceptance_linux.py','acceptance_multihost.py',
                 'acceptance_linux_runtime.py','acceptance_linux_runtime_oracles.py','acceptance_manual.py','acceptance_manual_oracles.py','acceptance_collection.py','acceptance_package.py','acceptance_orchestration.py','acceptance_scheduler.py','acceptance_policy.py','acceptance_policy_oracles.py','acceptance_headless.py','acceptance_headless_oracles.py','acceptance_mcp.py','acceptance_mcp_oracles.py','acceptance_source_identity.py'):
        path=root/'tools'/name
        if path.is_file():paths.add(path)
    paths.update((root/'tools').glob('acceptance*.py'))
    path=root/'docs/acceptance/catalog.json'
    if path.is_file():paths.add(path)
    for path in sorted((root/'test').glob('test_acceptance_*.py')):
        if path.is_file():paths.add(path)
    return {path.relative_to(root).as_posix():sha256(path) for path in sorted(paths)}


def mcp_inputs(plan,case,root):
    import acceptance_mcp
    driver,checks=validate_case(case,root,plan['environment'])
    value,unused=acceptance_mcp.validate_inputs(plan['environment'].get('mcp'),case['id'],checks,
        fixture=plan.get('candidate',{}).get('offline_fixture') is True)
    if plan.get('mode')=='full' and checks!=__import__('acceptance_mcp').CHECKS[case['id']]:raise ValueError('full MCP requires the entire original unit set')
    if 'ACC-019' in checks:
        value.setdefault('references',{})['ACC-008']=__import__('acceptance_mcp_dependencies').acc008_reference(plan)
    candidate=plan['candidate']
    for key in ('source_commit','package_sha256'):
        if candidate.get(key)!=value['identity'][key]:raise ValueError('MCP candidate differs from frozen '+key)
    return value,checks


def run_mcp_controller(root,case,plan,output_dir,python):
    # Original MCP runners are host controllers. They drive the already-bound
    # Windows channel; no copy of a controller is launched inside the VM.
    import acceptance_mcp as m
    from acceptance_runtime import write_json
    from datetime import datetime,timezone
    inputs,checks=mcp_inputs(plan,case,root);output=Path(output_dir).resolve()
    if runtime_block(case,plan['environment']):raise ValueError(runtime_block(case,plan['environment']))
    output.mkdir(parents=True,exist_ok=True)
    request={'schema':'fakenet.mcp-controller-request.v1','case':case['id'],'checks':checks,
             'inputs':inputs,'candidate':plan['candidate'],'execution_id':plan['execution_id'],
             'source_pins':m.source_pins(root),'output_root':str(output/'driver')}
    write_json(output/'request.json',request)
    started=datetime.now(timezone.utc).isoformat();error=None
    try:
        m.run(case['id'],output/'driver',inputs,selected=checks,
              fixture=plan['candidate'].get('offline_fixture') is True,root=root)
        import acceptance_mcp_oracles
        rows,clean,detail=acceptance_mcp_oracles.evaluate(root,output/'driver',case['id'],checks,inputs,
              allow_fixture=plan['candidate'].get('offline_fixture') is True)
        evaluation=_judge_rows(rows,checks);status=evaluation['verdict']
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:
        status='unknown';clean=False;detail={'error_type':type(exc).__name__,'message':str(exc)}
    write_json(output/'controller-result.json',{'status':status,'clean':clean,'details':detail})
    ended=datetime.now(timezone.utc).isoformat()
    artifacts=[{'path':str(p.resolve()),'sha256':sha256(p),'format':'native-evidence'}
               for p in sorted(output.rglob('*')) if p.is_file()]
    return {'status':status,'detail':detail,'started_at':started,'ended_at':ended,
        'required_checks':checks,'artifacts':artifacts,'native_target':inputs['target'],
        'cleanup':{'source':'original-business-and-observation','recovered':clean},
        'command':['original-mcp-controller',case['id'],*checks]}


def judge_mcp_controller(case,receipt,plan,root):
    import acceptance_mcp as m
    import acceptance_mcp_oracles as oracle
    output=Path(plan['run_dir'])/'results'/case['id']
    try:
        inputs,checks=mcp_inputs(plan,case,root)
        if receipt.get('command')!=['original-mcp-controller',case['id'],*checks] or receipt.get('required_checks')!=checks or receipt.get('native_target')!=inputs['target']:raise ValueError('MCP controller receipt identity differs')
        paths=[]
        for item in receipt.get('artifacts',[]):
            path=Path(item['path'])
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(output.resolve()) or sha256(path)!=item['sha256']:raise ValueError('MCP closed original missing/changed/outside root')
            paths.append(str(path.resolve()))
        actual={str(p.resolve()) for p in output.rglob('*') if p.is_file() and p.name!='receipt.json'}
        if not paths or len(paths)!=len(set(paths)) or set(paths)!=actual:raise ValueError('MCP closed original index not exact')
        expected={'schema':'fakenet.mcp-controller-request.v1','case':case['id'],'checks':checks,
            'inputs':inputs,'candidate':plan['candidate'],'execution_id':plan['execution_id'],
            'source_pins':m.source_pins(root),'output_root':str(output.resolve()/'driver')}
        if m.read(output/'request.json')!=expected:raise ValueError('MCP original request differs from frozen plan')
        rows,clean,details=oracle.evaluate(root,output/'driver',case['id'],checks,inputs,
            allow_fixture=plan['candidate'].get('offline_fixture') is True)
        evaluation=_judge_rows(rows,checks);evaluation['details']=rows
        reasons=[reason for row in rows for reason in row.get('reasons',[])]
        return {'status':evaluation['verdict'] if clean else 'fail','cleanup_ok':clean,'evaluation':evaluation,'details':details,'reason':'; '.join(reasons)}
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:
        return {'status':'fail' if receipt.get('status')=='fail' else 'unknown','cleanup_ok':False,'reason':str(exc)}
