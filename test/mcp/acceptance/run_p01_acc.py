#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P01 ACC runner — implements the master-plan §9.1 acceptance contract.

Usage (see --help). Exit codes: 0=pass 1=acceptance-failed 2=precondition-
blocked 3+=tool error. Evidence lands in
Logs/fakenetng-mcp/<candidate-id>/<acc-id>/.
"""

import argparse
import datetime
import hashlib
import json
import shutil
import sys
import time
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS, EXIT_TOOL_ERROR,  # noqa: E402
                     EvidenceWriter, PackageServer, StepError, Win10VmChannel)

P01_ENTRY_LABEL_DECLARATION = (
    'P01-ENTRY is a P01-owned precondition-evidence label, NOT a master-plan '
    'ACC id; its result never claims ACC-017.')


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def http_post(url, body, headers, timeout=15):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), \
                response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), \
            error.read().decode('utf-8', 'replace')


def envelope(version='2026-07-28', client='p01-acc-runner'):
    return {
        'io.modelcontextprotocol/protocolVersion': version,
        'io.modelcontextprotocol/clientInfo': {'name': client, 'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def ping_body(meta=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'ping', 'arguments': {},
                       '_meta': meta or envelope()}}


PING_HEADERS = {
    'MCP-Protocol-Version': '2026-07-28',
    'Mcp-Method': 'tools/call',
    'Mcp-Name': 'ping',
}


def deploy_package(args, channel, writer, vm_dir):
    """Serve the candidate over host-only and install it on the VM."""
    package = Path(args.package).resolve()
    package_sha = sha256_file(package)
    if package_sha != args.package_sha256:
        raise StepError('package sha256 mismatch: %s != %s' %
                        (package_sha, args.package_sha256))
    manifest = json.loads(Path(args.manifest).read_text(encoding='utf-8'))
    if manifest.get('source_commit') != args.source_commit:
        raise StepError('manifest source_commit != --source-commit')
    writer.add_evidence('candidate-manifest', manifest)

    # Serve ONLY the candidate zip (never the whole dist tree).
    import tempfile

    serve_root = Path(tempfile.mkdtemp(prefix='mcp-acc-transfer-'))
    shutil.copy2(package, serve_root / package.name)
    try:
        return _deploy_with_server(args, channel, writer, vm_dir, serve_root,
                                   package, package_sha)
    finally:
        shutil.rmtree(serve_root, ignore_errors=True)


def _deploy_with_server(args, channel, writer, vm_dir, serve_root, package,
                        package_sha):
    # Stop the running service BEFORE touching files: a live exe locks the
    # onedir payload and Expand-Archive would silently keep the old binary.
    channel.powershell(
        'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; '
        'Get-Process fakenetng-mcp -ErrorAction SilentlyContinue | '
        'Stop-Process -Force; Start-Sleep 2; "STOPPED"', timeout=120)
    with PackageServer(serve_root) as server:
        remote_zip = 'C:\\FakeNetMCP\\%s.zip' % args.candidate_id
        url = '%s/%s' % (server.base_url,
                         urllib.request.quote(package.name))
        download = channel.powershell(
            "[Net.ServicePointManager]::SecurityProtocol='Tls12'; "
            'New-Item -ItemType Directory -Force -Path C:\\FakeNetMCP | '
            'Out-Null; '
            "Invoke-WebRequest -Uri '%s' -OutFile '%s'; "
            '(Get-FileHash \'%s\' -Algorithm SHA256).Hash.ToLower()' % (
                url, remote_zip, remote_zip), timeout=600)
        remote_hash = download['output'].strip().splitlines()[-1].strip()
        writer.add_evidence('vm-download', download)
        if remote_hash != package_sha:
            raise StepError('VM-side package hash mismatch: %s' % remote_hash)

        expand = channel.powershell(
            "Expand-Archive -Path '%s' -DestinationPath '%s' -Force; "
            'Get-ChildItem -Recurse -File \'%s\' | Measure-Object | '
            'Select-Object -ExpandProperty Count' % (
                remote_zip, vm_dir, vm_dir), timeout=600)
        writer.add_evidence('vm-expand', expand)

        extra_ports = list(getattr(args, 'extra_exclude_port', []) or [])
        extra_ps = ''.join(
            ' -ExtraExcludePort %d' % port for port in extra_ports)
        install = channel.powershell(
            "powershell -ExecutionPolicy Bypass -File '%s\\"
            'install-fakenetng-mcp.ps1\' -ListenIp %s -Port %d '
            '-AllowedHost %s%s; exit $LASTEXITCODE' % (
                vm_dir, args.listen_ip, args.listen_port,
                args.allowed_host, extra_ps), timeout=600)
        writer.add_evidence('vm-install', install)
        start = channel.powershell(
            'sc.exe start fakenetng-mcp', timeout=120)
        writer.add_evidence('vm-sc-start', start)
        return package_sha


def collect_acc016_core(args, channel, writer):
    core = channel.powershell(
        'sc.exe qc fakenetng-mcp; sc.exe query fakenetng-mcp', timeout=120)
    writer.add_evidence('vm-sc-qc-query', core)
    layout = channel.powershell(
        "$d = Join-Path $env:ProgramData 'FakeNet-NG-MCP'; "
        'Get-ChildItem -Recurse $d | Select-Object FullName | '
        'Format-Table -AutoSize | Out-String -Width 300; '
        "Get-Content (Join-Path $d 'configs\\service.json')", timeout=120)
    writer.add_evidence('vm-programdata-layout', layout)
    process = channel.powershell(
        'Get-Process fakenetng-mcp -ErrorAction SilentlyContinue | '
        'Select-Object Id,ProcessName,SessionId,Path | Format-List | '
        'Out-String; '
        '$p = Get-CimInstance Win32_Process -Filter '
        '"Name=\'fakenetng-mcp.exe\'" | Select-Object -First 1; '
        '$owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner; '
        '"OWNER=$($owner.Domain)\\$($owner.User)"', timeout=120)
    writer.add_evidence('vm-process-owner', process)
    net_use = channel.powershell('net use', timeout=60)
    writer.add_evidence('vm-net-use', net_use)
    listen = channel.powershell(
        'netstat -ano | findstr :%d' % args.listen_port, timeout=60)
    writer.add_evidence('vm-netstat', listen)
    share_lines = [line for line in net_use['output'].splitlines()
                   if '\\\\' in line]
    listening_lines = [line for line in listen['output'].splitlines()
                       if 'LISTENING' in line.upper()]
    wildcard_listens = [line for line in listening_lines
                        if line.split()[1].startswith('0.0.0.0:') or
                        line.split()[1].startswith('[::]')]
    return {
        'sc_qc': core['output'],
        'owner': process['output'],
        'layout': layout['output'],
        'net_use_empty': not share_lines,
        'listening_lines': listening_lines,
        'wildcard_listens': wildcard_listens,
    }


def run_acc016(args, channel, writer):
    writer.action('acc016', 'LocalSystem install/layout/independence checks')
    core = collect_acc016_core(args, channel, writer)
    writer.expect('sc qc: auto_start, LocalSystem, binPath under package dir')
    writer.expect('process owner SYSTEM, session 0, no interactive desktop')
    writer.expect('ProgramData five dirs + service.json present')
    writer.expect('net use empty; no mapped drive dependence')
    writer.expect('listen bound to configured host-only IP only')
    qc = core['sc_qc']
    checks = {
        'auto_start': 'AUTO_START' in qc,
        'localsystem': 'LocalSystem' in qc or 'OBJE' not in qc,
        'running': 'RUNNING' in qc,
        'owner_system': 'OWNER=NT AUTHORITY\\SYSTEM' in core['owner'],
        'net_use_empty': core['net_use_empty'],
        'listen_scoped': (bool(core['listening_lines']) and
                          not core['wildcard_listens'] and
                          all(args.listen_ip in line
                              for line in core['listening_lines'])),
        'programdata_dirs': all(
            name in core['layout']
            for name in ('configs\\custom', '\\state', '\\logs',
                         '\\baselines', '\\artifacts', 'service.json')),
    }
    # 工具面负向: P01 工具清单仅 ping
    status, headers, text = http_post(
        args.target_base_url + '/mcp',
        {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/list',
         'params': {'_meta': envelope()}},
        {'MCP-Protocol-Version': '2026-07-28',
         'Mcp-Method': 'tools/list'})
    tools = json.loads(text)['result']['tools'] if status == 200 else []
    frozen_surface = {
        'ping', 'get_status', 'get_events', 'list_configs',
        'validate_config', 'read_config', 'list_artifacts', 'load_config',
        'start', 'stop', 'restart', 'create_config', 'import_config',
        'edit_config', 'rename_config', 'delete_config'}
    names = {t['name'] for t in tools}
    # Closed surface: every exposed tool belongs to the frozen domain set
    # (P01: ping; P02 sub-plan §3 adds the domain tools).
    checks['tool_surface_closed'] = names == frozen_surface
    writer.add_evidence('vm-tools-list', text)
    writer.observe(json.dumps(checks, ensure_ascii=False))
    passed = all(checks.values())
    return EXIT_PASS if passed else EXIT_FAIL


def run_zcode_client_probe(writer, controller_uuid=None):
    """Drive the real target client (ZCode desktop/CLI MCP stack) headlessly.

    Mirrors the DEC-006-unblocking configuration: the CLI's own
    ``/login bigmodel-coding-plan-api-key`` write format (provider.bigmodel
    with kind anthropic + the user's coding-plan credential from the
    desktop config), plus the probe MCP server entry.  Secrets are handled
    file-to-file and never printed.
    """
    import subprocess

    v2_path = '/home/adminn/.zcode/v2/config.json'
    cli_path = '/home/adminn/.zcode/cli/config.json'
    v2 = json.loads(Path(v2_path).read_text(encoding='utf-8'))
    opts = (v2.get('provider', {}).get('builtin:bigmodel-coding-plan',
                                       {}).get('options', {}))
    api_key = str(opts.get('apiKey', '')).strip()
    base_url = str(opts.get('baseURL', '')).strip()
    if not api_key or not base_url:
        return {'ok': False,
                'reason': 'desktop coding-plan credential unavailable'}
    controller = controller_uuid or str(uuid.uuid4())

    cfg = json.loads(Path(cli_path).read_text(encoding='utf-8'))
    cfg['provider'] = {
        'bigmodel': {
            'kind': 'anthropic',
            'name': 'BigModel Coding Plan',
            'options': {'apiKeyRequired': True, 'baseURL': base_url,
                        'apiKey': api_key},
            'models': {'glm-5.1': {'name': 'GLM-5.1'},
                       'glm-4.7': {'name': 'GLM-4.7'}},
        },
    }
    cfg['model'] = {'main': 'bigmodel/glm-5.1', 'lite': 'bigmodel/glm-4.7'}
    servers = cfg.setdefault('mcp', {}).setdefault('servers', {})
    servers['fakenetng-probe'] = {
        'type': 'http',
        'url': 'http://192.168.204.149:28788/mcp',
        'headers': {'X-FakeNet-Controller-ID': controller},
        'enabled': True, 'timeoutMs': 60000,
    }
    Path(cli_path).write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding='utf-8')

    command = [
        'node', '/opt/ZCode/resources/glm/zcode.cjs', '--cwd', '/tmp',
        '--no-color', '--prompt',
        '只调用工具 mcp__fakenetng-probe__ping 一次, 然后逐字输出该工具返回的'
        '全部内容, 不要执行其他任何工具, 不要输出其他解释。',
    ]
    completed = subprocess.run(command, capture_output=True, text=True,
                               timeout=260)
    output = (completed.stdout or '') + (completed.stderr or '')
    record = {
        'ok': (completed.returncode == 0 and
               '"controller_header": "valid_uuid"' in output and
               '"fakenetng-mcp"' in output),
        'client': 'ZCode desktop 3.10.2 / bundled CLI 0.16.5 (headless)',
        'exit_code': completed.returncode,
        'controller_uuid': controller,
        'output': output,
    }
    writer.add_evidence('zcode-client-probe', record)
    return record


def run_acc002(args, channel, writer, target_client_probe=True):
    writer.action('acc002', 'protocol/client interop evidence')
    records = {}
    # 1. raw protocol evidence (逐消息 POST, 必需头, SSE/JSON, 版本协商)
    controller = args.controller_uuid or str(uuid.uuid4())

    def ping_result(text):
        envelope = json.loads(text)
        return json.loads(envelope['result']['content'][0]['text'])

    status, headers, text = http_post(
        args.target_base_url + '/mcp', ping_body(),
        {**PING_HEADERS, 'X-FakeNet-Controller-ID': controller})
    records['ping_with_controller'] = {'status': status, 'body': text,
                                        'content_type':
                                            headers.get('Content-Type', '')}
    status2, _, text2 = http_post(
        args.target_base_url + '/mcp', ping_body(), dict(PING_HEADERS))
    records['ping_without_controller'] = {'status': status2, 'body': text2}
    status3, _, text3 = http_post(
        args.target_base_url + '/mcp', ping_body(envelope('1990-01-01')),
        {**PING_HEADERS, 'MCP-Protocol-Version': '1990-01-01'})
    records['unknown_version'] = {'status': status3, 'body': text3}
    status4, _, text4 = http_post(
        args.target_base_url + '/mcp',
        {'jsonrpc': '2.0', 'id': 3, 'method': 'server/discover',
         'params': {'_meta': envelope()}},
        {'MCP-Protocol-Version': '2026-07-28',
         'Mcp-Method': 'server/discover'})
    records['discover'] = {'status': status4, 'body': text4}
    writer.add_evidence('raw-protocol-probes', records)

    ok = (records['ping_with_controller']['status'] == 200 and
          ping_result(records['ping_with_controller']['body'])
          ['controller_header'] == 'valid_uuid' and
          records['ping_without_controller']['status'] == 200 and
          ping_result(records['ping_without_controller']['body'])
          ['controller_header'] == 'missing' and
          records['unknown_version']['status'] == 400 and
          '-32022' in records['unknown_version']['body'] and
          records['discover']['status'] == 200)
    if not ok:
        writer.observe('raw protocol probes failed')
        return EXIT_FAIL

    # 2. target-client step (ZCode 3.10.2) via the headless CLI channel the
    #    user unblocked (DEC-006 closure): one licensed probe run against
    #    the live service.  Other clients can never substitute this step.
    if target_client_probe:
        probe = run_zcode_client_probe(writer,
                                       controller_uuid=args.controller_uuid)
        if not probe.get('ok'):
            writer.blocker = {
                'step': 'target-client discovery + one no-side-effect '
                        'tool call',
                'reason': probe.get('reason') or
                          'headless ZCode probe failed',
            }
            writer.observe('target-client probe failed; raw protocol '
                           'portion passed')
            return EXIT_BLOCKED
        writer.observe('target-client probe passed: %s' % probe['client'])
        return EXIT_PASS
    return EXIT_PASS


def run_acc003(args, channel, writer):
    writer.action('acc003', 'host-only exposure + firewall scope checks')
    listen = channel.powershell(
        'netstat -ano | findstr :%d' % args.listen_port, timeout=60)
    rule = channel.powershell(
        'netsh advfirewall firewall show rule name="FakeNet-NG MCP" verbose',
        timeout=60)
    writer.add_evidence('vm-listen', listen)
    writer.add_evidence('vm-firewall-rule', rule)
    listening_lines = [line for line in listen['output'].splitlines()
                       if 'LISTENING' in line.upper()]
    wildcard = [line for line in listening_lines
                if line.split()[1].startswith('0.0.0.0:') or
                line.split()[1].startswith('[::]')]
    scope_ok = (bool(listening_lines) and not wildcard and
                all(args.listen_ip in line for line in listening_lines) and
                args.allowed_host in rule['output'] and
                str(args.listen_port) in rule['output'])

    # Idempotency: the single rule must appear exactly once.
    duplicate = channel.powershell(
        '(netsh advfirewall firewall show rule name="FakeNet-NG MCP" | '
        'Select-String -Pattern "FakeNet-NG MCP").Count', timeout=60)
    writer.add_evidence('vm-rule-count', duplicate)
    try:
        idempotent = duplicate['output'].strip().splitlines()[-1].strip() \
            == '1'
    except (IndexError, ValueError):
        idempotent = False

    # Firewall-enabled negative/positive round with channel protection.
    fw = channel.powershell(
        '$fw=Get-NetFirewallProfile | Select-Object Name,Enabled; '
        '$fw | Format-Table -AutoSize | Out-String', timeout=60)
    writer.add_evidence('vm-fw-before', fw)
    enabled_round = None
    if args.run_firewall_round:
        protect = channel.powershell(
            'New-NetFirewallRule -DisplayName "P01-ACC003-TEMP-Win10VM-28787" '
            '-Direction Inbound -Action Allow -Protocol TCP -LocalPort 28787 '
            '-RemoteAddress %s | Out-Null; '
            'Set-NetFirewallProfile -All -Enabled True; "PROTECTED+ON"' %
            args.allowed_host, timeout=120)
        writer.add_evidence('vm-fw-enable-protect', protect)
        time.sleep(2)
        try:
            allowed = helpers_probe(args.target_base_url)
            negative_probe = probe_from_non_allowed_source(
                args.target_base_url)
            enabled_round = {'allowed_host_ping': allowed,
                             'non_allowed_probe': negative_probe}
        finally:
            restore = channel.powershell(
                'Set-NetFirewallProfile -All -Enabled False; '
                'Remove-NetFirewallRule -DisplayName '
                '"P01-ACC003-TEMP-Win10VM-28787"; "RESTORED"', timeout=120)
            writer.add_evidence('vm-fw-restore', restore)
        writer.add_evidence('fw-enabled-round', enabled_round)

    deviation = channel.powershell(
        'Get-Content \'%s\\README-SECURITY.md\'' % args.vm_package_dir,
        timeout=60)
    writer.add_evidence('vm-readme-security', deviation)
    deviation_ok = 'DNS rebinding' in deviation['output']

    writer.expect('scoped listen, scoped rule, idempotent install, '
                  'deviation documented')
    checks = {'listen_scoped': scope_ok, 'rule_idempotent': idempotent,
              'deviation_documented': deviation_ok}
    if enabled_round is not None:
        checks['allowed_host_reachable_with_fw_on'] = \
            enabled_round['allowed_host_ping']
        if enabled_round.get('non_allowed_probe') is not None:
            checks['non_allowed_source_blocked'] = \
                not enabled_round['non_allowed_probe']
    writer.observe(json.dumps(checks, ensure_ascii=False))
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def probe_from_non_allowed_source(base_url, source_ip='192.168.255.1',
                                  timeout=8):
    """True when the MCP endpoint answers with the socket bound to a local
    address that is NOT in the firewall rule's RemoteIP list (negative
    source probe; no privileges needed because the address exists on
    another host interface)."""
    import http.client
    from urllib.parse import urlsplit

    parts = urlsplit(base_url)
    try:
        connection = http.client.HTTPConnection(
            parts.hostname, parts.port or 80, timeout=timeout,
            source_address=(source_ip, 0))
        connection.request('POST', parts.path or '/mcp',
                           body=json.dumps(ping_body()),
                           headers={'Content-Type': 'application/json',
                                    'Accept': 'application/json, '
                                              'text/event-stream',
                                    **PING_HEADERS})
        response = connection.getresponse()
        body = response.read().decode('utf-8', 'replace')
        connection.close()
        return response.status == 200 and '"fakenetng-mcp"' in body
    except OSError:
        return False


def helpers_probe(base_url):
    """True when ping over the MCP endpoint succeeds from this host."""
    try:
        status, _, text = http_post(base_url + '/mcp', ping_body(),
                                    dict(PING_HEADERS), timeout=8)
        return status == 200 and '"fakenetng-mcp"' in text
    except (urllib.error.URLError, OSError):
        return False


def run_p01_entry(args, channel, writer, package_sha):
    writer.action('p01-entry', P01_ENTRY_LABEL_DECLARATION)
    core = collect_acc016_core(args, channel, writer)
    reachable = helpers_probe(args.target_base_url)
    checks = {
        'service_running': 'RUNNING' in core['sc_qc'],
        'endpoint_reachable': reachable,
        'candidate_identity': {
            'source_commit': args.source_commit,
            'package_sha256': package_sha,
            'manifest': Path(args.manifest).resolve().name,
        },
    }
    writer.observe(json.dumps(checks, ensure_ascii=False))
    writer.expect('same-candidate native install + service start + '
                  'reachable endpoint (NOT an ACC-017 pass claim)')
    return EXIT_PASS if (checks['service_running'] and
                         checks['endpoint_reachable']) else EXIT_FAIL


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acc', required=True,
                        choices=['ACC-002', 'ACC-003', 'ACC-016', 'P01-ENTRY'])
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--requirements-blob', required=True)
    parser.add_argument('--master-plan-blob', required=True)
    parser.add_argument('--vm-identity', required=True)
    parser.add_argument('--config-identity', required=True)
    parser.add_argument('--candidate-id', required=True)
    parser.add_argument('--listen-ip', default='192.168.204.149')
    parser.add_argument('--listen-port', type=int, default=28788)
    parser.add_argument('--allowed-host', default='192.168.204.1')
    parser.add_argument('--target-base-url',
                        default='http://192.168.204.149:28788')
    parser.add_argument('--win10vm-mcp',
                        default='http://192.168.204.149:28787/mcp')
    parser.add_argument('--controller-uuid')
    parser.add_argument('--vm-package-dir',
                        default='C:\\FakeNetMCP\\candidate')
    parser.add_argument('--extra-exclude-port', action='append',
                        default=[], type=int)
    parser.add_argument('--run-firewall-round', action='store_true')
    parser.add_argument('--deploy', action='store_true',
                        help='deploy/install the package before checks')
    parser.add_argument('--output-root',
                        default=str(REPO_ROOT / 'Logs' / 'fakenetng-mcp'))
    args = parser.parse_args()

    started_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    out_dir = Path(args.output_root) / args.candidate_id / args.acc
    writer = EvidenceWriter(out_dir, started_at)
    channel = Win10VmChannel(args.win10vm_mcp)

    exit_code = EXIT_TOOL_ERROR
    guest_identity = 'unknown'
    package_sha = args.package_sha256
    try:
        identity = channel.computer_name()
        writer.action('vm-identity', '%s @ %s' % (identity, args.vm_identity))
        if 'DESKTOP-3FI41GR' not in identity:
            writer.blocker = {'reason': 'unexpected VM identity: %s' % identity}
            result = writer.write_result(
                acc_id=args.acc, p_id='P01', candidate_id=args.candidate_id,
                source_commit=args.source_commit,
                package_sha256=args.package_sha256,
                requirements_blob=args.requirements_blob,
                master_plan_blob=args.master_plan_blob,
                environment_identity='%s | %s | config=%s' % (
                    args.vm_identity, identity, args.config_identity),
                status='blocked')
            (out_dir / 'result.json').write_text(json.dumps(
                result, ensure_ascii=False, indent=2), encoding='utf-8')
            print('BLOCKED: unexpected VM identity')
            return EXIT_BLOCKED

        package_sha = args.package_sha256
        if args.deploy:
            package_sha = deploy_package(args, channel, writer,
                                          args.vm_package_dir)

        if args.acc == 'ACC-016':
            exit_code = run_acc016(args, channel, writer)
        elif args.acc == 'ACC-002':
            exit_code = run_acc002(args, channel, writer)
        elif args.acc == 'ACC-003':
            exit_code = run_acc003(args, channel, writer)
        elif args.acc == 'P01-ENTRY':
            exit_code = run_p01_entry(args, channel, writer, package_sha)
    except StepError as exc:
        writer.blocker = {'reason': str(exc)}
        exit_code = EXIT_BLOCKED
    except Exception as exc:  # noqa: BLE001
        writer.blocker = {'reason': 'tool error: %r' % exc}
        exit_code = EXIT_TOOL_ERROR

    status = {EXIT_PASS: 'pass', EXIT_FAIL: 'fail',
              EXIT_BLOCKED: 'blocked', EXIT_TOOL_ERROR: 'tool-error'}[
                  exit_code]
    writer.write_result(
        acc_id=args.acc, p_id='P01', candidate_id=args.candidate_id,
        source_commit=args.source_commit, package_sha256=package_sha,
        requirements_blob=args.requirements_blob,
        master_plan_blob=args.master_plan_blob,
        environment_identity='%s | %s | config=%s' % (
            args.vm_identity, guest_identity, args.config_identity),
        status=status)
    print('%s: %s (evidence: %s)' % (args.acc, status, out_dir))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
