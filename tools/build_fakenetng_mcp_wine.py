#!/usr/bin/env python3
"""Build the fakenetng-mcp Windows service candidate with the pinned Wine image.

Deterministic Docker/Wine counterpart of the P01 packaging contract
(PLAN/2026.09/2026.09.02-06 实施子方案 P01 IMP-P01-06):

1. archive one immutable source commit;
2. offline-install the MCP SDK wheel set from ``wheelhouse/`` into the
   image's Windows Python (``pip --no-index`` — a P01-verified step, not a
   v35 precedent);
3. run the ``test/mcp`` Windows-Python pytest gate;
4. freeze ``fakenetng-mcp.exe`` with PyInstaller (fakenet-mcp.spec);
5. smoke the *frozen* exe inside Wine against the 2026-07-28 contract;
6. assemble the candidate package (exe + configs + install scripts +
   manifest with candidate identity and the security-deviation note) into a
   deterministic ZIP under the requested output root.

It never touches the formal v35 GUI packaging contract.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
import xml.etree.ElementTree as ElementTree

PACKAGE_VERSION = 'p01-v1'
STAGE_DIRECTORY = 'stage'
PLAN_DOC = 'PLAN/2026.09/2026.09.02/2026.09.02-06-实施子方案-P01-可部署的MCP服务入口.md'
WINDOWS_PYTHON = r'C:\Python311\python.exe'
XVFB_SERVER_ARGS = '-screen 0 1920x1080x24'
FIXED_ZIP_TIME = (2000, 1, 1, 0, 0, 0)
MCP_SDK_PIN = 'mcp==2.1.1'
EXPECTED_SKIP_MODULES = frozenset(('test_singleinstance',
                                    'test_configstore_links'))
SMOKE_PORT = 39887
SMOKE_CONTROLLER = '11111111-2222-4333-8444-555555555555'
TARGET_CLIENT_IDENTITY = {
    'kind': 'ZCode desktop/CLI MCP client',
    'version': '3.10.2 (desktop), 0.16.5 (bundled CLI)',
    'config_capability': 'mcp.servers.<name> {type:http, url, headers}',
    'decisions': ['DEC-001', 'DEC-004', 'DEC-006'],
}
SECURITY_DEVIATION = (
    'Deployment accepts plaintext HTTP without TLS, bearer token, OAuth or '
    'Origin validation. This is a user-adjudicated deviation from the MCP '
    '2026-07-28 Streamable HTTP security requirements (requirement records '
    '009/010, CON-003, NON-004). It is valid only on a single-host, '
    'isolated, trusted host-only network with the firewall rule scoped to '
    'the configured host source IP. Residual risk: DNS rebinding. Do not '
    'claim full transport-security compliance.'
)


def run(command, cwd=None, capture=False, env=None):
    print('+ ' + ' '.join(str(item) for item in command), flush=True)
    return subprocess.run(
        [str(item) for item in command], cwd=str(cwd) if cwd else None,
        env=env,
        check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None)


def captured(command, cwd=None, env=None):
    return run(command, cwd=cwd, capture=True, env=env).stdout.strip()


def wine_path(path):
    return captured(['winepath', '-w', str(Path(path).resolve())])


def wine_command(arguments):
    command = ['xvfb-run', '-a', '-s', XVFB_SERVER_ARGS,
               'wine', WINDOWS_PYTHON]
    command.extend(str(item) for item in arguments)
    return command


def wine_python(arguments, cwd=None, env=None):
    run(wine_command(arguments), cwd=cwd, env=env)


def wine_python_logged(arguments, cwd, log_path, env=None):
    command = wine_command(arguments)
    print('+ ' + ' '.join(command), flush=True)
    completed = subprocess.run(
        command, cwd=str(cwd), env=env, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = completed.stdout or ''
    log_path.write_text(output, encoding='utf-8')
    if completed.returncode != 0:
        tail = '\n'.join(output.splitlines()[-30:])
        raise RuntimeError(
            'Windows-Python command failed (%d); log tail:\n%s' %
            (completed.returncode, tail))
    return completed


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def remove_pycache(root):
    for directory in list(Path(root).rglob('__pycache__')):
        if directory.is_dir():
            shutil.rmtree(directory)


def verify_source(stage):
    required = (
        stage / 'fakenet-mcp.spec',
        stage / 'tools' / 'build_fakenetng_mcp_wine.py',
        stage / 'Build-FakeNetNgMcpPackage.sh',
        stage / 'wheelhouse' / 'mcp-2.1.1-py3-none-any.whl',
        stage / 'fakenet' / 'mcp' / '__main__.py',
        stage / 'fakenet' / 'mcp' / 'server.py',
        stage / 'fakenet' / 'mcp' / 'transportguard.py',
        stage / 'test' / 'mcp' / 'test_sdk_probe.py',
    )
    for path in required:
        if not path.is_file():
            raise RuntimeError('MCP candidate source missing: %s' % path)


def offline_install_sdk(stage, build_root):
    """P01-new step: offline pip install of the SDK wheel set in Wine."""
    log = build_root / 'sdk-install.txt'
    find_links = wine_path(stage / 'wheelhouse')
    wine_python_logged(
        ['-m', 'pip', 'install', '--disable-pip-version-check',
         '--no-cache-dir', '--no-index',
         '--find-links', find_links, MCP_SDK_PIN],
        stage, log)
    freeze = build_root / 'sdk-freeze.txt'
    wine_python_logged(['-m', 'pip', 'freeze'], stage, freeze)
    versions = {}
    for line in freeze.read_text(encoding='utf-8').splitlines():
        if '==' in line:
            name, _, version = line.partition('==')
            versions[name.strip().lower().replace('_', '-')] = version.strip()
    for required_pin in ('mcp', 'pydantic', 'starlette', 'uvicorn', 'anyio'):
        if required_pin not in versions:
            raise RuntimeError('SDK freeze missing %s' % required_pin)
    return versions


def run_windows_test_gate(stage, build_root):
    validation = build_root / 'build-validation'
    validation.mkdir(parents=True, exist_ok=True)
    xml_path = validation / 'windows-pytest-mcp.xml'
    log_path = validation / 'windows-pytest-mcp.txt'
    args = ['-m', 'pytest', '-q', '--disable-warnings', 'test/mcp',
            '--junitxml', wine_path(xml_path)]
    wine_python_logged(args, stage, log_path)

    root = ElementTree.parse(xml_path).getroot()
    testcases = list(root.iter('testcase'))
    failures = sum(1 for item in testcases if item.find('failure') is not None)
    errors = sum(1 for item in testcases if item.find('error') is not None)
    skipped = []
    for item in testcases:
        if item.find('skipped') is not None:
            skipped.append('%s::%s' % (
                item.attrib.get('classname', ''), item.attrib.get('name', '')))
    skip_modules = set()
    for identity in skipped:
        lowered = identity.lower()
        for module in EXPECTED_SKIP_MODULES:
            if module in lowered:
                skip_modules.add(module)
    if failures or errors:
        raise RuntimeError('Windows-Python MCP gate failed: failures=%d '
                           'errors=%d skipped=%s' %
                           (failures, errors, skipped))
    if skip_modules != set(EXPECTED_SKIP_MODULES):
        raise RuntimeError('Windows-Python skip set drifted: %s' % skipped)
    return {
        'tests': len(testcases),
        'failures': failures,
        'errors': errors,
        'skipped': skipped,
        'expected_skip_modules': sorted(EXPECTED_SKIP_MODULES),
        'verdict': 'PASS',
    }


def smoke_frozen_exe(onedir, build_root):
    """Start the frozen exe (debug mode) in Wine and probe the contract."""
    exe = onedir / 'fakenetng-mcp.exe'
    if not exe.is_file() or exe.read_bytes()[:2] != b'MZ':
        raise RuntimeError('frozen exe missing: %s' % exe)
    programdata = build_root / 'smoke-programdata'
    config_dir = programdata / 'FakeNet-NG-MCP' / 'configs'
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / 'service.json').write_text(json.dumps({
        'listen_ip': '127.0.0.1',
        'listen_port': SMOKE_PORT,
        'allowed_host_ips': ['127.0.0.1'],
        'log_level': 'INFO',
    }), encoding='utf-8')

    env = os.environ.copy()
    env['FAKENETNG_MCP_PROGRAMDATA'] = wine_path(programdata)
    env['PYTHONIOENCODING'] = 'utf-8'
    log_path = build_root / 'smoke-exe.txt'
    output_chunks = []

    process = subprocess.Popen(
        ['xvfb-run', '-a', '-s', XVFB_SERVER_ARGS, 'wine',
         wine_path(exe), 'debug'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, env=env, text=True)

    def _drain():
        for line in process.stdout:
            output_chunks.append(line)

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()

    def _flush_log():
        log_path.write_text(''.join(output_chunks), encoding='utf-8')

    try:
        base = 'http://127.0.0.1:%d/mcp' % SMOKE_PORT
        envelope = {
            'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientInfo': {'name': 'builder',
                                                   'version': '0'},
            'io.modelcontextprotocol/clientCapabilities': {},
        }
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                'params': {'name': 'ping', 'arguments': {},
                           '_meta': envelope}}
        full_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2026-07-28',
            'Mcp-Method': 'tools/call',
            'Mcp-Name': 'ping',
            'X-FakeNet-Controller-ID': SMOKE_CONTROLLER,
        }

        def post(payload, headers, timeout=10):
            request = urllib.request.Request(
                base, data=json.dumps(payload).encode('utf-8'),
                method='POST', headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as r:
                    return r.status, r.read().decode('utf-8', 'replace')
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode('utf-8', 'replace')

        def wait_ready(deadline_s=90.0):
            deadline = time.time() + deadline_s
            probe = {'jsonrpc': '2.0', 'id': 0, 'method': 'server/discover',
                     'params': {'_meta': envelope}}
            headers = dict(full_headers)
            headers.pop('Mcp-Name')
            headers['Mcp-Method'] = 'server/discover'
            while time.time() < deadline:
                try:
                    status, text = post(probe, headers, timeout=3)
                    if status == 200:
                        return text
                except (urllib.error.URLError, OSError):
                    pass
                time.sleep(1.0)
            _flush_log()
            log_tail = '\n'.join(''.join(output_chunks).splitlines()[-40:])
            raise RuntimeError('frozen exe smoke: service never became '
                               'ready; exe log tail:\n%s' % log_tail)

        def parse_tool_result(text):
            envelope = json.loads(text)
            return json.loads(envelope['result']['content'][0]['text'])

        discover_text = wait_ready()
        if '2026-07-28' not in discover_text:
            raise RuntimeError('frozen exe smoke: discover missing version')
        status, text = post(body, full_headers)
        if status != 200:
            raise RuntimeError(
                'frozen exe smoke: ping failed (%d): %s' % (status, text[:300]))
        if parse_tool_result(text)['controller_header'] != 'valid_uuid':
            raise RuntimeError('frozen exe smoke: controller header not '
                               'delivered: %s' % text[:300])
        bare = {k: v for k, v in full_headers.items()
                if k != 'X-FakeNet-Controller-ID'}
        status, text = post(body, bare)
        if status != 200 or \
                parse_tool_result(text)['controller_header'] != 'missing':
            raise RuntimeError('frozen exe smoke: headerless ping unexpected: '
                               '(%d) %s' % (status, text[:200]))
        no_version = {k: v for k, v in bare.items()
                      if k != 'MCP-Protocol-Version'}
        status, text = post(body, no_version)
        if status != 400 or '-32020' not in text:
            raise RuntimeError('frozen exe smoke: missing-version rejection '
                               'unexpected: (%d) %s' % (status, text[:200]))
        return {'verdict': 'PASS', 'port': SMOKE_PORT,
                'log': log_path.name}
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)
        reader.join(timeout=10)
        _flush_log()


def iter_package_files(stage):
    for path in sorted(Path(stage).rglob('*'), key=lambda item: str(item)):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if '/Logs/' in '/' + relative + '/' or relative.startswith('Logs/'):
            continue
        yield path, relative


def write_deterministic_zip(stage, destination):
    if destination.exists():
        raise RuntimeError('Refusing to overwrite: %s' % destination)
    with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for path, relative in iter_package_files(stage):
            info = zipfile.ZipInfo(relative,
                                   date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            with open(path, 'rb') as handle:
                archive.writestr(info, handle.read())


def verify_package_zip(destination, manifest):
    with zipfile.ZipFile(destination) as archive:
        files = {item.filename for item in archive.infolist()
                 if not item.is_dir()}
        expected = {row['path'] for row in manifest['files']}
        expected.add('mcp-candidate-manifest.json')
        if files != expected:
            raise RuntimeError('candidate ZIP file set differs from manifest')
        for row in manifest['files']:
            payload = archive.read(row['path'])
            if (len(payload) != int(row['size']) or
                    hashlib.sha256(payload).hexdigest() != row['sha256']):
                raise RuntimeError('candidate hash/size mismatch: %s'
                                   % row['path'])
            if archive.getinfo(row['path']).date_time != FIXED_ZIP_TIME:
                raise RuntimeError('candidate timestamp drift: %s'
                                   % row['path'])
        embedded = json.loads(
            archive.read('mcp-candidate-manifest.json').decode('utf-8'))
        if embedded != manifest:
            raise RuntimeError('embedded candidate manifest differs')
    return {
        'schema': 'fakenet.mcp-candidate-verification.v1',
        'zip_path': destination.name,
        'zip_sha256': sha256(destination),
        'verified_files': len(manifest['files']),
        'manifest_match': True,
        'size_hash_match': True,
        'verdict': 'PASS',
    }


INSTALL_PS1 = """# fakenetng-mcp installer (P01)
param(
    [Parameter(Mandatory=$true)][string]$ListenIp,
    [int]$Port = 28788,
    [Parameter(Mandatory=$true)][string]$AllowedHost
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'install-fakenetng-mcp must run elevated (Administrator)'
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $root 'fakenetng-mcp.exe') install --listen-ip $ListenIp --port $Port --allowed-host $AllowedHost
if ($LASTEXITCODE -ne 0) { throw "fakenetng-mcp install failed: $LASTEXITCODE" }
Write-Host 'fakenetng-mcp installed. Start it with: sc start fakenetng-mcp (or fakenetng-mcp.exe start)'
"""

UNINSTALL_PS1 = """# fakenetng-mcp uninstaller (P01)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'uninstall-fakenetng-mcp must run elevated (Administrator)'
}
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $root 'fakenetng-mcp.exe') uninstall
if ($LASTEXITCODE -ne 0) { throw "fakenetng-mcp uninstall failed: $LASTEXITCODE" }
Write-Host 'fakenetng-mcp uninstalled.'
"""

README_SECURITY = """# fakenetng-mcp candidate — security deviation note

%s

Endpoint: /mcp (single MCP endpoint, POST only, MCP protocol 2026-07-28,
modern era only). Service name: fakenetng-mcp (LocalSystem, auto start).
""" % SECURITY_DEVIATION


def build(repo, source_commit, output_root, output_directory=None):
    resolved = captured(['git', '-C', str(repo), 'rev-parse',
                         source_commit + '^{commit}'])
    output_root = Path(output_root).resolve()
    destination_dir = (Path(output_directory).resolve()
                       if output_directory else next_output_directory(output_root))
    if destination_dir.exists():
        raise RuntimeError('Refusing to overwrite output directory: %s' %
                           destination_dir)
    destination = destination_dir / 'fakenetng-mcp-candidate.zip'

    with tempfile.TemporaryDirectory(prefix='fakenetng-mcp-') as tmp:
        build_root = Path(tmp)
        source_zip = build_root / 'source.zip'
        stage = build_root / STAGE_DIRECTORY
        run(['git', '-C', str(repo), 'archive', '--format=zip',
             '--output', str(source_zip), resolved])
        with zipfile.ZipFile(source_zip) as archive:
            archive.extractall(stage)
        shutil.rmtree(stage / 'dist', ignore_errors=True)
        verify_source(stage)

        sdk_versions = offline_install_sdk(stage, build_root)
        env = os.environ.copy()
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        env['PYTHONIOENCODING'] = 'utf-8'

        test_gate = run_windows_test_gate(stage, build_root)

        stage_windows = wine_path(stage)
        work = build_root / 'work-mcp'
        work.mkdir()
        wine_python(['-m', 'PyInstaller', 'fakenet-mcp.spec',
                     '--distpath', stage_windows,
                     '--workpath', wine_path(work), '--noconfirm'],
                    cwd=stage, env=env)
        onedir = stage / 'fakenetng-mcp-dist'
        if not onedir.is_dir():
            raise RuntimeError('PyInstaller onedir output missing')
        smoke = smoke_frozen_exe(onedir, build_root)

        package = stage / 'candidate-package'
        package.mkdir()
        shutil.copytree(onedir, package, dirs_exist_ok=True)
        shutil.copytree(stage / 'fakenet' / 'configs', package / 'configs')
        (package / 'install-fakenetng-mcp.ps1').write_text(
            INSTALL_PS1, encoding='utf-8-sig')
        (package / 'uninstall-fakenetng-mcp.ps1').write_text(
            UNINSTALL_PS1, encoding='utf-8-sig')
        (package / 'README-SECURITY.md').write_text(
            README_SECURITY, encoding='utf-8')
        shutil.copytree(build_root / 'build-validation',
                        package / 'build-validation')
        remove_pycache(package)

        rows = []
        for path, relative in iter_package_files(package):
            rows.append({'path': relative, 'size': path.stat().st_size,
                         'sha256': sha256(path)})
        exe_rel = 'fakenetng-mcp.exe'
        manifest = {
            'schema': 'fakenet.mcp-candidate-manifest.v1',
            'package_version': PACKAGE_VERSION,
            'source_commit': resolved,
            'source_snapshot_mode': 'commit',
            'plan_doc': PLAN_DOC,
            'builder': 'docker-wine-windows-python',
            'python_version': captured(wine_command(
                ['-c', 'import platform;print(platform.python_version())'])),
            'pyinstaller_version': captured(wine_command(
                ['-m', 'PyInstaller', '--version'])),
            'mcp_sdk': MCP_SDK_PIN,
            'mcp_sdk_versions': sdk_versions,
            'windows_test_gate': test_gate,
            'frozen_smoke': smoke,
            'target_client_identity': TARGET_CLIENT_IDENTITY,
            'protocol': 'MCP 2026-07-28 Streamable HTTP, modern era only',
            'endpoint_path': '/mcp',
            'default_port': 28788,
            'service_name': 'fakenetng-mcp',
            'security_deviation': SECURITY_DEVIATION,
            'exe_sha256': sha256(package / exe_rel),
            'built_at_utc': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'zip_entry_timestamp_utc': '2000-01-01T00:00:00Z',
            'files': rows,
        }
        manifest_payload = json.dumps(
            manifest, ensure_ascii=False, indent=2) + '\n'
        (package / 'mcp-candidate-manifest.json').write_text(
            manifest_payload, encoding='utf-8')

        destination_dir.mkdir(parents=True, exist_ok=False)
        write_deterministic_zip(package, destination)
        (destination_dir / 'mcp-candidate-manifest.json').write_text(
            manifest_payload, encoding='utf-8')
        verification = verify_package_zip(destination, manifest)
        (destination_dir / 'candidate-verification.json').write_text(
            json.dumps(verification, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')

        zip_sha = verification['zip_sha256']
        candidate_id = 'mcp-c%s-%s' % (resolved[:8], zip_sha[:12])
        (destination_dir / 'candidate-id.txt').write_text(
            candidate_id + '\n', encoding='utf-8')

    print('Candidate: %s' % destination)
    print('Candidate id: %s' % candidate_id)
    print('Source commit: %s' % resolved)
    print('ZIP sha256: %s' % zip_sha)
    print('Verification: %s' % verification['verdict'])
    return destination


def next_output_directory(output_root):
    output_root.mkdir(parents=True, exist_ok=True)
    for number in range(1, 10000):
        candidate = output_root / ('mcp-r%d' % number)
        if not candidate.exists():
            return candidate
    raise RuntimeError('no unused mcp-rN output directory remains')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='/workspace')
    parser.add_argument('--source-commit', default='HEAD')
    parser.add_argument('--output', default='/workspace/dist')
    parser.add_argument('--output-directory')
    args = parser.parse_args()
    build(Path(args.repo).resolve(), args.source_commit,
          Path(args.output).resolve(), args.output_directory)


if __name__ == '__main__':
    main()
