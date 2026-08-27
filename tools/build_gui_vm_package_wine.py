#!/usr/bin/env python3
"""Build the formal v35 onedir GUI VM package with the pinned Wine image.

The PowerShell script remains the Windows-native contract.  This entry point
is its deterministic Docker/Wine equivalent for Ubuntu CI and development:
it archives one immutable source commit, compiles both executables from that
staged tree, and refuses to overwrite a versioned output directory or ZIP.
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
import zipfile
import xml.etree.ElementTree as ElementTree


PACKAGE_VERSION = 'v35'
PACKAGE_NAME = 'Windows-GUI配置工具-VM验收-' + PACKAGE_VERSION
STAGE_DIRECTORY = 'stage'
PLAN_VERSION = '2026.08.27-01 v0.2'
PLAN_BLOB = '0bd8aea9a56d97f165b05e5fc6a68b08f06b4d20'
WINDOWS_PYTHON = r'C:\Python311\python.exe'
FIXED_ZIP_TIME = (2000, 1, 1, 0, 0, 0)
PYDIVERT_WHEEL = 'pydivert-2.1.0-py2.py3-none-any.whl'
HTTP_CONFLICT_TESTS = ('test/test_http_listener_stop.py',)
EXPECTED_SKIP_MODULES = frozenset((
    'test_gui_configmodel', 'test_gui_vm_acceptance'))


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


def wine_python(arguments, cwd=None, capture=False, env=None):
    command = ['xvfb-run', '-a', 'wine', WINDOWS_PYTHON]
    command.extend(str(item) for item in arguments)
    if capture:
        return captured(command, cwd=cwd, env=env)
    run(command, cwd=cwd, env=env)
    return ''


def wine_python_logged(arguments, cwd, log_path, env=None):
    """Run archived-source Windows Python and persist its complete output."""
    command = ['xvfb-run', '-a', 'wine', WINDOWS_PYTHON]
    command.extend(str(item) for item in arguments)
    print('+ ' + ' '.join(command), flush=True)
    try:
        completed = subprocess.run(
            command, cwd=str(cwd), env=env, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = completed.stdout or ''
    except OSError as exc:
        output = 'builder could not execute command: %s\n' % exc
        log_path.write_text(output, encoding='utf-8')
        raise RuntimeError('Windows-Python command could not start: %s' % exc)
    log_path.write_text(output, encoding='utf-8')
    if completed.returncode != 0:
        raise RuntimeError(
            'Windows-Python command failed (%d); see %s' %
            (completed.returncode, log_path))
    return completed


def _junit_summary(path):
    """Return counts and stable module identities from a pytest JUnit file."""
    root = ElementTree.parse(path).getroot()
    testcases = list(root.iter('testcase'))
    failures = sum(1 for item in testcases
                   if item.find('failure') is not None)
    errors = sum(1 for item in testcases if item.find('error') is not None)
    skipped = []
    for item in testcases:
        if item.find('skipped') is not None:
            skipped.append('%s::%s' % (
                item.attrib.get('classname', ''), item.attrib.get('name', '')))
    return {
        'tests': len(testcases), 'passed': len(testcases) - failures - errors - len(skipped),
        'failures': failures, 'errors': errors, 'skipped': len(skipped),
        'skip_tests': sorted(skipped),
    }


def run_windows_regression_gate(stage, build_root):
    """Run all archived-source tests before any formal PE is compiled.

    The HTTP listener test group is isolated because it owns local ports.  The
    two JUnit files are retained in the staged package so a successful ZIP
    carries machine-readable proof of both groups and of the exact two
    environment skips permitted by the repository's fixed Wine image.
    """
    validation_dir = stage / 'build-validation'
    validation_dir.mkdir(parents=True, exist_ok=True)
    wheel = stage / 'wheelhouse' / PYDIVERT_WHEEL
    if not wheel.is_file():
        raise RuntimeError('fixed pydivert wheel is missing from archive: %s' % wheel)
    pydivert_root = build_root / 'pydivert21'
    pydivert_root.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(pydivert_root)
    pydivert_windows = wine_path(pydivert_root).replace('\\', '/').lower()
    pydivert_prefix = pydivert_windows.rstrip('/') + '/'
    env = os.environ.copy()
    env['PYTHONPATH'] = pydivert_prefix
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'

    identity_log = validation_dir / 'pydivert-identity.txt'
    identity_code = (
        "import pydivert; p=pydivert.__file__.lower().replace(chr(92), '/'); "
        "print(pydivert.__version__, p); "
        "assert pydivert.__version__ == '2.1.0'; "
        "assert p.startswith(%r)" % pydivert_prefix)
    wine_python_logged(['-c', identity_code], stage, identity_log, env=env)

    main_xml = validation_dir / 'windows-pytest-main.xml'
    main_log = validation_dir / 'windows-pytest-main.txt'
    main_args = ['-m', 'pytest', '-q', '--disable-warnings']
    main_args.extend('--ignore=%s' % path for path in HTTP_CONFLICT_TESTS)
    main_args.extend(['--junitxml', wine_path(main_xml)])
    wine_python_logged(main_args, stage, main_log, env=env)

    http_xml = validation_dir / 'windows-pytest-http.xml'
    http_log = validation_dir / 'windows-pytest-http.txt'
    http_args = ['-m', 'pytest', '-q', '--disable-warnings']
    http_args.extend(HTTP_CONFLICT_TESTS)
    http_args.extend(['--junitxml', wine_path(http_xml)])
    wine_python_logged(http_args, stage, http_log, env=env)

    main = _junit_summary(main_xml)
    http = _junit_summary(http_xml)
    skip_modules = set()
    for identity in main['skip_tests'] + http['skip_tests']:
        lowered = identity.lower()
        for module in EXPECTED_SKIP_MODULES:
            if module in lowered:
                skip_modules.add(module)
    if main['failures'] or main['errors'] or http['failures'] or http['errors']:
        raise RuntimeError('archived Windows-Python regression failed: %s / %s' %
                           (main, http))
    if (main['skipped'] + http['skipped'] != len(EXPECTED_SKIP_MODULES) or
            skip_modules != set(EXPECTED_SKIP_MODULES)):
        raise RuntimeError(
            'archived Windows-Python skip set drifted: %s / %s' %
            (main['skip_tests'], http['skip_tests']))
    if http['tests'] == 0 or main['tests'] == 0:
        raise RuntimeError('archived Windows-Python regression collected no tests')
    return {
        'pythonpath': pydivert_prefix,
        'pydivert_wheel': PYDIVERT_WHEEL,
        'pydivert_wheel_sha256': sha256(wheel),
        'expected_skip_modules': sorted(EXPECTED_SKIP_MODULES),
        'main': main,
        'http_conflict_group': {
            'tests': list(HTTP_CONFLICT_TESTS), 'summary': http,
        },
        'total_tests': main['tests'] + http['tests'],
        'total_passed': main['passed'] + http['passed'],
        'total_skipped': main['skipped'] + http['skipped'],
        'verdict': 'PASS',
    }


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def git_blob_sha1(path):
    payload = Path(path).read_bytes()
    header = ('blob %d\0' % len(payload)).encode('ascii')
    return hashlib.sha1(header + payload).hexdigest()


def remove_pycache(root):
    for directory in list(Path(root).rglob('__pycache__')):
        if directory.is_dir():
            shutil.rmtree(directory)


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
            info = zipfile.ZipInfo(PACKAGE_NAME + '/' + relative,
                                   date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            with open(path, 'rb') as handle:
                archive.writestr(info, handle.read())


def verify_package_zip(destination, manifest, output_path):
    """Independently re-read the ZIP and verify its bound file manifest."""
    prefix = PACKAGE_NAME + '/'
    expected = {prefix + row['path']: row for row in manifest['files']}
    manifest_name = prefix + 'gui-vm-manifest.json'
    with zipfile.ZipFile(destination) as archive:
        files = {item.filename: item for item in archive.infolist()
                 if not item.is_dir()}
        expected_names = set(expected).union((manifest_name,))
        if set(files) != expected_names:
            raise RuntimeError('formal ZIP file set differs from manifest')
        for name, row in expected.items():
            payload = archive.read(name)
            if (len(payload) != int(row['size']) or
                    hashlib.sha256(payload).hexdigest() != row['sha256']):
                raise RuntimeError('formal ZIP hash/size mismatch: %s' % name)
            if files[name].date_time != FIXED_ZIP_TIME:
                raise RuntimeError('formal ZIP timestamp drift: %s' % name)
        embedded = json.loads(archive.read(manifest_name).decode('utf-8'))
        if embedded != manifest:
            raise RuntimeError('embedded formal manifest differs from builder model')
        if files[manifest_name].date_time != FIXED_ZIP_TIME:
            raise RuntimeError('formal ZIP manifest timestamp drifted')
    result = {
        'schema': 'fakenet.gui-vm-package-verification.v1',
        'package_version': PACKAGE_VERSION,
        'source_commit': manifest['source_commit'],
        'plan_version': manifest['plan_version'],
        'plan_blob': manifest['plan_blob'],
        'zip_path': destination.name,
        'zip_sha256': sha256(destination),
        'verified_files': len(expected),
        'entry_timestamp_utc': '2000-01-01T00:00:00Z',
        'manifest_match': True,
        'size_hash_match': True,
        'verdict': 'PASS',
    }
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    return result


def next_output_directory(output_root):
    output_root.mkdir(parents=True, exist_ok=True)
    for number in range(1, 10000):
        candidate = output_root / ('v35-r%d' % number)
        if not candidate.exists():
            return candidate
    raise RuntimeError('no unused v35-rN output directory remains')


def verify_source(stage):
    required = (
        stage / 'fakenet.spec', stage / 'fakenet-gui.spec',
        stage / 'Build-GuiVmPackage.ps1',
        stage / 'test' / 'gui_vm' / 'Run-Tests.cmd',
        stage / 'test' / 'gui_vm' / 'Run-SamplePayloadAcceptance.cmd',
        stage / 'test' / 'gui_vm' / 'verify_payload_report.py',
        stage / 'test' / 'gui_vm' / 'verify_payload_integrity.py',
        stage / 'test' / 'gui_vm' / 'verify_reassembly.py',
        stage / 'test' / 'gui_vm' / 'generate_payload_report_fixture.py',
        stage / 'test' / 'gui_vm' / 'run_sample_payload_acceptance.py',
        stage / 'tools' / 'replay_sample_payload.py',
    )
    for path in required:
        if not path.is_file():
            raise RuntimeError('formal v35 source is missing: %s' % path)
    build_script = (stage / 'Build-GuiVmPackage.ps1').read_text(
        encoding='utf-8-sig')
    if "'v35'" not in build_script or PLAN_VERSION not in build_script:
        raise RuntimeError('PowerShell formal package contract is not v35/v0.2')
    source = (stage / 'fakenet' / 'fakenet.py').read_text(encoding='utf-8')
    if 'Version 3.6' not in source:
        raise RuntimeError('formal source version banner is not 3.6')
    plan = (stage / 'PLAN' / '2026.08.27' /
            '2026.08.27-01-PCAP捕获完整性与双向载荷HTML报告修复方案.md')
    if not plan.is_file() or git_blob_sha1(plan) != PLAN_BLOB:
        raise RuntimeError('formal source does not contain the reviewed plan blob')


def build(repo, source_commit, output_root, output_directory=None):
    resolved = captured(['git', '-C', str(repo), 'rev-parse',
                         source_commit + '^{commit}'])
    output_root = Path(output_root).resolve()
    destination_dir = (Path(output_directory).resolve()
                       if output_directory else next_output_directory(output_root))
    if destination_dir.exists():
        raise RuntimeError('Refusing to overwrite output directory: %s' %
                           destination_dir)
    destination = destination_dir / (PACKAGE_NAME + '.zip')

    with tempfile.TemporaryDirectory(prefix='fakenet-gui-v35-') as tmp:
        build_root = Path(tmp)
        source_zip = build_root / 'source.zip'
        # Wine cannot reliably use a Unix working directory containing the
        # Chinese package display name. Keep the internal compilation stage
        # ASCII-only; PACKAGE_NAME remains the external ZIP/root directory.
        stage = build_root / STAGE_DIRECTORY
        run(['git', '-C', str(repo), 'archive', '--format=zip',
             '--output', str(source_zip), resolved])
        with zipfile.ZipFile(source_zip) as archive:
            archive.extractall(stage)
        shutil.rmtree(stage / 'dist', ignore_errors=True)
        verify_source(stage)
        regression = run_windows_regression_gate(stage, build_root)
        regression_env = os.environ.copy()
        regression_env['PYTHONPATH'] = regression['pythonpath']
        regression_env['PYTHONDONTWRITEBYTECODE'] = '1'
        regression_env['PYTHONIOENCODING'] = 'utf-8'

        stage_windows = wine_path(stage)
        core_work = build_root / 'work-fakenet'
        gui_work = build_root / 'work-gui'
        core_work.mkdir()
        gui_work.mkdir()
        wine_python([
            '-m', 'PyInstaller', 'fakenet.spec', '--distpath', stage_windows,
            '--workpath', wine_path(core_work), '--noconfirm'], cwd=stage,
            env=regression_env)
        wine_python([
            '-m', 'PyInstaller', 'fakenet-gui.spec',
            '--distpath', stage_windows, '--workpath', wine_path(gui_work),
            '--noconfirm'], cwd=stage, env=regression_env)

        fakenet_exe = stage / 'fakenet.exe'
        gui_exe = stage / 'fakenet-GUI.exe'
        for binary in (fakenet_exe, gui_exe):
            if not binary.is_file() or binary.read_bytes()[:2] != b'MZ':
                raise RuntimeError('Windows PE output missing: %s' % binary)
        collect_dir = stage / 'fakenet-dat'
        if not collect_dir.is_dir():
            raise RuntimeError('formal onedir output missing fakenet-dat')
        for item in collect_dir.iterdir():
            destination_item = stage / item.name
            if destination_item.exists():
                raise RuntimeError('onedir payload conflicts with source: %s' %
                                   item.name)
            shutil.move(str(item), str(destination_item))
        shutil.rmtree(collect_dir)
        if not (stage / '_internal').is_dir():
            raise RuntimeError('formal onedir payload missing _internal')

        for source, target in ((stage / 'fakenet' / 'configs', stage / 'configs'),
                               (stage / 'fakenet' / 'defaultFiles', stage / 'defaultFiles'),
                               (stage / 'fakenet' / 'listeners' / 'ssl_utils',
                                stage / 'listeners' / 'ssl_utils')):
            shutil.copytree(source, target)
        remove_pycache(stage)
        for source in (stage / 'test' / 'gui_vm' / 'verify_payload_report.py',
                       stage / 'test' / 'gui_vm' / 'verify_payload_integrity.py',
                       stage / 'test' / 'gui_vm' / 'verify_reassembly.py',
                       stage / 'test' / 'gui_vm' / 'generate_payload_report_fixture.py',
                       stage / 'test' / 'gui_vm' / 'run_sample_payload_acceptance.py',
                       stage / 'tools' / 'replay_sample_payload.py'):
            run(['python3', '-m', 'py_compile', str(source)])
        remove_pycache(stage)

        rows = []
        for path, relative in iter_package_files(stage):
            if relative == 'gui-vm-manifest.json':
                continue
            rows.append({'path': relative, 'size': path.stat().st_size,
                         'sha256': sha256(path)})
        manifest = {
            'schema_version': 1,
            'package_version': PACKAGE_VERSION,
            'package_mode': 'acceptance',
            'plan_version': PLAN_VERSION,
            'plan_blob': PLAN_BLOB,
            'source_commit': resolved,
            'source_snapshot_mode': 'commit',
            'builder': 'docker-wine-windows-python',
            'windows_python_regression': regression,
            'core_bundle_mode': 'pyinstaller-onedir',
            'core_bootloader_debug': False,
            'python_version': wine_python(
                ['-c', 'import platform;print(platform.python_version())'],
                capture=True, env=regression_env),
            'pyinstaller_version': wine_python(
                ['-m', 'PyInstaller', '--version'], capture=True,
                env=regression_env),
            'fakenet_exe_sha256': sha256(fakenet_exe),
            'fakenet_gui_exe_sha256': sha256(gui_exe),
            'acceptance_entry': 'test/gui_vm/Run-Tests.cmd',
            'sample_payload_entry': 'test/gui_vm/Run-SamplePayloadAcceptance.cmd',
            'payload_verifier': 'test/gui_vm/verify_payload_report.py',
            'payload_integrity_verifier': 'test/gui_vm/verify_payload_integrity.py',
            'historical_replay_entry': 'tools/replay_sample_payload.py',
            'payload_report_schema': 'fakenet.payload-report.v1',
            'capture_queue': 'length=8192;time_ms=2048;size_bytes=33554432',
            'logs_plaintext': True,
            'built_at_utc': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'zip_entry_timestamp_utc': '2000-01-01T00:00:00Z',
            'files': rows,
        }
        manifest_payload = json.dumps(
            manifest, ensure_ascii=False, indent=2) + '\n'
        (stage / 'gui-vm-manifest.json').write_text(
            manifest_payload, encoding='utf-8')
        destination_dir.mkdir(parents=True, exist_ok=False)
        write_deterministic_zip(stage, destination)
        (destination_dir / 'gui-vm-manifest.json').write_text(
            manifest_payload, encoding='utf-8')
        verification = verify_package_zip(
            destination, manifest,
            destination_dir / 'package-verification.json')

    print('Package: %s' % destination)
    print('Source commit: %s' % resolved)
    print('ZIP sha256: %s' % sha256(destination))
    print('Verification: %s' % verification['verdict'])
    return destination


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
