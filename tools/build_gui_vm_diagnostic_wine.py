#!/usr/bin/env python3
"""Build the Windows v33 diagnostic package with Windows Python under Wine."""

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


PACKAGE_VERSION = 'v33-diagnostic-03'
PACKAGE_NAME = 'Windows-GUI配置工具-VM诊断-' + PACKAGE_VERSION
PLAN_VERSION = '2026.08.26-01 v0.5'
WINDOWS_PYTHON = r'C:\Python311\python.exe'
FIXED_ZIP_TIME = (2000, 1, 1, 0, 0, 0)
WORKTREE_OVERLAY_PATHS = (
    'Build-GuiVmDiagnosticPackage.cmd',
    'Build-GuiVmDiagnosticPackage.sh',
    'Build-GuiVmPackage.ps1',
    'PLAN/2026.08.26/2026.08.26-01-v33实机问题分阶段修复方案.md',
    'PLAN/FaknetNG.md',
    'fakenet/gui/app.py',
    'test/gui_vm/Export-Logs.ps1',
    'test/gui_vm/README.md',
    'test/gui_vm/capture_windows_console.py',
    'test/gui_vm/run_vm_diagnostics.py',
    'test/gui_vm/stop_trace_runtime_hook.py',
    'test/test_gui_vm_diagnostic_wine_builder.py',
    'test/test_vm_diagnostics.py',
    'tools/build_gui_vm_diagnostic_wine.py',
)


def run(command, cwd=None, capture=False):
    print('+ ' + ' '.join(str(item) for item in command), flush=True)
    return subprocess.run(
        [str(item) for item in command], cwd=str(cwd) if cwd else None,
        check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None)


def captured(command, cwd=None):
    return run(command, cwd=cwd, capture=True).stdout.strip()


def wine_path(path):
    return captured(['winepath', '-w', str(Path(path).resolve())])


def wine_python(arguments, cwd=None, capture=False):
    command = ['xvfb-run', '-a', 'wine', WINDOWS_PYTHON]
    command.extend(str(item) for item in arguments)
    if capture:
        return captured(command, cwd=cwd)
    run(command, cwd=cwd)
    return ''


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


def copy_tree(source, destination):
    shutil.copytree(source, destination, dirs_exist_ok=True)


def overlay_worktree(repo, stage):
    rows = []
    for relative in WORKTREE_OVERLAY_PATHS:
        source = repo / relative
        destination = stage / relative
        if not source.is_file():
            raise RuntimeError('Worktree overlay file missing: %s' % source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        rows.append({
            'path': relative,
            'size': destination.stat().st_size,
            'sha256': sha256(destination),
        })
    return rows


def prepare_diagnostic_core_spec(stage):
    spec_path = stage / 'fakenet.spec'
    source = spec_path.read_text(encoding='utf-8')
    onedir_exe = '          [],\n          exclude_binaries=True,\n'
    onefile_exe = (
        '          a.binaries + driver_files,\n'
        '          a.zipfiles,\n'
        '          a.datas,\n')
    onedir_collect = (
        'coll = COLLECT(exe,\n'
        '               a.binaries + driver_files,\n'
        '               a.zipfiles,\n'
        '               a.datas,\n')
    if onedir_exe not in source or onedir_collect not in source:
        raise RuntimeError('Core spec onedir markers missing')
    source = source.replace(onedir_exe, onefile_exe, 1)
    source = source.replace(onedir_collect, 'coll = COLLECT(exe,\n', 1)
    runtime_old = '             runtime_hooks=[],'
    runtime_new = (
        "             runtime_hooks=['test/gui_vm/"
        "stop_trace_runtime_hook.py'],")
    if runtime_old not in source:
        raise RuntimeError('Core spec runtime_hooks marker missing')
    source = source.replace(runtime_old, runtime_new, 1)
    if '          debug=False,' not in source:
        raise RuntimeError('Core spec debug marker missing')
    source = source.replace('          debug=False,',
                            '          debug=True,', 1)
    spec_path.write_text(source, encoding='utf-8')


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
            info = zipfile.ZipInfo(
                PACKAGE_NAME + '/' + relative, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            with open(path, 'rb') as handle:
                archive.writestr(info, handle.read())


def verify_diagnostic_source(stage):
    core = (stage / 'fakenet' / 'fakenet.py').read_text(encoding='utf-8')
    exporter = (stage / 'test' / 'gui_vm' / 'Export-Logs.ps1').read_text(
        encoding='utf-8-sig')
    required = (
        stage / 'test' / 'gui_vm' / 'Run-Diagnostics.cmd',
        stage / 'test' / 'gui_vm' / 'run_vm_diagnostics.py',
        stage / 'test' / 'gui_vm' / 'capture_windows_console.py',
        stage / 'test' / 'gui_vm' / 'stop_trace_runtime_hook.py',
        stage / 'Start-FNPR-Sentinel.sh',
    )
    for path in required:
        if not path.is_file():
            raise RuntimeError('Diagnostic source missing: %s' % path)
    for marker in ('STOP_PHASE_BEGIN phase=complete',
                   'STOP_PROVIDER_BEGIN name=%s'):
        if marker not in core:
            raise RuntimeError('Core diagnostic marker missing: %s' % marker)
    for marker in ('stop-diagnosis.txt', 'EVIDENCE_PATH='):
        if marker not in exporter:
            raise RuntimeError('Exporter marker missing: %s' % marker)
    runner = (stage / 'test' / 'gui_vm' / 'run_vm_diagnostics.py').read_text(
        encoding='utf-8')
    for marker in ('probe_takeover_path', 'diagnostic-results-',
                   'diagnostic-network-before-',
                   'wait_for_gui_stop_observation', 'StopProcessMonitor',
                   'evaluate_bootloader_console'):
        if marker not in runner:
            raise RuntimeError('Strengthened diagnostic marker missing: %s' %
                               marker)


def build(repo, source_commit, output_root, worktree_overlay=False):
    resolved = captured([
        'git', '-C', str(repo), 'rev-parse', source_commit + '^{commit}'])
    destination = output_root / (PACKAGE_NAME + '.zip')
    if destination.exists():
        raise RuntimeError('Refusing to overwrite: %s' % destination)

    with tempfile.TemporaryDirectory(prefix='fakenet-gui-diagnostic-') as tmp:
        build_root = Path(tmp)
        source_zip = build_root / 'source.zip'
        stage = build_root / PACKAGE_NAME
        run(['git', '-C', str(repo), 'archive', '--format=zip',
             '--output', str(source_zip), resolved])
        with zipfile.ZipFile(source_zip) as archive:
            archive.extractall(stage)
        shutil.rmtree(stage / 'dist', ignore_errors=True)
        overlay_rows = overlay_worktree(repo, stage) if worktree_overlay else []
        verify_diagnostic_source(stage)
        prepare_diagnostic_core_spec(stage)

        stage_windows = wine_path(stage)
        core_work = build_root / 'work-fakenet'
        gui_work = build_root / 'work-gui'
        core_work.mkdir()
        gui_work.mkdir()
        wine_python([
            '-m', 'PyInstaller', 'fakenet.spec', '--distpath', stage_windows,
            '--workpath', wine_path(core_work), '--noconfirm'], cwd=stage)
        wine_python([
            '-m', 'PyInstaller', 'fakenet-gui.spec',
            '--distpath', stage_windows, '--workpath', wine_path(gui_work),
            '--noconfirm'], cwd=stage)

        fakenet_exe = stage / 'fakenet.exe'
        gui_exe = stage / 'fakenet-GUI.exe'
        for binary in (fakenet_exe, gui_exe):
            if not binary.is_file() or binary.read_bytes()[:2] != b'MZ':
                raise RuntimeError('Windows PE output missing: %s' % binary)
        shutil.rmtree(stage / 'fakenet-dat', ignore_errors=True)

        copy_tree(stage / 'fakenet' / 'configs', stage / 'configs')
        copy_tree(stage / 'fakenet' / 'defaultFiles', stage / 'defaultFiles')
        copy_tree(stage / 'fakenet' / 'listeners' / 'ssl_utils',
                  stage / 'listeners' / 'ssl_utils')
        remove_pycache(stage)

        diagnostic_python = (
            stage / 'test' / 'gui_vm' / 'run_vm_diagnostics.py',
            stage / 'test' / 'gui_vm' / 'capture_windows_console.py',
            stage / 'test' / 'gui_vm' / 'stop_trace_runtime_hook.py',
        )
        for source in diagnostic_python:
            run(['python3', '-m', 'py_compile', str(source)])
        remove_pycache(stage)

        python_version = wine_python(
            ['-c', 'import platform;print(platform.python_version())'],
            capture=True)
        pyinstaller_version = wine_python(
            ['-m', 'PyInstaller', '--version'], capture=True)
        rows = []
        for path, relative in iter_package_files(stage):
            if relative == 'gui-vm-manifest.json':
                continue
            rows.append({
                'path': relative,
                'size': path.stat().st_size,
                'sha256': sha256(path),
            })
        manifest = {
            'schema_version': 1,
            'package_version': PACKAGE_VERSION,
            'package_mode': 'diagnostic',
            'plan_version': PLAN_VERSION,
            'source_commit': resolved,
            'source_snapshot_mode': (
                'base-commit-plus-explicit-worktree-overlay'
                if worktree_overlay else 'commit'),
            'source_overlay_files': overlay_rows,
            'python_version': python_version,
            'pyinstaller_version': pyinstaller_version,
            'builder': 'docker-wine-windows-python',
            'core_bundle_mode': 'pyinstaller-onefile-diagnostic-debug',
            'core_bootloader_debug': True,
            'core_runtime_hook': (
                'test/gui_vm/stop_trace_runtime_hook.py'),
            'built_at_utc': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'fakenet_exe_sha256': sha256(fakenet_exe),
            'fakenet_gui_exe_sha256': sha256(gui_exe),
            'acceptance_entry': 'test/gui_vm/Run-Diagnostics.cmd',
            'logs_plaintext': True,
            'files': rows,
        }
        (stage / 'gui-vm-manifest.json').write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')
        output_root.mkdir(parents=True, exist_ok=True)
        write_deterministic_zip(stage, destination)

    print('Package: %s' % destination)
    print('Source commit: %s' % resolved)
    print('ZIP sha256: %s' % sha256(destination))
    return destination


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='/workspace')
    parser.add_argument('--source-commit', default='HEAD')
    parser.add_argument('--output', default='/workspace/dist')
    parser.add_argument('--worktree-overlay', action='store_true')
    args = parser.parse_args()
    build(Path(args.repo).resolve(), args.source_commit,
          Path(args.output).resolve(), args.worktree_overlay)


if __name__ == '__main__':
    main()
