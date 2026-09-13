#!/usr/bin/env python3
"""ACC-002: attest source/package, then run no-network packaged child probes."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_files(root, rows):
    seen = set()
    for row in rows:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(root) or path in seen or not path.is_file():
            raise ValueError('missing/duplicate/escaping identity member')
        seen.add(path)
        if path.stat().st_size != row['size'] or sha(path) != row['sha256']:
            raise ValueError('identity member bytes differ: ' + str(path))
    return seen


def negative_event_probe(package, mode):
    """Exercise the production event gate with only an owned benign child."""
    import msvcrt
    from fakenet.mcp.exit_capability import NativeCapabilityOwner
    from fakenet.mcp.jobobject import ManagedJob
    from fakenet.mcp.service_stop import process_identity
    owner = NativeCapabilityOwner(package, process_identity(), 'readiness-negative')
    owner.deadline = time.monotonic() + 10
    rejected = False
    error = None
    try:
        owner.job = ManagedJob()
        c, w = owner.job.c, owner.job.w
        create = owner.job._bind('CreateEventW', [w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR], w.HANDLE)
        owner.event = create(None, True, False, None)
        if not owner.event:
            owner.event = None
            owner.job._error()
        for _ in range(3):
            owner.fds.append(os.open(os.devnull, os.O_RDWR | os.O_BINARY))
        handles = [msvcrt.get_osfhandle(fd) for fd in owner.fds]
        for handle in handles:
            os.set_handle_inheritable(handle, True)
            owner.inherited.append(handle)
        code = 'raise SystemExit(0)' if mode == 'early-exit' else 'import time; time.sleep(30)'
        owner.job.spawn([sys.executable, '-c', code], package, handles)
        owner._release_inputs()
        try:
            owner.wait_ready(budget=2 if mode == 'early-exit' else 0.1)
        except RuntimeError as exc:
            error = repr(exc)
            rejected = True
        expected = '0' if mode == 'early-exit' else '258'
        if not rejected or not error.endswith(expected + "')"):
            raise RuntimeError('negative readiness did not reach expected native outcome: ' + str(error))
    finally:
        if not owner.cleanup(time.monotonic() + 30):
            raise RuntimeError('negative readiness child cleanup unconfirmed')
    return dict(mode=mode, rejected=rejected, error=error, resources_ended=owner.ended())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('package-root', 'source-root', 'output', 'source-commit', 'package-sha256', 'manifest'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--count', type=int, default=40)
    args = parser.parse_args(argv)
    output = Path(args.output).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print(json.dumps(dict(output=str(output), passed=False, returncode=2, error=repr(exc))))
        return 2
    report = dict(schema='fakenet.repair-readiness.v1', source_commit=args.source_commit,
        package_sha256=args.package_sha256, vm_identity={}, cases=[], passed=False)
    code = 2
    try:
        if os.name != 'nt' or args.count != 40:
            raise ValueError('native Windows and exactly 40 packaged cases required')
        package, source = Path(args.package_root).resolve(), Path(args.source_root).resolve()
        manifest_path = Path(args.manifest).resolve()
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if (manifest.get('schema') != 'fakenet.mcp-candidate-manifest.v1' or
                manifest.get('source_commit') != args.source_commit):
            raise ValueError('candidate manifest identity differs')
        verify_files(package, manifest['files'])
        installed = package / 'mcp-candidate-manifest.json'
        if installed.read_bytes() != manifest_path.read_bytes():
            raise ValueError('installed manifest differs')
        # This receipt accompanies the exact git archive transferred by host.
        source_identity = json.loads((source / 'source-identity.json').read_text())
        if (source_identity.get('source_commit') != args.source_commit or
                source_identity.get('package_sha256') != args.package_sha256):
            raise ValueError('source archive identity differs')
        archive = source_identity['package_archive']
        verify_files(source, [archive])
        if archive['sha256'] != args.package_sha256:
            raise ValueError('transferred archive SHA differs')
        members = verify_files(source, source_identity['files'])
        if not set(source.glob('fakenet/**/*.py')).issubset(members):
            raise ValueError('unattested source module')
        sys.path.insert(0, str(source))
        from fakenet.mcp.managed import ManagedProcess
        from fakenet.mcp.exit_native import TargetHandle
        from fakenet.mcp.exit_installation import assert_no_helpers
        from fakenet.mcp.service_stop import process_identity
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetCurrentProcess.restype = w.HANDLE
        kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        kernel.GetProcessHandleCount.restype = w.BOOL
        def handle_count():
            value = w.DWORD()
            if not kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(value)):
                raise ctypes.WinError(ctypes.get_last_error())
            return value.value
        report['vm_identity'] = dict(computer=os.environ.get('COMPUTERNAME'),
            probe_process=process_identity(), python=sys.version)
        report['manifest'] = dict(path=str(manifest_path), sha256=sha(manifest_path))
        assert_no_helpers(package)
        code = 1
        report['negative_probes'] = [negative_event_probe(package, mode)
                                     for mode in ('early-exit', 'no-ready')]
        for index in range(args.count):
            run_id = str(uuid.uuid4())
            directory = output / run_id
            directory.mkdir()
            before_handles = handle_count()
            case = dict(index=index, run_id=run_id, passed=False,
                        handles_before=before_handles, created_monotonic=time.monotonic())
            report['cases'].append(case)
            owner = ManagedProcess(run_id, directory, package,
                                   executable=package / 'fakenetng-mcp-managed.exe')
            retained = None
            try:
                owner.initialize()
                case['identity'] = owner.identity
                case['created_monotonic'] = time.monotonic()
                case['ready'] = owner.wait_ready()
                case['ready_monotonic'] = time.monotonic()
                retained = TargetHandle(owner.pid)
                actual = retained.identity()
                if (actual['creation_time'] != owner.identity['creation_time'] or
                        actual['image'].casefold() != str(package / 'fakenetng-mcp-managed.exe').casefold()):
                    raise RuntimeError('native target identity differs')
                case['command_line'] = retained.command_line()
                case['remote_read_monotonic'] = time.monotonic()
                if run_id not in case['command_line'] or 'managed-child' not in case['command_line']:
                    raise RuntimeError('native command line differs')
                case['cold_stop'] = owner.request('stop', timeout=10)
                end = time.monotonic() + 30
                while not retained.exited() or owner.job.members():
                    if time.monotonic() >= end:
                        raise TimeoutError('cold child tree end unconfirmed')
                    time.sleep(0.02)
                case['exit_code'], case['job_members'] = owner.job.poll(), owner.job.members()
                if case['cold_stop'] != {'stopped': True} or case['exit_code'] != 0:
                    raise RuntimeError('cold stop response/exit differs')
                retained.close()
                retained = None
                owner.close()
                assert_no_helpers(package)
                case.update(target_handle_closed=True, job_closed=owner.job is None,
                    pipe_reader_ended=owner._reader is None or not owner._reader.is_alive(),
                    descriptors_closed=not owner._descriptors and not owner._inherited and not owner._streams,
                    packaged_helpers_absent=True, handles_after=handle_count())
                if case['handles_after'] != before_handles:
                    raise RuntimeError('probe native handle count differs after cleanup')
                case['passed'] = True
            except BaseException as exc:
                case['error'] = repr(exc)
                case['cleanup_observed'] = owner.cleanup(time.monotonic() + 30)
                case['cleanup_errors'] = owner.cleanup_errors
                if retained is not None:
                    if retained.exited():
                        retained.close()
                        retained = None
                    else:
                        case['retained_target_live'] = True
                raise
            finally:
                case['completed_monotonic'] = time.monotonic()
        report['passed'] = len(report['cases']) == 40 and all(x['passed'] for x in report['cases'])
        code = 0 if report['passed'] else 1
    except BaseException as exc:
        report['error'] = repr(exc)
    finally:
        with (output / 'readiness-result.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        print(json.dumps(dict(output=str(output), passed=report['passed'], returncode=code)))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
