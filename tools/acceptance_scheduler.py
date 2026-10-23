"""Local bounded scheduling and ownership of the runner's Python children.

No target actions occur on import. Native recovery remains with its driver.
"""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import time

SAFE_PARALLEL = frozenset(('CORE-TLSHELLO', 'CORE-DUALPCAP-WRITER'))
MAX_WORKERS = 2


def depth_from_environment(environment=None):
    source = os.environ if environment is None else environment
    try:
        return max(0, int(source.get('FN_ACCEPTANCE_NESTED_DEPTH', '0')))
    except (TypeError, ValueError):
        return 1  # malformed nesting information only narrows capacity


def worker_capacity(environment=None, depth=None):
    if (depth_from_environment(environment) if depth is None else depth) > 0:
        return 1
    try:
        cpu = min(os.cpu_count() or 1, len(os.sched_getaffinity(0)))
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(memory['MemAvailable'].split()[0]) * 1024
        return max(1, min(MAX_WORKERS, cpu, available // (512 * 1024 * 1024)))
    except (AttributeError, OSError, ValueError, KeyError):
        return 1


def dependencies(case, plan=None):
    result = set(case.get('dependencies') or [])
    if (case['id'] == 'MCP-P04-FULL' and plan is not None and
            'ACC-019' in plan.get('required_checks', {}).get(case['id'], [])):
        result.add('MCP-P03-FULL')
    return result


def ordered_cases(cases, plan=None):
    """Stable topological traversal; retain every unresolvable case as blocked."""
    by_id = {case['id']: case for case in cases}
    if len(by_id) != len(cases):
        raise ValueError('duplicate scheduling case')
    pending = list(by_id)
    ordered, blocked = [], {}
    while pending:
        progressed = False
        for cid in list(pending):
            deps = dependencies(by_id[cid], plan)
            missing = deps - set(by_id)
            if missing:
                blocked[cid] = 'missing dependency: ' + ','.join(sorted(missing))
            elif deps & set(blocked):
                blocked[cid] = 'dependency not passed: ' + ','.join(sorted(deps & set(blocked)))
            elif not deps.issubset(ordered):
                continue
            else:
                ordered.append(cid)
            pending.remove(cid)
            progressed = True
        if not progressed:
            for cid in pending:
                blocked[cid] = 'dependency cycle'
            break
    return ordered, blocked


def _target_keys(target):
    if not isinstance(target, dict):
        return set()
    keys = set()
    if target.get('vm_uuid'):
        keys.add('target:uuid:' + str(target['vm_uuid']).lower())
    if target.get('platform') and target.get('hostname'):
        keys.add('target:host:' + str(target['platform']).lower() + ':' + str(target['hostname']).lower())
    return keys


def _resources(case, environment=None):
    """Return owned resources, not privilege labels or Python capacity tokens."""
    declared = {str(item) for item in case.get('resources', [])}
    if case.get('adapter') != 'native':
        return {'declared:' + item for item in declared - {'offline-python', 'offline-python-capacity'}}
    if case.get('native_driver') == 'build-identity':
        return set()  # immutable package bytes have no target recovery ownership
    env = environment or {}
    runtime = env.get('native_runtime') or {}
    if str(case.get('native_driver', '')).startswith('mcp-'):
        keys = _target_keys((env.get('mcp') or {}).get('target'))
    else:
        keys = _target_keys(runtime.get('identity'))
        transfer = runtime.get('transfer') or {}
        keys |= _target_keys(transfer.get('expected_vm_identity'))
        if case.get('native_driver') == 'upstream-multihost':
            # Until both physical owners are explicit, do not claim independence.
            keys = set()
    if not keys:
        keys.add('target:unresolved')
    # A response service on the host can be shared even across distinct VMs.
    for name in declared & {'sentinel', 'host-service', 'host-tcp', 'host-udp'}:
        keys.add('host-service:' + name)
    known = {'vm', 'vmware', 'windows-vm', 'linux-vm', 'client-vm', 'administrator',
             'root', 'administrator-or-root', 'root-or-administrator', 'pktmon',
             'mcp-service', 'controller', 'internet', 'sentinel', 'host-service',
             'host-tcp', 'host-udp'}
    keys |= {'declared:' + item for item in declared - known}
    return keys


def conflicts(left, right):
    if left & right:
        return True
    return (('target:unresolved' in left and any(key.startswith('target:') for key in right)) or
            ('target:unresolved' in right and any(key.startswith('target:') for key in left)))


def block_reason(case, facts, taints, *, plan=None, initial=None):
    if initial and case['id'] in initial:
        return initial[case['id']]
    deps = dependencies(case, plan)
    missing = deps - set((plan or {}).get('cases', facts)) if plan is not None else set()
    if missing:
        return 'missing dependency: ' + ','.join(sorted(missing))
    failed = [dep for dep in sorted(deps) if dep in facts and
              (facts[dep].get('status') != 'pass' or facts[dep].get('cleanup_ok') is False)]
    if failed:
        return 'dependency not passed: ' + ','.join(failed)
    resources = _resources(case, (plan or {}).get('environment'))
    owners = [owner for owner, owned in taints.items() if conflicts(resources, owned)]
    if owners:
        return 'resource recovery unresolved: ' + ','.join(sorted(owners))
    return None


def run_cases(cases, runner, *, capacity=None, completion=None, judge=None, plan=None, initial=None):
    """Run only ready jobs. The owner thread alone admits and settles jobs."""
    allowed = worker_capacity()
    capacity = allowed if capacity is None else max(1, min(allowed, int(capacity)))
    ordered, blocked = ordered_cases(cases, plan)
    by_id = {case['id']: case for case in cases}
    pending = [cid for cid in ordered if cid not in blocked]
    results, facts, taints, running = {}, {}, {}, {}
    for cid in blocked:
        facts[cid] = {'status': 'blocked'}

    def finish(cid, value):
        results[cid] = value
        try:
            observed = judge(by_id[cid], value) if judge else dict(value)
        except Exception as exc:
            observed = {'status': 'unknown', 'cleanup_ok': False,
                        'facility_error': type(exc).__name__ + ': ' + str(exc)}
        facts[cid] = observed
        if observed.get('cleanup_ok') is False:
            taints[cid] = _resources(by_id[cid], (plan or {}).get('environment'))

    def invoke(cid):
        try:
            return runner(by_id[cid])
        except Exception as exc:
            return {'status': 'unknown', 'cleanup_ok': False,
                    'facility_error': type(exc).__name__ + ': ' + str(exc)}

    def safe(cid):
        return (cid in SAFE_PARALLEL and
                by_id[cid].get('adapter', 'offline-pytest') == 'offline-pytest')

    with ThreadPoolExecutor(max_workers=capacity) as pool:
        while pending or running:
            for cid in list(pending):
                reason = block_reason(by_id[cid], facts, taints, plan=plan, initial=initial)
                if reason:
                    blocked[cid] = reason
                    facts[cid] = {'status': 'blocked'}
                    pending.remove(cid)
            ready = [cid for cid in pending if dependencies(by_id[cid], plan).issubset(facts)]
            for cid in ready:
                if not safe(cid):
                    if not running:
                        pending.remove(cid)
                        finish(cid, invoke(cid))
                    break  # serial case is also a barrier to later admissions
                resources = _resources(by_id[cid], (plan or {}).get('environment'))
                if len(running) >= capacity:
                    break
                if any(conflicts(resources, _resources(by_id[other], (plan or {}).get('environment')))
                       for other in running.values()):
                    continue
                pending.remove(cid)
                running[pool.submit(invoke, cid)] = cid
            if running:
                done, unused = wait(running, return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda f: ordered.index(running[f])):
                    cid = running.pop(future)
                    finish(cid, future.result())
            elif pending and not ready:
                raise RuntimeError('scheduler cannot settle its fixed dependency set')
    if completion:
        completion(results, blocked)
    return results, blocked


def _linux_group(pgid):
    members = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            values = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(values[2]) == pgid:
                members.append({'pid': int(directory.name), 'state': values[0],
                                'pgid': int(values[2]), 'sid': int(values[3]),
                                'birth_ticks': int(values[19])})
        except (OSError, ValueError, IndexError):
            continue
    return sorted(members, key=lambda item: item['pid'])


def _birth(pid):
    values = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'state': values[0], 'pgid': int(values[2]),
            'sid': int(values[3]), 'birth_ticks': int(values[19])}


def _track_descendants(leader, tracked):
    # Follow this launch's per-thread child lists, not unrelated host processes.
    pending, visited = [leader] + list(tracked), set()
    while pending:
        parent = pending.pop()
        if parent in visited:
            continue
        visited.add(parent)
        if parent in tracked:
            try:
                if _birth(parent)['birth_ticks'] != tracked[parent]['created']['birth_ticks']:
                    continue
            except OSError:
                continue
        try:
            tasks = list((Path('/proc') / str(parent) / 'task').iterdir())
        except OSError:
            continue
        for task in tasks:
            try:
                children = [int(value) for value in (task / 'children').read_text().split()]
            except (OSError, ValueError):
                continue
            for pid in children:
                if pid in tracked:
                    pending.append(pid)
                    continue
                try:
                    created = _birth(pid)
                except OSError:
                    continue
                descriptor = None
                try:
                    descriptor = os.pidfd_open(pid, 0)
                    if _birth(pid)['birth_ticks'] != created['birth_ticks']:
                        os.close(descriptor)
                        continue
                except (OSError, AttributeError):
                    if descriptor is not None:
                        os.close(descriptor)
                    descriptor = None
                tracked[pid] = {'created': created, 'descriptor': descriptor}
                pending.append(pid)


def _descendant_states(tracked):
    rows = []
    for pid, item in tracked.items():
        created = item['created']
        try:
            current = _birth(pid)
            state = current['state'] if current['birth_ticks'] == created['birth_ticks'] else 'reused'
        except FileNotFoundError:
            state = 'gone'
        except OSError:
            state = 'unknown'
        rows.append({'pid': pid, 'birth_ticks': created['birth_ticks'], 'state': state})
    return rows


class _WindowsJob:
    """Own a suspended Python process and its descendants before first execution.

    This branch needs native Windows validation; it is not exercised on Linux.
    """
    def __init__(self):
        from ctypes import wintypes as W
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.k.CreateJobObjectW.restype = W.HANDLE
        self.k.CreateJobObjectW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
        self.k.TerminateJobObject.argtypes = [W.HANDLE, W.UINT]
        self.k.QueryInformationJobObject.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.c_void_p]
        self.k.GetProcessTimes.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
        self.handle = self.k.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_resume(self, process):
        if not self.k.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        times = [ctypes.c_ulonglong() for unused in range(4)]
        if not self.k.GetProcessTimes(int(process._handle), *[ctypes.byref(item) for item in times]):
            raise ctypes.WinError(ctypes.get_last_error())
        resume = ctypes.WinDLL('ntdll').NtResumeProcess
        resume.argtypes = [ctypes.c_void_p]
        resume.restype = ctypes.c_long
        if resume(int(process._handle)) != 0:
            raise RuntimeError('owned suspended process could not resume')
        return times[0].value

    def active(self):
        # JOBOBJECT_BASIC_ACCOUNTING_INFORMATION: 4xLARGE_INTEGER + 4xDWORD.
        data = ctypes.create_string_buffer(48)
        if not self.k.QueryInformationJobObject(self.handle, 1, data, 48, None):
            raise ctypes.WinError(ctypes.get_last_error())
        return int.from_bytes(data.raw[40:44], 'little')

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None


def run_owned_process(argv, *, cwd, env, stdout, stderr, timeout):
    """Observe and reap only this launch's group/Job, including timeout paths."""
    started = time.monotonic()
    windows = os.name == 'nt'
    job = _WindowsJob() if windows else None
    options = ({'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP | 0x4}
               if windows else {'start_new_session': True})
    process = None
    tracked = {}
    observation = {'argv': list(argv), 'cwd': str(cwd), 'timed_out': False,
                   'forced': False, 'tree_exited': False, 'final_members': []}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                   shell=False, **options)
        if windows:
            try:
                birth = job.assign_resume(process)
            except BaseException:
                process.kill()  # exact owned suspended-process handle
                process.wait(timeout=5)
                raise
            created = {'pid': process.pid, 'birth_filetime': birth, 'kind': 'windows-job'}
        else:
            members = _linux_group(process.pid)
            created = next(item for item in members if item['pid'] == process.pid)
            if created['pgid'] != process.pid or created['sid'] != process.pid:
                raise RuntimeError('owned process group identity differs')
        observation['created'] = created
        deadline = started + timeout
        # On Linux WNOWAIT retains the leader's birth/PID until group cleanup,
        # preventing a reaped leader's numeric PID from becoming a new owner.
        while True:
            if not windows:
                _track_descendants(process.pid, tracked)
            exited = (process.poll() is not None if windows else
                      os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None)
            if exited:
                break
            if time.monotonic() >= deadline:
                observation['timed_out'] = True
                break
            time.sleep(min(.02, max(0, deadline - time.monotonic())))
        if windows:
            active = job.active()
            observation['active_before_cleanup'] = active
            if active:
                observation['forced'] = True
                if not job.k.TerminateJobObject(job.handle, 124):
                    raise ctypes.WinError(ctypes.get_last_error())
            process.wait(timeout=5)
            end = time.monotonic() + 5
            while job.active() and time.monotonic() < end:
                time.sleep(.02)
            observation['active_after_cleanup'] = job.active()
            observation['tree_exited'] = observation['active_after_cleanup'] == 0
        else:
            _track_descendants(process.pid, tracked)
            before = _linux_group(process.pid)
            observation['members_before_cleanup'] = before
            live = [item for item in before if item['state'] not in ('Z', 'X')]
            leader = next(item for item in before if item['pid'] == process.pid)
            if leader['birth_ticks'] != created['birth_ticks'] or leader['sid'] != process.pid:
                raise RuntimeError('owned leader birth changed before cleanup')
            descendants = _descendant_states(tracked)
            live_descendants = [item for item in descendants if item['state'] not in ('Z', 'X', 'gone', 'reused')]
            if live or live_descendants:
                observation['forced'] = True
                for item in live_descendants:
                    descriptor = tracked[item['pid']]['descriptor']
                    if descriptor is not None:
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                if live:
                    os.killpg(process.pid, signal.SIGKILL)
            end = time.monotonic() + 5
            while True:
                final = _linux_group(process.pid)
                descendants = _descendant_states(tracked)
                group_done = not any(item['state'] not in ('Z', 'X') for item in final)
                children_done = not any(item['state'] not in ('Z', 'X', 'gone', 'reused') for item in descendants)
                if (group_done and children_done) or time.monotonic() >= end:
                    break
                time.sleep(.02)
            observation['final_members'] = final
            observation['descendants_created'] = [item['created'] for item in tracked.values()]
            observation['descendants_after_cleanup'] = descendants
            observation['tree_exited'] = group_done and children_done
            process.wait(timeout=5)
        observation['returncode'] = process.returncode
        return observation
    finally:
        # A Python/control exception must not release a still-owned worker.
        # Never signal a name or a different process birth.
        if not windows and not observation['tree_exited']:
            for item in _descendant_states(tracked):
                if item['state'] not in ('Z', 'X', 'gone', 'reused'):
                    descriptor = tracked[item['pid']]['descriptor']
                    if descriptor is not None:
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
        if process is not None and process.returncode is None:
            if windows:
                job.k.TerminateJobObject(job.handle, 125)
                process.wait(timeout=5)
            else:
                group = _linux_group(process.pid)
                leader = next((item for item in group if item['pid'] == process.pid), None)
                if leader and leader.get('sid') == process.pid:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for item in tracked.values():
            if item['descriptor'] is not None:
                os.close(item['descriptor'])
        if job is not None:
            if not observation['tree_exited']:
                job.k.TerminateJobObject(job.handle, 125)
            job.close()
