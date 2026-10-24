"""Fixed, locally armed diagnostic stimuli; no native operation at import.

The extended arm must name this initialized managed process, its run, config,
and current Windows Job membership. Legacy two-field fault arms never select
a diagnostic stimulus. A rejected or expired arm is observational only.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

CLASSES = ('stacks_unavailable', 'native_crash', 'unknown_cause')
ARM_KEYS = {'fault', 'nonce', 'run_id', 'pid', 'creation_time', 'config_sha256',
            'job_members', 'expires_ns'}
PLAN_SCHEMA = 'fakenet.diagnostic-plan.v1'
READY_SCHEMA = 'fakenet.diagnostic-ready.v1'
PLAN_KEYS = {'schema', 'fault', 'nonce', 'expires_ns', 'config_sha256', 'service_identity'}
READY_KEYS = {'schema', 'fault', 'nonce', 'run_id', 'pid', 'creation_time',
              'config_sha256', 'job_members', 'expires_ns', 'config_path',
              'run_dir', 'service_identity'}
def _identity(value):
    return (isinstance(value, dict) and set(value) == {'pid', 'creation_time'}
            and type(value['pid']) is int and value['pid'] > 0
            and isinstance(value['creation_time'], str)
            and value['creation_time'].isdigit())


ARM_WINDOW_NS = 120_000_000_000
ARM_TIMEOUT_SECONDS = 5.0


class DiagnosticUnavailable(RuntimeError):
    """A stimulus cannot establish the required real condition."""


def _logs_directory():
    return Path(os.environ.get('PROGRAMDATA', 'C:/ProgramData')) / 'FakeNet-NG-MCP' / 'logs'


def plan_path():
    """Fixed local plan; deliberately not a caller-selected target path."""
    return _logs_directory() / 'diagnostic-plan.json'


def ready_path():
    """Fixed early-initialization observation written by the managed child."""
    return _logs_directory() / 'diagnostic-ready.json'


def arm_path():
    """The original fault arm path, kept for old fault classes."""
    return _logs_directory() / 'fault-injection.json'


def _enabled():
    return os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') == '1'


def _nonce(value):
    return isinstance(value, str) and 0 < len(value) <= 128


def plan_shape(value):
    now = time.time_ns()
    if not isinstance(value, dict) or set(value) != PLAN_KEYS:
        return False
    return (value['schema'] == PLAN_SCHEMA
            and value['fault'] in CLASSES
            and _nonce(value['nonce'])
            and _identity(value['service_identity'])
            and isinstance(value['config_sha256'], str)
            and len(value['config_sha256']) == 64
            and all(c in '0123456789abcdef' for c in value['config_sha256'])
            and type(value['expires_ns']) is int
            and now < value['expires_ns'] <= now + ARM_WINDOW_NS)


def ready_shape(value):
    if not isinstance(value, dict) or set(value) != READY_KEYS:
        return False
    try:
        valid_run = str(uuid.UUID(value['run_id'])) == value['run_id']
    except (ValueError, TypeError, AttributeError):
        return False
    return (value['schema'] == READY_SCHEMA
            and value['fault'] in CLASSES
            and _nonce(value['nonce'])
            and _identity(value['service_identity'])
            and valid_run
            and type(value['pid']) is int and value['pid'] > 0
            and isinstance(value['creation_time'], str)
            and value['creation_time'].isdigit()
            and isinstance(value['config_sha256'], str)
            and len(value['config_sha256']) == 64
            and all(c in '0123456789abcdef' for c in value['config_sha256'])
            and isinstance(value['job_members'], list)
            and bool(value['job_members'])
            and all(type(pid) is int and pid > 0 for pid in value['job_members'])
            and value['job_members'] == sorted(set(value['job_members']))
            and value['pid'] in value['job_members']
            and type(value['expires_ns']) is int
            and value['expires_ns'] > time.time_ns()
            and isinstance(value['config_path'], str) and value['config_path']
            and isinstance(value['run_dir'], str) and value['run_dir'])


def make_plan(fault, nonce=None, ttl_ns=60_000_000_000, *, config_sha256=None, service_identity=None):
    if fault not in CLASSES:
        raise DiagnosticUnavailable('unknown diagnostic class')
    nonce = str(uuid.uuid4()) if nonce is None else nonce
    if not _nonce(nonce):
        raise DiagnosticUnavailable('diagnostic nonce is invalid')
    if type(ttl_ns) is not int or not 1_000_000_000 <= ttl_ns <= ARM_WINDOW_NS:
        raise DiagnosticUnavailable('diagnostic window is outside the fixed bound')
    value = dict(schema=PLAN_SCHEMA, fault=fault, nonce=nonce,
                 expires_ns=time.time_ns() + ttl_ns, config_sha256=config_sha256,
                 service_identity=service_identity)
    if not plan_shape(value):
        raise DiagnosticUnavailable('diagnostic plan is invalid')
    return value


def write_plan(fault, nonce=None, ttl_ns=60_000_000_000, *, config_sha256=None, service_identity=None):
    if not _enabled():
        raise DiagnosticUnavailable('diagnostic planning requires the local fault environment')
    value = make_plan(fault, nonce=nonce, ttl_ns=ttl_ns,
                      config_sha256=config_sha256, service_identity=service_identity)
    path = plan_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return value


def _read_small(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None


def read_plan():
    if not _enabled():
        return None
    value = _read_small(plan_path())
    return value if plan_shape(value) else None


def read_ready():
    if not _enabled():
        return None
    value = _read_small(ready_path())
    return value if ready_shape(value) else None


def remove_window_files(plan, ready):
    # A name alone never grants cleanup ownership. Keep changed/foreign bytes.
    for path, expected in ((plan_path(), plan), (ready_path(), ready)):
        if not path.exists() and not path.is_symlink():
            continue
        observed = _read_small(path)
        if expected is None or observed is None or observed != expected:
            raise DiagnosticUnavailable('diagnostic rendezvous cleanup identity differs')
        path.unlink()


def _write_exclusive(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def build_ready(context, plan):
    """Build the child-side observation from actual identity, Job and config."""
    if not _enabled() or not plan_shape(plan):
        raise DiagnosticUnavailable('diagnostic plan is not live')
    if not isinstance(context, dict) or context.get('initialized') is not True:
        raise DiagnosticUnavailable('managed child is not initialized')
    run_id, run_dir, config_path = context.get('run_id'), context.get('run_dir'), context.get('config_path')
    if not isinstance(run_id, str) or not run_id:
        raise DiagnosticUnavailable('managed run identity missing')
    if not isinstance(run_dir, str) or not run_dir or Path(run_dir).name != run_id:
        raise DiagnosticUnavailable('managed run directory identity differs')
    if not isinstance(config_path, str) or not config_path:
        raise DiagnosticUnavailable('managed configuration path missing')
    from fakenet.mcp.service_stop import process_identity
    actual = process_identity(os.getpid())
    if any(actual.get(k) != context.get(k) for k in ('pid', 'creation_time')):
        raise DiagnosticUnavailable('managed child birth identity differs')
    config = Path(config_path)
    if not config.is_absolute():
        raise DiagnosticUnavailable('managed configuration path is not absolute')
    if config.is_symlink() or not config.is_file():
        raise DiagnosticUnavailable('managed configuration is not a regular file')
    parent = process_identity(os.getppid())
    if any(parent.get(k) != plan['service_identity'][k] for k in ('pid', 'creation_time')):
        raise DiagnosticUnavailable('managed parent differs from the verified service')
    config_sha256 = hashlib.sha256(config.read_bytes()).hexdigest()
    if config_sha256 != plan['config_sha256']:
        raise DiagnosticUnavailable('planned configuration differs from actual child input')
    members = current_job_members()
    if actual['pid'] not in members:
        raise DiagnosticUnavailable('managed child is outside the observed Job')
    value = dict(schema=READY_SCHEMA, fault=plan['fault'], nonce=plan['nonce'],
                 run_id=run_id, pid=actual['pid'],
                 creation_time=actual['creation_time'],
                 config_sha256=config_sha256,
                 job_members=members, expires_ns=plan['expires_ns'],
                 config_path=str(config), run_dir=str(Path(run_dir)),
                 service_identity=dict(plan['service_identity']))
    if not ready_shape(value):
        raise DiagnosticUnavailable('managed readiness observation is invalid')
    return value


def publish_ready(context, plan):
    value = build_ready(context, plan)
    _write_exclusive(ready_path(), value)
    return value


def arm_for_ready(ready, plan):
    """Producer side: turn a child observation into an exact local arm."""
    if not plan_shape(plan) or not ready_shape(ready):
        raise DiagnosticUnavailable('diagnostic ready/plan is not live')
    for name in ('fault', 'nonce', 'expires_ns', 'config_sha256', 'service_identity'):
        if ready[name] != plan[name]:
            raise DiagnosticUnavailable('diagnostic ready belongs to another plan')
    if ready['run_dir'] != str(Path(ready['run_dir'])):
        raise DiagnosticUnavailable('diagnostic run path is not normalized')
    run_dir = Path(ready['run_dir'])
    config = Path(ready['config_path'])
    if not config.is_absolute() or config.is_symlink() or not config.is_file():
        raise DiagnosticUnavailable('diagnostic config source is not regular/absolute')
    if hashlib.sha256(config.read_bytes()).hexdigest() != ready['config_sha256']:
        raise DiagnosticUnavailable('diagnostic config changed before arm')
    return arm_from_ready_observation(ready, plan)


def arm_from_ready_observation(ready, plan):
    """Arm from a child-observed record without trusting a host path.

    The managed child re-reads the actual process birth, Job and config hash
    with ``matching_arm`` before any stimulus. This function is only the
    external producer's exact serialization step.
    """
    if not plan_shape(plan) or not ready_shape(ready):
        raise DiagnosticUnavailable('diagnostic ready/plan is not live')
    for name in ('fault', 'nonce', 'expires_ns', 'config_sha256', 'service_identity'):
        if ready[name] != plan[name]:
            raise DiagnosticUnavailable('diagnostic ready belongs to another plan')
    value = {name: ready[name] for name in ARM_KEYS if name in ready}
    if not arm_shape(value):
        raise DiagnosticUnavailable('diagnostic arm is invalid')
    return value


def write_arm_from_ready(plan):
    """Fixed external producer; no caller-selected target or arbitrary path."""
    ready = read_ready()
    if ready is None:
        raise DiagnosticUnavailable('diagnostic ready observation is unavailable')
    value = arm_for_ready(ready, plan)
    _write_exclusive(arm_path(), value)
    return value


def wait_for_arm(context, plan, timeout=ARM_TIMEOUT_SECONDS):
    deadline = time.monotonic() + max(0.0, float(timeout))
    while time.monotonic() < deadline:
        value = matching_arm(context, arm_path())
        if value is not None and value['fault'] == plan['fault'] and value['nonce'] == plan['nonce']:
            return value
        time.sleep(0.02)
    raise DiagnosticUnavailable('diagnostic arm deadline exceeded')


def archive_window(context, plan, ready):
    """Retain the exact same-run window before removing global rendezvous files."""
    directory = Path(context['run_dir'])
    with (directory / 'diagnostic-window.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(schema='fakenet.diagnostic-window.v1', plan=plan,
                       ready=ready), stream)
        stream.flush()
        os.fsync(stream.fileno())


def _write_fault_receipt(context, value):
    directory = Path(context['run_dir'])
    if directory.name != value['run_id']:
        raise DiagnosticUnavailable('diagnostic trigger directory differs')
    with (directory / 'fault-triggered.json').open('x', encoding='utf-8') as stream:
        json.dump({'fault': value['fault'], 'nonce': value['nonce']}, stream)
        stream.flush()
        os.fsync(stream.fileno())


def arm_shape(value):
    if not isinstance(value, dict) or set(value) != ARM_KEYS:
        return False
    try:
        valid_run = str(uuid.UUID(value['run_id'])) == value['run_id']
    except (ValueError, TypeError, AttributeError):
        return False
    return (value['fault'] in CLASSES and valid_run
            and _nonce(value['nonce'])
            and type(value['pid']) is int and value['pid'] > 0
            and isinstance(value['creation_time'], str)
            and value['creation_time'].isdigit()
            and isinstance(value['config_sha256'], str)
            and len(value['config_sha256']) == 64
            and all(c in '0123456789abcdef' for c in value['config_sha256'])
            and isinstance(value['job_members'], list)
            and bool(value['job_members'])
            and all(type(pid) is int and pid > 0 for pid in value['job_members'])
            and value['job_members'] == sorted(set(value['job_members']))
            and value['pid'] in value['job_members']
            and type(value['expires_ns']) is int)


def current_job_members():
    """Query this process's current Job; no process is created or terminated."""
    if os.name != 'nt':
        raise DiagnosticUnavailable('diagnostic Job observation requires Windows')
    import ctypes as c
    from ctypes import wintypes as w
    # Fixed bound. A larger/changed Job is rejected, never silently truncated.
    class Members(c.Structure):
        _fields_ = [('assigned', w.DWORD), ('count', w.DWORD),
                    ('pids', c.c_size_t * 256)]
    kernel = c.WinDLL('kernel32', use_last_error=True)
    query = kernel.QueryInformationJobObject
    query.argtypes = [w.HANDLE, c.c_int, w.LPVOID, w.DWORD, w.LPVOID]
    query.restype = w.BOOL
    value = Members()
    if not query(None, 3, c.byref(value), c.sizeof(value), None):
        raise c.WinError(c.get_last_error())
    if not 0 < value.assigned == value.count <= 256:
        raise DiagnosticUnavailable('managed Job membership is incomplete')
    return sorted(int(pid) for pid in value.pids[:value.count])


def matching_arm(context, path):
    if os.environ.get('FAKENETNG_MCP_FAULT_INJECTION') != '1' or not context:
        return None
    if context.get('initialized') is not True:
        return None
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        return None
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not arm_shape(value):
            return None
        now = time.time_ns()
        if not now < value['expires_ns'] <= now + 120_000_000_000:
            return None
        for name in ('run_id', 'pid', 'creation_time', 'config_sha256', 'nonce'):
            if value[name] != context.get(name):
                return None
        from fakenet.mcp.service_stop import process_identity
        actual = process_identity(os.getpid())
        if any(actual.get(k) != value[k] for k in ('pid', 'creation_time')):
            return None
        if current_job_members() != value['job_members']:
            return None
        config = Path(context['config_path'])
        if config.is_symlink() or hashlib.sha256(config.read_bytes()).hexdigest() != value['config_sha256']:
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError, DiagnosticUnavailable):
        return None


def record_trigger(context, value):
    directory = Path(context['run_dir'])
    if directory.name != value['run_id']:
        raise DiagnosticUnavailable('diagnostic run directory differs')
    with (directory / 'diagnostic-triggered.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(value, observed_time_ns=time.time_ns()), stream)
        stream.flush()
        os.fsync(stream.fileno())


def _trigger_fail_fast(context, path, expected_fault):
    if expected_fault not in ('native_crash', 'stacks_unavailable'):
        raise DiagnosticUnavailable('unregistered fixed termination class')
    value = matching_arm(context, path)
    if value is None or value['fault'] != expected_fault:
        raise DiagnosticUnavailable('native stimulus target arm unconfirmed')
    if os.name != 'nt':
        raise DiagnosticUnavailable('native stimulus requires Windows')
    # ctypes memory reads on Windows translate access violations to Python
    # OSError. Fail-fast deliberately bypasses application exception handlers.
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    crash = kernel.RaiseFailFastException
    crash.argtypes = [w.LPVOID, w.LPVOID, w.DWORD]
    crash.restype = None
    record_trigger(context, value)
    _write_fault_receipt(context, value)
    try:
        arm = Path(path)
        if _read_small(arm) != value:
            raise DiagnosticUnavailable('native arm changed before consumption')
        arm.unlink()
    except OSError:
        pass
    crash(None, None, 0)
    raise DiagnosticUnavailable('Windows fail-fast unexpectedly returned')


def unknown_cause_observation():
    # A custom RuntimeError explains its own origin and cannot establish an
    # unknown failure. Do not consume the arm or manufacture a terminal event.
    raise DiagnosticUnavailable('no verified unattributed terminal stimulus')



def trigger_native_crash(context, path):
    return _trigger_fail_fast(context, path, 'native_crash')


def trigger_stack_unavailability(context, path):
    """Transparent fail-fast after early suppression, never an unknown cause."""
    if not context or context.get('no_stack_bound_early') is not True:
        raise DiagnosticUnavailable('no-stack stimulus was not bound before snapshots')
    directory = Path(context['run_dir'])
    for name in ('managed-thread-stacks.json', 'stop-thread-stacks.txt', 'fault-child-stacks.txt'):
        source = directory / name
        if source.exists() or source.is_symlink():
            raise DiagnosticUnavailable('preexisting stack source; preserve fallback')
    return _trigger_fail_fast(context, path, 'stacks_unavailable')


UNKNOWN_SCHEMA = 'fakenet.unknown-self-exit.v1'
UNKNOWN_EXIT_CODE = 0xE0420001
UNKNOWN_OPTIONS = {'schema': UNKNOWN_SCHEMA, 'mechanism': 'current-child-ExitProcess',
                   'exit_code': UNKNOWN_EXIT_CODE, 'cause_domain': 'complete-application-diagnostics.v1'}


def unknown_options(value):
    """Explicit opt-in; legacy unknown arms retain their observational behavior."""
    return isinstance(value, dict) and value == UNKNOWN_OPTIONS and type(value.get('exit_code')) is int


def trigger_unknown_self_exit(context, path):
    """Disclosed mechanism; it does not itself assert an unknown root cause."""
    if not context or not unknown_options(context.get('unknown_options')):
        raise DiagnosticUnavailable('explicit unknown self-exit context required')
    value = matching_arm(context, path)
    if value is None or value['fault'] != 'unknown_cause':
        raise DiagnosticUnavailable('unknown self-exit target arm unconfirmed')
    if os.name != 'nt':
        raise DiagnosticUnavailable('unknown self-exit requires Windows')
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    terminate = kernel.ExitProcess
    terminate.argtypes = [w.UINT]
    terminate.restype = None
    directory = Path(context['run_dir'])
    # Separate transparent test truth; never written into product exceptions.
    with (directory / 'diagnostic-self-exit.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(schema=UNKNOWN_SCHEMA, mechanism='current-child-ExitProcess',
                       exit_code=UNKNOWN_EXIT_CODE, arm=value, observed_time_ns=time.time_ns()), stream)
        stream.flush(); os.fsync(stream.fileno())
    record_trigger(context, value)
    _write_fault_receipt(context, value)
    if _read_small(Path(path)) != value:
        raise DiagnosticUnavailable('unknown arm changed before consumption')
    Path(path).unlink()
    terminate(UNKNOWN_EXIT_CODE)
    raise DiagnosticUnavailable('Windows self-exit unexpectedly returned')



def read_unknown_options():
    if not _enabled():
        return None
    value = _read_small(_logs_directory() / 'diagnostic-unknown-options.json')
    return value if unknown_options(value) else None
