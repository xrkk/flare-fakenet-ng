# Copyright 2026 Google LLC
"""LNX-FN lifecycle runner: real FakeNet-NG process management on Linux.

Implements the same runner surface RealSupervisor exposes on Windows
(start/stop/restart/health_detail) but drives the native Linux process:
``python -m fakenet.fakenet -c <config> -f <stop-flag>``.  Readiness and
health are verified from real network state (NFQUEUE rules present, IPv6
policy DROP present), and stop verifies the diverter's rule cleanup so a
finished run leaves no orphaned rules.  Failure is reported, never masked.
"""
import os
import signal
import subprocess
import threading
import time
import uuid


class LinuxRunnerError(Exception):
    pass


ORPHAN_RULES = (
    ('iptables', ['-t', 'mangle', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0']),
    ('iptables', ['-t', 'raw', '-D', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '1']),
    ('iptables', ['-t', 'nat', '-D', 'PREROUTING', '-j', 'REDIRECT']),
    ('iptables', ['-t', 'nat', '-D', 'OUTPUT', '-p', 'icmp', '-j', 'REDIRECT']),

)


def adopt_orphan_rules():
    """Remove every prior-generation takeover rule (crash recovery).

    A SIGKILLed fakenet leaves NFQUEUE/REDIRECT/DROP rules with no
    consumer: inbound NFQUEUE with a dead queue drops all traffic and can
    lock out management.  Called at MCP service startup so a restart always
    returns the host to a clean, manageable state.  Returns what was found.
    """
    adopted = []
    for binary, argv in ORPHAN_RULES:
        pos = argv.index('-D')
        check = [binary] + argv[:pos] + ['-C'] + argv[pos + 1:]
        if subprocess.run(check, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            subprocess.run([binary] + argv, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            adopted.append(' '.join([binary] + argv))
    from fakenet.diverters.linuxnetpolicy import NetPolicy
    adopted.extend(NetPolicy([('192.168.204.1', 2222)]).adopt_leftovers())
    return adopted


def _ipt_has(fragment, binary='iptables'):
    """Probe rule presence across ALL tables (iptables-save), not just filter.

    The diverter's NFQUEUE hooks live in mangle/raw and the policy DROP in
    filter/ip6tables: a filter-only `-S` can never see them (field-verified:
    a successfully running takeover was misjudged as not-ready and killed).
    """
    argv = [binary + '-save'] if binary == 'iptables' else ['ip6tables-save']
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinuxRunnerError('%s-save failed: %s' % (binary, exc)) from None
    return fragment in result.stdout.decode('utf-8', 'replace')


class LinuxRunner:
    """Runner bound to the Coordinator contract used by tools.py."""

    def __init__(self, config_path_resolver=None, logger=None,
                 python_bin=None, startup_timeout=45.0):
        import sys
        self._resolver = config_path_resolver
        self.logger = logger
        self._python = python_bin or sys.executable
        self._lock = threading.RLock()
        self._proc = None
        self._stop_flag = None
        self._run_id = None
        self._health_cache = {}
        self.startup_timeout = startup_timeout

    # -- health ---------------------------------------------------------
    def health_detail(self, state, max_wait=0.05):
        with self._lock:
            detail = dict(self._health_cache)
        detail['process_alive'] = self._proc is not None and \
            self._proc.poll() is None
        try:
            detail['nfqueue_present'] = _ipt_has('NFQUEUE')
            detail['ipv6_policy_drop'] = _ipt_has(
                '-j DROP', 'ip6tables') or _ipt_has(
                '-P OUTPUT DROP', 'ip6tables')
        except LinuxRunnerError as exc:
            detail['rule_probe_error'] = str(exc)
        return detail

    # -- lifecycle ------------------------------------------------------
    def start(self, coordinator, controller, config_identity,
              restart_quiescence=False):
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                raise LinuxRunnerError('managed process already exists')
        if self._resolver is None:
            raise LinuxRunnerError('config path resolver missing')
        path = self._resolver(config_identity.get('name'),
                              config_identity.get('builtin'))
        run_id = uuid.uuid4().hex
        stop_flag = '/tmp/fakenet-ng-stop-%s' % (run_id,)
        if os.path.exists(stop_flag):
            os.unlink(stop_flag)
        argv = [self._python, '-m', 'fakenet.fakenet',
                '-c', path, '-f', stop_flag, '-p']
        env = dict(os.environ)
        package_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', '..'))
        env['PYTHONPATH'] = package_root + os.pathsep + env.get('PYTHONPATH', '')
        child_log = os.path.join(package_root, 'Logs',
                                 'runner-child-%s.log' % run_id)
        os.makedirs(os.path.dirname(child_log), exist_ok=True)
        self._child_log = child_log
        child_handle = open(child_log, 'wb')
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=child_handle,
            stderr=subprocess.STDOUT, cwd=package_root, env=env)
        child_handle.close()
        with self._lock:
            self._proc, self._stop_flag, self._run_id = proc, stop_flag, run_id
        deadline = time.monotonic() + self.startup_timeout
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                tail = ''
                try:
                    with open(self._child_log, 'rb') as h:
                        tail = h.read()[-800:].decode('utf-8', 'replace')
                except OSError:
                    pass
                self._teardown_state()
                raise LinuxRunnerError(
                    'fakenet process exited during startup rc=%s tail=%s' %
                    (proc.returncode, tail))
            try:
                if _ipt_has('NFQUEUE') and _ipt_has(
                        '-j DROP', 'ip6tables'):
                    ready = True
                    break
            except LinuxRunnerError:
                pass
            time.sleep(0.5)
        if not ready:
            self._hard_kill()
            raise LinuxRunnerError('startup readiness timeout')
        with self._lock:
            self._health_cache = {'run_id': run_id, 'init_evidence': True,
                                  'probe': True, 'config': config_identity}
        return {'state': 'healthy', 'changed': True, 'run_id': run_id,
                'controller': controller, 'config_identity': dict(config_identity),
                'failure_reason': None, 'release_controller': False}

    def stop(self, coordinator, baseline_audit=True, deadline=None):
        with self._lock:
            proc, stop_flag = self._proc, self._stop_flag
        run_id = self._run_id
        if proc is not None:
            if stop_flag:
                open(stop_flag, 'w').close()
            deadline = deadline or (time.monotonic() + 30.0)
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.3)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        leftover = []
        try:
            if _ipt_has('NFQUEUE'):
                leftover.append('NFQUEUE')
            if _ipt_has('-j DROP', 'ip6tables'):
                leftover.append('ipv6-DROP')
        except LinuxRunnerError as exc:
            leftover.append('probe-error:%s' % (exc,))
        self._teardown_state()
        state = 'stopped' if not leftover else 'failed'
        if leftover:
            # Keep run responsibility until a later clean rule observation.
            self._run_id = run_id
        return {'state': state, 'changed': True,
                'run_id': self._run_id,
                'failure_reason': ('leftover rules: %s' % leftover) if leftover else None,
                'release_controller': state == 'stopped'}

    def restart(self, coordinator, controller, config_identity):
        stopped = self.stop(coordinator)
        if stopped['state'] != 'stopped':
            return stopped
        return self.start(coordinator, controller, config_identity)

    # -- internals ------------------------------------------------------
    def _hard_kill(self):
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        self._teardown_state()

    def _teardown_state(self):
        with self._lock:
            if self._stop_flag and os.path.exists(self._stop_flag):
                try:
                    os.unlink(self._stop_flag)
                except OSError:
                    pass
            self._proc = None
            self._stop_flag = None
            self._run_id = None
            self._health_cache = {}
