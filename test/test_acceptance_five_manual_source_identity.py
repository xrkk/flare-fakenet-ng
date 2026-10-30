"""FMS durable local tests (T061-R01): the five remaining manual cases take the
explicit single-selection source branch through the REAL entries - plan CLI
(v5 identity from the full registered M), host/guest pre-effect gates, the
v5 schema/five-key chain, STATIC benign fixtures into the original oracles
(real producers are NOT run; every real effect entry is blocked with a hit
marker before any test starts), tamper negatives, and v1/v3/v4 compatibility.
Local pass is fixture evidence only; it grants no native credit."""
import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as A
import acceptance_guest as guest
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as native

HEAD = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                               text=True).strip()
CATALOG = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text(encoding='utf-8'))
FIVE = ('GAP-EXECUTECMD', 'GAP-STANDALONE-LISTENERS', 'GAP-CTRLC-IPC',
        'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG')
CASES = {c['id']: c for s in CATALOG['suites'] for c in s.get('cases', []) if c['id'] in FIVE}
EFFECT_MARKER = Path(os.environ.get('FN_FIVE_EFFECT_MARKER',
                                    '/tmp/fnreg-t061-effect-marker.txt'))


def _hit(name):
    def boom(*args, **kwargs):
        EFFECT_MARKER.parent.mkdir(parents=True, exist_ok=True)
        EFFECT_MARKER.write_text('REAL_EFFECT_HIT: ' + name)
        raise AssertionError('REAL_EFFECT_HIT: ' + name)
    return boom


class _NoRealEffects(unittest.TestCase):
    """Block every real effect entry BEFORE the test body runs; a hit leaves
    a durable marker instead of reporting the block after the fact.  Read-only
    git identity lookups stay live (they are not case effects)."""

    def setUp(self):
        real_popen = subprocess.Popen

        def guarded_popen(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]).endswith('git'):
                return real_popen(argv, *args, **kwargs)
            EFFECT_MARKER.parent.mkdir(parents=True, exist_ok=True)
            with EFFECT_MARKER.open('a') as stream:
                stream.write('REAL_EFFECT_HIT: subprocess.Popen %r\n' % (argv[:2],))
            raise AssertionError('REAL_EFFECT_HIT: subprocess.Popen')
        patches = [mock.patch('subprocess.Popen', side_effect=guarded_popen),
                   mock.patch('socket.socket.bind', side_effect=_hit('socket.socket.bind')),
                   mock.patch('socket.socket.listen', side_effect=_hit('socket.socket.listen')),
                   mock.patch('socket.create_connection', side_effect=_hit('socket.create_connection'))]
        try:
            import win32evtlog
            patches.append(mock.patch.object(win32evtlog, 'OpenEventLog',
                                             side_effect=_hit('win32evtlog.OpenEventLog')))
        except ImportError:
            pass
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        super().setUp()


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _source_plan(work, case_id):
    run = work / 'run'
    run.mkdir(parents=True, exist_ok=True)
    candidate = {'schema': A.CANDIDATE_V2, 'source_commit': HEAD,
                 'deployed_identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                 'deployment_kind': 'source'}
    (work / 'candidate.json').write_text(json.dumps(candidate))
    environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['windows-vm'],
                   'interpreters': {'python': sys.executable}, 'work_root': str(run),
                   'allowed_actions': ['native'], 'endpoints': [], 'auth_refs': [],
                   'native_runtime': {'transport': 'windows-mcp-velo',
                                      'identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                                      'python': 'C:\\py.exe', 'source_root': 'E:\\src',
                                      'work_root': 'E:\\w',
                                      'transfer': {'expected_vm_identity': {
                                          'vm_uuid': 'u' * 36, 'boot_identity': 'b', 'vm_epoch': 'e'}}},
                   'manual': {'schema': 'fakenet.manual-options.v1', 'responsea': '192.0.2.55'}}
    (work / 'environment.json').write_text(json.dumps(environment))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                       '--case', case_id, '--candidate', str(work / 'candidate.json'),
                       '--environment', str(work / 'environment.json'),
                       '--output', str(run / 'plan.json')])
    assert code == 0
    plan = json.loads((run / 'plan.json').read_text())
    plan['execution_id'] = 'fms-regression'
    return plan


def _replan(work, candidate, environment, case_ids, output):
    (work / 'c.json').write_text(json.dumps(candidate))
    (work / 'e.json').write_text(json.dumps(environment))
    output.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        args = ['--root', str(ROOT), 'plan', '--mode', 'selected']
        for case_id in case_ids:
            args += ['--case', case_id]
        code = A.main(args + ['--candidate', str(work / 'c.json'),
                              '--environment', str(work / 'e.json'), '--output', str(output)])
    return code


def _identity_of(inputs):
    if inputs['schema'] in ('fakenet.manual-input.v3', 'fakenet.manual-input.v4',
                            'fakenet.manual-input.v5'):
        return {k: inputs[k] for k in ('candidate_id', 'source_commit', 'package_sha256',
                                       'execution_id', 'source_deployment_identity')}
    return {k: inputs[k] for k in ('candidate_id', 'source_commit', 'package_sha256',
                                   'execution_id')}


def _closure_of(plan, case_id):
    expected = dict(native.native_source_pins(ROOT))
    for name in A.case_sources(CASES[case_id]):
        expected[name] = _sha(ROOT / name)
    return expected


# ---------------------------------------------------------------- fixtures --
def _write(out, inputs, body):
    payload = {'schema': 'fakenet.manual-result.v1', 'case': inputs['case'],
               'fixture': inputs.get('fixture') is True, 'inputs': inputs,
               'identity': _identity_of(inputs)}
    payload.update(body)
    (out / 'manual-result.json').write_text(json.dumps(payload, indent=1) + '\n',
                                            encoding='utf-8')


def _build_executecmd(out, inputs):
    token = inputs['execution_id']
    output = out / 'command-output.txt'
    cfgdir = out / 'config'
    cfgdir.mkdir(parents=True)
    template = ('cmd.exe /c echo {pid} {procname} {src_addr} {src_port} {dst_addr} '
                '{dst_port} ' + token + '>>"' + str(output) + '"')
    cfg = cfgdir / 'executecmd.ini'
    cfg.write_text('[svc]\nProtocol: TCP\nPort: 8080\nExecuteCmd: ' + template
                   + '\n[plain]\nProtocol: TCP\nPort: 8090\n')
    payload = '1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080 ' + token
    raw = (payload + '\n').encode('ascii')
    output.write_bytes(raw)
    expected = 'cmd.exe /c echo ' + payload + '>>"' + str(output) + '"'
    actions = [
        {'name': 'first', 'protocol': 'TCP', 'source_port': 40000, 'destination_port': 8080,
         'pid': 1234, 'first_packet': True, 'executions': 1, 'session_count': 1},
        {'name': 'duplicate', 'protocol': 'TCP', 'source_port': 40000, 'destination_port': 8080,
         'pid': 1234, 'first_packet': False, 'executions': 0, 'session_count': 1},
        {'name': 'missing-pid', 'protocol': 'TCP', 'source_port': 40001, 'destination_port': 8080,
         'pid': None, 'first_packet': True, 'executions': 0, 'session_count': 2},
        {'name': 'no-command-listener', 'protocol': 'TCP', 'source_port': 40002,
         'destination_port': 8090, 'pid': 1234, 'first_packet': True, 'executions': 0,
         'session_count': 3},
        {'name': 'no-default-protocol', 'protocol': 'UDP', 'source_port': 40003,
         'destination_port': 8080, 'pid': 1234, 'first_packet': True, 'executions': 0,
         'session_count': 3}]
    _write(out, inputs, {
        'executecmd': {'configuration': 'config/executecmd.ini',
                       'configuration_sha256': _sha(cfg), 'template': template,
                       'command': expected, 'command_output': str(output),
                       'command_output_sha256': _sha(output), 'command_output_bytes': raw.hex(),
                       'command_output_encoding': 'hex', 'token': token,
                       'first_packet': True, 'duplicate_first_packet': False,
                       'executed': [{'command': expected, 'pid': 43210}],
                       'missing_pid_executions': 0, 'nonmatching_command': None,
                       'bad_format_error': {'type': 'SystemExit', 'code': 1},
                       'actions': actions, 'sessions_after': 0, 'port_forwards_after': 0,
                       'os_platform': 'posix'},
        'source_hashes': {n: _sha(ROOT / n) for n in
                          ('fakenet/diverters/diverterbase.py', 'fakenet/diverters/fnpacket.py')},
        'cleanup': {'stopped': True, 'threads_joined': True, 'sockets_closed': True,
                    'network_restored': True, 'scope': 'in-memory-case-state',
                    'child_exit': 'not-observed', 'child_termination_performed': False},
        'checks': [{'id': x} for x in M.CHECKS['GAP-EXECUTECMD']]})


def _build_diverter_switch(out, inputs):
    cfgdir = out / 'config'
    cfgdir.mkdir(parents=True)
    token = inputs['execution_id']
    values = {}
    for mode, traffic in (('on', 'Yes'), ('off', 'No')):
        cfg = cfgdir / (mode + '.ini')
        cfg.write_text('[FakeNet]\nDivertTraffic: ' + traffic
                       + '\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n')
        calls = ([{'method': m, 'event': e} for m in ('start', 'stop')
                  for e in ('call', 'return')] if mode == 'on' else [])
        obs = out / (mode + '-observation.json')
        obs.write_text(json.dumps({'schema': 'fakenet.switch-observation.v1', 'mode': mode,
                                   'execution_id': token, 'calls': calls,
                                   'stop_complete': True, 'stop_result': True,
                                   'stop_error': None, 'start_error': None,
                                   'stop_errors': []}))
        log = out / (mode + '-core.log')
        lines = (['DEFAULT_INTERCEPTION_READY'] if mode == 'on' else [])
        lines.append('STOP_PHASE_END phase=complete healthy=True')
        log.write_text('\n'.join(lines) + '\n')
        values[mode] = {'config': str(cfg), 'config_sha256': _sha(cfg),
                        'before': {'diverttraffic': traffic, 'diverter': None, 'listeners': 0},
                        'error': None,
                        'after': {'diverter': 'FakeDiverter' if mode == 'on' else None,
                                  'started': mode == 'on', 'stop1': True, 'stop2': True,
                                  'stop_calls': 1 if mode == 'on' else 0, 'listeners': 0},
                        'start_calls': 1 if mode == 'on' else 0,
                        'observation': str(obs), 'observation_sha256': _sha(obs),
                        'core_log': str(log), 'core_log_sha256': _sha(log)}
    _write(out, inputs, {
        'diverter_switch': values,
        'source_hashes': {n: _sha(ROOT / n) for n in
                          ('fakenet/fakenet.py', 'fakenet/diverters/linux.py',
                           'fakenet/diverters/windows.py')},
        'cleanup': {'stopped': True, 'scope': 'observed-core-start-stop',
                    'system_network_restored': 'unverified'},
        'checks': [{'id': x} for x in M.CHECKS['GAP-DIVERTER-SWITCH']]})


def _build_syslog(out, inputs):
    token = inputs['execution_id']
    pid = 43211
    cfgdir = out / 'config'
    cfgdir.mkdir(parents=True)
    cfg = cfgdir / 'syslog.ini'
    cfg.write_text('[FakeNet]\nDivertTraffic: No\n')
    exits = {}
    for mode in ('on', 'off'):
        log = out / ('main-' + mode + '.log')
        log.write_text('pid=%s manual fixture\nLoaded configuration file: %s\n'
                       'FakeNet-NG started successfully\nWill seek stop flag at %s\n'
                       'FakeNet-NG exiting: rc=0\nstop-%s-%s\n'
                       % (pid, cfg, out / ('stop-' + token + '-' + mode),
                          token, mode), encoding='utf-8')
        exits[mode] = {'returncode': 0,
                       'calls': [{'method': m, 'event': 'call'}
                                 for m in ('parse_config', 'start', 'stop')]}
    icmp_line = b'ICMP type 8 code 0 192.0.2.10->192.0.2.20\n'
    (out / 'packet-icmp.bin').write_bytes(bytes.fromhex(
        '4500001c0001000040010000c000020ac00002140800000010e10001'))
    (out / 'packet-tcp.bin').write_bytes(bytes.fromhex(
        '450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000'))
    phases = {}
    for phase, data in (('linux', icmp_line), ('windows', icmp_line),
                        ('nonicmp', b''), ('blocked', b'')):
        (out / ('icmp-' + phase + '.log')).write_bytes(data)
        phases[phase] = {'closed': True}
    (out / 'icmp.log').write_bytes(icmp_line + icmp_line)
    sink = out / 'syslog.sink'
    sink.write_bytes(('"FakeNet-NG": {"loggerName":"FakeNet", "moduleName":"fakenet", '
                      '"levelName":"INFO", "message":"Will seek stop flag at %s"}\n'
                      % (out / ('stop-' + token + '-on'))).encode())
    snapshot = [{'name': name, 'handlers': [], 'level': 20, 'propagate': True,
                 'disabled': False} for name in ('', 'FakeNet', 'Diverter', 'manual-syslog-icmp')]
    (out / 'lifecycle.json').write_text(json.dumps({
        'before': snapshot, 'after': copy.deepcopy(snapshot),
        'created_handlers': [{'class': 'FileHandler', 'closed': True, 'stream_closed': True}],
        'argv_restored': True, 'profile_restored': True, 'pid': pid, 'token': token,
        'calls': exits['on']['calls'] + exits['off']['calls'],
        'records': [{'logger': 'FakeNet', 'process': pid, 'message': 'fixture'}],
        'phases': phases, 'errors': []}, indent=1) + '\n', encoding='utf-8')
    _write(out, inputs, {
        'evidence_kind': 'original-core-and-packet-logging',
        'syslog_icmp': {'config': str(cfg), 'config_sha256': _sha(cfg),
                        'main_rc_on': 0, 'main_rc_off': 0,
                        'main_log_on': str(out / 'main-on.log'),
                        'main_log_off': str(out / 'main-off.log'),
                        'syslog_sink': str(sink), 'syslog_sink_sha256': _sha(sink),
                        'icmp_log': str(out / 'icmp.log'), 'icmp_log_sha256': _sha(out / 'icmp.log'),
                        'icmp_type': 8, 'icmp_code': 0, 'icmp_id': 4321,
                        'owner_pid': pid, 'execution_token': token,
                        'handler_closed': True, 'exits': exits},
        'source_hashes': {n: _sha(ROOT / n) for n in
                          ('fakenet/fakenet.py', 'fakenet/diverters/fnpacket.py',
                           'fakenet/diverters/diverterbase.py')},
        'cleanup': {'scope': 'owned-handlers-and-logger-state', 'stopped': True,
                    'system_network_restored': 'not-exercised'},
        'checks': [{'id': x} for x in M.CHECKS['GAP-SYSLOG-ICMP-LOG']]})


def _build_ctrlc(out, inputs):
    token = inputs['execution_id']
    pid = 43212
    cfgdir = out / 'config'
    cfgdir.mkdir(parents=True)
    cfg = cfgdir / 'shutdown.ini'
    cfg.write_text('[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\n'
                   'LinuxRestrictInterface: Off\n', encoding='ascii')
    branches = {}
    for mode in ('ctrlc', 'ipc'):
        folder = out / mode
        folder.mkdir()
        (folder / 'unrelated.flag').write_text('unrelated-%s-%s\n' % (token, mode),
                                               encoding='utf-8')
        flag = folder / ('stop-%s-%s.flag' % (token, mode))
        events = [{'method': m, 'event': 'call'}
                  for m in ('parse_config', 'start', 'wait_for_shutdown')]
        backend = [{'method': 'start', 'event': 'call'},
                   {'method': 'start', 'event': 'return', 'result': True},
                   {'method': 'wait_for_capture_failure', 'event': 'call'}]
        if mode == 'ipc':
            backend.append({'method': 'wait_for_capture_failure', 'event': 'return', 'result': False})
            events.append({'method': 'stop', 'event': 'call'})
            events.append({'method': 'stop', 'event': 'return', 'result': True})
            observations = {'expected_existed_before_trigger': False,
                            'unrelated_existed_before_trigger': True,
                            'stop_calls_before_correct': 0,
                            'stop_started_before_correct': False,
                            'unrelated_window_epoch': 1.0,
                            'correct_flag_written_epoch': 2.0}
        else:
            backend.append({'method': 'wait_for_capture_failure', 'event': 'error',
                            'type': 'KeyboardInterrupt'})
            observations = {'interrupt_main_epoch': 1.0}
        backend += [{'method': 'stop', 'event': 'call'},
                    {'method': 'stop', 'event': 'return', 'result': True}]
        text = ['pid=%s manual fixture' % pid,
                'Loaded configuration file: %s' % cfg,
                'Will seek stop flag at %s' % flag,
                'DEFAULT_INTERCEPTION_READY',
                'FakeNet-NG started successfully',
                'STOP_PHASE_BEGIN phase=complete',
                'STOP_PHASE_END phase=complete',
                'FakeNet-NG exiting: rc=0']
        if mode == 'ipc':
            text.insert(5, 'Stop flag found at %s' % flag)
        else:
            text.insert(5, 'KeyboardInterrupt received')
        (folder / 'main.log').write_text('\n'.join(text) + '\n', encoding='utf-8')
        branches[mode] = {'config': str(cfg), 'config_sha256': _sha(cfg),
                          'log': str(folder / 'main.log'),
                          'log_sha256': _sha(folder / 'main.log'),
                          'flag': str(flag), 'flag_exists_after': False,
                          'unrelated_flag': str(folder / 'unrelated.flag'),
                          'unrelated_exists_after': True,
                          'unrelated_text_after': 'unrelated-%s-%s\n' % (token, mode),
                          'rc': 0, 'error': None, 'calls': events,
                          'wait_entered': True, 'watcher_fired': True,
                          'watcher_alive': False, 'watcher_errors': [],
                          'observations': observations,
                          'runtime': {'fakenet_class': 'Fakenet', 'listener_count': 0,
                                      'diverter_class': 'FakeDiverter',
                                      'backend_observations': backend,
                                      'start_calls': 1, 'stop_calls': 1, 'wait_calls': 1,
                                      'backend_started': True, 'backend_stopped': True,
                                      'stop_started': True, 'stop_complete': True,
                                      'stop_result': True, 'stop_error': None},
                          'stop_flag_argument': str(flag),
                          'backend_wrappers_restored': True}
    logger_snapshot = [{'name': n, 'handlers': [], 'level': 20, 'propagate': True,
                        'disabled': False} for n in ('', 'FakeNet')]
    signal_ids = {'SIGINT': 1, 'SIGTERM': 2}
    (out / 'lifecycle.json').write_text(json.dumps({
        'scope': 'owned-main-ctrlc-file-ipc-and-runtime-state',
        'signal_ids_before': signal_ids, 'signal_ids_after': dict(signal_ids),
        'signals_restored': True,
        'logger_before': logger_snapshot, 'logger_after': copy.deepcopy(logger_snapshot),
        'logger_restored': True, 'argv_restored': True, 'profile_restored': True,
        'owned_threads_absent': True, 'thread_names': ['MainThread'],
        'errors': [], 'pid': pid, 'token': token,
        'created_handlers': [{'class': 'FileHandler', 'closed': True}]}, indent=1) + '\n',
        encoding='utf-8')
    _write(out, inputs, {
        'evidence_kind': 'original-main-ctrl-c-and-file-ipc',
        'ctrlc_ipc': {'config': str(cfg), 'config_sha256': _sha(cfg),
                      'branches': branches, 'owner_pid': pid, 'execution_token': token,
                      'checks': list(M.CHECKS['GAP-CTRLC-IPC'])},
        'source_hashes': {'fakenet/fakenet.py': _sha(ROOT / 'fakenet/fakenet.py')},
        'cleanup': {'scope': 'owned-main-ctrlc-file-ipc-and-runtime-state',
                    'stopped': True, 'threads_joined': True, 'flags_removed': True,
                    'logger_restored': True, 'argv_restored': True,
                    'profile_restored': True, 'signals_restored': True,
                    'system_network_restored': 'not-exercised', 'system_console_used': False},
        'checks': [{'id': x} for x in M.CHECKS['GAP-CTRLC-IPC']]})


NAMES = ('DNSListener', 'HTTPListener', 'FTPListener', 'IRCListener', 'POPListener',
         'SMTPListener', 'RawListener', 'TFTPListener', 'ProxyListener')


def _build_standalone(out, inputs):
    token = inputs['execution_id']
    pid = 43213
    html = (ROOT / 'fakenet/defaultFiles/FakeNet.html').read_bytes()
    txt = (ROOT / 'fakenet/defaultFiles/FakeNet.txt').read_bytes()
    results = {}
    log_lines = []
    for index, name in enumerate(NAMES):
        folder = out / name
        folder.mkdir()
        if name == 'DNSListener':
            # Hand-built wire-legal DNS query/answer (no library needed to
            # construct; the oracle itself still parses with dnslib).
            qname = b'\x06google\x03com\x00'
            request = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                       + qname + b'\x00\x01\x00\x01')
            response = (b'\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                        + qname + b'\x00\x01\x00\x01'
                        + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01')
        elif name in ('HTTPListener', 'ProxyListener'):
            request = b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'
            response = (b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(html)) + html
        elif name == 'FTPListener':
            request = b'USER user\r\nPASS password\r\nQUIT\r\n'
            response = b'220 welcome\r\n331 need password\r\n230 logged in\r\n221 bye\r\n'
        elif name == 'IRCListener':
            request = b'NICK standalone\r\n'
            response = b':server 001 standalone welcome\r\n'
        elif name == 'POPListener':
            request = b'USER standalone\r\nPASS test\r\nSTAT\r\nQUIT\r\n'
            response = b'+OK POP3 ready\r\n+OK User accepted\r\n+OK 2 320\r\n+OK bye\r\n'
        elif name == 'SMTPListener':
            request = b'EHLO standalone\r\nQUIT\r\n'
            response = b'220 smtp ready\r\n250 OK\r\n221 bye\r\n'
        elif name == 'RawListener':
            request = b'HELO\n'
            response = request
        else:
            request = b'\x00\x01test.txt\x00octet\x00'
            response = b'\x00\x03\x00\x01' + txt[:512]
        (folder / 'request.bin').write_bytes(request)
        (folder / 'response.bin').write_bytes(response)
        required = {'main', '__init__', 'start', 'stop'}
        if name not in ('RawListener', 'TFTPListener', 'ProxyListener'):
            required.add('test')
        if name == 'ProxyListener':
            required = {'main', 'handle'}
        calls = [{'event': 'call', 'function': fn, 'line': 10, 'thread': 1}
                 for fn in sorted(required)]
        (folder / 'calls.json').write_text(json.dumps(calls))
        resources = {'threads': [{'name': 'owned-' + name, 'ident': index + 1, 'alive': False}],
                     'sockets': [{'fileno': -1}]}
        (folder / 'resources.json').write_text(json.dumps(resources))
        results[name] = {'script': str(ROOT / ('fakenet/listeners/' + name + '.py')),
                         'main_called': True, 'embedded_test_called': 'test' in required,
                         'listener_started': True, 'endpoint': ['127.0.0.1', 20001 + index],
                         'config': {'ipaddr': '127.0.0.1', 'port': '0'},
                         'request': str(folder / 'request.bin'),
                         'request_sha256': _sha(folder / 'request.bin'),
                         'response': str(folder / 'response.bin'),
                         'response_sha256': _sha(folder / 'response.bin'),
                         'calls_sha256': _sha(folder / 'calls.json'),
                         'resources_sha256': _sha(folder / 'resources.json'),
                         'main_error': None, 'probe_error': None, 'stop_errors': [],
                         'thread_alive': False, 'socket_closed': True,
                         'hooks_restored': True, 'compatibility': None,
                         'log': str(out / 'standalone.log')}
        log_lines.append('MANUAL-STANDALONE %s token=%s' % (name, token))
    log = out / 'standalone.log'
    log.write_text('\n'.join(log_lines) + '\n', encoding='utf-8')
    owner = {'schema': 'fakenet.owner.v1', 'pid': pid, 'execution_token': token,
             'started_at': '2026-10-30T00:00:00+00:00'}
    (out / 'owner.json').write_text(json.dumps(owner))
    _write(out, inputs, {
        'evidence_kind': 'original-standalone-scripts-and-listeners',
        'standalone': {'scripts': results, 'log': str(log), 'log_sha256': _sha(log),
                       'owner_pid': pid, 'execution_token': token,
                       'owner_sha256': _sha(out / 'owner.json')},
        'source_hashes': {('fakenet/listeners/' + n + '.py'): _sha(ROOT / ('fakenet/listeners/' + n + '.py'))
                          for n in NAMES},
        'cleanup': {'scope': 'owned-standalone-listeners', 'stopped': True,
                    'system_network_restored': 'not-exercised', 'system_console_used': False},
        'checks': [{'id': x} for x in M.CHECKS['GAP-STANDALONE-LISTENERS']]})


BUILDERS = {'GAP-EXECUTECMD': _build_executecmd,
            'GAP-DIVERTER-SWITCH': _build_diverter_switch,
            'GAP-SYSLOG-ICMP-LOG': _build_syslog,
            'GAP-CTRLC-IPC': _build_ctrlc,
            'GAP-STANDALONE-LISTENERS': _build_standalone}


def _v5_inputs(work, case_id, plan):
    inputs = native.manual_inputs(plan, CASES[case_id], str(work))
    return inputs


def _v1_inputs(out, case_id, execution_id):
    return {'schema': 'fakenet.manual-input.v1', 'case': case_id,
            'candidate_id': 'manual-candidate', 'source_commit': HEAD,
            'package_sha256': 'ab' * 32, 'execution_id': execution_id,
            'owned_root': str(out), 'config': str(out / 'config'),
            'responsea': '192.0.2.55', 'fixture': True}


# ------------------------------------------------------------------- tests --
class FiveSourcePlanTests(_NoRealEffects):
    """FMS-A1: the real plan CLI derives/freezes each five-case identity."""

    def test_identity_from_full_registered_closure(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                work = Path(tempfile.mkdtemp(prefix='fnreg-fms-plan-', dir='/tmp'))
                plan = _source_plan(work, case_id)
                identity = plan['candidate']['source_deployment_identity']
                closure = plan['source_deployment_closure']
                self.assertEqual(case_id, identity['case_id'])
                self.assertEqual(HEAD, identity['source_commit'])
                payload = json.dumps(closure, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode('utf-8')
                self.assertEqual(hashlib.sha256(payload).hexdigest(),
                                 identity['source_hashes_sha256'])
                self.assertEqual(_closure_of(plan, case_id), closure)
                for key in ('package_path', 'package_manifest', 'package_sha256'):
                    self.assertIsNone(plan['candidate'].get(key))

    def test_package_field_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-pkg-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        candidate = json.loads((work / 'candidate.json').read_text())
        candidate['package_sha256'] = 'a' * 64
        code = _replan(work, candidate, plan['environment'], ['GAP-EXECUTECMD'],
                       work / 'run' / 'pkg' / 'p.json')
        self.assertEqual(2, code)

    def test_mixed_selection_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-mix-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        code = _replan(work, json.loads((work / 'candidate.json').read_text()),
                       plan['environment'], ['GAP-EXECUTECMD', 'GAP-NCSI'],
                       work / 'run' / 'mixed' / 'p.json')
        self.assertEqual(2, code)

    def test_dump_mixed_selection_still_dump_identity(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-dump-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        output = work / 'run' / 'dump-mixed' / 'plan.json'
        code = _replan(work, json.loads((work / 'candidate.json').read_text()),
                       plan['environment'], ['GAP-DUMPPACKETS', 'GAP-NCSI'], output)
        self.assertEqual(0, code)
        mixed = json.loads(output.read_text())
        self.assertEqual('GAP-DUMPPACKETS',
                         mixed['candidate']['source_deployment_identity']['case_id'])

    def test_forged_supplied_identity_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-forge-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-SYSLOG-ICMP-LOG')
        candidate = json.loads((work / 'candidate.json').read_text())
        candidate['source_deployment_identity'] = {
            'schema': 'fakenet.source-deployment-identity.v1', 'source_commit': HEAD,
            'case_id': 'GAP-SYSLOG-ICMP-LOG', 'source_hashes_sha256': '0' * 64}
        code = _replan(work, candidate, plan['environment'], ['GAP-SYSLOG-ICMP-LOG'],
                       work / 'run' / 'forged' / 'p.json')
        self.assertEqual(2, code)


class FivePreEffectGateTests(_NoRealEffects):
    """FMS-A2: host/guest refusals land before channel/mkdir/producer."""

    def _request(self, work, case_id):
        plan = _source_plan(work, case_id)
        driver, checks, request = native._expected_remote_request(ROOT, CASES[case_id], plan)
        return request

    def _guest_boundary(self, request):
        import acceptance_runtime as rt
        output = Path(tempfile.mkdtemp(prefix='fnreg-fms-guest-', dir='/tmp')) / 'out'
        request = dict(request)
        request['output_root'] = str(output)
        with mock.patch.object(rt, 'require_target', return_value=request['target']):
            with mock.patch.object(native, 'run_production',
                                   side_effect=RuntimeError('PRODUCER_BOUNDARY')):
                try:
                    guest.execute(request, ROOT)
                except RuntimeError:
                    return 'producer-boundary', output.exists()
                except ValueError as error:
                    return 'refused:%s' % error, output.exists()
        return 'completed', output.exists()

    def test_valid_controls_reach_producer_boundary(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                work = Path(tempfile.mkdtemp(prefix='fnreg-fms-ok-', dir='/tmp'))
                request = self._request(work, case_id)
                outcome, created = self._guest_boundary(request)
                self.assertEqual('producer-boundary', outcome)
                self.assertTrue(created)

    def test_subset_closure_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-sub-', dir='/tmp'))
        request = self._request(work, 'GAP-EXECUTECMD')
        member = sorted(request['source_hashes'])[0]
        subset = {k: v for k, v in request['source_hashes'].items() if k != member}
        payload = json.dumps(subset, ensure_ascii=False, sort_keys=True,
                             separators=(',', ':')).encode('utf-8')
        request['source_hashes'] = subset
        request['candidate']['source_deployment_identity']['source_hashes_sha256'] = \
            hashlib.sha256(payload).hexdigest()
        outcome, created = self._guest_boundary(request)
        self.assertIn('not the registered selection M', outcome)
        self.assertFalse(created)

    def test_source_plus_package_refused_before_mkdir(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-spkg-', dir='/tmp'))
        request = self._request(work, 'GAP-DIVERTER-SWITCH')
        request['candidate']['package_sha256'] = 'a' * 64
        outcome, created = self._guest_boundary(request)
        self.assertTrue(outcome.startswith('refused'), outcome)
        self.assertFalse(created)

    def test_undeclared_null_package_refused_before_mkdir(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                work = Path(tempfile.mkdtemp(prefix='fnreg-fms-null-', dir='/tmp'))
                request = self._request(work, case_id)
                request['candidate'] = dict(request['candidate'])
                request['candidate'].pop('deployment_kind')
                outcome, created = self._guest_boundary(request)
                self.assertIn('package identity or the explicit source deployment kind', outcome)
                self.assertFalse(created)


class FiveInputSchemaTests(_NoRealEffects):
    """FMS-04: manual-input.v5 field set, case binding, v1..v4 compatibility."""

    def test_v5_derived_for_each_case(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                work = Path(tempfile.mkdtemp(prefix='fnreg-fms-v5-', dir='/tmp'))
                plan = _source_plan(work, case_id)
                value = _v5_inputs(work, case_id, plan)
                self.assertEqual('fakenet.manual-input.v5', value['schema'])
                self.assertIsNone(value['package_sha256'])
                self.assertEqual(sorted(value), sorted(
                    ['schema', 'case', 'candidate_id', 'source_commit', 'package_sha256',
                     'execution_id', 'owned_root', 'config', 'responsea', 'fixture',
                     'source_deployment_identity']))
                self.assertEqual(case_id,
                                 value['source_deployment_identity']['case_id'])

    def test_v5_field_set_and_identity_strictness(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-fields-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        value = _v5_inputs(work, 'GAP-EXECUTECMD', plan)
        extra = dict(value, unapproved='x')
        with self.assertRaisesRegex(ValueError, 'field set differs'):
            M.validate_inputs('GAP-EXECUTECMD', extra)
        missing = {k: v for k, v in value.items() if k != 'responsea'}
        with self.assertRaisesRegex(ValueError, 'field set differs'):
            M.validate_inputs('GAP-EXECUTECMD', missing)

    def test_v3_v4_refuse_five_cases(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-s34-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        value = _v5_inputs(work, 'GAP-EXECUTECMD', plan)
        for schema in ('fakenet.manual-input.v3', 'fakenet.manual-input.v4'):
            with self.subTest(schema=schema):
                broken = dict(value, schema=schema)
                with self.assertRaisesRegex(ValueError, 'fixed to'):
                    M.validate_inputs('GAP-EXECUTECMD', broken)

    def test_v5_refuses_dump_and_list(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-s5dl-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-EXECUTECMD')
        value = _v5_inputs(work, 'GAP-EXECUTECMD', plan)
        for case_id in ('GAP-DUMPPACKETS', 'GAP-LIST-MUTEX'):
            with self.subTest(case=case_id):
                broken = dict(value, case=case_id)
                with self.assertRaisesRegex(ValueError, 'fixed to'):
                    M.validate_inputs(case_id, broken)

    def test_v1_packaged_inputs_still_valid_with_four_keys(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-v1-', dir='/tmp'))
        out = work / 'driver'
        value = _v1_inputs(out, 'GAP-EXECUTECMD', 'fms-v1-compat')
        M.validate_inputs('GAP-EXECUTECMD', value)
        identity = M._result_identity(value)
        self.assertEqual(sorted(identity),
                         ['candidate_id', 'execution_id', 'package_sha256', 'source_commit'])

    def test_unknown_schema_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-fms-unk-', dir='/tmp'))
        plan = _source_plan(work, 'GAP-CTRLC-IPC')
        value = _v5_inputs(work, 'GAP-CTRLC-IPC', plan)
        broken = dict(value, schema='fakenet.manual-input.v9')
        with self.assertRaisesRegex(ValueError, 'schema/case mismatch'):
            M.validate_inputs('GAP-CTRLC-IPC', broken)


class FiveOracleChainTests(_NoRealEffects):
    """FMS-A3: STATIC benign fixtures through the original oracles; the five
    real producers never run (blocked by the class-level effect guards)."""

    def _fixture(self, work_prefix, case_id, inputs_factory=None):
        work = Path(tempfile.mkdtemp(prefix=work_prefix, dir='/tmp'))
        if inputs_factory is None:
            plan = _source_plan(work, case_id)
            inputs = native.manual_inputs(plan, CASES[case_id], str(work))
        else:
            inputs = inputs_factory(work, case_id)
        # FMS-A3: every local static fixture is EXPLICIT fixture evidence.
        inputs = dict(inputs, fixture=True)
        out = Path(inputs['owned_root'])
        out.mkdir(parents=True, exist_ok=False)
        BUILDERS[case_id](out, inputs)
        return out, inputs

    def _assert_oracle_refusal(self, out, case_id, inputs, needle,
                               allow_fixture=True):
        """Collecting oracles record the refusal; raising oracles raise it."""
        try:
            rows, clean, detail = O.evaluate(ROOT, out, case_id, inputs,
                                             allow_fixture=allow_fixture)
        except ValueError as exc:
            self.assertIn(needle, str(exc))
            return
        self.assertFalse(clean, detail)
        self.assertIn(needle, json.dumps(detail))

    def _dnslib_available(self):
        import importlib.util
        return importlib.util.find_spec('dnslib') is not None

    def test_static_fixture_passes_original_oracle_v5(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                if case_id == 'GAP-STANDALONE-LISTENERS' and not self._dnslib_available():
                    self.skipTest('dnslib is not installed in this local environment; '
                                  'the standalone oracle itself imports it for the DNS '
                                  'wire check - no dependency is installed here')
                out, inputs = self._fixture('fnreg-fms-oracle-', case_id)
                rows, clean, detail = O.evaluate(ROOT, out, case_id, inputs,
                                                 allow_fixture=True)
                self.assertTrue(clean, detail)
                self.assertEqual(M.CHECKS[case_id], [r['id'] for r in rows])
                self.assertFalse(EFFECT_MARKER.exists())

    def test_v1_four_key_fixture_still_passes(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                if case_id == 'GAP-STANDALONE-LISTENERS' and not self._dnslib_available():
                    self.skipTest('dnslib not installed locally (see v5 pass test)')
                out, inputs = self._fixture(
                    'fnreg-fms-v1o-', case_id,
                    lambda work, cid: _v1_inputs(work / 'driver', cid, 'fms-v1-oracle'))
                rows, clean, detail = O.evaluate(ROOT, out, case_id, inputs,
                                                 allow_fixture=True)
                self.assertTrue(clean, detail)

    def test_v5_identity_tamper_refused(self):
        for case_id in FIVE:
            with self.subTest(case=case_id):
                out, inputs = self._fixture('fnreg-fms-tamper-', case_id)
                path = out / 'manual-result.json'
                value = json.loads(path.read_text())
                value['identity']['source_deployment_identity']['source_hashes_sha256'] = '1' * 64
                path.write_text(json.dumps(value, indent=1) + '\n')
                self._assert_oracle_refusal(out, case_id, inputs, 'identity mismatch')

    def test_v5_identity_extra_key_refused(self):
        out, inputs = self._fixture('fnreg-fms-extra-', 'GAP-STANDALONE-LISTENERS')
        path = out / 'manual-result.json'
        value = json.loads(path.read_text())
        value['identity']['unapproved_extra_field'] = 'must-refuse'
        path.write_text(json.dumps(value) + '\n')
        self._assert_oracle_refusal(out, 'GAP-STANDALONE-LISTENERS', inputs,
                                    'identity mismatch')

    def test_inputs_tamper_refused(self):
        out, inputs = self._fixture('fnreg-fms-inputs-', 'GAP-DIVERTER-SWITCH')
        path = out / 'manual-result.json'
        value = json.loads(path.read_text())
        value['inputs']['responsea'] = '198.51.100.1'
        path.write_text(json.dumps(value) + '\n')
        self._assert_oracle_refusal(out, 'GAP-DIVERTER-SWITCH', inputs,
                                    'frozen inputs mismatch')

    def test_fixture_cannot_native_credit(self):
        out, inputs = self._fixture('fnreg-fms-native-', 'GAP-CTRLC-IPC')
        self._assert_oracle_refusal(out, 'GAP-CTRLC-IPC', inputs,
                                    'fixture cannot native credit', allow_fixture=False)


if __name__ == '__main__':
    unittest.main()
