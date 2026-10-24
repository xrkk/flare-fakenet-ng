#!/usr/bin/env python3
"""Read original wire bytes and frozen expectations, never producer verdicts."""
from __future__ import annotations
from collections import Counter
from datetime import timezone
import email.utils
import configparser
import hashlib
import json
import struct
from pathlib import Path
RAW=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\nContent-Length: 35\r\nConnection: close\r\n\r\nbody<RAW-DATE>\x00\xff'
STATIC=b'static-<RAW-DATE>'

def _evaluate_syslog_icmp(root, original, expected_inputs, allow_fixture=False):
    base = Path(original).absolute()
    errors = []
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)
    def read(name):
        path = base / name
        require(path.is_file() and not any(part.is_symlink() for part in (path, *path.parents)), 'missing/linked original: ' + name)
        return path.read_bytes()
    try:
        v = json.loads(read('manual-result.json'))
        require(str(base) == expected_inputs.get('owned_root') and v.get('inputs') == expected_inputs, 'owned/frozen inputs mismatch')
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-SYSLOG-ICMP-LOG', 'case/schema mismatch')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('checks') == [{'id': key} for key in ('syslog', 'icmp', 'owner')], 'checks mismatch')
        require(v.get('cleanup') == {'scope': 'owned-handlers-and-logger-state', 'stopped': True, 'system_network_restored': 'not-exercised'}, 'cleanup scope mismatch')
        d = v['syslog_icmp']
        for key, name in (('config', 'config/syslog.ini'), ('main_log_on', 'main-on.log'), ('main_log_off', 'main-off.log'), ('icmp_log', 'icmp.log'), ('syslog_sink', 'syslog.sink')):
            require(d.get(key) == str(base / name), 'owned original path mismatch: ' + key)
        config = read('config/syslog.ini')
        require(config == b'[FakeNet]\nDivertTraffic: No\n' and d.get('config_sha256') == hashlib.sha256(config).hexdigest(), 'exact configuration mismatch')
        require(read('packet-icmp.bin') == bytes.fromhex('4500001c0001000040010000c000020ac00002140800000010e10001'), 'ICMP original bytes mismatch')
        require(read('packet-tcp.bin') == bytes.fromhex('450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000'), 'TCP original bytes mismatch')
        state = json.loads(read('lifecycle.json'))
        require(not state.get('errors') and state.get('before') == state.get('after') and len(state.get('before', [])) == 4 and state.get('argv_restored') is True and state.get('profile_restored') is True, 'logger/argv/profile restoration mismatch')
        require(state.get('created_handlers') and all(item.get('closed') is True and item.get('stream_closed') is True for item in state['created_handlers']) and d.get('handler_closed') is True, 'owned handler not closed')
        token = expected_inputs['execution_id']
        pid = state['pid']
        require(type(pid) is int and pid > 0 and d.get('owner_pid') == pid and d.get('execution_token') == token and state.get('token') == token, 'owner/token mismatch')
        for mode in ('on', 'off'):
            require(d.get('main_rc_' + mode) == 0, 'main exit mismatch')
            messages = read('main-' + mode + '.log').decode('utf-8')
            require('pid=%s ' % pid in messages and 'Loaded configuration file: ' + str(base / 'config/syslog.ini') in messages and 'FakeNet-NG started successfully' in messages and 'FakeNet-NG exiting: rc=0' in messages and 'stop-' + token + '-' + mode in messages, 'main log original trigger/owner missing')
            calls = d.get('exits', {}).get(mode, {}).get('calls', [])
            require([item.get('method') for item in calls] == ['parse_config', 'start', 'stop'], 'original main call chain mismatch')
            require(not (base / ('stop-' + token + '-' + mode)).exists(), 'owned stop flag not consumed')
        sink = read('syslog.sink')
        require(d.get('syslog_sink_sha256') == hashlib.sha256(sink).hexdigest(), 'syslog sink hash mismatch')
        marker = ('"FakeNet-NG": {"loggerName":"FakeNet", "moduleName":"fakenet", "levelName":"INFO", "message":"Will seek stop flag at ' + str(base / ('stop-' + token + '-on')) + '"}').encode()
        require(marker in sink and ('stop-' + token + '-off').encode() not in sink, 'original syslog formatter/on-off arrival mismatch')
        expect = b'ICMP type 8 code 0 192.0.2.10->192.0.2.20\n'
        for phase in ('linux', 'windows', 'nonicmp', 'blocked'):
            require(read('icmp-' + phase + '.log') == (expect if phase in ('linux', 'windows') else b''), 'ICMP phase bytes mismatch: ' + phase)
            require(state.get('phases', {}).get(phase, {}).get('closed') is True, 'ICMP handler not closed: ' + phase)
        icmp = read('icmp.log')
        require(icmp == expect * 2 and d.get('icmp_log_sha256') == hashlib.sha256(icmp).hexdigest(), 'ICMP aggregate bytes mismatch')
        require((d.get('icmp_type'), d.get('icmp_code'), d.get('icmp_id')) == (8, 0, 4321), 'ICMP parser fields mismatch')
        require(state.get('records') and all(row.get('process') == pid for row in state['records']), 'original LogRecord owner mismatch')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in ('fakenet/fakenet.py', 'fakenet/diverters/fnpacket.py', 'fakenet/diverters/diverterbase.py')}, 'source binding mismatch')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in ('syslog', 'icmp', 'owner')], not errors, {'failures': errors}

def _evaluate_ctrlc_ipc(root, original, expected_inputs, allow_fixture=False):
    base = Path(original).resolve()
    errors = []
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)
    def read(name):
        path = base / name
        require(path.is_file() and not path.is_symlink() and not any(part.is_symlink() for part in path.parents), 'missing/linked original: ' + name)
        return path.read_bytes()
    try:
        v = json.loads(read('manual-result.json'))
        require(str(base) == expected_inputs.get('owned_root') and v.get('inputs') == expected_inputs, 'owned/frozen inputs mismatch')
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-CTRLC-IPC', 'case/schema mismatch')
        require(v.get('evidence_kind') == 'original-main-ctrl-c-and-file-ipc', 'original branch provenance missing')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('checks') == [{'id': key} for key in ('ctrlc', 'ipc-stop', 'owned-exit')], 'checks mismatch')
        d = v['ctrlc_ipc']
        require(d.get('checks') == ['ctrlc', 'ipc-stop', 'owned-exit'], 'inner checks mismatch')
        require(set(d.get('branches') or {}) == {'ctrlc', 'ipc'}, 'exact Ctr-C/IPC branch set differs')
        pid = d.get('owner_pid'); token = d.get('execution_token')
        require(type(pid) is int and pid > 0 and d.get('execution_token') == expected_inputs['execution_id'] and token, 'owner/token mismatch')
        config = read('config/shutdown.ini')
        require(config == b'[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n', 'exact configuration mismatch')
        require(d.get('config') == str(base / 'config/shutdown.ini') and d.get('config_sha256') == hashlib.sha256(config).hexdigest(), 'configuration path/hash mismatch')
        state = json.loads(read('lifecycle.json'))
        require(state.get('pid') == pid and state.get('token') == token, 'lifecycle owner/token mismatch')
        require(state.get('scope') == 'owned-main-ctrlc-file-ipc-and-runtime-state', 'lifecycle scope mismatch')
        require(state.get('signals_restored') is True and state.get('logger_restored') is True and state.get('argv_restored') is True and state.get('profile_restored') is True, 'owned state not restored')
        require(state.get('signal_ids_before') == state.get('signal_ids_after') and set(state.get('signal_ids_before', {})) == {'SIGINT','SIGTERM'}, 'signal snapshots differ')
        require(state.get('logger_before') == state.get('logger_after') and len(state.get('logger_before', [])) == 2, 'logger snapshots differ')
        require(state.get('owned_threads_absent') is True and not any(name.startswith('owned-') and token in name for name in state.get('thread_names', [])), 'owned watcher thread remains')
        require(state.get('errors') == [], 'producer errors present')
        require(all(item.get('closed') is True for item in state.get('created_handlers', [])) and state.get('created_handlers'), 'owned logging handler not closed')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in ('fakenet/fakenet.py',)}, 'source binding mismatch')
        for mode in ('ctrlc', 'ipc'):
            item = d['branches'][mode]
            log_path = base / mode / 'main.log'
            flag_path = base / mode / ('stop-' + token + '-' + mode + '.flag')
            unrelated_path = base / mode / 'unrelated.flag'
            require(item.get('config') == str(base / 'config/shutdown.ini') and item.get('log') == str(log_path) and item.get('flag') == str(flag_path) and item.get('unrelated_flag') == str(unrelated_path), 'branch-owned parameter path mismatch: ' + mode)
            require(item.get('config_sha256') == hashlib.sha256(config).hexdigest(), 'branch configuration hash mismatch: ' + mode)
            require(item.get('log_sha256') == hashlib.sha256(read(mode + '/main.log')).hexdigest(), 'branch log hash mismatch: ' + mode)
            require(item.get('stop_flag_argument') == str(flag_path), 'original -f argument mismatch: ' + mode)
            require(item.get('flag_exists_after') is False and not flag_path.exists(), 'owned stop flag remains: ' + mode)
            require(item.get('rc') == 0 and item.get('error') is None, 'original main did not exit cleanly: ' + mode)
            require(item.get('wait_entered') is True and item.get('watcher_fired') is True and item.get('watcher_alive') is False and item.get('watcher_errors') == [], 'wait trigger/thread mismatch: ' + mode)
            calls = item.get('calls') or []
            call_methods = [row.get('method') for row in calls if row.get('event') == 'call']
            # CPython stops delivering profile events once interrupt_main raises
            # KeyboardInterrupt, so the Ctrl-C branch proves stop through the
            # original log and actual runtime state; the file-IPC branch keeps
            # the full profiled chain.
            expected_calls = ['parse_config', 'start', 'wait_for_shutdown'] + (['stop'] if mode == 'ipc' else [])
            require(call_methods == expected_calls, 'original main call chain mismatch: ' + mode)
            if mode == 'ipc':
                require(any(row.get('method') == 'stop' and row.get('event') == 'return' and row.get('result') is True for row in calls), 'original stop return missing/failed: ' + mode)
            runtime = item.get('runtime') or {}
            observed = runtime.get('backend_observations') or []
            allowed_methods = ('start', 'stop', 'wait_for_capture_failure')
            require(len(observed) >= 4 and all(isinstance(row, dict) and row.get('method') in allowed_methods
                    and row.get('event') in ('call', 'return', 'error') for row in observed), 'backend observation shape mismatch: ' + mode)
            require(observed[0] == {'method': 'start', 'event': 'call'}
                    and observed[1].get('method') == 'start' and observed[1].get('event') == 'return'
                    and observed[1].get('result') is not False, 'backend start call/return mismatch: ' + mode)
            require(observed[-2] == {'method': 'stop', 'event': 'call'}
                    and observed[-1].get('method') == 'stop' and observed[-1].get('event') == 'return'
                    and observed[-1].get('result') is True, 'backend stop call/return failed: ' + mode)
            middle = observed[2:-2]
            wait_calls = 0
            wait_interrupts = 0
            index = 0
            while index < len(middle):
                call = middle[index]
                require(call.get('method') == 'wait_for_capture_failure' and call.get('event') == 'call',
                        'backend unexpected wait ordering: ' + mode)
                require(index + 1 < len(middle), 'backend wait call has no terminal: ' + mode)
                terminal = middle[index + 1]
                require(terminal.get('method') == 'wait_for_capture_failure'
                        and terminal.get('event') in ('return', 'error'), 'backend wait terminal mismatch: ' + mode)
                wait_calls += 1
                if terminal.get('event') == 'error':
                    require(mode == 'ctrlc' and terminal.get('type') == 'KeyboardInterrupt',
                            'backend unexpected wait error: ' + mode)
                    wait_interrupts += 1
                    require(wait_interrupts == 1 and index + 2 == len(middle),
                            'backend Ctrl-C wait interruption must be unique and final: ' + mode)
                index += 2
            require(wait_calls >= 1, 'backend wait missing: ' + mode)
            require(runtime.get('start_calls') == 1 and runtime.get('stop_calls') == 1
                    and runtime.get('wait_calls') == wait_calls, 'backend actual call counts mismatch: ' + mode)
            require(item.get('backend_wrappers_restored') is True, 'backend method observations not restored')
            require(runtime.get('listener_count') == 0 and runtime.get('diverter_class') and runtime.get('start_calls') == 1 and runtime.get('stop_calls') == 1 and runtime.get('wait_calls') >= 1 and runtime.get('backend_started') is True and runtime.get('backend_stopped') is True and runtime.get('stop_started') is True and runtime.get('stop_complete') is True and runtime.get('stop_result') is True and runtime.get('stop_error') is None, 'original runtime start/stop state mismatch: ' + mode)
            text = read(mode + '/main.log').decode('utf-8')
            require(('pid=%s ' % pid) in text and ('Loaded configuration file: ' + str(base / 'config/shutdown.ini')) in text and ('Will seek stop flag at ' + str(flag_path)) in text and text.count('DEFAULT_INTERCEPTION_READY') == 1 and text.count('FakeNet-NG started successfully') == 1 and 'STOP_PHASE_BEGIN phase=complete' in text and 'STOP_PHASE_END phase=complete' in text and 'FakeNet-NG exiting: rc=0' in text, 'original main/log chain missing: ' + mode)
            unrelated = unrelated_path.read_bytes()
            require(item.get('unrelated_exists_after') is True and unrelated == ('unrelated-' + token + '-' + mode + '\n').encode(), 'unrelated flag damaged/changed: ' + mode)
            observations = item.get('observations') or {}
            if mode == 'ipc':
                require('Stop flag found at ' + str(flag_path) in text and 'KeyboardInterrupt' not in text, 'IPC stop flag branch/log mismatch')
                require(observations.get('expected_existed_before_trigger') is False and observations.get('unrelated_existed_before_trigger') is True and observations.get('stop_calls_before_correct') == 0 and observations.get('stop_started_before_correct') is False and observations.get('unrelated_window_epoch') < observations.get('correct_flag_written_epoch'), 'IPC unrelated/trigger ordering mismatch')
            else:
                require('KeyboardInterrupt' in text and 'Stop flag found' not in text and observations.get('interrupt_main_epoch'), 'Ctrl-C branch/log mismatch')
        require(v.get('cleanup') == {'scope': 'owned-main-ctrlc-file-ipc-and-runtime-state', 'stopped': True, 'threads_joined': True, 'flags_removed': True, 'logger_restored': True, 'argv_restored': True, 'profile_restored': True, 'signals_restored': True, 'system_network_restored': 'not-exercised', 'system_console_used': False}, 'cleanup/provenance mismatch')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in ('ctrlc', 'ipc-stop', 'owned-exit')], not errors, {'failures': errors}

def _evaluate_linux_flush_interface(root, original, expected_inputs, allow_fixture=False):
    base = Path(original).resolve()
    errors = []
    scenarios = {
        'flush_on': dict(mode='SingleHost', flush=True, dns='service dns-clean restart', restrict='Off',
                         iface=None, chains=(('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=0),
        'flush_off': dict(mode='SingleHost', flush=False, dns=None, restrict='Off',
                          iface=None, chains=(('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=None),
        'dns_nonzero': dict(mode='SingleHost', flush=False, dns='false', restrict='Off',
                            iface=None, chains=(('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=1),
        'multihost_iface': dict(mode='MultiHost', flush=False, dns=None, restrict='eth1',
                                iface='eth1', chains=(('PREROUTING', 'raw'), ('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=None),
        'multihost_off': dict(mode='MultiHost', flush=False, dns=None, restrict='Off',
                              iface=None, chains=(('PREROUTING', 'raw'), ('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=None),
        'singlehost_iface': dict(mode='SingleHost', flush=False, dns=None, restrict='eth1',
                                 iface=None, chains=(('INPUT', 'mangle'), ('OUTPUT', 'raw')), dns_rc=None),
    }
    def require(ok, reason):
        if not ok:
            raise ValueError(reason)
    def read(name):
        path = base / name
        require(path.is_file() and not path.is_symlink() and not any(part.is_symlink() for part in path.parents), 'missing/linked original: ' + name)
        return path.read_bytes()
    def expected_config(spec):
        lines = ['[FakeNet]', 'DivertTraffic: Yes', '[Diverter]', 'NetworkMode: ' + spec['mode'],
                 'LinuxFlushIptables: ' + ('Yes' if spec['flush'] else 'No')]
        if spec['dns'] is not None:
            lines.append('LinuxFlushDNSCommand: ' + spec['dns'])
        lines.append('LinuxRestrictInterface: ' + spec['restrict'])
        return ('\n'.join(lines) + '\n').encode()
    def nfq(chain, table, qno, iface):
        argv = ['iptables', '-I', chain]
        if iface:
            argv += ['-i' if chain in ('INPUT', 'PREROUTING') else '-o', iface]
        return argv + ['-t', table, '-j', 'NFQUEUE', '--queue-num', str(qno)]
    def redir(iface):
        argv = ['iptables', '-I', 'PREROUTING']
        if iface:
            argv += ['-i', iface]
        return argv + ['-t', 'nat', '-j', 'REDIRECT']
    def icmp(iface):
        argv = ['iptables', '-I', 'OUTPUT']
        if iface:
            argv += ['-o', iface]
        return argv + ['-t', 'nat', '-p', 'icmp', '-j', 'REDIRECT']
    def remove(argv):
        copy = list(argv)
        require('-I' in copy, 'missing -I in expected rule')
        copy[copy.index('-I')] = '-D'
        return copy
    def expected_events(spec, qrows, rrows, snapshot_truth):
        events = [('popen', ['iptables-save'], None), ('wait', ['iptables-save'], 0)]
        if spec['flush']:
            for table in ('raw', 'filter', 'mangle', 'nat'):
                argv = ['iptables', '--flush', '-t', table]
                events += [('popen', argv, None), ('wait', argv, 0)]
        for qrow, (chain, table) in zip(qrows, spec['chains']):
            qno=qrow['qno']
            argv = nfq(chain, table, qno, spec['iface'])
            events += [('call', argv, 0), ('bind', qno, None)]
        if spec['mode'] == 'SingleHost':
            if spec['dns'] is not None:
                events.append(('call', spec['dns'].split(), spec['dns_rc']))
            events.append(('call', icmp(None), 0))
        events.append(('call', redir(spec['iface']), 0))
        for row in rrows:
            events.append(('call', remove(row['add'].split()), 0))
        for row in qrows:
            qno=row['qno']
            events.append(('unbind', qno, None))
            events.append(('call', remove(row['add'].split()), 0))
        if spec['flush']:
            events += [('popen', ['iptables-restore'], None),
                       ('communicate', ['iptables-restore'], snapshot_truth.hex()),
                       ('wait', ['iptables-restore'], 0)]
        return events
    def actual_events(rows, branch):
        value = []
        for row in rows:
            if row.get('branch') != branch:
                continue
            kind = row.get('kind')
            if kind in ('popen', 'wait', 'call'):
                if not isinstance(row.get('argv'), list) or not all(isinstance(item, str) for item in row['argv']):
                    raise ValueError('bad command argv: ' + branch)
                value.append((kind, row['argv'], row.get('rc')))
            elif kind in ('bind', 'unbind'):
                value.append((kind, row.get('qno'), None))
            elif kind == 'communicate':
                value.append((kind, row.get('argv'), row.get('input_hex')))
            else:
                raise ValueError('unknown OS event: ' + str(kind))
        return value
    try:
        v = json.loads(read('manual-result.json'))
        require(str(base) == expected_inputs.get('owned_root') and v.get('inputs') == expected_inputs, 'owned/frozen inputs mismatch')
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-LINUX-FLUSH-INTERFACE', 'case/schema mismatch')
        require(v.get('evidence_kind') == 'original-linux-callback-os-boundary', 'callback provenance missing')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('checks') == [{'id': key} for key in ('flush-iptables', 'flush-dns', 'restrict-interface')], 'checks mismatch')
        d = v['linux_flush_interface']
        require(d.get('config_dir') == str(base / 'config') and d.get('log') == str(base / 'diverter.log') and d.get('os_calls') == str(base / 'os-calls.jsonl'), 'owned path mismatch')
        require(isinstance(d.get('owner_pid'), int) and d.get('owner_pid') > 0 and d.get('execution_token') == expected_inputs['execution_id'], 'owner/token mismatch')
        require(d.get('log_sha256') == hashlib.sha256(read('diverter.log')).hexdigest(), 'log hash mismatch')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in ('fakenet/diverters/linux.py', 'fakenet/diverters/linutil.py', 'fakenet/diverters/diverterbase.py')}, 'source binding mismatch')
        require(set(d.get('branches') or {}) == set(scenarios), 'exact branch set differs')
        lifecycle=json.loads(read('observer-lifecycle.json'))
        require(lifecycle == {key:True for key in ('profile_restored','linux_module_restored','linutil_module_restored','logger_handlers_restored','logger_level_restored','handler_closed')}, 'observer/logger state not restored')
        rows = [json.loads(line) for line in read('producer-os-calls.jsonl').decode('utf-8').splitlines() if line.strip()]
        log_text = read('diverter.log').decode('utf-8')
        for branch, spec in scenarios.items():
            item = d['branches'][branch]
            require(item.get('config') == str(base / 'config' / (branch + '.ini')), 'branch config path mismatch: ' + branch)
            config = read('config/' + branch + '.ini')
            require(config == expected_config(spec) and item.get('config_sha256') == hashlib.sha256(config).hexdigest(), 'branch config bytes mismatch: ' + branch)
            require(item.get('network_mode') == spec['mode'] and bool(item.get('single_host_mode')) == (spec['mode'] == 'SingleHost'), 'network mode mismatch: ' + branch)
            require(item.get('flush_iptables') == spec['flush'] and item.get('dns_command') == spec['dns'] and item.get('restrict_interface') == spec['restrict'], 'field parse mismatch: ' + branch)
            require(item.get('start_result') is True and item.get('stop_result') is True and item.get('start_error') is None and item.get('stop_error') is None, 'callback result/error mismatch: ' + branch)
            snapshot_truth=read('capture-save-'+branch+'.bin')
            require(bool(snapshot_truth) and b'COMMIT' in snapshot_truth, 'initial command output missing: '+branch)
            bindings=json.loads(read('bindings-before-'+branch+'.json'))
            require(isinstance(bindings,list) and all(type(q) is int and 0<=q<=65535 for q in bindings), 'initial queue bindings invalid')
            queue_numbers=[q for q in range(65536) if q not in bindings][:len(spec['chains'])]
            snapshot_path = base / ('snapshot-' + branch + '.sav')
            require(item.get('snapshot') == str(snapshot_path) and read('snapshot-' + branch + '.sav') == snapshot_truth and item.get('snapshot_sha256') == hashlib.sha256(snapshot_truth).hexdigest() and item.get('snapshot_bytes') == len(snapshot_truth), 'snapshot original mismatch: ' + branch)
            expected_q = []
            for qno, (chain, table) in zip(queue_numbers,spec['chains']):
                argv = nfq(chain, table, qno, spec['iface'])
                expected_q.append({'qno': qno, 'chain': chain, 'table': table, 'add': ' '.join(argv), 'remove': ' '.join(remove(argv))})
            actual_q = item.get('queues_after_start') or []
            require(len(actual_q) == len(expected_q), 'queue count mismatch: ' + branch)
            for actual, wanted in zip(actual_q, expected_q):
                require(actual.get('qno') == wanted['qno'] and actual.get('chain') == wanted['chain'] and actual.get('table') == wanted['table'] and actual.get('add', '').split() == wanted['add'].split() and actual.get('remove', '').split() == wanted['remove'].split() and actual.get('started') is True and actual.get('bound') is True and actual.get('rule_added') is True and actual.get('thread_alive') is True and actual.get('thread_error') is None and actual.get('stop_error') is None, 'queue start rule/state mismatch: ' + branch)
            stopped_q = item.get('queues_after_stop') or []
            require(len(stopped_q) == len(expected_q), 'stopped queue count mismatch: ' + branch)
            for actual, wanted in zip(stopped_q, expected_q):
                require(actual.get('qno') == wanted['qno'] and actual.get('chain') == wanted['chain'] and actual.get('table') == wanted['table'] and actual.get('add', '').split() == wanted['add'].split() and actual.get('remove', '').split() == wanted['remove'].split() and actual.get('started') is True and actual.get('bound') is False and actual.get('rule_added') is False and actual.get('thread_alive') is False and actual.get('thread_error') is None and actual.get('stop_error') is None, 'queue stop rule/state mismatch: ' + branch)
            expected_r = []
            if spec['mode'] == 'SingleHost':
                expected_r.append(icmp(None))
            expected_r.append(redir(spec['iface']))
            actual_r = item.get('rules_after_start') or []
            require([row.get('add', '').split() for row in actual_r] == [argv for argv in expected_r] and [row.get('remove', '').split() for row in actual_r] == [remove(argv) for argv in expected_r], 'iptables rule construction mismatch: ' + branch)
            require([row.get('add', '').split() for row in (item.get('rules_after_stop') or [])] == [argv for argv in expected_r], 'iptables rule inventory changed unexpectedly: ' + branch)
            expected_os = expected_events(spec, expected_q, actual_r, snapshot_truth)
            actual_os = actual_events(rows, branch)
            require(actual_os == expected_os, 'OS command/restore sequence mismatch: ' + branch)
            require(('MANUAL-LINUX-BRANCH ' + branch + ' token=' + d['execution_token']) in log_text and ('pid=%s ' % d['owner_pid']) in log_text and 'Stopped Linux Diverter' in log_text and 'NET_POLICY_STOPPED' in log_text, 'original callback log/owner missing: ' + branch)
            if not spec['flush']:
                require('LinuxFlushIptables is disabled' in log_text, 'flush-disabled log missing: ' + branch)
            if spec['dns'] == 'false':
                require('Failed to flush DNS cache. Local machine may use cached DNS results.' in log_text, 'DNS nonzero log missing: ' + branch)
        require(v.get('cleanup') == {'scope': 'owned-linux-callback-os-boundary', 'stopped': True, 'threads_joined': True, 'rules_cleared': True, 'system_network_restored': 'not-exercised', 'system_iptables_restored': 'not-exercised'}, 'cleanup/provenance mismatch')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in ('flush-iptables', 'flush-dns', 'restrict-interface')], not errors, {'failures': errors}

def _evaluate_network_fix(root, original, expected_inputs, allow_fixture=False):
    import configparser
    base = Path(original).resolve()
    errors = []
    keys = ('fix-gateway', 'fix-dns', 'modify-local-dns', 'stop-dns')
    def require(ok, reason):
        if not ok: raise ValueError(reason)
    def read(name):
        path = base / name
        require(path.is_file() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents), 'missing/linked original: ' + str(name))
        require(path.resolve().is_relative_to(base), 'original outside owned directory')
        return path.read_bytes()
    try:
        v = json.loads(read('manual-result.json'))
        require(str(base) == expected_inputs.get('owned_root') and v.get('inputs') == expected_inputs, 'owned/frozen inputs mismatch')
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-NETWORK-FIX', 'case/schema mismatch')
        require(v.get('evidence_kind') == 'original-network-fix-config-start-stop', 'original configuration/start-stop provenance missing')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('checks') == [{'id': key} for key in keys], 'checks mismatch')
        d = v['network_fix']
        require(d.get('config') == str(base / 'config/network-fix.ini') and d.get('config_sha256') == hashlib.sha256(read('config/network-fix.ini')).hexdigest(), 'configuration identity mismatch')
        require(d.get('producer_calls') == str(base / 'producer-os-calls.jsonl') and d.get('producer_calls_sha256') == hashlib.sha256(read('producer-os-calls.jsonl')).hexdigest(), 'producer-owned command original mismatch')
        require(d.get('log') == str(base / 'network-fix.log') and d.get('log_sha256') == hashlib.sha256(read('network-fix.log')).hexdigest(), 'log identity mismatch')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in ('fakenet/diverters/winutil.py', 'fakenet/diverters/windows.py', 'fakenet/diverters/linux.py', 'fakenet/diverters/linutil.py', 'fakenet/diverters/diverterbase.py')}, 'source mismatch')
        rows = [json.loads(line) for line in read('producer-os-calls.jsonl').decode().splitlines() if line]
        require(rows and type(d.get('owner_pid')) is int and d['owner_pid'] > 0 and all(row.get('owner_pid') == d['owner_pid'] and row.get('token') == expected_inputs['execution_id'] for row in rows), 'original owner/token mismatch')
        require(d.get('execution_token') == expected_inputs['execution_id'], 'execution token mismatch')
        logs = read('network-fix.log').decode()
        branches = ('win_fix', 'win_existing', 'win_modify', 'win_off', 'linux_gateway', 'linux_modify', 'linux_off')
        require(set(d.get('branches', {})) == set(branches), 'exact configuration branch set missing')
        def events(branch, kind, op=None):
            return [row for row in rows if row['branch'] == branch and row['kind'] == kind and (op is None or row.get('op') == op)]
        def commands(branch):
            return [row['args'][0] for row in events(branch, 'subprocess') if row['op'] in ('check_call', 'check_output', 'call')]
        expected_fix = ['netsh interface ip set address name="Ethernet" static 192.0.2.10 255.255.255.0 192.0.2.1', 'netsh interface ip set dns name="Ethernet" static 192.0.2.10', 'ipconfig /flushdns', 'netsh interface ip set address name="Ethernet" dhcp', 'netsh interface ip delete dns name="Ethernet" all', 'netsh interface ip set dns "Ethernet" dhcp', 'ipconfig /flushdns']
        require(commands('win_fix') == expected_fix and not any(row.get('error') for row in events('win_fix', 'subprocess')), 'Windows gateway/DNS commands or restoration failed')
        for name in branches:
            item = d['branches'][name]
            require(item.get('config') == str(base / ('config/' + name + '.ini')), 'branch config path mismatch')
            parser = configparser.ConfigParser(); parser.read_string(read('config/' + name + '.ini').decode())
            parsed = dict(parser.items('Diverter'))
            expected = {'networkmode': 'SingleHost', 'fixgateway': 'Yes' if name in ('win_fix', 'win_existing', 'linux_gateway') else 'No', 'fixdns': 'Yes' if name in ('win_fix', 'win_existing') else 'No', 'modifylocaldns': 'Yes' if name in ('win_modify', 'linux_modify') else 'No', 'stopdnsservice': 'Yes' if name == 'win_modify' else 'No'}
            require(item.get('parsed') == parsed and all(parsed.get(key) == value for key, value in expected.items()), 'configuration values/parsed branch mismatch: ' + name)
            require(item.get('start') is True and item.get('stop') is True and item.get('threads_stopped') is True, 'startup/stop/resource failure: ' + name)
            method_rows = events(name, 'method')
            platform_source = 'windows.py' if name.startswith('win') else 'linux.py'
            require(any(row.get('source') == 'diverterbase.py' and row.get('method') == '__init__' for row in method_rows), 'original base initializer missing: ' + name)
            for method in ('startCallback', 'stopCallback'):
                require(any(row.get('source') == platform_source and row.get('method') == method and row.get('result') is True for row in method_rows), 'original successful callback missing: ' + name + '/' + method)
            require(('MANUAL-NETWORK-BRANCH ' + name + ' token=' + expected_inputs['execution_id']) in logs and ('pid=%s ' % d['owner_pid']) in logs, 'original branch log missing')
            if name.startswith('win'):
                require(item['registry_before'] == item['registry_after'], 'registry not actually restored: ' + name)
                require(item['service_before'] == item['service_after'] == 4, 'service not actually restored: ' + name)
                queries = events(name, 'registry', 'QueryValueEx')
                require(queries and (queries[0]['result'][0] or None) == item['registry_before'] and (queries[-1]['result'][0] or None) == item['registry_after'], 'raw registry initial/final mismatch')
                if name == 'win_modify':
                    require(item['registry_middle'] == '192.0.2.10' and item['service_middle'] == 1, 'DNS/service modification not observed')
                    require(commands(name) == ['ipconfig /flushdns', 'ipconfig /flushdns'], 'nonowned adapter settings changed')
                    controls = events(name, 'service', 'ControlService')
                    require(controls and controls[0]['args'][1] == 1 and events(name, 'service', 'StartServiceA'), 'original service stop/start missing')
                elif name != 'win_fix':
                    require(commands(name) == ['ipconfig /flushdns', 'ipconfig /flushdns'], 'off/existing branch changed network')
                    require(not events(name, 'service', 'ControlService') and not events(name, 'registry', 'SetValueEx'), 'off branch changed DNS/service')
            else:
                require(item['resolver_before'] == item['resolver_after'], 'resolver not restored: ' + name)
                writes = events(name, 'resolver', 'write')
                if name == 'linux_modify':
                    require(item['resolver_middle'] == 'nameserver 192.0.2.10\n' and item['old_dns_after'] is None, 'resolver modification/restore not observed')
                    require([row['data'] for row in writes] == [item['resolver_middle'], item['resolver_before']], 'raw resolver write bytes mismatch')
                else:
                    require(not writes, 'disabled resolver feature changed state')
        require(d['windows']['fix']['gateway_result'] is True and d['windows']['fix']['dns_result'] is True, 'gateway/DNS original result mismatch')
        require(d['windows']['existing']['gateway_result'] is False and d['windows']['existing']['dns_result'] is False, 'existing-state fix unexpectedly called')
        require(d['linux']['gateway']['gateway_result'] is True, 'original Linux gateway path missing')
        require(d['linux']['unsupported'] == {'fix_gateway_result': False, 'fix_dns_result': False, 'stop_dns_service_supported': False}, 'Linux unsupported facts changed')
        require(d.get('observer_restored') is True and v.get('cleanup') == {'system_network_restored': 'not-exercised'}, 'observer/resource cleanup changed')
        require(v.get('known_limits', {}).get('linux_new_gateway_restoration') == 'original stopCallback has no default-route removal; not proven restored', 'missing known Linux route restoration limitation')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in keys], not errors, {'failures': errors, 'system_network_restoration': 'not-exercised', 'linux_route_restoration': 'original implementation does not remove newly added default route; full acceptance remains incomplete'}


def _evaluate_standalone(root, original, expected_inputs, allow_fixture=False):
    base=Path(original).resolve();errors=[]
    names=('DNSListener','HTTPListener','FTPListener','IRCListener','POPListener','SMTPListener','RawListener','TFTPListener','ProxyListener')
    def require(ok,reason):
        if not ok:raise ValueError(reason)
    def read(name):
        path=base/name
        require(path.is_file() and not path.is_symlink() and not any(p.is_symlink() for p in path.parents),'missing/linked original: '+name)
        return path.read_bytes()
    try:
        v=json.loads(read('manual-result.json'))
        require(str(base)==expected_inputs.get('owned_root') and v.get('inputs')==expected_inputs,'owned/frozen inputs mismatch')
        require(v.get('schema')=='fakenet.manual-result.v1' and v.get('case')=='GAP-STANDALONE-LISTENERS','case/schema mismatch')
        require(v.get('evidence_kind')=='original-standalone-scripts-and-listeners','standalone provenance missing')
        require(v.get('identity')=={k:expected_inputs[k] for k in ('candidate_id','source_commit','package_sha256','execution_id')},'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture']==(expected_inputs.get('fixture') is True),'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture,'fixture cannot native credit')
        require(v.get('checks')==[{'id':x} for x in ('listener-bytes','listener-close')],'checks mismatch')
        d=v['standalone'];require(set(d.get('scripts') or {})==set(names),'exact nine-script set differs')
        require(d.get('log')==str(base/'standalone.log') and d.get('log_sha256')==hashlib.sha256(read('standalone.log')).hexdigest(),'standalone log missing/changed')
        require(type(d.get('owner_pid')) is int and d['owner_pid']>0 and d.get('execution_token')==expected_inputs['execution_id'],'owner/token mismatch')
        owner=json.loads(read('owner.json'))
        require(owner.get('schema')=='fakenet.owner.v1' and owner.get('pid')==d['owner_pid'] and owner.get('execution_token')==d['execution_token'] and d.get('owner_sha256')==hashlib.sha256(read('owner.json')).hexdigest(),'owner original mismatch')
        require(v.get('source_hashes')=={('fakenet/listeners/'+name+'.py'):hashlib.sha256((Path(root)/('fakenet/listeners/'+name+'.py')).read_bytes()).hexdigest() for name in names},'source binding mismatch')
        log=read('standalone.log').decode('utf-8')
        for name in names:
            item=d['scripts'][name];require(item.get('main_called') is True,'original main not called: '+name)
            require(item.get('listener_started') is True and item.get('endpoint') and item['endpoint'][0]=='127.0.0.1' and type(item['endpoint'][1]) is int and item['endpoint'][1]>=1024,'owned endpoint mismatch: '+name)
            require(item.get('main_error') is None and item.get('probe_error') is None and item.get('stop_errors')==[],'original start/probe/stop error: '+name)
            require(item.get('thread_alive') is False and item.get('socket_closed') is True,'owned listener not closed: '+name)
            require(('MANUAL-STANDALONE '+name+' token='+d['execution_token']) in log,'standalone log marker missing: '+name)
            require(item.get('hooks_restored') is True,'temporary observer not restored: '+name)
            calls_bytes=read(name+'/calls.json'); resources_bytes=read(name+'/resources.json')
            require(item.get('calls_sha256')==hashlib.sha256(calls_bytes).hexdigest() and item.get('resources_sha256')==hashlib.sha256(resources_bytes).hexdigest(),'lifecycle original mismatch: '+name)
            calls=json.loads(calls_bytes); resources=json.loads(resources_bytes)
            functions={c['function'] for c in calls if c.get('event')=='call'}
            required={'main','handle'} if name=='ProxyListener' else {'main','__init__','start','stop'}
            if name not in ('RawListener','TFTPListener','ProxyListener'): required.add('test')
            require(required <= functions,'original lifecycle calls missing: '+name)
            require(resources.get('threads') and all(t.get('alive') is False for t in resources['threads']) and resources.get('sockets') and all(t.get('fileno')==-1 for t in resources['sockets']),'owned resource observations not closed: '+name)
            cfg=item.get('config') or {}
            require(cfg.get('ipaddr')=='127.0.0.1' and str(cfg.get('port'))=='0','loopback/port fixture mismatch: '+name)
            request=read(name+'/request.bin');response=read(name+'/response.bin')
            require(len(request)>0 and len(response)>0 and item.get('request_sha256')==hashlib.sha256(request).hexdigest() and item.get('response_sha256')==hashlib.sha256(response).hexdigest(),'request/response original mismatch: '+name)
            if name=='DNSListener':
                from dnslib import DNSRecord
                q=DNSRecord.parse(request);r=DNSRecord.parse(response)
                require(len(q.questions)==1 and len(r.questions)==1 and r.header.qr==1 and r.header.rcode==0 and r.header.id==q.header.id and r.questions[0]==q.questions[0] and any(str(rr.rdata)=='127.0.0.1' and rr.rtype==1 for rr in r.rr),'DNS response mismatch')
            elif name in ('HTTPListener','ProxyListener'):
                require(request.startswith(b'GET / HTTP/1.1\r\n') and response.startswith(b'HTTP/1.') and b' 200 ' in response.split(b'\r\n',1)[0],'HTTP request/response mismatch: '+name)
                require(response.split(b'\r\n\r\n',1)[1]==(Path(root)/'fakenet/defaultFiles/FakeNet.html').read_bytes(),'HTTP body mismatch: '+name)
            elif name=='FTPListener':
                require(request==b'USER user\r\nPASS password\r\nQUIT\r\n' and [line[:3] for line in response.splitlines()]==[b'220',b'331',b'230',b'221'],'FTP response mismatch')
            elif name=='IRCListener':
                require(b'001' in response or b'376' in response or b'PONG' in response,'IRC response mismatch')
            elif name=='POPListener':
                require(response.startswith(b'+OK') and b'+OK User accepted' in response and b'+OK 2 320' in response,'POP response mismatch')
            elif name=='SMTPListener':
                require(response.startswith(b'220') and b'250' in response and b'221' in response,'SMTP response mismatch')
            elif name=='RawListener':
                require(request==b'HELO\n' and response==request,'raw echo mismatch')
            elif name=='TFTPListener':
                require(request==b'\x00\x01test.txt\x00octet\x00' and response==b'\x00\x03\x00\x01'+(Path(root)/'fakenet/defaultFiles/FakeNet.txt').read_bytes()[:512],'TFTP response mismatch')
        require(v.get('cleanup')=={'scope':'owned-standalone-listeners','stopped':True,'system_network_restored':'not-exercised','system_console_used':False},'cleanup/provenance mismatch')
    except Exception as exc:errors.append(type(exc).__name__+': '+str(exc))
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('listener-bytes','listener-close')],not errors,{'failures':errors}

def _evaluate_dumppackets(root, original, expected_inputs, allow_fixture=False):
    import configparser
    import dpkt
    from fakenet.payload_report import load_capture_originals
    base = Path(original).absolute()
    errors = []
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    def plain(path):
        path = Path(path)
        require(path.is_file(), 'missing original: ' + str(path))
        require(not any(item.is_symlink() for item in (path, *path.parents)), 'linked original')
        return path
    try:
        require(str(base) == expected_inputs.get('owned_root'), 'frozen owned root mismatch')
        v = json.loads(plain(base / 'manual-result.json').read_text())
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-DUMPPACKETS', 'case/schema mismatch')
        require(v.get('inputs') == expected_inputs, 'frozen inputs mismatch')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('evidence_kind') == 'offline-packet-replay' and v.get('wire_capture') is False, 'packet replay provenance missing')
        require(v.get('checks') == [{'id': key} for key in ('enabled', 'disabled', 'prefix', 'content')], 'checks mismatch')
        require(v.get('cleanup') == {'scope': 'owned-capture-files', 'stopped': True, 'system_network_restored': 'not-exercised'}, 'owned cleanup mismatch')
        # Independent literal packet truth, never selected by the producer's files.
        expected = [bytes.fromhex('450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000'),
                    bytes.fromhex('450000200002000040110000c000020ac00002149c411f91000c000074657374')]
        for number, packet in enumerate(expected):
            require(plain(base / ('packet-%d.bin' % number)).read_bytes() == packet, 'fixed packet input mismatch')
        sources = ('fakenet/diverters/diverterbase.py', 'fakenet/diverters/fnconfig.py',
                   'fakenet/diverters/pcapwriter.py', 'fakenet/capture_originals.py', 'fakenet/payload_report.py')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in sources}, 'source binding mismatch')
        require(set(v.get('dumppackets', {})) == {'enabled', 'disabled'}, 'missing capture branch')
        for mode, setting in (('enabled', 'Yes'), ('disabled', 'No')):
            item = v['dumppackets'][mode]
            folder = base / mode
            cfg = base / 'config' / (mode + '.ini')
            prefix = str(folder / 'customcap')
            require(folder.is_dir() and not any(path.is_symlink() for path in (folder, *folder.parents)), 'owned branch path mismatch')
            require(item.get('folder') == str(folder) and item.get('prefix') == prefix and item.get('config') == str(cfg), 'owned configuration/prefix mismatch')
            require(plain(cfg).read_text() == '[Diverter]\nDumpPackets: ' + setting + '\nDumpPacketsFilePrefix: ' + prefix + '\n', 'exact configuration mismatch')
            require(item.get('config_sha256') == hashlib.sha256(cfg.read_bytes()).hexdigest(), 'configuration hash mismatch')
            parser = configparser.ConfigParser()
            parser.read(cfg)
            require(parser.getboolean('Diverter', 'DumpPackets') == (mode == 'enabled'), 'configured switch mismatch')
            require(item.get('before') == [] and item.get('error') is None and item.get('writer_closed') is True, 'branch before/error/close mismatch')
            files = sorted(path.name for path in folder.glob('*.pcap'))
            require(item.get('pcap_files') == files, 'actual PCAP inventory mismatch')
            lifecycle = json.loads(plain(base / ('lifecycle-' + mode + '.json')).read_text())
            require(lifecycle.get('scope') == 'owned-capture-files' and lifecycle.get('streams_closed') is True and lifecycle.get('writer_closed') is True and lifecycle.get('originals_closed') is True and lifecycle.get('close_error') is None and lifecycle.get('capture_failure') is None, 'actual writer lifecycle mismatch')
            if mode == 'disabled':
                require(not list(folder.iterdir()) and item.get('summary') is None and lifecycle.get('writer_present') is False and lifecycle.get('originals_sealed') is False and lifecycle.get('observations') == [], 'disabled output/writer mismatch')
                continue
            require(len(files) == 2 and all(name.startswith('customcap_') and Path(name).name == name for name in files), 'enabled custom prefix output missing')
            raw = plain(folder / next(name for name in files if not name.endswith('-converted.pcap')))
            converted = plain(folder / next(name for name in files if name.endswith('-converted.pcap')))
            loaded = load_capture_originals(raw, converted)
            with raw.open('rb') as stream:
                reader = dpkt.pcap.Reader(stream)
                require(reader.datalink() == dpkt.pcap.DLT_RAW, 'raw linktype mismatch')
                raws = [bytes(packet) for _, packet in reader]
            with converted.open('rb') as stream:
                reader = dpkt.pcap.Reader(stream)
                require(reader.datalink() == dpkt.pcap.DLT_EN10MB, 'converted linktype mismatch')
                converted_packets = [bytes(packet) for _, packet in reader]
            header = bytes.fromhex('0200000000020200000000010800')
            require(raws == expected and converted_packets == [header + packet for packet in expected], 'PCAP bytes/frames differ from independent fixed packets')
            require(lifecycle.get('writer_present') is True and lifecycle.get('originals_sealed') is True and lifecycle.get('observations') == loaded.entries, 'sealed observations/lifecycle mismatch')
            for number, entry in enumerate(loaded.entries):
                require(entry.get('logical_packet_id') == 'dump-packet-%d' % number and entry.get('direction') == 'inbound' and entry.get('observation_role') == 'inbound', 'observation direction/identity mismatch')
            require(len(loaded.entries) == len(expected), 'observation count mismatch')
            require(set(path.name for path in folder.iterdir()) == {raw.name, converted.name, raw.name + '.observations.ndjson', raw.name + '.nbis.ndjson', raw.name + '.capture-originals.json'}, 'capture original inventory mismatch')
            summary = item.get('summary') or {}
            require(summary.get('raw_filename') == str(raw) and summary.get('ethernet_filename') == str(converted) and summary.get('raw_write_count') == len(expected) and summary.get('ethernet_write_count') == len(expected) and summary.get('healthy') is True and summary.get('discarded') is False, 'writer summary mismatch')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in ('enabled', 'disabled', 'prefix', 'content')], not errors, {'failures': errors}

def _evaluate_diverter_switch(root,original,expected_inputs,allow_fixture=False):
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-DIVERTER-SWITCH':raise ValueError('case/schema mismatch')
    if v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity mismatch')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    errors=[];data=v.get('diverter_switch') or {}
    if set(data)!=set(('on','off')):errors.append('exact branch set differs')
    for mode,traffic in (('on','Yes'),('off','No')):
        item=data.get(mode) or {};cfg=base/'config'/(mode+'.ini')
        if item.get('config')!=str(cfg) or not cfg.is_file() or cfg.is_symlink() or item.get('config_sha256')!=hashlib.sha256(cfg.read_bytes()).hexdigest():
            errors.append(mode+' config missing/changed/foreign');continue
        text='[FakeNet]\nDivertTraffic: '+traffic+'\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n'
        if cfg.read_text()!=text:errors.append(mode+' traffic configuration differs')
        if item.get('before')!={'diverttraffic':traffic,'diverter':None,'listeners':0}:errors.append(mode+' before state differs')
        if item.get('error') is not None:errors.append(mode+' production error')
        after=item.get('after') or {};on=mode=='on'
        if item.get('start_calls')!=(1 if on else 0):errors.append(mode+' backend start not observed once')
        if (after.get('started') is not on or (on and not after.get('diverter')) or (not on and after.get('diverter') is not None)
                or after.get('stop1') is not True or after.get('stop2') is not True or after.get('stop_calls')!=(1 if on else 0)
                or after.get('listeners')!=0):errors.append(mode+' start/stop/restore mismatch')
        obs=base/(mode+'-observation.json');log=base/(mode+'-core.log')
        if (item.get('observation')!=str(obs) or not obs.is_file() or obs.is_symlink() or item.get('observation_sha256')!=hashlib.sha256(obs.read_bytes()).hexdigest()
                or item.get('core_log')!=str(log) or not log.is_file() or log.is_symlink() or item.get('core_log_sha256')!=hashlib.sha256(log.read_bytes()).hexdigest()):
            errors.append(mode+' observation/log original missing/changed');continue
        expected_calls=[{'method':method,'event':event} for method in ('start','stop') for event in ('call','return')] if on else []
        expected_obs={'schema':'fakenet.switch-observation.v1','mode':mode,'execution_id':expected_inputs['execution_id'],
                      'calls':expected_calls,'stop_complete':True,'stop_result':True,'stop_error':None,'start_error':None,'stop_errors':[]}
        if json.loads(obs.read_text())!=expected_obs:errors.append(mode+' original call/cleanup observations differ')
        lines=log.read_text().splitlines()
        if lines.count('DEFAULT_INTERCEPTION_READY')!=(1 if on else 0):errors.append(mode+' original interception-ready marker differs')
        if not any(line.startswith('STOP_PHASE_END phase=complete') and line.endswith('healthy=True') for line in lines):errors.append(mode+' stop completion log missing')
    if v.get('source_hashes')!={n:hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() for n in ('fakenet/fakenet.py','fakenet/diverters/linux.py','fakenet/diverters/windows.py')}:errors.append('source binding mismatch')
    if v.get('cleanup')!={'stopped':True,'scope':'observed-core-start-stop','system_network_restored':'unverified'}:errors.append('cleanup mismatch')
    if v.get('checks')!=[{'id':k} for k in ('on','off','restore')]:errors.append('exact check set differs')
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('on','off','restore')],not errors,{'failures':errors}

def _evaluate_executecmd(root,original,expected_inputs,allow_fixture=False):
    from types import SimpleNamespace
    from fakenet.diverters.diverterbase import DiverterBase,DivertParms
    import logging
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-EXECUTECMD':raise ValueError('case/schema mismatch')
    if v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity/credit mismatch')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if not v['fixture'] and (v.get('executecmd',{}).get('os_platform')!='windows'):raise ValueError('native command evidence requires Windows platform')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    data=v.get('executecmd') or {};cfg=base/'config/executecmd.ini';errors=[]
    if not cfg.is_file() or cfg.is_symlink() or data.get('configuration')!='config/executecmd.ini' or data.get('configuration_sha256')!=hashlib.sha256(cfg.read_bytes()).hexdigest():raise ValueError('configuration original missing/changed')
    token=str(expected_inputs['execution_id']);output=base/'command-output.txt'
    template='cmd.exe /c echo {pid} {procname} {src_addr} {src_port} {dst_addr} {dst_port} '+token+'>>"'+str(output)+'"'
    if cfg.read_text()!='[svc]\nProtocol: TCP\nPort: 8080\nExecuteCmd: '+template+'\n[plain]\nProtocol: TCP\nPort: 8090\n':errors.append('frozen configuration differs')
    diverter=DiverterBase.__new__(DiverterBase);diverter.logger=logging.getLogger('oracle-executecmd');diverter.sessions={};diverter.configure({});diverter.listener_ports=__import__('fakenet.diverters.diverterbase',fromlist=['ListenerPorts']).ListenerPorts()
    diverter.parse_listeners_config({'svc':{'protocol':'TCP','port':'8080','executecmd':template}})
    pkt=SimpleNamespace(proto='TCP',sport=40000,dport=8080,src_ip='192.0.2.10',dst_ip='192.0.2.20',src_ip0='192.0.2.10',dst_ip0='192.0.2.20',dport0=8080,_dport0=8080,ipver=4)
    payload='1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080 '+token
    expected='cmd.exe /c echo '+payload+'>>"'+str(output)+'"'
    if diverter.build_cmd(pkt,1234,'benign.exe')!=expected:errors.append('production build_cmd differs')
    parms=DivertParms(diverter,pkt,1234,'benign.exe')
    if parms.first_packet_new_session is not True:errors.append('first session predicate false')
    diverter.addSession(pkt,1234,'benign.exe')
    if DivertParms(diverter,pkt,1234,'benign.exe').first_packet_new_session is not False:errors.append('duplicate session predicate true')
    raw=None
    if data.get('command_output')!=str(output) or not output.is_file() or output.is_symlink():
        errors.append('command output original missing/changed')
    elif output.stat().st_size>4096:errors.append('command output exceeds fixed probe bound')
    else:
        raw=output.read_bytes()
        if data.get('command_output_sha256')!=hashlib.sha256(raw).hexdigest():errors.append('command output original missing/changed')
        if raw not in ((payload+'\n').encode('ascii'),(payload+'\r\n').encode('ascii')):
            errors.append('command output six fields/token or line count differs')
        if data.get('command_output_encoding')!='hex' or data.get('command_output_bytes')!=raw.hex():
            errors.append('command output byte observation differs')
    if data.get('token')!=token:errors.append('command token differs')
    if data.get('command')!=expected or data.get('first_packet') is not True or data.get('duplicate_first_packet') is not False:errors.append('command/session originals mismatch')
    executed=data.get('executed')
    if not isinstance(executed,list) or len(executed)!=1 or executed[0].get('command')!=expected or type(executed[0].get('pid')) is not int or executed[0]['pid']<=0:errors.append('first execution original mismatch')
    if data.get('missing_pid_executions')!=0:errors.append('missing PID executed')
    if data.get('nonmatching_command') is not None:errors.append('nonmatching port built command')
    bad=data.get('bad_format_error')
    if not isinstance(bad,dict) or bad.get('type')!='SystemExit' or bad.get('code')!=1:errors.append('bad format did not exit 1')
    expected_actions=[
      {'name':'first','protocol':'TCP','source_port':40000,'destination_port':8080,'pid':1234,'first_packet':True,'executions':1,'session_count':1},
      {'name':'duplicate','protocol':'TCP','source_port':40000,'destination_port':8080,'pid':1234,'first_packet':False,'executions':0,'session_count':1},
      {'name':'missing-pid','protocol':'TCP','source_port':40001,'destination_port':8080,'pid':None,'first_packet':True,'executions':0,'session_count':2},
      {'name':'no-command-listener','protocol':'TCP','source_port':40002,'destination_port':8090,'pid':1234,'first_packet':True,'executions':0,'session_count':3},
      {'name':'no-default-protocol','protocol':'UDP','source_port':40003,'destination_port':8080,'pid':1234,'first_packet':True,'executions':0,'session_count':3}]
    if data.get('actions')!=expected_actions:errors.append('original first/duplicate/nontrigger action sequence differs')
    if data.get('sessions_after')!=0 or data.get('port_forwards_after')!=0:errors.append('original in-memory state not restored')
    if data.get('template')!=template:errors.append('command template identity differs')
    if v.get('checks')!=[{'id':k} for k in ('command','first-connection','non-connection')]:errors.append('exact check set differs')
    if v.get('source_hashes')!={n:hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() for n in ('fakenet/diverters/diverterbase.py','fakenet/diverters/fnpacket.py')}:errors.append('source binding mismatch')
    if v.get('cleanup')!={'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True,
            'scope':'in-memory-case-state','child_exit':'not-observed','child_termination_performed':False}:errors.append('cleanup mismatch')
    out=[{'id':k,'status':'fail' if errors else 'pass'} for k in ('command','first-connection','non-connection')]
    return out,not errors,{'failures':errors}

def _evaluate_list_mutex(root,original,expected_inputs,allow_fixture=False):
    from fakenet.diverters.diverterbase import ListenerMeta,ListenerPorts,ListenerBlackWhiteList,DiverterBase
    import logging
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-LIST-MUTEX':raise ValueError('case/schema mismatch')
    if not isinstance(expected_inputs,dict) or v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity missing/changed')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    wanted={'proc-black':{'protocol':'TCP','port':'8080','processblacklist':'evil.exe, helper.exe'},
            'proc-white':{'protocol':'TCP','port':'8081','processwhitelist':'good.exe'},
            'host-black':{'protocol':'TCP','port':'8082','hostblacklist':'evil.test, bad.test'},
            'host-white':{'protocol':'TCP','port':'8083','hostwhitelist':'good.test'}}
    config=base/'config/list-mutex.ini'
    if config.is_symlink() or not config.is_file() or not config.resolve().is_relative_to(base):raise ValueError('configuration original missing/escaped')
    if v.get('configuration')!={'path':'config/list-mutex.ini','sha256':hashlib.sha256(config.read_bytes()).hexdigest()}:raise ValueError('configuration hash differs')
    parser=configparser.ConfigParser();parser.read(config)
    if {sec:dict(parser.items(sec)) for sec in parser.sections()}!=wanted:raise ValueError('frozen list configuration/target changed')
    names=('fakenet/diverters/diverterbase.py','fakenet/diverters/fnconfig.py')
    if v.get('source_hashes')!={name:hashlib.sha256((Path(root)/name).read_bytes()).hexdigest() for name in names}:raise ValueError('production source binding mismatch')
    obj=DiverterBase.__new__(DiverterBase);obj.logger=logging.getLogger('oracle-list-mutex');obj.listener_ports=ListenerPorts();obj.configure({})
    obj.parse_listeners_config({sec:dict(parser.items(sec)) for sec in parser.sections()})
    ports=obj.listener_ports;queries=[];errors=[]
    for method,port,positive,negative in [('isProcessBlackListHit',8080,'evil.exe','clean.exe'),
            ('isProcessWhiteListMiss',8081,'other.exe','good.exe'),
            ('isHostBlackListHit',8082,'evil.test','good.test'),
            ('isHostWhiteListMiss',8083,'other.test','good.test')]:
        for index,(proto,number,subject) in enumerate([('TCP',port,positive),('TCP',port,negative),('UDP',port,positive),('TCP',65500,positive)]):
            observed=getattr(ports,method)(proto,number,subject)
            if observed is not (index==0):errors.append('production predicate violates positive/negative target '+method)
            queries.append({'method':method,'protocol':proto,'port':number,'subject':subject,'result':observed})
    data=v.get('list_mutex') or {}
    expected_rows=[{'name':'proc-black','hit':True,'allow':False}, {'name':'proc-white','miss_allowed':True,'miss_denied':False},
                   {'name':'host-black','hit':True,'allow':False}, {'name':'host-white','miss_allowed':True,'miss_denied':False}]
    if data.get('observations')!=expected_rows or data.get('queries')!=queries:errors.append('original list observations disagree')
    if data.get('ports')!=[8080,8081,8082,8083] or data.get('ports_after')!=[]:errors.append('port identity/lifecycle mismatch')
    mutex=[]
    for kind in ('process','host'):
        meta=ListenerMeta('TCP',8090 if kind=='process' else 8091)
        try:
            if kind=='process':meta.setProcessBlacklist('a.exe');meta.setProcessWhitelist('b.exe')
            else:meta.setHostBlacklist('a.test');meta.setHostWhitelist('b.test')
            error=None;errors.append(kind+' mutex unexpectedly accepted')
        except ListenerBlackWhiteList as exc:error={'type':type(exc).__name__,'message':str(exc)}
        mutex.append({'kind':kind,'error':error,'process_cleared':meta.proc_wl is None and meta.proc_bl is None,'host_cleared':meta.host_wl is None and meta.host_bl is None})
    if data.get('mutex')!=mutex:errors.append('original mutex records missing/duplicate/foreign/error mismatch')
    for entry in mutex:
        error=entry.get('error')
        if (not isinstance(error,dict) or error.get('type')!='ListenerBlackWhiteList' or
                not isinstance(error.get('message'),str) or not error['message'].strip()):
            errors.append('mutex exception type/message not independently proven')
        if entry.get('process_cleared') is not True or entry.get('host_cleared') is not True:
            errors.append('mutex lists not cleared by original production path')
    conflicts=[]
    for scope in ('listener-process','listener-host','global-process'):
        d=DiverterBase.__new__(DiverterBase);d.logger=obj.logger;d.listener_ports=ListenerPorts();d.configure({})
        try:
            if scope=='global-process':d.configure({'processblacklist':'bad.exe','processwhitelist':'good.exe'});d.parse_diverter_config()
            else:
                keys=('processblacklist','processwhitelist') if scope=='listener-process' else ('hostblacklist','hostwhitelist')
                d.parse_listeners_config({'conflict':dict(protocol='TCP',port='8099',**{keys[0]:'a',keys[1]:'b'})})
            error=None;errors.append(scope+' parser accepted conflict')
        except SystemExit as exc:
            error={'type':'SystemExit','code':exc.code}
            if exc.code!=1:errors.append('unexpected conflict exit')
        conflicts.append({'scope':scope,'error':error,'registered_ports':d.listener_ports.getPortList('TCP')})
        if (not isinstance(error,dict) or error.get('type')!='SystemExit' or error.get('code')!=1 or
                d.listener_ports.getPortList('TCP')!=[]):
            errors.append('parser conflict did not exit 1 before registering a port')
    if data.get('parser_conflicts')!=conflicts:errors.append('original parser conflict observations differ')
    if v.get('cleanup')!={'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True}:errors.append('pure-logic lifecycle missing/changed')
    if v.get('checks')!=[{'id':k} for k in ('blacklist','whitelist','mutex')]:errors.append('exact check set differs')
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('blacklist','whitelist','mutex')],not errors,{'failures':errors}

def evaluate(root,original,case,expected_inputs,allow_fixture=False):
    if case=='GAP-SYSLOG-ICMP-LOG':return _evaluate_syslog_icmp(root,original,expected_inputs,allow_fixture)
    if case=='GAP-CTRLC-IPC':return _evaluate_ctrlc_ipc(root,original,expected_inputs,allow_fixture)
    if case=='GAP-LINUX-FLUSH-INTERFACE':return _evaluate_linux_flush_interface(root,original,expected_inputs,allow_fixture)
    if case=='GAP-NETWORK-FIX':return _evaluate_network_fix(root,original,expected_inputs,allow_fixture)
    if case=='GAP-STANDALONE-LISTENERS':return _evaluate_standalone(root,original,expected_inputs,allow_fixture)
    if case=='GAP-DUMPPACKETS':return _evaluate_dumppackets(root,original,expected_inputs,allow_fixture)
    if case=='GAP-DIVERTER-SWITCH':return _evaluate_diverter_switch(root,original,expected_inputs,allow_fixture)
    if case=='GAP-EXECUTECMD':return _evaluate_executecmd(root,original,expected_inputs,allow_fixture)
    if case=='GAP-LIST-MUTEX':return _evaluate_list_mutex(root,original,expected_inputs,allow_fixture)
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):raise NotImplementedError('case is not implemented in this round: '+case)
    base=Path(original).resolve()
    def read(path):
        p=Path(path)
        if not p.is_absolute() or not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(base):raise ValueError('original path missing/outside owned case')
        return p.read_bytes()
    v=json.loads(read(base/'manual-result.json'))
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!=case:raise ValueError('case/schema mismatch')
    if not isinstance(expected_inputs,dict) or v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if v.get('fixture') and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    errors=[]
    def need(ok,reason):
        if not ok:errors.append(reason)
    states=list(v.get('listener',{}).get('transports',{}).values()) if case=='GAP-NCSI' else [v.get('listener',{})]
    need(len(states)==(2 if case=='GAP-NCSI' else 1),'lifecycle missing listeners')
    for index,s in enumerate(states):
        name=('lifecycle-'+list(v['listener']['transports'])[index]+'.json') if case=='GAP-NCSI' else 'lifecycle-http.json'
        need(json.loads(read(base/name))==s,'lifecycle original observations mismatch')
        need(s.get('started') is True and s.get('stopped') is True and s.get('thread_alive') is False and s.get('socket_closed') is True and s.get('stop_error') is None and isinstance(s.get('thread_id'),int),'lifecycle stop observation failed')
        need(s.get('bind')=='127.0.0.1' and isinstance(s.get('port'),int) and s['port']>0,'lifecycle endpoint missing')
    need(all(v.get('cleanup',{}).get(k) is True for k in ('stopped','threads_joined','sockets_closed')),'lifecycle cleanup failed')
    need(not v.get('error'),'producer error')
    if case=='GAP-NCSI':
        from dnslib import DNSRecord,QTYPE
        expected={(t,n) for t in ('udp','tcp') for n in ('dns.msftncsi.com','other.example')}
        rows=v.get('queries',[]);counts=Counter((r.get('transport'),r.get('name')) for r in rows)
        need(set(counts)==expected and all(x==1 for x in counts.values()),'four-combination DNS coverage failed')
        for row in rows:
            try:
                qb=read(row['query']);rb=read(row['response']);q=DNSRecord.parse(qb);r=DNSRecord.parse(rb)
                wire_query=read(row['wire_query']);wire_response=read(row['wire_response'])
                if row['transport']=='tcp':
                    if wire_query!=struct.pack('!H',len(qb))+qb or wire_response!=struct.pack('!H',len(rb))+rb:raise ValueError('TCP frame boundary mismatch')
                elif wire_query!=qb or wire_response!=rb:raise ValueError('UDP datagram mismatch')
                name=str(q.q.qname).rstrip('.');want='131.107.255.225' if name=='dns.msftncsi.com' else expected_inputs.get('responsea','192.0.2.55')
                if (len(q.questions)!=1 or len(r.questions)!=1 or len(r.rr)!=1 or name!=row['name'] or name not in ('dns.msftncsi.com','other.example') or q.header.id!=r.header.id or q.header.qr!=0 or r.header.qr!=1 or r.header.rcode!=0 or q.q.qtype!=QTYPE.A or str(r.q.qname)!=str(q.q.qname) or r.q.qtype!=QTYPE.A or [str(a.rdata) for a in r.rr if a.rtype==QTYPE.A]!=[want]):raise ValueError('wire identity/answer mismatch')
                for k,data in [('query',qb),('response',rb)]:
                    if row.get(k+'_sha256')!=hashlib.sha256(data).hexdigest():raise ValueError('byte hash mismatch')
                s=v['listener']['transports'][row['transport']]
                if row['peer']!=['127.0.0.1',s['port']] or row['server_port']!=s['port'] or not row.get('client_port') or row.get('client_closed') is not True:raise ValueError('wire endpoint/client exit mismatch')
            except Exception as e:errors.append('DNS bytes: '+str(e))
        checks=['ncsi-ipv4','other-domain','dns-evidence']
    else:
        try:
            need(read(v['raw_template'])==RAW,'template raw differs from fixed stimulus')
            need(read(v['static_template'])==STATIC,'template static differs from fixed stimulus')
            config_bytes=read(base/'config/custom.ini');config=configparser.ConfigParser();config.read_string(config_bytes.decode())
            wanted={'raw':{'listenertype':'HTTP','httpuris':'/raw','httphosts':'example.test','httprawfile':'raw.bin'},'static':{'listenertype':'HTTP','httpuris':'/static','httphosts':'example.test','httpstaticstring':STATIC.decode(),'contenttype':'text/plain'}}
            need({section:dict(config.items(section)) for section in config.sections()}==wanted,'template configuration mismatch')
            need(hashlib.sha256(config_bytes).hexdigest()==v.get('config_sha256'),'template configuration hash mismatch')
            need(Path(v['raw_template'])==base/'config/raw.bin' and Path(v['static_template'])==base/'static.txt','template path mismatch')
            exchanges=v['http']['exchanges'];expected={'raw':('example.test','/raw'),'static':('example.test','/static'),'wrong-host':('other.test','/raw'),'wrong-uri':('example.test','/none')}
            need(Counter(r.get('name') for r in exchanges)==Counter(expected.keys()),'HTTP request coverage failed')
            for row in exchanges:
                name=row['name'];host,path=expected[name];request=read(row['request']);response=read(row['response'])
                need(row['host']==host and row['path']==path and request==('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'%(path,host)).encode(),'HTTP request identity mismatch')
                need(row['peer']==['127.0.0.1',v['listener']['port']] and row['client_closed'] is True,'lifecycle HTTP peer/client failed')
                try:
                    header,body=response.split(b'\r\n\r\n',1);lines=header.split(b'\r\n');fields={k.decode().lower():val.strip() for k,val in (line.split(b':',1) for line in lines[1:])}
                    date=fields['date'];dt=email.utils.parsedate_to_datetime(date.decode());stamp=dt.timestamp()
                    if dt.tzinfo is None or not row['started_epoch']-2<=stamp<=row['ended_epoch']+2:raise ValueError('HTTP date outside original observation window')
                    if email.utils.format_datetime(dt,usegmt=True).encode()!=date:raise ValueError('HTTP date not canonical RFC')
                    if name=='raw':need(response==RAW.replace(b'<RAW-DATE>',date),'HTTP bytes raw mismatch')
                    else:
                        expected_body=STATIC.replace(b'<RAW-DATE>',date) if name=='static' else (b'normal-file-raw' if name=='wrong-host' else b'normal-file-none')
                        need(lines[0]==b'HTTP/1.0 200 OK' and body==expected_body and int(fields['content-length'])==len(body),'HTTP bytes static/file framing mismatch')
                        expected_header=b'HTTP/1.0 200 OK\r\nServer: FakeNet/manual\r\nDate: '+date+b'\r\n'
                        if name!='static':expected_header+=b'Content-Type: text/html\r\n'
                        expected_header+=b'Content-Length: '+str(len(expected_body)).encode()+b'\r\n\r\n'
                        need(response==expected_header+expected_body,'HTTP bytes original headers/body mismatch')
                    need(b'<RAW-DATE>' not in response,'HTTP bytes placeholder remains')
                except (ValueError,KeyError,TypeError) as e:errors.append(str(e) if 'HTTP date' in str(e) else 'HTTP bytes: '+str(e))
        except (ValueError,KeyError,TypeError) as e:errors.append('HTTP bytes: '+str(e))
        checks=['raw-date','preserved-bytes']
    rows=[{'id':k,'status':'fail' if errors else 'pass'} for k in checks]
    return rows,not errors,{'failures':errors}
