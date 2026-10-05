"""Bounded exact-domain DNS capture around the original Suite P7 probe.

Import starts no capture. Probe hooks are scoped to one owner's admission.
"""
from contextlib import contextmanager
import json, signal, subprocess, time, uuid
from pathlib import Path
import scenario_suite as s
from .context import exact_path
from .instance import save
from .dns_evidence import api_ipv4
from .source import export_closed_run
_ACTIVE_PROBE_HOOKS = None

class Captures:

    def __init__(self, runner, context):
        self.context = context.revalidate()
        self.pending = None
        assert exact_path(str(runner.root)).is_relative_to(context.evidence_root)
        self.runner = runner
        self.owned = []
        self.seq = 0

    @contextmanager
    def probe_hooks(self):
        global _ACTIVE_PROBE_HOOKS
        self.context.revalidate()
        if _ACTIVE_PROBE_HOOKS is not None:
            raise RuntimeError('another P7 hook owner is active; no context overlap')
        old_begin, old_end = (s.p7_capture_begin, s.p7_capture_end)
        _ACTIVE_PROBE_HOOKS = self
        s.p7_capture_begin, s.p7_capture_end = (self.begin, self.end)
        try:
            yield self
        finally:
            s.p7_capture_begin, s.p7_capture_end = (old_begin, old_end)
            _ACTIVE_PROBE_HOOKS = None

    def close(self):
        errors = []
        records = []
        unresolved = []
        while self.owned:
            p, stream, path, command = self.owned.pop()
            try:
                if p.poll() is None:
                    p.send_signal(signal.SIGINT)
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(5)
            except BaseException as e:
                errors.append(repr(e))
            finally:
                try:
                    stream.close()
                except BaseException as e:
                    errors.append(repr(e))
                try:
                    returncode = p.poll()
                except BaseException as e:
                    errors.append(repr(e))
                    returncode = None
                if returncode is None:
                    unresolved.append((p, stream, path, command))
                records.append({'pid': p.pid, 'argv': command, 'returncode': returncode, 'pcap': s.file_record(path) if path.exists() else None})
        self.owned = unresolved
        if errors or unresolved:
            raise RuntimeError(str({'errors': errors, 'unresolved_writer_pids': [x[0].pid for x in unresolved]}))
        return records

    def begin(self, root, sid, attempt):
        self.context.revalidate()
        assert exact_path(str(root)).is_relative_to(self.context.evidence_root)
        assert not self.owned
        self.seq += 1
        out = Path(root) / ('P7-original-capture-' + str(self.seq))
        out.mkdir(exist_ok=False)
        expected_files = list(Path(root).glob('instance-gates/*/new-instance-identity.json'))
        assert len(expected_files) == 1
        expected = json.loads(expected_files[0].read_text())
        native_command = '$ErrorActionPreference=\'Stop\';$s=Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'";$p=Get-Process -Id $s.ProcessId;@{pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()}|ConvertTo-Json -Compress'
        native_raw = self.runner.vm.powershell(native_command, 30)
        assert json.loads(native_raw['output']) == expected
        save(out / 'current-SCM-before-original-capture.json', native_raw)
        p4 = Path(root) / 'preflight-evidence/p4-route-dns.json'
        value = json.loads(p4.read_text())['value']
        api_ipv4(value['api_ipv4'])
        binding = {'P4_original': s.file_record(p4), 'api_ipv4': value['api_ipv4'], 'external_dns_server': value['external_dns_server'], 'routes': value['routes'], 'native_identity': expected, 'capture_root': str(out), 'P4_not_runtime_lease': True}
        save(out / 'P4-route-only-binding.json', binding)
        route = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', '192.168.204.233'], text=True, timeout=10))[0]
        assert route['prefsrc'] == '192.168.204.1'
        save(out / 'host-only-route-original.json', route)
        from .dns_evidence import dns_filter
        filter = dns_filter('192.168.204.233', value['external_dns_server'])
        save(out / 'DNS-capture-intent.json', {'filter': filter, 'domain': 'api.deepseek.com', 'protocol': 'UDP DNS', 'no_TLS_host_capture': True, 'P4_API_not_capture_target': True})
        control = {'root': str(out), 'sid': sid, 'attempt': attempt, 'native_identity': expected, 'native_identity_command': native_command, 'P4_route_only': binding, 'DNS_capture': str(out / 'runtime-api-DNS.pcap'), 'capture_contract': 'exact-domain runtime UDP DNS + original native relay records', 'added_host_capture_writers': 1, 'no_external_TLS_capture': True, 'route': route, 'filter': filter, 'activated': False}
        self.pending = control
        self.runner.vm.p7_binding = binding
        self.runner.vm.p7_capture_start = self.activate
        return control

    def activate(self):
        self.context.revalidate()
        control = self.pending
        assert control and (not control['activated']) and (not self.owned)
        out = Path(control['root'])
        route = control['route']
        filter = control['filter']
        save(out / 'DNS-capture-activation.json', {'trigger': 'actual original preflight-b1 VM command after Suite._preflight_b1 healthy start', 'P4_DNS_not_reused': True, 'before_original_domain_probe': True})
        subprocess.run(['dumpcap', '-D'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        path = out / 'runtime-api-DNS.pcap'
        cmd = ['dumpcap', '-i', route['dev'], *([] if route['dev'] == 'vmnet8' else ['-p']), '-P', '-s', '0', '-a', 'duration:180', '-a', 'filesize:16384', '-f', filter, '-w', str(path)]
        stream = (out / 'DNS-capture.stderr').open('x')
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=stream)
            self.owned.append((process, stream, path, cmd))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                assert process.poll() is None
                if path.exists() and path.stat().st_size >= 24:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('capture readiness deadline')
        except BaseException as error:
            closed, cleanup_error = [], None
            try:
                if not self.owned:
                    stream.close()
                closed = self.close()
            except BaseException as secondary:
                cleanup_error = repr(secondary)
                error.add_note('capture cleanup failed: ' + cleanup_error)
            try:
                save(out / 'DNS-capture-start-failure.json', {'error': repr(error), 'closed': closed,
                     'cleanup_error': cleanup_error, 'host_writers_ended': not bool(self.owned)})
            except BaseException as secondary:
                error.add_note('capture failure audit failed: ' + repr(secondary))
            raise
        control['activated'] = True

    def end(self, control, run, probe, cleanup):
        self.context.revalidate()
        if not control:
            return
        out = Path(control['root'])
        primary, closed = None, []
        try:
            closed = self.close()
            save(out / 'DNS-capture-closed.json', closed)
            raw = self.runner.vm.powershell(control['native_identity_command'], 30)
            save(out / 'current-SCM-after-original-capture.json', raw)
            assert json.loads(raw['output']) == control['native_identity']
            save(out / 'original-probe-and-cleanup.json', {'run_id': run, 'probe': probe, 'cleanup': cleanup})
            if not run or not probe:
                raise RuntimeError('P7 did not reach original domain probe; no invented lease/capture')
            final = cleanup.get('final') or {}
            assert not cleanup.get('errors') and final.get('state') == 'stopped' and (not final.get('run_id')) and (not final.get('controller')), 'P7 run capture must be stopped/ownerfree before original export'
            assert str(uuid.UUID(run)) == run
            exported = export_closed_run(self.runner, self.context, run, cleanup, out / 'closed-P7-originals')
            save(out / 'closed-P7-export-summary.json', exported)
            index = json.loads((out / 'closed-P7-originals/guest-original-index.json').read_text())
            guest_root = 'C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\' + run
            logs = [Path(x['host_path']) for x in index if x['guest']['path'] == guest_root + '\\run.log']
            native = [Path(x['host_path']) for x in index if x['guest']['path'] == guest_root + '\\relay-native-events.jsonl']
            assert len(logs) == len(native) == 1
            from .dns_evidence import bind_dns_native
            verdict = bind_dns_native(control['DNS_capture'], logs[0], native[0], probe, run, control['P4_route_only'], source='192.168.204.233')
            save(out / 'runtime-DNS-lease-TLS-binding.json', {'passed': True, 'captures': [verdict], 'no_external_TLS_host_capture': True, 'unrelated_packets_never_accepted': True})
        except BaseException as error:
            primary = error
            try:
                save(out / 'P7-binding-failure.json', {'error': repr(error), 'original_failure_retained': True, 'no_fake_lease_or_retry': True})
            except BaseException as secondary:
                error.add_note('P7 failure audit failed: ' + repr(secondary))
            raise
        finally:
            self.runner.vm.p7_binding = None
            self.runner.vm.p7_capture_start = None
            self.pending = None
            cleanup_error = None
            try:
                closed.extend(self.close())
            except BaseException as secondary:
                cleanup_error = secondary
            final = cleanup.get('final') or {}
            terminal = {'added_host_writers': closed, 'host_writers_ended': not bool(self.owned),
                        'unresolved_writer_pids': [item[0].pid for item in self.owned],
                        'cleanup_error': repr(cleanup_error) if cleanup_error else None,
                        'original_managed_capture_closed': bool(final) and not cleanup.get('errors')
                        and final.get('state') == 'stopped' and not final.get('run_id') and not final.get('controller'),
                        'domain_only_DNS_host_capture': True}
            try:
                save(out / 'terminal.json', terminal)
            except BaseException as secondary:
                if cleanup_error:
                    cleanup_error.add_note('terminal audit failed: ' + repr(secondary))
                else:
                    cleanup_error = secondary
            if cleanup_error:
                if primary:
                    primary.add_note('P7 terminal cleanup/audit failed: ' + repr(cleanup_error))
                else:
                    raise cleanup_error
