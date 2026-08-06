"""One-click Linux VM acceptance runner for synchronized dual PCAP output.

This is intentionally a real-network test harness. It refuses non-Linux,
non-root, container, and unverified physical-host execution before FakeNet-NG
is imported or any network state is changed.
"""

import base64
import configparser
import datetime
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback


PACKAGE_VERSION = 'v1'
PLAN_VERSION = 'v4'
TARGET_IP = '198.51.100.77'
TARGET_PORT = 53535
MARKER = 'dual-pcap-linux-v1'
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
LOG_ROOT = REPO_ROOT / 'dist' / 'Logs'
REQUIRED_COMMANDS = (
    'iptables', 'iptables-save', 'iptables-restore',
    'ip6tables-save', 'ip6tables-restore', 'ip')
REQUIRED_MODULES = (
    'dpkt', 'dnslib', 'netifaces', 'pyftpdlib', 'cryptography',
    'OpenSSL', 'jinja2', 'netfilterqueue')


class AcceptanceError(RuntimeError):
    pass


class Runner(object):
    def __init__(self):
        stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        self.run_directory = LOG_ROOT / (
            'dual-pcap-linux-%s-%s' % (PACKAGE_VERSION, stamp))
        self.results = []
        self.active = None
        self.active_stop_flag = None
        self.interrupted = False
        self.virtualization = None
        self.run_directory.mkdir(parents=True, exist_ok=False)
        self.results_path = self.run_directory / 'results.tsv'
        self.results_path.write_text(
            'status\tname\tdetail\n', encoding='utf-8', newline='\n')

    def record(self, name, passed, detail):
        status = 'PASS' if passed else 'FAIL'
        clean = str(detail).replace('\t', ' ').replace('\r', ' ').replace(
            '\n', ' | ')
        row = {'status': status, 'name': name, 'detail': clean}
        self.results.append(row)
        with self.results_path.open('a', encoding='utf-8', newline='\n') as out:
            out.write('%s\t%s\t%s\n' % (status, name, clean))
        print('%-7s %-28s %s' % (status, name, clean), flush=True)

    def step(self, name, action):
        try:
            detail = action()
        except BaseException as exc:
            self.record(name, False, '%s: %s' % (type(exc).__name__, exc))
            raise
        self.record(name, True, detail)
        return detail

    def signal_stop(self, signum, unused_frame):
        self.interrupted = True
        print('\nSignal %s received; stopping the active VM test safely.' %
              signum, flush=True)
        if self.active_stop_flag is not None:
            try:
                self.active_stop_flag.touch(exist_ok=True)
            except OSError:
                pass

    def validate_manifest(self):
        manifest_path = REPO_ROOT / 'dual-pcap-linux-manifest.json'
        if not manifest_path.exists():
            return 'source-tree run; packaged manifest is absent by design'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        if manifest.get('package_version') != PACKAGE_VERSION:
            raise AcceptanceError('package manifest version mismatch')
        if manifest.get('plan_version') != PLAN_VERSION:
            raise AcceptanceError('plan manifest version mismatch')
        if manifest.get('logs_plaintext') is not True:
            raise AcceptanceError('manifest does not require plaintext logs')
        for row in manifest.get('files', []):
            path = REPO_ROOT / Path(row['path'])
            try:
                path.relative_to(REPO_ROOT)
            except ValueError:
                raise AcceptanceError('manifest path escapes package root')
            if not path.is_file():
                raise AcceptanceError('manifest file missing: %s' % row['path'])
            content = path.read_bytes()
            if len(content) != row['size']:
                raise AcceptanceError('manifest size mismatch: %s' % row['path'])
            if hashlib.sha256(content).hexdigest() != row['sha256']:
                raise AcceptanceError('manifest hash mismatch: %s' % row['path'])
        return 'package=%s; source_commit=%s; files=%d' % (
            manifest['package_version'], manifest['source_commit'],
            len(manifest.get('files', [])))

    @staticmethod
    def _command(command, timeout=10, input_bytes=None, check=True):
        completed = subprocess.run(
            command, input=input_bytes, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False)
        if check and completed.returncode != 0:
            raise AcceptanceError(
                'command failed (%s): %s' %
                (' '.join(command), completed.stderr.decode(
                    'utf-8', errors='replace').strip()))
        return completed

    def detect_vm(self):
        if shutil.which('systemd-detect-virt'):
            container = self._command(
                ['systemd-detect-virt', '--container'], check=False)
            if container.returncode == 0:
                raise AcceptanceError(
                    'containers are refused; use a snapshotted Linux VM')
            vm = self._command(
                ['systemd-detect-virt', '--vm'], check=False)
            value = vm.stdout.decode('utf-8', errors='replace').strip()
            if vm.returncode == 0 and value and value != 'none':
                return value
        dmi = []
        for name in ('sys_vendor', 'product_name', 'board_vendor'):
            path = Path('/sys/class/dmi/id') / name
            if path.is_file():
                dmi.append(path.read_text(
                    encoding='utf-8', errors='replace').strip())
        rendered = ' '.join(dmi).lower()
        tokens = ('vmware', 'virtualbox', 'kvm', 'qemu', 'hyper-v',
                  'microsoft corporation virtual machine', 'xen')
        if any(token in rendered for token in tokens):
            return 'dmi:' + ' / '.join(dmi)
        raise AcceptanceError(
            'virtual-machine identity could not be proven; physical hosts are refused')

    @staticmethod
    def _running_fakenet_processes():
        found = []
        proc = Path('/proc')
        for child in proc.iterdir():
            if not child.name.isdigit() or int(child.name) == os.getpid():
                continue
            try:
                command = (child / 'cmdline').read_bytes().replace(b'\0', b' ')
            except OSError:
                continue
            lowered = command.lower()
            if b'fakenet.fakenet' in lowered or b'fault_launcher.py' in lowered:
                found.append('%s:%s' % (
                    child.name, command.decode('utf-8', errors='replace')))
        return found

    def preflight(self):
        if platform.system() != 'Linux':
            raise AcceptanceError('Linux is required; current=%s' % platform.system())
        if not hasattr(os, 'geteuid') or os.geteuid() != 0:
            raise AcceptanceError('root is required for the isolated VM acceptance run')
        self.virtualization = self.detect_vm()
        missing = [name for name in REQUIRED_COMMANDS if not shutil.which(name)]
        if missing:
            raise AcceptanceError('required commands are missing: %s' %
                                  ', '.join(missing))
        if self._running_fakenet_processes():
            raise AcceptanceError('another FakeNet-NG process is already running')
        resolv = Path('/etc/resolv.conf')
        if not resolv.exists() or not os.access(str(resolv), os.W_OK):
            raise AcceptanceError('/etc/resolv.conf is not writable')
        if sys.version_info < (3, 10):
            raise AcceptanceError('Python 3.10 or newer is required')
        return ('vm=%s; kernel=%s; python=%s; uid=%d' % (
            self.virtualization, platform.release(),
            platform.python_version(), os.geteuid()))

    def dependency_identity(self):
        rows = {}
        for name in REQUIRED_MODULES:
            module = importlib.import_module(name)
            rows[name] = {
                'path': os.path.abspath(getattr(module, '__file__', 'built-in')),
                'version': getattr(module, '__version__', 'unknown')}
        dpkt = importlib.import_module('dpkt')
        if getattr(dpkt, '__version__', None) != '1.9.8':
            raise AcceptanceError('dpkt 1.9.8 is required; found %s' %
                                  getattr(dpkt, '__version__', 'unknown'))
        if dpkt.pcap.DLT_RAW != 12:
            raise AcceptanceError('dpkt DLT_RAW must be 12')
        fakenet = importlib.import_module('fakenet')
        source = Path(fakenet.__file__).resolve()
        try:
            source.relative_to(REPO_ROOT)
        except ValueError:
            raise AcceptanceError('fakenet imported outside this package: %s' % source)
        rows['python'] = {'path': sys.executable, 'version': sys.version}
        rows['fakenet'] = {'path': str(source)}
        rows['dpkt']['dlt_raw'] = dpkt.pcap.DLT_RAW
        rows['distributions'] = {}
        for distribution in ('dpkt', 'dnslib', 'netifaces', 'pyftpdlib',
                             'cryptography', 'pyOpenSSL', 'Jinja2',
                             'NetfilterQueue'):
            try:
                rows['distributions'][distribution] = \
                    importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError:
                rows['distributions'][distribution] = 'metadata-unavailable'
        output = self.run_directory / 'dependency-identity.json'
        output.write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n',
                          encoding='utf-8', newline='\n')
        return 'dpkt=1.9.8; DLT_RAW=12; identity=%s' % output

    def child_environment(self):
        environment = os.environ.copy()
        environment['PYTHONPATH'] = str(REPO_ROOT)
        environment['PYTHONIOENCODING'] = 'utf-8'
        return environment

    def run_logged(self, name, command, timeout):
        log = self.run_directory / ('%s.log' % name)
        with log.open('wb') as stream:
            completed = subprocess.run(
                command, cwd=str(REPO_ROOT), env=self.child_environment(),
                stdout=stream, stderr=subprocess.STDOUT, timeout=timeout,
                check=False)
        if completed.returncode != 0:
            raise AcceptanceError('%s exited %d; see %s' %
                                  (name, completed.returncode, log))
        return log

    @staticmethod
    def _dns_state():
        path = Path('/etc/resolv.conf')
        return {
            'is_symlink': path.is_symlink(),
            'link_target': os.readlink(str(path)) if path.is_symlink() else None,
            'content': path.read_bytes()}

    def network_snapshot(self):
        return {
            'iptables': self._command(['iptables-save']).stdout,
            'ip6tables': self._command(['ip6tables-save']).stdout,
            'routes4': self._command(['ip', '-4', 'route', 'show',
                                      'table', 'all']).stdout,
            'routes6': self._command(['ip', '-6', 'route', 'show',
                                      'table', 'all']).stdout,
            'dns': self._dns_state()}

    @staticmethod
    def _serializable_snapshot(snapshot):
        rendered = {}
        for name in ('iptables', 'ip6tables', 'routes4', 'routes6'):
            value = snapshot[name]
            rendered[name] = {
                'sha256': hashlib.sha256(value).hexdigest(),
                'base64': base64.b64encode(value).decode('ascii')}
        rendered['dns'] = {
            'is_symlink': snapshot['dns']['is_symlink'],
            'link_target': snapshot['dns']['link_target'],
            'sha256': hashlib.sha256(snapshot['dns']['content']).hexdigest(),
            'base64': base64.b64encode(
                snapshot['dns']['content']).decode('ascii')}
        return rendered

    def write_snapshot(self, path, snapshot):
        path.write_text(json.dumps(
            self._serializable_snapshot(snapshot), indent=2,
            sort_keys=True) + '\n', encoding='utf-8', newline='\n')

    @staticmethod
    def snapshot_differences(before, after):
        differences = []
        for name in ('iptables', 'ip6tables', 'routes4', 'routes6'):
            if before[name] != after[name]:
                differences.append(name)
        if before['dns'] != after['dns']:
            differences.append('dns')
        return differences

    def emergency_restore(self, before, case_directory, differences):
        """Safety rollback only; it never converts a failed check into PASS."""
        rows = ['differences before emergency rollback: %s' %
                ', '.join(differences)]
        if 'iptables' in differences:
            result = self._command(
                ['iptables-restore'], input_bytes=before['iptables'], check=False)
            rows.append('iptables-restore exit=%d stderr=%s' % (
                result.returncode,
                result.stderr.decode('utf-8', errors='replace').strip()))
        if 'ip6tables' in differences:
            result = self._command(
                ['ip6tables-restore'], input_bytes=before['ip6tables'], check=False)
            rows.append('ip6tables-restore exit=%d stderr=%s' % (
                result.returncode,
                result.stderr.decode('utf-8', errors='replace').strip()))
        if 'dns' in differences:
            current = self._dns_state()
            same_link = (
                current['is_symlink'] == before['dns']['is_symlink'] and
                current['link_target'] == before['dns']['link_target'])
            if same_link:
                Path('/etc/resolv.conf').write_bytes(before['dns']['content'])
                rows.append('DNS content restored through unchanged path')
            else:
                rows.append('DNS link identity changed; unsafe automatic repair refused')
        after = self.network_snapshot()
        remaining = self.snapshot_differences(before, after)
        rows.append('differences after emergency rollback: %s' %
                    (', '.join(remaining) if remaining else 'none'))
        (case_directory / 'emergency-rollback.txt').write_text(
            '\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
        return remaining

    @staticmethod
    def write_config(path, prefix):
        source = REPO_ROOT / 'fakenet' / 'configs' / 'default.ini'
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read(str(source), encoding='utf-8')
        for section in parser.sections():
            if section not in ('FakeNet', 'Diverter') and \
                    parser.has_option(section, 'Enabled'):
                parser.set(section, 'Enabled', 'No')
        values = {
            'NetworkMode': 'SingleHost',
            'DebugLevel': 'PCAP,NFQUEUE,IPTABLES,MANGLE',
            'LinuxRestrictInterface': 'Off',
            'LinuxFlushIptables': 'Yes',
            'LinuxFlushDNSCommand': '/bin/true',
            'DumpPackets': 'Yes',
            'DumpPacketsFilePrefix': str(prefix),
            'FixGateway': 'No',
            'FixDNS': 'No',
            'ModifyLocalDNS': 'Yes',
            'StopDNSService': 'No',
            'RedirectAllTraffic': 'No',
            'ExternalAccessPolicy': 'Disabled'}
        parser.set('FakeNet', 'DivertTraffic', 'Yes')
        for key, value in values.items():
            parser.set('Diverter', key, value)
        with path.open('w', encoding='utf-8', newline='\n') as stream:
            parser.write(stream)

    def wait_for_ready(self, process, log_path, before, timeout=35):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.interrupted:
                raise AcceptanceError('operator interrupted the acceptance run')
            if process.poll() is not None:
                raise AcceptanceError(
                    'FakeNet-NG exited before NFQUEUE readiness: %d' %
                    process.returncode)
            text = ''
            try:
                text = log_path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                pass
            current = self._command(['iptables-save']).stdout
            if ('Capturing traffic to' in text and
                    current != before['iptables'] and b'NFQUEUE' in current):
                return
            time.sleep(0.1)
        raise AcceptanceError('timed out waiting for Linux NFQUEUE readiness')

    @staticmethod
    def send_marker():
        payload = MARKER.encode('ascii')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for index in range(4):
                sock.sendto(payload + b'-' + str(index).encode('ascii'),
                            (TARGET_IP, TARGET_PORT))
                time.sleep(0.1)
        finally:
            sock.close()

    def wait_process(self, process, stop_flag, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = process.poll()
            if code is not None:
                return code
            if self.interrupted:
                stop_flag.touch(exist_ok=True)
            time.sleep(0.1)
        stop_flag.touch(exist_ok=True)
        try:
            return process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                return process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return process.wait(timeout=5)

    @staticmethod
    def capture_paths(case_directory):
        raw = sorted(path for path in case_directory.glob('capture_*.pcap')
                     if not path.name.endswith('-converted.pcap'))
        converted = sorted(case_directory.glob('capture_*-converted.pcap'))
        if len(raw) != 1 or len(converted) != 1:
            raise AcceptanceError(
                'expected one raw and one converted PCAP; found %d/%d' %
                (len(raw), len(converted)))
        return raw[0], converted[0]

    @staticmethod
    def resource_residue(case_directory):
        needles = (str(case_directory).encode('utf-8'),)
        found = []
        for child in Path('/proc').iterdir():
            if not child.name.isdigit() or int(child.name) == os.getpid():
                continue
            try:
                command = (child / 'cmdline').read_bytes()
            except OSError:
                command = b''
            if any(needle in command for needle in needles):
                found.append('%s:cmdline' % child.name)
            fd_root = child / 'fd'
            try:
                descriptors = list(fd_root.iterdir())
            except OSError:
                continue
            for descriptor in descriptors:
                try:
                    target = os.readlink(str(descriptor)).encode('utf-8')
                except (OSError, UnicodeEncodeError):
                    continue
                if any(needle in target for needle in needles):
                    found.append('%s:fd:%s' % (child.name, descriptor.name))
        return found

    def run_case(self, mode):
        case_directory = self.run_directory / mode
        case_directory.mkdir()
        config = case_directory / 'fakenet.ini'
        stop_flag = case_directory / 'stop.flag'
        prefix = case_directory / 'capture'
        app_log = case_directory / 'fakenet.log'
        console_log = case_directory / 'console.log'
        self.write_config(config, prefix)
        before = self.network_snapshot()
        self.write_snapshot(case_directory / 'network-before.json', before)
        if mode == 'normal':
            command = [sys.executable, '-X', 'utf8', '-m', 'fakenet.fakenet',
                       '--config-file', str(config), '--stop-flag', str(stop_flag),
                       '--log-file', str(app_log), '--no-pause']
        else:
            command = [sys.executable, '-X', 'utf8',
                       str(SCRIPT_DIR / 'fault_launcher.py'), '--mode', mode,
                       '--config', str(config), '--stop-flag', str(stop_flag),
                       '--log-file', str(app_log)]
        process = None
        case_error = None
        code = None
        with console_log.open('wb') as console:
            try:
                process = subprocess.Popen(
                    command, cwd=str(REPO_ROOT), env=self.child_environment(),
                    stdout=console, stderr=subprocess.STDOUT,
                    start_new_session=True)
                self.active = process
                self.active_stop_flag = stop_flag
                self.wait_for_ready(process, app_log, before)
                self.send_marker()
                if mode in ('normal', 'close'):
                    time.sleep(1.0)
                    stop_flag.touch(exist_ok=True)
                    code = self.wait_process(process, stop_flag, 40)
                else:
                    code = self.wait_process(process, stop_flag, 25)
            except BaseException as exc:
                case_error = exc
            finally:
                if process is not None and process.poll() is None:
                    code = self.wait_process(process, stop_flag, 8)
                self.active = None
                self.active_stop_flag = None
        after = self.network_snapshot()
        self.write_snapshot(case_directory / 'network-after.json', after)
        differences = self.snapshot_differences(before, after)
        remaining = []
        if differences:
            remaining = self.emergency_restore(before, case_directory, differences)
        network_ok = not differences
        residue = self.resource_residue(case_directory)
        (case_directory / 'exit-code.txt').write_text(
            ('unavailable' if code is None else str(code)) + '\n',
            encoding='ascii', newline='\n')
        if case_error is not None:
            raise AcceptanceError('%s failed: %s; network_diff=%s; residual=%s' %
                                  (mode, case_error, differences, residue))
        if not network_ok:
            raise AcceptanceError(
                '%s did not restore network state: %s; emergency_remaining=%s' %
                (mode, differences, remaining))
        if residue:
            raise AcceptanceError('%s left process/file residue: %s' %
                                  (mode, residue))
        # The same logging record is intentionally present in both files.
        # Count fatal markers only in the application log to avoid double
        # counting the console copy.
        log_text = app_log.read_text(
            encoding='utf-8', errors='replace') if app_log.exists() else ''
        if mode == 'normal':
            if code != 0:
                raise AcceptanceError('normal case exit code is %s' % code)
            if 'PCAP_DUAL_WRITE_FAILED' in log_text:
                raise AcceptanceError('normal case contains capture-fatal log')
            if 'PCAP_DUAL_SUMMARY' not in log_text or 'healthy=True' not in log_text:
                raise AcceptanceError('normal case lacks healthy summary')
            raw, converted = self.capture_paths(case_directory)
            verify_log = case_directory / 'verify.log'
            command = [sys.executable, '-X', 'utf8',
                       str(SCRIPT_DIR / 'verify_capture.py'), str(raw),
                       str(converted), '--marker', MARKER,
                       '--original-destination', TARGET_IP, '--output',
                       str(case_directory / 'verify.json')]
            with verify_log.open('wb') as stream:
                verified = subprocess.run(
                    command, cwd=str(REPO_ROOT), env=self.child_environment(),
                    stdout=stream, stderr=subprocess.STDOUT, check=False)
            if verified.returncode != 0:
                raise AcceptanceError('live PCAP verification failed; see %s' %
                                      verify_log)
            return 'exit=0; paired PCAP and original/mangled IPv4 PASS; network restored'
        if code is None or code == 0:
            raise AcceptanceError('%s did not exit nonzero: %s' % (mode, code))
        if log_text.count('PCAP_DUAL_WRITE_FAILED') != 1:
            raise AcceptanceError('%s capture-fatal count is not one' % mode)
        if mode in ('raw-write', 'ethernet-write'):
            if log_text.count('PCAP_DUAL_CURRENT_PACKET_DROP') != 1:
                raise AcceptanceError('%s current-packet drop count is not one' % mode)
        if mode == 'close' and 'healthy=False' not in log_text:
            raise AcceptanceError('close fault lacks unhealthy summary')
        return ('exit=%d; single capture-fatal; %s; network restored' % (
            code,
            'current NFQUEUE packet dropped' if mode != 'close'
            else 'close failure observed'))

    def finish(self):
        passed = all(row['status'] == 'PASS' for row in self.results)
        summary = {
            'package_version': PACKAGE_VERSION,
            'plan_version': PLAN_VERSION,
            'run_directory': str(self.run_directory),
            'platform': platform.platform(),
            'virtualization': self.virtualization,
            'passed': passed,
            'results': self.results,
            'coverage_boundary': {
                'live': 'Linux NFQUEUE IPv4 original/mangled capture',
                'file_contract': 'IPv4, IPv6, truncated known-version, readable EOF'},
            'logs_plaintext': True,
        }
        (self.run_directory / 'summary.json').write_text(
            json.dumps(summary, indent=2, sort_keys=True) + '\n',
            encoding='utf-8', newline='\n')
        print('\nPlain logs available at: %s' % self.run_directory, flush=True)
        return 0 if passed else 1

    def run(self):
        signal.signal(signal.SIGINT, self.signal_stop)
        signal.signal(signal.SIGTERM, self.signal_stop)
        try:
            self.step('Manifest', self.validate_manifest)
            self.step('Environment', self.preflight)
            self.step('Dependencies', self.dependency_identity)

            def unit_step():
                log = self.run_logged(
                    'unit-tests', [sys.executable, '-X', 'utf8',
                     str(SCRIPT_DIR / 'run_unit_tests.py')], timeout=180)
                return 'Linux/cross-platform suites; %s' % log
            self.step('UnitTests', unit_step)

            def writer_step():
                log = self.run_logged(
                    'writer-contract', [sys.executable, '-X', 'utf8',
                     str(SCRIPT_DIR / 'writer_contract.py'),
                     '--output-directory',
                     str(self.run_directory / 'writer-contract-files')],
                    timeout=60)
                return 'IPv4/IPv6/truncated/EOF; %s' % log
            self.step('WriterContract', writer_step)

            performance = self.run_directory / 'performance.json'

            def performance_step():
                log = self.run_logged(
                    'performance', [sys.executable, '-X', 'utf8',
                     str(REPO_ROOT / 'test' / 'benchmark_dual_pcap.py'),
                     '--output', str(performance)], timeout=900)
                return ('100000 records x 64/1500, median ratio <=2.5; %s' %
                        log)
            self.step('PerformanceGate', performance_step)

            for mode in ('normal', 'raw-write', 'ethernet-write', 'close'):
                self.step('Live-' + mode,
                          lambda selected=mode: self.run_case(selected))
            if self.interrupted:
                raise AcceptanceError('acceptance run was interrupted')
        except BaseException as exc:
            self.record('Runner', False, '%s: %s' %
                        (type(exc).__name__, exc))
            (self.run_directory / 'runner-error.log').write_text(
                traceback.format_exc(), encoding='utf-8', newline='\n')
            if self.active is not None and self.active.poll() is None:
                try:
                    self.wait_process(self.active, self.active_stop_flag, 8)
                except BaseException:
                    pass
        return self.finish()


def main():
    runner = Runner()
    print('Linux dual-PCAP acceptance %s' % PACKAGE_VERSION, flush=True)
    print('This runner changes iptables and DNS only inside a proven VM.',
          flush=True)
    print('Do not run malware or another FakeNet-NG instance during acceptance.',
          flush=True)
    raise SystemExit(runner.run())


if __name__ == '__main__':
    main()
