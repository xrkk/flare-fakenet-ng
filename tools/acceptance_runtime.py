"""Fixed, local native runtime; imports perform no process or network actions.

Use only on the explicitly selected target. Readiness and recovery are observed
from the owned core and before/after state, never inferred from a delay or PID.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import time


def command(argv, timeout=15):
    result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('%r exited %s: %s' % (argv, result.returncode,
                           result.stderr.decode('utf-8', 'replace')))
    return result.stdout


def target_identity():
    return {'platform': platform.system().lower(), 'hostname': socket.gethostname()}


def require_target(expected):
    actual = target_identity()
    if expected != actual:
        raise ValueError('native target identity mismatch: %r != %r' % (actual, expected))
    if actual['platform'] == 'linux':
        if os.geteuid() != 0:
            raise ValueError('native Linux target requires root')
        if Path('/.dockerenv').exists() or Path('/run/.containerenv').exists():
            raise ValueError('native runner requires a VM, not a container')
        kind = command(['systemd-detect-virt', '--vm']).decode().strip()
        if kind not in ('vmware', 'kvm', 'qemu', 'microsoft', 'oracle', 'xen', 'parallels'):
            raise ValueError('unverified native VM: %s' % kind)
        for path in Path('/proc').iterdir():
            if not path.name.isdigit() or int(path.name)==os.getpid():
                continue
            try: argv=(path/'cmdline').read_bytes().split(b'\0')
            except OSError: continue
            if b'fakenet.fakenet' in argv or any(item.endswith(b'/fault_launcher.py') for item in argv):
                raise ValueError('another core already owns native network resources')
    elif actual['platform'] == 'windows':
        script = ("$ErrorActionPreference='Stop'; "
                  "$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); "
                  "if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 2}; "
                  "$s=Get-CimInstance Win32_ComputerSystem; "
                  "if(($s.Manufacturer+' '+$s.Model) -notmatch 'virtual|vmware|kvm|qemu|hyper-v|xen|parallels'){exit 3}; "
                  "$owners=@(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and "
                  "$_.CommandLine -match '(-m\\s+fakenet\\.fakenet|fault_launcher\\.py)' }); "
                  "if($owners.Count){exit 4}")
        command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script])
    else:
        raise ValueError('unsupported native platform')
    return actual


def network_snapshot():
    """Read exact relevant state; unavailable evidence raises, never passes."""
    if platform.system() == 'Linux':
        values = {name: base64.b64encode(command(argv)).decode('ascii')
                  for name, argv in (
                      ('iptables', ['iptables-save']), ('ip6tables', ['ip6tables-save']),
                      ('routes4', ['ip', '-4', 'route', 'show', 'table', 'all']),
                      ('routes6', ['ip', '-6', 'route', 'show', 'table', 'all']))}
        dns = Path('/etc/resolv.conf')
        values['dns'] = {'link': os.readlink(dns) if dns.is_symlink() else None,
                         'content': base64.b64encode(dns.read_bytes()).decode('ascii')}
        return values
    script = ("$ErrorActionPreference='Stop'; [ordered]@{ "
              "dns=@(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | "
              "Select-Object InterfaceIndex,AddressFamily,ServerAddresses); "
              "routes=@(Get-NetRoute | Sort-Object InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric | "
              "Select-Object InterfaceIndex,AddressFamily,DestinationPrefix,NextHop,RouteMetric,PolicyStore); "
              "dns_service=(Get-Service Dnscache).Status.ToString() } | ConvertTo-Json -Depth 8 -Compress")
    return json.loads(command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script]).decode('utf-8-sig'))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8')


class OwnedCore:
    def __init__(self, argv, cwd, directory, stop_flag, app_log, source_root=None):
        self.argv, self.cwd = list(argv), Path(cwd)
        self.directory = Path(directory)
        self.stop_flag, self.app_log = Path(stop_flag), Path(app_log)
        self.source_root = source_root
        self.process = None
        self.console = None
        self.state = {'ready': False, 'stopped': False, 'forced': False,
                      'argv': self.argv, 'returncode': None}

    def start(self, timeout=40):
        if self.process is not None or self.stop_flag.exists() or self.app_log.exists():
            raise RuntimeError('owned core paths/process already in use')
        self.console = (self.directory/'core-console.log').open('xb')
        try:
            options = {'start_new_session': True} if os.name != 'nt' else {
                'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
            env = os.environ.copy()
            if self.source_root is not None:
                env['PYTHONPATH'] = str(self.source_root)
            self.process = subprocess.Popen(self.argv, cwd=self.cwd, shell=False, env=env,
                                            stdout=self.console, stderr=subprocess.STDOUT, **options)
            self.state['pid'] = self.process.pid
            deadline = time.monotonic()+timeout
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError('owned core exited before ready')
                text = self.app_log.read_text(encoding='utf-8', errors='replace') if self.app_log.exists() else ''
                if 'FakeNet-NG started successfully' in text:
                    self.state['ready'] = True
                    return
                time.sleep(.1)
            raise TimeoutError('owned core readiness timeout')
        except BaseException:
            self.stop()
            raise

    def stop(self, timeout=30):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    self.stop_flag.touch(exist_ok=True)
                    try:
                        self.process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        self.state['forced'] = True
                        # The forced path is always a failed recovery; it cannot
                        # earn native cleanup credit, even if the process exits.
                        self.process.terminate()
                        try:
                            self.process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            self.process.kill()
                            self.process.wait(timeout=5)
                self.state['returncode'] = self.process.returncode
                self.state['stopped'] = self.process.poll() is not None
        finally:
            if self.console is not None:
                self.console.close()
            write_json(self.directory/'core-lifecycle.json', self.state)
        return self.state['stopped'] and not self.state['forced'] and self.state['returncode'] == 0
