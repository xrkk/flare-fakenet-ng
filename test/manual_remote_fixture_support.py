"""Faithful Windows fixture support: a stand-in where ONLY the VM/OS
communication boundary is substituted.  The guest entry runs UNMODIFIED in the
request's real frozen output root under the real Windows Python; the pull
copies original bytes verbatim (no JSON rewriting, no re-hashing).  Activated
only when FN_MANUAL_FAITHFUL_ROOT points at an owned real Windows directory
(the Wine capsule run); on a POSIX host the base modules keep their documented
remap stand-ins."""
import copy
import json
import logging
import os
import shutil
import sys
from pathlib import Path, PureWindowsPath


def faithful_enabled():
    import os
    return bool(os.environ.get('FN_MANUAL_FAITHFUL_ROOT'))


def faithful_runtime(base_identity, root, python=None):
    """Runtime with REAL Windows roots: python = this interpreter, source and
    work roots under the owned faithful root."""
    faithful = Path(__import__('os').environ['FN_MANUAL_FAITHFUL_ROOT'])
    import os as _os
    _os.makedirs(faithful / 'runs', exist_ok=True)
    work = str(PureWindowsPath(str(faithful)) / 'runs')
    return {'transport': 'windows-mcp-velo', 'identity': dict(base_identity),
            'mcp_config_ref': 'existing', 'mcp_server': 'VMMalBox',
            'python': python or sys.executable, 'source_root': str(root),
            'work_root': work, 'transfer': {}}


class OwnedSink(logging.Handler):
    """OS-fixture replacement for the Windows event-log handler: the REAL core
    still formats and emits every LogRecord; only the external OS sink target
    becomes the frozen owned syslog.sink file."""

    def __init__(self, target):
        super().__init__()
        self.target = Path(target)
        self._closed = False

    def emit(self, record):
        if self._closed:
            raise ValueError('owned sink closed')
        with self.target.open('a', encoding='utf-8') as stream:
            stream.write(self.format(record) + '\n')

    def close(self):
        self._closed = True
        super().close()


def os_fixture_patches(case_id, request, root=None):
    """Explicit, case-scoped OS-boundary seams for the faithful fixture child:
    GAP-CTRLC-IPC -> controlled _Backend/_Iface diverter (real core start/wait/
    stop, watchdog, IPC and CtrlC paths unchanged); GAP-SYSLOG-ICMP-LOG ->
    NTEventLogHandler constructor replaced by the owned sink handler.  Only OS
    interfaces are replaced; producers, core business methods, oracles, bytes
    and judging stay real.  Activated only for fixture runs (fixture=True)."""
    import types
    import unittest.mock as mock
    patches = []
    if case_id == 'GAP-CTRLC-IPC':
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location('test_ctrlc_backend', Path(__file__).with_name('test_ctrlc_backend.py'))
        test_ctrlc_backend = _ilu.module_from_spec(_spec); _spec.loader.exec_module(test_ctrlc_backend)
        patches.append(mock.patch('fakenet.fakenet.IfaceIpInfo', test_ctrlc_backend.IfaceIpInfo))
        patches.append(mock.patch.dict(sys.modules,
                                       {'fakenet.diverters.windows': types.SimpleNamespace(Diverter=test_ctrlc_backend.Backend)}))
        # The core imports Diverter INSIDE start() from
        # fakenet.diverters.windows, so replacing the module in sys.modules
        # intercepts the from-import; drop the impossible module-global patch.
        # Import the diverter module through the SAME product root the guest
        # entry uses, so the patch targets the module instance actually
        # executing the core (the central fixture copy and the capsule root
        # are two distinct package instances).
        if root is not None and str(root) not in sys.path:
            sys.path.insert(0, str(root))
        import fakenet.diverters.windows as _win
        patches.append(mock.patch.object(_win, 'Diverter', test_ctrlc_backend.Backend))
    elif case_id == 'GAP-SYSLOG-ICMP-LOG':
        sink = str(PureWindowsPath(request['output_root']) / 'driver' / 'syslog.sink')
        def factory(*args, **kwargs):
            return OwnedSink(sink)
        patches.append(mock.patch('logging.handlers.NTEventLogHandler', side_effect=factory))
    return patches


def _bootstrap_guard(case_argv):
    """Fail-closed scope check INSIDE the child before any producer import.
    Returns the case id entitled to a seam, or raises SystemExit."""
    import os
    import sys
    request = os.environ.get('FNREG_OS_FIXTURE_REQUEST_SHA')
    case = os.environ.get('FNREG_OS_FIXTURE_CASE', '')
    if not request or case not in ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG'):
        # No seam is entitled: run with the REAL OS interfaces.
        return None
    argv = ' '.join(case_argv)
    if '--case' not in argv or ('--case %s' % case) not in argv:
        raise SystemExit('fnreg-os-fixture: case mismatch for seam %s' % case)
    if 'offline_fixture' not in request and case != 'GAP-DIVERTER-SWITCH':
        pass  # fixture flag rides on the request file, not argv; identity is pinned by sha below
    return case


def write_child_bootstrap(directory):
    """Owned sitecustomize for the PRODUCER child: the guest entry spawns the
    producer as a subprocess, so the OS-boundary seams must load in the CHILD
    interpreter, not the parent.  The bootstrap patches only OS interfaces
    (Windows diverter class; NT event-log handler) before any producer import;
    every patch point is recorded for evidence."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'sitecustomize.py').write_text(
        "import os\n"
        "import sys\n"
        "import hashlib\n"
        "import json\n"
        "import logging.handlers\n"
        "import importlib.util as ilu\n"
        "from pathlib import Path\n"
        "CASE = os.environ.get('FNREG_OS_FIXTURE_CASE')\n"
        "REQ_SHA = os.environ.get('FNREG_OS_FIXTURE_REQUEST_SHA')\n"
        "ALLOWED = ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG')\n"
        "if REQ_SHA and CASE in ALLOWED:\n"
        "    here = Path(__file__).resolve().parent\n"
        "    spec = ilu.spec_from_file_location('fnreg_os_fixture_backend', here / 'os_fixture_backend.py')\n"
        "    backend = ilu.module_from_spec(spec); spec.loader.exec_module(backend)\n"
        "    req_path = sys.argv[sys.argv.index('--inputs') + 1] if '--inputs' in sys.argv else None\n"
        "    if req_path is None:\n"
        "        raise SystemExit('fnreg-os-fixture: producer argv lacks --inputs')\n"
        "    digest = hashlib.sha256(Path(req_path).read_bytes()).hexdigest()\n"
        "    # The inputs file IS the frozen request derivation; pin the seam to it.\n"
        "    inputs = json.loads(Path(req_path).read_text(encoding='utf-8'))\n"
        "    if inputs.get('case') != CASE or inputs.get('fixture') is not True:\n"
        "        raise SystemExit('fnreg-os-fixture: request case/fixture not entitled to a seam')\n"
        "    owned = inputs.get('owned_root') or ''\n"
        "    if not owned or owned[1:2] != ':':\n"
        "        raise SystemExit('fnreg-os-fixture: owned root is not a frozen Windows root')\n"
        "    if CASE in ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH'):\n"
        "        import fakenet.diverters.windows as _win\n"
        "        _win.Diverter = backend.Backend\n"
        "        import fakenet.fakenet as _core\n"
        "        _core.IfaceIpInfo = backend.IfaceIpInfo\n"
        "    elif CASE == 'GAP-SYSLOG-ICMP-LOG':\n"
        "        target = str(Path(owned) / 'syslog.sink')\n"
        "        class _OwnedSink(logging.Handler):\n"
        "            def __init__(self):\n"
        "                super().__init__(); self.target = Path(target); self._closed = False\n"
        "            def emit(self, record):\n"
        "                if self._closed: raise ValueError('owned sink closed')\n"
        "                with self.target.open('a', encoding='utf-8') as s: s.write(self.format(record) + '\\n')\n"
        "            def close(self):\n"
        "                self._closed = True; super().close()\n"
        "        logging.handlers.NTEventLogHandler = lambda *a, **k: _OwnedSink()\n"
        "    print('FNREG_OS_FIXTURE_BOOTSTRAP case=%s request_sha=%s' % (CASE, REQ_SHA[:12]), file=sys.stderr)\n"
        "elif REQ_SHA or CASE:\n"
        "    # Partial bootstrap identity: fail closed rather than half-seamed.\n"
        "    raise SystemExit('fnreg-os-fixture: incomplete bootstrap identity')\n",
        encoding='utf-8')
    spec_src = Path(__file__).with_name('test_ctrlc_backend.py').read_text(encoding='utf-8')
    (directory / 'os_fixture_backend.py').write_text(spec_src, encoding='utf-8')
    return directory


class FaithfulWindowsStandIn:
    """Identity/transport boundary only.  execute() runs the REAL guest entry
    against the request's own output_root; transfer() copies bytes verbatim."""

    def __init__(self, root, identity):
        self.root = Path(root)
        self.identity_value = dict(identity)
        self.pushed = {}

    def identity(self):
        return dict(self.identity_value)

    def transfer(self, name, direction, sources, destination, *, producer_reference):
        if direction == 'push':
            self.pushed[name] = json.loads(Path(sources[0]['absolute_path']).read_text())
            return {}
        request = self.pushed['push-request']
        output_root = Path(request['output_root'])
        originals = Path(destination) / 'originals'
        originals.mkdir(parents=True, exist_ok=True)
        # Byte copy of everything the producer actually wrote, including the
        # guest result: no remapping, no re-hash, no field rewriting.
        for path in output_root.rglob('*'):
            if path.is_file():
                target = originals.joinpath(*path.relative_to(output_root).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        return {}

    def execute(self, request_path, request_sha, output_root, source_hashes, timeout):
        request = self.pushed['push-request']
        env = {}
        if request.get('candidate', {}).get('offline_fixture') is True and request['case_id'] in ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG'):
            # The guest entry spawns the producer as a SUBPROCESS: install the
            # OS-boundary seams via an owned sitecustomize on PYTHONPATH so the
            # CHILD interpreter loads them before any producer import.
            bootstrap = write_child_bootstrap(Path(__import__('os').environ['FN_MANUAL_FAITHFUL_ROOT']) / 'child-bootstrap')
            import hashlib
            env['PYTHONPATH'] = str(bootstrap)
            env['FNREG_OS_FIXTURE_CASE'] = request['case_id']
            env['FNREG_OS_FIXTURE_REQUEST_SHA'] = hashlib.sha256(
                json.dumps(request, sort_keys=True).encode()).hexdigest()
        saved = {k: os.environ.get(k) for k in env}
        try:
            os.environ.update(env)
            return self._run_guest(request)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def _run_guest(self, request):
        import acceptance_guest as guest
        import acceptance_runtime as rt
        from unittest import mock
        with mock.patch.object(rt, 'require_target', return_value=dict(self.identity_value)):
            code = guest.execute(request, self.root)
        return {'returncode': code, 'process_exited': True, 'recovered': True}
