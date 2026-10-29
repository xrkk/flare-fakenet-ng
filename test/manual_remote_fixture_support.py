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


def write_child_bootstrap(directory):
    """Owned sitecustomize for the PRODUCER child: the guest entry spawns the
    producer as a subprocess, so the OS-boundary seams must load in the CHILD
    interpreter, not the parent.  The bootstrap patches only OS interfaces
    (Windows diverter class; NT event-log handler) before any producer import;
    every patch point is recorded for evidence."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'sitecustomize.py').write_text(
        "import hashlib\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "import traceback\n"
        "from pathlib import Path, PureWindowsPath\n"
        "ALLOWED = ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG')\n"
        "# This sitecustomize runs only for parent-authorized fixture children.\n"
        "# Any missing/invalid identity is a FATAL startup error: SystemExit in\n"
        "# sitecustomize terminates the interpreter (unlike Exception, which\n"
        "# Python only warns about and continues), so the producer NEVER runs\n"
        "# and no real OS interface is reached.\n"
        "def _die(reason):\n"
        "    sys.stderr.write('FNREG_OS_FIXTURE_REFUSED: %s\\n' % reason)\n"
        "    raise SystemExit(78)\n"
        "pins_raw = os.environ.get('FNREG_OS_FIXTURE_PINS')\n"
        "if not pins_raw:\n"
        "    _die('no pinned spec: this sitecustomize is only for authorized fixture children')\n"
        "try:\n"
        "    pins = json.loads(pins_raw)\n"
        "except Exception:\n"
        "    _die('pinned spec is not valid JSON')\n"
        "required = ('case', 'fixture', 'request_file_sha256', 'request_file', 'expected_inputs',\n"
        "            'output_root', 'owned_root', 'faithful_root', 'helper_sha256')\n"
        "if any(key not in pins or not pins[key] for key in required):\n"
        "    _die('pinned spec missing fields: %s' % ','.join(k for k in required if not pins.get(k)))\n"
        "# SAME-OBJECT outer-request binding: hash the actual frozen request\n"
        "# FILE bytes the parent pushed; identical algorithm on both ends.\n"
        "try:\n"
        "    request_bytes = Path(pins['request_file']).read_bytes()\n"
        "except OSError:\n"
        "    _die('frozen outer request file unreadable: %s' % pins['request_file'])\n"
        "if hashlib.sha256(request_bytes).hexdigest() != pins['request_file_sha256']:\n"
        "    _die('outer request bytes differ from the pinned request digest')\n"
        "if pins['case'] not in ALLOWED:\n"
        "    _die('case not seam-entitled: %s' % pins['case'])\n"
        "if pins['fixture'] is not True:\n"
        "    _die('pinned spec does not carry fixture=true')\n"
        "# The producer child's argv names its derived inputs file.\n"
        "if '--inputs' not in sys.argv:\n"
        "    _die('producer argv lacks --inputs')\n"
        "inputs_path = Path(sys.argv[sys.argv.index('--inputs') + 1])\n"
        "try:\n"
        "    inputs_bytes = inputs_path.read_bytes()\n"
        "except OSError:\n"
        "    _die('derived inputs file unreadable: %s' % inputs_path)\n"
        "try:\n"
        "    inputs = json.loads(inputs_bytes.decode('utf-8'))\n"
        "except Exception:\n"
        "    _die('derived inputs are not valid JSON')\n"
        "if inputs.get('case') != pins['case']:\n"
        "    _die('inputs case %r does not match pinned case %r' % (inputs.get('case'), pins['case']))\n"
        "if inputs.get('fixture') is not True:\n"
        "    _die('inputs do not carry fixture=true')\n"
        "owned = inputs.get('owned_root') or ''\n"
        "if owned != pins['owned_root']:\n"
        "    _die('inputs owned_root %r does not match the pinned request root %r' % (owned, pins['owned_root']))\n"
        "root = PureWindowsPath(owned)\n"
        "if not root.is_absolute() or root.drive.upper() not in ('E:', 'D:'):\n"
        "    _die('owned root is not a frozen E:/D: producer root: %s' % owned)\n"
        "# Path relations: owned == output_root/driver; output_root under the\n"
        "# faithful parent root; the inputs file lives inside the owned root.\n"
        "if owned != pins['owned_root']:\n"
        "    _die('owned root differs from the pinned request derivation')\n"
        "out_root = PureWindowsPath(pins['output_root'])\n"
        "if not pins['output_root'].endswith('\\\\output') or not str(out_root.parent).startswith(pins['faithful_root']):\n"
        "    _die('output root is not under the frozen faithful parent root: %s' % pins['output_root'])\n"
        "# Path RELATION among pinned values (the physical file location is\n"
        "# platform-dependent in tests; the real chain's identity binding is\n"
        "# the owned_root/output_root equality already verified above).\n"
        "if pins['owned_root'] != pins['output_root'].rstrip('\\\\') + '\\\\driver':\n"
        "    _die('pinned owned root is not the output root driver derivation')\n"
        "# Derived-inputs FULL identity: the parent's expectation is derived\n"
        "# from the frozen request (never from the file under test); every\n"
        "# identity field must match exactly.\n"
        "expected = pins['expected_inputs']\n"
        "for field in ('case', 'fixture', 'owned_root', 'config', 'candidate_id',\n"
        "              'source_commit', 'package_sha256', 'execution_id'):\n"
        "    if inputs.get(field) != expected.get(field):\n"
        "        _die('derived inputs field %s differs from the frozen request derivation: %r != %r'\n"
        "             % (field, inputs.get(field), expected.get(field)))\n"
        "# The helper bytes are pinned by the parent from what it wrote; the\n"
        "# child re-reads the SAME file and compares against the pin (never\n"
        "# re-deriving the expectation from the file under test).\n"
        "helper_path = Path(__file__).resolve().parent / 'os_fixture_backend.py'\n"
        "try:\n"
        "    helper_bytes = helper_path.read_bytes()\n"
        "except OSError:\n"
        "    _die('os_fixture_backend helper missing: %s' % helper_path)\n"
        "if hashlib.sha256(helper_bytes).hexdigest() != pins['helper_sha256']:\n"
        "    _die('helper bytes differ from the pinned spec')\n"
        "# Whole-initialization fail-closed: every remaining stage (helper\n"
        "# exec, case-module imports, patch install, success marker) runs under\n"
        "# one top-level try; ANY failure is fatal — sitecustomize's warn-and-\n"
        "# continue behavior can never leak the child into the producer.\n"
        "def _install():\n"
        "    import importlib.util as ilu\n"
        "    spec = ilu.spec_from_file_location('fnreg_os_fixture_backend', helper_path)\n"
        "    backend = ilu.module_from_spec(spec)\n"
        "    spec.loader.exec_module(backend)\n"
        "    import logging.handlers\n"
        "    if pins['case'] in ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH'):\n"
        "        import fakenet.diverters.windows as _win\n"
        "        _win.Diverter = backend.Backend\n"
        "        import fakenet.fakenet as _core\n"
        "        _core.IfaceIpInfo = backend.IfaceIpInfo\n"
        "    elif pins['case'] == 'GAP-SYSLOG-ICMP-LOG':\n"
        "        target = str(PureWindowsPath(owned) / 'syslog.sink')\n"
        "        class _OwnedSink(logging.Handler):\n"
        "            def __init__(self):\n"
        "                super().__init__(); self.target = Path(target); self._closed = False\n"
        "            def emit(self, record):\n"
        "                if self._closed: raise ValueError('owned sink closed')\n"
        "                with self.target.open('a', encoding='utf-8') as s: s.write(self.format(record) + '\\n')\n"
        "            def close(self):\n"
        "                self._closed = True; super().close()\n"
        "        logging.handlers.NTEventLogHandler = lambda *a, **k: _OwnedSink()\n"
        "try:\n"
        "    _install()\n"
        "except SystemExit:\n"
        "    raise\n"
        "except BaseException as error:\n"
        "    sys.stderr.write('FNREG_OS_FIXTURE_INIT_FAILED: %s: %s\\n' % (type(error).__name__, error))\n"
        "    traceback.print_exc()\n"
        "    raise SystemExit(78)\n"
        "sys.stderr.write('FNREG_OS_FIXTURE_BOOTSTRAP case=%s request_file=%s helper=%s owned=%s\\n'\n"
        "                 % (pins['case'], pins['request_file_sha256'][:12], pins['helper_sha256'][:12], owned))\n",
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
            self.pushed['push-request-file'] = sources[0]['absolute_path']
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
            bootstrap_dir = Path(__import__('os').environ['FN_MANUAL_FAITHFUL_ROOT']) / 'child-bootstrap'
            bootstrap = write_child_bootstrap(bootstrap_dir)
            import hashlib
            env['PYTHONPATH'] = str(bootstrap)
            # PARENT-derived pinned spec: every value comes from the frozen
            # guest request or the parent-verified helper bytes — the child
            # matches ALL of it against its own argv/inputs/file reads.
            # The child verifies the ACTUAL frozen outer-request FILE bytes
            # (same object, same algorithm on both ends) — not a re-serialization.
            request_file = next(iter(self.pushed.values()))
            request_bytes = Path(self.pushed['push-request-file']).read_bytes()
            expected_inputs = dict(request_file.get('manual') or {})
            expected_inputs.update({
                'case': request_file['case_id'],
                'fixture': request_file.get('candidate', {}).get('offline_fixture') is True,
                'owned_root': request['output_root'].rstrip('\\') + '\\driver',
                'config': request['output_root'].rstrip('\\') + '\\driver\\config',
                'candidate_id': 'manual-candidate',
                'source_commit': request_file['candidate']['source_commit'],
                'package_sha256': request_file['candidate']['package_sha256'],
                'execution_id': request_file['execution_id'],
            })
            env['FNREG_OS_FIXTURE_PINS'] = json.dumps({
                'case': request['case_id'],
                'fixture': True,
                'request_file_sha256': hashlib.sha256(request_bytes).hexdigest(),
                'request_file': str(self.pushed['push-request-file']),
                'expected_inputs': expected_inputs,
                'output_root': request['output_root'],
                'owned_root': request['output_root'].rstrip('\\') + '\\driver',
                'faithful_root': Path(__import__('os').environ['FN_MANUAL_FAITHFUL_ROOT']).anchor,
                'helper_sha256': hashlib.sha256((bootstrap_dir / 'os_fixture_backend.py').read_bytes()).hexdigest(),
            })
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
