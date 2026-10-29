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
        "\n"
        "def _die(reason):\n"
        "    sys.stderr.write('FNREG_OS_FIXTURE_REFUSED: %s\\n' % reason)\n"
        "    raise SystemExit(78)\n"
        "\n"
        "def _initialize():\n"
        "    pins_raw = os.environ.get('FNREG_OS_FIXTURE_PINS')\n"
        "    if not pins_raw:\n"
        "        _die('no pinned spec: this sitecustomize is only for authorized fixture children')\n"
        "    try:\n"
        "        pins = json.loads(pins_raw)\n"
        "    except Exception:\n"
        "        _die('pinned spec is not valid JSON')\n"
        "    if not isinstance(pins, dict):\n"
        "        _die('pinned spec must be a JSON object, got %s' % type(pins).__name__)\n"
        "    required = ('case', 'fixture', 'request_file_sha256', 'request_file',\n"
        "                'expected_inputs', 'output_root', 'owned_root',\n"
        "                'faithful_root', 'helper_sha256')\n"
        "    if any(key not in pins or pins[key] in (None, '') for key in required):\n"
        "        _die('pinned spec missing fields: %s' % ','.join(k for k in required if not pins.get(k)))\n"
        "    if not isinstance(pins['expected_inputs'], dict):\n"
        "        _die('expected_inputs must be an object, got %s' % type(pins['expected_inputs']).__name__)\n"
        "    if pins['case'] not in ALLOWED:\n"
        "        _die('case not seam-entitled: %s' % pins['case'])\n"
        "    if pins['fixture'] is not True:\n"
        "        _die('pinned spec does not carry fixture=true')\n"
        "    try:\n"
        "        request_bytes = Path(pins['request_file']).read_bytes()\n"
        "    except OSError:\n"
        "        _die('frozen outer request file unreadable: %s' % pins['request_file'])\n"
        "    if hashlib.sha256(request_bytes).hexdigest() != pins['request_file_sha256']:\n"
        "        _die('outer request bytes differ from the pinned request digest')\n"
        "    if '--inputs' not in sys.argv or sys.argv.index('--inputs') + 1 >= len(sys.argv):\n"
        "        _die('producer argv lacks a readable --inputs value')\n"
        "    inputs_path = Path(sys.argv[sys.argv.index('--inputs') + 1])\n"
        "    try:\n"
        "        inputs_bytes = inputs_path.read_bytes()\n"
        "    except OSError:\n"
        "        _die('derived inputs file unreadable: %s' % inputs_path)\n"
        "    try:\n"
        "        inputs = json.loads(inputs_bytes.decode('utf-8'))\n"
        "    except Exception:\n"
        "        _die('derived inputs are not valid JSON')\n"
        "    if not isinstance(inputs, dict):\n"
        "        _die('derived inputs must be a JSON object, got %s' % type(inputs).__name__)\n"
        "    if inputs.get('case') != pins['case']:\n"
        "        _die('inputs case %r does not match pinned case %r' % (inputs.get('case'), pins['case']))\n"
        "    if inputs.get('fixture') is not True:\n"
        "        _die('inputs do not carry fixture=true')\n"
        "    owned = inputs.get('owned_root') or ''\n"
        "    if owned != pins['owned_root']:\n"
        "        _die('inputs owned_root %r does not match the pinned request root %r' % (owned, pins['owned_root']))\n"
        "    root = PureWindowsPath(owned)\n"
        "    if not root.is_absolute() or root.drive.upper() not in ('E:', 'D:'):\n"
        "        _die('owned root is not a frozen E:/D: producer root: %s' % owned)\n"
        "    if pins['owned_root'] != pins['output_root'].rstrip('\\\\') + '\\\\driver':\n"
        "        _die('pinned owned root is not the output root driver derivation')\n"
        "    out_root = PureWindowsPath(pins['output_root'])\n"
        "    root_parts = PureWindowsPath(pins['faithful_root']).parts\n"
        "    if list(out_root.parts)[:len(root_parts)] != list(root_parts):\n"
        "        _die('output root is not under the frozen faithful parent root: %s' % pins['output_root'])\n"
        "    expected = pins['expected_inputs']\n"
        "    for field in ('schema', 'case', 'fixture', 'owned_root', 'config',\n"
        "                  'candidate_id', 'source_commit', 'package_sha256',\n"
        "                  'execution_id', 'responsea'):\n"
        "        if inputs.get(field) != expected.get(field):\n"
        "            _die('derived inputs field %s differs from the frozen request derivation: %r != %r'\n"
        "                 % (field, inputs.get(field), expected.get(field)))\n"
        "    helper_path = Path(__file__).resolve().parent / 'os_fixture_backend.py'\n"
        "    try:\n"
        "        helper_bytes = helper_path.read_bytes()\n"
        "    except OSError:\n"
        "        _die('os_fixture_backend helper missing: %s' % helper_path)\n"
        "    if hashlib.sha256(helper_bytes).hexdigest() != pins['helper_sha256']:\n"
        "        _die('helper bytes differ from the pinned spec')\n"
        "    import importlib.util as ilu\n"
        "    import logging.handlers\n"
        "    spec = ilu.spec_from_file_location('fnreg_os_fixture_backend', helper_path)\n"
        "    backend = ilu.module_from_spec(spec)\n"
        "    spec.loader.exec_module(backend)\n"
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
        "    return owned, pins\n"
        "\n"
        "try:\n"
        "    owned, pins = _initialize()\n"
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
        # The caller's frozen digest pins the request this channel may run;
        # _build_child_env verifies the on-disk bytes against it (and the
        # cached dict against the verified bytes) BEFORE any guest call. The
        # child env applies ONLY for the duration of the guest call and is
        # restored immediately on return AND on any exception.
        self.frozen_request_sha = request_sha
        env = self._build_child_env()
        saved = {key: os.environ.get(key) for key in env}
        try:
            os.environ.update(env)
            return self._run_guest(self.pushed['push-request'])
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def _build_child_env(self):
        """Verify the frozen request and build/apply the child env; raises
        on any digest or cached-dict divergence before the guest can run."""
        import hashlib
        request = self.pushed['push-request']
        actual_bytes = Path(self.pushed['push-request-file']).read_bytes()
        actual_digest = hashlib.sha256(actual_bytes).hexdigest()
        if getattr(self, 'frozen_request_sha', None) is not None:
            if actual_digest != self.frozen_request_sha:
                raise ValueError('frozen request digest mismatch: file changed after freeze')
        if json.loads(actual_bytes.decode('utf-8')) != request:
            raise ValueError('cached request differs from the verified on-disk bytes')
        env = {}
        if request.get('candidate', {}).get('offline_fixture') is True and \
                request['case_id'] in ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG'):
            bootstrap_dir = Path(os.environ['FN_MANUAL_FAITHFUL_ROOT']) / 'child-bootstrap'
            bootstrap = write_child_bootstrap(bootstrap_dir)
            env['PYTHONPATH'] = str(bootstrap)
            # Derive through the REAL single-value builder the product uses
            # (native._manual_input_value) — never a hand-copied field list.
            import acceptance_native as native
            directory = PureWindowsPath(request['output_root']) / 'driver'
            expected_inputs = native._manual_input_value(
                {'candidate': request['candidate'], 'execution_id': request['execution_id']},
                {'id': request['case_id']},
                dict(request.get('manual') or {}),
                str(directory), str(directory / 'config'))
            env['FNREG_OS_FIXTURE_PINS'] = json.dumps({
                'case': request['case_id'],
                'fixture': True,
                'request_file_sha256': actual_digest,
                'request_file': self.pushed['push-request-file'],
                'expected_inputs': expected_inputs,
                'output_root': request['output_root'],
                'owned_root': request['output_root'].rstrip('\\') + '\\driver',
                'faithful_root': Path(os.environ['FN_MANUAL_FAITHFUL_ROOT']).resolve().as_posix().rstrip('/'),
                'helper_sha256': hashlib.sha256((bootstrap_dir / 'os_fixture_backend.py').read_bytes()).hexdigest(),
            })
        return env  # applied and restored by execute() around the guest call

    def _run_guest(self, request):
        import acceptance_guest as guest
        import acceptance_runtime as rt
        from unittest import mock
        with mock.patch.object(rt, 'require_target', return_value=dict(self.identity_value)):
            code = guest.execute(request, self.root)
        return {'returncode': code, 'process_exited': True, 'recovered': True}
