"""Faithful Windows fixture support: a stand-in where ONLY the VM/OS
communication boundary is substituted.  The guest entry runs UNMODIFIED in the
request's real frozen output root under the real Windows Python; the pull
copies original bytes verbatim (no JSON rewriting, no re-hashing).  Activated
only when FN_MANUAL_FAITHFUL_ROOT points at an owned real Windows directory
(the Wine capsule run); on a POSIX host the base modules keep their documented
remap stand-ins."""
import copy
import json
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
        import acceptance_guest as guest
        import acceptance_runtime as rt
        from unittest import mock
        with mock.patch.object(rt, 'require_target', return_value=dict(self.identity_value)):
            code = guest.execute(request, self.root)
        return {'returncode': code, 'process_exited': True, 'recovered': True}
