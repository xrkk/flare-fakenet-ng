"""Read-only export uses actual source authority, capture gates and Suite copies."""

import base64
import hashlib
import json
from pathlib import Path
import re

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_source import historical, instance_for
from formal_runtime import source
from bounded_mcp import TransportUnknown


RID = '11111111-2222-3333-4444-555555555555'


class SourceClient:
    def __init__(self, binding, failure=None):
        self.binding, self.failure = binding, failure
        self.calls = []
        self.inventories = 0
        self.bytes = {path: ('source:' + path).encode() for path in binding.values['required_files']}
        self.bytes[r'C:\ProgramData\FakeNet-NG-MCP\artifacts\runs' + '\\' + RID + r'\run.log'] = b'actual owned run bytes'
        self.audit_path = r'C:\ProgramData\FakeNet-NG-MCP\logs\recovery-audit-' + RID + '-01.json'
        self.bytes[self.audit_path] = b'{"owned":"recovery"}'

    def metadata(self, path):
        data = self.bytes[path]
        return {'path': path, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def powershell(self, command, timeout):
        self.calls.append((command, timeout))
        if '$sessions=@()' in command:
            value = {'sessions': [{'name': kernel['name'], 'exit': -2144337918,
                                    'query': 'Data Collector Set was not found.'}
                                   for kernel in self.binding.values['kernels']],
                     'probe': [7] if self.failure == 'writer' else [], 'children': [], 'pktmon': 'PktMon is not running.'}
        elif 'Get-ChildItem -LiteralPath $root' in command:
            self.inventories += 1
            if self.failure == 'after-change' and self.inventories > 1:
                path = self.binding.values['required_files'][0]
                self.bytes[path] = b'changed after copying'
            files = [self.metadata(path) for path in self.bytes if path != self.audit_path]
            if self.failure == 'missing':
                files = [item for item in files if item['path'] != self.binding.values['required_files'][0]]
            elif self.failure == 'wrong-source':
                files.append({'path': r'E:\unowned\probe.jsonl', 'size': 1, 'sha256': '0' * 64})
            elif self.failure == 'duplicate':
                files.append(dict(files[0], sha256='0' * 64))
            elif self.failure == 'total':
                files.extend({'path': self.binding.physical_namespace + '\\oversize-%d.bin' % n,
                              'size': 192 * 2 ** 20, 'sha256': '0' * 64} for n in range(24))
            missing = [r'C:\ProgramData\FakeNet-NG-MCP\artifacts' + '\\' + RID,
                       r'C:\ProgramData\FakeNet-NG-MCP\logs\exit-evidence' + '\\' + RID]
            value = {'files': files, 'missing': missing}
        elif "('recovery-audit-'+$id+'-*')" in command:
            value = {'files': [self.metadata(self.audit_path)]}
        elif '$s=[IO.File]::OpenRead(' in command:
            if self.failure == 'unknown':
                raise TransportUnknown('source read result unknown', {'sent': 'possibly_sent'})
            path = re.search(r"OpenRead\('([^']+)'\)", command)[1]
            offset = int(re.search(r'\$s.Seek\((\d+),', command)[1])
            length = int(re.search(r'New-Object byte\[\] (\d+)', command)[1])
            return {'output': base64.b64encode(self.bytes[path][offset:offset + length]).decode()}
        else:
            raise AssertionError('unexpected command at read-only environment boundary')
        return {'output': json.dumps(value), 'exit_code': 0}


@pytest.fixture
def exporting(historical):
    context, root, _, _, files, freeze_index = historical
    name = 'results/scenario-sst-010.json'
    files[name] = {'run_chain': [{'run_id': RID}]}
    (root / name).parent.mkdir()
    write_json(root / name, files[name])
    context = freeze_index()
    binding = source.resolve_source(context, root)
    instance = instance_for(binding, context.evidence_root)
    return context, root, binding, instance


def test_full_readonly_inventory_copy_and_original_state_restoration(exporting):
    context, root, binding, instance = exporting
    client = SourceClient(binding)
    instance.vm = client
    destination = context.evidence_root / 'export'
    result = source.export_source(instance, context, root, destination)
    assert result['passed'] and result['guest_writes'] == result['deletions'] == 0
    assert result['local_writers_ended']
    assert result['full_SHA'] and result['before_after_size_double_SHA'] and not result['required_missing']
    assert client.inventories == 2 and instance.vm is client and instance.physical_source_binding is binding
    exported = json.loads((destination / 'guest-original-index.json').read_text())
    assert {row['guest']['path'] for row in exported} == set(client.bytes)
    assert all(Path(row['host_path']).read_bytes() == client.bytes[row['guest']['path']] for row in exported)
    assert (destination / 'source-inventory-value.json').read_bytes() == (destination / 'source-post-inventory-value.json').read_bytes()
    assert all(timeout <= 30 and 'transport-stage' not in command for command, timeout in client.calls)
    assert len(list((destination / 'readonly-final-intents').glob('*.json'))) == len(client.calls)
    terminal = json.loads((destination / 'source-export-terminal.json').read_text())
    assert terminal['passed'] and terminal['local_writers_ended']
    with pytest.raises(source.SourceError, match='output exists; never retry'):
        source.export_source(instance, context, root, destination)


@pytest.mark.parametrize('failure,reason', [('writer', 'active or UNKNOWN'), ('missing', 'required originals missing'),
                                          ('wrong-source', 'cross-source/unowned'), ('duplicate', 'duplicate source'),
                                          ('total', 'over-bound'), ('after-change', 'changed during export')])
def test_inventory_failure_preserves_originals_and_withholds_export(exporting, failure, reason):
    context, root, binding, instance = exporting
    client = SourceClient(binding, failure)
    instance.vm = client
    destination = context.evidence_root / failure
    with pytest.raises(source.SourceError, match=reason):
        source.export_source(instance, context, root, destination)
    assert instance.vm is client and instance.physical_source_binding is binding
    assert not (destination / 'guest-original-index.json').exists()
    terminal = json.loads((destination / 'source-export-terminal.json').read_text())
    assert not terminal['passed'] and terminal['local_writers_ended'] and terminal['export_withheld_or_incomplete']
    if failure != 'after-change':
        assert not any('OpenRead(' in command for command, _ in client.calls)


def test_unknown_read_stops_without_retry_and_retains_terminal(exporting):
    context, root, binding, instance = exporting
    client = SourceClient(binding, 'unknown')
    instance.vm = client
    destination = context.evidence_root / 'unknown'
    with pytest.raises(TransportUnknown):
        source.export_source(instance, context, root, destination)
    assert sum('OpenRead(' in command for command, _ in client.calls) == 1
    assert instance.vm is client
    terminal = json.loads((destination / 'source-export-terminal.json').read_text())
    assert terminal['exception_type'] == 'TransportUnknown' and not terminal['passed'] and terminal['no_replay']
    calls = len(client.calls)
    with pytest.raises(source.SourceError, match='never retry'):
        source.export_source(instance, context, root, destination)
    assert len(client.calls) == calls


def test_readonly_adapter_rechecks_independent_material_pin_before_every_rpc(exporting):
    context, _, binding, _ = exporting
    client = SourceClient(binding)
    root = context.evidence_root / 'read-adapter'
    adapter = source.ReadOnlySourceVm(client, context, binding, root)
    context.materials_path.write_bytes(context.materials_path.read_bytes() + b'\n')
    from formal_runtime.context import MaterialError
    with pytest.raises(MaterialError, match='independent materials SHA256 mismatch'):
        adapter.powershell('Get-Content owned-source', 30)
    assert not client.calls and not root.exists()


def test_exact_supervisor_lineage_is_queried_without_broad_native_export(exporting):
    context, root, _, instance = exporting
    # Add the frozen exact PID/FILETIME witness and repin this controlled source.
    material_path = context.materials_path
    data = json.loads(material_path.read_bytes())
    path = root / 'instance-gates/new/new-instance-identity.json'
    path.parent.mkdir(parents=True)
    witness = write_json(path, {'pid': 812, 'filetime': '134355786888519306'})
    index_path = Path(data['source_indices'][0]['path'])
    index = json.loads(index_path.read_bytes())
    index['rows'].append(dict(witness, path=str(path.relative_to(root))))
    data['source_indices'][0] = write_json(index_path, index)
    pin = write_json(material_path, data)['sha256']
    from formal_runtime.context import load_context
    context = load_context(material_path, pin, repository_root=context.repository_root)
    binding = source.resolve_source(context, root)

    class LineageClient(SourceClient):
        def powershell(self, command, timeout):
            if '$sup=ConvertFrom-Json ' in command:
                self.calls.append((command, timeout))
                assert 'supervisor_pid -eq $v.pid' in command
                assert 'supervisor_creation_time -ceq [string]$v.filetime' in command
                assert '134355786888519306' in command and '812' in command
                return {'output': json.dumps({'ids': [RID]})}
            return super().powershell(command, timeout)

    client = LineageClient(binding)
    instance.vm = client
    del instance.physical_source_binding
    result = source.export_source(instance, context, root, context.evidence_root / 'lineage')
    assert result['passed'] and result['local_writers_ended']
    assert not hasattr(instance, 'physical_source_binding') and instance.vm is client
    assert sum('$sup=ConvertFrom-Json ' in command for command, _ in client.calls) == 1


@pytest.mark.parametrize('command,reason', [("[IO.File]::WriteAllText('x','changed')", 'mutation/staging'),
                                          ('Get-Content owned;#' + 'x' * 12500, 'wire bound'),
                                          (r"Get-Content 'E:\FakeNet-NG-MCP-test-work\clean-r55-20261004" + '\\' +
                                           '2' * 32 + '\\' + '3' * 12 + "\\probe.jsonl'", 'cross-source')])
def test_readonly_adapter_never_stages_mutates_or_reads_wrong_namespace(exporting, command, reason):
    context, _, binding, _ = exporting
    client = SourceClient(binding)
    adapter = source.ReadOnlySourceVm(client, context, binding, context.evidence_root / 'read-only')
    with pytest.raises(source.SourceError, match=reason):
        adapter.powershell(command)
    assert not client.calls and not context.evidence_root.exists()
