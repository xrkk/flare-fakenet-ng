"""Original Suite byte-copy boundary for exact closed P7 exports."""
import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from test_formal_runtime_context import materials, load
from test_formal_runtime_instance import subject
from formal_runtime import source
from bounded_mcp import TransportUnknown


RUN = '11111111-2222-3333-4444-555555555555'


class ClosedRunClient:
    def __init__(self, failure=None):
        self.failure, self.calls, self.inventories = failure, [], 0
        self.root = r'C:\ProgramData\FakeNet-NG-MCP\artifacts\runs' + '\\' + RUN
        self.bytes = {self.root + r'\run.log': b'original stopped-run log',
                      self.root + r'\relay-native-events.jsonl': b'{"original":"native"}\n'}

    def powershell(self, command, timeout):
        self.calls.append((command, timeout))
        assert timeout <= 30
        if 'Add-Original' in command:
            self.inventories += 1
            if self.failure == 'after-change' and self.inventories == 2:
                self.bytes[self.root + r'\run.log'] += b'changed'
            files = [{'root': self.root, 'path': path, 'size': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest(), 'sha256_after': hashlib.sha256(raw).hexdigest()}
                     for path, raw in self.bytes.items()]
            if self.failure == 'foreign':
                files[0]['path'] = files[0]['path'].replace(RUN, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
            if self.failure == 'missing': files.pop()
            if self.failure == 'double-sha': files[0]['sha256_after'] = '0' * 64
            if self.failure == 'ordinary-budget': files[0]['size'] = 192 * 2**20 + 1
            if self.failure == 'duplicate': files.append(dict(files[0]))
            if self.failure == 'total-budget':
                files.extend({'root': self.root, 'path': self.root + '\\budget-%02d.bin' % n,
                              'size': 192 * 2**20, 'sha256': '0' * 64, 'sha256_after': '0' * 64}
                             for n in range(23))
            return {'output': json.dumps({'run_id': RUN, 'files': files, 'missing': []})}
        if '$s=[IO.File]::OpenRead(' in command:
            if self.failure == 'unknown': raise TransportUnknown('closed run read unknown', {})
            path = re.search(r"OpenRead\('([^']+)'\)", command)[1]
            offset = int(re.search(r'\$s.Seek\((\d+),', command)[1])
            size = int(re.search(r'New-Object byte\[\] (\d+)', command)[1])
            return {'output': base64.b64encode(self.bytes[path][offset:offset + size]).decode()}
        raise AssertionError('not an original bounded inventory/copy command')


def cleanup():
    return {'errors': [], 'final': {'state': 'stopped', 'controller': None, 'run_id': None,
                                   'config_identity': {'name': 'default.ini'}}}


def test_closed_original_run_inventory_and_Suite_copies_remain_exact_and_readonly(materials):
    context = load(materials)
    r = subject(context)
    client = ClosedRunClient()
    r.vm = client
    destination = context.evidence_root / 'P7-closed-run'
    report = source.export_closed_run(r, context, RUN, cleanup(), destination)
    assert report['passed'] and report['full_SHA'] and report['before_after_size_double_SHA']
    assert report['local_writers_ended'] and report['guest_writes'] == 0
    rows = json.loads((destination / 'guest-original-index.json').read_bytes())
    assert all(Path(row['host_path']).read_bytes() == client.bytes[row['guest']['path']] for row in rows)
    assert client.inventories == 2 and r.vm is client
    assert sum('OpenRead(' in command for command, _ in client.calls) == 2
    with pytest.raises(source.SourceError, match='no retry'):
        source.export_closed_run(r, context, RUN, cleanup(), destination)
    assert len(client.calls) == 4


@pytest.mark.parametrize('failure', ['foreign', 'missing', 'double-sha', 'ordinary-budget', 'total-budget',
                                     'duplicate', 'after-change', 'unknown'])
def test_closed_run_failure_retains_originals_and_revokes_only_read_adapter(materials, failure):
    context = load(materials)
    r = subject(context)
    client = ClosedRunClient(failure)
    r.vm = client
    destination = context.evidence_root / failure
    with pytest.raises((source.SourceError, TransportUnknown)):
        source.export_closed_run(r, context, RUN, cleanup(), destination)
    assert r.vm is client and not (destination / 'guest-original-index.json').exists()
    terminal = json.loads((destination / 'closed-run-export-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['local_writers_ended'] and terminal['no_replay']
    if failure not in ('after-change', 'unknown'):
        assert not any('OpenRead(' in command for command, _ in client.calls)


def test_unsettled_original_cleanup_never_exports_or_creates_output(materials):
    context = load(materials)
    r = subject(context)
    client = ClosedRunClient()
    r.vm = client
    for state in ('healthy', 'recovering'):
        original = cleanup(); original['final']['state'] = state
        with pytest.raises(source.SourceError, match='cleanup is unresolved'):
            source.export_closed_run(r, context, RUN, original, context.evidence_root / state)
        assert not (context.evidence_root / state).exists()
    assert not client.calls
