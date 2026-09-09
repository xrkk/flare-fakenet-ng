"""A file containing an error message is not successful evidence."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from fakenet.mcp import incident


@pytest.mark.parametrize('outcome', [
    SimpleNamespace(returncode=1, stdout='partial', stderr='access denied'),
    SimpleNamespace(returncode=0, stdout='', stderr=''),
    OSError('missing collector'),
    subprocess.TimeoutExpired('collector', 1),
])
def test_command_failure_is_manifest_failure(tmp_path, monkeypatch, outcome):
    def run(*args, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr(incident.subprocess, 'run', run)
    collector = incident.IncidentCollector(tmp_path, 'run')
    collector.collect({})
    manifest = json.loads((collector.root / 'manifest.json').read_text())
    items = {entry['item']: entry for entry in manifest['entries']}
    for name in ('process_tree.txt', 'handle_summary.txt', 'firewall_diff.txt',
                 'event_log.txt'):
        assert items[name]['result'] == 'failed'
        assert items[name]['failure_reason']


def test_missing_stdout_and_log_do_not_count_as_complete(tmp_path):
    collector = incident.IncidentCollector(tmp_path, 'run')
    collector.collect({})
    manifest = json.loads((collector.root / 'manifest.json').read_text())
    items = {entry['item']: entry for entry in manifest['entries']}
    assert items['stdout_stderr.log']['result'] == 'failed'
    assert items['run_log.txt']['result'] == 'failed'
