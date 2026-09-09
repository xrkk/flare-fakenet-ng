from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize('change', [
    {'path': r'C:\Users\Other\private.txt'},
    {'path': r'C:\ProgramData\FakeNet-NG-MCP\artifacts\..\other.txt'},
    {'size': 0}, {'sha256': 'invalid'}, {'complete': False},
])
def test_invalid_transfer_cannot_start_receiver_or_call_vm(tmp_path, monkeypatch, change):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from artifact_transfer import receive_artifact
    called = []
    channel = SimpleNamespace(powershell=lambda *a, **k: called.append(a))
    item = {'path': r'C:\ProgramData\FakeNet-NG-MCP\artifacts\run\real.pcap',
            'size': 100, 'sha256': 'a'*64, 'complete': True}
    item.update(change)
    with pytest.raises(ValueError):
        receive_artifact(channel, item, tmp_path/'received.pcap')
    assert not called and not (tmp_path/'received.pcap').exists()


def test_kernel_listener_check_distinguishes_time_wait_and_other_ports(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from artifact_transfer import listener_rows
    table = 'header\n 0: 0100007F:1F90 00000000:0000 06 rest\n 1: 00000000:1F91 00000000:0000 0A rest\n'
    assert listener_rows(table, 8080) == []
    actual = ' 2: 01CCA8C0:1F90 00000000:0000 0A rest'
    assert listener_rows(table + actual + '\n', 8080) == [actual]
