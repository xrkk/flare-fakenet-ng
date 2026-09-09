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
