"""Real closed HTTP output without intercepting unrelated traffic."""
from pathlib import Path
from types import SimpleNamespace
from urllib.request import Request, urlopen

from fakenet.diverters.diverterbase import DiverterListenerCallbacks
from fakenet.listeners.HTTPListener import HTTPListener
from fakenet.mcp.managed import probe_instance


def test_live_no_divert_http_post_and_closed_listener_health(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    provider=HTTPListener({'ipaddr':'127.0.0.1','port':0,'protocol':'TCP',
                           'webroot':str(Path(__file__).resolve().parents[2]/'fakenet/defaultFiles'),
                           'dumphttpposts':'Yes','dumphttppostsfileprefix':'handoff_http',
                           'usessl':'No'})
    provider.acceptDiverterListenerCallbacks(DiverterListenerCallbacks(None))
    instance=SimpleNamespace(diverter=None, fakenet_config={'diverttraffic':'No'},
                             running_listener_providers=[provider])
    provider.start()
    try:
        assert probe_instance(instance)['probe'] is True
        port=provider.server.server_address[1]
        with urlopen(Request('http://127.0.0.1:%d/handoff'%port,data=b'benign closed POST'),timeout=5) as response:
            assert response.status==200
        paths=list(tmp_path.glob('handoff_http_*.txt'))
        assert len(paths)==1 and b'benign closed POST' in paths[0].read_bytes()
        instance.fakenet_config['diverttraffic']='Yes'
        assert probe_instance(instance)['probe'] is False
        instance.fakenet_config['diverttraffic']='No'
    finally:
        provider.stop()
    assert probe_instance(instance)['probe'] is False
