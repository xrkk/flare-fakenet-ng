"""Two independent FakeNet control-port exclusion paths."""

from configparser import ConfigParser
from pathlib import Path
from types import SimpleNamespace

from fakenet.diverters.fnconfig import Config
from fakenet.mcp.config import ServiceConfig
from fakenet.mcp.controlfilter import apply_control_link_exclusion
from fakenet.mcp.tools import AppContext


DEFAULT_INI = Path(__file__).resolve().parents[2] / "fakenet" / "configs" / "default.ini"


def test_repository_default_ini_excludes_all_mcp_tcp_ports():
    parser = ConfigParser()
    assert parser.read(DEFAULT_INI) == [str(DEFAULT_INI)]
    assert parser.getboolean("Diverter", "RedirectAllTraffic")
    config = Config(dict(parser.items("Diverter")),
                    portlists=["BlackListPortsTCP", "BlackListPortsUDP"])
    assert config.getconfigval("BlackListPortsTCP") == [139, 28787, 28788, 28790]
    assert config.getconfigval("BlackListPortsUDP") == [67, 68, 137, 138, 443, 1900, 5355]


def test_service_exclusion_merges_listen_extras_and_custom_config(monkeypatch, tmp_path):
    monkeypatch.setenv("FAKENETNG_MCP_PROGRAMDATA", str(tmp_path))
    monkeypatch.delenv("FAKENETNG_MCP_TESTDOUBLE", raising=False)
    config = ServiceConfig("192.168.204.149", 28788, ["192.168.204.1"],
                           extra_control_ports=[28787, 28790, 30001])
    context = AppContext(config)
    assert context.runner._exclusion == {
        "ip": "192.168.204.1", "port": "28788,28787,28790,30001"}

    parsed = SimpleNamespace(diverter_config={"ControlLinkExcludePort": "443"})
    context.runner._inject_exclusion(parsed)
    assert set(parsed.diverter_config["ControlLinkExcludePort"].split(",")) == {
        "443", "28787", "28788", "28790", "30001"}
    assert parsed.diverter_config["ControlLinkExcludeIp"] == "192.168.204.1"
    actual_filter = apply_control_link_exclusion(
        "outbound and ip", parsed.diverter_config["ControlLinkExcludeIp"],
        parsed.diverter_config["ControlLinkExcludePort"])
    for port in (443, 28787, 28788, 28790, 30001):
        assert "tcp.SrcPort != %d" % port in actual_filter
