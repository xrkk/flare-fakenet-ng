"""Runtime loader agrees with UTF-8 MCP writes and legacy GUI files."""
import builtins
import locale
from fakenet.fakenet import Fakenet


def test_utf8_config_under_windows_ansi_default(tmp_path, monkeypatch):
    path = tmp_path / "unicode.ini"
    path.write_text("[FakeNet]\nDumpPackets = No\nDescription = \u91c7\u96c6\u914d\u7f6e\n", encoding="utf-8")
    original = builtins.open
    def windows_open(file, mode="r", *args, **kwargs):
        if "b" not in mode and kwargs.get("encoding") in (None, "locale"):
            kwargs["encoding"] = "cp1252"
        return original(file, mode, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", windows_open)
    fn = Fakenet()
    fn.parse_config(str(path))
    assert fn.fakenet_config["description"] == "\u91c7\u96c6\u914d\u7f6e"


def test_legacy_local_encoding_is_preserved(tmp_path, monkeypatch):
    path = tmp_path / "legacy.ini"
    path.write_bytes("[FakeNet]\nDumpPackets = No\nDescription = caf\u00e9\n".encode("cp1252"))
    monkeypatch.setattr(locale, "getpreferredencoding", lambda _=False: "cp1252")
    fn = Fakenet()
    fn.parse_config(str(path))
    assert fn.fakenet_config["description"] == "caf\u00e9"
