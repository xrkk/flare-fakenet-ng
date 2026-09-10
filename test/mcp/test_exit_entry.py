import sys

import pytest

from fakenet.mcp import cli


@pytest.mark.parametrize('arguments', [[], ['install'], ['run'], ['start'], ['stop'],
                                      ['uninstall'], ['debug'], ['incident-dump', '1', '2', '3'],
                                      ['managed-fault-hang'], ['--help']])
def test_dedicated_managed_image_cannot_dispatch_service_commands(monkeypatch, arguments):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', '/package/fakenetng-mcp-managed.exe')
    assert cli.main(arguments) == 2
