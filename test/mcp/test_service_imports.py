# Copyright 2026 Google LLC
"""Import-time coverage for the Windows-only service modules (P01).

``fakenet.mcp.winservice`` executes its ctypes SCM setup at import time on
Windows; importing ``fakenet.mcp.cli`` here exercises that path on every
platform so the Wine gate catches missing attributes early.
"""

import importlib


def test_cli_imports_winservice_modules():
    module = importlib.import_module('fakenet.mcp.cli')
    assert callable(module.main)
    assert callable(module.service_main)
    winservice = importlib.import_module('fakenet.mcp.winservice')
    assert winservice.SERVICE_NAME == 'fakenetng-mcp'


def test_transportguard_constants():
    from fakenet.mcp import transportguard

    assert transportguard.JSONRPC_HEADER_MISMATCH == -32020
    assert transportsupport_versions(transportguard) == ['2026-07-28']


def transportsupport_versions(transportguard):
    return transportguard.SUPPORTED_VERSIONS
