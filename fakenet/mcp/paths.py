# Copyright 2026 Google LLC
"""Machine-level layout for fakenetng-mcp.

Program/built-in configs live under %ProgramFiles%\\FakeNet-NG-MCP\\ (created by
the installer, never written here).  All writable data lives under
%ProgramData%\\FakeNet-NG-MCP\\ with the five frozen sub-directories required by
REQ-014 plus the service deployment config ``configs\\service.json`` (DEC-005:
a deployment config under configs\\, outside the five-dir product data set).

The service must not depend on cwd, user profile, desktop, mapped drives or an
interactive session, so every path here is absolute and rooted at the machine
ProgramData location.  ``FAKENETNG_MCP_PROGRAMDATA`` is a test-only override.
"""

import os
from pathlib import Path

DATA_DIR_NAME = 'FakeNet-NG-MCP'
CONFIGS_DIR_NAME = 'configs'
CUSTOM_CONFIGS_DIR_NAME = 'custom'
STATE_DIR_NAME = 'state'
LOGS_DIR_NAME = 'logs'
BASELINES_DIR_NAME = 'baselines'
ARTIFACTS_DIR_NAME = 'artifacts'
SERVICE_CONFIG_NAME = 'service.json'


def _windows_common_appdata() -> Path:
    import ctypes
    import ctypes.wintypes

    csidl_common_appdata = 0x0023
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    result = ctypes.windll.shell32.SHGetFolderPathW(
        None, csidl_common_appdata, None, 0, buf)
    if result != 0:
        raise RuntimeError(
            'SHGetFolderPathW(CSIDL_COMMON_APPDATA) failed: %d' % result)
    return Path(buf.value)


def programdata_root() -> Path:
    """Absolute machine ProgramData root for this service."""
    override = os.environ.get('FAKENETNG_MCP_PROGRAMDATA')
    if override:
        base = Path(override)
    elif os.name == 'nt':
        base = _windows_common_appdata()
    else:
        base = Path(os.environ.get('PROGRAMDATA', '/tmp/fakenetng-mcp-programdata'))
    return (base / DATA_DIR_NAME).resolve()


def service_config_path() -> Path:
    return programdata_root() / CONFIGS_DIR_NAME / SERVICE_CONFIG_NAME


def data_directories() -> dict:
    root = programdata_root()
    return {
        'configs': root / CONFIGS_DIR_NAME,
        'configs_custom': root / CONFIGS_DIR_NAME / CUSTOM_CONFIGS_DIR_NAME,
        'state': root / STATE_DIR_NAME,
        'logs': root / LOGS_DIR_NAME,
        'baselines': root / BASELINES_DIR_NAME,
        'artifacts': root / ARTIFACTS_DIR_NAME,
    }


def ensure_data_directories() -> dict:
    """Create the writable machine-level layout if missing (idempotent)."""
    dirs = data_directories()
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs
