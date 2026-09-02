# Copyright 2026 Google LLC
"""Machine-level layout behavior (P01 IMP-P01-03)."""

from pathlib import Path

from fakenet.mcp import paths


def test_override_root_yields_five_dirs(tmp_path):
    import os

    os.environ['FAKENETNG_MCP_PROGRAMDATA'] = str(tmp_path)
    try:
        dirs = paths.ensure_data_directories()
        expected = {'configs_custom', 'state', 'logs', 'baselines',
                    'artifacts'}
        assert set(dirs) >= expected
        for name in expected:
            assert Path(dirs[name]).is_dir()
        assert Path(dirs['configs_custom']).parent == Path(dirs['configs'])
        # Every path is absolute (no cwd / profile / mapped-drive reliance).
        for path in dirs.values():
            assert path.is_absolute()
        assert paths.service_config_path().parent == Path(dirs['configs'])
    finally:
        os.environ.pop('FAKENETNG_MCP_PROGRAMDATA', None)


def test_ensure_is_idempotent(tmp_path):
    import os

    os.environ['FAKENETNG_MCP_PROGRAMDATA'] = str(tmp_path)
    try:
        paths.ensure_data_directories()
        dirs2 = paths.ensure_data_directories()
        assert dirs2 == paths.data_directories()
    finally:
        os.environ.pop('FAKENETNG_MCP_PROGRAMDATA', None)
