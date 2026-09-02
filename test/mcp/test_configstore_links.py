# Copyright 2026 Google LLC
"""Symlink escape matrix (requires an environment able to create symlinks).

Skipped where symlink creation needs privileges the runtime lacks (e.g.
Wine without admin); hard-link coverage lives in test_configstore.py.
"""

import os
import tempfile

import pytest

from fakenet.mcp import errors
from fakenet.mcp.configstore import ConfigStore

VALID_INI = '[FakeNet]\nDumpPackets = No\n'


def _can_symlink():
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 't.ini')
            link = os.path.join(tmp, 'l.ini')
            open(target, 'w').close()
            os.symlink(target, link)
            # Some Wine configurations silently materialize a copy instead
            # of a real link; only run when a true symlink round-trips.
            return os.path.islink(link)
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _can_symlink(),
                                reason='symlink creation unavailable')


@pytest.fixture()
def store(tmp_path):
    return ConfigStore(custom_root=tmp_path / 'custom',
                       builtin_root=tmp_path / 'builtin',
                       audit_path=tmp_path / 'logs' / 'config-audit.jsonl')


def test_symlink_inside_root_rejected(store, tmp_path):
    outside = tmp_path / 'outside.ini'
    outside.write_text(VALID_INI, encoding='utf-8')
    link = store.custom_root / 'link.ini'
    os.symlink(outside, link)
    with pytest.raises(errors.McpError) as excinfo:
        store.read('link.ini')
    assert excinfo.value.code == errors.PATH_ESCAPE_BLOCKED


def test_symlink_edit_target_rejected(store, tmp_path):
    outside = tmp_path / 'outside.ini'
    outside.write_text(VALID_INI, encoding='utf-8')
    link = store.custom_root / 'pre.ini'
    os.symlink(outside, link)
    with pytest.raises(errors.McpError):
        store.edit(controller='A', command_id='c1', name='pre.ini',
                   content=VALID_INI, expected_sha256='whatever')
