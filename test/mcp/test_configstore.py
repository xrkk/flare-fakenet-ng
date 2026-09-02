# Copyright 2026 Google LLC
"""ConfigStore: managed-root operations, escape matrix, audit-first commit."""

import hashlib
import json
import os

import pytest

from fakenet.mcp import errors
from fakenet.mcp.configstore import ConfigStore

VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
OTHER_INI = '[FakeNet]\nDumpPackets = Yes\n'


@pytest.fixture()
def store(tmp_path):
    return ConfigStore(custom_root=tmp_path / 'custom',
                       builtin_root=tmp_path / 'builtin',
                       audit_path=tmp_path / 'logs' / 'config-audit.jsonl')


def sha_of(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def test_create_read_edit_delete_roundtrip(store):
    result = store.create(controller='A', command_id='c1', name='a.ini',
                          content=VALID_INI)
    assert result['changed'] is True
    record = store.read('a.ini')
    assert record['content'] == VALID_INI
    assert record['sha256'] == sha_of(VALID_INI)

    edit = store.edit(controller='A', command_id='c2', name='a.ini',
                      content=OTHER_INI,
                      expected_sha256=sha_of(VALID_INI))
    assert edit['changed'] is True
    with pytest.raises(errors.McpError) as excinfo:
        store.edit(controller='A', command_id='c3', name='a.ini',
                   content=VALID_INI, expected_sha256='deadbeef')
    assert excinfo.value.code == errors.VERSION_CONFLICT

    store.delete(controller='A', command_id='c4', name='a.ini',
                 expected_sha256=sha_of(OTHER_INI))
    with pytest.raises(errors.McpError):
        store.read('a.ini')


def test_create_refuses_overwrite(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    with pytest.raises(errors.McpError) as excinfo:
        store.create(controller='A', command_id='c2', name='a.ini',
                     content=OTHER_INI)
    assert excinfo.value.code == errors.NAME_CONFLICT


def test_validation_rejects_garbage(store):
    from fakenet.mcp import errors as mcp_errors

    with pytest.raises(mcp_errors.McpError):
        store.validate_content('\0not an ini at all\x1b[31m')


def test_escape_matrix(store):
    for bad in ('../escape.ini', '..\\escape.ini', '/abs.ini',
                'C:/abs.ini', 'sub/dir.ini', 'sub\\dir.ini', 'CON.ini',
                'nul.ini', 'com1.ini'):
        with pytest.raises(errors.McpError) as excinfo:
            store.create(controller='A', command_id='c', name=bad,
                         content=VALID_INI)
        assert excinfo.value.code == errors.PATH_ESCAPE_BLOCKED, bad


def test_hard_link_rejected(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    link = store.custom_root / 'hard.ini'
    os.link(store.custom_root / 'a.ini', link)
    with pytest.raises(errors.McpError) as excinfo:
        store.read('hard.ini')
    assert excinfo.value.code == errors.PATH_ESCAPE_BLOCKED


def test_active_config_locked(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    store.set_active('a.ini')
    for invoker in (
            lambda: store.edit(controller='A', command_id='c2',
                               name='a.ini', content=OTHER_INI,
                               expected_sha256=sha_of(VALID_INI)),
            lambda: store.delete(controller='A', command_id='c3',
                                 name='a.ini',
                                 expected_sha256=sha_of(VALID_INI))):
        with pytest.raises(errors.McpError) as excinfo:
            invoker()
        assert excinfo.value.code == errors.CONFIG_IN_USE


def test_rename_locked_while_active(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    store.set_active('a.ini')
    with pytest.raises(errors.McpError) as excinfo:
        store.rename(controller='A', command_id='c2', name='a.ini',
                     new_name='b.ini', expected_sha256=sha_of(VALID_INI))
    assert excinfo.value.code == errors.CONFIG_IN_USE


def test_builtin_readonly(store):
    builtin = store.builtin_root / 'default.ini'
    builtin.parent.mkdir(parents=True, exist_ok=True)
    builtin.write_text(VALID_INI, encoding='utf-8')
    record = store.read('default.ini')
    assert record['builtin'] is True
    with pytest.raises(errors.McpError) as excinfo:
        store.delete(controller='A', command_id='c1', name='default.ini',
                     expected_sha256=record['sha256'])
    assert excinfo.value.code == errors.BUILTIN_READONLY


def test_audit_captures_every_outcome(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    with pytest.raises(errors.McpError):
        store.create(controller='A', command_id='c2', name='a.ini',
                     content=OTHER_INI)  # name_conflict (audited)
    with pytest.raises(errors.McpError):
        store.edit(controller='A', command_id='c3', name='a.ini',
                   content=OTHER_INI, expected_sha256='wrong')  # conflict
    store.edit(controller='A', command_id='c4', name='a.ini',
               content=VALID_INI, expected_sha256=sha_of(VALID_INI))
    lines = store.audit_lines()
    by_op = {('%s:%s' % (line['operation'], line['result'])): line
             for line in lines}
    assert 'create:ok' in by_op
    assert 'create:name_conflict' in by_op
    assert 'edit:version_conflict' in by_op
    assert 'edit:no_change' in by_op
    for line in lines:
        assert set(line) >= {'timestamp', 'controller', 'command_id',
                             'target', 'operation', 'before_sha256',
                             'after_sha256', 'result'}


def test_audit_write_failure_aborts_commit(store, tmp_path):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    # Make the audit sink an unwritable path (a directory): the real IO
    # failure path must convert to audit_write_failed and abort the commit.
    broken_dir = tmp_path / 'broken-audit'
    broken_dir.mkdir()
    store.audit_path = broken_dir
    with pytest.raises(errors.McpError) as excinfo:
        store.edit(controller='A', command_id='c2', name='a.ini',
                   content=OTHER_INI, expected_sha256=sha_of(VALID_INI))
    assert excinfo.value.code == errors.AUDIT_WRITE_FAILED
    # The original content is intact: the commit never ran.
    assert store.read('a.ini')['content'] == VALID_INI


def test_audit_is_plain_jsonl_not_state(store):
    store.create(controller='A', command_id='c1', name='a.ini',
                 content=VALID_INI)
    raw = store.audit_path.read_text(encoding='utf-8').splitlines()
    assert len(raw) == 1
    parsed = json.loads(raw[0])
    assert parsed['operation'] == 'create'
