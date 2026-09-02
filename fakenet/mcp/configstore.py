# Copyright 2026 Google LLC
"""Custom .ini config store: managed root, escape blocking, audit-first.

Sub-plan P02 §3 frozen semantics (records 012/013/014/032/033):

* names match ``[A-Za-z0-9._-]+\\.ini``; absolute paths, separators,
  ``..``, Windows reserved device names, symlinks and hard links
  (``st_nlink > 1``) are rejected (``path_escape_blocked``); reparse-point
  enforcement is a P03 real-Windows hook;
* create/import refuse to overwrite (``name_conflict``); edit/rename/delete
  require ``expected_sha256`` (``version_conflict`` on mismatch);
* writes go temp-file -> audit append -> atomic ``os.replace``; an audit
  append failure aborts the commit (``audit_write_failed``);
* every operation — including failures, conflicts and attempts that change
  nothing — appends one audit line (plain JSONL, never a state source);
* the active config name is registered by the lifecycle tools; writes to it
  are ``config_in_use``; while a run is active only the owning controller
  may write (the tools layer enforces the controller gate, this store
  enforces the active-name gate).
"""

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path

from fakenet.mcp import errors

NAME_PATTERN = re.compile(r'^[A-Za-z0-9._-]+\.ini$')
RESERVED_DEVICE_NAMES = frozenset(
    ('CON', 'PRN', 'AUX', 'NUL') +
    tuple('COM%d' % i for i in range(1, 10)) +
    tuple('LPT%d' % i for i in range(1, 10)))
MAX_CONFIG_BYTES = 1024 * 1024


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_name(name):
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise errors.McpError(
            errors.PATH_ESCAPE_BLOCKED,
            'config name must match [A-Za-z0-9._-]+.ini', {'name': name})
    stem = name.split('.')[0].upper()
    if stem in RESERVED_DEVICE_NAMES:
        raise errors.McpError(
            errors.PATH_ESCAPE_BLOCKED,
            'config name uses a reserved device name', {'name': name})
    return name


class ConfigStore:

    def __init__(self, custom_root, builtin_root, audit_path):
        self.custom_root = Path(custom_root)
        self.builtin_root = Path(builtin_root)
        self.audit_path = Path(audit_path)
        self.custom_root.mkdir(parents=True, exist_ok=True)
        self._active_name = None

    # -- audit -------------------------------------------------------------
    def audit(self, *, controller, command_id, target, operation,
              before_sha256, after_sha256, result):
        entry = {
            'timestamp': time.time(),
            'controller': controller,
            'command_id': command_id,
            'target': target,
            'operation': operation,
            'before_sha256': before_sha256,
            'after_sha256': after_sha256,
            'result': result,
        }
        line = json.dumps(entry, ensure_ascii=False) + '\n'
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_path, 'a', encoding='utf-8') as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise errors.McpError(
                errors.AUDIT_WRITE_FAILED,
                'config audit log unavailable; refusing commit',
                {'reason': repr(exc)[:160]}) from exc

    def audit_lines(self):
        if not self.audit_path.is_file():
            return []
        return [json.loads(line) for line in
                self.audit_path.read_text(encoding='utf-8').splitlines()
                if line.strip()]

    # -- active config registry -------------------------------------------
    def set_active(self, name):
        self._active_name = name

    @property
    def active_name(self):
        return self._active_name

    def _guard_writable(self, name):
        if self._active_name is not None and name == self._active_name:
            raise errors.McpError(
                errors.CONFIG_IN_USE,
                'config is active for the running FakeNet-NG',
                {'name': name})

    # -- path resolution ---------------------------------------------------
    def _custom_path(self, name):
        validate_name(name)
        raw = self.custom_root / name
        if raw.is_symlink():
            raise errors.McpError(
                errors.PATH_ESCAPE_BLOCKED, 'symlink rejected',
                {'name': name})
        candidate = raw.resolve()
        if candidate.parent != self.custom_root.resolve():
            raise errors.McpError(
                errors.PATH_ESCAPE_BLOCKED, 'resolved path escapes root',
                {'name': name})
        return candidate

    def _check_not_hardlink(self, path):
        try:
            if path.stat().st_nlink > 1:
                raise errors.McpError(
                    errors.PATH_ESCAPE_BLOCKED, 'hard link rejected',
                    {'name': path.name})
        except FileNotFoundError:
            pass

    @staticmethod
    def _check_new_file_not_link(path):
        if path.is_symlink():
            raise errors.McpError(
                errors.PATH_ESCAPE_BLOCKED, 'symlink rejected',
                {'name': path.name})

    # -- read operations ---------------------------------------------------
    def list(self):
        items = []
        if self.builtin_root.is_dir():
            for path in sorted(self.builtin_root.glob('*.ini')):
                items.append({
                    'name': path.name, 'builtin': True,
                    'size': path.stat().st_size,
                    'sha256': _sha256_bytes(path.read_bytes()),
                    'active': path.name == self._active_name,
                })
        for path in sorted(self.custom_root.glob('*.ini')):
            self._check_new_file_not_link(path)
            self._check_not_hardlink(path)
            items.append({
                'name': path.name, 'builtin': False,
                'size': path.stat().st_size,
                'sha256': _sha256_bytes(path.read_bytes()),
                'active': path.name == self._active_name,
            })
        return items

    def read(self, name):
        if _is_builtin_candidate(name):
            path = self.builtin_root / name
            if path.is_file():
                raw = path.read_bytes()
                return {'name': name, 'builtin': True,
                        'sha256': _sha256_bytes(raw), 'size': len(raw),
                        'content': raw.decode('utf-8', 'replace')}
        path = self._custom_path(name)
        if not path.is_file():
            raise errors.McpError(
                errors.CONFIG_NOT_FOUND, 'config not found',
                {'name': name})
        self._check_new_file_not_link(path)
        self._check_not_hardlink(path)
        raw = path.read_bytes()
        if len(raw) > MAX_CONFIG_BYTES:
            raise errors.McpError(
                errors.INVALID_REQUEST, 'config exceeds size limit',
                {'name': name, 'size': len(raw)})
        return {'name': name, 'builtin': False, 'sha256': _sha256_bytes(raw),
                'size': len(raw),
                'content': raw.decode('utf-8', 'replace')}

    def validate_content(self, content):
        """Syntax/base-semantics validation via Fakenet.parse_config."""
        import tempfile

        from fakenet.fakenet import Fakenet

        if not isinstance(content, str):
            raise errors.McpError(
                errors.INVALID_REQUEST, 'content must be a string')
        if len(content.encode('utf-8')) > MAX_CONFIG_BYTES:
            raise errors.McpError(
                errors.INVALID_REQUEST, 'content exceeds size limit')
        handle, tmp_name = tempfile.mkstemp(suffix='.ini')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                stream.write(content)
            instance = Fakenet()
            try:
                instance.parse_config(tmp_name)
            except SystemExit as exc:
                raise errors.McpError(
                    errors.VALIDATION_FAILED,
                    'configuration rejected by parser',
                    {'exit_code': exc.code}) from exc
            except Exception as exc:  # noqa: BLE001 - parser errors et al.
                raise errors.McpError(
                    errors.VALIDATION_FAILED,
                    'configuration rejected by parser',
                    {'reason': repr(exc)[:200]}) from exc
            sections = {
                'fakenet': dict(instance.fakenet_config),
                'diverter': dict(instance.diverter_config),
                'listeners': {name: dict(value) for name, value in
                              instance.listeners_config.items()},
            }
            return {'valid': True, 'sections': sections}
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass

    # -- write operations (audit-first commit) ------------------------------
    def _commit(self, *, controller, command_id, operation, name, content,
                expected_sha256, allow_create, allow_missing):
        target = self._custom_path(name)
        exists = target.is_file()
        if exists:
            self._check_new_file_not_link(target)
            self._check_not_hardlink(target)
            self._guard_writable(name)
        before_sha = _sha256_bytes(target.read_bytes()) if exists else None

        def refuse(code, message, detail):
            exc = errors.McpError(code, message, detail)
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation=operation,
                       before_sha256=before_sha, after_sha256=None,
                       result=code)
            return exc

        if not exists and not allow_create:
            raise refuse(errors.CONFIG_NOT_FOUND, 'config not found',
                         {'name': name})
        if exists and allow_create:
            raise refuse(errors.NAME_CONFLICT, 'config already exists',
                         {'name': name})
        if exists and expected_sha256 is not None and \
                expected_sha256 != before_sha:
            raise refuse(
                errors.VERSION_CONFLICT,
                'expected_sha256 does not match current content',
                {'expected': expected_sha256, 'current': before_sha})

        raw = content.encode('utf-8')
        after_sha = _sha256_bytes(raw)
        if exists and before_sha == after_sha and operation != 'rename':
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation=operation,
                       before_sha256=before_sha, after_sha256=after_sha,
                       result='no_change')
            return {'name': name, 'sha256': after_sha, 'changed': False}

        tmp = target.with_name('.%s.%d.tmp' % (target.name, os.getpid()))
        try:
            with open(tmp, 'wb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation=operation,
                       before_sha256=before_sha, after_sha256=after_sha,
                       result='ok')
            os.replace(tmp, target)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation=operation,
                       before_sha256=before_sha, after_sha256=after_sha,
                       result='commit_failed')
            raise errors.McpError(
                errors.INTERNAL_ERROR, 'commit failed',
                {'reason': repr(exc)[:160]}) from exc
        return {'name': name, 'sha256': after_sha, 'changed': True}

    def create(self, *, controller, command_id, name, content):
        validate_name(name)
        return self._commit(controller=controller, command_id=command_id,
                            operation='create', name=name, content=content,
                            expected_sha256=None, allow_create=True,
                            allow_missing=False)

    def edit(self, *, controller, command_id, name, content,
             expected_sha256):
        return self._commit(controller=controller, command_id=command_id,
                            operation='edit', name=name, content=content,
                            expected_sha256=expected_sha256,
                            allow_create=False, allow_missing=True)

    def rename(self, *, controller, command_id, name, new_name,
               expected_sha256):
        validate_name(new_name)
        source = self._custom_path(name)
        self._guard_writable(name)
        record = self.read(name)
        if record.get('builtin'):
            raise errors.McpError(
                errors.BUILTIN_READONLY, 'builtin configs are read-only',
                {'name': name})
        destination = self._custom_path(new_name)
        if destination.is_file():
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation='rename',
                       before_sha256=record['sha256'], after_sha256=None,
                       result=errors.NAME_CONFLICT)
            raise errors.McpError(
                errors.NAME_CONFLICT, 'target name already exists',
                {'name': new_name})
        if expected_sha256 is not None and expected_sha256 != record[
                'sha256']:
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation='rename',
                       before_sha256=record['sha256'], after_sha256=None,
                       result=errors.VERSION_CONFLICT)
            raise errors.McpError(
                errors.VERSION_CONFLICT,
                'expected_sha256 does not match current content',
                {'expected': expected_sha256, 'current': record['sha256']})
        self.audit(controller=controller, command_id=command_id,
                   target=name, operation='rename',
                   before_sha256=record['sha256'],
                   after_sha256=record['sha256'],
                   result='ok:%s' % new_name)
        try:
            os.replace(source, destination)
        except OSError as exc:
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation='rename',
                       before_sha256=record['sha256'],
                       after_sha256=record['sha256'],
                       result='commit_failed')
            raise errors.McpError(
                errors.INTERNAL_ERROR, 'rename failed',
                {'reason': repr(exc)[:160]}) from exc
        if self._active_name == name:
            self._active_name = new_name
        return {'name': new_name, 'sha256': record['sha256'],
                'changed': True}

    def delete(self, *, controller, command_id, name, expected_sha256):
        path = self._custom_path(name)
        record = self.read(name)
        if record.get('builtin'):
            raise errors.McpError(
                errors.BUILTIN_READONLY, 'builtin configs are read-only',
                {'name': name})
        self._guard_writable(name)
        if expected_sha256 is not None and \
                expected_sha256 != record['sha256']:
            self.audit(controller=controller, command_id=command_id,
                       target=name, operation='delete',
                       before_sha256=record['sha256'], after_sha256=None,
                       result=errors.VERSION_CONFLICT)
            raise errors.McpError(
                errors.VERSION_CONFLICT,
                'expected_sha256 does not match current content',
                {'expected': expected_sha256,
                 'current': record['sha256']})
        self.audit(controller=controller, command_id=command_id,
                   target=name, operation='delete',
                   before_sha256=record['sha256'], after_sha256=None,
                   result='ok')
        try:
            path.unlink()
        except OSError as exc:
            raise errors.McpError(
                errors.INTERNAL_ERROR, 'delete failed',
                {'reason': repr(exc)[:160]}) from exc
        return {'name': name, 'changed': True}


def _is_builtin_candidate(name):
    return isinstance(name, str) and os.sep not in name and \
        '/' not in name and '..' not in name
