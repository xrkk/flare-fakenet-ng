# Copyright 2026 Google LLC
"""Build identity for the ping probe (T003 §C).

Reads the packaged ``mcp-candidate-manifest.json`` next to the frozen exe
(or at the project package root in source checkouts) through a strict
whitelist: interface revision (a fixed contract constant), the manifest's
own SHA-256, and its source_commit (40- or 64-char hex only). Missing,
unreadable or malformed manifests never fail the ping and never invent an
identity — the answer is explicitly unknown with a short reason.

No git commands, no network, no manifest internals (files arrays, paths,
credentials) are ever echoed. The value is read at most once per process
and cached: a deployment that changes the manifest must restart the
service before ping reports the new identity.
"""

import hashlib
import json
import re
from pathlib import Path

INTERFACE_REVISION = '2026-10-06.1'
MANIFEST_NAME = 'mcp-candidate-manifest.json'
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
MANIFEST_SCHEMA = 'fakenet.mcp-candidate-manifest.v1'
_HEX_COMMIT = re.compile(r'\A[0-9a-f]{40}\Z|\A[0-9a-f]{64}\Z')

_cache = None


def manifest_path():
    """The packaged manifest location for this running process."""
    if getattr(__import__('sys'), 'frozen', False):
        return Path(__import__('sys').executable).resolve().parent / MANIFEST_NAME
    return Path(__file__).resolve().parents[2] / MANIFEST_NAME


def _unknown(reason=None):
    identity = {
        'interface_revision': INTERFACE_REVISION,
        'source_commit': None,
        'source': 'unknown',
        'manifest_sha256': None,
        'error': reason,
    }
    return identity


def _read_manifest(path):
    import stat

    try:
        info = path.lstat()
    except OSError:
        return None, None  # absent: unknown, not an error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return None, 'manifest is not a regular file'
    if info.st_size > MANIFEST_MAX_BYTES:
        return None, 'manifest exceeds 4 MiB bound'
    try:
        raw = path.read_bytes()
    except OSError:
        return None, 'manifest unreadable'
    if len(raw) > MANIFEST_MAX_BYTES:
        return None, 'manifest exceeds 4 MiB bound'
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        return digest, 'manifest is not valid JSON'
    if not isinstance(data, dict) or data.get('schema') != MANIFEST_SCHEMA:
        return digest, 'manifest schema mismatch'
    commit = data.get('source_commit')
    if commit is None:
        return digest, 'manifest carries no source_commit'
    if (not isinstance(commit, str) or
            not _HEX_COMMIT.match(commit)):
        return digest, 'manifest source_commit malformed'
    return digest, commit


def build_identity():
    """The cached build identity answer (see module docstring)."""
    global _cache
    if _cache is None:
        digest, outcome = _read_manifest(manifest_path())
        # outcome is None (absent), a validated hex commit, or a short
        # refusal reason — never a free-form echo of file contents.
        if outcome is None:
            _cache = _unknown()
        elif _HEX_COMMIT.match(outcome):
            _cache = {
                'interface_revision': INTERFACE_REVISION,
                'source_commit': outcome,
                'source': 'candidate_manifest',
                'manifest_sha256': digest,
                'error': None,
            }
        else:
            identity = _unknown(outcome)
            identity['manifest_sha256'] = digest
            _cache = identity
    return dict(_cache)
