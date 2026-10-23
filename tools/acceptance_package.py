"""Read-only MCP candidate ZIP identity, independent of target execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import time
import unicodedata
import zipfile

SCHEMA = 'fakenet.package-identity.v1'
CASE = 'BUILD-PACKAGE-IDENTITY'
CHECKS = ['frozen-source', 'archive-members', 'embedded-manifest', 'qualification-preserved']
MAX_MANIFEST = 16 * 1024 * 1024
MAX_MEMBER = 512 * 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024 * 1024
MAX_ENTRIES = 50000


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_json_bytes(payload):
    return json.loads(payload.decode('utf-8'), object_pairs_hook=unique_object)


def regular_file(value):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError('package input path must be absolute')
    path = Path(value)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('linked package input path')
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('package input is not a regular file')
    if str(path.resolve()) != value:
        raise ValueError('package input path is not canonical')
    return path


def member_key(name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('invalid ZIP member path')
    parts = name.split('/')
    if any(not part or part in ('.', '..') or part[-1:] in (' ', '.') or
           any(ord(char) < 32 or char in ':<>"|?*' for char in part) for part in parts):
        raise ValueError('ambiguous or escaping ZIP member path: ' + name)
    return '/'.join(unicodedata.normalize('NFC', part).casefold() for part in parts)


def manifest_at(path):
    if path.stat().st_size > MAX_MANIFEST:
        raise ValueError('manifest exceeds bounded read')
    raw = path.read_bytes()
    value = read_json_bytes(raw)
    required = {'schema', 'source_commit', 'source_snapshot_mode', 'files',
                'exe_sha256', 'qualification_status', 'native_gaps', 'zip_entry_timestamp_utc'}
    if not isinstance(value, dict) or not required <= set(value):
        raise ValueError('MCP manifest identity/qualification fields missing')
    if value['schema'] != 'fakenet.mcp-candidate-manifest.v1':
        raise ValueError('unsupported package manifest format; not evaluated')
    if value['source_snapshot_mode'] != 'commit' or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', str(value['source_commit'])):
        raise ValueError('manifest source is not an immutable commit')
    if value['zip_entry_timestamp_utc'] != '2000-01-01T00:00:00Z':
        raise ValueError('MCP manifest timestamp contract differs')
    if not isinstance(value['qualification_status'], str) or not value['qualification_status'] or not isinstance(value['native_gaps'], list):
        raise ValueError('manifest qualification metadata missing')
    rows = value['files']
    if not isinstance(rows, list) or not rows or len(rows) > MAX_ENTRIES:
        raise ValueError('manifest file set missing or over bound')
    keys = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'size', 'sha256'}:
            raise ValueError('manifest member fields missing/unknown')
        key = member_key(row['path'])
        if key in keys or key == 'mcp-candidate-manifest.json':
            raise ValueError('duplicate/ambiguous manifest member')
        keys.add(key)
        if type(row['size']) is not int or not 0 <= row['size'] <= MAX_MEMBER or not re.fullmatch(r'[0-9a-f]{64}', str(row['sha256'])):
            raise ValueError('invalid manifest member size/hash')
    exe = [row for row in rows if row['path'] == 'fakenetng-mcp.exe']
    if len(exe) != 1 or value['exe_sha256'] != exe[0]['sha256']:
        raise ValueError('manifest executable identity differs')
    return raw, value


def freeze_candidate(candidate):
    result = dict(candidate)
    package = regular_file(result.get('package_path'))
    manifest = regular_file(result.get('package_manifest'))
    if package == manifest or package.suffix.lower() != '.zip':
        raise ValueError('only distinct MCP ZIP and manifest inputs are supported')
    if not re.fullmatch(r'[0-9a-f]{64}', str(result.get('package_sha256'))):
        raise ValueError('frozen package SHA-256 required')
    raw, value = manifest_at(manifest)
    if value['source_commit'] != result.get('source_commit'):
        raise ValueError('manifest source differs from candidate source')
    digest = hashlib.sha256(raw).hexdigest()
    if result.get('package_manifest_sha256', digest) != digest:
        raise ValueError('manifest differs from frozen SHA-256')
    result['package_manifest_sha256'] = digest
    return result


def verify(root, candidate):
    # freeze_candidate rechecks the declared manifest hash; it never rebinds it.
    frozen = freeze_candidate(candidate)
    if frozen != candidate:
        raise ValueError('package manifest identity was not frozen at planning')
    package = regular_file(candidate['package_path'])
    manifest_path = regular_file(candidate['package_manifest'])
    raw, manifest = manifest_at(manifest_path)
    if package.stat().st_size > MAX_TOTAL or sha256(package) != candidate['package_sha256']:
        raise ValueError('package bytes differ from frozen SHA-256')
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > MAX_ENTRIES:
            raise ValueError('ZIP member count outside bounded format')
        keys = set()
        total = 0
        for entry in entries:
            key = member_key(entry.filename)
            mode = (entry.external_attr >> 16) & 0o170000
            if key in keys or entry.is_dir() or mode not in (0, stat.S_IFREG) or entry.flag_bits & 1:
                raise ValueError('duplicate, linked or unsupported ZIP member')
            keys.add(key)
            total += entry.file_size
            limit = MAX_MANIFEST if entry.filename == 'mcp-candidate-manifest.json' else MAX_MEMBER
            if entry.file_size > limit or total > MAX_TOTAL:
                raise ValueError('ZIP expands beyond bounded read')
        for key in keys:
            parts = key.split('/')
            if any('/'.join(parts[:end]) in keys for end in range(1, len(parts))):
                raise ValueError('ZIP file/directory path conflict')
        embedded = read_json_bytes(archive.read('mcp-candidate-manifest.json'))
        if embedded != manifest:
            raise ValueError('embedded manifest differs from frozen original')
    from acceptance_oracles import load
    builder = load(root, 'tools/build_fakenetng_mcp_wine.py')
    original = builder.verify_package_zip(package, manifest)
    # Detect concurrent replacement of either original during the read.
    if sha256(package) != candidate['package_sha256'] or manifest_path.read_bytes() != raw:
        raise ValueError('package originals changed during verification')
    return {'verification': original, 'source_commit': manifest['source_commit'],
            'qualification_status': manifest['qualification_status'],
            'native_gaps': manifest['native_gaps'], 'native_functionality_evaluated': False,
            'reproducible_build_evaluated': False}


def request_for(case, plan):
    if case['id'] != CASE or plan['candidate']['source_commit'] != plan['source_commit']:
        raise ValueError('package case/source identity differs')
    return {'schema': SCHEMA, 'case_id': CASE, 'execution_id': plan['execution_id'],
            'candidate': plan['candidate'], 'checks': CHECKS,
            'source_pins': plan['native_source_hashes']}


def run(root, case, plan, output):
    from acceptance_runtime import write_json
    output = Path(output)
    request = request_for(case, plan)
    started = time.time()
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / 'package-request.json', request)
    manifest = regular_file(plan['candidate']['package_manifest'])
    if manifest.stat().st_size > MAX_MANIFEST:
        raise ValueError('manifest exceeds bounded read')
    with (output / 'manifest-original.json').open('xb') as stream:
        stream.write(manifest.read_bytes())
    try:
        facts = verify(root, plan['candidate'])
        result = {'status': 'pass', 'facts': facts}
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile) as exc:
        result = {'status': 'fail', 'reason': str(exc)}
    write_json(output / 'package-result.json', result)
    artifacts = [{'path': str(path.resolve()), 'sha256': sha256(path), 'format': 'package-original'}
                 for path in sorted(output.iterdir()) if path.is_file()]
    return {'status': result['status'], 'detail': result, 'returncode': 0 if result['status'] == 'pass' else 1,
            'command': ['read-only-package-identity', CASE], 'required_checks': CHECKS,
            'duration_seconds': time.time() - started, 'artifacts': artifacts,
            'cleanup': {'source': 'read-only-package', 'mutated_external_resources': False}}


def judge(root, case, receipt, plan):
    output = Path(plan['run_dir']) / 'results' / CASE
    try:
        expected = request_for(case, plan)
        if receipt.get('returncode') != 0 or receipt.get('cleanup') != {'source': 'read-only-package', 'mutated_external_resources': False}:
            raise ValueError('package receipt exit/resource declaration differs')
        if receipt.get('command') != ['read-only-package-identity', CASE] or receipt.get('required_checks') != CHECKS:
            raise ValueError('package receipt identity differs')
        required = {output / name for name in ('package-request.json', 'manifest-original.json', 'package-result.json')}
        indexed = []
        for row in receipt.get('artifacts', []):
            path = regular_file(row['path'])
            if path not in required or sha256(path) != row['sha256'] or row['format'] != 'package-original':
                raise ValueError('package original index differs')
            indexed.append(path)
        actual = {path for path in output.iterdir() if path.name != 'receipt.json'}
        if len(indexed) != len(required) or set(indexed) != required or actual != required:
            raise ValueError('package original index not exact')
        if read_json_bytes((output / 'package-request.json').read_bytes()) != expected:
            raise ValueError('package request differs from frozen plan')
        if hashlib.sha256((output / 'manifest-original.json').read_bytes()).hexdigest() != plan['candidate']['package_manifest_sha256']:
            raise ValueError('archived manifest differs from frozen original')
        facts = verify(root, plan['candidate'])
        result = read_json_bytes((output / 'package-result.json').read_bytes())
        if result != {'status': 'pass', 'facts': facts} or receipt.get('status') != 'pass':
            raise ValueError('package result differs from original rejudgment')
        return {'status': 'pass', 'cleanup_ok': True, 'details': facts}
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        return {'status': 'fail', 'cleanup_ok': True, 'reason': str(exc)}
