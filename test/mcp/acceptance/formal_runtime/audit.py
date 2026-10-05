"""Source-authorized proof-key projection for a separate audit interpreter.

Import installs nothing. Original derive and complete proof comparison remain
unchanged; only the two absolute input-key maps are projected.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading

import scenario_aux_qpc_contract as contract
import scenario_aux_qpc_v2 as v2
import scenario_suite as suite
from .context import checked_record, exact_path, file_sha256, read_json
from .source import SourceAuthority

SCHEMA = 'fakenetng.formal-runtime.source-bijection.v1'
_LOCK = threading.Lock()


class AuditError(ValueError):
    """An authority, copy, or selected dependency is not the exact source."""


def require(condition, reason):
    if not condition:
        raise AuditError(reason)


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')


class AuditGuard:
    """Inactive outside a scoped audit; no import-time global hook."""
    def __init__(self, context):
        self.context = context
        self.active = False
        self.deriving = False
        self.trace = []
        self.qualified_files = None
        self.git_reads = {
            ('git', '-C', str(context.source_root), 'cat-file', 'blob',
             context.tool_source['commit'] + ':' + Path(row['path']).relative_to(context.source_root).as_posix())
            for row in context.tool_source['files']}

    def __call__(self, event, args):
        if not self.active:
            return
        if event.startswith('socket.'):
            raise AuditError('independent audit forbids network')
        if event == 'exec':
            filename = args[0].co_filename
            if Path(filename).is_absolute():
                path = Path(filename).resolve()
                require(not path.is_relative_to(self.context.repository_root / 'Logs'),
                        'audit refuses code execution from Logs')
                if self.qualified_files is not None and (path.is_relative_to(self.context.source_root / 'test/mcp')
                        or path.is_relative_to(self.context.source_root / 'fakenet')):
                    require(path in self.qualified_files and file_sha256(path) == self.qualified_files[path],
                            'audit code outside qualified source closure')
            return
        if event == 'subprocess.Popen':
            require(tuple(args[1]) in self.git_reads, 'independent audit forbids business subprocess')
            return
        paths, write = [], False
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            paths = [args[0]]
            write = bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            write = write or args[1] is not None and any(c in args[1] for c in 'wax+')
        elif event in ('os.scandir', 'os.listdir'):
            paths = [args[0]] if isinstance(args[0], (str, bytes, os.PathLike)) else []
        elif event in ('os.chmod', 'os.chown', 'os.utime', 'os.truncate'):
            paths, write = [args[0]], True
        elif event in ('os.mkdir', 'os.rmdir', 'os.remove', 'os.rename', 'os.link', 'os.symlink'):
            paths, write = list(args[:2] if event in ('os.rename', 'os.link') else args[:1]), True
        if event == 'os.symlink':
            paths = [args[1]]
        for i, value in enumerate(paths):
            if not isinstance(value, (str, bytes, os.PathLike)):
                continue
            path = Path(os.fsdecode(value))
            dirfd = None
            if event == 'os.mkdir': dirfd = args[-1]
            elif event in ('os.remove', 'os.rmdir') and len(args) > 1: dirfd = args[1]
            elif event in ('os.rename', 'os.link') and len(args) > 2: dirfd = args[2 + i]
            elif event == 'os.chmod' and len(args) > 2: dirfd = args[2]
            elif event in ('os.utime', 'os.chown') and len(args) > 3: dirfd = args[3]
            if not path.is_absolute() and isinstance(dirfd, int) and dirfd >= 0:
                path = Path(os.readlink('/proc/self/fd/' + str(dirfd))) / path
            path = path.absolute()
            resolved = path.resolve()
            require(not write or resolved.is_relative_to(self.context.audit_root),
                    'audit write outside independent output refused: ' + str(path))
            if self.deriving:
                protected = [Path(p) for p in self.context.materials['protected_sources']]
                require(not any(resolved == p or resolved.is_relative_to(p) for p in protected)
                        and not (resolved.is_relative_to(self.context.repository_root / 'Logs')
                                 and not resolved.is_relative_to(self.context.audit_root)),
                        'original derive historical fallback refused: ' + str(path))
            self.trace.append({'event': event, 'path': str(path), 'write': bool(write)})


class Mapper:
    def __init__(self, context, authority_path, authority_sha256):
        self.context = context.revalidate()
        self.path = exact_path(str(authority_path))
        require(self.path.is_relative_to(context.audit_root / 'authorities'),
                'authority outside independent output')
        self.sha256 = authority_sha256
        self.authority = self._snapshot()
        require(self.authority.get('schema') == SCHEMA, 'unsupported authority schema')
        self.view = exact_path(self.authority['runtime_view'])
        require(self.view == context.audit_root / 'view', 'authority runtime view differs')
        self.records = copy.deepcopy(self.authority['records'])
        self.contexts = copy.deepcopy(self.authority['contexts'])
        self.selected = copy.deepcopy(self.authority['selected'])
        self.count = 0
        self.guard = AuditGuard(context)
        self.verify_snapshot()

    def _snapshot(self):
        require(self.path.is_file() and file_sha256(self.path) == self.sha256,
                'authority changed after independent freeze')
        return read_json(self.path)

    def check_authority(self):
        self.context.revalidate()
        require(self._snapshot() == self.authority and self.records == self.authority['records']
                and self.contexts == self.authority['contexts'] and self.selected == self.authority['selected'],
                'constructor/source/context differs from trusted authority')

    def verify_snapshot(self):
        require(isinstance(self.records, dict) and isinstance(self.contexts, dict)
                and isinstance(self.selected, dict) and bool(self.selected), 'authority fields invalid')
        scope = self.authority.get('scope')
        if scope == 'row-selection':
            from .row_selection import selection
            expected_selection = selection(self.context)
        elif scope == 'batch-selection':
            from .batch_selection import selection
            expected_selection = selection(self.context)
        elif scope == 'credited-selection':
            expected_selection = read_json(checked_record(dict(self.context.materials['credited_selection'])))
        elif scope == 'spike-only':
            report_path = checked_record(dict(self.context.materials['spike_source']))
            report = SourceAuthority(self.context, report_path.parent).read(report_path)
            expected_selection = {case['scenario_id']: str(report_path.parent) for case in report['cases']}
            require(len(expected_selection) == len(report['cases']), 'Spike selected cases duplicated')
        else:
            raise AuditError('unregistered authority selection scope')
        require({sid: row['root'] for sid, row in self.selected.items()} == expected_selection,
                'authority selection differs from independent material')
        product = self.context.candidate_identity
        identity = {'candidate_id': product['candidate'], 'source_commit': product['source'],
                    'package_sha256': product['zip_sha256']}
        require(self.authority.get('identity') == identity, 'authority candidate differs')
        authorities = {}
        for selected in self.selected.values():
            root = exact_path(selected['root'])
            if root not in authorities:
                authorities[root] = SourceAuthority(self.context, root)
        sources = set()
        for key, row in self.records.items():
            require(set(row) == {'target', 'source_root', 'source_path', 'size', 'sha256', 'source_seal'},
                    'authority record fields invalid')
            target = exact_path(key)
            require(row['target'] == key and target.is_relative_to(self.view), 'mapping target escape/alias')
            root, source = exact_path(row['source_root']), exact_path(row['source_path'])
            require(root in authorities and source == root / target.relative_to(self.view),
                    'mapping source root/relative position differs')
            require(source not in sources, 'source mapping not bijective')
            sources.add(source)
            authority = authorities[root]
            require(row['source_seal'] == {'root': str(root), 'index': authority.index_record['path'],
                    'sha256': authority.index_record['sha256']}, 'source certificate differs from independent pin')
            original = authority.rows.get(source.relative_to(root).as_posix())
            require(original is not None and original['size'] == row['size']
                    and original['sha256'] == row['sha256'], 'mapping differs from sealed original')
            checked_record({'path': key, 'size': row['size'], 'sha256': row['sha256']})
            checked_record({'path': str(source), 'size': row['size'], 'sha256': row['sha256']})
            require((target.stat().st_dev, target.stat().st_ino) != (source.stat().st_dev, source.stat().st_ino),
                    'audit copy shares original inode')
        original_manifest = read_json(checked_record(dict(read_json(checked_record(
            dict(self.context.materials['plan'])))['original_manifest'])))
        require(not suite.manifest_issues(original_manifest), 'original manifest contract invalid')
        canonical = checked_record(dict(read_json(checked_record(
            dict(self.context.materials['plan'])))['original_manifest'])).read_bytes()
        for authority in authorities.values():
            require(authority.read(authority.root/'scenario-manifest.json') == original_manifest
                    and (authority.root/'scenario-manifest.json').read_bytes() == canonical,
                    'selected producer canonical manifest differs')
        expected_contexts = set()
        for sid, selected in self.selected.items():
            authority = authorities[Path(selected['root'])]
            result_path = self.view / 'results' / ('scenario-' + sid + '.json')
            require(str(result_path) in self.records and self.records[str(result_path)]['source_root'] == selected['root'],
                    'selected result source mapping missing/different')
            result = authority.read(authority.root / 'results' / result_path.name)
            require(read_json(result_path) == result and result.get('scenario_id') == sid
                    and result.get('state') == 'pass' and result.get('identity') == identity
                    and result.get('scenario') == next((row for row in original_manifest['scenarios']
                        if row['scenario_id'] == sid), None), 'actual selected result candidate/contract differs')
            runs = result.get('run_chain') or []
            nonce = result.get('traffic_evidence', {}).get('nonce')
            require(type(result.get('attempt')) is int and result['attempt'] > 0
                    and isinstance(nonce, str) and re.fullmatch(re.escape(sid) + r'-a%d-[0-9a-f]{32}'
                        % result['attempt'], nonce) is not None, 'selected attempt/nonce differs')
            require(selected == {'root': str(authority.root), 'attempt': result['attempt'], 'nonce': nonce,
                    'run_ids': [row['run_id'] for row in runs]}, 'selected source/run/attempt identity differs')
            require(bool(runs) and len(selected['run_ids']) == len(set(selected['run_ids'])),
                    'selected runs empty/duplicated')
            for run in runs:
                if not run.get('auxiliary_qpc_proof'):
                    continue
                responsibility = run['auxiliary_qpc_process']['qpc-process-responsibility.json']
                native = exact_path(str(self.view / responsibility['path'])).parent
                case = native / 'auxiliary-qpc-input.json'
                export = native / 'qpc-native/export'
                key = str(case)
                expected_contexts.add(key)
                binding = self.contexts.get(key)
                role = {'scenario': sid, 'attempt': result['attempt'], 'run_label': run['label'],
                        'run_id': run['run_id'], 'nonce': nonce, 'source_root': selected['root']}
                require(binding is not None and binding.get('role') == role
                        and binding.get('export') == str(export), 'selected run context differs')
                data = read_json(case)
                require(data.get('run_id') == run['run_id'] and data.get('nonce') == nonce
                        and data.get('candidate_id') == product['candidate'], 'actual case identity differs')
                keys = [str(exact_path(str(p))) for p in v2._source_paths(case, self.view, data, export)]
                require(binding.get('keys') == keys and len(keys) == len(set(keys)),
                        'actual parser dependency keys duplicate/missing/extra')
                require(all(self.records.get(k, {}).get('source_root') == selected['root'] for k in keys),
                        'nested input missing or wrong source')
        require(set(self.contexts) == expected_contexts, 'authority missing/extra selected contexts')

    def context_for(self, case_path, root, export):
        require(exact_path(str(root)) == self.view, 'audit root differs')
        key = str(exact_path(str(case_path)))
        binding = self.contexts.get(key)
        require(binding is not None and exact_path(str(export)) == Path(binding['export']),
                'unregistered/aliased selected context')
        return binding

    def validate(self, binding):
        self.check_authority()
        require(binding in self.authority['contexts'].values(), 'selected source/run/attempt context differs')
        sid = binding['role']['scenario']
        result_key = str(self.view / 'results' / ('scenario-' + sid + '.json'))
        for key in [result_key, *binding['keys']]:
            row = self.records.get(key)
            require(row == self.authority['records'].get(key) and row is not None,
                    'mapping differs from trusted authority')
            checked_record({'path': key, 'size': row['size'], 'sha256': row['sha256']})
            source = checked_record({'path': row['source_path'], 'size': row['size'], 'sha256': row['sha256']})
            target = Path(key)
            require((target.stat().st_dev, target.stat().st_ino) != (source.stat().st_dev, source.stat().st_ino),
                    'audit copy shares original inode')

    def project(self, proof, binding):
        require(proof.get('schema') == 'sst.aux-qpc-offline.v2', 'unsupported relocation proof schema')
        self.validate(binding)
        allowed = set(binding['keys'])
        require(all(isinstance(proof.get(field), dict) and set(proof[field]) == allowed
                    for field in ('inputs_before', 'inputs_after')), 'input keys missing/extra/aliased')
        require(proof['inputs_before'] == proof['inputs_after'], 'before/after inputs inconsistent')
        projected, audit = copy.deepcopy(proof), []
        for field in ('inputs_before', 'inputs_after'):
            values = {}
            for key, value in proof[field].items():
                row = self.records[key]
                require(value == {'bytes': row['size'], 'sha256': row['sha256']},
                        'rebuilt value differs from sealed copy')
                require(row['source_path'] not in values, 'source mapping not bijective')
                values[row['source_path']] = copy.deepcopy(value)
                audit.append({'field': field, 'copy_key': key, 'source_key': row['source_path'],
                              'value_preserved': value, 'source_root': row['source_root'], 'role': binding['role']})
            projected[field] = values
        return projected, audit

    @contextmanager
    def installed(self, output):
        require(_LOCK.acquire(blocking=False), 'audit context must be serial and nonnested')
        original, oldtemp = contract.offline.derive, tempfile.tempdir
        try:
            self.check_authority()
            output = exact_path(str(output))
            require(output.is_relative_to(self.context.audit_root), 'proof output outside independent root')
            output.mkdir(parents=True, exist_ok=False)
            temporary = output / 'temporary'
            temporary.mkdir()
            tempfile.tempdir = str(temporary)
            sys.addaudithook(self.guard)
            self.guard.active = True

            def derive(case_path, root, export, destination, **kwargs):
                binding = self.context_for(case_path, root, export)
                self.validate(binding)
                destination = exact_path(str(destination))
                require(destination.is_relative_to(self.context.audit_root), 'derive destination outside independent output')
                try:
                    self.guard.deriving = True
                    raw = original(case_path, root, export, destination, **kwargs)
                finally:
                    self.guard.deriving = False
                projected, mapping = self.project(raw, binding)
                self.count += 1
                save(output / ('%04d-proof.json' % self.count), {
                    'authority_sha256': self.sha256, 'context': binding, 'raw_derived': raw,
                    'projected_derived': projected, 'mapping_audit': mapping,
                    'only_fields': ['inputs_before.keys', 'inputs_after.keys'],
                    'original_compare_not_replaced': True})
                return projected

            contract.offline.derive = derive
            yield self
        finally:
            self.guard.active = self.guard.deriving = False
            contract.offline.derive = original
            tempfile.tempdir = oldtemp
            _LOCK.release()
