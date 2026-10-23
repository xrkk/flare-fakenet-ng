"""Read-only original independent ACC014 acceptance references.

A local mapping only locates facts already in immutable originals. It never
supplies a verdict or reviewer identity and never rewrites a closed report.
"""
from __future__ import annotations
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace

SCHEMA = 'fakenet.mcp-capability-reference.v1'
FILES = {'task', 'receive_config', 'result', 'receipt', 'report', 'acceptance'}
FIELDS = {'capability', 'verdict', 'evidence_level', 'reviewer', 'controller',
          'implementers', 'identity', 'target', 'config_identity', 'manifest_sha256',
          'dependencies', 'fault_records', 'localization', 'accepted_verdict',
          'accepted_result_sha256', 'accepting_controller', 'report_path', 'report_sha256'}
PASS = {'pass', '通过', '验收通过', '核验通过'}
SEEDS = ('supervisor', 'managed', 'incident', 'incident_task', 'managed_stacks',
         'dumpworker', 'exit_native', 'exit_monitor', 'exit_retention',
         'baseline', 'snapshot', 'coordination', 'service_stop', 'faultinject')


class CapabilityUnavailable(ValueError):
    pass


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_file(reference, limit=64 * 1024 * 1024):
    if not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}:
        raise CapabilityUnavailable('original file reference fields differ')
    if (not isinstance(reference['path'], str) or not reference['path'] or
            not isinstance(reference['sha256'], str) or
            re.fullmatch(r'[0-9a-f]{64}', reference['sha256']) is None):
        raise CapabilityUnavailable('invalid original file identity')
    path = Path(reference['path'])
    if (not path.is_absolute() or path != path.resolve() or path.is_symlink() or
            not path.is_file() or path.stat().st_size > limit):
        raise CapabilityUnavailable('original file missing, linked or outside bound')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise CapabilityUnavailable('original file bytes changed')
    return path, raw


def data(raw):
    text = raw.decode('utf-8-sig')
    try:
        value = json.loads(text)
    except ValueError:
        blocks = re.findall(r'^```json\s*\n(.*?)^```\s*$', text, re.M | re.S)
        if len(blocks) != 1:
            raise CapabilityUnavailable('original must have one unambiguous JSON object')
        try:
            value = json.loads(blocks[0])
        except ValueError as exc:
            raise CapabilityUnavailable('invalid original JSON block') from exc
    if not isinstance(value, dict):
        raise CapabilityUnavailable('original structured facts are not an object')
    return value


def select(document, pointer):
    if not isinstance(pointer, str) or (pointer and not pointer.startswith('/')):
        raise CapabilityUnavailable('invalid original JSON pointer')
    value = document
    for token in pointer.split('/')[1:] if pointer else ():
        token = token.replace('~1', '/').replace('~0', '~')
        try:
            if isinstance(value, list):
                if re.fullmatch(r'0|[1-9][0-9]*', token) is None:
                    raise ValueError('invalid array index')
                value = value[int(token)]
            elif isinstance(value, dict):
                value = value[token]
            else:
                raise TypeError('pointer crosses scalar')
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise CapabilityUnavailable('original JSON pointer unavailable') from exc
    return copy.deepcopy(value)


def source_pins(root):
    """Fixed product dependency closure; doc/test HEAD changes are irrelevant."""
    root = Path(root)
    pending = ['fakenet/mcp/' + name + '.py' for name in SEEDS]
    pending += ['fakenet/fakenet.py']
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        path = root / name
        if not path.is_file():
            raise CapabilityUnavailable('required product dependency unavailable: ' + name)
        seen.add(name)
        tree = ast.parse(path.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                if node.level:
                    parent = name.split('/')[:-1]
                    base = '.'.join(parent[:len(parent)-node.level+1])
                    module = base + ('.' + module if module else '')
                if module:
                    modules = [module] + [module + '.' + item.name for item in node.names]
            for module in modules:
                if not module.startswith('fakenet.'):
                    continue
                relative = module.replace('.', '/') + '.py'
                if (root / relative).is_file() and relative not in seen:
                    pending.append(relative)
    return {name: digest(root / name) for name in sorted(seen)}


def load(reference, inputs, root, fixture=False):
    if (not isinstance(reference, dict) or set(reference) != {'schema', 'files', 'mapping'} or
            reference['schema'] != SCHEMA or not isinstance(reference['files'], dict) or
            set(reference['files']) != FILES or not isinstance(reference['mapping'], dict) or
            set(reference['mapping']) != FIELDS):
        raise CapabilityUnavailable('complete original capability reference required')
    originals = {}
    facts = {}
    paths = {}
    for name in sorted(FILES):
        path, raw = checked_file(reference['files'][name])
        paths[name] = path
        originals[name] = raw
    # The task can be an immutable plain-text task; its hash is bound by the
    # original receive configuration. Other structured facts are explicit.
    for name in FILES - {'task'}:
        facts[name] = data(originals[name])
    mapped = {}
    for name, location in reference['mapping'].items():
        if (not isinstance(location, dict) or set(location) != {'file', 'pointer'} or
                not isinstance(location['file'], str) or location['file'] not in FILES - {'task'}):
            raise CapabilityUnavailable('mapping may only select existing structured original facts')
        expected = ('acceptance' if name in ('accepted_verdict', 'accepted_result_sha256', 'accepting_controller')
                    else 'result' if name in ('reviewer', 'controller', 'report_path', 'report_sha256') else 'report')
        if location['file'] != expected:
            raise CapabilityUnavailable('capability fact selected from wrong original: ' + name)
        mapped[name] = select(facts[location['file']], location['pointer'])
    cfg, result, receipt = (facts[name] for name in ('receive_config', 'result', 'receipt'))
    event = cfg.get('event')
    if (not isinstance(event, dict) or not event.get('RUN_ID') or not event.get('TYPE') or
            not any(key.endswith('_ID') and key != 'RUN_ID' for key in event)):
        raise CapabilityUnavailable('original event identity unavailable')
    if any(result.get(key) != value or receipt.get(key) != value for key, value in event.items()):
        raise CapabilityUnavailable('original close/receive event differs')
    if (cfg.get('task') != str(paths['task']) or cfg.get('task_sha256') != reference['files']['task']['sha256'] or
            cfg.get('result') != str(paths['result']) or receipt.get('result_path') != str(paths['result']) or
            receipt.get('result_sha256') != reference['files']['result']['sha256'] or
            receipt.get('STATUS') != 'RECEIVED' or result.get('STATUS') != 'COMPLETED' or
            result.get('WORK_STOPPED') is not True):
        raise CapabilityUnavailable('original task/result close and matching receive not established')
    reviewer, controller = mapped['reviewer'], mapped['controller']
    implementers = mapped['implementers']
    if (not isinstance(reviewer, str) or not reviewer or not isinstance(controller, str) or not controller or
            reviewer == controller or not isinstance(implementers, list) or controller not in implementers or
            any(not isinstance(actor, str) or not actor for actor in implementers) or reviewer in implementers or
            result.get('native_session') != reviewer or result.get('controller_native') != controller or
            receipt.get('receiver_session') != controller):
        raise CapabilityUnavailable('original reviewer independence or native identity not established')
    if (mapped['capability'] != 'ACC-014' or not isinstance(mapped['verdict'], str) or mapped['verdict'] not in PASS or
            not isinstance(mapped['accepted_verdict'], str) or mapped['accepted_verdict'] not in PASS or
            mapped['accepted_result_sha256'] != reference['files']['result']['sha256'] or mapped['accepting_controller'] != controller):
        raise CapabilityUnavailable('no accepted independent product ACC014 conclusion')
    if mapped['evidence_level'] != ('fixture' if fixture else 'native'):
        raise CapabilityUnavailable('fixture or non-native source cannot grant native capability')
    if (mapped['report_path'] != str(paths['report']) or
            mapped['report_sha256'] != reference['files']['report']['sha256']):
        raise CapabilityUnavailable('original capability report reference differs')
    for key in ('identity', 'target', 'config_identity', 'manifest_sha256'):
        if mapped[key] != inputs[key]:
            raise CapabilityUnavailable('capability identity no longer applicable: ' + key)
    if mapped['dependencies'] != source_pins(root):
        raise CapabilityUnavailable('capability product dependencies changed or unknown')
    if not isinstance(mapped['fault_records'],list) or not 1 <= len(mapped['fault_records']) <= 128:raise CapabilityUnavailable('bounded original fault records required')
    records = []
    for item in mapped['fault_records']:
        path, raw = checked_file(item)
        records.append((path, data(raw)))
    local_path, local_raw = checked_file(mapped['localization'])
    data(local_raw)
    if not records:
        raise CapabilityUnavailable('original fault records absent')
    return {'facts': mapped, 'records': records, 'localization': local_path,
            'reference': reference, 'original_event': event}


class OriginalArchiveChannel:
    """Fixed export boundary over accepted immutable original ZIP bytes."""
    def __init__(self, records):
        self.archives = {}
        self.selected = None
        for path, record in records:
            run_id = record['fault_evidence']['receipt']['run_id']
            for item in record['incident_exports']:
                archive, raw = checked_file({'path': item['path'], 'sha256': item['sha256']}, 512 * 1024 * 1024)
                key = (run_id, item['incident_name'])
                if key in self.archives:
                    raise CapabilityUnavailable('duplicate original run/incident package')
                self.archives[key] = raw
    def powershell(self, command, timeout=120):
        import io
        import zipfile
        if 'Compress-Archive' in command:
            match = re.search(r"artifacts\\([0-9a-f-]{36})\\(incident(?:-[0-9]{2,})?)'", command)
            if not match or match.groups() not in self.archives:
                raise CapabilityUnavailable('requested original run/incident missing')
            self.selected = self.archives[match.groups()]
            with zipfile.ZipFile(io.BytesIO(self.selected)) as archive:
                if len(archive.infolist()) > 4096 or sum(info.file_size for info in archive.infolist()) > 512*1024*1024:raise CapabilityUnavailable('original incident expansion exceeds bound')
                manifest = archive.read('manifest.json')
            output = json.dumps({'size': len(self.selected), 'sha256': hashlib.sha256(self.selected).hexdigest(),
                                 'manifest_sha256': hashlib.sha256(manifest).hexdigest()})
        elif '[IO.File]::OpenRead(' in command and self.selected is not None:
            offset = int(re.search(r'\.Seek\((\d+),', command).group(1))
            count = int(re.search(r'byte\[\] (\d+)', command).group(1))
            output = base64.b64encode(self.selected[offset:offset+count]).decode('ascii')
        else:
            raise CapabilityUnavailable('unknown original archive export operation')
        return {'output': output, 'raw': output, 'exit_code': 0, 'is_error': False}


def evaluate(reference, inputs, root, writer, fixture=False):
    import acceptance_mcp as m
    accepted = load(reference, inputs, root, fixture=fixture)
    args = SimpleNamespace(**inputs['identity'],
        fault_record=[str(path) for path, record in accepted['records']],
        localization_record=str(accepted['localization']))
    writer.add_evidence('original-capability-reference', reference)
    writer.add_evidence('original-capability-event', accepted['original_event'])
    import zipfile
    try:
        return m.modules(root)['run_p04_acc'].run_acc014('', OriginalArchiveChannel(accepted['records']), writer, args)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, IndexError) as exc:
        raise CapabilityUnavailable('original incident bytes cannot be rejudged: ' + str(exc)) from exc
