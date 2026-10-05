"""Read indexed producer witnesses and classify the original transfer budgets.

Historical guest identity comes from the original frozen execution and actual
capture command/response, never from the new consumer's output directory.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from types import MappingProxyType

from .context import RunContext, checked_record, exact_path, file_sha256, read_json, _freeze


NAMESPACE = re.compile(r'^E:\\FakeNet-NG-MCP-test-work\\clean-r\d+-\d{8}\\(?P<nonce>[0-9a-f]{32})\\(?P<scope>[0-9a-f]{12})$')


class SourceError(ValueError):
    """The exact source or physical producer cannot be established."""


def require(condition, reason):
    if not condition:
        raise SourceError(reason)


def parts(path):
    return tuple(part.casefold() for part in PureWindowsPath(path).parts)


class SourceAuthority:
    def __init__(self, context: RunContext, source: Path):
        self.context = context.revalidate()
        self.root = exact_path(str(source))
        protected = [exact_path(path) for path in context.materials['protected_sources']]
        require(self.root.is_dir() and self.root.is_relative_to(context.repository_root / 'Logs')
                and any(self.root == path or self.root.is_relative_to(path) for path in protected),
                'source root must be explicitly protected repository Logs')
        matches = [dict(row) for row in context.materials['source_indices']
                   if Path(row['path']).parent == self.root]
        require(len(matches) == 1, 'source lacks unique independently pinned index')
        self.index_record = matches[0]
        index = read_json(checked_record(self.index_record))
        require(isinstance(index, dict) and isinstance(index.get('rows'), list), 'source index rows missing')
        rows = {}
        for row in index['rows']:
            require(isinstance(row, dict) and isinstance(row.get('path'), str), 'invalid source row')
            relative = PurePosixPath(row['path'])
            require(relative.as_posix() == row['path'] and not relative.is_absolute()
                    and '..' not in relative.parts and '\\' not in row['path'], 'source row escape/alias')
            require(row['path'] not in rows, 'duplicate source index name')
            rows[row['path']] = _freeze(row)
        self.rows = MappingProxyType(rows)
        self.witnesses = []

    def read(self, path: Path):
        path = exact_path(str(path))
        require(path.is_relative_to(self.root), 'source reference escape')
        relative = path.relative_to(self.root).as_posix()
        row = self.rows.get(relative)
        require(row is not None, 'source witness missing/unindexed: ' + relative)
        record = {'path': str(path), 'size': row.get('size'), 'sha256': row.get('sha256')}
        checked_record(record)
        self.witnesses.append(record)
        return read_json(path)

    def frozen_dependency(self, path: Path, sha256: str):
        path = exact_path(str(path))
        require(path.is_relative_to(self.context.repository_root / 'Logs'), 'frozen dependency outside repository Logs')
        record = {'path': str(path), 'size': path.stat().st_size, 'sha256': sha256}
        checked_record(record)
        self.witnesses.append(record)
        return read_json(path)


@dataclass(frozen=True)
class SourceBinding:
    values: object

    @property
    def physical_namespace(self):
        return self.values['physical_namespace']

    @property
    def owner_roots(self):
        return frozenset(parts(PureWindowsPath(row['run']).parent)
                         for row in self.values['captures'] if row['run_label'] == 'run-01')


def resolve_source(context: RunContext, source: Path) -> SourceBinding:
    authority = SourceAuthority(context, source)
    root = authority.root
    declared = None
    if (root / 'exact-argv.json').exists():
        argv = authority.read(root / 'exact-argv.json')
        command = argv.get('driver')
        require(isinstance(command, list) and all(isinstance(item, str) for item in command)
                and '--execute' in command and command.count('--root') == 1
                and command.count('--inputs-sha256') == 1 and len(command) > 2, 'unknown source execution')
        original = exact_path(command[command.index('--root') + 1])
        driver = exact_path(command[2])
        frozen = driver.parent / 'frozen-inputs.json'
        frozen_sha = command[command.index('--inputs-sha256') + 1]
        require(driver.name == 'spike_driver.py', 'unknown source driver')
    else:
        declared = authority.read(root / 'guest-namespace-binding.json')
        require(declared.get('schema') == 'source-namespace-binding.v1', 'unknown formal source declaration')
        original = exact_path(declared['original_execution_root'])
        driver = exact_path(declared['driver'])
        frozen = driver.parent / 'frozen-plan2.json'
        frozen_sha = declared['frozen_inputs_sha256']
        require(driver.name == 'formal_adapter.py', 'unknown formal source driver')
    require(original.is_relative_to(context.repository_root / 'Logs'), 'original execution outside repository Logs')
    freeze = authority.frozen_dependency(frozen, frozen_sha)
    require(freeze.get('identity') == dict(context.candidate_identity), 'source candidate identity conflict')
    if declared is not None:
        require(freeze.get('root') == str(original)
                and freeze.get('physical_namespace') == declared['physical_namespace'], 'formal plan root/namespace conflict')
    else:
        require(argv.get('identity') == freeze['identity'], 'source argv candidate conflict')
    start = driver.parent / 'start.json'
    dependencies = freeze.get('dependencies')
    require(isinstance(dependencies, dict), 'source frozen dependencies missing')
    for dependency in (start, driver):
        relative = dependency.relative_to(context.repository_root).as_posix()
        sha256 = dependencies.get(relative)
        require(isinstance(sha256, str), 'source driver/nonce not frozen')
        # The historical driver is fingerprinted data, never imported or run.
        if dependency == driver:
            checked_record({'path': str(dependency), 'size': dependency.stat().st_size, 'sha256': sha256})
            authority.witnesses.append({'path': str(dependency), 'size': dependency.stat().st_size, 'sha256': sha256})
        else:
            start_value = authority.frozen_dependency(dependency, sha256)
    if declared is not None:
        checked_record(declared['nonce_file'])
        require(declared['nonce_file']['path'] == str(start)
                and declared['nonce_file']['sha256'] == dependencies[start.relative_to(context.repository_root).as_posix()],
                'source nonce witness conflict')
    nonce = start_value.get('nonce')
    require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce), 'source nonce invalid')
    namespaces, captures = set(), []
    for relative in sorted(authority.rows):
        path = PurePosixPath(relative)
        if len(path.parts) != 3 or path.parts[0] != 'file-transport' or path.name != 'execution-original.json':
            continue
        response = authority.read(root / relative)
        try:
            value = json.loads(response['output'])
        except (KeyError, TypeError, ValueError):
            continue
        if not isinstance(value, dict) or not all(value.get(key) for key in ('guest', 'etl', 'probe')):
            continue
        intent = authority.read((root / relative).with_name('intent.json'))
        command = intent.get('original_command')
        run = value['guest']
        require(isinstance(run, str) and isinstance(command, str), 'capture request/response type invalid')
        namespace = run.split('\\scenario-suite-20260912\\')[0]
        match = NAMESPACE.fullmatch(namespace)
        require(match is not None and match['nonce'] == nonce
                and match['scope'] == hashlib.sha256(str(original).encode()).hexdigest()[:12]
                and '..' not in PureWindowsPath(run).parts, 'source capture nonce/scope/path conflict')
        label = value.get('run_label')
        require(label in ('run-01', 'run-02') and PureWindowsPath(run).name == label
                and len(parts(run)) == len(parts(namespace)) + 3, 'capture producer path/label invalid')
        etl = run + r'\pktmon.etl'
        if value.get('shared_physical'):
            require(label == 'run-02' and value.get('nonce')
                    and value.get('physical_owner_id') == value['nonce'] + ':pktmon'
                    and value['physical_owner_id'] in command, 'shared source capture owner mismatch')
            etl = str(PureWindowsPath(run).parent / 'run-01' / 'pktmon.etl')
        require(value['etl'] == etl and value['probe'] == run + r'\probe.jsonl'
                and namespace in command, 'source capture request/response mismatch')
        require(type(value.get('pid')) is int and value['pid'] > 0
                and type(value.get('probe_creation_ticks')) is int and value['probe_creation_ticks'] > 0,
                'source probe ownership missing')
        namespaces.add(namespace)
        captures.append({'run': run, 'pid': value['pid'], 'creation_ticks': value['probe_creation_ticks'],
                         'run_label': label, 'response': str(root / relative),
                         'required': [etl, value['probe'], value['pktmon_nic']],
                         'optional': [value[key] for key in ('stdout', 'stderr', 'start', 'case', 'stop', 'exit_control')
                                      if value.get(key)]})
    require(len(namespaces) == 1 and captures, 'missing or ambiguous actual source namespace')
    physical = namespaces.pop()
    for capture in captures:
        if capture['required'][0] != capture['run'] + r'\pktmon.etl':
            require(any(owner['run_label'] == 'run-01' and owner['required'][0] == capture['required'][0]
                        for owner in captures), 'shared source has no actual owner response')
    if declared is None and (root / 'guest-namespace-binding.json').exists():
        declared = authority.read(root / 'guest-namespace-binding.json')
    if declared is not None:
        require(declared.get('schema') == 'source-namespace-binding.v1'
                and declared.get('physical_namespace') == physical
                and declared.get('original_execution_root') == str(original), 'persisted binding conflicts with actual witness')
    kernels = []
    for relative in sorted(authority.rows):
        path = PurePosixPath(relative)
        if len(path.parts) != 2 or path.parts[0] != 'VM-final-intents' or path.suffix != '.json':
            continue
        command = authority.read(root / relative).get('command')
        if not isinstance(command, str) or 'logman start $s -ets' not in command:
            continue
        session = re.search(r"\$s='(SST-Kernel-[a-f0-9-]+)'", command)
        run = re.search(r"\$r='([^']+)'", command)
        require(session and run and run[1].startswith(physical + '\\scenario-suite-20260912\\')
                and '..' not in PureWindowsPath(run[1]).parts, 'owned ETW intent identity/root invalid')
        kernels.append({'name': session[1], 'run': run[1], 'metadata': run[1] + r'\kernel-network.metadata.json',
                        'etl': run[1] + r'\kernel-network.etl',
                        'optional': [run[1] + r'\kernel-network' + suffix
                                     for suffix in ('.events.jsonl', '.header.xml', '.summary.txt')]})
    require(kernels and len({row['name'] for row in kernels}) == len(kernels), 'capture/ETW ownership incomplete or duplicate')
    execution = authority.read(root / 'execution-context.json')
    required = {path for capture in captures for path in capture['required']}
    required.update(path for kernel in kernels for path in (kernel['metadata'], kernel['etl']))
    optional = {path for capture in captures for path in capture['optional']}
    optional.update(path for kernel in kernels for path in kernel['optional'])
    for name in execution['backup_names']:
        require(isinstance(name, str) and name and not any(token in name for token in ('/', '\\', '..')),
                'backup name escape')
        required.add(physical + '\\scenario-suite-20260912\\' + name)
    for relative in sorted(authority.rows):
        if '/' not in relative and relative.startswith('cycle-') and relative.endswith('-intent.json'):
            receipt = authority.read(root / relative)['receipt']
            logical = r'E:\FakeNet-NG-MCP-test-work'
            if receipt.startswith(logical + '\\scenario-suite-20260912\\'):
                receipt = physical + receipt[len(logical):]
            require(receipt.startswith(physical + '\\scenario-suite-20260912\\')
                    and '..' not in PureWindowsPath(receipt).parts, 'receipt cross-source path')
            required.add(receipt)
    return SourceBinding(_freeze({
        'schema': 'source-namespace-binding.v1', 'identity': freeze['identity'],
        'source_evidence_root': str(root), 'original_execution_root': str(original),
        'original_driver': str(driver), 'physical_namespace': physical, 'source_nonce': nonce,
        'captures': captures, 'kernels': kernels, 'required_files': sorted(required),
        'optional_files': sorted(optional - required), 'witnesses': authority.witnesses,
        'source_index': authority.index_record, 'derived_from_actual_immutable_source': True,
        'original_response_unchanged': True}))


def shared_source(binding: SourceBinding, guest_path: str) -> bool:
    guest = PureWindowsPath(guest_path)
    require(guest.is_absolute() and '..' not in guest.parts, 'bound source path invalid')
    path, namespace = parts(guest), parts(binding.physical_namespace)
    if 'clean-r' in str(guest).casefold() and path[:len(namespace)] != namespace:
        raise SourceError('bound source cross-namespace')
    if path[:len(namespace)] == namespace and path[-2:] == ('run-01', 'pktmon.txt'):
        require(len(path) == len(namespace) + 4 and path[len(namespace)] == 'scenario-suite-20260912'
                and parts(guest.parent.parent) in binding.owner_roots, 'shared source producer ownership differs')
        return True
    return False


def transfer_limit(instance, guest_path: str, destination: Path, *, auxiliary_v2_output=False) -> int:
    # Import the original constants rather than introducing wider budgets.
    from scenario_suite import MAX_GUEST_TRANSFER, MAX_SHARED_PKTMON_TEXT_TRANSFER, MAX_AUX_V2_ZIP_TRANSFER
    binding = getattr(instance, 'physical_source_binding', None)
    require(binding is None or isinstance(binding, SourceBinding), 'verified physical source binding required')
    guest, root = parts(guest_path), parts(instance.guest_work_root)
    shared = (shared_source(binding, guest_path) if binding is not None else
              guest[:len(root)] == root and len(guest) == len(root) + 4
              and guest[len(root)] == 'scenario-suite-20260912' and guest[-2:] == ('run-01', 'pktmon.txt'))
    shared = (shared and instance.capture_contract == 'scenario-shared-v2'
              and destination.name == 'pktmon.txt' and destination.parent.name == 'run-01')
    native = (auxiliary_v2_output and guest[:len(root)] == root and len(guest) == len(root) + 2
              and guest[len(root)].startswith('qpc-contract-') and guest[-1] == 'output.zip'
              and destination.name == 'qpc-output.zip' and destination.parent.name == 'auxiliary-qpc')
    require(not auxiliary_v2_output or native, 'auxiliary v2 output transfer scope differs')
    return MAX_AUX_V2_ZIP_TRANSFER if native else MAX_SHARED_PKTMON_TEXT_TRANSFER if shared else MAX_GUEST_TRANSFER


def export_destination(binding: SourceBinding, destination: Path, index: int, guest_path: str) -> Path:
    path = destination / 'guest-originals' / ('%05d' % index)
    if shared_source(binding, guest_path):
        path /= 'run-01'
    return path / PureWindowsPath(guest_path).name
