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
import uuid

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


class ReadOnlySourceVm:
    """Only the tool's bounded source-read commands; no remote staging fallback."""

    def __init__(self, client, context: RunContext, binding: SourceBinding, root: Path):
        self.client, self.context, self.binding = client, context, binding
        self.root = exact_path(str(root))
        require(self.root.is_relative_to(context.evidence_root), 'read-only evidence outside explicit output')
        require(dict(binding.values['identity']) == dict(context.candidate_identity), 'read-only source candidate differs')

    def powershell(self, command, timeout=30):
        self.context.revalidate()
        from .command_transport import LIMIT, map_command, wire_units, write_new_json
        require(type(timeout) is int and timeout > 0, 'read-only timeout invalid')
        require(not re.search(r'(?i)WriteAll|Set-Content|Out-File|Export-Clixml|Invoke-CimMethod|'
                              r'Start-Service|Stop-Service|(?:New|Remove|Set|Move)-Item|'
                              r'(?:pktmon|logman)\s+(?:start|stop)|Stop-Process| -Action (?!identity)', command),
                'read-only source adapter refuses guest mutation/staging')
        logical = r'E:\FakeNet-NG-MCP-test-work\scenario-suite-20260912'
        physical = self.binding.physical_namespace + r'\scenario-suite-20260912'
        command = map_command(command, ((logical, physical),))
        require(wire_units(command) <= LIMIT, 'read-only command exceeds wire bound; split locally, never guest stage')
        for namespace in re.findall(r'E:\\FakeNet-NG-MCP-test-work\\clean-r\d+-\d{8}\\[a-f0-9]{32}\\[a-f0-9]{12}', command):
            require(namespace == self.binding.physical_namespace, 'command cross-source namespace')
        directory = self.root / 'readonly-final-intents'
        directory.mkdir(parents=True, exist_ok=True)
        write_new_json(directory / (uuid.uuid4().hex + '.json'), {
            'command': command, 'timeout': min(timeout, 30), 'physical_namespace': self.binding.physical_namespace,
            'guest_writes': 0, 'no_staging': True})
        return self.client.powershell(command, min(timeout, 30))


def source_capture_gate(instance, binding: SourceBinding, destination: Path):
    from scenario_suite import Suite, quote_ps
    from .command_transport import write_new_json
    names = sorted({kernel['name'] for kernel in binding.values['kernels']})
    ids = sorted({capture['pid'] for capture in binding.values['captures']})
    command = (
        "$ErrorActionPreference='Stop';$sessions=@();foreach($n in @(" + ','.join(quote_ps(name) for name in names) +
        ")){$q=(& logman query $n -ets 2>&1|Out-String);$sessions+=@{name=$n;exit=$LASTEXITCODE;query=$q}};"
        "$probe=@();foreach($id in @(" + ','.join(str(pid) for pid in ids) +
        ")){$p=Get-Process -Id $id -ErrorAction SilentlyContinue;if($p){$probe+=@{pid=$p.Id;"
        "creation_ticks=[string]$p.StartTime.ToUniversalTime().Ticks}}};"
        "$children=@(Get-CimInstance Win32_Process|Where-Object{$_.ParentProcessId -in @(" +
        ','.join(str(pid) for pid in ids) + ")}|Select-Object ProcessId,ParentProcessId,CreationDate);"
        "@{sessions=$sessions;probe=$probe;children=$children;pktmon=(& pktmon status|Out-String)}"
        "|ConvertTo-Json -Depth 6 -Compress")
    raw = instance.vm.powershell(command, 30)
    write_new_json(destination / 'source-capture-gate-original.json', raw)
    value = json.loads(raw['output'])
    require({row['name'] for row in value['sessions']} == set(names) and len(value['sessions']) == len(names)
            and not value['probe'] and not value['children'] and Suite._pktmon_stopped(value['pktmon'])
            and all(row['exit'] == -2144337918 and 'Data Collector Set was not found.' in row['query']
                    for row in value['sessions']), 'source owned capture/ETW active or UNKNOWN; export withheld')
    return value


def export_source(instance, context: RunContext, source_root: Path, destination: Path):
    """Export a stable, bounded inventory via the original Suite transfer method.

Writers must have stopped, all required capture/backup/receipt bytes must exist,
and both complete inventories must agree. Unknown calls are never retried.
"""
    from scenario_suite import MAX_GUEST_TRANSFER, quote_ps
    from .command_transport import write_new_json
    authority = SourceAuthority(context, source_root)
    binding = resolve_source(context, authority.root)
    destination = exact_path(str(destination))
    require(destination.is_relative_to(context.evidence_root) and destination != context.evidence_root,
            'source export must use a distinct child of the explicit output')
    require(not destination.exists(), 'source export output exists; never retry')
    require(exact_path(str(instance.root)) == context.evidence_root and instance.vm is not None,
            'source export Suite/client differs from explicit output context')
    destination.mkdir(parents=True, exist_ok=False)
    original_vm = instance.vm
    sentinel = object()
    original_binding = getattr(instance, 'physical_source_binding', sentinel)
    instance.vm = ReadOnlySourceVm(original_vm, context, binding, destination)
    instance.physical_source_binding = binding
    terminal = {'passed': False, 'guest_writes': 0, 'deletions': 0, 'no_replay': True}

    def read(relative):
        return authority.read(authority.root / relative)

    def invoke(label, command):
        raw = instance.vm.powershell(command, 30)
        write_new_json(destination / (label + '-original.json'), raw)
        return json.loads(raw['output'])

    try:
        source_capture_gate(instance, binding, destination)
        namespace = binding.physical_namespace
        required, optional = set(binding.values['required_files']), set(binding.values['optional_files'])
        runs, supervisors = set(), []

        def add_run(value):
            try:
                runs.add(str(uuid.UUID(str(value))))
            except (ValueError, TypeError, AttributeError):
                pass  # Only actual UUID identities add native export authority.

        for relative in sorted(authority.rows):
            path = PurePosixPath(relative)
            if path.name == 'result.json' and 'instance-gates' in path.parts:
                value = read(relative)
                add_run(value.get('admission_run')); add_run(value.get('native_run'))
            elif path.name == 'six-native-verdict.json':
                add_run(read(relative).get('run_id'))
            elif path.name == 'new-instance-identity.json':
                value = read(relative)
                require(type(value.get('pid')) is int and value['pid'] > 0
                        and re.fullmatch(r'[0-9]+', str(value.get('filetime', ''))), 'supervisor source identity invalid')
                supervisors.append(value)
            elif len(path.parts) == 2 and path.parts[0] == 'results' and path.name.startswith('scenario-'):
                for value in read(relative).get('run_chain', []):
                    add_run(value.get('run_id'))
            elif path.name == 'request.json' and 'transport-product' in path.parts:
                response = str(path.with_name('response.json'))
                if response not in authority.rows:
                    continue
                value = read(relative)['body'].get('params', {})
                if value.get('name') not in ('start', 'restart'):
                    continue
                for content in read(response)['value'].get('result', {}).get('content', []):
                    if content.get('type') == 'text':
                        try:
                            add_run(json.loads(content['text']).get('run_id'))
                        except ValueError:
                            pass
        ids = set(runs)
        for offset in range(0, len(supervisors), 4):
            data = json.dumps(supervisors[offset:offset + 4], separators=(',', ':'))
            command = (
                "$ErrorActionPreference='Stop';$sup=ConvertFrom-Json " + quote_ps(data) +
                ";$ids=@();foreach($d in @(Get-ChildItem 'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\exit-evidence' -Directory)){"
                "if(Test-Path (Join-Path $d.FullName 'capability.json')){$e=Get-Content (Join-Path $d.FullName 'entry.json') -Raw|ConvertFrom-Json;"
                "foreach($v in $sup){if($e.target.supervisor_pid -eq $v.pid -and "
                "[string]$e.target.supervisor_creation_time -ceq [string]$v.filetime){$ids+=@($d.Name)}}}};"
                "@{ids=@($ids|Sort-Object -Unique)}|ConvertTo-Json -Compress")
            for value in invoke('lineage-%d' % offset, command)['ids']:
                require(str(uuid.UUID(value)) == value, 'native lineage UUID invalid')
                ids.add(value)
        logical = r'E:\FakeNet-NG-MCP-test-work'
        for relative in sorted(authority.rows):
            path = PurePosixPath(relative)
            if path.name == 'p5-probe-stage.json':
                extra = [read(relative)['path']]
            elif path.name == 'p7-probe-wire.json':
                probe = read(relative).get('probe') or {}
                extra = [probe[key] for key in ('stdout_path', 'stderr_path') if probe.get(key)]
            else:
                continue
            for value in extra:
                if value.startswith(logical + '\\scenario-suite-20260912\\'):
                    value = namespace + value[len(logical):]
                require(value.startswith(namespace + '\\') and '..' not in PureWindowsPath(value).parts,
                        'probe cross-source reference')
                required.add(value)
        roots = [namespace] + [r'C:\ProgramData\FakeNet-NG-MCP' + '\\' + base + '\\' + rid
                               for rid in sorted(ids) for base in ('artifacts', r'artifacts\runs', r'logs\exit-evidence')]

        def check_file(value, audit=False):
            require(isinstance(value, dict) and set(value) == {'path', 'size', 'sha256'}, 'inventory file fields invalid')
            path = value['path']
            require(isinstance(path, str) and PureWindowsPath(path).is_absolute() and '..' not in PureWindowsPath(path).parts,
                    'inventory source path invalid')
            if audit:
                require(PureWindowsPath(path).parent == PureWindowsPath(r'C:\ProgramData\FakeNet-NG-MCP\logs')
                        and any(PureWindowsPath(path).name.startswith('recovery-audit-' + rid + '-') for rid in ids),
                        'inventory unowned recovery audit')
                limit = MAX_GUEST_TRANSFER
            else:
                require(any(path.startswith(root + '\\') for root in roots), 'inventory cross-source/unowned path')
                limit = transfer_limit(instance, path, export_destination(binding, destination, 0, path))
            require(type(value['size']) is int and 0 <= value['size'] <= limit
                    and isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256']),
                    'source inventory outside original transfer bound/SHA')

        def inventory(label):
            files, missing = {}, []
            for offset in range(0, len(roots), 12):
                command = (
                    "$ErrorActionPreference='Stop';$paths=@();$missing=@();foreach($root in @(" +
                    ','.join(quote_ps(root) for root in roots[offset:offset + 12]) +
                    ")){if(Test-Path -LiteralPath $root){$paths+=@(Get-ChildItem -LiteralPath $root -File -Recurse"
                    "|Select-Object -ExpandProperty FullName)}else{$missing+=@($root)}};"
                    "$files=@();foreach($p in @($paths|Sort-Object -Unique)){$f=Get-Item -LiteralPath $p;"
                    "$h=(Get-FileHash -LiteralPath $p).Hash.ToLower();$h2=(Get-FileHash -LiteralPath $p).Hash.ToLower();"
                    "if($h -cne $h2 -or $f.Length -ne (Get-Item -LiteralPath $p).Length){throw 'source original unstable'};"
                    "$files+=@{path=$p;size=$f.Length;sha256=$h}};@{files=$files;missing=$missing}|ConvertTo-Json -Depth 5 -Compress")
                value = invoke(label + '-%d' % offset, command)
                missing.extend(value['missing'])
                for file in value['files']:
                    check_file(file)
                    require(file['path'] not in files or files[file['path']] == file, 'duplicate source inventory conflict')
                    files[file['path']] = file
            for offset in range(0, len(ids), 12):
                command = (
                    "$ErrorActionPreference='Stop';$files=@();foreach($id in @(" +
                    ','.join(quote_ps(rid) for rid in sorted(ids)[offset:offset + 12]) +
                    ")){foreach($f in @(Get-ChildItem 'C:\\ProgramData\\FakeNet-NG-MCP\\logs' -File -Filter "
                    "('recovery-audit-'+$id+'-*'))){$h=(Get-FileHash $f.FullName).Hash.ToLower();"
                    "if($h -cne (Get-FileHash $f.FullName).Hash.ToLower()){throw 'audit unstable'};"
                    "$files+=@{path=$f.FullName;size=$f.Length;sha256=$h}}};@{files=$files}|ConvertTo-Json -Depth 5 -Compress")
                for file in invoke(label + '-audit-%d' % offset, command)['files']:
                    check_file(file, audit=True)
                    require(file['path'] not in files or files[file['path']] == file, 'duplicate audit inventory conflict')
                    files[file['path']] = file
            require(namespace not in missing and not required.difference(files), 'required originals missing')
            require(files and sum(file['size'] for file in files.values()) <= 4 * 2 ** 30,
                    'empty/over-bound source inventory')
            for rid in runs:
                require(any(path.startswith(r'C:\ProgramData\FakeNet-NG-MCP' + '\\' + base + '\\' + rid + '\\')
                            for path in files for base in ('artifacts', r'artifacts\runs', r'logs\exit-evidence')),
                        'owned run originals absent: ' + rid)
            return {'files': files, 'required': sorted(required), 'optional_missing': sorted(optional.difference(files)),
                    'alternative_layout_missing': sorted(set(missing) - required - optional), 'source_namespace': namespace}

        before = inventory('before')
        write_new_json(destination / 'source-inventory-value.json', before)
        exported = []
        for index, file in enumerate(before['files'].values()):
            target = export_destination(binding, destination, index, file['path'])
            record = instance._transfer_guest_file(file['path'], file['size'], file['sha256'], target)
            require(file_sha256(target) == file['sha256'], 'export host SHA differs')
            exported.append({'guest': file, 'host_path': str(target), 'record': record})
        after = inventory('after')
        write_new_json(destination / 'source-post-inventory-value.json', after)
        require(after == before, 'source originals changed during export')
        write_new_json(destination / 'guest-original-index.json', exported)
        terminal.update(passed=True, files=len(exported), bytes=sum(file['size'] for file in before['files'].values()),
                        required_files=len(required), required_missing=[], optional_missing=before['optional_missing'],
                        alternative_layout_missing=before['alternative_layout_missing'], full_SHA=True,
                        before_after_size_double_SHA=True, source_namespace=namespace)
    except BaseException as error:
        terminal.update(error=repr(error), exception_type=type(error).__name__, export_withheld_or_incomplete=True)
        raise
    finally:
        instance.vm = original_vm
        if original_binding is sentinel:
            del instance.physical_source_binding
        else:
            instance.physical_source_binding = original_binding
        terminal['local_writers_ended'] = True
        write_new_json(destination / 'source-export-terminal.json', terminal)
    return dict(terminal)
