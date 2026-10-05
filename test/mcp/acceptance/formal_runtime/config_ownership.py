"""Read-only complete namespace gate and current-execution config ownership.
No pruning, renamed contract, product patch or success projection.
"""
from .context import RunContext, exact_path
from .command_transport import write_new_json

def save(path, value):
    exact_path(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    write_new_json(path, value)
from pathlib import Path, PureWindowsPath
import ast, hashlib, json, re, threading, copy
CUSTOM = 'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\custom'
BUILTIN = 'C:\\Program Files\\FakeNet-NG-MCP\\configs'
INVENTORY_COMMAND = "$ErrorActionPreference='Stop';$roots=@(@{path='C:\\ProgramData\\FakeNet-NG-MCP\\configs\\custom';builtin=$false},@{path='C:\\Program Files\\FakeNet-NG-MCP\\configs';builtin=$true});$rows=@();foreach($root in $roots){$dir=Get-Item -LiteralPath $root.path -Force;if(-not $dir.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'config inventory root invalid/reparse'};$all=@(Get-ChildItem -LiteralPath $root.path -Force);foreach($file in $all){if($root.builtin -and ($file.PSIsContainer -or $file.Extension -cne '.ini')){continue};if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'custom inventory incomplete/unsafe nonfile'};$first=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower();$last=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower();if($first -cne $last){throw 'config inventory unstable'};$rows+=@{name=$file.Name;path=$file.FullName;builtin=$root.builtin;size=$file.Length;sha256=$first}}};@{schema='r48.config-inventory.v1';complete=$true;custom_root=$roots[0].path;builtin_root=$roots[1].path;rows=$rows;count=$rows.Count}|ConvertTo-Json -Depth 5 -Compress"

def selection_plan(suite):
    import scenario_suite as s
    scenarios = suite.manifest()['scenarios']
    selected = scenarios if getattr(suite, 'args', None) is not None and getattr(suite.args, 'command', None) == 'run' else [sorted((row for row in scenarios if row['fault_class'] == fault and row['config_profile']['bucket'] != 'default'), key=lambda row: row['scenario_id'])[0] for fault in s.FAULTS]
    source = Path(s.__file__).read_text()
    tree = ast.parse(source)
    methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    fragment = ast.get_source_segment(source, methods['_run_one'])
    assert "for label in ('scratch', 'active', 'import')" in fragment and "scenario_id + '-%s-a%d.ini'" in fragment and ("scratch + '-stale'" in fragment), 'original name lifecycle changed; gate must be reviewed'
    pre = ast.get_source_segment(source, methods['_preflight_b1'])
    match = re.search("name = '([^']+)'", pre)
    assert match
    recover = ast.get_source_segment(source, methods['_fault_recovery_cycle'])
    assert "{'name': 'default.ini'}" in recover
    cases = []
    for row in selected:
        sid = row['scenario_id']
        scratch = sid + '-scratch-a1.ini'
        active = sid + '-active-a1.ini'
        imported = sid + '-import-a1.ini'
        cases.append({'scenario_id': sid, 'fault_class': row['fault_class'], 'attempt': 1, 'scratch': scratch, 'active': active, 'import': imported, 'stale_rejection_target': scratch + '-stale', 'lifecycle': ['create scratch', 'stale create must reject state_conflict/no creation', 'read/edit scratch', 'rename scratch -> active', 'import/read/delete import', 'load active', 'traffic lifecycle', 'cleanup owned import/scratch/active only', 'fault recovery load default.ini']})
    names = [case[k] for case in cases for k in ['scratch', 'active', 'import', 'stale_rejection_target']] + [match[1]]
    assert len(set((n.casefold() for n in names))) == len(names)
    return {'schema': 'r48.config-plan.v1', 'selected': cases, 'must_be_absent': names, 'preflight_temporary': match[1], 'restoration_builtin': 'default.ini', 'selection_source': str(Path(s.__file__).resolve()), 'selection_source_SHA': hashlib.sha256(source.encode()).hexdigest(), 'no_contract_renaming': True}

def validate_inventory(plan, listing, inventory, default_sha):

    def require(v, message):
        if not v:
            raise RuntimeError(message)
    require(isinstance(listing, dict) and listing.get('error') is None and isinstance(listing.get('configs'), list), 'config list unknown/invalid')
    require(isinstance(inventory, dict) and inventory.get('schema') == 'r48.config-inventory.v1' and (inventory.get('complete') is True) and (inventory.get('custom_root') == CUSTOM) and (inventory.get('builtin_root') == BUILTIN), 'config inventory unknown/incomplete/root mismatch')
    rows = inventory.get('rows')
    require(isinstance(rows, list) and type(inventory.get('count')) is int and inventory.get('count') == len(rows), 'config inventory incomplete count')

    def validate(row):
        require(isinstance(row, dict), 'invalid config row')
        name = row.get('name')
        require(isinstance(name, str) and name and ('/' not in name) and ('\\' not in name) and ('..' not in name), 'invalid config name')
        require(type(row.get('builtin')) is bool and type(row.get('size')) is int and (row['size'] >= 0) and isinstance(row.get('sha256'), str) and re.fullmatch('[a-f0-9]{64}', row['sha256']), 'config row SHA/size/identity unknown')
        return ((name.casefold(), row['builtin']), (row['size'], row['sha256']))
    full = {}
    canonical = {}
    for row in rows:
        key, value = validate(row)
        require(row.get('path') == str(PureWindowsPath(BUILTIN if row['builtin'] else CUSTOM) / row['name']), 'config inventory physical path differs')
        require(key not in full, 'duplicate/case aliased inventory')
        full[key] = value
        canonical[key] = row
    listed = {}
    for row in listing['configs']:
        key, value = validate(row)
        require(key not in listed, 'duplicate/case aliased list')
        listed[key] = value
    projected = {key: value for key, value in full.items() if key[0].endswith('.ini')}
    require(listed == projected, 'product list and complete filesystem inventory differ/incomplete')
    require(full.get(('default.ini', True), (None, None))[1] == default_sha, 'default restoration SHA missing/different')
    forbidden = {n.casefold() for n in plan['must_be_absent']}
    collisions = [row for row in rows if row['name'].casefold() in forbidden]
    if collisions:
        raise RuntimeError('planned config namespace collision (no prune): ' + json.dumps(collisions, ensure_ascii=False))
    return {'passed': True, 'complete': True, 'config_count': len(rows), 'planned_absent_count': len(forbidden), 'collisions': [], 'mutations_before_gate': 0}

class AuditWriteError(RuntimeError):

    def __init__(self, event, outcome, error):
        super().__init__('local audit write failed after RPC; no replay: ' + repr(error))
        self.event = copy.deepcopy(event)
        self.outcome = outcome
        self.response_known = outcome is not None
        self.audit_error = error

class ConfigOwnedService:

    def __init__(self, client, context: RunContext, plan, inventory, root=None):
        self.context = context.revalidate()
        root = context.evidence_root if root is None else exact_path(str(root))
        if not root.is_relative_to(context.evidence_root):
            raise RuntimeError('configuration evidence outside explicit output')
        if (root / 'config-ownership').exists():
            raise RuntimeError('configuration ownership output exists; no implicit resume')
        self.client = client
        self.controller_id = client.controller_id
        self.plan = plan
        self.root = Path(root)
        self.number = 0
        self.owned = {}
        self.allowed = {n.casefold() for n in plan['must_be_absent']}
        self.baseline = {r['name'].casefold() for r in inventory['rows']}
        self.mutation_safe = True
        self._lock = threading.RLock()
        self._inflight_mutation = None
        self.audit_safe = True
        self.audit_failures = {}

    def tool_outcome(self, name, args=None, timeout=120):
        self.context.revalidate()
        args = copy.deepcopy(args or {})
        key = str(args.get('name', '')).casefold()
        mutation = name in ['create_config', 'import_config', 'edit_config', 'rename_config', 'delete_config', 'load_config', 'save_config', 'start', 'stop', 'restart']
        with self._lock:
            self.number += 1
            number = self.number
            event = {'event_id': number, 'tool': name, 'name': args.get('name'), 'command_id': args.get('command_id'), 'arguments': args, 'owned_before': dict(self.owned), 'forwarded': False, 'response_received': False}
        out = None
        failure = None
        try:
            with self._lock:
                if mutation and (not self.mutation_safe or not self.audit_safe):
                    raise RuntimeError('prior mutation response or local audit unresolved; no replay or cleanup write')
                if mutation and self._inflight_mutation is not None:
                    raise RuntimeError('concurrent mutation inflight; observe only, no second dispatch')
                if name in ['create_config', 'import_config']:
                    if key not in self.allowed or key in self.baseline or key in self.owned:
                        raise RuntimeError('config create/import not a fresh planned current-execution name')
                if name in ['edit_config', 'rename_config', 'delete_config']:
                    if key not in self.owned or args.get('expected_sha256') != self.owned[key]:
                        raise RuntimeError('config mutation/cleanup lacks current-execution ownership and exact SHA')
                if name == 'rename_config':
                    target = str(args.get('new_name', '')).casefold()
                    if target not in self.allowed or target in self.baseline or target in self.owned:
                        raise RuntimeError('rename target is not a fresh planned name')
                if name == 'save_config':
                    raise RuntimeError('unplanned save_config denied')
                if name == 'load_config' and key != 'default.ini' and (key not in self.owned):
                    raise RuntimeError('load_config lacks current-execution ownership')
                if mutation:
                    self._inflight_mutation = number
                event['owned_at_dispatch'] = dict(self.owned)
                event['forwarded'] = True
            out = self.client.tool_outcome(name, args, timeout)
            event.update(response_received=True, outcome=copy.deepcopy(out))
            with self._lock:
                if mutation:
                    if not isinstance(out, dict) or type(out.get('ok')) is not bool or 'error' not in out:
                        raise RuntimeError('mutation response ok missing/invalid')
                    if out['ok']:
                        if out.get('error') is not None or not isinstance(out.get('value'), dict) or out['value'].get('error') is not None:
                            raise RuntimeError('mutation success response error/value inconsistent')
                    elif not isinstance(out.get('error'), dict) or not isinstance(out['error'].get('code'), str):
                        raise RuntimeError('mutation rejection untyped/unknown')
                event.update(ok=out['ok'], error=out.get('error'))
                if out['ok'] and name in ['create_config', 'import_config', 'edit_config', 'rename_config', 'delete_config']:
                    changed = out['value'].get('changed')
                    if type(changed) is not bool:
                        raise RuntimeError('config changed flag missing/invalid')
                    content_sha = hashlib.sha256(args['content'].encode()).hexdigest() if name in ['create_config', 'import_config', 'edit_config'] else None
                    expected_name = args.get('new_name') if name == 'rename_config' else args.get('name')
                    if out['value'].get('name') != expected_name:
                        raise RuntimeError('config response name differs from exact request')
                    if name != 'delete_config':
                        expected_sha = content_sha if content_sha is not None else self.owned[key]
                        if out['value'].get('sha256') != expected_sha:
                            raise RuntimeError('config response SHA differs from exact bytes')
                    if not changed:
                        if name != 'edit_config' or content_sha != self.owned[key] or args.get('expected_sha256') != self.owned[key]:
                            raise RuntimeError('changed=false cannot grant/transfer/remove ownership or conceal changed content')
                        event['ownership_effect'] = 'no-op edit retained existing exact owner'
                    else:
                        if name in ['create_config', 'import_config', 'edit_config']:
                            self.owned[key] = content_sha
                        if name == 'rename_config':
                            self.owned[target] = self.owned.pop(key)
                        if name == 'delete_config':
                            self.owned.pop(key)
                        event['ownership_effect'] = 'successful changed mutation recorded'
        except BaseException as e:
            failure = e
            event['error_local'] = repr(e)
            with self._lock:
                if event['forwarded'] and mutation:
                    self.mutation_safe = False
                    event['mutation_response_unresolved'] = True
                    state = getattr(self.client, 'state', None)
                    if state is not None:
                        state.unknown(e)
        with self._lock:
            event.update(owned_after=dict(self.owned), mutation_safe=self.mutation_safe, audit_safe=self.audit_safe)
        try:
            save(self.root / 'config-ownership' / ('%05d.json' % number), event)
        except BaseException as e:
            with self._lock:
                self.audit_safe = False
                self.audit_failures[number] = {'event': copy.deepcopy(event), 'audit_error': repr(e), 'response_known': out is not None, 'not_product_transport_unknown': out is not None}
            if failure is None:
                failure = AuditWriteError(event, out, e)
            else:
                failure.add_note('independent local audit failure: ' + repr(e))
                failure.audit_failure = self.audit_failures[number]
        with self._lock:
            if self._inflight_mutation == number:
                self._inflight_mutation = None
        if failure is not None:
            raise failure
        return out

    def audit_responsibility(self):
        with self._lock:
            return {'audit_safe': self.audit_safe, 'mutation_safe': self.mutation_safe, 'inflight_mutation': self._inflight_mutation, 'audit_failures': copy.deepcopy(self.audit_failures), 'no_mutation_replay': True}

    def tool(self, name, args=None, timeout=120):
        out = self.tool_outcome(name, args, timeout)
        if not out['ok']:
            import scenario_suite as s
            raise s.SuiteError(str(out['error']))
        return out['value']

def prestart_gate(r, context):
    context = context.revalidate()
    root = context.evidence_root
    identity = context.candidate_identity
    if exact_path(str(r.root)) != root:
        raise RuntimeError('configuration Suite root differs from explicit context')
    plan = selection_plan(r)
    save(root / 'planned-config-lifecycle.json', plan)
    listing = r.service.tool_outcome('list_configs', {}, 30)
    save(root / 'prestart-list-configs-original.json', listing)
    if not listing.get('ok'):
        raise RuntimeError('prestart list_configs failed/unknown; no SCM')
    raw = r.vm.powershell(INVENTORY_COMMAND, 30)
    save(root / 'prestart-config-inventory-original.json', raw)
    inventory = json.loads(raw['output'])
    try:
        verdict = validate_inventory(plan, listing['value'], inventory, identity['default_sha256'])
    except BaseException as e:
        save(root / 'config-namespace-blocked.json', {'error': repr(e), 'mutation_SCM_capture_before_gate': 0, 'no_automatic_prune': True})
        raise
    save(root / 'config-namespace-verdict.json', verdict)
    r.service = ConfigOwnedService(r.service, context, plan, inventory, root)
    return verdict
