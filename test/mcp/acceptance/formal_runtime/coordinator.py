"""Original single SCM cycles and per-instance admission orchestration.

This module reuses Suite methods and never schedules a second formal matrix.
"""
import copy, hashlib, json, os, time, traceback, uuid
from contextlib import contextmanager
from pathlib import Path
import bounded_mcp as b
import scenario_suite as s
from .context import exact_path, checked_record, read_json
from .instance import FirstSpikeInstanceGate, bind_namespace, save
from .dns_evidence import route_binding, api_ipv4

_ACTIVE_COORDINATOR = None

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def host_capacity(context):
    context.revalidate()
    resource = context.materials['resource_plan']
    assert resource['host_reserve_bytes'] == 24 * 2 ** 30
    assert resource['tmp_reserve_bytes'] == 768 * 2 ** 20
    free = {str(path): os.statvfs(path).f_bavail * os.statvfs(path).f_frsize for path in (context.repository_root, Path('/tmp'))}
    assert free[str(context.repository_root)] >= resource['host_reserve_bytes']
    assert free['/tmp'] >= resource['tmp_reserve_bytes']
    return free
SCENE = '$ErrorActionPreference=\'Stop\';$s=Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'";$p=if($s.ProcessId){Get-Process -Id $s.ProcessId};$root=\'C:\\Program Files\\FakeNet-NG-MCP\';$m=Get-Content (Join-Path $root \'mcp-candidate-manifest.json\') -Raw|ConvertFrom-Json;$prop=Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp\' -Name Environment -ErrorAction SilentlyContinue;@{computer=$env:COMPUTERNAME;uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;mac=@(Get-NetAdapter|Select-Object -ExpandProperty MacAddress);service=$s.State;pid=$s.ProcessId;filetime=if($p){[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()};source=$m.source_commit;manifest_sha=(Get-FileHash (Join-Path $root \'mcp-candidate-manifest.json\')).Hash.ToLower();members=@($m.files|ForEach-Object{$f=Get-Item (Join-Path $root $_.path);@{path=$_.path;size=$f.Length;sha256=(Get-FileHash $f.FullName).Hash.ToLower()}});marker=(Get-Content \'C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json\' -Raw|ConvertFrom-Json);env_present=($null -ne $prop -and $null -ne $prop.Environment);env=@($prop.Environment);config_sha=(Get-FileHash \'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json\').Hash.ToLower();grace=(Get-Content \'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json\' -Raw|ConvertFrom-Json).stop_grace_seconds;fault=Test-Path \'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json\';fault_gate=Test-Path \'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection-gate.json\';workers=@(Get-CimInstance Win32_Process|Where-Object{$_.ProcessId -ne $PID -and ($_.Name -match \'fakenetng-mcp-managed|exit-monitor|scenario-probe|pktmon\' -or $_.CommandLine -match \'scenario_probes\\.ps1|scenario-probe-client\\.exe|managed-(?:child|fault-hang)|scenario_aux.*\\.py\')}|Select-Object ProcessId,Name,CreationDate);space=@(Get-PSDrive C,E|Select-Object Name,Free)}|ConvertTo-Json -Depth 8 -Compress'

def wait_readonly_status(original, timeout, observations):
    """Retry only get_status UNKNOWN inside this caller's existing deadline.

 No SCM/VM mutation is retried. Each failed bounded original remains UNKNOWN.
 """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            value = original(timeout=min(10, remaining))
            observations.append({'status': value, 'remaining': remaining})
            return value
        except b.TransportUnknown as error:
            observations.append({'error': repr(error), 'original_transport': error.record, 'read_only': True, 'no_mutation_replay': True})
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    raise s.SuiteError('fault-mode endpoint readiness deadline: ' + repr(observations))

def validate_scene(x, status, identity, manifest, env, grace=60):
    assert x['computer'] == 'DESKTOP-3FI41GR' and x['uuid'] == 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49' and ('00-0C-29-C1-CA-49' in x['mac'])
    assert x['source'] == identity['source'] and x['manifest_sha'] == identity['manifest_sha256'] and (x['service'] == 'Running') and (x['pid'] > 0) and (int(x['filetime']) > 0)
    expected = {f['path']: (f['size'], f['sha256']) for f in manifest['files']}
    assert len(expected) == len(x['members']) == 199
    assert {f['path']: (f['size'], f['sha256']) for f in x['members']} == expected
    assert not x['marker']['needs_recovery'] and (not x['workers']) and (not x['fault']) and (not x['fault_gate']) and (x['grace'] == grace)
    assert {'present': x['env_present'], 'values': x['env']} == env
    assert status['state'] == 'stopped' and (not status['controller']) and (not status['run_id']) and (status['config_identity']['sha256'] == identity['default_sha256'])
    for drive, min_gib in [('C', 4), ('E', 11)]:
        assert next((t['Free'] for t in x['space'] if t['Name'] == drive)) >= min_gib * 2 ** 30
    return {'pid': x['pid'], 'filetime': x['filetime']}

class Coordinator:

    def __init__(self, r, state, capture, context):
        context.revalidate()
        assert exact_path(str(r.root)) == context.evidence_root
        self.context = context
        self.r = r
        self.state = state
        self.capture = capture
        self.identity = context.candidate_identity
        self.seq = 0
        self.admitted = []
        self.gate = FirstSpikeInstanceGate(context, state)
        self.current = None
        self.original_fault = r._fault_mode
        self.original_ipc = r._ipc_evidence_mode
        self.backup_prefix = 'r20-' + uuid.uuid4().hex
        self.r.vm.replacements['ipc-evidence-original-environment.xml'] = self.backup_prefix + '-ipc-environment.xml'
        self.expected_env = []
        self.expected_grace = 60
        self.current_kind = None
        self.fault_number = 0
        self.fault_restore_pending = False
        self.backup_names = {self.r.vm.replacements['ipc-evidence-original-environment.xml']}
        self.scenario_admission_attempts = []
        self.original_run_one = getattr(r, '_run_one', None)
        self.original_continuation = r._continuation_gate
        self.watermarks = 0

    def run_one(self, scenario, attempt):
        self.context.revalidate()
        if not scenario.get('fault_class'):
            return self.original_run_one(scenario, attempt)
        self.scenario_admission_attempts.append(scenario['scenario_id'])
        note = self.r.root / 'scenario-bindings' / (scenario['scenario_id'] + '-a' + str(attempt) + '.json')
        enabled = None
        consumed = False
        old_mode = self.r._fault_mode
        result = None
        failure = None
        frozen_path = None
        try:
            enabled = self.cycle('fault', True)
            pf = self.r._require_preflight()
            frozen_path = self.r.preflight_path
            frozen_sha = sha(frozen_path)

            def mode(value):
                nonlocal consumed
                if value:
                    assert not consumed, 'one scenario may consume its completed enable only once'
                    assert self.r.preflight_path == frozen_path and sha(frozen_path) == frozen_sha
                    consumed = True
                    return enabled
                return self.cycle('fault', False)
            self.r._fault_mode = mode
            result = self.original_run_one(scenario, attempt)
            return result
        except BaseException as error:
            failure = {'error': repr(error), 'traceback': traceback.format_exc()}
            raise
        finally:
            self.r._fault_mode = old_mode
            save(note, {'scenario_id': scenario['scenario_id'], 'attempt': attempt, 'original_mode_enabled': enabled, 'enable_answer_consumed_once': consumed, 'profile_freeze_after_fault_instance_admission': enabled is not None, 'selected_preflight': s.file_record(frozen_path) if frozen_path and frozen_path.is_file() else None, 'failure': failure, 'result_state': result.get('state') if result else None, 'no_extra_SCM_enable': True})

    def admit(self, answer, env, grace, backup):
        self.context.revalidate()
        args = copy.copy(self.r.args)
        args.suite_root = str(self.r.root / 'instances' / ('cycle-' + str(self.seq).zfill(2)))
        view = s.Suite(args)
        bind_namespace(view, self.context)
        view.generate()
        view.vm = self.r.vm
        view.service = self.r.service
        view.bootstrap_environment = env
        view.bootstrap_grace = grace
        view.bootstrap_preflight = True
        old = self.capture.runner
        self.capture.runner = view
        self.state.admission_ready = False
        self.state.admission_context = True
        failure = None
        try:
            with self.capture.probe_hooks():
                x = self.gate(view, 'cycle-' + str(self.seq), {'backup': backup})
        except BaseException as error:
            failure = error
            raise
        finally:
            self.capture.runner = old
            self.state.admission_context = False
            try:
                self.capture.close()
            except BaseException as close_error:
                if failure is None:
                    raise
                failure.add_note('independent P7 writer-close failure: ' + repr(close_error))
                try:
                    save(view.root / 'admission-writer-close-failure.json', {
                        'primary_error': repr(failure), 'writer_close_error': repr(close_error)})
                except BaseException as audit_error:
                    failure.add_note('admission close-failure audit failed: ' + repr(audit_error))
        previous = None
        if self.r.preflight_path.exists():
            previous = self.r._require_preflight()
        pf = view._require_preflight()
        if previous:
            assert route_binding(previous) == route_binding(pf), 'preflight route/DNS server changed; stop without business'
        api_ipv4(pf['api_ipv4'])
        assert x['passed'] is True and self.state.safe
        self.current = x['identity']
        self.admitted.append(x)
        self.state.admission_ready = True
        self.r.preflight_path = view.preflight_path
        save(self.r.root / ('cycle-' + str(self.seq) + '-admission.json'), x)
        return x

    def cycle(self, kind, enabled):
        self.context.revalidate()
        assert kind in ('ipc', 'fault') and type(enabled) is bool
        self.state.refuse()
        host_capacity(self.context)
        assert self.seq < 70, 'R38 frozen 20 IPC batch cycles + 15 fault pairs bound'
        self.seq += 1
        raw = self.r.vm.powershell(SCENE, 90)
        scene = json.loads(raw['output'])
        save(self.r.root / ('cycle-' + str(self.seq) + '-capacity-original.json'), raw)
        assert scene['computer'] == 'DESKTOP-3FI41GR' and scene['uuid'] == 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49' and ('00-0C-29-C1-CA-49' in scene['mac']) and (scene['source'] == self.identity['source']) and (not scene['marker']['needs_recovery'])
        if self.identity:
            plan = read_json(checked_record(dict(self.context.materials['plan'])))
            manifest = read_json(checked_record(plan['candidate_files']['manifest']))
            assert scene['manifest_sha'] == self.identity['manifest_sha256'] and {x['path']: (x['size'], x['sha256']) for x in scene['members']} == {x['path']: (x['size'], x['sha256']) for x in manifest['files']}
        for drive, n in [('C', 4), ('E', 11)]:
            assert next((t['Free'] for t in scene['space'] if t['Name'] == drive)) >= n * 2 ** 30
        assert [e for e in scene['env'] if e] == self.expected_env and scene['env_present'] == bool(self.expected_env) and (scene['grace'] == self.expected_grace), 'unexpected Environment/grace before SCM mutation'
        before_reads = []
        try:
            status = wait_readonly_status(self.r._status, 60, before_reads)
        finally:
            save(self.r.root / ('cycle-' + str(self.seq) + '-before-status-observations.json'), before_reads)
        assert status['state'] == 'stopped' and (not status['controller']) and (not status['run_id'])
        assert not (kind == 'ipc' and (not enabled) and self.fault_restore_pending), 'precise fault configuration restoration must precede outer Environment restoration'
        receipt = self.r.guest_work_root + '\\scenario-suite-20260912\\' + self.backup_prefix + '-cycle-' + str(self.seq) + '\\receipt.json'
        self.state.receipt = receipt
        self.state.expected_enabled = enabled
        self.state.cycle_applied = False
        self.current_kind = kind
        if kind == 'fault' and enabled:
            self.fault_number += 1
            for old in ['fault-mode-original-service.json', 'fault-mode-original-environment.xml']:
                self.r.vm.replacements[old] = self.backup_prefix + '-case-' + str(self.fault_number) + '-' + old
            self.backup_names.update(self.r.vm.replacements.values())
        save(self.r.root / ('cycle-' + str(self.seq) + '-intent.json'), {'kind': kind, 'enabled': enabled, 'receipt': receipt, 'original_vm_budget': 180, 'readiness_budget': 60, 'no_mutation_replay': True})

        def applied():
            if kind == 'fault':
                self.fault_restore_pending = enabled
            self.expected_env = ['FAKENETNG_MCP_FAULT_INJECTION=1'] if kind == 'fault' or enabled else []
            self.expected_grace = 5 if kind == 'fault' and enabled else 60
        self.state.on_applied = applied
        original_status = self.r._status
        readiness = []

        def readonly_ready(timeout=120):
            if not self.state.cycle_applied:
                return original_status(timeout=timeout)
            return wait_readonly_status(original_status, timeout, readiness)
        self.r._status = readonly_ready
        try:
            x = (self.original_fault if kind == 'fault' else self.original_ipc)(enabled)
            self.state.cycle_applied = True
            save(self.r.root / ('cycle-' + str(self.seq) + '-outcome.json'), x)
        except BaseException as error:
            save(self.r.root / ('cycle-' + str(self.seq) + '-failure.json'), {'error': repr(error), 'safe_to_restore': self.state.safe, 'original_failure_preserved': True})
            raise
        finally:
            self.r._status = original_status
            save(self.r.root / ('cycle-' + str(self.seq) + '-readiness-observations.json'), readiness)
            if self.state.cycle_applied:
                if kind == 'fault':
                    self.fault_restore_pending = enabled
                self.expected_env = ['FAKENETNG_MCP_FAULT_INJECTION=1'] if kind == 'fault' or enabled else []
                self.expected_grace = 5 if kind == 'fault' and enabled else 60
            save(self.r.root / ('cycle-' + str(self.seq) + '-responsibility.json'), {'transaction_completed': self.state.cycle_applied, 'safe_to_mutate': self.state.safe, 'fault_restore_pending': self.fault_restore_pending, 'expected_env': self.expected_env, 'expected_grace': self.expected_grace, 'admission_not_granted_by_transaction': True})
            self.state.receipt = None
            self.state.on_applied = None
        env = ['FAKENETNG_MCP_FAULT_INJECTION=1'] if kind == 'fault' or enabled else []
        backup_name = self.r.vm.replacements['fault-mode-original-environment.xml'] if kind == 'fault' else self.r.vm.replacements['ipc-evidence-original-environment.xml']
        self.admit(x, env, 5 if kind == 'fault' and enabled else 60, self.r.guest_work_root + '\\scenario-suite-20260912\\' + backup_name)
        return x

    def batch_gate(self, runner, phase, answer):
        self.context.revalidate()
        assert runner is self.r and phase in ('enabled', 'disabled')
        assert self.admitted and self.state.admission_ready and self.state.safe
        raw = runner.vm.powershell(
            "$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "$p=Get-Process -Id $s.ProcessId;@{pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()}"
            "|ConvertTo-Json -Compress", 30)
        save(runner.root / ('cycle-%d-batch-%s-identity.json' % (self.seq, phase)), raw)
        assert json.loads(raw['output']) == self.current == self.admitted[-1]['identity']
        # Return the actual completed original native/P1-P7 gate ledger.
        return self.admitted[-1]

    def restore_allowed(self):
        if not self.state.safe:
            return False
        if self.fault_restore_pending:
            save(self.r.root / 'pending-fault-exact-restoration.json', self.cycle('fault', False))
        return self.state.safe and not self.fault_restore_pending

    def continuation(self):
        self.context.revalidate()
        value = self.original_continuation()
        capacity = host_capacity(self.context)
        raw = self.r.vm.powershell(SCENE, 90)
        scene = json.loads(raw['output'])
        self.watermarks += 1
        save(self.r.root / 'resource-watermarks' / ('%04d.json' % self.watermarks), {
            'host': capacity, 'guest_original': raw, 'current_instance': self.current})
        assert self.current == {'pid': scene['pid'], 'filetime': scene['filetime']}
        assert scene['computer'] == 'DESKTOP-3FI41GR' and scene['uuid'] == 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49'
        assert '00-0C-29-C1-CA-49' in scene['mac']
        assert scene['source'] == self.identity['source'] and scene['manifest_sha'] == self.identity['manifest_sha256']
        plan = read_json(checked_record(dict(self.context.materials['plan'])))
        manifest = read_json(checked_record(plan['candidate_files']['manifest']))
        assert len(scene['members']) == len(manifest['files']) == 199
        assert {x['path']:(x['size'],x['sha256']) for x in scene['members']} == {
            x['path']:(x['size'],x['sha256']) for x in manifest['files']}
        assert not scene['marker']['needs_recovery'] and not scene['workers'] and not scene['fault'] and not scene['fault_gate']
        assert scene['grace'] == self.expected_grace and scene['env_present'] == bool(self.expected_env)
        assert [entry for entry in scene['env'] if entry] == self.expected_env
        for drive, minimum in [('C', 4), ('E', 11)]:
            assert next(row['Free'] for row in scene['space'] if row['Name'] == drive) >= minimum * 2**30
        # Original benign cleanup need not load default between rows.
        self.r._require_preflight()
        return dict(value, current_native_identity=self.current, scene=scene)

    @contextmanager
    def installed(self):
        global _ACTIVE_COORDINATOR
        self.context.revalidate()
        if _ACTIVE_COORDINATOR is not None:
            raise RuntimeError('another SCM coordinator is active; no context overlap')
        originals = {name:getattr(self.r, name, None) for name in (
            '_ipc_evidence_mode', '_ipc_restore_allowed', '_continuation_gate',
            '_prune_scenario_vm_footprint', '_prune_scenario_configs', '_run_one')}
        old_reconcile = s.reconcile_timed_out_command
        _ACTIVE_COORDINATOR = self

        def reconcile(*args, **kwargs):
            result = old_reconcile(*args, **kwargs)
            self.state.reconcile(result)
            return result

        self.r._ipc_evidence_mode = lambda enabled:self.cycle('ipc', enabled)
        if self.original_run_one:
            self.r._run_one = self.run_one
        self.r._ipc_restore_allowed = self.restore_allowed
        self.r._continuation_gate = self.continuation
        self.r._prune_scenario_vm_footprint = lambda *args, **kwargs: {
            'cleanup_mode':'audit-only', 'pruned_runs':[], 'guest_removed':False,
            'formal_pass_fail_retained':True}
        self.r._prune_scenario_configs = lambda sid: {
            'deleted':[], 'cleanup_mode':'audit-only', 'scenario_id':sid}
        s.reconcile_timed_out_command = reconcile
        try:
            yield self
        finally:
            s.reconcile_timed_out_command = old_reconcile
            for name, original in originals.items():
                if original is None:
                    if hasattr(self.r, name): delattr(self.r, name)
                else:
                    setattr(self.r, name, original)
            _ACTIVE_COORDINATOR = None
