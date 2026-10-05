"""Per-instance original native-six and P1-P7 admission, with explicit context.

No prior material, historical identity or completed SCM transaction grants
business authority. Native originals remain subject to the original checks.
"""
from __future__ import annotations
import hashlib, json, re, time, uuid
from pathlib import Path, PureWindowsPath
import bounded_mcp as bounded
import scenario_suite as suite
from .context import RunContext, exact_path
from .command_transport import StageFileVm, map_command, write_new_json

def save(path, value):
    path = exact_path(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    write_new_json(path, value)

class Responsibility:

    def __init__(self):
        self.safe = True
        self.reasons = []
        self.receipt = None
        self.expected_enabled = None
        self.cycle_applied = False
        self.on_applied = None
        self.admission_ready = False
        self.admission_context = False
        self.cleanup_stops = 0

    def applied(self):
        self.cycle_applied = True
        self.admission_ready = False
        if self.on_applied:
            self.on_applied()

    def refuse(self):
        if not self.safe:
            raise RuntimeError('unknown prior mutation; read-only reconciliation required, no replay')

    def reconcile(self, result):
        if result.get('settled'):
            self.safe = True

    def unknown(self, error):
        self.safe = False
        self.reasons.append(repr(error))

class MutationUnknown(ConnectionError):

    def __init__(self, error):
        super().__init__(str(error))
        self.record = error.record
MUTATIONS = {'start', 'stop', 'restart', 'load_config', 'save_config', 'create_config', 'edit_config', 'rename_config', 'import_config', 'delete_config'}


class ProtectedVm:
    def __init__(self, client, context, state):
        self.context = context.revalidate()
        self.client = StageFileVm(client, context, state)
        self.state, self.root = state, context.evidence_root
        self.number, self.replacements, self.p7_binding = 0, {}, None
        from .producer import VmJournal
        self.journal = VmJournal(context, state)

    def powershell(self, command, timeout=120):
        self.context.revalidate()
        command = map_command(command, tuple(self.replacements.items()))
        if '& $p -Action preflight-b1 -Nonce $n' in command:
            from .dns_evidence import selected_p7_command
            assert self.p7_binding, 'P7 needs current-instance route-only binding'
            self.state.refuse()
            activator = getattr(self, 'p7_capture_start', None)
            if activator:
                activator()
            command, intent = selected_p7_command(command, self.p7_binding, self.context)
            save(Path(self.p7_binding['capture_root']) / 'selected-P7-command-intent.json', intent)
        changing = bool(re.search(
            r'(?i)(?:Start|Stop|Restart)-Service|\b(?:New|Remove|Set)-Item(?:Property)?|WriteAll|'
            r'Export-Clixml|\b(?:logman|pktmon)\s+(?:start|stop)| -Action (?!ensure-client)|'
            r'\.exe[\x27\x22]?\s+stop|Set-Content', command))
        if changing:
            self.state.refuse()
        source = suite.E_GUEST_WORK_ROOT + '\\scenario-suite-20260912'
        target = self.context.physical_namespace + '\\scenario-suite-20260912'
        command = map_command(command, ((source, target),))
        receipt = self.state.receipt
        if receipt:
            receipt = receipt.replace(source, target)
        transaction = receipt and 'Start-Service fakenetng-mcp' in command
        if transaction:
            command = receipt_command(command, receipt, self.state.expected_enabled)
        def dispatch(text, budget):
            raw = self.client.powershell(text, budget)
            if transaction:
                self.state.applied()
            return raw
        try:
            return self.journal.dispatch(dispatch, command, timeout, receipt=receipt)
        except (bounded.TransportUnknown, suite.VmCommandError) as error:
            if changing:
                self.state.unknown(error)
            if not transaction:
                raise
            self.number += 1
            path = self.root / ('receipt-reconciliation-%d.json' % self.number)
            record = {'original_error': repr(error), 'original_transport': getattr(
                error, 'record', getattr(error, 'vm_record', {})), 'receipt': receipt, 'no_mutation_replay': True}
            try:
                raw = self.journal.dispatch(self.client.powershell,
                    "$ErrorActionPreference='Stop';$r=" + suite.quote_ps(receipt) +
                    ";if(Test-Path $r){Get-Content $r -Raw}else{@{stage='absent'}|ConvertTo-Json -Compress}",
                    30, receipt=receipt)
                phase = json.loads(raw['output'])
                record.update(raw=raw, phase=phase)
                if (phase.get('stage') == 'completed' and phase.get('enabled') is self.state.expected_enabled
                        and phase.get('dispatch_nonce') == hashlib.sha256(receipt.encode()).hexdigest()):
                    local_audit_safe = self.journal.audit_safe and getattr(self.client.client, 'audit_safe', True)
                    self.state.safe = local_audit_safe
                    self.state.applied()
                    record['settled'] = True
                    record['safe_to_mutate'] = local_audit_safe
                    save(path, record)
                    return dict(raw, output=json.dumps(phase['answer']), original_response_unknown=True,
                                receipt_reconciliation=raw, projection='completed receipt.answer')
            except BaseException as reconcile:
                record['reconciliation_error'] = repr(reconcile)
            save(path, record)
            raise


def bind_namespace(runner, context):
    context.revalidate()
    assert exact_path(str(runner.root)).is_relative_to(context.evidence_root)
    assert runner.guest_work_root == suite.E_GUEST_WORK_ROOT
    assert getattr(runner, 'physical_namespace', None) is None, 'Suite namespace already bound'
    runner.physical_namespace = context.physical_namespace
    runner.transfer_owner_roots = set()
    original_root = runner._guest_scenario_root

    def scenario_root(sid, attempt):
        context.revalidate()
        logical = original_root(sid, attempt)
        assert logical.startswith(runner.guest_work_root + '\\scenario-suite-20260912\\')
        physical = context.physical_namespace + logical[len(runner.guest_work_root):]
        runner.transfer_owner_roots.add(physical)
        return physical

    runner._guest_scenario_root = scenario_root
    # Transfer scope is populated only after the original capture validators
    # have accepted an actual producer response, never by generating a path.
    from .source import SourceBinding, _freeze
    captures = []

    def remember(original):
        def capture(*args, **kwargs):
            result = original(*args, **kwargs)
            nonce = args[2] if len(args) > 2 else kwargs['nonce']
            label = args[3] if len(args) > 3 else kwargs['run_label']
            # Original _run_one assigns nonce: pktmon immediately after this
            # original response returns; it is not a guest response field.
            if runner.capture_contract == 'scenario-shared-v2' and label == 'run-01':
                assert result['run_label'] == label
                assert result['guest'].startswith(context.physical_namespace + '\\scenario-suite-20260912\\')
                captures.append({'run': result['guest'], 'run_label': label,
                                 'nonce': nonce, 'physical_owner_id': nonce + ':pktmon'})
                runner.physical_source_binding = SourceBinding(_freeze({
                    'physical_namespace': context.physical_namespace, 'captures': captures,
                    'derived_from_current_original_capture_response': True,
                    'materials_sha256': context.materials_sha256}))
            return result
        return capture

    runner._start_capture_and_probe = remember(runner._start_capture_and_probe)
    from .recovery import bind_recovery
    bind_recovery(runner, context)
    return context.physical_namespace

class ProtectedService:

    def __init__(self, client, context, state):
        self.client, self.context, self.state = (client, context.revalidate(), state)
        self.controller_id = client.controller_id

    def tool_outcome(self, name, args=None, timeout=120):
        self.context.revalidate()
        if name in MUTATIONS:
            self.state.refuse()
            if not self.state.admission_ready and (not self.state.admission_context):
                raise suite.Blocked('current SCM instance lacks native6/P1-P7 admission; no business mutation')
        try:
            return self.client.tool_outcome(name, args, timeout)
        except bounded.TransportUnknown as error:
            if name in MUTATIONS:
                self.state.unknown(error)
                raise MutationUnknown(error) from error
            raise

    def tool(self, name, args=None, timeout=120):
        outcome = self.tool_outcome(name, args, timeout)
        if not outcome['ok']:
            raise suite.SuiteError(str(outcome['error']))
        return outcome['value']

class FirstSpikeInstanceGate:

    def __init__(self, context, state):
        self.context = context.revalidate()
        self.state = state
        self.instances = []
        self.formal_identity = None

    def __call__(self, runner, phase, ipc):
        self.context.revalidate()
        assert isinstance(phase, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,79}', phase)
        assert exact_path(str(runner.root)).is_relative_to(self.context.evidence_root)
        assert runner.identity.source_commit == self.context.candidate_identity['source']
        root = runner.root / 'instance-gates' / phase
        root.mkdir(parents=True, exist_ok=False)
        seq = 0
        unknown = False
        admission = None
        out = {'passed': False, 'phase': phase, 'formal_credit': 0}

        def native(name, command, timeout=60):
            self.context.revalidate()
            save(root / (name + '-intent.json'), {'command': command, 'timeout': timeout})
            raw = runner.vm.powershell(command, timeout)
            save(root / (name + '-original.json'), raw)
            return json.loads(raw['output'])

        def call(name, args=None, mutate=False):
            nonlocal seq, unknown
            self.context.revalidate()
            seq += 1
            arguments = dict(args or {})
            if mutate:
                arguments.update(command_id='instance-admission-' + uuid.uuid4().hex, expected_state_version=runner._status(timeout=30)['state_version'])
            save(root / f'{seq:02d}-{name}-intent.json', {'tool': name, 'arguments': arguments, 'controller': runner.service.controller_id, 'timeout': 480 if mutate else 60})
            try:
                answer = runner.service.tool_outcome(name, arguments, timeout=480 if mutate else 60)
            except (bounded.TransportUnknown, ConnectionError) as error:
                unknown = mutate
                save(root / f'{seq:02d}-{name}-unknown.json', {'error': repr(error), 'record': getattr(error, 'record', {}), 'no_resend': True})
                if mutate:
                    settled = suite.reconcile_timed_out_command(runner.service, arguments['command_id'], name, runner.service.controller_id, 60)
                    save(root / f'{seq:02d}-{name}-reconcile.json', settled)
                    unknown = not settled['settled']
                raise
            save(root / f'{seq:02d}-{name}-outcome.json', answer)
            if not answer['ok']:
                raise RuntimeError('admission tool rejected: ' + repr(answer['error']))
            return answer['value']
        try:
            scene = native('identity-candidate-environment', '$ErrorActionPreference=\'Stop\';$s=Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'";$p=Get-Process -Id $s.ProcessId;$root=\'C:\\Program Files\\FakeNet-NG-MCP\';$m=Get-Content (Join-Path $root \'mcp-candidate-manifest.json\') -Raw|ConvertFrom-Json;$prop=Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\fakenetng-mcp\' -Name Environment -ErrorAction SilentlyContinue;@{computer=$env:COMPUTERNAME;uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;mac=@(Get-NetAdapter|Select-Object -ExpandProperty MacAddress);service=$s.State;pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();marker=if(Test-Path \'C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json\'){Get-Content \'C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json\' -Raw|ConvertFrom-Json}else{$null};source=$m.source_commit;manifest_sha=(Get-FileHash (Join-Path $root \'mcp-candidate-manifest.json\')).Hash.ToLower();members=@($m.files|ForEach-Object{@{path=$_.path;expected=$_.sha256;actual=(Get-FileHash (Join-Path $root $_.path)).Hash.ToLower()}});environment_present=($null -ne $prop -and $null -ne $prop.Environment);environment=@($prop.Environment);fault=Test-Path \'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection.json\';fault_gate=Test-Path \'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\fault-injection-gate.json\';config=(Get-Content \'C:\\ProgramData\\FakeNet-NG-MCP\\configs\\service.json\' -Raw|ConvertFrom-Json);space=@(Get-PSDrive C,E|Select-Object Name,Free);utc=[DateTime]::UtcNow.ToString(\'o\')}|ConvertTo-Json -Depth 8 -Compress')
            if scene['marker'] is None:
                assert phase == 'initial-clean-native' and json.loads(Path(runner.args.deployment_record).read_text())['clean_install'], 'missing marker allowed only before first clean native lifecycle'
            identity = {k: scene[k] for k in ('pid', 'filetime')}
            assert scene['computer'] == 'DESKTOP-3FI41GR' and scene['uuid'] == 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49' and ('00-0C-29-C1-CA-49' in scene['mac'])
            assert scene['service'] == 'Running' and identity not in self.instances and (identity != {'pid': 4828, 'filetime': '134353511031106360'}) and (not (scene['marker'] and scene['marker']['needs_recovery'])) and (not scene['fault']) and (not scene['fault_gate']) and (scene['config']['stop_grace_seconds'] == runner.bootstrap_grace)
            assert scene['manifest_sha'] == self.context.candidate_identity['manifest_sha256']
            assert scene['source'] == runner.identity.source_commit and len(scene['members']) == 199 and all((x['actual'] == x['expected'] for x in scene['members']))
            backup = native('original-environment', '$saved=Import-Clixml ' + suite.quote_ps(ipc['backup']) + ';@{present=$saved.present;values=@($saved.values)}|ConvertTo-Json -Compress', 30)
            original = [x for x in backup['values'] if x]
            expected = runner.bootstrap_environment
            assert [x for x in scene['environment'] if x] == expected and scene['environment_present'] == bool(expected)
            self.instances.append(identity)
            save(root / 'new-instance-identity.json', identity)
            status = call('get_status')
            assert status['state'] == 'stopped' and (not status['controller']) and (not status['run_id'])
            call('load_config', {'name': 'default.ini'}, True)
            started = call('start', mutate=True)
            admission = started['run_id']
            assert started['state'] == 'healthy'
            for _ in range(3):
                time.sleep(2)
                assert call('get_status')['state'] == 'healthy'
            call('get_events', {'limit': 500})
            stopped = call('stop', mutate=True)
            assert stopped['state'] == 'stopped'
            assert call('get_status')['config_identity']['sha256'] == self.context.candidate_identity['default_sha256']
            inventory = native('six-original-inventory', '$ErrorActionPreference=\'Stop\';$s=Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'";$p=Get-Process -Id $s.ProcessId;$runs=@();foreach($d in @(Get-ChildItem \'C:\\ProgramData\\FakeNet-NG-MCP\\logs\\exit-evidence\' -Directory)){if(Test-Path (Join-Path $d.FullName \'capability.json\')){$entry=Get-Content (Join-Path $d.FullName \'entry.json\') -Raw|ConvertFrom-Json;if($entry.target.supervisor_pid -eq $p.Id -and [string]$entry.target.supervisor_creation_time -ceq [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc()){$runs+=@{run_id=$d.Name;files=@(Get-ChildItem $d.FullName -File|ForEach-Object{@{path=$_.FullName;size=$_.Length;sha256=(Get-FileHash $_.FullName).Hash.ToLower()}})}}}};@{pid=$p.Id;filetime=[string]$p.StartTime.ToUniversalTime().ToFileTimeUtc();runs=$runs}|ConvertTo-Json -Depth 7 -Compress')
            assert {k: inventory[k] for k in identity} == identity and len(inventory['runs']) == 1
            run = inventory['runs'][0]
            files = run['files']
            assert len(files) == 6 and sum((x['size'] for x in files)) <= 64 * 2 ** 20
            local = root / 'six-originals'
            records = []
            for row in files:
                assert row['size'] <= 32 * 2 ** 20
                dest = local / PureWindowsPath(row['path']).name
                records.append({'guest': row, 'host': runner._transfer_guest_file(row['path'], row['size'], row['sha256'], dest)})
            entry = json.loads((local / 'entry.json').read_text())
            result = json.loads((local / 'result.json').read_text())
            owner = json.loads((local / 'owner-result.json').read_text())
            cap = json.loads((local / 'capability.json').read_text())
            target = result['target']
            dump = local / result['dump']['name']
            checks = {'same_target': entry['target'] == owner['target'] == target, 'current_supervisor': target['supervisor_pid'] == identity['pid'] and str(target['supervisor_creation_time']) == identity['filetime'], 'budget60': target['budget_seconds'] == 60, 'deadline': result['entered_monotonic'] <= result['completed_monotonic'] <= result['deadline_monotonic'] and result['deadline_monotonic'] - result['entered_monotonic'] <= 60, 'capability': cap['passed'] is True and 0 <= cap['elapsed_seconds'] <= 60, 'self_exit': result['notification']['target_pid'] == result['notification']['initiator_pid'] == target['pid'] and result['notification']['exit_status'] == 49158, 'dump_SHA_size': hashlib.sha256(dump.read_bytes()).hexdigest() == result['dump']['sha256'] and dump.stat().st_size == result['dump']['size'], 'native_closed': result['target_handle_closed'] and owner['helper_ended'] and owner['retained_target_handle_closed']}
            assert all(checks.values())
            save(root / 'six-native-verdict.json', {'passed': True, 'identity': identity, 'checks': checks, 'records': records, 'run_id': run['run_id']})
            if runner.bootstrap_preflight:
                preflight = runner.preflight()
                assert preflight['passed']
                runner._require_preflight()
                save(root / 'first-Spike-admission.json', {'preflight_passed': True, 'existing_Spike_not_a_bootstrap_prerequisite': True, 'formal_fault_validator_unchanged': True})
                self.formal_identity = identity
            final = call('get_status')
            assert final['state'] == 'stopped' and (not final['run_id']) and (not final['controller']) and (final['config_identity']['sha256'] == self.context.candidate_identity['default_sha256'])
            out.update(passed=True, identity=identity, admission_run=admission, native_run=run['run_id'], checks=checks, environment_expected=expected, environment_backup=backup, final_status=final)
            return out
        except BaseException as error:
            out.update(error=repr(error), admission_run=admission, unsettled=unknown)
            if unknown:
                runner._ipc_restore_allowed = lambda: False
            if not unknown:
                try:
                    status = call('get_status')
                    if status['controller'] == runner.service.controller_id and status['state'] in ('healthy', 'failed'):
                        count = self.state.cleanup_stops
                        if count >= 1:
                            raise RuntimeError('R41 single cleanup-stop quota already spent; preserve responsibility')
                        self.state.cleanup_stops = count + 1
                        runner._r41_cleanup_stops = count + 1
                        out['cleanup'] = call('stop', mutate=True)
                except BaseException as cleanup:
                    out['cleanup_error'] = repr(cleanup)
            raise
        finally:
            save(root / 'result.json', out)

def receipt_command(command, receipt, enabled):
    assert 'Start-Service fakenetng-mcp' in command
    dispatch_nonce = hashlib.sha256(receipt.encode()).hexdigest()
    prefix = '$receipt=' + suite.quote_ps(receipt) + ";if(Test-Path $receipt){throw 'receipt collision'};New-Item -ItemType Directory -Force (Split-Path $receipt)|Out-Null;function Write-IpcPhase($stage,$answer){$v=@{dispatch_nonce='" + dispatch_nonce + "';stage=$stage;enabled=" + ('$true' if enabled else '$false') + ";utc=[DateTime]::UtcNow.ToString('o');observer_pid=$PID;observer_filetime=[string](Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc();answer=$answer};$tmp=$receipt+'.tmp';[IO.File]::WriteAllText($tmp,($v|ConvertTo-Json -Depth 8 -Compress));Move-Item -LiteralPath $tmp -Destination $receipt -Force};Write-IpcPhase 'entered' $null;"
    command = command.replace(";& 'C:", ";Write-IpcPhase 'stop_intent' $null;& 'C:").replace("\n& 'C:", "\nWrite-IpcPhase 'stop_intent' $null;& 'C:").replace(';Start-Service fakenetng-mcp;', ";Write-IpcPhase 'environment_completed' $null;Write-IpcPhase 'start_intent' $null;Start-Service fakenetng-mcp;Write-IpcPhase 'start_completed' $null;")
    command = command.replace('@{enabled=$true;backup=', '$answer=@{enabled=$true;backup=').replace('@{enabled=$false;backup=', '$answer=@{enabled=$false;backup=')
    assert command.count('}|ConvertTo-Json -Compress') == 1
    command = command.replace('}|ConvertTo-Json -Compress', "};Write-IpcPhase 'completed' $answer;$answer|ConvertTo-Json -Compress")
    return "$ErrorActionPreference='Stop';" + prefix + command
