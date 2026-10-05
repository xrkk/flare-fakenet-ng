"""Original capture reconciliation, scoped to its exact cooperative stop only."""

import copy
import hashlib
import re

import bounded_mcp
import scenario_suite as suite
from .command_transport import StageFileVm, map_command
from .context import exact_path
from .instance import save


class _RecoveryResponsibility:
    def __init__(self):
        self.safe = True

    def refuse(self):
        if not self.safe:
            raise RuntimeError('exact recovery transport unresolved; no further stage write')

    def unknown(self, error):
        self.safe = False


class ExactRecoveryVm:
    def __init__(self, protected, capture, context):
        self.context = context.revalidate()
        self.protected = protected
        self.capture = copy.deepcopy(capture)
        self.responsibility = _RecoveryResponsibility()
        self.client = StageFileVm(protected.client.client, context, self.responsibility)
        cap = self.capture
        assert cap['guest'].startswith(context.physical_namespace + '\\scenario-suite-20260912\\')
        assert cap['run_label'] == 'run-01' and cap['physical_owner_id'] == cap['nonce'] + ':pktmon'
        assert type(cap['pid']) is int and cap['pid'] > 0 and int(cap['probe_creation_ticks']) > 0
        assert cap['kernel_capture']['guest'] == cap['guest']
        assert cap['kernel_capture']['metadata'] == cap['guest'] + '\\kernel-network.metadata.json'
        self.directory = context.evidence_root / 'exact-recovery' / hashlib.sha256(
            (cap['guest'] + ':' + cap['nonce']).encode()).hexdigest()

    def powershell(self, command, timeout=120):
        self.context.revalidate()
        self.responsibility.refuse()
        command = map_command(command, tuple(self.protected.replacements.items()))
        command = map_command(command, ((suite.E_GUEST_WORK_ROOT + '\\scenario-suite-20260912',
                                         self.context.physical_namespace + '\\scenario-suite-20260912'),))
        cap = self.capture
        if re.search(r'(?i)(?:Start|Stop|Restart)-Service|Invoke-CimMethod|Stop-Process|'
                     r'pktmon start|logman start| -Action (?!identity)', command):
            raise RuntimeError('recovery forbids business/start/force kill')
        allowed = (
            (cap['stop'] in command and str(cap['probe_creation_ticks']) in command
             and str(cap['pid']) in command and 'Invoke-Expression $c' in command)
            or ('pktmon stop' in command and suite.quote_ps(cap['physical_owner_id']) in command)
            or (cap['kernel_capture']['metadata'] in command
                and suite.quote_ps(cap['kernel_capture']['session_name']) in command and 'logman query' in command)
            or (cap['etl'] in command and cap['pktmon_nic'] in command and 'pktmon etl2txt' in command)
            or (cap['probe'] in command and '$files=@(' in command and 'Get-FileHash' in command))
        if not allowed:
            raise RuntimeError('outside exact original capture recovery command')
        key = hashlib.sha256(command.encode()).hexdigest()
        intent = exact_path(str(self.directory / (key + '.json')))
        if intent.exists():
            raise RuntimeError('recovery command already dispatched; never replay')
        save(intent, {'command': command, 'timeout': timeout, 'capture': cap, 'no_replay': True})
        try:
            return self.client.powershell(command, timeout)
        except (bounded_mcp.TransportUnknown, suite.VmCommandError) as error:
            self.responsibility.unknown(error)
            self.protected.state.unknown(error)
            raise


def bind_recovery(runner, context):
    context.revalidate()
    original = runner._reconcile_capture_start

    def reconcile(snapshot, kernel, run_root, etl, nic, nonce, run_label, owner_id):
        context.revalidate()
        protected = runner.vm
        if not hasattr(protected, 'state') or protected.state.safe:
            return original(snapshot, kernel, run_root, etl, nic, nonce, run_label, owner_id)
        original_stop = runner._stop_capture_and_probe

        def stop(capture):
            # The original nonce/native identity/creation/ETL-owner predicates
            # have already succeeded; retain all scope checks at this seam.
            assert snapshot.get('identity_match') is True and owner_id == nonce + ':pktmon' and run_label == 'run-01'
            assert run_root.startswith(context.physical_namespace + '\\scenario-suite-20260912\\')
            assert capture['guest'] == run_root and capture['etl'] == etl and capture['pktmon_nic'] == nic
            assert capture['nonce'] == nonce and capture['kernel_capture'] == kernel
            assert capture['pid'] == snapshot['value']['process']['pid']
            assert capture['probe_creation_ticks'] == snapshot['value']['process']['creation_ticks']
            assert kernel['guest'] == run_root and kernel['metadata'] == run_root + '\\kernel-network.metadata.json'
            runner.vm = ExactRecoveryVm(protected, capture, context)
            try:
                return original_stop(capture)
            finally:
                runner.vm = protected

        runner._stop_capture_and_probe = stop
        try:
            return original(snapshot, kernel, run_root, etl, nic, nonce, run_label, owner_id)
        finally:
            runner._stop_capture_and_probe = original_stop

    runner._reconcile_capture_start = reconcile
