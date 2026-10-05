"""Read-only source export with original identity, resource and transfer gates."""
import json
from pathlib import Path

import formal_batch_v3 as batch
import scenario_suite as suite
from .context import checked_record, read_json, exact_path
from .runtime_sources import qualify, loaded_sources
from .runner import require, _capacity, _package
from .source import SourceAuthority, resolve_source, export_source
from .instance import Responsibility
from .clients import FreshClient
from .coordinator import SCENE, validate_scene
from .current_source import _transport_closed
from .producer import file_record
from .command_transport import write_new_json


class _CapacityReadClient:
    def __init__(self, client, context):
        self.client, self.context = client, context

    def powershell(self, command, timeout=30):
        _capacity(self.context, 1)
        return self.client.powershell(command, min(timeout, 30))


def inputs(context, source_root, entry):
    """No Suite/output/RPC before exact source, package and fresh capacity."""
    qualified = qualify(context, entry); loaded_sources(context, qualified)
    root = exact_path(str(source_root))
    SourceAuthority(context, root)
    binding = resolve_source(context, root)
    require(not context.evidence_root.exists(), 'source export requires unused output; no retry')
    args = batch.load_suite_args(checked_record(dict(context.materials['suite_argv']['benign'])))
    require(bool(args.win10vm_mcp) and bool(args.target_base_url),
            'source export requires explicit original VM and status endpoints')
    plan = read_json(checked_record(dict(context.materials['plan'])))
    package = _package(context, plan, args)
    capacity = _capacity(context, 1)
    return args, binding, qualified, package, capacity


def run(context, source_root, entry):
    args, binding, qualified, package, capacity = inputs(context, source_root, entry)
    root = context.evidence_root
    # Original Suite constructor creates only this unused local output; no
    # generate/run/start/SCM or remote staging is invoked by this entry.
    runner = suite.Suite(args)
    state = Responsibility()
    vm = FreshClient(runner.vm, context, state)
    service = FreshClient(runner.service, context, state)
    runner.vm = _CapacityReadClient(vm, context)
    runner.service = service
    manifest = read_json(checked_record(read_json(checked_record(dict(context.materials['plan'])))['candidate_files']['manifest']))
    failure, result, closed = None, None, False
    initial_identity = None
    gates = {}

    def gate(label):
        _capacity(context, 1)
        status = runner._status(30)
        raw = vm.powershell(SCENE, 30)
        write_new_json(root/(label+'-scene-original.json'), raw)
        scene = json.loads(raw['output'])
        identity = validate_scene(scene, status, context.candidate_identity, manifest,
                                  {'present': False, 'values': []})
        write_new_json(root/(label+'-readonly-gate.json'), {'status': status, 'scene': scene,
            'identity': identity, 'business_authorized': False, 'new_formal_credit': 0})
        gates[label] = file_record(root/(label+'-readonly-gate.json'))
        return identity

    def closure():
        nonlocal closed
        _transport_closed(vm, context, 'vm'); _transport_closed(service, context, 'service')
        if not closed:
            require(gate('after-export') == initial_identity, 'source export native identity changed')
            _transport_closed(vm, context, 'vm'); _transport_closed(service, context, 'service')
            closed = True
        for name in ('before-export', 'after-export'):
            checked_record(gates[name])
        witnesses = _transport_closed(vm, context, 'vm')+_transport_closed(service, context, 'service')
        return {'host_writers_ended': True, 'actual_terminal_and_completion_witnesses': witnesses,
                'original_before_after_identity_gate': True, 'business_authorized': False,
                'new_formal_credit': 0}

    try:
        write_new_json(root/'source-export-entry-intent.json', {'materials_sha256': context.materials_sha256,
            'source_root': str(source_root), 'source_namespace': binding.physical_namespace,
            'package': package, 'capacity': capacity, 'read_only': True, 'no_business_admission': True})
        initial_identity = gate('before-export')
        result = export_source(runner, context, source_root, root/'source-originals', close_check=closure)
        qualify(context, entry); loaded_sources(context, qualified)
        closure()
        return result
    except BaseException as error:
        failure = error
        raise
    finally:
        closure_error = None
        try:
            _transport_closed(vm, context, 'vm'); _transport_closed(service, context, 'service')
        except BaseException as error:
            closure_error = repr(error)
        # A received response with failed local audit can still have an
        # actually waited bounded writer. Keep these two facts distinct.
        writers_ended = (vm.responsibility()['host_writers_ended']
                         and service.responsibility()['host_writers_ended'])
        try:
            write_new_json(root/'source-export-entry-terminal.json', {
                'passed': result is not None and failure is None and closure_error is None,
                'original_error': repr(failure) if failure else None, 'closure_error': closure_error,
                'read_only': True, 'guest_mutations': 0, 'new_formal_credit': 0,
                'host_writers_ended': writers_ended,
                'transport_audit_safe': vm.audit_safe and service.audit_safe,
                'transport_closure_resolved': closure_error is None,
                'source_namespace': binding.physical_namespace})
        except BaseException as error:
            if failure is not None: failure.add_note('source export entry terminal failed: '+repr(error))
            else: raise
        if failure is None and closure_error is not None:
            raise suite.SuiteError('read-only export transport closure unresolved: '+closure_error)
