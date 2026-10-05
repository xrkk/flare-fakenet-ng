"""Original single-batch assembly, with no audit adapter in this interpreter.

All instance admission and row adjudication stay in original Suite/Batch and
the scoped Coordinator. This module never schedules a default matrix/retry.
"""
from dataclasses import dataclass

import formal_batch_v3 as batch
import scenario_suite as suite

from .clients import FreshClient
from .config_ownership import prestart_gate
from .context import checked_record
from .coordinator import Coordinator
from .dns_capture import Captures
from .instance import Responsibility, ProtectedVm, ProtectedService, bind_namespace
from .preparation import execution_plan, configuration_plan
from .preparation_receipt import PreparedExecution
from .producer import register_execution
from .runner import BatchRequest, single_batch_request, require, _capacity
from .command_transport import write_new_json
from .current_source import _transport_closed
from .source import export_current_source


@dataclass
class Execution:
    context: object
    request: BatchRequest
    runner: object
    state: Responsibility
    vm: FreshClient
    service: FreshClient
    captures: Captures
    coordinator: Coordinator


def _assemble(context, request):
    """Private construction seam; no RPC or instance admission occurs here."""
    context.revalidate()
    require(isinstance(request, BatchRequest) and request.context.materials_sha256 == context.materials_sha256
            and request.context.evidence_root == context.evidence_root,
            'single-batch request belongs to a different execution')
    execution_plan(context)
    args = request.suite_args()
    require(args.guest_work_root == suite.E_GUEST_WORK_ROOT,
            'formal physical namespace requires original E-drive guest work root')
    require(bool(args.target_base_url) and bool(args.win10vm_mcp),
            'original explicit service and VM endpoints required for execution')
    require(not context.evidence_root.exists(), 'business output exists; no implicit resume')
    register_execution(context)
    runner = suite.Suite(args)
    runner.generate()
    state = Responsibility()
    vm = FreshClient(runner.vm, context, state)
    service = FreshClient(runner.service, context, state)
    runner.vm = ProtectedVm(vm, context, state)
    runner.service = ProtectedService(service, context, state)
    bind_namespace(runner, context)
    captures = Captures(runner, context)
    coordinator = Coordinator(runner, state, captures, context)
    return Execution(context, request, runner, state, vm, service, captures, coordinator)


def _configuration_closed(execution):
    runner, state = execution.runner, execution.state
    owned = getattr(runner.service, 'owned', None)
    require(isinstance(owned, dict), 'current-execution configuration ownership absent')
    require(not owned, 'original cleanup retains owned configurations; no blind/prune cleanup')
    audit = runner.service.audit_responsibility()
    require(audit['audit_safe'] and audit['mutation_safe'] and audit['inflight_mutation'] is None,
            'configuration mutation/audit outcome unresolved')
    require(state.safe and state.admission_ready and not execution.coordinator.fault_restore_pending,
            'native instance/restoration responsibility unresolved')
    status = runner._status(30)
    require(status.get('state') == 'stopped' and not status.get('run_id') and not status.get('controller')
            and status.get('config_identity', {}).get('sha256') == execution.context.candidate_identity['default_sha256'],
            'original final service is not stopped/ownerfree/default')
    return status


def run_batch(prepared, explicit_batch_id):
    """Run one original batch, retain failures, export only exact closed source.

Independent rejudging/credit publication must still follow this handoff in a
separate interpreter; successful online storage/export alone is not credit.
"""
    require(isinstance(prepared, PreparedExecution), 'independently bound complete preparation required')
    prepared = prepared.revalidate()
    context = prepared.context
    request = single_batch_request(context, explicit_batch_id)
    # Fresh resource and frozen config semantics immediately precede creation.
    _capacity(context, len(request.scenario_ids))
    configuration_plan(context)
    execution, primary, terminal, exported, final_status = None, None, None, None, None
    closures, secondary_errors = [], []
    try:
        execution = _assemble(context, request)
        runner = execution.runner
        prestart_gate(runner, context)
        with execution.coordinator.installed():
            selected, manifest, preflight = batch.validate_inputs(runner, runner.args, request.batch_id,
                list(request.scenario_ids), evidence_root=context.evidence_root.parent, defer_preflight=True)
            terminal = batch.run_batch(runner, runner.args, checked_record(dict(request.argv_record)),
                request.batch_id, selected, manifest, preflight, instance_gate=execution.coordinator.batch_gate)
        if terminal.get('passed') is not True:
            primary = suite.SuiteError('original batch stopped: '+str(terminal.get('stop_reason')))
        execution.captures.close()
        final_status = _configuration_closed(execution)
    except BaseException as error:
        if primary is None: primary = error
        else:
            secondary_errors.append({'phase': 'final-original-configuration', 'error': repr(error)})
            primary.add_note('final original configuration failed: '+repr(error))
    finally:
        if execution is not None:
            try: closures = execution.captures.close()
            except BaseException as error:
                secondary_errors.append({'phase': 'host-capture-close', 'error': repr(error)})
                if primary is None: primary = error
                else: primary.add_note('host capture close failed: '+repr(error))
            try:
                # The final original backup names are known only after the
                # actual fault/IPC ledger; publish once rather than rewriting.
                write_new_json(context.evidence_root/'execution-context.json', {
                    'backup_names': sorted(execution.coordinator.backup_names),
                    'materials_sha256': context.materials_sha256,
                    'batch_id': request.batch_id, 'SCM_cycles': execution.coordinator.seq,
                    'responsibility_safe': execution.state.safe,
                    'guest_business_closed': final_status is not None,
                    'final_original_status': final_status,
                    'no_formal_credit': True})
                require(not execution.captures.owned, 'owned host capture writer remains active')
                require(final_status is not None,
                        'guest business/default/owner closure unresolved; current export withheld')
                _transport_closed(execution.vm, context, 'vm')
                _transport_closed(execution.service, context, 'service')
                # A current source handoff is not a historical authority and
                # never makes unknown captures closed. Original gates apply.
                exported = export_current_source(execution.runner, context, execution.service,
                                                 context.evidence_root/'source-originals')
            except BaseException as error:
                secondary_errors.append({'phase': 'exact-current-export', 'error': repr(error)})
                if primary is None: primary = error
                else: primary.add_note('exact current export failed: '+repr(error))
            record = {'schema': 'fakenetng.formal-runtime.batch-handoff.v1',
                'materials_sha256': context.materials_sha256, 'batch_id': request.batch_id,
                'scenario_ids': list(request.scenario_ids), 'original_batch_terminal': terminal,
                'original_primary_error': repr(primary) if primary else None,
                'secondary_errors': secondary_errors, 'current_export': exported,
                'final_original_status': final_status, 'host_capture_close': closures,
                'host_capture_writers_ended': not bool(execution.captures.owned),
                'VM_responsibility_safe': execution.state.safe,
                'admission_ready': execution.state.admission_ready,
                'independent_original_rejudge_required': True, 'new_formal_credit': 0}
            try: write_new_json(context.evidence_root/'batch-handoff.json', record)
            except BaseException as error:
                if primary is None: primary = error
                else: primary.add_note('batch handoff audit failed: '+repr(error))
    if primary is not None:
        raise primary
    require(terminal is not None and terminal.get('passed') is True,
            'original batch stopped on a nonpass; no later batch or new credit')
    from .sealing import seal
    index = seal(execution, record)
    # No further writes to the business root occur after sealing.
    return {'handoff': record, 'source_index': index}
