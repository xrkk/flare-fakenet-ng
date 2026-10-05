"""Versioned execution identity and paired actual VM dispatch witnesses.

These records preserve producer responsibility. They neither seal an index nor
admit business, prove guest capture closure, or grant source-reader authority.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import threading
import time
import uuid

from .command_transport import write_new_json
from .context import checked_record, exact_path, file_sha256


EXECUTION_SCHEMA = 'fakenetng.formal-runtime.execution.v1'
DISPATCH_SCHEMA = 'fakenetng.formal-runtime.vm-dispatch.v1'


def file_record(path):
    path = exact_path(str(path))
    return {'path': str(path), 'size': path.stat().st_size,
            'sha256': file_sha256(path)}


def register_execution(context):
    """Write the explicit original execution once; no implicit new namespace."""
    from .source import NAMESPACE, require
    context.revalidate()
    match = NAMESPACE.fullmatch(context.physical_namespace)
    require(match is not None and match['scope'] == hashlib.sha256(
        str(context.evidence_root).encode()).hexdigest()[:12],
        'current producer namespace nonce/scope differs from original output')
    checked_record(dict(context.materials['plan']))
    record = {
        'schema': EXECUTION_SCHEMA,
        'original_execution_root': str(context.evidence_root),
        'source_root': str(context.source_root),
        'identity': dict(context.candidate_identity),
        'physical_namespace': context.physical_namespace,
        'source_nonce': match['nonce'],
        'materials': file_record(context.materials_path),
        'plan': dict(context.materials['plan']),
        'tool_commit': context.tool_source['commit'],
        'no_business_admission': True,
    }
    context.evidence_root.mkdir(parents=True, exist_ok=True)
    write_new_json(context.evidence_root/'execution-binding.json', record)
    return record


class VmJournal:
    """Keep each mapped final command paired with its actual adapter response.

    Receipt reconciliation is a separate read dispatch. A missing response is
    kept as unknown rather than silently omitted from capture ownership.
    Received responses survive local audit failure, with memory responsibility
    retained and later mutation blocked by the shared responsibility object.
    """

    def __init__(self, context, state):
        self.context = context.revalidate()
        self.state = state
        self.calls = {}
        self.audit_failures = {}
        self.audit_safe = True
        self._lock = threading.Lock()

    def dispatch(self, callback, command, timeout, *, receipt=None):
        self.context.revalidate()
        if not isinstance(command, str) or not command:
            raise ValueError('VM journal requires the exact nonempty final command')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('VM journal requires the original finite positive timeout')
        key = uuid.uuid4().hex
        root = self.context.evidence_root
        intent_path = exact_path(str(root/'VM-final-intents'/(key+'.json')))
        response_path = exact_path(str(root/'VM-final-responses'/(key+'.json')))
        terminal_path = exact_path(str(root/'VM-final-terminals'/(key+'.json')))
        intent = {
            'schema': DISPATCH_SCHEMA, 'call_id': key,
            'command': command, 'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
            'timeout': timeout, 'receipt': receipt,
            'materials_sha256': self.context.materials_sha256, 'no_replay': True,
        }
        terminal = {
            'schema': DISPATCH_SCHEMA, 'call_id': key, 'intent': str(intent_path),
            'materials_sha256': self.context.materials_sha256,
            'dispatch_started': False, 'response_known': False, 'response_persisted': False,
            'original_error': None, 'original_error_record': None,
            'response': None, 'no_mutation_replay': True,
        }
        with self._lock:
            self.calls[key] = {'intent': intent, 'terminal': terminal, 'known_original_response': None}
        outcome, primary = None, None
        try:
            intent_path.parent.mkdir(parents=True, exist_ok=True)
            write_new_json(intent_path, intent)
            # Large staged commands remain in their immutable witness file;
            # ordinary byte-transfer calls must not accumulate payloads in RAM.
            with self._lock:
                self.calls[key]['intent'] = {
                    'call_id': key, 'record': file_record(intent_path),
                    'command_sha256': intent['command_sha256'],
                }
        except BaseException as error:
            self._audit_failure(key, error)
            raise
        try:
            terminal['dispatch_started'] = True
            outcome = callback(command, timeout)
            terminal['response_known'] = True
            with self._lock:
                self.calls[key]['known_original_response'] = outcome
            return outcome
        except BaseException as error:
            primary = error
            terminal['original_error'] = repr(error)
            terminal['original_error_record'] = getattr(error, 'record', getattr(error, 'vm_record', None))
            raise
        finally:
            terminal['finished_monotonic'] = time.monotonic()
            try:
                if terminal['response_known']:
                    response_path.parent.mkdir(parents=True, exist_ok=True)
                    write_new_json(response_path, outcome)
                    terminal['response'] = file_record(response_path)
                    terminal['response_persisted'] = True
                terminal_path.parent.mkdir(parents=True, exist_ok=True)
                write_new_json(terminal_path, terminal)
                with self._lock:
                    self.calls[key]['known_original_response'] = None
            except BaseException as error:
                self._audit_failure(key, error)
                if primary is not None:
                    primary.add_note('independent VM witness audit failure: '+repr(error))

    def _audit_failure(self, key, error):
        with self._lock:
            self.audit_safe = False
            self.audit_failures[key] = repr(error)
        self.state.unknown(error)

    def responsibility(self):
        with self._lock:
            return {
                'audit_safe': self.audit_safe,
                'calls': [{'intent': dict(row['intent']), 'terminal': dict(row['terminal'])}
                          for row in self.calls.values()],
                'audit_failures': dict(self.audit_failures),
                'unknown_dispatches': [key for key, row in self.calls.items()
                                       if row['terminal']['dispatch_started'] and
                                       not row['terminal']['response_known']],
                'transport_writer_closure_not_inferred_from_response': True,
            }
