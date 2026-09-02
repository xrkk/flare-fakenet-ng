# Copyright 2026 Google LLC
"""Lifecycle test double for the P02 domain tools (no real FakeNet-NG).

Implements the state machine surface the tools exercise:
``stopped -> starting -> healthy -> (degraded | failed) -> stopped``.
P03 replaces this module with the real supervisor without touching the
tool contracts.
"""

import threading
import time

TRANSITION_SECONDS = 0.05


class LifecycleDouble:

    def __init__(self):
        self.fail_next_start = None  # reason string or None
        self.degrade_after_start = False
        self.stop_blocker = None  # callable invoked during stop
        self._lock = threading.Lock()

    # -- tool-facing operations -------------------------------------------
    def start(self, coordinator, controller, config_identity):
        if self.fail_next_start is not None:
            reason = self.fail_next_start
            self.fail_next_start = None
            return {'state': 'failed', 'changed': True,
                    'failure_reason': reason,
                    'run_id': None, 'controller': None,
                    'release_controller': True,
                    'config_identity': config_identity}
        time.sleep(TRANSITION_SECONDS)
        result = {
            'state': 'degraded' if self.degrade_after_start else 'healthy',
            'changed': True,
            'run_id': coordinator.new_run_id(),
            'controller': controller,
            'config_identity': config_identity,
        }
        self.degrade_after_start = False
        return result

    def stop(self, coordinator):
        if self.stop_blocker is not None:
            self.stop_blocker()
        time.sleep(TRANSITION_SECONDS)
        return {'state': 'stopped', 'changed': True, 'run_id': None,
                'failure_reason': None, 'release_controller': True}

    def restart(self, coordinator, controller, config_identity):
        stopped = self.stop(coordinator)
        started = self.start(coordinator, controller, config_identity)
        started['changed'] = True
        return started

    # -- read-side ---------------------------------------------------------
    @staticmethod
    def health_detail(state):
        return {
            'stopped': {'process_alive': False, 'init_evidence': False,
                        'probe': None},
            'starting': {'process_alive': True, 'init_evidence': None,
                         'probe': None},
            'healthy': {'process_alive': True, 'init_evidence': True,
                        'probe': 'pass'},
            'degraded': {'process_alive': True, 'init_evidence': True,
                         'probe': 'degraded'},
            'failed': {'process_alive': False, 'init_evidence': False,
                       'probe': 'fail'},
        }.get(state, {'process_alive': None, 'init_evidence': None,
                      'probe': None})
