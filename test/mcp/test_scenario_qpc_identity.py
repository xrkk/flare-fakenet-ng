"""Synthetic identity negatives never qualify a live QPC acceptance result."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import uuid

import pytest

spec = importlib.util.spec_from_file_location(
    'scenario_qpc_identity', Path(__file__).parent / 'acceptance' / 'scenario_qpc_identity.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DiagnosticIdentityError = module.DiagnosticIdentityError
check_provenance = module.check_provenance
FILETIME_EPOCH_TICKS = module.FILETIME_EPOCH_TICKS


def evidence():
    nonce, capture_run, managed_run, candidate = 'nonce-1', 'nonce-1:run-01', 'managed-1', 'candidate-1'
    boot_guid = uuid.UUID('11111111-2222-3333-4444-555555555555')
    raw = boot_guid.bytes_le + (2).to_bytes(4, 'little') + bytes(4) + (9).to_bytes(8, 'little')
    boot = dict(information_class=90, ntstatus=0, return_length=32, buffer_length=32,
                raw_hex=raw.hex(), boot_identifier=str(boot_guid),
                firmware_type=2, boot_flags=9,
                layout='phnt:SYSTEM_BOOT_ENVIRONMENT_INFORMATION:win10-19045-x64')
    def identity(run, pid, created, collector=None):
        row = dict(schema='sst.native-identity.v1', supported=True, run_id=run,
                   nonce=nonce, candidate_id=candidate, boot=deepcopy(boot), pid=pid,
                   boot_layout=boot['layout'],
                   creation_filetime_100ns=created, qpc_frequency=10_000_000,
                   vm_identity={'computer_name': 'WIN10', 'machine_guid': 'machine-1'})
        if collector is not None:
            row['collector_pid'] = collector
        return row
    capture = dict(capture_run_id=capture_run, nonce=nonce, candidate_id=candidate,
                   native_identity_before=identity(capture_run, 99, 400),
                   native_identity_after=identity(capture_run, 101, 500),
                   clock_before={'stopwatch_frequency': 10_000_000},
                   clock_after={'stopwatch_frequency': 10_000_000})
    ready = dict(nonce=nonce, pid=1572, creation_ticks=FILETIME_EPOCH_TICKS + 1000,
                 native_identity=identity(capture_run, 1572, 1000))
    established = dict(pid=1572, nonce=nonce)
    action = dict(run_id=managed_run, nonce=nonce, pid=8024,
                  native_identity={'before': identity(managed_run, 8024, 2000),
                                   'after': identity(managed_run, 8024, 2000)},
                  clock_observations={key: dict(supported=True, pid=8024,
                                               qpc_frequency=10_000_000,
                                               qpc_before=20, qpc_after=21)
                                      for key in ('before', 'after')})
    header = dict(ReservedFlags=1, PerfFreq=10_000_000, BootTime=1234,
                  EventsLost=0, BuffersLost=0)
    return [capture, ready, None, established, action, header,
            candidate, managed_run, 8024, 2000]


def test_consistent_identity_is_diagnostic_only():
    assert check_provenance(*evidence())['status'] == 'IDENTITY_CONSISTENT_DIAGNOSTIC_ONLY'


@pytest.mark.parametrize('mutation', [
    lambda x: x[0]['native_identity_after']['boot'].update(boot_identifier='other'),
    lambda x: x[4]['native_identity']['before'].update(pid=9000),
    lambda x: x[4]['native_identity']['after'].update(creation_filetime_100ns=3000),
    lambda x: x[4]['native_identity']['after'].update(qpc_frequency=1),
    lambda x: x[4].update(nonce='other'),
    lambda x: x[0]['native_identity_before'].update(supported=False),
    lambda x: x[5].update(PerfFreq=1),
    lambda x: x[1]['native_identity'].update(pid=17),
])
def test_cross_source_splices_rejected(mutation):
    rows = evidence()
    mutation(rows)
    with pytest.raises(DiagnosticIdentityError):
        check_provenance(*rows)


def test_b3_must_bind_real_child_and_distinguish_wrapper():
    rows = evidence()
    rows[2] = dict(pid=200, nonce='nonce-1',
                   creation_ticks=FILETIME_EPOCH_TICKS + 3000,
                   native_identity=deepcopy(rows[1]['native_identity']))
    rows[2]['native_identity'].update(pid=200, creation_filetime_100ns=3000,
                                      collector_pid=1572)
    rows[3]['pid'] = 200
    assert check_provenance(*rows)['probe_pid'] == 200
    rows[2]['native_identity']['pid'] = 1572
    with pytest.raises(DiagnosticIdentityError):
        check_provenance(*rows)
