"""The physical PktMon owner and each logical probe have separate native runs."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
from scenario_qpc_identity import check_aux_provenance, DiagnosticIdentityError  # noqa: E402
from test_scenario_qpc_identity import evidence, FILETIME_EPOCH_TICKS  # noqa: E402


def shared_case():
    capture, ready, child, established, _action, header, candidate, _run, pid, created = copy.deepcopy(evidence())
    nonce = capture['nonce']
    run = 'managed-2'
    logical = nonce + ':run-02'
    ready['native_identity']['run_id'] = logical
    ready['utc_ticks'] = 621355968000001000
    close = {'event': 'close', 'nonce': nonce, 'utc_ticks': 621355968000001500}
    capture['clock_before'].update(q0=1, q1=2)
    capture['clock_after'].update(q0=3, q1=4)
    prefix = 'evidence/sst-012/attempt-01/'
    physical = [dict(path=prefix + 'run-01/' + name, size=1, sha256='a' * 64)
                for name in ('pktmon.etl', 'pktmon.txt', 'pktmon-nic.json')]
    probe = dict(path=prefix + 'run-02/probe.jsonl', size=2, sha256='b' * 64)
    metadata = next(x for x in physical if x['path'].endswith('pktmon-nic.json'))
    owner = dict(schema='sst.scenario-physical-capture-owner.v2',
                 owner_id=nonce + ':pktmon', nonce=nonce, scenario_id='sst-012', epoch=1,
                 capture_contract='scenario-shared-v2', guest_work_root=r'E:\work',
                 tool_sha256='c' * 64, physical_files=physical,
                 run_ids=['managed-1', run], started_utc='2026-09-27T00:00:00Z',
                 stopped_utc=None)
    owner_raw=json.dumps(owner).encode()
    owner_ref=dict(path=prefix + 'physical-capture-owner.json', size=len(owner_raw),
                   sha256=hashlib.sha256(owner_raw).hexdigest())
    view = dict(schema='sst.scenario-run-capture-view.v2', owner=owner_ref,
                owner_id=owner['owner_id'], scenario_id='sst-012', attempt=1,
                run_id=run, label='run-02', nonce=nonce, capture_run_id=logical,
                guest_work_root=owner['guest_work_root'], tool_sha256=owner['tool_sha256'],
                probe_pid=ready['pid'], probe_creation_ticks=ready['creation_ticks'],
                probe=probe, physical_files=physical,
                capture_started_utc=owner['started_utc'], capture_stopped_utc=None)
    view_raw=json.dumps(view).encode()
    view_ref=dict(path=prefix + 'run-02-capture-view.json', size=len(view_raw),
                  sha256=hashlib.sha256(view_raw).hexdigest())
    launch=dict(pid=ready['pid'], creation_ticks=ready['creation_ticks'], nonce=nonce,
                capture_run_id=logical, candidate_id=candidate,
                native_identity=ready['native_identity'])
    launch_raw=json.dumps(launch).encode()
    launch_ref=dict(path=prefix + 'run-02/probe-launch.json', size=len(launch_raw),
                    sha256=hashlib.sha256(launch_raw).hexdigest())
    case=dict(schema='sst.aux-qpc-input.v1', candidate_id=candidate, run_id=run,
              nonce=nonce, files=[dict(path=x['path'],bytes=x['size'],sha256=x['sha256'])
                                  for x in physical + [probe,owner_ref,view_ref,launch_ref]],
              capture=dict(metadata_ref=dict(path=metadata['path'], byte_start=0,
                                             byte_end=1, event_key='json:'),
                           etl_path=physical[0]['path'], text_path=physical[1]['path']),
              shared_capture=dict(owner=owner_ref, view=view_ref, launch=launch_ref))
    class ManifestEvidence:
        data={owner_ref['path']:owner_raw,view_ref['path']:view_raw,
              launch_ref['path']:launch_raw}
    shared=dict(case=case,evidence=ManifestEvidence(),probe_rows=[ready,close],
                capture_interval=(0,200000))
    return [capture,ready,child,established,header,candidate,run,pid,created],shared


def test_shared_physical_and_logical_runs_bind_without_changing_markers():
    args,shared=shared_case()
    proof=check_aux_provenance(*args,shared=shared)
    assert proof['capture_run_id']=='nonce-1:run-01'
    assert proof['probe_run_id']=='nonce-1:run-02'
    assert proof['managed_run_id']=='managed-2'


@pytest.mark.parametrize('mutation', ['missing', 'epoch', 'run', 'nonce', 'probe_creation',
                                      'capture', 'interval', 'boot'])
def test_shared_binding_rejects_cross_identity_or_window(mutation):
    args,shared=shared_case()
    if mutation=='missing':shared=None
    elif mutation=='epoch':shared['case']['shared_capture']['view']['path']='evidence/sst-012/attempt-02/run-02-capture-view.json'
    elif mutation=='run':args[1]['native_identity']['run_id']='nonce-1:run-03'
    elif mutation=='nonce':args[1]['native_identity']['nonce']='other'
    elif mutation=='probe_creation':args[1]['creation_ticks']+=1
    elif mutation=='capture':shared['case']['capture']['metadata_ref']['path']='evidence/sst-012/attempt-01/other/pktmon-nic.json'
    elif mutation=='interval':shared['capture_interval']=(200001,300000)
    elif mutation=='boot':args[1]['native_identity']['boot']['boot_identifier']='other'
    with pytest.raises(DiagnosticIdentityError):
        check_aux_provenance(*args,shared=shared)
