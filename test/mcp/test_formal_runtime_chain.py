"""Original failure chains; full positive preparation/VM chain remains unverified.

No successful preparation, row, verifier or recovery function is substituted.
The host/Windows environments are controlled; these tests give no formal credit.
"""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from test_formal_runtime_context import materials
from test_formal_runtime_prepare import prepared, repin
from test_formal_runtime_entry import config_prepared, entry_material
from test_formal_runtime_instance import full_preflight_environment
from test_formal_runtime_coordinator import environment
import scenario_suite as suite
import formal_batch_v3 as batch


def test_public_batch_failed_original_preparation_stops_before_all_business(entry_material,tmp_path):
    repo,material,pin,data,_=entry_material
    entry=repo/'test/mcp/acceptance/run_formal_completion.py'
    code='import runpy,shutil,sys; from types import SimpleNamespace; shutil.disk_usage=lambda _:SimpleNamespace(free=100*2**30); sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name="__main__")'
    command=[sys.executable,'-B','-c',code,str(entry.parent),str(entry),'--materials-json',str(material),
             '--materials-sha256',pin,'--repository-root',str(repo),'run-batch','--batch-id','benign-00']
    completed=subprocess.run(command,cwd=repo,capture_output=True,text=True,timeout=480)
    (tmp_path/'batch.stdout').write_text(completed.stdout);(tmp_path/'batch.stderr').write_text(completed.stderr)
    assert completed.returncode==4 and 'original independent preparation audit failed' in completed.stdout
    root=Path(data['audit_root'])
    terminal=json.loads((root/'preparation-terminal.json').read_bytes())
    assert terminal['passed'] is False and terminal['VM_calls']==terminal['new_formal_credit']==0
    assert terminal['host_audit_processes_waited'] is True and len(terminal['audits'])==1
    assert terminal['audits'][0]['exit_code']!=0
    assert Path(terminal['audits'][0]['stderr']['path']).is_file()
    assert not (root/'prepare-spike-only.intent.json').exists()
    assert not (root/'preparation-result.json').exists()
    assert not (root/'new-batch-audit-intent.json').exists()
    assert not Path(data['evidence_root']).exists()


@pytest.mark.parametrize('failure',['baseline-first-nonpass','unknown-SCM'])
def test_actual_original_rows_stop_and_batch_finally_preserves_exact_recovery(environment,failure):
    context,r,store,state,captures,co,model,calls,processes=environment
    originals=(suite.p7_capture_begin,suite.p7_capture_end,suite.reconcile_timed_out_command,r._run_one)
    if failure=='unknown-SCM':model['unknown_SCM']=True
    rows=[row for row in r.manifest()['scenarios'] if row['fault_class'] is None][:2]
    argv=Path(context.materials['suite_argv']['benign']['path']);args=batch.load_suite_args(argv)
    with co.installed():
        terminal=batch.run_batch(r,args,argv,'original-failure-chain',rows,r.manifest(),
            {'passed':False,'deferred_until_enabled_instance':True},instance_gate=co.batch_gate)
    assert terminal['passed'] is False and terminal['stop_reason']
    assert rows[1]['scenario_id'] in terminal['not_executed']
    assert not r._result_path(rows[1]['scenario_id']).exists()
    assert not captures.owned and all(process.poll() is not None for process in processes)
    assert (suite.p7_capture_begin,suite.p7_capture_end,suite.reconcile_timed_out_command,r._run_one)==originals
    recovery=json.loads((r.root/'formal-batches/original-failure-chain/recovery.json').read_bytes())
    assert recovery['status']=='failed' and recovery['stop_reason']==terminal['stop_reason']
    assert not (r.root/'host-source-index.json').exists()
    if failure=='unknown-SCM':
        assert model['scm_calls']==1 and not state.safe and not state.admission_ready
        assert not co.admitted and not processes
        assert 'blind restore mutation withheld' in terminal['ipc_evidence']['disabled']['error']
        assert not r._result_path(rows[0]['scenario_id']).exists()
    else:
        assert model['scm_calls']==2 and len(co.admitted)==2 and state.safe
        assert all(item['passed'] for item in co.admitted)
        assert not r.service.owned and not list(store.custom_root.glob('sst-*.ini'))
