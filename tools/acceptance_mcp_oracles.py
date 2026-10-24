"""Re-execute original MCP assertions over the closed transport bytes."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import acceptance_mcp as m


def evaluate(root,original,case,checks,expected_inputs=None,*,allow_fixture=False,subset=False):
 original=Path(original).resolve();value=m.read(original/'mcp-result.json');inputs=m.read(original/'inputs.json')
 if expected_inputs is None:raise ValueError('frozen MCP inputs required for independent judgment')
 if inputs!=expected_inputs:raise ValueError('MCP inputs differ from frozen plan')
 m.validate_inputs(inputs,case,checks,fixture=allow_fixture)
 if (value.get('schema')!=m.SCHEMA or value.get('case')!=case or value.get('identity')!=inputs['identity'] or value.get('target')!=inputs['target'] or value.get('config_identity')!=inputs['config_identity']):raise ValueError('MCP result identity differs')
 if value.get('fixture') is not False and not allow_fixture:raise ValueError('MCP fixture has no native credit')
 if (not subset and set(value.get('checks',{}))!=set(checks)) or (subset and not set(checks)<=set(value.get('checks',{}))):raise ValueError('MCP selected unit set differs')
 if m.read(original/'source-pins.json')!=m.source_pins(root):raise ValueError('MCP original source closure changed')
 if 'ACC-019' in checks:__import__('acceptance_mcp_dependencies').verify_acc008(inputs,root=root,fixture=allow_fixture)
 mods=m.modules(root);rows=[];details={};clean=True
 for unit in checks:
  if value['checks'][unit]=={'status':'not_run','result':None,'trace':None}:
   rows.append({'id':unit,'status':'not_run','reasons':['preceding unit recovery unresolved']});details[unit]=['preceding unit recovery unresolved'];clean=False;continue
  expected={'status':value['checks'][unit].get('status'),'result':'units/'+unit+'/result.json','trace':'units/'+unit+'/trace.json'}
  if value['checks'][unit]!=expected:raise ValueError('MCP unit output path changed')
  path=original/expected['result'];result=m.read(path);trace=m.read(original/expected['trace'])
  failures=mods['evidence_integrity'].validate_result(result,inputs['identity'],path.parent)
  if (trace.get('schema')!='fakenet.mcp-unit-trace.v1' or trace.get('unit')!=unit or trace.get('identity')!=inputs['identity'] or trace.get('target')!=inputs['target'] or trace.get('config_identity')!=inputs['config_identity']):failures.append('unit trace identity mismatch')
  original_not_passed=trace.get('returncode')!=0 or trace.get('error')
  if original_not_passed:failures.append('original unit did not pass')
  if unit in ('DIAGNOSTIC-NATIVE-CRASH','DIAGNOSTIC-STACKS-UNAVAILABLE','DIAGNOSTIC-UNKNOWN-CAUSE'):
   try:
    matches=[item for item in result.get('evidence',[]) if item.get('name')=='diagnostic-record']
    if len(matches)!=1:raise ValueError('single original diagnostic record required')
    record=m.read(matches[0]['path'])
    expected_class={'DIAGNOSTIC-NATIVE-CRASH':'native_crash',
                    'DIAGNOSTIC-STACKS-UNAVAILABLE':'stacks_unavailable',
                    'DIAGNOSTIC-UNKNOWN-CAUSE':'unknown_cause'}[unit]
    if record.get('class')!=expected_class:raise ValueError('diagnostic selected unit/class differs')
    __import__('acceptance_mcp_diagnostic_oracles').validate_original_record(
       record,record.get('fault_evidence'),record.get('incident_exports'),expected=inputs,root=root,transport=trace.get('records'))
   except (OSError,ValueError,KeyError,TypeError,RuntimeError) as exc:
    failures.append('original diagnostic rejudge refused: '+str(exc))
   unit_clean=trace.get('recovery_observed') is True and trace.get('recovery_error') is None
   rows.append({'id':unit,'status':'fail' if failures else 'pass','reasons':failures})
   details[unit]=failures;clean=clean and unit_clean
   continue
  # Re-run the unchanged business assertions. A forged summary or rehashed
  # failed response still reaches the original error/version/content checks.
  unit_clean=False
  replayable=not any(item not in ('result is not an unblocked pass','original unit did not pass') for item in failures)
  if replayable:
   if trace.get('unit_root')!=str(path.parent.resolve()):failures.append('original unit root differs')
   try:
    scratch=original.parent.parent/'mcp-rejudge';scratch.mkdir(exist_ok=True)
    temp=tempfile.mkdtemp(prefix='unit-',dir=scratch)
    replay=m.ReplayBoundary(trace['records'],trace['unit_root'],str((Path(temp)/'unit').resolve()))
    replayed,replay_trace=m.run_unit(unit,inputs,Path(temp)/'unit',replay,root=root,fixture=allow_fixture)
    unit_clean=replay_trace.get('recovery_observed') is True and replay_trace.get('recovery_error') is None
    if replayed['status']!='pass' or replay_trace['returncode']!=0:failures.append('original assertions reject transport contents')
   except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:failures.append('original replay refused: '+str(exc))
  status='fail' if failures else 'pass';rows.append({'id':unit,'status':status,'reasons':failures});details[unit]=failures
  clean=clean and unit_clean
 return rows,clean,details
