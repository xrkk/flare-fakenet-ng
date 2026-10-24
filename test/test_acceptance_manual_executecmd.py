import json,os,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class _Proc:
 pid=43210
class ExecuteCmdTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-EXECUTECMD','candidate_id':'cmd-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'cmd-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_parser_command_first_session_and_negatives(self):
  out=self.base/'case';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()) as popen:value=M.run('GAP-EXECUTECMD',out,inputs)
  self.assertEqual(1,popen.call_count)
  args,popen_kwargs=popen.call_args
  self.assertIn('cmd.exe /c echo 1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080',args[0])
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['command','first-connection','non-connection'],[x['id'] for x in rows]);self.assertEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-EXECUTECMD'])['verdict'])
 def test_original_negatives_and_tamper(self):
  out=self.base/'bad';inputs=self.inputs(out)
  with mock.patch('subprocess.Popen',return_value=_Proc()):M.run('GAP-EXECUTECMD',out,inputs)
  p=out/'manual-result.json';v=json.loads(p.read_text());v['executecmd']['command']='foreign';p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-EXECUTECMD',inputs,allow_fixture=True);self.assertFalse(clean,detail)
 def test_central_driver_registration(self):
  self.assertEqual('manual-executecmd',N.driver_table(ROOT)['manual-executecmd']['production_kind'])
if __name__=='__main__':unittest.main()
