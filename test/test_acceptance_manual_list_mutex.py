import contextlib,io,json,os,socket,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance as A
import acceptance_manual as M,acceptance_manual_oracles as O,acceptance_native as N
class ListMutexTests(unittest.TestCase):
 def setUp(self):
  self.base=Path(os.environ.get('FN_MANUAL_CHECK_DIR',str(ROOT/'Logs'/'manual-list-mutex-tests')))/'retained'/self.id().split('.')[-1]
  self.base.mkdir(parents=True,exist_ok=False)
 def inputs(self,out):
  return {'schema':'fakenet.manual-input.v1','case':'GAP-LIST-MUTEX','candidate_id':'list-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'list-fixture-01','config':str(out/'config'),'owned_root':str(out),'fixture':True}
 def test_real_listener_meta_black_white_and_mutex(self):
  out=self.base/'case';inputs=self.inputs(out);value=M.run('GAP-LIST-MUTEX',out,inputs)
  rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True)
  self.assertTrue(clean,detail);self.assertEqual(['blacklist','whitelist','mutex'],[x['id'] for x in rows]);self.assertTrue(N._judge_rows(rows,M.CHECKS['GAP-LIST-MUTEX'])['verdict']=='pass')
 def test_tampered_observation_is_rejected(self):
  out=self.base/'bad';inputs=self.inputs(out);M.run('GAP-LIST-MUTEX',out,inputs);p=out/'manual-result.json';v=json.loads(p.read_text());v['list_mutex']['observations'][0]['hit']=False;p.write_text(json.dumps(v));rows,clean,detail=O.evaluate(ROOT,out,'GAP-LIST-MUTEX',inputs,allow_fixture=True);self.assertFalse(clean,detail)

 def test_central_driver_registration(self):
  self.assertEqual('manual-list-mutex',N.driver_table(ROOT)['manual-list-mutex']['production_kind'])
  catalog=json.loads((ROOT/'docs/acceptance/catalog.json').read_text());row=next(c for s in catalog['suites'] for c in s.get('cases') or [] if c['id']=='GAP-LIST-MUTEX');self.assertEqual('manual-list-mutex',row['native_driver'])
if __name__=='__main__':unittest.main()
