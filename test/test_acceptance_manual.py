import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M, acceptance_manual_oracles as O, acceptance_native as N
class ManualTests(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup); self.base=Path(self.t.name)
 def test_all_cases(self):
  for case in M.CASES:
   with self.subTest(case=case):
    out=self.base/case; M.run(case,out,memory_mode=True); rows,clean,detail=O.evaluate(ROOT,out,case,M.CHECKS[case],allow_fixture=True); self.assertTrue(clean,detail); self.assertEqual('pass',N._judge_rows(rows,M.CHECKS[case])['verdict'])
 def test_bad_content(self):
  out=self.base/'bad'; M.run('GAP-NCSI',out,memory_mode=True); (out/'dns.jsonl').write_text(json.dumps({'q':'dns.msftncsi.com','a':['198.51.100.1']})+'\n'); rows,clean,detail=O.evaluate(ROOT,out,'GAP-NCSI',M.CHECKS['GAP-NCSI'],allow_fixture=True); self.assertFalse(clean); self.assertNotEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-NCSI'])['verdict'])
if __name__=='__main__': unittest.main()
