import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_linux_runtime as L, acceptance_linux_runtime_oracles as O, acceptance_native as N
class LinuxTests(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup); self.base=Path(self.t.name)
 def test_cases(self):
  for case in L.CASES:
   with self.subTest(case=case):
    out=self.base/case; L.run(case,out,memory_mode=True); rows,clean,detail=O.evaluate(ROOT,out,case,allow_fixture=True); self.assertTrue(clean,detail); self.assertEqual('pass',N._judge_rows(rows,L.CHECKS[case])['verdict'])
 def test_bad_receipt(self):
  out=self.base/'bad'; L.run('LINUX-DEPLOY-UPDATE',out,memory_mode=True); (out/'receipt.json').write_text(json.dumps({'phase':'failed'})); rows,clean,detail=O.evaluate(ROOT,out,'LINUX-DEPLOY-UPDATE',allow_fixture=True); self.assertFalse(clean); self.assertNotEqual('pass',N._judge_rows(rows,L.CHECKS['LINUX-DEPLOY-UPDATE'])['verdict'])
if __name__=='__main__': unittest.main()
