import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_manual as M, acceptance_manual_oracles as O, acceptance_native as N
def inputs(case,root,responsea='192.0.2.55'):
 return {'schema':'fakenet.manual-input.v1','case':case,'candidate_id':'fixture','source_commit':'a'*40,
  'package_sha256':'b'*64,'execution_id':'exec-0001','config':str(root/'config'),'owned_root':str(root),'responsea':responsea}
class ManualTests(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup); self.base=Path(self.t.name)
 def test_ncsi_and_raw_date_real_product_functions(self):
  out=self.base/'ncsi'; M.run('GAP-NCSI',out,inputs('GAP-NCSI',out),memory_mode=True); rows,clean,detail=O.evaluate(ROOT,out,'GAP-NCSI',inputs('GAP-NCSI',out),allow_fixture=True); self.assertTrue(clean,detail); self.assertEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-NCSI'])['verdict'])
  out=self.base/'raw'; M.run('GAP-RAW-DATE',out,inputs('GAP-RAW-DATE',out),memory_mode=True); rows,clean,detail=O.evaluate(ROOT,out,'GAP-RAW-DATE',inputs('GAP-RAW-DATE',out),allow_fixture=True); self.assertTrue(clean,detail); self.assertEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-RAW-DATE'])['verdict'])
 def test_bad_dns_and_raw_content(self):
  out=self.base/'ncsi-bad'; M.run('GAP-NCSI',out,inputs('GAP-NCSI',out),memory_mode=True); p=next((out).glob('response-udp-0.bin')); p.write_bytes(b'bad'); rows,clean,detail=O.evaluate(ROOT,out,'GAP-NCSI',inputs('GAP-NCSI',out),allow_fixture=True); self.assertFalse(clean); self.assertNotEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-NCSI'])['verdict'])
  out=self.base/'raw-bad'; M.run('GAP-RAW-DATE',out,inputs('GAP-RAW-DATE',out),memory_mode=True); p=out/'raw-response.bin'; p.write_bytes(p.read_bytes()+b'x'); rows,clean,detail=O.evaluate(ROOT,out,'GAP-RAW-DATE',inputs('GAP-RAW-DATE',out),allow_fixture=True); self.assertFalse(clean); self.assertNotEqual('pass',N._judge_rows(rows,M.CHECKS['GAP-RAW-DATE'])['verdict'])
 def test_unimplemented_cases_do_not_return_pass(self):
  for case in M.CASES:
   if case in ('GAP-NCSI','GAP-RAW-DATE'): continue
   with self.assertRaises(NotImplementedError): M.run(case,self.base/case,inputs(case,self.base/case),memory_mode=True)
if __name__=='__main__': unittest.main()
