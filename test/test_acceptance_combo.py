import json,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_policy as P, acceptance_policy_oracles as O, acceptance_native as N
CHECKS=['exact_domain','wildcard_domain','tls_application','reviewed_ip_tls','sink_tcp','sink_udp','port_80_denied','port_444_denied','udp443_denied','other_ip_denied','adjacent_denied','route_restore']
class ComboTests(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def run_combo(self): out=self.base/'combo';P.run('combo',out,substitute=True);return out
 def test_combo_has_exact_twelve_and_consumes_denied_dns(self):
  self.assertEqual(CHECKS,P.CHECKS['combo'])
  out=self.run_combo();rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertTrue(clean);self.assertEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])
  result=json.loads((out/'policy-result.json').read_text());self.assertEqual(12,len(result['checks']));self.assertTrue(any((out/'probes'/'sink_tcp-dns.json').is_file() for _ in [0]));self.assertEqual(6,len(P.CHECKS['combined']))
 def test_old_combined_checks_remain_six(self):
  self.assertEqual(6,len(P.CHECKS['combined']))
 def test_wrong_nonce_and_config_fail(self):
  out=self.run_combo();v=json.loads((out/'policy-result.json').read_text());v['attempts'][0]['nonce']='wrong';(out/'policy-result.json').write_text(json.dumps(v));rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertFalse(clean);self.assertNotEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])
  out=self.base/'combo2';P.run('combo',out,substitute=True);p=out/'policy.ini';t=p.read_text().replace('ExternalAccessPolicy = EgressControl','ExternalAccessPolicy = Off');p.write_text(t);v=json.loads((out/'policy-result.json').read_text());v['config']['sha256']=P.sha256(p);(out/'policy-result.json').write_text(json.dumps(v));rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertFalse(clean);self.assertNotEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])

if __name__=='__main__':unittest.main()
