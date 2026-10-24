import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_linux_runtime as L
class ContractTests(unittest.TestCase):
 def test_cases_are_declared_and_input_is_structured(self):
  self.assertEqual(('LINUX-SINGLEHOST','LINUX-DEPLOY-UPDATE'),L.CASES)
  with self.assertRaises(ValueError):L.run('LINUX-SINGLEHOST',ROOT/'Logs'/'should-not-exist',{})
class ControllerTruthTests(unittest.TestCase):
 def proof(self,name):
  import os
  root=Path(os.environ['FN_COMPAT_CHECK_DIR'])/name
  root.mkdir(parents=True)
  return root
 def test_comment_multihost_and_no_traffic_cannot_pass(self):
  import json
  import acceptance_linux_runtime_oracles as oracle
  root=self.proof('comment-no-traffic')
  config=root/'config.ini'
  config.write_text('[Diverter]\nNetworkMode: SingleHost\n# MultiHost not executed\n')
  value={'schema':L.SCHEMA,'case':'LINUX-SINGLEHOST','fixture':True,'mode':'singlehost',
   'config':str(config),'rules':{'v4':[['iptables','unrelated']], 'v6':[['ip6tables','unrelated']]},
   'before':{'rules':0},'after':{'rules':0},'cleanup':{'stopped':True,'network_restored':True}}
  (root/'linux-result.json').write_text(json.dumps(value))
  rows,clean,detail=oracle.evaluate(ROOT,root,'LINUX-SINGLEHOST',allow_fixture=True)
  self.assertFalse(clean,detail)
 def test_removed_fixture_label_and_no_runtime_cannot_earn_native(self):
  import json
  import acceptance_linux_runtime_oracles as oracle
  root=self.proof('removed-fixture-native')
  config=root/'config.ini';config.write_text('[Diverter]\nNetworkMode: SingleHost\n# MultiHost\n')
  value={'schema':L.SCHEMA,'case':'LINUX-SINGLEHOST','mode':'singlehost','config':str(config),
   'rules':{'v4':[['iptables','anything']], 'v6':[['ip6tables','anything']]},
   'before':{'rules':0},'after':{'rules':0},'cleanup':{'stopped':True,'network_restored':True}}
  (root/'linux-result.json').write_text(json.dumps(value))
  rows,clean,detail=oracle.evaluate(ROOT,root,'LINUX-SINGLEHOST',allow_fixture=False)
  self.assertFalse(clean,detail)
 def test_old_handwritten_receipt_no_update_or_rollback_cannot_pass(self):
  import json
  import acceptance_linux_runtime_oracles as oracle
  root=self.proof('old-receipt')
  package=root/'package';package.mkdir();(package/'manifest.json').write_text('{}')
  token=root/'target/etc/fakenet-ng-linux/token';token.parent.mkdir(parents=True)
  token.write_text('z'*65);token.chmod(0o600)
  receipt=root/'receipt.json';receipt.write_text(json.dumps({'phase':'completed','operation':'old-op',
   'manifest':L.sha(package/'manifest.json'),'originals':{'nonexistent':'unverified'}}))
  value={'schema':L.SCHEMA,'case':'LINUX-DEPLOY-UPDATE','fixture':True,
   'receipt':str(receipt),'inputs':{'install_package':str(package),'operation':'old-op','root':str(root/'target')},
   'cleanup':{'stopped':True,'network_restored':True}}
  (root/'linux-result.json').write_text(json.dumps(value))
  rows,clean,detail=oracle.evaluate(ROOT,root,'LINUX-DEPLOY-UPDATE',allow_fixture=True)
  self.assertFalse(clean,detail)
 def test_bad_identity_and_missing_config_refused_before_output(self):
  root=self.proof('input-preflight');out=root/'output'
  inputs={'candidate_id':'bad','source_commit':'g'*40,'package_sha256':'z'*64,'execution_id':'id'}
  with self.assertRaises(ValueError):L.run('LINUX-SINGLEHOST',out,inputs)
  self.assertFalse(out.exists(),'invalid request created output before all inputs validated')

if __name__=='__main__':unittest.main()
