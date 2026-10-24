import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_linux_runtime as L, acceptance_linux_runtime_oracles as O
class LinuxTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def inputs(self,case):
  return {'candidate_id':'linux-fixture','source_commit':'a'*40,'package_sha256':'b'*64,'execution_id':'linux-fixture-01','fixture':True}
 def test_singlehost_real_policy_and_oracle(self):
  root=self.base/'case';cfg=self.base/'default.ini';cfg.write_text('[Diverter]\nNetworkMode: SingleHost\n# NetworkMode: MultiHost\nLinuxRestrictInterface: eth0\nLinuxControlEndpoints: 192.0.2.1:2222\n')
  inputs=self.inputs('LINUX-SINGLEHOST');inputs.update(config=str(cfg),mode='singlehost',control_ip='192.0.2.1',control_port=2222)
  value=L.run('LINUX-SINGLEHOST',root,inputs)
  self.assertTrue(value['rules']['v4']);self.assertTrue(value['rules']['v6'])
  rows,clean,detail=O.evaluate(ROOT,root,'LINUX-SINGLEHOST',allow_fixture=True);self.assertTrue(clean,detail)
 def test_input_refusal_and_deploy_identity_require_package(self):
  with self.assertRaises(ValueError):L.run('LINUX-SINGLEHOST',self.base/'bad',{})
  inputs=self.inputs('LINUX-DEPLOY-UPDATE');inputs.update(root=str(self.base/'root'),operation='op-1')
  with self.assertRaises(ValueError):L.run('LINUX-DEPLOY-UPDATE',self.base/'deploy',inputs)
if __name__=='__main__':unittest.main()
