import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_linux_runtime as L
class ContractTests(unittest.TestCase):
 def test_cases_are_declared_and_input_is_structured(self):
  self.assertEqual(('LINUX-SINGLEHOST','LINUX-DEPLOY-UPDATE'),L.CASES)
  with self.assertRaises(ValueError):L.run('LINUX-SINGLEHOST',ROOT/'Logs'/'should-not-exist',{})
if __name__=='__main__':unittest.main()
