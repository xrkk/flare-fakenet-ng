import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_linux_runtime as L
class LinuxTests(unittest.TestCase):
 def test_unimplemented(self):
  with tempfile.TemporaryDirectory() as t:
   for case in L.CASES:
    with self.assertRaises(NotImplementedError): L.run(case,Path(t)/case,memory_mode=True)
if __name__=='__main__': unittest.main()
