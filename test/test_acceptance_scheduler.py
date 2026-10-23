import os,sys,threading,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'tools'))
import acceptance_scheduler as S
class SchedulerTests(unittest.TestCase):
 def test_capacity_depth_and_bounds(self):
  self.assertEqual(1,S.worker_capacity(depth=1))
  self.assertGreaterEqual(S.worker_capacity(depth=0),1)
  self.assertLessEqual(S.worker_capacity(depth=0),2)
 def test_dependency_order_and_missing(self):
  cases=[{'id':'B','dependencies':['A']},{'id':'A'},{'id':'C','dependencies':['MISSING']}]
  order,blocked=S.ordered_cases(cases)
  self.assertEqual(['A','B'],order)
  self.assertIn('C',blocked)
 def test_safe_group_overlaps_and_other_group_serial(self):
  active=0; maximum=0; lock=threading.Lock(); events=[]
  def runner(case):
   nonlocal active,maximum
   with lock:
    active+=1; maximum=max(maximum,active); events.append(('start',case['id'],time.monotonic()))
   time.sleep(0.2)
   with lock:
    active-=1; events.append(('end',case['id'],time.monotonic()))
   return {'status':'pass'}
  cases=[{'id':'CORE-TLSHELLO'},{'id':'CORE-DUALPCAP-WRITER'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual(2,len(results)); self.assertFalse(blocked); self.assertGreaterEqual(maximum,2)
  active=0; maximum=0
  cases=[{'id':'CORE-DNS-OFFLINE'},{'id':'CORE-LISTENERS-OFFLINE'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual(2,len(results)); self.assertEqual(maximum,1)
 def test_failed_dependency_blocks_only_dependants(self):
  def runner(case):
   return {'status':'fail' if case['id']=='A' else 'pass'}
  cases=[{'id':'A'},{'id':'B','dependencies':['A']},{'id':'C'}]
  results,blocked=S.run_cases(cases,runner,capacity=2)
  self.assertEqual('fail',results['A']['status']); self.assertIn('B',blocked); self.assertEqual('pass',results['C']['status'])
 def test_nested_depth_forces_one(self):
  old=os.environ.get('FN_ACCEPTANCE_NESTED_DEPTH'); os.environ['FN_ACCEPTANCE_NESTED_DEPTH']='2'
  try: self.assertEqual(1,S.worker_capacity())
  finally:
   if old is None: os.environ.pop('FN_ACCEPTANCE_NESTED_DEPTH',None)
   else: os.environ['FN_ACCEPTANCE_NESTED_DEPTH']=old
if __name__=='__main__': unittest.main()
