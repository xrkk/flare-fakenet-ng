#!/usr/bin/env python3
"""Verify PLAN-CHANGE-008's exact count mapping and obligation transfer."""
import argparse
import json
from pathlib import Path
import re
import subprocess

REPO = Path(__file__).resolve().parents[3]
SOURCES = {'S2': 'ec4f025a5926be82aa1728eff10dfef39d8a827a',
           'S3': 'd8987f5be98269ee8465f3696f9a02bf39088106'}

def verify(path):
    checks = []
    def check(name, passed):checks.append(dict(id=name, passed=bool(passed)))
    text = Path(path).read_text(encoding='utf-8')
    blocks = re.findall(r'```json\s*\n(.*?)\n```', text, re.S)
    contract = json.loads(next(b for b in blocks if 'sst.plan-change-008.v1' in b))
    check('schema', contract.get('schema') == 'sst.plan-change-008.v1')
    check('old_mapping', contract.get('old') == {'normal-builtin':50,'normal-custom':50,'fault-per-class':10,'fault-classes':5})
    check('new_mapping', contract.get('new') == {'normal-builtin':3,'normal-custom':2,'fault-per-class':1,'fault-classes':5})
    check('suite_obligations', contract.get('suite') == {'total':100,'benign':85,'fault':15,'fault-per-class':3,'tools':15,'tools-per-scenario-min':10,'scenarios-per-tool-min':5})
    required = {'five_sections','lock_tree','continuous_probe','same_candidate_continuity','traffic','fault_incident','actual_coverage'}
    obligations = contract.get('obligations',{})
    check('bidirectional_acc_mapping',set(obligations)==required and all(isinstance(v,list) and v and all(re.fullmatch(r'ACC-SST-0[4-9]',a) for a in v) for v in obligations.values()))
    check('six_counts', contract.get('six_counts') == ['应承接','完整','未落点','语义弱化','不可验收','失效或复核条件缺失'])
    check('approval_field', '审批栏' in text and '用户执行授权' in text and '第三方审核结论' in text)
    check('source_identity',contract.get('sources')==SOURCES)
    for key,blob in SOURCES.items():
        raw = subprocess.check_output(['git','cat-file','blob',blob],cwd=REPO).decode('utf-8')
        check(key+'_original_counts',('100 次正常矩阵' in raw and '五类×10' in raw) if key=='S2' else ('共 100 份' in raw and '共 50 份' in raw))
    return dict(passed=sum(c['passed'] for c in checks),failed=sum(not c['passed'] for c in checks),checks=checks)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('record');a=p.parse_args()
    try:r=verify(a.record)
    except (OSError,ValueError,StopIteration,subprocess.CalledProcessError) as e:r=dict(passed=0,failed=1,checks=[dict(id='input',passed=False,reason=str(e))])
    print(json.dumps(r,ensure_ascii=False));return 3 if r['failed'] else 0
if __name__=='__main__':raise SystemExit(main())
