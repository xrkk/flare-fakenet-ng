"""Real product listeners, persistent originals and unchanged central CLI."""
import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import unittest
import uuid
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT)]
import acceptance as A
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N

def write(p,v):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(v,indent=2)+'\n')

class ManualIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(os.environ.get('FN_MANUAL_CHECK_DIR',str(ROOT/'Logs'/'manual-tests'/uuid.uuid4().hex)))/'retained'/self.id().split('.')[-1]
        self.base.mkdir(parents=True,exist_ok=False)
    def inputs(self,case,out):
        return dict(schema='fakenet.manual-input.v1',case=case,candidate_id='manual-fixture',source_commit='a'*40,package_sha256='b'*64,execution_id='manual-fixture-0001',config=str(out/'config'),owned_root=str(out),responsea='192.0.2.55',fixture=True)
    def produce(self,case,tag):
        out=self.base/tag;inputs=self.inputs(case,out);v=M.run(case,out,inputs)
        rows,clean,detail=O.evaluate(ROOT,out,case,inputs,allow_fixture=True)
        self.assertTrue(clean,detail);self.assertEqual('pass',N._judge_rows(rows,M.CHECKS[case])['verdict'],detail)
        return out,inputs,v
    def mutate(self,out,v):write(out/'manual-result.json',v)
    def rejected(self,out,inputs,reason):
        try:
            rows,clean,detail=O.evaluate(ROOT,out,inputs['case'],inputs,allow_fixture=True)
        except ValueError as e:
            self.assertIn(reason,str(e));return
        self.assertFalse(clean,detail);self.assertIn(reason,json.dumps(detail));self.assertNotEqual('pass',N._judge_rows(rows,M.CHECKS[inputs['case']])['verdict'])
    def test_ncsi_four_real_roundtrips_and_independent_negatives(self):
        out,inputs,v=self.produce('GAP-NCSI','ncsi')
        self.assertEqual({('udp','dns.msftncsi.com'),('tcp','dns.msftncsi.com'),('udp','other.example'),('tcp','other.example')},{(r['transport'],r['name']) for r in v['queries']})
        for mutation,reason in [('missing','four-combination'),('duplicate','four-combination'),('bytes','DNS bytes'),('cleanup','lifecycle'),('identity','identity mismatch'),('escape','outside owned case')]:
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(v)
                if mutation=='missing':value['queries'].pop()
                if mutation=='duplicate':value['queries'][-1]=value['queries'][0]
                if mutation=='bytes':
                    p=Path(value['queries'][0]['response']);old=p.read_bytes();p.write_bytes(b'bad');value['queries'][0]['response_sha256']=M.sha256(p)
                if mutation=='cleanup':value['listener']['transports']['tcp']['thread_alive']=True
                if mutation=='identity':value['identity']['execution_id']='foreign'
                if mutation=='escape':value['queries'][0]['query']=str(ROOT/'AGENTS.md')
                self.mutate(out,value);self.rejected(out,inputs,reason)
                if mutation=='bytes':p.write_bytes(old)
        self.mutate(out,v)
    def test_http_original_bytes_dates_misses_and_cleanup(self):
        out,inputs,v=self.produce('GAP-RAW-DATE','http')
        self.assertIn(b'\x00\xff',Path(v['raw_response']).read_bytes())
        self.assertEqual({'raw','static','wrong-host','wrong-uri'},{r['name'] for r in v['http']['exchanges']})
        for mutation,reason in [('body','HTTP bytes'),('date','HTTP date'),('template','template'),('cleanup','lifecycle'),('request','HTTP request'),('config','template configuration')]:
            with self.subTest(mutation=mutation):
                value=copy.deepcopy(v);restore=None
                if mutation=='body':
                    p=Path(value['raw_response']);restore=p.read_bytes();p.write_bytes(restore+b'x')
                if mutation=='date':value['http']['exchanges'][0]['started_epoch']=0;value['http']['exchanges'][0]['ended_epoch']=1
                if mutation=='template':
                    p=Path(value['raw_template']);restore=p.read_bytes();p.write_bytes(restore+b'x')
                if mutation=='cleanup':value['listener']['socket_closed']=False
                if mutation=='request':value['http']['exchanges'][0]['host']='other.test'
                if mutation=='config':
                    p=out/'config/custom.ini';restore=p.read_bytes();p.write_bytes(restore.replace(b'example.test',b'foreign.test'));value['config_sha256']=M.sha256(p)
                self.mutate(out,value);self.rejected(out,inputs,reason)
                if restore is not None:p.write_bytes(restore)
        self.mutate(out,v)
    def cli(self,*args):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):code=A.main(['--root',str(ROOT),*map(str,args)])
        return code,out.getvalue(),err.getvalue()
    def test_same_central_cli_fixture_and_rehashed_bad_byte(self):
        identity={'platform':sys.platform if sys.platform!='win32' else 'windows','hostname':socket.gethostname()}
        write(self.base/'candidate.json',dict(schema=A.CANDIDATE_V2,source_commit=A.git_head(ROOT),deployed_identity=identity,package_sha256='b'*64,offline_fixture=True))
        write(self.base/'environment.json',dict(schema=A.ENVIRONMENT_V2,targets=['host-linux'],interpreters={'python':sys.executable},work_root=str(self.base),allowed_actions=['native'],endpoints=[],auth_refs=[],native_runtime={'transport':'manual-loopback-fixture','identity':identity},manual={'schema':'fakenet.manual-options.v1','responsea':'192.0.2.55'}))
        run=self.base/'run'
        for args in [('plan','--mode','selected','--case','GAP-NCSI','--case','GAP-RAW-DATE','--candidate',self.base/'candidate.json','--environment',self.base/'environment.json','--output',run/'plan.json'),('execute','--plan',run/'plan.json'),('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'independent.json')]:
            result=self.cli(*args);self.assertEqual(0,result[0],result)
        summary=json.loads((run/'independent.json').read_text());self.assertTrue(summary['fixture_contract_pass']);self.assertFalse(summary['full_functional_pass'])
        case_dir=run/'results/GAP-RAW-DATE';p=case_dir/'driver/raw-response.bin';p.write_bytes(p.read_bytes()+b'x')
        receipt=json.loads((case_dir/'receipt.json').read_text())
        for x in receipt['artifacts']:x['sha256']=M.sha256(x['path'])
        write(case_dir/'receipt.json',receipt)
        index=json.loads((run/'results/results.json').read_text())
        for x in index['receipts']:
            if x['case_id']=='GAP-RAW-DATE':x['sha256']=M.sha256(case_dir/'receipt.json')
        write(run/'results/results.json',index)
        result=self.cli('judge','--plan',run/'plan.json','--results',run/'results','--output',run/'bad-byte.json');self.assertNotEqual(0,result[0],result)
        bad=json.loads((run/'bad-byte.json').read_text());self.assertFalse(bad['fixture_contract_pass']);self.assertIn('HTTP bytes',json.dumps(bad))
    def test_unknown_manual_case_and_missing_central_authority_have_no_side_effects(self):
        out=self.base/'unknown'
        with self.assertRaises(NotImplementedError):M.run('GAP-EXECUTECMD',out,self.inputs('GAP-EXECUTECMD',out))
        self.assertFalse(out.exists())
        case=next(c for c in A.all_cases(A.read_catalog(ROOT)) if c['id']=='GAP-NCSI')
        self.assertIsNotNone(A.expected_block(case,[],{'linux'},ROOT,{},{}))
        driver=N.driver_table(ROOT)['manual-ncsi'];self.assertIn('argv',driver)
        self.assertIn('tools/acceptance_manual.py',N.native_source_pins(ROOT))

if __name__=='__main__':unittest.main()
