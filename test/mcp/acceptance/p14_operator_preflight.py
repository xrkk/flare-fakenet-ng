"""One finite native receipt/release proof while the product service is Stopped."""
import argparse,json,time,uuid,base64
from pathlib import Path
from p14_operator_fixture import Runner,release_receipt,sha,write_new,WORKER

def close(r,root,ready):
    r.root=root;r.ready=ready
    receipt=release_receipt(ready);encoded=base64.b64encode(json.dumps(receipt).encode()).decode()
    path=root+r'\release.json';r.vm("$ErrorActionPreference='Stop';$p="+r.ps(path)+";$b=[Convert]::FromBase64String('"+encoded+"');$s=[IO.File]::Open($p,[IO.FileMode]::CreateNew);try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()};'precise own release'",30)
    closed=r.wait_file(root+r'\closed.json',30);assert closed['reason']=='cooperative_release' and closed['seconds']<1800 and closed['listener_stopped'];r.save('closed-'+ready['nonce']+'.json',closed)
    r.samples(False);ended=r.vm('$p=Get-Process -Id '+str(ready['pid'])+" -ErrorAction SilentlyContinue;if($p -and [string]$p.StartTime.ToUniversalTime().ToFileTimeUtc() -ceq '"+ready['creation_time']+"'){if(!$p.WaitForExit(10000)){throw 'own worker not ended'}};'native preflight worker ended'",15);r.save('native-ended-'+ready['nonce']+'.json',ended)

def execute(output):
    output.mkdir(exist_ok=False,parents=True);r=Runner(output);r.j.run_id=str(uuid.uuid4());workers=[];result={'status':'FAILED','business_entered':False,'product_mutations':0};closed=set()
    try:
        scene=r.scene('stopped-preflight',False);assert scene['service']['State']=='Stopped' and scene['service']['ProcessId']==0 and not scene['marker']['needs_recovery'] and not scene['processes']
        r.resource_gate('preflight')
        for role in ['reference','own']:
            r.nonce=str(uuid.uuid4());root='E:\\FakeNetEvidence\\r08\\preflight\\'+r.j.run_id+'\\'+r.nonce;r.root=root
            workers.append((root,None));launch_start=time.monotonic();launch=r.setup_worker(root,'Preflight');ready=r.wait_file(root+r'\ready.json',30)
            assert ready['mode']=='Preflight' and ready['managed_job_proof']['preflight_service_stopped'] and ready['address']=='127.0.0.1' and ready['nonce']==r.nonce and (ready['pid'],ready['creation_time'])==(launch['pid'],launch['creation_time'])
            workers[-1]=(root,ready);r.save(role+'-ready.json',ready);r.save(role+'-launch.json',{'launch':launch,'setup_and_receipt_seconds':time.monotonic()-launch_start});r.ready=ready;r.samples(True)
        ownroot,ownready=workers[1];close(r,ownroot,ownready);closed.add(ownready['nonce'])
        refroot,refready=workers[0];r.root=refroot;r.ready=refready;reference=r.native_sample('foreign-unchanged');assert reference['pid']==refready['pid'] and reference['creation_time']==refready['creation_time'] and reference['rows'];r.save('independent-socket-unchanged.json',reference)
        close(r,refroot,refready);closed.add(refready['nonce']);result.update(status='COMPLETED',exact_release_native_end=True,foreign_socket_unchanged=True,worker_sha256=sha(WORKER.read_bytes()),workers=[x[1] for x in workers])
    except BaseException as e:
        import traceback
        result.update(reason=repr(e),exception_type=type(e).__name__,traceback=traceback.format_exc())
    finally:
        for root,ready in reversed(workers):
            if ready is None:
                try:ready=r.wait_file(root+r'\ready.json',30)
                except BaseException as e:result.setdefault('closure_errors',[]).append('unknown native worker: '+repr(e));continue
            if ready['nonce'] not in closed:
                try:close(r,root,ready);closed.add(ready['nonce'])
                except BaseException as e:result.setdefault('closure_errors',[]).append(repr(e));result['status']='FAILED'
        result['native_workers_ended']=len(closed)==len(workers);r.save('result.json',result)
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();result=execute(a.output);print(json.dumps(result,ensure_ascii=False));raise SystemExit(0 if result['status']=='COMPLETED' else 1)
