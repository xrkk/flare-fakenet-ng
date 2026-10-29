"""Fixed target entry for an already deployed candidate; never deploys/builds."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(request,root):
    import acceptance_native as native
    from acceptance_runtime import require_target,write_json
    fields={'schema','case_id','case','checks','source_hashes','candidate',
            'target','output_root','execution_id','actions'}
    allowed = {frozenset(fields), frozenset(fields|{'policy'}),
               frozenset(fields|{'headless'}),
               frozenset(fields|{'mcp'}),
               frozenset(fields|{'policy','headless'}),
               frozenset(fields|{'policy','mcp'}),
               frozenset(fields|{'headless','mcp'}),
               frozenset(fields|{'policy','headless','mcp'})}
    allowed |= {frozenset(fields|{'upstream_protected_tcp_ports'}),
                frozenset(fields|{'policy','upstream_protected_tcp_ports'}),
                frozenset(fields|{'headless','upstream_protected_tcp_ports'}),
                frozenset(fields|{'mcp','upstream_protected_tcp_ports'}),
                frozenset(fields|{'policy','headless','upstream_protected_tcp_ports'}),
                frozenset(fields|{'policy','mcp','upstream_protected_tcp_ports'}),
                frozenset(fields|{'headless','mcp','upstream_protected_tcp_ports'}),
                frozenset(fields|{'policy','headless','mcp','upstream_protected_tcp_ports'}),
                frozenset(fields|{'manual'}),
                frozenset(fields|{'manual','upstream_protected_tcp_ports'})}
    if frozenset(request) not in allowed | {frozenset(fields|{'linux'})} or request['schema']!='fakenet.native-guest-request.v1':
        raise ValueError('invalid guest request schema/fields')
    if request['actions']!=['native']:
        raise ValueError('guest native action not authorized')
    require_target(request['target'])
    root=Path(root).resolve()
    for relative,want in request['source_hashes'].items():
        path=root/relative
        if (Path(relative).is_absolute() or '..' in Path(relative).parts or path.is_symlink() or
            not path.resolve().is_relative_to(root) or not path.is_file() or file_sha(path)!=want):
            raise ValueError('candidate source mismatch: '+relative)
    catalog=json.loads((root/'docs/acceptance/catalog.json').read_text(encoding='utf-8'))
    matches=[case for suite in catalog['suites'] for case in suite.get('cases',[]) if case['id']==request['case_id']]
    if len(matches)!=1 or matches[0]!=request['case']:
        raise ValueError('guest catalog case differs from selected candidate')
    environment={'native_runtime':{'transport':'local-target','identity':request['target']}}
    if 'policy' in request:
        environment['policy']=request['policy']
    if 'headless' in request:
        environment['headless']=request['headless']
    if 'mcp' in request:
        environment['mcp']=request['mcp']
    if 'linux' in request:
        environment['linux']=request['linux']
    if 'manual' in request:
        environment['manual']=request['manual']
    if 'upstream_protected_tcp_ports' in request:
        environment['native_runtime']['upstream_protected_tcp_ports'] = \
            native.validate_upstream_protected_tcp_ports(
                request['upstream_protected_tcp_ports'])
    driver,checks=native.validate_case(matches[0],root,environment)
    if not driver.get('production_kind') or checks!=request['checks']:
        raise ValueError('guest fixed driver/check selection mismatch')
    if 'manual' in request and matches[0].get('native_driver') not in native.MANUAL_REMOTE_DRIVERS:
        raise ValueError('guest manual options do not apply to this case')
    if matches[0].get('native_driver') in native.MANUAL_REMOTE_DRIVERS:
        # The two fixed remote drivers always carry the shared frozen options;
        # an absent key is missing options and dies before output.mkdir or any
        # launch.  Legal requests keep deriving owned_root from their own root.
        native.manual_options({'manual': request.get('manual')})
    # F2/SD-05: an explicit source-deployment candidate is fully verified from
    # the request's own closure M BEFORE output.mkdir or any producer launch.
    if request['candidate'].get('deployment_kind') == 'source':
        native._source_deployment_identity_from_request(request, root, matches[0])
    elif request['case_id'] in ('GAP-DUMPPACKETS', 'GAP-LIST-MUTEX') and \
            request['candidate'].get('package_sha256') is None:
        raise ValueError('manual candidate requires a package identity or the '
                         'explicit source deployment kind (pre-mkdir)')
    if driver.get('production_kind','').startswith('policy-'):
        native.policy_inputs(environment,request['candidate'].get('offline_fixture') is True,driver['production_kind'].split('-',1)[1])
    if driver['production_kind'] in ('process-redirect','payload-three-way'):
        native.headless_inputs(environment,driver,checks)
    output=Path(request['output_root'])
    if not output.is_absolute():raise ValueError('guest output root must be absolute')
    output.mkdir(parents=True,exist_ok=False)
    plan={'candidate':request['candidate'],'environment':environment,'execution_id':request['execution_id'],
          # SD-05: keep the VERIFIED request closure M for pure input derivation,
          # in both the shadow form and the frozen-selection key form the
          # rebuild compares against.
          'source_deployment_closure':dict(request['source_hashes']),
          'native_source_hashes':{},
          'source_hashes':{request['case_id']:dict(request['source_hashes'])}}
    receipt=native.run_production(root,matches[0],plan,output,sys.executable)
    result={'schema':'fakenet.native-guest-result.v1','execution_id':request['execution_id'],
            'case_id':request['case_id'],'request':request,'receipt':receipt}
    write_json(output/'guest-result.json',result)
    return 0 if receipt['status']=='pass' else 1 if receipt['status']=='fail' else 2


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True);parser.add_argument('--request-sha256',required=True)
    args=parser.parse_args(argv);path=Path(args.request)
    if not path.is_file() or path.is_symlink() or file_sha(path)!=args.request_sha256:
        raise ValueError('guest request identity mismatch')
    request=json.loads(path.read_text(encoding='utf-8'))
    output=Path(request['output_root']);was_present=output.exists()
    try:
        code=execute(request,Path(__file__).resolve().parents[1])
        # DC-02: only a Windows GAP-DUMPPACKETS success of this same fixed
        # entry gets a source closure, printed ONCE on stdout for the direct
        # MCP response.  Any finalization failure propagates nonzero and
        # never prints a partial object.
        if (code==0 and request.get('case_id')=='GAP-DUMPPACKETS' and
                request.get('target',{}).get('platform')=='windows'):
            import acceptance_native as native
            import traceback
            try:
                closure=native.finalize_dump_evidence(
                    Path(__file__).resolve().parents[1],request,args.request_sha256,
                    str(output))
            except BaseException as finalize_error:
                # Preserve the source-finalization failure verbatim for the
                # host (the PowerShell stderr path truncates tracebacks);
                # re-raise so the nonzero exit stands - never a fake closure.
                (output/'finalize-error.json').write_text(
                    json.dumps({'error_type': type(finalize_error).__name__,
                                'traceback': traceback.format_exc()},
                               ensure_ascii=False), encoding='utf-8')
                raise
            print(json.dumps(closure,ensure_ascii=False,sort_keys=True,
                             separators=(',',':')),flush=True)
        return code
    finally:
        # The entry is the last producer. The Host still observes its job exit
        # before reading this closed index through the existing SDK.
        if request.get('target',{}).get('platform')=='linux' and not was_present and output.is_dir() and (output/'guest-result.json').is_file():
            from acceptance_collection import write_index
            result=json.loads((output/'guest-result.json').read_text())
            if result.get('receipt',{}).get('cleanup',{}).get('process_exit',{}).get('exited') is True:
                write_index(output,args.request_sha256)


if __name__=='__main__':raise SystemExit(main())
