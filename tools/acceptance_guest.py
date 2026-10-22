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
    if set(request)!={'schema','case_id','case','checks','source_hashes','candidate','target','output_root','execution_id','actions'} or request['schema']!='fakenet.native-guest-request.v1':
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
    driver,checks=native.validate_case(matches[0],root,environment)
    if not driver.get('production_kind') or checks!=request['checks']:
        raise ValueError('guest fixed driver/check selection mismatch')
    output=Path(request['output_root'])
    if not output.is_absolute():raise ValueError('guest output root must be absolute')
    output.mkdir(parents=True,exist_ok=False)
    plan={'candidate':request['candidate'],'environment':environment}
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
        return execute(request,Path(__file__).resolve().parents[1])
    finally:
        # The entry is the last producer. The Host still observes its job exit
        # before reading this closed index through the existing SDK.
        if request.get('target',{}).get('platform')=='linux' and not was_present and output.is_dir() and (output/'guest-result.json').is_file():
            from acceptance_collection import write_index
            result=json.loads((output/'guest-result.json').read_text())
            if result.get('receipt',{}).get('cleanup',{}).get('process_exit',{}).get('exited') is True:
                write_index(output,args.request_sha256)


if __name__=='__main__':raise SystemExit(main())
