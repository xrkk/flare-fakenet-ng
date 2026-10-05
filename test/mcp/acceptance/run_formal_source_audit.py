#!/usr/bin/env python3
"""Rejudge pinned original sources in a separate, network-free interpreter."""
import argparse
import json
from pathlib import Path
import sys


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materials-json',type=Path,required=True)
    parser.add_argument('--materials-sha256',required=True)
    parser.add_argument('--selection-json',type=Path,required=True)
    parser.add_argument('--scope',choices=('credited-selection','spike-only'),default='credited-selection')
    parser.add_argument('--repository-root',type=Path,default=Path(__file__).resolve().parents[3])
    args=parser.parse_args(argv)
    # Imports and helpers are qualified against the caller's independent
    # materials pin before a source-copy output or original verifier runs.
    from formal_runtime.context import load_context, MaterialError
    from formal_runtime.audit import AuditError, save
    from formal_runtime.audit_entry import run
    context=None
    try:
        context=load_context(args.materials_json,args.materials_sha256,
                             repository_root=args.repository_root,
                             source_root=Path(__file__).resolve().parents[3])
        verdict=run(context,args.selection_json,args.scope,Path(__file__).resolve())
        save(context.audit_root/'audit-result.json',verdict)
        print(json.dumps({'passed':verdict['passed'],'scope':args.scope,
                          'output':str(context.audit_root),'new_formal_credit':0},ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({'passed':False,'error':repr(error),'output':str(context.audit_root) if context else None,
                          'VM_calls':0,'new_formal_credit':0},ensure_ascii=False),file=sys.stderr)
        return 4 if isinstance(error,(AuditError,MaterialError)) else 3


if __name__=='__main__':
    raise SystemExit(main())
