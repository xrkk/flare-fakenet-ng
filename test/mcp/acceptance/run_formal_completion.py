#!/usr/bin/env python3
"""Prepare pinned materials or execute one explicitly selected original batch."""
import argparse
import json
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--materials-json', type=Path, required=True)
    parser.add_argument('--materials-sha256', required=True)
    parser.add_argument('--repository-root', type=Path, default=Path(__file__).resolve().parents[3])
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('prepare', help='offline inputs, original config plan and independent original audits')
    run = actions.add_parser('run-batch', help='one original batch after complete offline and live admission')
    run.add_argument('--batch-id', required=True)
    run.add_argument('--preparation-json', type=Path,
                     help='previous exact preparation result; requires its independently frozen SHA')
    run.add_argument('--preparation-sha256')
    export = actions.add_parser('export-source', help='read-only export from one independently indexed source')
    export.add_argument('--source-root', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == 'run-batch' and bool(args.preparation_json) != bool(args.preparation_sha256):
        parser.error('--preparation-json and --preparation-sha256 must be supplied together')
    from formal_runtime.context import load_context, MaterialError
    from formal_runtime.preparation import prepare
    context = None
    try:
        context = load_context(args.materials_json, args.materials_sha256,
                               repository_root=args.repository_root,
                               source_root=Path(__file__).resolve().parents[3])
        entry = Path(__file__).resolve()
        if args.action == 'prepare':
            result = prepare(context, entry)
            print(json.dumps({'passed': result['passed'], 'VM_calls': 0,
                              'business_authorized': False, 'output': str(context.audit_root)}, ensure_ascii=False))
        elif args.action == 'run-batch':
            from formal_runtime.execution import run_batch
            from formal_runtime.preparation_receipt import load_preparation
            from formal_runtime.context import file_sha256, read_json
            from formal_runtime.runner import single_batch_request
            single_batch_request(context, args.batch_id)
            if args.preparation_json is None:
                # A new preparation in this interpreter supplies its known
                # original result bytes. Existing results are never inferred.
                result = prepare(context, entry)
                receipt = context.audit_root/'preparation-result.json'
                if read_json(receipt) != result:
                    raise MaterialError('current original preparation result changed before handoff')
                expected = file_sha256(receipt)
            else:
                receipt, expected = args.preparation_json, args.preparation_sha256
            prepared = load_preparation(context, receipt, expected, entry)
            result = run_batch(prepared, args.batch_id)
            from formal_runtime.batch_rejudge import run as rejudge
            verdict = rejudge(context, args.batch_id, result['source_index'], entry)
            print(json.dumps({'independently_rejudged': verdict['passed'], 'batch_id': args.batch_id,
                              'new_formal_credit': 0,
                              'output': str(context.evidence_root)}, ensure_ascii=False))
        else:
            from formal_runtime.export_entry import run as export_source
            result = export_source(context, args.source_root, entry)
            print(json.dumps({'exported': result['passed'], 'read_only': True,
                              'new_formal_credit': 0, 'output': str(context.evidence_root)}, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({'passed': False, 'error': repr(error),
                          **({'VM_calls': 0} if args.action == 'prepare' else {}),
                          'new_formal_credit': 0, 'output': str(context.audit_root) if context else None},
                         ensure_ascii=False))
        return 4 if isinstance(error, MaterialError) else 3


if __name__ == '__main__':
    raise SystemExit(main())
