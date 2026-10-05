#!/usr/bin/env python3
"""Prepare the pinned formal runtime without VM calls or business dispatch."""
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
    args = parser.parse_args(argv)
    from formal_runtime.context import load_context, MaterialError
    from formal_runtime.preparation import prepare
    context = None
    try:
        context = load_context(args.materials_json, args.materials_sha256,
                               repository_root=args.repository_root,
                               source_root=Path(__file__).resolve().parents[3])
        result = prepare(context, Path(__file__).resolve())
        print(json.dumps({'passed': result['passed'], 'VM_calls': 0,
                          'business_authorized': False, 'output': str(context.audit_root)}, ensure_ascii=False))
        return 0
    except Exception as error:
        print(json.dumps({'passed': False, 'error': repr(error), 'VM_calls': 0,
                          'new_formal_credit': 0, 'output': str(context.audit_root) if context else None},
                         ensure_ascii=False))
        return 4 if isinstance(error, MaterialError) else 3


if __name__ == '__main__':
    raise SystemExit(main())
