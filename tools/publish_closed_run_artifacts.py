#!/usr/bin/env python3
"""Explicit stopped-run publication for deployments awaiting a frozen upgrade.

Run this file from the source bundle with fakenet/mcp/artifacts.py and package
initializers. It opens no network connection and changes no process or ACL.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fakenet.mcp.artifacts import ArtifactRegistry


def publish(overview, artifacts_root):
    status = overview['service_status']
    query = overview['artifacts_query']
    run = overview['selected_run_id']
    if (str(uuid.UUID(run)) != run or overview.get('error') or
            overview.get('consistent') is not True or overview.get('partial') is not False or
            status['state'] != 'stopped' or status['health']['process_alive'] is not False or
            status['state_version'] != overview['status_after_version'] or
            query.get('error') or query['query']['run_id'] != run):
        raise ValueError('Consistent, quiescent stopped-run overview required')
    root = Path(artifacts_root)
    if not root.is_absolute() or root.name != 'artifacts':
        raise ValueError('Explicit registered artifacts root required')
    destination = root / run
    if root.resolve() != root or destination.resolve() != destination or destination.is_symlink():
        raise ValueError('Ordinary registered destination required')
    source = root / 'runs' / run
    if source.resolve() != source or source.is_symlink() or not source.is_dir():
        raise ValueError('Ordinary retained run source required')
    config = source / 'active-config.ini'
    if (config.is_symlink() or config.stat().st_size > 1024*1024 or
            hashlib.sha256(config.read_bytes()).hexdigest() != status['config_identity']['sha256']):
        raise ValueError('Retained run config differs from stopped producer identity')
    copied = ArtifactRegistry(root).register_fakenet_outputs(run, source, prefix='')
    return {'schema': 'fakenet.closed-run-publication.v1', 'run_id': run,
            'file_count': len(copied), 'paths': [str(path) for path in copied]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--overview', required=True)
    parser.add_argument('--artifacts-root', required=True)
    args = parser.parse_args()
    try:
        path = Path(args.overview)
        if not path.is_absolute() or path.stat().st_size > 1024*1024:
            raise ValueError('Bounded absolute overview required')
        print(json.dumps(publish(json.loads(path.read_text(encoding='utf-8-sig')), args.artifacts_root)))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({'operation': 'closed-run-publication', 'overview_path': args.overview,
                          'source_root': str(Path(args.artifacts_root)/'runs'),
                          'destination_root': args.artifacts_root, 'exception_type': type(exc).__name__,
                          'errno': getattr(exc,'errno',None), 'winerror': getattr(exc,'winerror',None),
                          'os_error': str(exc)}),file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
