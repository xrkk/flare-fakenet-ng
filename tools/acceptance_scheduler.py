"""Bounded offline scheduler for the existing acceptance execute entry."""
from __future__ import annotations
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

SAFE_PARALLEL = frozenset(('CORE-TLSHELLO', 'CORE-DUALPCAP-WRITER'))
MAX_WORKERS = 2


def depth_from_environment(environment=None):
    raw = os.environ.get('FN_ACCEPTANCE_NESTED_DEPTH', '0')
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return max(0, value)


def worker_capacity(environment=None, depth=None):
    if depth is None:
        depth = depth_from_environment(environment)
    if depth > 0:
        return 1
    try:
        cpu = os.cpu_count() or 1
    except Exception:
        return 1
    return max(1, min(MAX_WORKERS, cpu, 2))


def _case_map(cases):
    return {case['id']: case for case in cases}


def ordered_cases(cases):
    """Stable dependency order; missing dependencies are explicit blocks."""
    by_id = _case_map(cases)
    pending = {case['id']: set(case.get('dependencies') or []) for case in cases}
    ordered = []
    blocked = {}
    while pending:
        ready = [cid for cid, deps in pending.items()
                 if not deps or deps.issubset({x for x in ordered})]
        if not ready:
            for cid, deps in pending.items():
                missing = sorted(deps - set(by_id))
                blocked[cid] = 'missing dependency: ' + ','.join(missing) if missing else 'dependency cycle'
            break
        ready.sort(key=lambda cid: [case['id'] for case in cases].index(cid))
        for cid in ready:
            ordered.append(cid)
            pending.pop(cid)
    return ordered, blocked


def _resources(case):
    aliases = {'windows-vm': 'vm:windows', 'linux-vm': 'vm:linux',
               'vm': 'vm:windows', 'vmware': 'vm:windows'}
    return {aliases.get(str(item), str(item)) for item in (case.get('resources') or [])}


def run_cases(cases, runner, *, capacity=None, completion=None):
    """Run offline cases with bounded safe parallelism and unique dirs.

    ``runner(case)`` returns a receipt.  Only the explicit SAFE_PARALLEL
    group may overlap; every other case is serialized.  Dependency failures
    block dependants while independent cases continue.
    """
    capacity = worker_capacity() if capacity is None else max(1, int(capacity))
    ordered, order_blocks = ordered_cases(cases)
    by_id = _case_map(cases)
    results = {}
    blocked = dict(order_blocks)
    safe_ready = []
    serial = []
    for cid in ordered:
        if cid in blocked:
            continue
        deps = by_id[cid].get('dependencies') or []
        if any(results.get(dep, {}).get('status') != 'pass' for dep in deps):
            blocked[cid] = 'dependency not passed: ' + ','.join(
                dep for dep in deps if results.get(dep, {}).get('status') != 'pass')
            continue
        if cid in SAFE_PARALLEL and capacity > 1:
            safe_ready.append(cid)
        else:
            serial.append(cid)
    # Safe group first, bounded by capacity; serial groups run after it.
    if safe_ready:
        with ThreadPoolExecutor(max_workers=capacity) as pool:
            futures = {pool.submit(runner, by_id[cid]): cid for cid in safe_ready}
            for future in as_completed(futures):
                cid = futures[future]
                results[cid] = future.result()
    for cid in serial:
        deps = by_id[cid].get('dependencies') or []
        if any(results.get(dep, {}).get('status') != 'pass' for dep in deps):
            blocked[cid] = 'dependency not passed: ' + ','.join(
                dep for dep in deps if results.get(dep, {}).get('status') != 'pass')
            continue
        results[cid] = runner(by_id[cid])
    if completion:
        completion(results, blocked)
    return results, blocked
