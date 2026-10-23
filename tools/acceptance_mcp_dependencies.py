"""Fixed same-execution MCP predecessor references; never a boolean waiver."""
from pathlib import Path
import json


def acc008_reference(plan):
    import acceptance_mcp as m
    directory = Path(plan['run_dir']).resolve() / 'results/MCP-P03-FULL/driver'
    path = directory / 'units/ACC-008/result.json'
    return {'directory': str(directory), 'result_sha256': m.sha256(path)}


def verify_acc008(inputs, *, root, fixture=False):
    import acceptance_mcp as m
    import acceptance_mcp_oracles as oracle
    references = inputs.get('references', {})
    if set(references) != {'ACC-008'}:
        raise ValueError('ACC-019 requires this execution original ACC-008 reference')
    reference = references['ACC-008']
    if not isinstance(reference, dict) or set(reference) != {'directory', 'result_sha256'}:
        raise ValueError('ACC-008 reference fields differ')
    directory = Path(reference['directory'])
    owned = Path(inputs['work_root']).resolve()
    if (not directory.is_absolute() or directory != directory.resolve() or directory.is_symlink() or
            not directory.resolve().is_relative_to(owned)):
        raise ValueError('ACC-008 reference outside owned execution root')
    path = directory / 'units/ACC-008/result.json'
    if path.is_symlink() or not path.resolve().is_relative_to(directory) or m.sha256(path) != reference['result_sha256']:
        raise ValueError('ACC-008 original result changed')
    predecessor = m.read(directory / 'inputs.json')
    if predecessor.get('references'):
        raise ValueError('ACC-008 predecessor cannot recursively reference results')
    for key in ('identity', 'target', 'config_identity', 'manifest_sha256'):
        if predecessor.get(key) != inputs[key]:
            raise ValueError('ACC-008 predecessor identity differs: ' + key)
    rows, clean, details = oracle.evaluate(
        root, directory, 'MCP-P03-FULL', ['ACC-008'], predecessor,
        allow_fixture=fixture, subset=True)
    if not clean or len(rows) != 1 or rows[0]['status'] != 'pass':
        raise ValueError('ACC-008 predecessor capability not verified: ' + json.dumps(details))
    original = m.read(path)
    if original.get('acc_id') != 'ACC-008':
        raise ValueError('ACC-008 result unit differs')
    entries = [row for row in original['evidence'] if row.get('name') == 'acc008-checks']
    if len(entries) != 1:
        raise ValueError('ACC-008 direct checks not unique')
    checks = m.read(entries[0]['path'])
    required = ('corrupt_snapshot_fails_recovery', 'start_forbidden_on_corrupt')
    if any(checks.get(key) is not True for key in required):
        raise ValueError('ACC-008 required recovery sub-capability missing')
    return {'reference': reference, 'checks': checks,
            'scope': 'startup-corrupt-snapshot-recovery-only',
            'prestop_audit_failure_proven': False}


def plan_selection(selected, catalog, environment, mode):
    """Expand only ACC019's fixed current-execution predecessor before plan."""
    import copy
    import acceptance_mcp as m
    chosen = list(selected)
    if not any(case['id'] == 'MCP-P04-FULL' for case in chosen):
        return chosen, environment
    checks = environment.get('mcp_checks', {}).get('MCP-P04-FULL', m.CHECKS['MCP-P04-FULL'])
    if 'ACC-019' not in checks:
        return chosen, environment
    environment = copy.deepcopy(environment)
    source = next((case for case in chosen if case['id'] == 'MCP-P03-FULL'), None)
    if source is None:
        source = next(case for suite in catalog['suites'] for case in suite.get('cases', []) if case['id'] == 'MCP-P03-FULL')
        chosen.append(source)
        environment.setdefault('mcp_checks', {})['MCP-P03-FULL'] = ['ACC-008']
    elif 'MCP-P03-FULL' in environment.get('mcp_checks', {}):
        subset = environment['mcp_checks']['MCP-P03-FULL']
        if 'ACC-008' not in subset:
            subset.append('ACC-008')
    # Retain the order of unrelated groups. Pin P03 immediately before P04.
    chosen.remove(source)
    position = next(i for i, case in enumerate(chosen) if case['id'] == 'MCP-P04-FULL')
    chosen.insert(position, source)
    return chosen, environment


def validate_plan_order(plan):
    if 'MCP-P04-FULL' not in plan['required_cases']:
        return
    if 'ACC-019' not in plan.get('required_checks', {}).get('MCP-P04-FULL', []):
        return
    cases = plan['required_cases']
    if ('MCP-P03-FULL' not in cases or cases.index('MCP-P03-FULL') > cases.index('MCP-P04-FULL') or
            'ACC-008' not in plan.get('required_checks', {}).get('MCP-P03-FULL', [])):
        raise ValueError('ACC019 requires planned ACC008 predecessor before P04')
