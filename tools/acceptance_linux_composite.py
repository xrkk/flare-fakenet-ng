"""Composite LINUX-SINGLEHOST: remote original SingleHost then MultiHost."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = 'fakenet.linux-composite-result.v1'
INPUT_SCHEMA = 'fakenet.linux-composite-input.v1'
CHECKS = ['singlehost', 'multihost', 'nfqueue', 'ipv6-block', 'restore']
SINGLE_CASE = 'LINUX-SINGLEHOST'
MULTI_CASE = 'UPSTREAM-MULTIHOST'
SOURCE_PINS = (
    'fakenet/mcp/linuxrunner.py', 'fakenet/diverters/linuxnetpolicy.py',
    'deploy/linux/deploy.sh', 'deploy/linux/update-idle.py',
    'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py',
    'tools/acceptance_linux_composite.py', 'tools/acceptance_orchestration.py',
    'tools/acceptance_multihost.py', 'tools/acceptance_linux.py',
    'tools/acceptance_guest.py', 'tools/acceptance_collection.py',
    'test/test.py', 'test/template.ini', 'test/custom_responses.ini',
    'test/CustomProviderExample.py', 'test/sample_raw_response.txt',
    'test/sample_raw_tcp_response.txt')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def _catalog_case(case_id):
    catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
    return next(item for suite in catalog['suites'] for item in suite.get('cases', [])
                if item['id'] == case_id)


def _source_hashes(value):
    pins = value.get('source_hashes')
    if not isinstance(pins, dict) or set(pins) != set(SOURCE_PINS):
        raise ValueError('composite source bindings required')
    for rel, digest in pins.items():
        path = ROOT / rel
        if (Path(rel).is_absolute() or '..' in Path(rel).parts or path.is_symlink()
                or not path.resolve().is_relative_to(ROOT) or sha(path) != digest):
            raise ValueError('composite source mismatch: ' + rel)


def _identities(value):
    single = value.get('singlehost', {})
    multi = value.get('multihost', {})
    return ({'singlehost': single.get('target'),
             'server': multi.get('server', {}).get('identity'),
             'client': multi.get('client', {}).get('identity')})


def validate_inputs(out, value):
    common = {'schema', 'case', 'candidate_id', 'source_commit', 'package_sha256',
              'execution_id', 'target', 'owned_root', 'source_hashes', 'singlehost',
              'multihost', 'deployed_identity'}
    optional = {'fixture'} if 'fixture' in value else set()
    if value.get('schema') != INPUT_SCHEMA or value.get('case') != SINGLE_CASE:
        raise ValueError('composite schema/case required')
    if set(value) != common | optional:
        raise ValueError('composite exact input schema required')
    if 'fixture' in value and type(value['fixture']) is not bool:
        raise ValueError('composite fixture identity invalid')
    for key, size in (('source_commit', 40), ('package_sha256', 64)):
        if not isinstance(value.get(key), str) or not re.fullmatch('[0-9a-f]{%d}' % size, value[key]):
            raise ValueError('composite source/package identity invalid')
    if not isinstance(value.get('execution_id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value['execution_id']):
        raise ValueError('composite execution identity invalid')
    destination = Path(out)
    if (not destination.is_absolute() or destination.is_symlink() or destination.exists()
            or any(p.is_symlink() for p in destination.parents)
            or str(destination) != value['owned_root']):
        raise ValueError('composite new absolute owned output required')
    single = value.get('singlehost')
    if not isinstance(single, dict) or set(single) != {'target', 'config', 'config_sha256', 'probe'}:
        raise ValueError('composite SingleHost options required')
    target = single['target']
    if not isinstance(target, dict) or set(target) != {'platform', 'hostname'} or target['platform'] != 'linux' or not target.get('hostname'):
        raise ValueError('composite explicit SingleHost Linux target required')
    if value.get('target') != target:
        raise ValueError('composite target must equal the explicit SingleHost target')
    config = Path(single['config'])
    if not config.is_absolute() or config.is_symlink() or not config.is_file() or sha(config) != single['config_sha256']:
        raise ValueError('composite SingleHost configuration changed')
    probe = single['probe']
    if not isinstance(probe, dict) or set(probe) != {'address', 'port', 'nonce'}:
        raise ValueError('composite SingleHost probe required')
    import ipaddress
    ipaddress.IPv4Address(probe['address'])
    if type(probe['port']) is not int or not 1 <= probe['port'] <= 65535 or not re.fullmatch(r'[a-f0-9]{32}', probe['nonce']):
        raise ValueError('composite SingleHost probe invalid')
    multi = value.get('multihost')
    if not isinstance(multi, dict) or set(multi) != {'server', 'client', 'server_ipv4', 'allowed_actions'}:
        raise ValueError('composite MultiHost options required')
    if not isinstance(multi['allowed_actions'], list) or not {'native', 'multihost', 'vm-execute', 'vm-transfer'}.issubset(multi['allowed_actions']):
        raise ValueError('composite MultiHost actions required')
    for role in ('server', 'client'):
        runtime = multi[role]
        if not isinstance(runtime, dict) or runtime.get('identity', {}).get('platform') != 'linux':
            raise ValueError('composite two explicit Linux targets required')
        if not runtime.get('workspace_root') or not runtime.get('work_root') or not runtime.get('source_root'):
            raise ValueError('composite MultiHost channel references incomplete')
    identities = _identities(value)
    if identities['singlehost'] != identities['server']:
        raise ValueError('composite SingleHost must be the server target, never the independent client')
    if identities['server'] == identities['client']:
        raise ValueError('composite MultiHost requires distinct server/client identities')
    if value.get('deployed_identity') != identities:
        raise ValueError('composite deployed identity must bind singlehost/server/client exactly')
    topology = {'transport': 'remnux-multihost', 'server': multi['server'],
                'client': multi['client'], 'server_ipv4': multi['server_ipv4']}
    import acceptance_native as native
    reason = native.runtime_block(dict(_catalog_case(MULTI_CASE)), {'native_runtime': topology,
                               'allowed_actions': multi['allowed_actions']})
    if reason:
        raise ValueError('composite MultiHost precondition: ' + reason)
    ipaddress.IPv4Address(multi['server_ipv4'])
    _source_hashes(value)
    return destination


def _single_plan(value):
    import acceptance_native as native
    case = _catalog_case(SINGLE_CASE)
    from pathlib import PurePosixPath
    runtime = value['multihost']['server']
    remote_config = str(PurePosixPath(runtime['workspace_root']) / 'published' /
                        value['execution_id'] / SINGLE_CASE / 'source.ini')
    linux = {'schema': 'fakenet.linux-runtime-options.v2',
             'config': remote_config,
             'config_sha256': value['singlehost']['config_sha256'],
             'mode': 'singlehost', 'probe': value['singlehost']['probe']}
    environment = {'native_runtime': {'transport': 'remnux-sdk',
                                      **value['multihost']['server']},
                   'allowed_actions': list(value['multihost']['allowed_actions']),
                   'linux': linux}
    checks = native.validate_case(case, ROOT, environment)[1]
    plan = {'environment': environment,
            'candidate': {'candidate_id': value['candidate_id'],
                          'source_commit': value['source_commit'],
                          'package_sha256': value['package_sha256'],
                          'deployed_identity': value['singlehost']['target'],
                          'offline_fixture': value.get('fixture') is True},
            'source_hashes': {SINGLE_CASE: dict(value['source_hashes'])},
            'native_source_hashes': {}, 'execution_id': value['execution_id'],
            'cases': {SINGLE_CASE: {'required_checks': checks}}}
    plan['linux_config_source'] = value['singlehost']['config']
    return case, plan


def _multi_plan(value):
    import acceptance_native as native
    case = _catalog_case(MULTI_CASE)
    multi = value['multihost']
    environment = {'native_runtime': {'transport': 'remnux-multihost',
                                      'server': multi['server'], 'client': multi['client'],
                                      'server_ipv4': multi['server_ipv4']},
                   'allowed_actions': list(multi['allowed_actions'])}
    checks = native.validate_case(case, ROOT, environment)[1]
    plan = {'environment': environment,
            'candidate': {'candidate_id': value['candidate_id'],
                          'source_commit': value['source_commit'],
                          'package_sha256': value['package_sha256'],
                          'deployed_identity': {'server': multi['server']['identity'],
                                                'client': multi['client']['identity']}},
            'source_hashes': {MULTI_CASE: dict(value['source_hashes'])},
            'native_source_hashes': {}, 'execution_id': value['execution_id'],
            'cases': {MULTI_CASE: {'required_checks': checks}}}
    return case, plan


def _single_evidence(single_dir, single_plan):
    import acceptance_native as native
    import acceptance_linux_runtime_oracles as oracle
    request = json.loads((single_dir / 'guest-request.json').read_text())
    original = single_dir / 'incoming/originals'
    guest = json.loads((original / 'guest-result.json').read_text())
    # This validates the complete original request, command, target, check set
    # and exact artifact mapping. The full case intentionally lacks MultiHost.
    native._remote_original_evaluation(ROOT, _catalog_case(SINGLE_CASE),
                                      single_plan, request, guest, original)
    expected = native.linux_inputs(single_plan, _catalog_case(SINGLE_CASE),
                                   request['output_root'], ROOT)
    rows, unused_full_clean, detail = oracle.evaluate(
        ROOT, original / 'driver', SINGLE_CASE, CHECKS,
        expected_inputs=expected,
        allow_fixture=single_plan['candidate'].get('offline_fixture') is True)
    receipt = guest['receipt']; cleanup = receipt.get('cleanup') or {}
    process = cleanup.get('process_exit') or {}
    terminal = json.loads((single_dir / 'producer-exit.json').read_text())
    driver = native.validate_case(_catalog_case(SINGLE_CASE), ROOT,
                                  single_plan['environment'])[0]
    checks = {row['id']: row['status'] for row in rows}
    # A failed whole-case status is expected only for its absent second host.
    # Do not reuse the whole-case recovered flag as stage recovery evidence.
    clean = (set(checks) == set(CHECKS) and
             all(checks[name] == 'pass' for name in CHECKS if name != 'multihost') and
             checks['multihost'] == 'fail' and
             receipt.get('returncode') == 1 and receipt.get('status') == 'fail' and
             cleanup.get('source') == 'driver' and cleanup.get('resources') == driver['resources'] and
             process.get('exited') is True and process.get('timed_out') is False and
             process.get('returncode') == receipt['returncode'] and
             terminal.get('state') == 'exited' and bool(terminal.get('job_id')) and
             type(terminal.get('pid')) is int)
    return rows, clean


def run(out, value, boundary=None):
    """Run remote original SingleHost, gate on its recovery, then MultiHost."""
    import acceptance_orchestration as orchestration
    destination = validate_inputs(out, value)
    destination.mkdir(parents=True, exist_ok=False)
    single_dir = destination / 'singlehost'; single_dir.mkdir()
    multi_dir = destination / 'multihost'; multi_dir.mkdir()
    single_case, single_plan = _single_plan(value)
    single_receipt = None
    multi_receipt = None
    multi_plan = None
    try:
        single_receipt = orchestration.run_linux(ROOT, single_case, single_plan, single_dir)
    except BaseException as exc:
        single_receipt = {'status': 'blocked', 'detail': type(exc).__name__ + ': ' + str(exc),
                          'returncode': None, 'cleanup': {'recovered': False}}
    single_gate_rows = None; stage_clean = False
    try:
        single_gate_rows, stage_clean = _single_evidence(single_dir, single_plan)
    except (OSError, ValueError, KeyError, TypeError):
        single_gate_rows = None; stage_clean = False
    single_gate_map = {row.get('id'): row.get('status') for row in (single_gate_rows or [])}
    gate = (stage_clean and single_gate_map.get('singlehost') == 'pass' and
            single_gate_map.get('nfqueue') == 'pass' and
            single_gate_map.get('ipv6-block') == 'pass' and
            single_gate_map.get('restore') == 'pass')
    if not gate:
        multi_receipt = {'status': 'blocked', 'detail': 'SingleHost recovery/original gate did not pass',
                         'returncode': None, 'required_checks': []}
    else:
        try:
            multi_case, multi_plan = _multi_plan(value)
            multi_receipt = orchestration.run_multihost(ROOT, multi_case, multi_plan, multi_dir)
        except BaseException as exc:
            multi_receipt = {'status': 'blocked', 'detail': type(exc).__name__ + ': ' + str(exc),
                             'returncode': None, 'required_checks': []}
    result = {'schema': SCHEMA, 'case': SINGLE_CASE, 'inputs': value,
              'fixture': bool(value.get('fixture') is True),
              'singlehost': single_receipt, 'multihost': multi_receipt,
              'singlehost_plan': single_plan, 'multihost_plan': multi_plan,
              'singlehost_gate': gate, 'source_hashes': value['source_hashes'],
              'cleanup': {'singlehost': (single_receipt or {}).get('cleanup'),
                          'multihost': (multi_receipt or {}).get('cleanup')},
              'error': None if gate else (single_receipt or {}).get('detail')}
    _json(destination / 'linux-result.json', result)
    return result


def evaluate(root, original, expected_inputs, allow_fixture=False):
    import acceptance_orchestration as orchestration
    import acceptance_native as native
    folder = Path(original)
    rows = {name: 'fail' for name in CHECKS}; detail = {}
    try:
        result = json.loads((folder / 'linux-result.json').read_text())
        if result.get('schema') != SCHEMA or result.get('inputs') != expected_inputs:
            raise ValueError('composite result/input mismatch')
        if result.get('fixture') != (expected_inputs.get('fixture') is True):
            raise ValueError('composite fixture identity differs')
        _source_hashes(expected_inputs)
        if result.get('fixture') and not allow_fixture:
            raise ValueError('composite fixture cannot earn native credit')
        if result.get('singlehost_gate') is not True:
            raise ValueError('SingleHost original/recovery gate did not pass')
        unused_single_case, single_plan = _single_plan(expected_inputs)
        if not isinstance(single_plan, dict):
            raise ValueError('singlehost plan evidence missing')
        srows, sclean = _single_evidence(folder / 'singlehost', single_plan)
        smap = {row['id']: row['status'] for row in srows}
        rows['singlehost'] = smap.get('singlehost', 'fail')
        rows['nfqueue'] = smap.get('nfqueue', 'fail')
        rows['ipv6-block'] = smap.get('ipv6-block', 'fail')
        rows['restore'] = 'pass' if sclean and smap.get('restore') == 'pass' else 'fail'
        multi_case, multi_plan = _multi_plan(expected_inputs)
        meval, mclean = orchestration.evaluate_multihost(root, multi_case, multi_plan, folder / 'multihost')
        rows['multihost'] = 'pass' if meval.get('verdict') == 'pass' and mclean else 'fail'
        if not mclean: rows['restore'] = 'fail'
        detail = {'singlehost': srows, 'multihost': meval, 'single_clean': sclean,
                  'multi_clean': mclean}
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        rows = {name: 'fail' for name in CHECKS}
        detail['error'] = type(exc).__name__ + ': ' + str(exc)
    return ([{'id': name, 'status': rows[name]} for name in CHECKS],
            all(status == 'pass' for status in rows.values()), detail)


def selected(plan, case):
    return (case.get('id') == SINGLE_CASE and
            plan.get('environment', {}).get('linux', {}).get('schema') ==
            'fakenet.linux-composite-options.v1')


def run_controller(root, case, plan, output):
    import acceptance_native as native
    from datetime import datetime, timezone
    output = Path(output)
    value = native.linux_inputs(plan, case, output, root)
    validate_inputs(output / 'driver', value)
    runtime = plan['environment'].get('native_runtime')
    expected_runtime = {'transport': 'remnux-multihost',
                        'server': value['multihost']['server'],
                        'client': value['multihost']['client'],
                        'server_ipv4': value['multihost']['server_ipv4']}
    if runtime != expected_runtime:
        raise ValueError('composite runtime differs from exact bound topology')
    if not set(value['multihost']['allowed_actions']).issubset(
            plan['environment'].get('allowed_actions', [])):
        raise ValueError('composite nested actions exceed controller authorization')
    output.mkdir(parents=True, exist_ok=True)
    _json(output / 'linux-inputs.json', value)
    start = datetime.now(timezone.utc)
    run(output / 'driver', value)
    rows, clean, detail = evaluate(root, output / 'driver', value,
                                  allow_fixture=value.get('fixture') is True)
    evaluation = native._judge_rows(rows, CHECKS)
    end = datetime.now(timezone.utc)
    from acceptance_orchestration import artifact_index
    return {'status': evaluation['verdict'], 'detail': detail,
            'returncode': 0 if clean else 1,
            'command': ['registered:linux-composite'], 'required_checks': CHECKS,
            'native_target': value['deployed_identity'],
            'started_at': start.isoformat(), 'ended_at': end.isoformat(),
            'duration_seconds': (end-start).total_seconds(),
            'artifacts': artifact_index(output),
            'cleanup': {'source': 'controller', 'recovered': clean,
                        'resources': native.validate_case(case, root, plan['environment'])[0]['resources'],
                        'temp_roots': [str(output.resolve())]}}


def judge_controller(root, case, receipt, plan):
    import acceptance_native as native
    from acceptance_orchestration import artifact_index
    output = Path(plan['run_dir']) / 'results' / case['id']
    value = native.linux_inputs(plan, case, output, root)
    expected = [r for r in artifact_index(output) if Path(r['path']) != output/'receipt.json']
    if receipt.get('artifacts') != expected:
        return {'status': 'unknown', 'cleanup_ok': False, 'reason': 'composite artifact set/hash differs'}
    if (receipt.get('command') != ['registered:linux-composite'] or
            receipt.get('required_checks') != CHECKS or
            receipt.get('native_target') != value['deployed_identity']):
        return {'status': 'fail', 'cleanup_ok': False, 'reason': 'composite command/checks/role identity mismatch'}
    if json.loads((output/'linux-inputs.json').read_text()) != value:
        return {'status': 'fail', 'cleanup_ok': False, 'reason': 'composite frozen inputs differ'}
    rows, clean, detail = evaluate(root, output/'driver', value,
                                  allow_fixture=plan['candidate'].get('offline_fixture') is True)
    clean = clean and receipt.get('cleanup', {}).get('recovered') is True
    result = native._judge_rows(rows, CHECKS)
    status = result['verdict']
    if receipt.get('status') != 'pass' or receipt.get('returncode') != 0 or not clean:
        status = 'fail' if status == 'fail' else 'unknown'
    return {'status': status, 'cleanup_ok': clean, 'evaluation': result, 'detail': detail}
