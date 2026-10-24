"""Reject mixed identities, missing raw evidence and incomplete round windows."""
import hashlib
import json
import zipfile
from pathlib import Path


IDENTITY_FIELDS = ('candidate_id', 'source_commit', 'package_sha256',
                   'requirements_blob', 'master_plan_blob')


def validate_result(record, expected, root):
    failures = []
    for field in IDENTITY_FIELDS:
        if not expected.get(field) or record.get(field) != expected[field]:
            failures.append('identity mismatch: ' + field)
    if record.get('status') != 'pass' or record.get('blocker'):
        failures.append('result is not an unblocked pass')
    evidence = record.get('evidence')
    if not isinstance(evidence, list) or not evidence:
        return failures + ['raw evidence missing']
    root = Path(root).resolve()
    for item in evidence:
        try:
            path = Path(item['path']).resolve()
            if not path.is_relative_to(root):
                raise ValueError('evidence outside candidate directory')
            raw = path.read_bytes()
            if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('evidence hash/size mismatch')
        except (KeyError, TypeError, OSError, ValueError) as exc:
            failures.append(str(exc))
    return failures


def validate_round(record, expected, *, expected_diagnostic=None):
    failures = []
    if expected_diagnostic is not None:
        if record.get('class') != 'stacks_unavailable':
            failures.append('no-stack context supplied for another class')
        try:
            arm = validate_stack_context(expected_diagnostic, record.get('run_id'))
            event = expected_diagnostic['trigger']['observed_time_ns'] / 1e9
            if (record.get('nonce') != arm['nonce']
                    or (record.get('fault_evidence') or {}).get('receipt', {}).get('receipt')
                       != {'fault': 'stacks_unavailable', 'nonce': arm['nonce']}
                    or not record['probe_window_start'] <= event <= record['probe_window_end']):
                raise ValueError('no-stack original round receipt/window differs')
        except (KeyError, TypeError, ValueError, OSError) as exc:
            failures.append('no-stack context rejected: ' + str(exc))
    for field in IDENTITY_FIELDS:
        if not expected.get(field) or record.get(field) != expected[field]:
            failures.append('identity mismatch: ' + field)
    if record.get('failure') or record.get('final_state') != 'stopped':
        failures.append('round did not converge')
    if record.get('audit_diff') or 'audit_diff' not in record:
        failures.append('audit absent or dirty')
    if not record.get('lock_released_after_stop'):
        failures.append('configuration lock not released')
    if record.get('class') and record.get('class') != 'normal':
        try:
            import ntpath
            run_id = record['fault_evidence']['receipt']['run_id']
            expected_names = [ntpath.basename(ntpath.dirname(item['path']))
                              for item in record['fault_evidence']['incidents']]
            exports = record['incident_exports']
            names = [item['incident_name'] for item in exports]
            if (not expected_names or len(set(expected_names)) != len(expected_names) or
                    len(set(names)) != len(names) or set(names) != set(expected_names)):
                raise ValueError('incident export coverage mismatch')
            for exported in exports:
                if expected_diagnostic is None:
                    failures.extend(validate_incident_export(exported, run_id, fault_round=True))
                else:
                    failures.extend(validate_incident_export(exported, run_id, fault_round=True,
                                                             expected_diagnostic=expected_diagnostic))
        except (KeyError, TypeError, OSError, ValueError) as exc:
            failures.append('verified incident export unavailable: ' + str(exc))
    captures = record.get('capture_evidence')
    if not isinstance(captures, list) or len(captures) < 2:
        failures.append('raw before/after environment captures missing')
    else:
        seen = set()
        for item in captures:
            try:
                path = Path(item['path']).resolve()
                if path in seen:
                    raise ValueError('environment capture reused')
                seen.add(path)
                raw = path.read_bytes()
                if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise ValueError('environment capture hash/size mismatch')
                capture = json.loads(raw)
                if any(capture.get(field) != expected[field] for field in IDENTITY_FIELDS):
                    raise ValueError('environment capture identity mismatch')
                sections = capture.get('sections', {})
                required = ('routes', 'dns_servers', 'windivert_processes', 'listen_ports', 'services')
                if not capture.get('complete') or any(not sections.get(key) for key in required):
                    raise ValueError('environment capture incomplete')
                began, ended = capture.get('started_at'), capture.get('ended_at')
                window_start, window_end = record.get('probe_window_start'), record.get('probe_window_end')
                if (not all(isinstance(t, (int, float)) for t in
                            (began, ended, window_start, window_end)) or
                        not window_start <= began <= ended <= window_end):
                    raise ValueError('environment capture outside current round')
            except (KeyError, TypeError, OSError, ValueError) as exc:
                failures.append(str(exc))
        if len(captures) >= 2:
            # Recompute the environment difference from the raw captures: a
            # summary that reports a clean audit_diff while its own raw
            # baselines differ must not pass (CHK-066).
            try:
                raw_before = json.loads(Path(captures[0]['path']).read_bytes())
                raw_after = json.loads(Path(captures[-1]['path']).read_bytes())
            except (KeyError, TypeError, OSError, ValueError) as exc:
                failures.append('raw baseline reread failed: ' + str(exc))
            else:
                recomputed = raw_section_diff(raw_before.get('sections', {}),
                                              raw_after.get('sections', {}))
                if recomputed and not record.get('audit_diff'):
                    failures.append('raw baseline diff not recorded: %s'
                                    % sorted(recomputed))
    start, end = record.get('probe_window_start'), record.get('probe_window_end')
    timeline = record.get('probe_timeline')
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)) or not timeline:
        return failures + ['full probe window absent']
    # The recorded round window itself must be ordered and consistent: a
    # summary whose ended_at precedes started_at is not a real observation.
    try:
        import datetime
        began_at = datetime.datetime.fromisoformat(record['started_at'])
        ended_at = datetime.datetime.fromisoformat(record['ended_at'])
        if ended_at < began_at:
            raise ValueError('ended before started')
    except (KeyError, TypeError, ValueError):
        failures.append('round start/end timestamps absent or out of order')
    times = [p.get('t') for p in timeline]
    if (any(not isinstance(t, (int, float)) for t in times) or
            any(not p.get('ok') for p in timeline)):
        return failures + ['invalid or failed probe']
    if times != sorted(times) or times[0] > start or times[-1] < end:
        failures.append('probe window not covered')
    if any(b-a > 2 for a, b in zip(times, times[1:])):
        failures.append('probe sampling gap exceeds two seconds')
    before, after = record.get('vm_before'), record.get('vm_after')
    if not before or before != after:
        failures.append('VM/service identity drift')
    return failures


def raw_section_diff(before, after):
    """Sections whose raw before/after content actually differs."""
    from fakenet.mcp import baseline
    changed = set()
    for key in set(before or {}) | set(after or {}):
        left = baseline._normalize(key, (before or {}).get(key))
        right = baseline._normalize(key, (after or {}).get(key))
        if left != right:
            changed.add(key)
    return changed


def validate_rounds(records, required_classes=None):
    """Cross-round uniqueness and category coverage for a release summary.

    A summary that counts the same run twice, or that omits a required
    fault class, is not the required sample set (CHK-066).
    """
    failures = []
    seen = set()
    classes = {}
    capture_paths = set()
    for index, record in enumerate(records or []):
        run_id = record.get('run_id') if isinstance(record, dict) else None
        fault_class = record.get('class') if isinstance(record, dict) else None
        if not run_id:
            failures.append('round %d has no run identity' % index)
            continue
        if not fault_class:
            failures.append('round %d has no fault class' % index)
            continue
        if run_id in seen:
            # One run is one sample: filing it under another class does not
            # make it a second observation.
            failures.append('round run reused: %s (as %s)' % (run_id, fault_class))
            continue
        seen.add(run_id)
        for item in record.get('capture_evidence', []):
            path = str(Path(item['path']).resolve())
            if path in capture_paths:
                failures.append('environment capture reused across rounds: ' + path)
            capture_paths.add(path)
        classes[fault_class] = classes.get(fault_class, 0) + 1
    for fault_class, minimum in (required_classes or {}).items():
        if classes.get(fault_class, 0) < minimum:
            failures.append('category under-sampled: %s (%d/%d)'
                            % (fault_class, classes.get(fault_class, 0), minimum))
    return failures


def validate_sample_category(record, prefix):
    """Compare the file's requested slot with actual run/trigger facts."""
    failures = []
    if not record.get('run_id'):
        failures.append('sample has no actual run identity')
    if prefix.startswith('normal-'):
        expected = 'default.ini' if prefix == 'normal-builtin' else 'release-custom.ini'
        if record.get('class') != 'normal' or record.get('config') != expected:
            failures.append('normal sample configuration/category mismatch')
        try:
            observed = record['config_read']
            identity = {key: observed[key] for key in ('name', 'sha256', 'builtin')}
            if (identity['name'] != expected or identity['builtin'] != (prefix == 'normal-builtin') or
                    hashlib.sha256(observed['content'].encode('utf-8')).hexdigest() != identity['sha256'] or
                    record['start_response']['run_id'] != record['run_id'] or
                    record['lock_held_evidence']['status']['run_id'] != record['run_id'] or
                    record['lock_held_evidence']['status']['config_identity'] != identity or
                    record['lock_held_evidence']['file_probe']['before'] != identity['sha256'] or
                    record['lock_held_evidence']['file_probe']['after'] != identity['sha256']):
                raise ValueError('normal sample actual run/config identity mismatch')
            if prefix == 'normal-custom':
                builtin = record['builtin_config_read']
                if (not builtin['builtin'] or builtin['name'] != 'default.ini' or
                        hashlib.sha256(builtin['content'].encode('utf-8')).hexdigest() != builtin['sha256'] or
                        observed['content'].replace('\r\n', '\n') != custom_config_body(builtin['content'])):
                    raise ValueError('custom sample semantic configuration mismatch')
        except (KeyError, TypeError, ValueError) as exc:
            failures.append('normal sample identity evidence unavailable: ' + str(exc))
    else:
        expected = prefix.removeprefix('fault-')
        receipt = (record.get('fault_evidence') or {}).get('receipt') or {}
        trigger = receipt.get('receipt') or {}
        started_run = (record.get('start_response') or {}).get('run_id')
        if started_run is None and record.get('last_run_outcome') == 'failed':
            # Start-injection classes converge as failed starts; the receipt
            # is then the actual run identity of the sample.
            started_run = receipt.get('run_id')
        if (record.get('class') != expected or trigger.get('fault') != expected or
                trigger.get('nonce') != record.get('nonce') or not record.get('nonce') or
                receipt.get('run_id') != record.get('run_id') or
                started_run != record.get('run_id')):
            failures.append('fault sample run/category/trigger mismatch')
    return failures


def incident_entry_omission_allowed(entry, fault_round=False):
    """The two existing, explicit omissions; never a generic failed-item pass."""
    return ((entry.get('item') == 'userdump.dmp' and
             entry.get('result') == 'skipped' and
             entry.get('failure_reason') == 'no escalation condition' and
             entry.get('size') == 0 and entry.get('sha256') is None) or
            (fault_round and entry.get('item') == 'managed-exit.json' and
             entry.get('result') == 'failed' and
             entry.get('failure_reason') == 'exit evidence incomplete'))


def validate_incident_export(exported, run_id, fault_round=False, *, expected_diagnostic=None):
    """Re-read actual members; a cached complete flag is insufficient.

    In a fault round the scenario IS the failure: managed-exit.json may
    honestly record incomplete exit evidence (the producer's end fact,
    CHK-070) while the pack's escalation dump proves the failure. That
    one honest bookkeeping failure is acceptable exactly there; normal
    and release exports keep the strict rule."""
    if expected_diagnostic is not None:
        if not fault_round:
            return ['explicit diagnostic requires a fault round']
        try:
            assess_no_stack_export(exported, run_id, expected_diagnostic)
            return []
        except (KeyError, TypeError, OSError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            return ['no-stack original export invalid: ' + str(exc)]
    import zipfile
    from fakenet.mcp.incident import BASIC_ITEMS
    failures = []
    try:
        raw = Path(exported['path']).read_bytes()
        if (not exported.get('complete') or len(raw) != exported['size'] or
                hashlib.sha256(raw).hexdigest() != exported['sha256'] or
                exported['run_id'] != run_id):
            raise ValueError('incident archive identity/hash/integrity mismatch')
        with zipfile.ZipFile(exported['path']) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                raise ValueError('duplicate archive member')
            manifest = json.loads(archive.read('manifest.json'))
            if manifest.get('run_id') != run_id:
                raise ValueError('actual manifest belongs to another run')
            if not manifest.get('complete') and not fault_round:
                raise ValueError('actual manifest not complete for this run')
            names = set()
            verified = set()
            for item in manifest.get('entries', []):
                name = item['item']
                if name in names or '/' in name or '\\' in name or name in ('', '.', '..'):
                    raise ValueError('invalid or duplicate incident member')
                names.add(name)
                if incident_entry_omission_allowed(item, fault_round):
                    continue
                if item['result'] != 'ok':
                    raise ValueError('failed incident member: ' + name)
                data = archive.read(name)
                if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('incident member changed: ' + name)
                verified.add(name)
            if set(name for name, _ in BASIC_ITEMS) - verified:
                raise ValueError('basic incident members missing')
    except (KeyError, TypeError, OSError, ValueError, zipfile.BadZipFile) as exc:
        failures.append('incident export invalid: ' + str(exc))
    return failures


def custom_config_body(content):
    """The exact approved custom sample delta, applied to the actual builtin."""
    lines, found = [], set()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith(('DumpHTTPWebRoot:', 'DumpHTTPWebRoot =', 'DumpHTTPWebRoot=')):
            line = 'DumpHTTPWebRoot: '
            found.add('webroot')
        if stripped.startswith(('DumpPacketsFilePrefix:', 'DumpPacketsFilePrefix =', 'DumpPacketsFilePrefix=')):
            line = 'DumpPacketsFilePrefix = release-custom'
            found.add('prefix')
        lines.append(line)
    # The prefix rename is the mandatory semantic delta; the webroot key is
    # only rewritten when the builtin actually carries it (current default
    # configs ship without DumpHTTPWebRoot).
    if 'prefix' not in found:
        raise ValueError('builtin does not contain the required custom delta fields')
    body = '\n'.join(lines) + '\n'
    if body == content.replace('\r\n', '\n'):
        raise ValueError('custom configuration has no semantic delta')
    return body



def validate_stack_context(context, run_id):
    """Only exact typed original observations; a caller flag grants nothing."""
    from fakenet.mcp import diagnostic_faults as d
    if (not isinstance(context, dict) or set(context) !=
            {'schema', 'plan', 'ready', 'arm', 'trigger', 'fallback_files', 'originals'}
            or context['schema'] != 'fakenet.no-stack-context.v1'):
        raise ValueError('no-stack context is not structured original evidence')
    plan, ready, arm, trigger = (context[k] for k in ('plan', 'ready', 'arm', 'trigger'))
    if len(json.dumps(context).encode('utf-8')) > 64 * 1024:
        raise ValueError('no-stack original context exceeds fixed bound')
    import base64
    originals = context['originals']
    if not isinstance(originals, dict) or set(originals) != {'window', 'trigger', 'fallbacks', 'transport'}:
        raise ValueError('no-stack original observations absent')
    decoded = {}
    for name in ('window', 'trigger'):
        response = originals[name]
        if (not isinstance(response, dict) or response.get('exit_code') != 0
                or response.get('is_error') is not False):
            raise ValueError('no-stack source transport unresolved')
        wrapped = json.loads(response['output'])
        if set(wrapped) != {'base64', 'sha256'} or len(wrapped['base64']) > 12000:
            raise ValueError('no-stack raw source bound differs')
        raw = base64.b64decode(wrapped['base64'], validate=True)
        if len(raw) > 8192 or hashlib.sha256(raw).hexdigest() != wrapped['sha256']:
            raise ValueError('no-stack raw source hash differs')
        decoded[name] = json.loads(raw)
    if decoded['window'] != {'schema': 'fakenet.diagnostic-window.v1', 'plan': plan, 'ready': ready} or decoded['trigger'] != trigger:
        raise ValueError('no-stack typed context differs from original bytes')
    transport = originals['transport']
    if not isinstance(transport, list) or not 3 <= len(transport) <= 8:
        raise ValueError('no-stack original transport set missing or unbounded')
    from pathlib import PureWindowsPath
    directory = PureWindowsPath(ready['run_dir'])
    required = [('window', [str(directory/'diagnostic-window.json')]),
                ('trigger', [str(directory/'diagnostic-triggered.json')]),
                ('fallbacks', [str(directory/name) for name in
                    ('managed-thread-stacks.json', 'stop-thread-stacks.txt', 'fault-child-stacks.txt')])]
    for key, paths in required:
        if not any(row.get('kind') == 'powershell' and not row.get('error')
                   and row.get('output') == originals[key]
                   and all(path.replace("'", "''") in row.get('input', {}).get('command', '') for path in paths)
                   for row in transport):
            raise ValueError('no-stack original response/path detached from transport')
    response = originals['fallbacks']
    if (not isinstance(response, dict) or response.get('exit_code') != 0
            or response.get('is_error') is not False
            or json.loads(response['output']) != context['fallback_files']):
        raise ValueError('no-stack fallback transport observation differs')

    if (not isinstance(plan, dict) or set(plan) != d.PLAN_KEYS
            or plan['schema'] != d.PLAN_SCHEMA or not d._identity(plan['service_identity'])
            or not isinstance(ready, dict) or set(ready) != d.READY_KEYS
            or ready['schema'] != d.READY_SCHEMA or not d.arm_shape(arm)
            or not isinstance(trigger, dict) or set(trigger) != d.ARM_KEYS | {'observed_time_ns'}):
        raise ValueError('no-stack typed window/target differs')
    if (arm['fault'] != 'stacks_unavailable' or arm['run_id'] != run_id
            or {k: ready[k] for k in d.ARM_KEYS} != arm
            or {k: trigger[k] for k in d.ARM_KEYS} != arm
            or any(plan[k] != ready[k] for k in
                   ('fault', 'nonce', 'expires_ns', 'config_sha256', 'service_identity'))):
        raise ValueError('no-stack run/target/nonce/config/Job binding differs')
    event = trigger['observed_time_ns']
    if type(event) is not int or not arm['expires_ns'] - d.ARM_WINDOW_NS <= event < arm['expires_ns']:
        raise ValueError('no-stack trigger outside original window')
    from pathlib import PureWindowsPath
    directory = PureWindowsPath(ready['run_dir'])
    if (not directory.is_absolute() or directory.name != run_id
            or not PureWindowsPath(ready['config_path']).is_absolute()):
        raise ValueError('no-stack original child paths differ')
    names = {'managed-thread-stacks.json', 'stop-thread-stacks.txt', 'fault-child-stacks.txt'}
    if (not isinstance(context['fallback_files'], dict)
            or set(context['fallback_files']) != names
            or any(v != {'exists': False} for v in context['fallback_files'].values())):
        raise ValueError('stack fallback exists or original absence is unobserved')
    return arm


def no_stack_manifest_entry(entry):
    return (isinstance(entry, dict) and entry.get('item') == 'thread_stacks.txt'
            and entry.get('result') == 'failed'
            and entry.get('failure_reason') == 'unavailable'
            and type(entry.get('size')) is int and entry['size'] == 0
            and entry.get('sha256') is None)


def assess_no_stack_export(exported, run_id, context):
    """Re-read raw failure bytes; never edit complete, failures, or members."""
    import zipfile, tempfile
    from fakenet.mcp.incident import BASIC_ITEMS
    from fakenet.mcp.exit_native import verify_dump
    arm = validate_stack_context(context, run_id)
    path = Path(exported['path'])
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or not 0 < path.stat().st_size <= 512 * 1024 * 1024):
        raise ValueError('no-stack archive source differs')
    raw = path.read_bytes()
    if (not 0 < len(raw) <= 512 * 1024 * 1024 or len(raw) != exported['size']
            or hashlib.sha256(raw).hexdigest() != exported['sha256']
            or exported.get('run_id') != run_id or exported.get('complete') is not False):
        raise ValueError('no-stack archive transfer identity differs')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist(); names = [i.filename for i in infos]
        if (not 1 <= len(infos) <= 4096 or len(set(names)) != len(names)
                or sum(i.file_size for i in infos) > 512 * 1024 * 1024
                or any(i.flag_bits & 1 or (i.external_attr >> 16) & 0o170000 == 0o120000
                       or '/' in i.filename or '\\' in i.filename
                       or i.filename in ('', '.', '..') for i in infos)):
            raise ValueError('no-stack archive expansion/path/member refused')
        manifest = json.loads(archive.read('manifest.json'))
        if manifest.get('run_id') != run_id or manifest.get('complete') is not False:
            raise ValueError('no-stack raw manifest verdict must remain incomplete')
        if len(json.dumps(context).encode('utf-8')) > 64 * 1024:
            raise ValueError('no-stack context exceeds fixed bound')
        entries = manifest.get('entries'); seen = set(); verified = set(); missing_stack = 0
        if not isinstance(entries, list):
            raise ValueError('no-stack manifest entries absent')
        for item in entries:
            name = item['item']
            if name in seen or '/' in name or '\\' in name or name in ('', '.', '..'):
                raise ValueError('no-stack duplicate or unsafe manifest item')
            seen.add(name)
            if name == 'thread_stacks.txt':
                if not no_stack_manifest_entry(item) or name in names:
                    raise ValueError('no-stack must preserve the exact unavailable item')
                missing_stack += 1
                continue
            if incident_entry_omission_allowed(item, fault_round=True):
                continue
            if item.get('result') != 'ok':
                raise ValueError('another incident member failed: ' + name)
            data = archive.read(name)
            if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('no-stack incident member bytes differ: ' + name)
            verified.add(name)
        required = {name for name, _ in BASIC_ITEMS} - {'thread_stacks.txt'}
        if missing_stack != 1 or required - verified or 'userdump.dmp' not in verified:
            raise ValueError('no-stack other basic members or dump missing')
        if hashlib.sha256(archive.read('config_snapshot.ini')).hexdigest() != arm['config_sha256']:
            raise ValueError('no-stack original config snapshot differs')
        versions = json.loads(archive.read('versions.json'))
        managed = versions.get('managed_process') or {}; identity = managed.get('identity') or {}
        code = managed.get('exit_code')
        if (any(identity.get(k) != arm[k] for k in ('pid', 'creation_time'))
                or versions.get('config_sha256') != arm['config_sha256']
                or type(code) is not int or code & 0xffffffff not in (0xc0000602, 0xc0000409)):
            raise ValueError('no-stack original target/config/transparent exit differs')
        exit_record = json.loads(archive.read('managed-exit.json'))
        target = exit_record.get('target') or {}
        if (exit_record.get('schema') != 'fakenet.exit-result.v1' or target.get('run_id') != run_id
                or any(target.get(k) != arm[k] for k in ('pid', 'creation_time'))):
            raise ValueError('no-stack original exit monitor target differs')
        dump = archive.read('userdump.dmp')
        with tempfile.TemporaryDirectory(prefix='no-stack-dump-', dir=path.parent) as directory:
            dump_path = Path(directory) / 'userdump.dmp'; dump_path.write_bytes(dump)
            if verify_dump(dump_path, arm['pid']) != len(dump):
                raise ValueError('no-stack original dump differs')
    return {'schema': 'fakenet.diagnostic-assessment.v1', 'class': 'stacks_unavailable',
            'run_id': run_id, 'expected_unavailable': 'thread_stacks.txt',
            'raw_manifest_complete': False, 'verified_members': sorted(verified),
            'archive_sha256': exported['sha256'], 'full_acc014_credit': False}
