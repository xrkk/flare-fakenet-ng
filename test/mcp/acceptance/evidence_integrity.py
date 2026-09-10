"""Reject mixed identities, missing raw evidence and incomplete round windows."""
import hashlib
import json
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


def validate_round(record, expected):
    failures = []
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
                failures.extend(validate_incident_export(exported, run_id))
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
                    record['load_response']['config_identity'] != identity or
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
        if (record.get('class') != expected or trigger.get('fault') != expected or
                trigger.get('nonce') != record.get('nonce') or not record.get('nonce') or
                receipt.get('run_id') != record.get('run_id') or
                (record.get('start_response') or {}).get('run_id') != record.get('run_id')):
            failures.append('fault sample run/category/trigger mismatch')
    return failures


def validate_incident_export(exported, run_id):
    """Re-read actual members; a cached complete flag is insufficient."""
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
            if manifest.get('run_id') != run_id or not manifest.get('complete'):
                raise ValueError('actual manifest not complete for this run')
            names = set()
            verified = set()
            for item in manifest.get('entries', []):
                name = item['item']
                if name in names or '/' in name or '\\' in name or name in ('', '.', '..'):
                    raise ValueError('invalid or duplicate incident member')
                names.add(name)
                if item['result'] == 'skipped' and name == 'userdump.dmp' and item.get('failure_reason') == 'no escalation condition' and item.get('size') == 0 and item.get('sha256') is None:
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
    if found != {'webroot', 'prefix'}:
        raise ValueError('builtin does not contain the required custom delta fields')
    body = '\n'.join(lines) + '\n'
    if body == content.replace('\r\n', '\n'):
        raise ValueError('custom configuration has no semantic delta')
    return body
