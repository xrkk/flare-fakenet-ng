#!/usr/bin/env python3
"""One-click, operator-assisted sample payload acceptance runner.

This entry point intentionally performs no sample launch and no destructive
network operation on its own.  It is limited to an elevated, isolated
Windows VM and refuses before starting pktmon when the safety preconditions
cannot be proven.
"""

import argparse
import ctypes
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time


HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from fakenet.gui import launcher  # noqa: E402


EXIT_PASS, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
CORE_STARTED_MARKER = 'FakeNet-NG started successfully'
CORE_FAILURE_MARKERS = (
    'Traceback (most recent call last):',
    'FakeNet-NG terminated with an error',
    'FakeNet-NG stop failed',
)


def _is_admin():
    if os.name != 'nt':
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _timestamp():
    return datetime.datetime.now().strftime('%Y%m%d-%H%M%S')


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        '+00:00', 'Z')


def _unique_directory(parent, prefix):
    os.makedirs(parent, exist_ok=True)
    path = os.path.join(parent, prefix + _timestamp())
    suffix = 1
    candidate = path
    while os.path.exists(candidate):
        candidate = '%s-%d' % (path, suffix)
        suffix += 1
    os.makedirs(candidate)
    return candidate


def _run(command, transcript, check=True):
    transcript.write('$ %s\n' % ' '.join(str(item) for item in command))
    transcript.flush()
    completed = subprocess.run(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True,
                               errors='replace')
    transcript.write(completed.stdout or '')
    transcript.write('\n[exit %d]\n' % completed.returncode)
    transcript.flush()
    if check and completed.returncode != 0:
        raise RuntimeError('command failed (%d): %s' %
                           (completed.returncode, command[0]))
    return completed


def _read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as stream:
            return stream.read()
    except OSError:
        return ''


def _write_json(path, value):
    with open(path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')


def _write_hashes(directory):
    rows = []
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            path = os.path.join(root, name)
            if name == 'evidence-sha256.tsv':
                continue
            digest = hashlib.sha256()
            with open(path, 'rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            relative = os.path.relpath(path, directory).replace(os.sep, '/')
            rows.append('%s\t%s' % (relative, digest.hexdigest()))
    with open(os.path.join(directory, 'evidence-sha256.tsv'), 'w',
              encoding='ascii', newline='\n') as stream:
        stream.write('\n'.join(rows) + ('\n' if rows else ''))


def _resolve_logged_path(root, value):
    value = str(value or '').strip().strip('"')
    if not value:
        return None
    if os.path.isabs(value):
        return os.path.abspath(value)
    return os.path.abspath(os.path.join(root, value))


def _discover_active_session(root):
    """Bind the runner to one GUI-owned core session before pktmon starts."""
    gui_logs = sorted(
        glob.glob(os.path.join(root, 'Logs', 'fakenet-GUI-*.log')),
        key=os.path.getmtime, reverse=True)
    for gui_log in gui_logs:
        content = _read_text(gui_log)
        markers = list(re.finditer(
            r'FakeNet session started:\s*log=(.+)$|'
            r'FakeNet session exited:\s*code=([^\s]+)',
            content, re.M))
        if not markers or markers[-1].group(1) is None:
            continue
        core_log = _resolve_logged_path(root, markers[-1].group(1))
        if not core_log or not os.path.isfile(core_log):
            continue
        core_content = _read_text(core_log)
        if CORE_STARTED_MARKER not in core_content:
            continue
        if re.search(r'FakeNet-NG exiting:\s*rc=', core_content):
            continue
        stop_flag = core_log + '.stopflag'
        if os.path.exists(stop_flag):
            continue
        return {
            'gui_log': os.path.abspath(gui_log),
            'gui_log_offset': os.path.getsize(gui_log),
            'core_log': os.path.abspath(core_log),
            'core_log_offset': os.path.getsize(core_log),
            'stop_flag': os.path.abspath(stop_flag),
        }
    return None


def _preflight(root):
    """Return ``(refusal, session)`` before pktmon can be attempted."""
    if os.name != 'nt':
        return ('This runner must be executed inside the isolated Windows VM.',
                None)
    try:
        vm = launcher.query_vm_state()
    except Exception as exc:
        return 'VM detection failed closed: %s' % exc, None
    if vm.verdict == launcher.VERDICT_PHYSICAL:
        return (('Physical machine detected (%s / %s); isolated VM is required.' %
                 (vm.manufacturer, vm.model)), None)
    if vm.verdict != launcher.VERDICT_VM:
        return (('VM detection inconclusive; refusing before pktmon starts: %s' %
                 (vm.detail or vm.verdict)), None)
    if not _is_admin():
        return 'Administrator elevation is required before capture starts.', None
    if not os.path.isdir(root):
        return 'Package root does not exist: %s' % root, None
    if shutil.which('pktmon') is None:
        return 'pktmon.exe is not available; no capture was started.', None
    if not launcher.is_fakenet_running():
        return ('No GUI-owned FakeNet core is running. Start FakeNet from the '
                'GUI with the sample configuration, then run this entry.', None)
    session = _discover_active_session(root)
    if session is None:
        return ('Unable to bind one active GUI/core log pair; refusing before '
                'pktmon starts.', None)
    return None, session


def _stop_pktmon(state, transcript):
    """Stop pktmon once; callers use this both normally and in finally."""
    if not state.get('started') or state.get('stop_attempted'):
        return True
    state['stop_attempted'] = True
    try:
        completed = _run(['pktmon', 'stop'], transcript, check=False)
    except Exception as exc:
        transcript.write('FAIL: pktmon stop raised: %s\n' % exc)
        transcript.flush()
        state['stopped'] = True
        return False
    state['stop_returncode'] = completed.returncode
    state['stopped'] = True
    if completed.returncode != 0:
        transcript.write('FAIL: pktmon stop returned %d\n' %
                         completed.returncode)
        transcript.flush()
        return False
    return True


def _read_suffix(path, offset):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as stream:
            stream.seek(offset)
            return stream.read()
    except OSError:
        return ''


def _wait_for_gui_stop(session, timeout=120.0, poll_interval=0.05):
    """Observe GUI stop feedback and its owned core process handle result."""
    started = time.monotonic()
    stop_seen = None
    feedback_seen = None
    handle_returned = None
    core_exit_seen = None
    stop_flag = session['stop_flag']
    handle_code = None
    core_exit_code = None
    gui_exit_code = None
    gui_log = None
    events = []

    def event(name, detail):
        events.append({'event': name, 'utc': _utc_now(), 'detail': detail})

    deadline = started + float(timeout)
    while time.monotonic() < deadline:
        now = time.monotonic()
        if stop_seen is None and os.path.isfile(stop_flag):
            stop_seen = now
            event('stop_flag_seen', stop_flag)
        gui_log = session['gui_log']
        if stop_seen is not None:
            content = _read_suffix(gui_log, session['gui_log_offset'])
            stop_match = re.search(
                r'Stop requested via flag:\s*(.+)', content)
            if stop_match and feedback_seen is None:
                logged_flag = os.path.normcase(os.path.abspath(
                    stop_match.group(1).strip()))
                if logged_flag == os.path.normcase(stop_flag):
                    feedback_seen = now
                    event('gui_stop_feedback_seen', gui_log)
            handle_match = re.search(
                r'FakeNet session exited: code=([^\s]+)', content)
            if handle_match and handle_returned is None:
                handle_returned = now
                handle_code = handle_match.group(1)
                event('top_handle_returned',
                      'code=%s log=%s' % (handle_code, gui_log))

        core_content = _read_suffix(
            session['core_log'], session['core_log_offset'])
        match = re.search(r'FakeNet-NG exiting: rc=([^\s]+)', core_content)
        if match and core_exit_seen is None:
            core_exit_seen = now
            core_exit_code = match.group(1)
            event('core_exit_seen',
                  'code=%s log=%s' % (core_exit_code, session['core_log']))

        if handle_returned is not None and core_exit_seen is not None:
            break
        time.sleep(poll_interval)

    elapsed = time.monotonic() - started
    return {
        'events': events,
        'gui_log': gui_log,
        'stop_flag': stop_flag,
        'feedback_seconds': (
            feedback_seen - stop_seen
            if feedback_seen is not None and stop_seen is not None else None),
        'top_handle_seconds': (
            handle_returned - stop_seen
            if handle_returned is not None and stop_seen is not None else None),
        'handle_code': handle_code,
        'core_exit_code': core_exit_code,
        'core_exit_seen': core_exit_seen is not None,
        'gui_exit_code': gui_exit_code,
        'timed_out': handle_returned is None or core_exit_seen is None,
        'wait_seconds': elapsed,
    }


def _core_session_ok(paths):
    if not paths:
        return False
    for path in paths:
        content = _read_text(path)
        if CORE_STARTED_MARKER not in content:
            continue
        if any(marker in content for marker in CORE_FAILURE_MARKERS):
            continue
        if ('PCAP_DUAL_WRITE_FAILED' in content or
                'HTML_REPORT_SUPPRESSED' in content or
                'overall_health=false' in content):
            continue
        codes = re.findall(r'FakeNet-NG exiting: rc=([^\s]+)', content)
        if codes and codes[-1] == '0' and 'Stopping...' in content:
            return True
    return False


def _write_failure_results(output, detail):
    with open(os.path.join(output, 'results.tsv'), 'w',
              encoding='utf-8', newline='\n') as results:
        results.write('check\tstatus\tdetail\n')
        results.write('sample_payload_acceptance\tFAIL\t%s\n' % detail)


def _copy_session_evidence(root, output, session):
    """Copy only paths proven to belong to the bound core session."""
    core_content = _read_text(session['core_log'])
    copied = {
        'gui_log': shutil.copy2(session['gui_log'], output),
        'core_log': shutil.copy2(session['core_log'], output),
    }
    patterns = {
        'config': r'Loaded configuration file:\s*(.+)$',
        'raw_pcap': r'PCAP_DUAL_SUMMARY\s+raw=([^\s]+)',
        'converted_pcap': r'PCAP_DUAL_SUMMARY\s+raw=[^\s]+\s+ethernet=([^\s]+)',
        'html': r'Generated new HTML report:\s*(.+)$',
    }
    for name, pattern in patterns.items():
        matches = re.findall(pattern, core_content, re.M)
        if not matches:
            raise RuntimeError('session log does not identify %s' % name)
        source = _resolve_logged_path(root, matches[-1])
        if not source or not os.path.isfile(source):
            raise RuntimeError('session %s evidence is missing: %s' %
                               (name, source))
        target_name = ('report.html' if name == 'html' else
                       'session.ini' if name == 'config' else
                       os.path.basename(source))
        target = os.path.join(output, target_name)
        shutil.copy2(source, target)
        copied[name] = target
    return copied


def run(root, gui_exe=None):
    del gui_exe  # retained only for command-line compatibility with v35 drafts
    refusal, session = _preflight(root)
    if refusal:
        print('REFUSED: %s' % refusal)
        return EXIT_REFUSED

    output = _unique_directory(os.path.join(root, 'test', 'gui_vm', 'Logs'),
                               'sample-payload-')
    transcript_path = os.path.join(output, 'console-transcript.txt')
    observation_path = os.path.join(output, 'session-observation.json')
    result = EXIT_FAIL
    failure_detail = 'sample payload acceptance did not complete'
    pktmon_state = {
        'start_attempted': False, 'start_returncode': None,
        'started': False, 'stop_attempted': False, 'stopped': False,
        'stop_returncode': None,
        'wire_etl': os.path.join(output, 'wire.etl'),
    }
    observation = {
        'schema': 'fakenet.sample-payload-session.v1',
        'session': dict(session),
        'pktmon': dict(pktmon_state),
        'events': [],
    }
    with open(transcript_path, 'w', encoding='utf-8', newline='\n') as transcript:
        try:
            _run(['pktmon', 'filter', 'remove'], transcript, check=False)
            # Mark the start as attempted before invoking the native command.
            # If pktmon starts and then reports a non-zero status, the finally
            # block must still issue the safe stop command rather than leave a
            # capture session behind.
            pktmon_state['start_attempted'] = True
            pktmon_state['started'] = True
            start_result = _run(
                ['pktmon', 'start', '--capture', '--pkt-size', '0',
                 '--file-name', pktmon_state['wire_etl'], '--comp', 'nics'],
                transcript)
            pktmon_state['start_returncode'] = start_result.returncode
            print('ACTION 1: Start the sample only inside this isolated VM.')
            print('ACTION 2: Wait for both directions of payload, then click the GUI Stop button.')
            print('WAIT: This tool detects the stop flag and exports evidence automatically.')

            observation.update(_wait_for_gui_stop(session))
            observation['pktmon'] = dict(pktmon_state)
            _write_json(observation_path, observation)
            if observation['timed_out']:
                raise RuntimeError(
                    'GUI stop feedback/core/top-handle completion was not observed')
            if observation['handle_code'] != '0':
                raise RuntimeError('GUI-owned FakeNet handle returned %s' %
                                   observation['handle_code'])
            if observation['core_exit_code'] != '0':
                raise RuntimeError('FakeNet core returned %s' %
                                   observation['core_exit_code'])
            if (observation['feedback_seconds'] is None or
                    observation['feedback_seconds'] > 1.0):
                raise RuntimeError('GUI stop feedback exceeded one second')
            if (observation['top_handle_seconds'] is None or
                    observation['top_handle_seconds'] > 5.0):
                raise RuntimeError('GUI-owned core handle exceeded five seconds')
            if not _stop_pktmon(pktmon_state, transcript):
                raise RuntimeError('pktmon stop failed')
            observation['pktmon'] = dict(pktmon_state)

            _run(['pktmon', 'etl2pcap', pktmon_state['wire_etl'], '--out',
                  os.path.join(output, 'wire.pcapng')], transcript)
            copied = _copy_session_evidence(root, output, session)
            html = copied['html']

            if not _core_session_ok([copied['core_log']]):
                raise RuntimeError('core log does not prove a normal rc=0 stop')
            verifier = os.path.join(root, 'test', 'gui_vm',
                                    'verify_payload_report.py')
            verification = os.path.join(output, 'html-verification.json')
            _run([sys.executable, verifier, '--html', html, '--output',
                  verification], transcript)
            wire = os.path.join(output, 'wire.pcapng')
            if not os.path.isfile(wire):
                raise RuntimeError(
                    'three-way verifier inputs are incomplete (raw/wire/log/INI)')
            integrity = os.path.join(root, 'test', 'gui_vm',
                                     'verify_payload_integrity.py')
            three_way = os.path.join(output, 'payload-verification.json')
            _run([sys.executable, integrity, '--raw-pcap', copied['raw_pcap'],
                  '--wire-pcapng', wire, '--html', html,
                  '--log', copied['core_log'], '--ini', copied['config'],
                  '--output', three_way], transcript)
            with open(os.path.join(output, 'results.tsv'), 'w',
                      encoding='utf-8', newline='\n') as results:
                results.write('check\tstatus\tdetail\n')
                results.write('pktmon_nics\tPASS\tNIC full-size capture\n')
                results.write('gui_feedback_within_1s\tPASS\t%.3f seconds\n' %
                              observation['feedback_seconds'])
                results.write('top_handle_within_5s\tPASS\t%.3f seconds\n' %
                              observation['top_handle_seconds'])
                results.write('core_rc0\tPASS\tcore exit 0\n')
                results.write('html_payload_verifier\tPASS\t%s\n' % verification)
                results.write('three_way_payload_verifier\tPASS\t%s\n' % three_way)
            result = EXIT_PASS
            failure_detail = ''
        except (EOFError, KeyboardInterrupt):
            failure_detail = 'operator interrupted before completion'
            transcript.write('FAIL: %s\n' % failure_detail)
            _write_failure_results(output, failure_detail)
        except Exception as exc:
            failure_detail = str(exc)
            transcript.write('FAIL: %s\n' % failure_detail)
            _write_failure_results(output, failure_detail)
        finally:
            if not _stop_pktmon(pktmon_state, transcript):
                result = EXIT_FAIL
                if not failure_detail:
                    failure_detail = 'pktmon stop failed'
                    _write_failure_results(output, failure_detail)
            observation['pktmon'] = dict(pktmon_state)
            observation['result'] = result
            if failure_detail:
                observation['failure'] = failure_detail
            try:
                _write_json(observation_path, observation)
            except OSError as exc:
                transcript.write('FAIL: unable to persist session observation: %s\n' %
                                 exc)
                result = EXIT_FAIL
            try:
                transcript.flush()
                _write_hashes(output)
            except OSError as exc:
                transcript.write('FAIL: unable to hash evidence: %s\n' % exc)
                result = EXIT_FAIL
    print('EVIDENCE_PATH=%s' % os.path.abspath(output))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--package-root', default=os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..')))
    parser.add_argument('--gui-exe')
    args = parser.parse_args(argv)
    return run(os.path.abspath(args.package_root), args.gui_exe)


if __name__ == '__main__':
    raise SystemExit(main())
