"""Bounded, owned pktmon capture around the P7 preflight stage.

The child scenario suite opts into the file rendezvous through
SST_P7_CAPTURE_CONTROL_DIR. No default suite verdict changes.
"""
import argparse
import base64
import hashlib
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from scenario_suite import VmMcp, quote_ps

REPO = Path(__file__).resolve().parents[3]
MAX_BYTES = 64 * 1024 * 1024
VM = 'http://192.168.204.233:28787/mcp'


def save_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def save_control(path, value):
    temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex)
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False) + '\n', encoding='utf-8')
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def vm_json(vm, command, timeout=90):
    wire = vm.powershell(command, timeout)
    return json.loads(wire['output']), wire


def start_capture(vm, owner, guest_root):
    etl = guest_root + r'\p7.etl'
    marker = guest_root + r'\owner.txt'
    command = (
        "$ErrorActionPreference='Stop';$g=" + quote_ps(guest_root) +
        ';$etl=' + quote_ps(etl) + ';$marker=' + quote_ps(marker) +
        ';$owner=' + quote_ps(owner) +
        ";if(Test-Path -LiteralPath $g){throw 'P7 guest evidence collision'};"
        "$status=(& pktmon status|Out-String);if($LASTEXITCODE -ne 0 -or "
        "($status -notmatch '没有运行' -and $status -notmatch 'not running')){throw 'pktmon already active or unknown'};"
        "New-Item -ItemType Directory -Path $g|Out-Null;"
        "[IO.File]::WriteAllText($marker,$owner,[Text.UTF8Encoding]::new($false));"
        "$owned=$false;try{"
        "$start=(& pktmon start --capture --comp all --pkt-size 0 --flags 0x1f "
        "--trace -p Microsoft-Windows-TCPIP -k 0xFF -l 4 --file-name $etl --file-size 64|Out-String);"
        "if($LASTEXITCODE -ne 0){throw ('pktmon start failed: '+$start)};$owned=$true;"
        "@{owner=$owner;etl=$etl;marker=$marker;started=[DateTimeOffset]::UtcNow.ToString('o');"
        "before=$status;start=$start;max_file_mib=64}|ConvertTo-Json -Compress"
        "}catch{if($owned){$now=(& pktmon status|Out-String);"
        "if($now -match [regex]::Escape($etl)){& pktmon stop 2>&1|Out-Null}};throw}")
    return vm_json(vm, command)


def stop_capture(vm, owner, guest_root):
    etl = guest_root + r'\p7.etl'
    marker = guest_root + r'\owner.txt'
    command = (
        "$ErrorActionPreference='Stop';$etl=" + quote_ps(etl) +
        ';$marker=' + quote_ps(marker) + ';$owner=' + quote_ps(owner) +
        ";if(-not(Test-Path -LiteralPath $marker) -or "
        "[IO.File]::ReadAllText($marker) -ne $owner){throw 'pktmon ownership marker mismatch'};"
        "$before=(& pktmon status|Out-String);if($LASTEXITCODE -ne 0){throw 'pktmon status failed'};"
        "$stop='';$stopCode=0;if($before -notmatch '没有运行' -and $before -notmatch 'not running'){"
        "if($before -notmatch [regex]::Escape($etl)){throw 'active pktmon is not owned ETL'};"
        "$stop=(& pktmon stop|Out-String);$stopCode=$LASTEXITCODE};"
        "if($stopCode -ne 0){throw ('owned pktmon stop failed: '+$stop)};"
        "$after=(& pktmon status|Out-String);if($LASTEXITCODE -ne 0 -or "
        "($after -notmatch '没有运行' -and $after -notmatch 'not running')){throw 'pktmon still active'};"
        "@{owner=$owner;etl=$etl;before=$before;stop=$stop;after=$after;"
        "ended=[DateTimeOffset]::UtcNow.ToString('o');etl_exists=(Test-Path -LiteralPath $etl)}|ConvertTo-Json -Compress")
    return vm_json(vm, command, timeout=120)


def export_capture(vm, guest_root):
    etl = guest_root + r'\p7.etl'
    pcap = guest_root + r'\p7.pcapng'
    command = (
        "$ErrorActionPreference='Stop';$etl=" + quote_ps(etl) +
        ';$pcap=' + quote_ps(pcap) +
        ";if(-not(Test-Path -LiteralPath $etl)){throw 'owned ETL absent'};"
        "if(Test-Path -LiteralPath $pcap){throw 'pcap collision'};"
        "$conversion=(& pktmon etl2pcap $etl --out $pcap|Out-String);"
        "if($LASTEXITCODE -ne 0){throw ('pktmon conversion failed: '+$conversion)};"
        "$files=@(foreach($p in @($etl,$pcap)){$i=Get-Item -LiteralPath $p;"
        "@{path=$p;size=$i.Length;sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}});"
        "@{conversion=$conversion;files=$files}|ConvertTo-Json -Depth 5 -Compress")
    return vm_json(vm, command, timeout=120)


def pull_file(vm, file_info, destination):
    size = file_info['size']
    if type(size) is not int or not 0 <= size <= MAX_BYTES:
        raise RuntimeError('guest capture file exceeds 64 MiB bound')
    digest = hashlib.sha256()
    with destination.open('xb') as stream:
        for offset in range(0, size, 1024 * 1024):
            count = min(1024 * 1024, size - offset)
            command = ("$ErrorActionPreference='Stop';$s=[IO.File]::OpenRead(" +
                       quote_ps(file_info['path']) + ");try{$null=$s.Seek(" + str(offset) +
                       ",[IO.SeekOrigin]::Begin);$b=New-Object byte[] " + str(count) +
                       ";$n=$s.Read($b,0,$b.Length);if($n -ne $b.Length){throw 'short read'};"
                       "[Convert]::ToBase64String($b)}finally{$s.Dispose()}")
            data = base64.b64decode(vm.powershell(command, 60)['output'], validate=True)
            if len(data) != count:
                raise RuntimeError('guest capture short block')
            stream.write(data)
            digest.update(data)
    if digest.hexdigest() != file_info['sha256']:
        raise RuntimeError('guest capture SHA-256 mismatch')
    return {'path': str(destination), 'size': size, 'sha256': digest.hexdigest()}


def wait_for(path, process, seconds, clock=time.monotonic, pause=time.sleep):
    deadline = clock() + seconds
    while not path.is_file() and process.poll() is None and clock() < deadline:
        pause(0.05)
    return path.is_file(), clock() >= deadline


def await_responsible_child(process, evidence_root, terminal):
    """Keep the single suite writer until its bounded API cleanup has exited."""
    try:
        pending = process.poll() is None
    except BaseException as exc:
        terminal['errors'].append('child poll interrupted: ' + repr(exc))
        pending = True
    if pending:
        try:
            save_new(evidence_root / 'recovery-pending.json', {
                'child_pid': getattr(process, 'pid', None),
                'capture_deadline_reached': terminal.get('capture_deadline_reached'),
                'capture_stop': terminal.get('stop'),
                'reason': 'waiting for original scenario suite cleanup/restore',
                'recorded_at': time.time()})
        except BaseException as exc:
            terminal['errors'].append('recovery pending record failed: ' + repr(exc))
    while True:
        try:
            terminal['process_exit'] = process.wait(timeout=30)
            return
        except subprocess.TimeoutExpired:
            event = {'event': 'child-still-responsible', 'child_pid': getattr(process, 'pid', None),
                     'recorded_at': time.time()}
        except KeyboardInterrupt:
            terminal['errors'].append('operator interrupt deferred until original child exits')
            event = {'event': 'interrupt-deferred', 'child_pid': getattr(process, 'pid', None),
                     'recorded_at': time.time()}
        except BaseException as exc:
            terminal['errors'].append('child wait failed; retaining responsibility: ' + repr(exc))
            event = {'event': 'child-wait-error', 'child_pid': getattr(process, 'pid', None),
                     'error': repr(exc), 'recorded_at': time.time()}
            try:
                time.sleep(1)
            except BaseException as retry_error:
                terminal['errors'].append('wait retry interrupted: ' + repr(retry_error))
        try:
            with (evidence_root / 'recovery-progress.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        except BaseException as exc:
            terminal['errors'].append('recovery progress record failed: ' + repr(exc))


def run(vm, suite_root, evidence_root, command, request_seconds=600, capture_seconds=120):
    evidence_root.mkdir(parents=True, exist_ok=False)
    if (suite_root / 'preflight.json').exists():
        raise RuntimeError('suite preflight already exists; use a new suite root')
    control = evidence_root / 'control'
    control.mkdir()
    owner = str(uuid.uuid4())
    guest_root = r'C:\ProgramData\FakeNet-NG-MCP\diagnostics\p7-capture-' + owner
    terminal = {'owner': owner, 'guest_root': guest_root, 'command': command,
                'suite_root': str(suite_root), 'capture_started': False,
                'process_exit': None, 'errors': []}
    process = None
    capture_may_be_owned = False
    try:
        env = dict(os.environ, SST_P7_CAPTURE_CONTROL_DIR=str(control))
        with (evidence_root / 'command.stdout.txt').open('xb') as stdout, \
                (evidence_root / 'command.stderr.txt').open('xb') as stderr:
            process = subprocess.Popen(command, cwd=REPO, env=env, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            seen, expired = wait_for(control / 'request.json', process, request_seconds)
            terminal['request_seen'] = seen
            terminal['request_deadline_reached'] = expired
            if not seen:
                raise RuntimeError('P7 capture request absent before child exit/deadline')
            request = json.loads((control / 'request.json').read_text())
            if request.get('suite_root') != str(suite_root):
                raise RuntimeError('P7 capture request suite root mismatch')
            terminal['request'] = request
            try:
                capture_may_be_owned = True
                started, wire = start_capture(vm, owner, guest_root)
                terminal['start'] = started
                terminal['capture_started'] = True
                save_new(evidence_root / 'start-wire.json', wire)
                save_control(control / 'ack.json', {'status': 'ready', **started})
            except BaseException as exc:
                terminal['errors'].append('capture-start: ' + repr(exc))
                record = getattr(exc, 'record', None)
                if record is not None:
                    save_new(evidence_root / 'start-error-wire.json', record)
                save_control(control / 'ack.json', {'status': 'error', 'error': repr(exc)})
                raise
            done, expired = wait_for(control / 'done.json', process, capture_seconds)
            terminal['done_seen'] = done
            terminal['capture_deadline_reached'] = expired
            if done:
                terminal['done'] = json.loads((control / 'done.json').read_text())
            if not done:
                terminal['errors'].append('P7 completion absent before child exit/capture deadline')
    except BaseException as exc:
        terminal['errors'].append(repr(exc))
    finally:
        if capture_may_be_owned:
            try:
                stopped, wire = stop_capture(vm, owner, guest_root)
                terminal['stop'] = stopped
                save_new(evidence_root / 'stop-wire.json', wire)
                if terminal['capture_started']:
                    exported, wire = export_capture(vm, guest_root)
                    terminal['export'] = exported
                    save_new(evidence_root / 'export-wire.json', wire)
                    terminal['capture_files'] = [pull_file(vm, item,
                        evidence_root / ntpath.basename(item['path'])) for item in exported['files']]
            except BaseException as exc:
                terminal['errors'].append('owned capture stop/export: ' + repr(exc))
                record = getattr(exc, 'record', None)
                if record is not None:
                    try:
                        save_new(evidence_root / 'stop-error-wire.json', record)
                    except BaseException as write_error:
                        terminal['errors'].append('stop error wire write failed: ' +
                                                  repr(write_error))
        if process:
            await_responsible_child(process, evidence_root, terminal)
            terminal['child_finished_at'] = time.time()
            if terminal['process_exit'] != 0:
                terminal['errors'].append('preflight child exited nonzero: ' +
                                          str(terminal['process_exit']))
        if (control / 'done.json').is_file() and not terminal.get('done'):
            terminal['done'] = json.loads((control / 'done.json').read_text())
            terminal['done_after_capture_stop'] = True
        if terminal.get('done') and terminal.get('start') and terminal.get('stop'):
            done = terminal['done']
            start = terminal['start']
            stop = terminal['stop']
            terminal['same_run_coverage'] = bool(
                terminal.get('done_seen') and not terminal.get('capture_deadline_reached') and
                done.get('run_id') and done.get('probe_started_at') and
                done.get('probe_ended_at') and
                start['started'] <= done['probe_started_at'] <=
                done['probe_ended_at'] <= stop['ended'])
        else:
            terminal['same_run_coverage'] = False
        if not terminal['same_run_coverage']:
            terminal['errors'].append('capture lacks P7 same-run timing proof')
        save_new(evidence_root / 'terminal.json', terminal)
    return terminal


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite-root', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--request-seconds', type=int, default=600)
    parser.add_argument('--capture-seconds', type=int, default=120)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if (not command or not 1 <= args.request_seconds <= 900 or
            not 1 <= args.capture_seconds <= 180):
        parser.error('provide command, request window 1..900, capture window 1..180 seconds')
    result = run(VmMcp(VM), args.suite_root, args.evidence_root, command,
                 args.request_seconds, args.capture_seconds)
    print(json.dumps({'process_exit': result['process_exit'], 'errors': result['errors'],
                      'same_run_coverage': result['same_run_coverage']}, ensure_ascii=False))
    raise SystemExit(0 if result['process_exit'] == 0 and not result['errors'] and
                     result['same_run_coverage'] else 1)


if __name__ == '__main__':
    main()
