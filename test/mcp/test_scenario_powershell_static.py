"""Portable lexical and control checks for generated shared-capture PowerShell.

These checks do not execute PowerShell or native capture commands.
"""
import base64
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite


PROFILE = {'bucket':'B1','tempo':'normal','variant':'v','interleave':'restart-window',
           'cadence_ms':100,'connection_window_seconds':10,
           'probe_target':{'host':'example.com','port':443,'protocol':'tls'}}


def code_mask(source):
    """Blank quoted strings/comments while retaining source offsets and braces."""
    out = list(source)
    state = 'code'
    pos = 0
    while pos < len(source):
        char = source[pos]
        if state == 'code':
            if char == "'":
                out[pos] = ' '; state = 'single'
            elif char == '"':
                out[pos] = ' '; state = 'double'
            elif char == '#':
                out[pos] = ' '; state = 'comment'
        elif state == 'single':
            out[pos] = ' '
            if char == "'":
                if pos + 1 < len(source) and source[pos + 1] == "'":
                    pos += 1; out[pos] = ' '
                else:
                    state = 'code'
        elif state == 'double':
            out[pos] = ' '
            if char == '`' and pos + 1 < len(source):
                pos += 1; out[pos] = ' '
            elif char == '"':
                state = 'code'
        else:
            if char == '\n':
                state = 'code'
            else:
                out[pos] = ' '
        pos += 1
    if state in ('single', 'double'):
        raise ValueError('unterminated PowerShell string')
    return ''.join(out)


def delimiters(source):
    """Check all PowerShell delimiters outside strings and return brace spans."""
    masked = code_mask(source)
    stack = []
    spans = []
    closing = {')':'(', ']':'[', '}':'{'}
    for pos, char in enumerate(masked):
        if char in '([{':
            stack.append((char, pos))
        elif char in closing:
            if not stack or stack[-1][0] != closing[char]:
                raise ValueError(f'unmatched {char} at {pos}')
            opening, start = stack.pop()
            if opening == '{':
                spans.append((start, pos))
    if stack:
        raise ValueError(f'unclosed {stack[-1][0]} at {stack[-1][1]}')
    return masked, spans


def runner():
    target = suite.Suite.__new__(suite.Suite)
    target.vm = object()
    target.guest_work_root = suite.E_GUEST_WORK_ROOT
    target.capture_contract = 'scenario-shared-v2'
    target.native_clock_diagnostic = True
    target.identity = SimpleNamespace(candidate_id='candidate')
    target.pktmon_file_size_mib = 128
    target._start_kernel_capture = lambda root: {'session_name':'owned-kernel'}
    target._stop_kernel_capture = lambda kernel: {'files':[],'raw':'kernel wire'}
    return target


def capture(shared=False):
    base = r'E:\scope\run-02' if shared else r'E:\scope\run-01'
    row = {'pid':101,'probe_creation_ticks':123,'probe':base+r'\probe.jsonl',
           'stop':base+r'\probe.stop','etl':r'E:\scope\run-01\pktmon.etl',
           'pktmon_nic':r'E:\scope\run-01\pktmon-nic.json',
           'stdout':base+r'\probe.stdout','stderr':base+r'\probe.stderr',
           'kernel_capture':{'session_name':'owned-kernel'},
           'physical_owner_id':'nonce:pktmon','capture_run_id':'nonce:run-02' if shared else 'nonce:run-01',
           'nonce':'nonce','run_label':'run-02' if shared else 'run-01'}
    if shared: row['shared_physical'] = True
    return row


def generated_commands(monkeypatch):
    target = runner()
    commands = {}
    def wire(label, value):
        def call(command, timeout):
            commands.setdefault(label, []).append(command)
            return value, 'synthetic wire'
        target._vm_json = call
    wire('first-start', {'startup_failed':True,'cooperative_exit':'exited',
                         'physical_terminal':'stopped','cooperative_errors':[]})
    with pytest.raises(suite.SuiteError, match='startup failed'):
        target._start_capture_and_probe(r'E:\scope', PROFILE, 'nonce', 'run-01')
    owner = {'run_label':'run-01','etl':r'E:\scope\run-01\pktmon.etl',
             'pktmon_nic':r'E:\scope\run-01\pktmon-nic.json',
             'physical_owner_id':'nonce:pktmon'}
    wire('second-start', {'physical_owner_id':owner['physical_owner_id'],
        'etl':owner['etl'],'pktmon_nic':owner['pktmon_nic'],
        'guest':r'E:\scope\run-02','run_label':'run-02',
        'nonce':'nonce','capture_run_id':'nonce:run-02',
        'probe':r'E:\scope\run-02\probe.jsonl','pid':102,
        'probe_creation_ticks':124})
    target._start_probe_on_shared_capture(r'E:\scope',PROFILE,'nonce','run-02',owner)
    wire('snapshot', {'probe_ready':None,'process':None,'pktmon_status':'Not Running',
                      'pktmon_exit':0,'etl_exists':False})
    target._capture_start_snapshot(r'E:\scope\run-01',owner['etl'],'nonce','run-01')
    monkeypatch.setattr(suite.time,'sleep',lambda _:None)
    stop_calls = []
    def shared_wire(command, timeout):
        stop_calls.append(command)
        if len(stop_calls)==1:return {'coop':{'cooperative_exit':'exited','errors':[]}},'coop wire'
        return {'files':[]},'files wire'
    target._vm_json = shared_wire
    target._stop_capture_and_probe(capture(shared=True))
    commands['second-stop'] = stop_calls
    owner_calls = []
    def owner_wire(command, timeout):
        owner_calls.append(command)
        if len(owner_calls)==1:return {'coop':{'cooperative_exit':'exited','errors':[]}},'coop wire'
        if len(owner_calls)==2:return {'owner_id':'nonce:pktmon','output':'stopped',
            'exit':0,'status':'Not Running','status_exit':0},'stop wire'
        if len(owner_calls)==3:return {'conversion':{},'status':'Not Running'},'convert wire'
        return {'files':[]},'files wire'
    target._vm_json = owner_wire
    target._stop_capture_and_probe(capture())
    commands['physical-stop-convert'] = owner_calls
    commands['cooperative-body'] = [target._probe_cooperative_cleanup_command(
        101,123,r'E:\scope\run-01\probe.stop',r'E:\scope\run-01\probe.exit-status.json',None)]
    return commands


def test_generated_shared_commands_have_balanced_lexical_structure(monkeypatch):
    commands = generated_commands(monkeypatch)
    assert {name:len(values) for name,values in commands.items()} == {
        'first-start':1,'second-start':1,'snapshot':1,'second-stop':2,
        'physical-stop-convert':4,'cooperative-body':1}
    for name, values in commands.items():
        for index, command in enumerate(values):
            try:
                delimiters(command)
            except ValueError as exc:
                pytest.fail(f'{name}[{index}] lexical structure invalid: {exc}')
    first = commands['first-start'][0]
    encoded = re.search(r"\$encoded='([A-Za-z0-9+/=]+)'",first)
    assert encoded is not None
    delimiters(base64.b64decode(encoded[1]).decode('utf-16-le'))


def test_start_catch_physical_stop_is_nested_in_proven_terminal_guard(monkeypatch):
    first = generated_commands(monkeypatch)['first-start'][0]
    masked, spans = delimiters(first)
    stop = masked.index('pktmon stop')
    catch = [m for m in re.finditer(r'catch\s*\{',masked)
             if m.start() < stop and any(start == m.end()-1 and end > stop
                                          for start,end in spans)]
    assert catch
    guards = (r'if\(\$captureStarted\)\s*\{',
              r'if\(\$probeTerminal -eq .*?-or \$probeTerminal -eq .*?\)\s*\{',
              r'if\(\$errors.Count -eq 0\)\s*\{')
    for pattern in guards:
        matches = [m for m in re.finditer(pattern,masked)
                   if m.start() < stop and any(start == m.end()-1 and end > stop
                                                for start,end in spans)]
        assert matches, pattern
    assert 'identity-mismatch' in first
    # The old extra } after identity-mismatch must fail this same full-command check.
    broken = first.replace("$probeTerminal='identity-mismatch'}}}};",
                           "$probeTerminal='identity-mismatch'}}}}};")
    assert broken != first
    with pytest.raises(ValueError,match='unmatched'):
        delimiters(broken)


def test_start_catch_identity_and_start_unknown_branches_remain_inside_catch():
    body = suite.Suite._shared_start_failure_ps()
    masked, spans = delimiters(body)
    outer = next((start,end) for start,end in spans if start == masked.index('{'))
    assert outer[1] == len(body)-1
    def guard(pattern, target):
        pos = masked.index(target)
        return any(start < pos < end for match in re.finditer(pattern,masked)
                   for start,end in spans if start == match.end()-1)
    assert guard(r'if\(\$probeCreateAttempted\)\s*\{','Get-Process -Id $launchPidOut')
    assert guard(r'if\(\$probeCreateAttempted\)\s*\{','WriteAllText($stop')
    assert guard(r'if\(\$captureStarted\)\s*\{','pktmon stop')
    assert 'elseif($pktmonStartAttempted){$physicalTerminal=' in body
    assert outer[0] < masked.index('$physicalTerminal=') < outer[1]
    assert outer[0] < masked.index('ConvertTo-Json -Depth 6') < outer[1]
