"""Per-run endpoint evidence. No evidence file authorizes network recovery."""
import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from fakenet.mcp.endpoint_trace import (
    complete_trace, owned_trace_sessions, trace_action_script,
    trace_inventory_script)


def powershell_json(script, deadline=None):
    from fakenet.mcp.baseline import _run, COLLECTION_FAILED
    timeout = 60 if deadline is None else min(60, deadline - time.monotonic())
    if timeout <= 0:
        raise TimeoutError('endpoint observation deadline')
    raw = _run(['powershell', '-NoProfile', '-Command', script], timeout=timeout)
    if raw == COLLECTION_FAILED:
        raise RuntimeError('endpoint observation command failed')
    return json.loads(raw)


def write_evidence(path, payload):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def process_identities_script():
    return ("$ErrorActionPreference='Stop'; ConvertTo-Json -InputObject "
            "@(Get-CimInstance Win32_Process | Select-Object ProcessId,"
            "@{Name='CreationTime';Expression={if($_.CreationDate){"
            "$_.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString()}}}) "
            "-Depth 4 -Compress")


def event_export_script(path):
    payload = base64.b64encode(str(path).encode()).decode()
    return ("$ErrorActionPreference='Stop'; $p=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String('" + payload + "')); "
            "$rows=@(Get-WinEvent -Path $p -Oldest | Where-Object {"
            "$_.ProviderName -eq 'Microsoft-Windows-Winsock-AFD'} | "
            "ForEach-Object {@{provider=$_.ProviderName;id=$_.Id;"
            "time=$_.TimeCreated.ToUniversalTime().ToString('o');xml=$_.ToXml()}}); "
            "ConvertTo-Json -InputObject $rows -Depth 5 -Compress")


class EndpointObservation:
    """The caller supplies a current run identity, never a stored command."""

    def __init__(self, directory, run_id, execute=powershell_json):
        self.directory = Path(directory)
        self.run_id = str(uuid.UUID(run_id))
        self.active = self.directory / 'udp.etl.part'
        self.final = self.directory / 'udp.etl'
        self.execute = execute
        self.start_info = None
        self.finished = None

    def _action(self, action, deadline=None):
        return self.execute(trace_action_script(action, self.run_id, self.active), deadline)

    def start(self, deadline=None):
        if (self.directory / 'endpoint-trace-start.json').exists() or self.final.exists():
            raise FileExistsError('endpoint evidence already exists')
        self.start_info = self._action('start', deadline)
        processes = self.execute(process_identities_script(), deadline)
        write_evidence(self.directory / 'endpoint-trace-start.json', {
            'run_id': self.run_id, 'time_ns': time.time_ns(),
            'trace': self.start_info, 'processes': processes})

    def finish(self, deadline=None):
        if self.finished is not None:
            return self.finished
        report = {'run_id': self.run_id, 'complete': False, 'absent': False}
        try:
            live = self._action('query', deadline)
            if live.get('Code') in (4201, 1168):
                report['absent'] = True
                report['failure'] = 'trace was already absent; coverage unverified'
            else:
                # Native stop independently rechecks live GUID and exact path.
                report['stop'] = self._action('stop', deadline)
                report['after_stop'] = self._action('query', deadline)
                report['absent'] = report['after_stop'].get('Code') in (4201, 1168)
                if not report['absent']:
                    raise RuntimeError('endpoint trace remains active')
                if self.final.exists():
                    raise FileExistsError('refuse to replace completed trace')
                self.active.rename(self.final)
                raw = self.final.read_bytes()
                report.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                if self.start_info is None:
                    # Optional evidence only; the live identity above remains
                    # the sole basis for stopping this diagnostic session.
                    start = json.loads((self.directory / 'endpoint-trace-start.json').read_text())
                    if start.get('run_id') != self.run_id:
                        raise ValueError('trace start evidence identity mismatch')
                    self.start_info = start['trace']
                report['complete'] = complete_trace(
                    self.start_info, report['stop'], report['after_stop'], len(raw))
                report['processes'] = self.execute(process_identities_script(), deadline)
                events = self.execute(event_export_script(self.final), deadline)
                from fakenet.mcp.endpoint_evidence import udp_lifetimes
                write_evidence(self.directory / 'endpoint-events.json', {
                    'run_id': self.run_id, 'etl_sha256': report['sha256'], 'events': events})
                write_evidence(self.directory / 'endpoint-lifetimes.json', {
                    'run_id': self.run_id, 'lifetimes': udp_lifetimes(events)})
        except Exception as exc:
            report['complete'] = False
            report['failure'] = repr(exc)
        report['time_ns'] = time.time_ns()
        write_evidence(self.directory / ('endpoint-trace-end-%s.json' % uuid.uuid4()), report)
        if report['absent']:
            self.finished = report
        return report

    def audit_proof(self, deadline=None):
        """Read only this completed run's hash-bound evidence for comparison."""
        end = self.finish(deadline)
        if end.get('complete') is not True or end.get('absent') is not True:
            raise ValueError('endpoint observation is incomplete')
        start = json.loads((self.directory / 'endpoint-trace-start.json').read_text())
        events = json.loads((self.directory / 'endpoint-events.json').read_text())
        digest = hashlib.sha256(self.final.read_bytes()).hexdigest()
        if (start.get('run_id') != self.run_id or events.get('run_id') != self.run_id or
                end['sha256'] != digest or events.get('etl_sha256') != digest):
            raise ValueError('endpoint evidence identity/hash mismatch')
        return dict(run_id=self.run_id, start=start, end=end,
                    events=events['events'], etl_sha256=digest)


def stop_orphan_observers(artifacts_root, exclude_run=None, execute=powershell_json):
    """At exclusive service entry, clean owned live sessions, not stored jobs."""
    live = execute(trace_inventory_script(), None)
    if not isinstance(live, list):
        raise ValueError('endpoint trace inventory is incomplete')
    result = []
    for item in owned_trace_sessions(live, artifacts_root, exclude_run):
        stop = execute(trace_action_script('stop', item['run_id'], item['path']), None)
        after = execute(trace_action_script('query', item['run_id'], item['path']), None)
        if after.get('Code') not in (4201, 1168):
            raise RuntimeError('orphan endpoint observer remains active')
        result.append(dict(item, stop=stop, after_stop=after))
    return result
