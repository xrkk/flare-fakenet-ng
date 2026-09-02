# Copyright 2026 Google LLC
"""Shared helpers for the P01 ACC runner (§9.1 contract implementation)."""

import json
import subprocess
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import anyio

from mcp import Client

DEFAULT_WIN10VM_MCP = 'http://192.168.204.149:28787/mcp'
HOST_ONLY_BIND = '192.168.204.1'


class StepError(RuntimeError):
    pass


def run_local(command, cwd=None, timeout=120):
    completed = subprocess.run(
        [str(item) for item in command], cwd=cwd, capture_output=True,
        text=True, timeout=timeout)
    return {
        'command': [str(item) for item in command],
        'returncode': completed.returncode,
        'stdout': completed.stdout,
        'stderr': completed.stderr,
    }


class PackageServer:
    """Temporary host-only HTTP service bound to 192.168.204.1 only."""

    def __init__(self, root, port=0):
        self.root = Path(root).resolve()
        handler = _make_handler(self.root)
        self.httpd = ThreadingHTTPServer((HOST_ONLY_BIND, port), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)

    @property
    def base_url(self):
        return 'http://%s:%d' % (HOST_ONLY_BIND, self.port)


def _make_handler(root):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, format, *args):  # noqa: A002
            pass

    return Handler


class Win10VmChannel:
    """Drive the acceptance VM through its existing Win10VM MCP server."""

    def __init__(self, url=DEFAULT_WIN10VM_MCP):
        self.url = url

    def powershell(self, command, timeout=120):
        record = {'tool': 'PowerShell', 'command': command,
                  'timeout': timeout}

        async def _call():
            async with Client(self.url,
                              read_timeout_seconds=timeout + 30) as client:
                result = await client.call_tool(
                    'PowerShell', {'command': command, 'timeout': timeout})
                return result

        outcome = anyio.run(_call)
        record['is_error'] = bool(getattr(outcome, 'is_error', False))
        texts = []
        content = getattr(outcome, 'content', None) or []
        for item in content:
            text = getattr(item, 'text', None)
            if text is not None:
                texts.append(text)
        raw = '\n'.join(texts)
        record['raw'] = raw
        output = raw
        exit_code = None
        marker = 'Status Code:'
        index = raw.rfind(marker)
        if index >= 0:
            tail = raw[index + len(marker):].strip()
            try:
                exit_code = int(tail.splitlines()[0].strip() or '0')
            except (ValueError, IndexError):
                exit_code = None
            output = raw[:index]
        if output.startswith('Response:'):
            output = output[len('Response:'):]
        record['output'] = output.strip()
        record['exit_code'] = exit_code
        if record['is_error'] or (exit_code or 0) != 0:
            raise StepError('PowerShell failed (exit=%s): %s' %
                            (exit_code, raw[:500]))
        return record

    def computer_name(self):
        record = self.powershell('$env:COMPUTERNAME', timeout=60)
        return record['output'].strip()


class EvidenceWriter:

    def __init__(self, out_dir, started_at):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.started_at = started_at
        self.actions = []
        self.expected = []
        self.observed = []
        self.evidence = []
        self.blocker = None

    def action(self, name, detail):
        self.actions.append({'name': name, 'detail': detail})

    def expect(self, text):
        self.expected.append(text)

    def observe(self, text):
        self.observed.append(text)

    def add_evidence(self, name, content):
        if isinstance(content, (dict, list)):
            import hashlib
            import io

            raw = json.dumps(content, ensure_ascii=False, indent=2).encode(
                'utf-8')
            digest = hashlib.sha256(raw).hexdigest()
            path = self.out_dir / (name + '.json')
            path.write_bytes(raw)
        else:
            import hashlib

            raw = str(content).encode('utf-8')
            digest = hashlib.sha256(raw).hexdigest()
            path = self.out_dir / name
            suffix = Path(name).suffix or '.txt'
            path = self.out_dir / (Path(name).stem + suffix)
            path.write_bytes(raw)
        self.evidence.append({
            'name': name, 'path': str(path), 'sha256': digest,
            'size': len(raw)})
        return path

    def write_result(self, *, acc_id, p_id, candidate_id, source_commit,
                     package_sha256, requirements_blob, master_plan_blob,
                     environment_identity, status):
        import datetime

        result = {
            'acc_id': acc_id,
            'p_id': p_id,
            'candidate_id': candidate_id,
            'source_commit': source_commit,
            'package_sha256': package_sha256,
            'requirements_blob': requirements_blob,
            'master_plan_blob': master_plan_blob,
            'environment_identity': environment_identity,
            'started_at': self.started_at,
            'ended_at': datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            'status': status,
            'actions': self.actions,
            'expected': self.expected,
            'observed': self.observed,
            'evidence': self.evidence,
            'blocker': self.blocker,
        }
        (self.out_dir / 'result.json').write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')
        return result


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2
EXIT_TOOL_ERROR = 3
