"""Bounded command staging; no business or recovery authority is granted here.

Short commands use the original client. Long commands are dot-sourced by the
same remote PowerShell executor after exact-byte staging and SHA verification.
The caller supplies the current mutation responsibility and a pinned context.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import time
import uuid

from bounded_mcp import TransportUnknown
from .context import RunContext, exact_path


LIMIT = 32767
WRAPPER_RESERVE = 2048
CHUNK = 1024
MAX_SCRIPT = 4 * 2 ** 20
ENCODED_TOKEN = re.compile(r"(\$encoded\s*=\s*')([A-Za-z0-9+/=]+)(')")
FILE_VARIABLE = re.compile(r"(?i)[$](PSScriptRoot|PSCommandPath|MyInvocation)\b")


class CommandTransportError(RuntimeError):
    """Command staging cannot safely continue."""


def units(text: str) -> int:
    return len(text.encode('utf-16-le')) // 2


def wire_units(command: str) -> int:
    encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
    return units(encoded) + WRAPPER_RESERVE + 1


def map_command(command: str, replacements: tuple[tuple[str, str], ...]) -> str:
    """Map literal namespace text and the original $encoded UTF16LE tokens."""
    def replace(text):
        for old, new in replacements:
            text = text.replace(old, new)
        return text

    def encoded(match):
        child = base64.b64decode(match[2], validate=True).decode('utf-16-le')
        mapped = replace(child)
        if mapped == child:
            return match[0]
        return match[1] + base64.b64encode(mapped.encode('utf-16-le')).decode('ascii') + match[3]

    return replace(ENCODED_TOKEN.sub(encoded, command))


def quote(path: str) -> str:
    return "'" + path.replace("'", "''") + "'"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def script_bytes(command: str) -> bytes:
    return b'\xef\xbb\xbf' + command.encode('utf-8')


def short_execute(path: str, sha256: str) -> str:
    # Keep the original dot-source semantics, read hold, and EAP restoration.
    return (
        "$__r46SavedEap=$ErrorActionPreference;$ErrorActionPreference='Stop';"
        "$__r46StageFile=" + quote(path) + ";"
        "$__r46ReadHold=[IO.File]::Open($__r46StageFile,[IO.FileMode]::Open,"
        "[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"
        "if((Get-FileHash -LiteralPath $__r46StageFile -Algorithm SHA256).Hash.ToLower() -cne '" +
        sha256 + "'){throw 'r46 execute SHA mismatch'};"
        "$ErrorActionPreference=$__r46SavedEap;. $__r46StageFile}finally{"
        "$__r46ReadHold.Dispose();$ErrorActionPreference=$__r46SavedEap}")


def chunk_command(path: str, block: bytes, offset: int, prefix: str) -> str:
    mode = 'CreateNew' if offset == 0 else 'Open'
    return (
        "$ErrorActionPreference='Stop';$__r46p=" + quote(path) + ";"
        "$__r46b=[Convert]::FromBase64String('" + base64.b64encode(block).decode('ascii') + "');"
        "New-Item -ItemType Directory -Force (Split-Path $__r46p)|Out-Null;"
        "$__r46ancestor=Split-Path $__r46p;while($__r46ancestor){"
        "if((Get-Item -LiteralPath $__r46ancestor -Force).Attributes -band "
        "[IO.FileAttributes]::ReparsePoint){throw 'r46 reparse ancestor refused'};"
        "$__r46next=Split-Path $__r46ancestor;if($__r46next -eq $__r46ancestor){break};"
        "$__r46ancestor=$__r46next};"
        "$__r46f=[IO.File]::Open($__r46p,[IO.FileMode]::" + mode + ","
        "[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);try{"
        "if($__r46f.Length -ne " + str(offset) + "){throw 'r46 stage collision/offset'};"
        "$__r46old=[byte[]]::new($__r46f.Length);"
        "if($__r46f.Read($__r46old,0,$__r46old.Length) -ne $__r46old.Length){throw 'r46 stage short prefix'};"
        "if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($__r46old)).ToLower() -cne '" +
        prefix + "'){throw 'r46 stage prefix SHA'};"
        "$__r46f.Write($__r46b,0,$__r46b.Length);$__r46f.Flush($true)}finally{$__r46f.Dispose()};"
        "@{size=(Get-Item -LiteralPath $__r46p).Length;"
        "sha256=(Get-FileHash -LiteralPath $__r46p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")


def write_new_json(path: Path, value) -> None:
    exact_path(str(path))
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True)
        stream.write('\n')


class StageFileVm:
    def __init__(self, client, context: RunContext, responsibility):
        self.client = client
        self.context = context
        self.responsibility = responsibility
        self.unknown: set[str] = set()

    def powershell(self, command: str, timeout: int = 120) -> dict:
        if type(timeout) is not int or timeout <= 0:
            raise CommandTransportError('integer original total deadline required')
        start = time.monotonic()
        deadline = start + timeout
        key = digest(command.encode('utf-8'))
        base = self.context.evidence_root / 'file-transport'
        unknown_path = exact_path(str(base / ('unknown-' + key + '.json')))
        if key in self.unknown or unknown_path.exists():
            raise CommandTransportError('prior file execution UNKNOWN; never reissue')
        self.context.revalidate()
        if wire_units(command) <= LIMIT:
            try:
                return self.client.powershell(command, timeout)
            except (TransportUnknown, KeyboardInterrupt) as error:
                self._unknown(key, unknown_path, error)
                raise
        self.responsibility.refuse()  # Even a long read requires staging writes.
        if FILE_VARIABLE.search(command):
            raise CommandTransportError('file-specific automatic variable semantics unsupported; no execution')
        data = script_bytes(command)
        if len(data) > MAX_SCRIPT:
            raise CommandTransportError('staged script bound')
        nonce = uuid.uuid4().hex
        directory = exact_path(str(base / nonce))
        directory.mkdir(parents=True, exist_ok=False)
        path = self.context.physical_namespace + '\\transport-stage\\' + nonce + '\\command.ps1'
        sha256 = digest(data)
        script = directory / 'command.ps1'
        with script.open('xb') as stream:
            stream.write(data)
        write_new_json(directory / 'intent.json', {
            'original_command': command, 'command_SHA_utf8': key,
            'original_budget': timeout, 'start_monotonic': start, 'deadline': deadline,
            'guest_path': path, 'script_bytes': len(data), 'script_sha256': sha256,
            'source_UTF16': units(command), 'source_wire_UTF16_reserved': wire_units(command),
            'same_remote_engine_PID_cwd': True, 'no_replay': True,
            'materials_sha256': self.context.materials_sha256,
            'short_call': short_execute(path, sha256)})
        terminal = {'passed': False, 'execution_started': False, 'unknown': False,
                    'stage_chunks': 0, 'original_deadline': deadline}

        def call(text):
            if wire_units(text) > LIMIT:
                raise CommandTransportError('transport command too long even after staging')
            remaining = int(deadline - time.monotonic())
            if remaining <= 0:
                raise CommandTransportError('original total deadline exhausted; no execute')
            previous = getattr(self.client, '_absolute_deadline', float('inf'))
            self.client._absolute_deadline = min(previous, deadline)
            try:
                raw = self.client.powershell(text, remaining)
            finally:
                self.client._absolute_deadline = previous
            if time.monotonic() >= deadline:
                raise TransportUnknown('original total deadline exhausted during parsing', {'response': raw})
            return raw

        try:
            prefix = hashlib.sha256()
            for offset in range(0, len(data), CHUNK):
                block = data[offset:offset + CHUNK]
                text = chunk_command(path, block, offset, prefix.hexdigest())
                prefix.update(block)
                expected = {'size': offset + len(block), 'sha256': prefix.hexdigest()}
                raw = call(text)
                write_new_json(directory / ('chunk-%04d.json' % (offset // CHUNK)), raw)
                if json.loads(raw['output']) != expected:
                    raise CommandTransportError('stage SHA/partial write mismatch; refuse execute')
                terminal['stage_chunks'] += 1
            check = (
                "$ErrorActionPreference='Stop';$p=" + quote(path) + ";"
                "@{size=(Get-Item -LiteralPath $p).Length;"
                "sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
            raw = call(check)
            write_new_json(directory / 'verified-stage-original.json', raw)
            if json.loads(raw['output']) != {'size': len(data), 'sha256': sha256}:
                raise CommandTransportError('staged full SHA mismatch; refuse execute')
            terminal['execution_started'] = True
            raw = call(short_execute(path, sha256))
            write_new_json(directory / 'execution-original.json', raw)
            terminal.update(passed=True, original_exit_code=raw.get('exit_code'), original_output_preserved=True)
            return dict(raw, transport_original_command=command, file_transport={
                'script': str(script), 'guest_path': path, 'sha256': sha256,
                'original_budget': timeout, 'stage_receipt': str(directory / 'terminal.json')})
        except BaseException as error:
            unknown = isinstance(error, (TransportUnknown, KeyboardInterrupt))
            terminal.update(error=repr(error), unknown=unknown, no_reissue=unknown)
            if unknown:
                self._unknown(key, unknown_path, error)
            raise
        finally:
            end = time.monotonic()
            terminal.update(finished_monotonic=end, elapsed=end - start, local_writers_ended=True)
            write_new_json(directory / 'terminal.json', terminal)

    def _unknown(self, key: str, path: Path, error: BaseException) -> None:
        self.unknown.add(key)
        self.responsibility.unknown(error)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_new_json(path, {'command_SHA_utf8': key, 'error': repr(error),
                              'no_reissue': True, 'materials_sha256': self.context.materials_sha256})
