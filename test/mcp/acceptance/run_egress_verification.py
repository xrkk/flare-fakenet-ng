#!/usr/bin/env python3
"""Run one host stdio egress verification against a dedicated VM config.

The command_id is unique per run/case and saved before the call.  The
expectation functions inspect the complete result, not just verdict/status;
a known error cannot be accepted as a different negative case.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import uuid

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters

from fakenet.mcp import egress_contract


CASES = ('normal', 'host_unknown', 'control_missing', 'nonce_mismatch',
         'identity_change', 'timeout')


def _structured(result):
    value = getattr(result, 'structured_content', None)
    if isinstance(value, dict):
        return value
    texts = [item.text for item in (getattr(result, 'content', None) or [])
             if getattr(item, 'text', None)]
    if len(texts) != 1:
        raise ValueError('expected one tool result text')
    return json.loads(texts[0])


def _checks(result):
    return result.get('checks') or {}


def _check_value(result, name):
    return (_checks(result).get(name) or {}).get('value')


def _failed(result):
    return (result.get('conclusion') or {}).get('failed_checks') or []


def _complete(result):
    conclusion = result.get('conclusion') or {}
    completeness = conclusion.get('matrix_completeness') or {}
    coverage = result.get('coverage') or {}
    if not completeness.get('complete'):
        return False
    if (coverage.get('matrix_planned') or 0) != 30:
        return False
    if coverage.get('matrix_not_run'):
        return False
    for step in result.get('steps') or []:
        if step.get('outcome') != 'pass':
            return False
    return True


def _helper_consistent(result):
    helper_input = result.get('helper_input') or {}
    if not isinstance(helper_input, dict):
        return False
    plan = helper_input.get('plan')
    observation = helper_input.get('observation')
    if not isinstance(plan, dict) or not isinstance(observation, dict):
        return False
    try:
        helper = egress_contract.evaluate_interception_qualification(
            plan, observation)
    except Exception:
        return False
    conclusion = result.get('conclusion') or {}
    return (helper.get('status') == conclusion.get('status') and
            helper.get('sample_path_qualified') == conclusion.get(
                'sample_path_qualified') and
            helper.get('verdict', egress_contract.verdict_from_status(
                helper.get('status'))) == result.get('verdict'))


def expectation(case, result):
    verdict = result.get('verdict')
    status = (result.get('conclusion') or {}).get('status')
    lifecycle = (result.get('lifecycle') or {}).get('state')
    completion = result.get('probe_completion') or {}
    if case == 'normal':
        return (result.get('contract_version') == 2 and result.get('phase') == 'running' and
                verdict == 'pass' and status == 'qualified_in_scope' and
                lifecycle == 'completed' and _complete(result) and
                bool(completion.get('completed_at')) and
                _helper_consistent(result) and
                result.get('authorized') is False and
                (result.get('conclusion') or {}).get(
                    'sample_path_qualified') is True and
                bool((result.get('artifact') or {}).get('sha256')))
    if case == 'host_unknown':
        return bool(verdict == 'unknown' and status == 'underdetermined' and
                    lifecycle == 'completed' and not result.get('error') and
                    result.get('authorized') is False and
                    (result.get('coverage') or {}).get('matrix_executed') == 30 and
                    _check_value(result, 'running_egress_contained') is None)
    if case == 'control_missing':
        return (verdict == 'fail' and status != 'qualified_in_scope' and
                ((_check_value(result, 'mcp_control_exclusions_effective')
                  is False or
                  _check_value(result, 'control_channels_reachable') is False)
                 or 'mcp_control_exclusions_effective' in _failed(result)
                 or 'control_channels_reachable' in _failed(result)))
    if case == 'nonce_mismatch':
        return (verdict in ('fail', 'unknown') and
                status != 'qualified_in_scope' and
                (_check_value(result, 'local_interception_observed')
                 is False or 'response_nonce_mismatch' in _failed(result)))
    if case == 'identity_change':
        return (verdict in ('fail', 'unknown') and
                status != 'qualified_in_scope' and
                ((result.get('conclusion') or {}).get(
                    'reason') in ('state_conflict', 'sample_context_mismatch',
                                  'execution_context_changed') or
                 'sample_path_equivalent' in _failed(result) or
                 _check_value(result, 'sample_path_equivalent') is None))
    if case == 'timeout':
        return (verdict == 'unknown' and
                lifecycle in ('timed_out', 'ownership_unknown', 'failed') and
                (result.get('error') or {}).get('code') in (
                    'deadline_exceeded', 'windows_timeout',
                    'windows_transport_error', 'guest_transport_error',
                    'ownership_unknown'))
    raise ValueError('unknown case')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--case', choices=CASES, default='normal')
    parser.add_argument('--command-id')
    parser.add_argument('--expected-manifest-sha256')
    args = parser.parse_args(argv)
    output = Path(args.output).resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print(json.dumps({'status': 'ERROR', 'error': repr(exc)}))
        return 2
    command_id = args.command_id or str(uuid.uuid4())
    try:
        command_id = str(uuid.UUID(command_id))
    except ValueError:
        print(json.dumps({'status': 'ERROR', 'error': 'command_id invalid'}))
        return 2
    (output / 'command-id.txt').write_text(command_id + '\n', encoding='utf-8')
    command = [sys.executable, '-m', 'fakenet.mcp.host_stdio',
               '--config', str(Path(args.config).resolve())]

    async def run():
        params = StdioServerParameters(command=command[0], args=command[1:],
                                       cwd=str(Path(__file__).resolve(
                                       ).parents[3]))
        async with Client(params, read_timeout_seconds=75) as client:
            tools = await client.list_tools()
            names = [tool.name for tool in tools.tools]
            if names != ['verify_egress_isolation']:
                raise RuntimeError('host tool surface is not singular: %r' %
                                   names)
            result = await client.call_tool(
                'verify_egress_isolation', {'command_id': command_id})
            return _structured(result)

    try:
        result = anyio.run(run)
    except Exception as exc:  # noqa: BLE001 - preserve the runner evidence
        (output / 'runner-error.json').write_text(
            json.dumps({'status': 'ERROR', 'error': repr(exc)},
                       ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')
        print(json.dumps({'status': 'ERROR', 'error': repr(exc)}))
        return 2
    (output / 'result.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    if args.expected_manifest_sha256:
        manifest_sha = (result.get('manifest') or {}).get('sha256')
        if manifest_sha != args.expected_manifest_sha256:
            print(json.dumps({'status': 'FAIL', 'case': args.case,
                              'error': 'manifest mismatch',
                              'expected': args.expected_manifest_sha256,
                              'actual': manifest_sha}))
            return 1
    passed = expectation(args.case, result)
    summary = {'status': 'PASS' if passed else 'FAIL', 'case': args.case,
               'command_id': command_id,
               'verdict': result.get('verdict'),
               'lifecycle': (result.get('lifecycle') or {}).get('state'),
               'conclusion': (result.get('conclusion') or {}).get('status'),
               'matrix_complete': ((result.get('conclusion') or {}).get(
                   'matrix_completeness') or {}).get('complete'),
               'failed_checks': _failed(result)}
    (output / 'runner-summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    print(json.dumps(summary))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
