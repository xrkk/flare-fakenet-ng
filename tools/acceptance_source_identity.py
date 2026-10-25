"""Explicit product-source reuse proof; never treats Git HEAD as deployment."""
from __future__ import annotations
import hashlib
import json
import subprocess
from pathlib import Path
import re

SCHEMA = 'fakenet.source-reuse.v1'
PRODUCT_PREFIXES = ('fakenet/', 'deploy/', 'wheelhouse/', 'tools/docker/', '.github/workflows/')
PRODUCT_ROOT_FILES = ('setup.py', 'pyproject.toml', 'requirements.txt',
                      'requirements.lock', 'Pipfile', 'Pipfile.lock', 'setup.cfg', 'MANIFEST.in')
PRODUCT_BUILD_PREFIXES = ('Build-', 'build-')
PRODUCT_TOOL_BUILD_PREFIX = 'tools/build'


# Explicit facility registry; product modules are never excluded by native pins.
HARNESS_FILES = ('tools/acceptance_contained.py', 'test/test_acceptance_contained.py', 'test/mcp/acceptance/artifact_transfer.py', 'test/mcp/acceptance/bounded_mcp.py', 'test/mcp/acceptance/controlled_exit_case.py', 'test/mcp/acceptance/controlled_exit_failure.py', 'test/mcp/acceptance/etl_raw_clock.py', 'test/mcp/acceptance/evidence_integrity.py', 'test/mcp/acceptance/formal_batch_v3.py', 'test/mcp/acceptance/formal_instance_gate.py', 'test/mcp/acceptance/formal_runtime/__init__.py', 'test/mcp/acceptance/formal_runtime/audit.py', 'test/mcp/acceptance/formal_runtime/audit_entry.py', 'test/mcp/acceptance/formal_runtime/audit_view.py', 'test/mcp/acceptance/formal_runtime/batch_rejudge.py', 'test/mcp/acceptance/formal_runtime/batch_selection.py', 'test/mcp/acceptance/formal_runtime/clients.py', 'test/mcp/acceptance/formal_runtime/command_transport.py', 'test/mcp/acceptance/formal_runtime/config_ownership.py', 'test/mcp/acceptance/formal_runtime/context.py', 'test/mcp/acceptance/formal_runtime/coordinator.py', 'test/mcp/acceptance/formal_runtime/current_source.py', 'test/mcp/acceptance/formal_runtime/dns_capture.py', 'test/mcp/acceptance/formal_runtime/dns_evidence.py', 'test/mcp/acceptance/formal_runtime/execution.py', 'test/mcp/acceptance/formal_runtime/export_entry.py', 'test/mcp/acceptance/formal_runtime/historical_capture.py', 'test/mcp/acceptance/formal_runtime/instance.py', 'test/mcp/acceptance/formal_runtime/preparation.py', 'test/mcp/acceptance/formal_runtime/preparation_receipt.py', 'test/mcp/acceptance/formal_runtime/producer.py', 'test/mcp/acceptance/formal_runtime/producer_source.py', 'test/mcp/acceptance/formal_runtime/recovery.py', 'test/mcp/acceptance/formal_runtime/row_audit.py', 'test/mcp/acceptance/formal_runtime/row_selection.py', 'test/mcp/acceptance/formal_runtime/runner.py', 'test/mcp/acceptance/formal_runtime/runtime_sources.py', 'test/mcp/acceptance/formal_runtime/sealing.py', 'test/mcp/acceptance/formal_runtime/source.py', 'test/mcp/acceptance/formal_runtime/source_graph.py', 'test/mcp/acceptance/formal_runtime/spike_gate.py', 'test/mcp/acceptance/gui_contract_export.py', 'test/mcp/acceptance/health_composition.py', 'test/mcp/acceptance/helpers.py', 'test/mcp/acceptance/ipc_evidence.py', 'test/mcp/acceptance/p14_operator_fixture.py', 'test/mcp/acceptance/p14_operator_preflight.py', 'test/mcp/acceptance/p14_single.py', 'test/mcp/acceptance/p7_capture_wrapper.py', 'test/mcp/acceptance/process_recovery.py', 'test/mcp/acceptance/release_matrix.py', 'test/mcp/acceptance/replay_observation.py', 'test/mcp/acceptance/run_active_probe.py', 'test/mcp/acceptance/run_control_cases.py', 'test/mcp/acceptance/run_creation_cases.py', 'test/mcp/acceptance/run_egress_verification.py', 'test/mcp/acceptance/run_formal_completion.py', 'test/mcp/acceptance/run_formal_source_audit.py', 'test/mcp/acceptance/run_initialization_case.py', 'test/mcp/acceptance/run_ipc_cases.py', 'test/mcp/acceptance/run_p01_acc.py', 'test/mcp/acceptance/run_p02_acc.py', 'test/mcp/acceptance/run_p03_acc.py', 'test/mcp/acceptance/run_p04_acc.py', 'test/mcp/acceptance/run_p05_release.py', 'test/mcp/acceptance/run_readiness_probe.py', 'test/mcp/acceptance/run_snapshot_cases.py', 'test/mcp/acceptance/scenario_application.py', 'test/mcp/acceptance/scenario_aux_qpc_contract.py', 'test/mcp/acceptance/scenario_aux_qpc_diagnostic.py', 'test/mcp/acceptance/scenario_aux_qpc_offline.py', 'test/mcp/acceptance/scenario_aux_qpc_single_pass.py', 'test/mcp/acceptance/scenario_aux_qpc_v2.py', 'test/mcp/acceptance/scenario_capture_view.py', 'test/mcp/acceptance/scenario_clock.py', 'test/mcp/acceptance/scenario_fault_evidence.py', 'test/mcp/acceptance/scenario_kernel_network.py', 'test/mcp/acceptance/scenario_pktmon.py', 'test/mcp/acceptance/scenario_qpc_contract.py', 'test/mcp/acceptance/scenario_qpc_diagnostic.py', 'test/mcp/acceptance/scenario_qpc_identity.py', 'test/mcp/acceptance/scenario_qpc_offline.py', 'test/mcp/acceptance/scenario_result_ledger.py', 'test/mcp/acceptance/scenario_suite.py', 'test/mcp/acceptance/scenario_tcpip.py', 'test/mcp/acceptance/snapshot_evidence.py', 'test/mcp/acceptance/sst_fault_evidence.py', 'test/mcp/acceptance/sst_pc008_assert.py', 'test/mcp/acceptance/tdh_metadata.py', 'test/test_acceptance_catalog.py', 'test/test_acceptance_combo.py', 'test/test_acceptance_headless.py', 'test/test_acceptance_linux_composite.py', 'test/test_acceptance_linux_deploy_update.py', 'test/test_acceptance_linux_runtime.py', 'test/test_acceptance_linux_runtime_contract.py', 'test/test_acceptance_manual.py', 'test/test_acceptance_manual_ctrlc_ipc.py', 'test/test_acceptance_manual_diverter_switch.py', 'test/test_acceptance_manual_dumppackets.py', 'test/test_acceptance_manual_executecmd.py', 'test/test_acceptance_manual_integration.py', 'test/test_acceptance_manual_linux_flush_interface.py', 'test/test_acceptance_manual_list_mutex.py', 'test/test_acceptance_manual_network_fix.py', 'test/test_acceptance_manual_standalone.py', 'test/test_acceptance_manual_syslog_icmp.py', 'test/test_acceptance_mcp.py', 'test/test_acceptance_mcp_baseline.py', 'test/test_acceptance_mcp_compatibility.py', 'test/test_acceptance_mcp_http_contract.py', 'test/test_acceptance_mcp_identity.py', 'test/test_acceptance_mcp_snapshot_receipts.py', 'test/test_acceptance_mcp_transport.py', 'test/test_acceptance_native.py', 'test/test_acceptance_native_channels.py', 'test/test_acceptance_native_oracles.py', 'test/test_acceptance_orchestration.py', 'test/test_acceptance_package.py', 'test/test_acceptance_policy.py', 'test/test_acceptance_regression.py', 'test/test_acceptance_scheduler.py', 'test/test_acceptance_source_reuse.py', 'tools/acceptance.py', 'tools/acceptance_collection.py', 'tools/acceptance_guest.py', 'tools/acceptance_headless.py', 'tools/acceptance_headless_oracles.py', 'tools/acceptance_linux.py', 'tools/acceptance_linux_composite.py', 'tools/acceptance_linux_runtime.py', 'tools/acceptance_linux_runtime_oracles.py', 'tools/acceptance_manual.py', 'tools/acceptance_manual_oracles.py', 'tools/acceptance_mcp.py', 'tools/acceptance_mcp_capabilities.py', 'tools/acceptance_mcp_dependencies.py', 'tools/acceptance_mcp_oracles.py', 'tools/acceptance_multihost.py', 'tools/acceptance_native.py', 'tools/acceptance_oracles.py', 'tools/acceptance_orchestration.py', 'tools/acceptance_package.py', 'tools/acceptance_policy.py', 'tools/acceptance_policy_oracles.py', 'tools/acceptance_runtime.py', 'tools/acceptance_scheduler.py', 'tools/acceptance_source_identity.py', 'tools/acceptance_windows.py')

def current_harness_paths(root):
    root = Path(root)
    return {name for name in HARNESS_FILES if (root/name).is_file()}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def candidate_enabled(candidate):
    """Only an explicit, minimal opt-in is accepted."""
    if not isinstance(candidate, dict) or 'source_reuse' not in candidate:
        return False
    value = candidate['source_reuse']
    if not isinstance(value, dict) or set(value) != {'schema'} or value['schema'] != SCHEMA:
        raise ValueError('source_reuse requires the exact fakenet.source-reuse.v1 schema')
    return True


def _git(root, *argv, input_data=None):
    result = subprocess.run(['git', '-C', str(Path(root)), *argv],
                            input=input_data, capture_output=True, timeout=60, check=False)
    if result.returncode != 0:
        raise ValueError('read-only Git source proof failed: %s' % (result.stderr.decode('utf-8', 'replace')[:300]))
    return result.stdout


def _tree(root, commit):
    raw = _git(root, 'ls-tree', '-r', '-z', commit)
    entries = {}
    for item in raw.split(b'\0'):
        if not item: continue
        metadata, name = item.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split()
        name = name.decode('utf-8')
        if name in entries or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('ambiguous Git closure path')
        entries[name] = (mode, kind, oid)
    return entries


def _file_identity(path, algorithm):
    length = path.stat().st_size
    git = hashlib.new(algorithm); git.update(('blob %d\0' % length).encode())
    content = hashlib.sha256(); count = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            count += len(block); git.update(block); content.update(block)
    if count != length or path.stat().st_size != length:
        raise ValueError('closure file changed during hashing')
    return git.hexdigest(), content.hexdigest()


def _is_product(relative):
    if relative.startswith(PRODUCT_PREFIXES):
        return True
    if (relative in PRODUCT_ROOT_FILES or relative.startswith(PRODUCT_BUILD_PREFIXES)
            or ('/' not in relative and (relative.endswith('.spec') or relative.startswith('requirements')
                                        or relative.startswith('Test-')))):
        return True
    if relative.startswith(PRODUCT_TOOL_BUILD_PREFIX):
        return True
    if relative.startswith('test/'):
        return True
    return False


def _current_paths(root, harness_paths=()):
    root = Path(root)
    harness_paths = set(harness_paths)
    paths = set()
    roots = [root / name.rstrip('/') for name in PRODUCT_PREFIXES]
    roots.append(root / 'test')
    roots.append(root / 'tools' / 'build')
    for base in roots:
        if not base.is_dir():
            continue
        for path in base.rglob('*'):
            if not path.is_file() and not path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if any(part in ('__pycache__', '.pytest_cache') for part in Path(relative).parts) or relative.endswith('.pyc'):
                continue
            if relative in harness_paths:
                continue
            if _is_product(relative):
                paths.add(relative)
    for path in root.iterdir():
        if (path.is_file() or path.is_symlink()) and _is_product(path.name):
            paths.add(path.name)
    for path in (root / 'tools').glob('build*'):
        if path.is_file() or path.is_symlink():
            paths.add(path.relative_to(root).as_posix())
    return paths


def _paths(root, candidate_source, case_sources, harness_paths=()):
    if not isinstance(candidate_source, str) or not re.fullmatch(r'[0-9a-f]{40}', candidate_source):
        raise ValueError('candidate source must be an immutable 40-hex commit')
    tree = _tree(root, candidate_source)
    expected_harness = current_harness_paths(root)
    if harness_paths and set(harness_paths) != expected_harness:
        raise ValueError('caller cannot alter the fixed harness registry')
    harness_paths = expected_harness
    def runtime(name):
        if not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts:
            raise ValueError('case source path is not relative')
        # Exact current harness files are independently pinned. Docs are not
        # product/runtime inputs. Other registered case inputs extend the
        # product closure, including a renamed product test or tool.
        return name not in harness_paths and not (name.startswith('docs/') and name.endswith('.md'))
    extra = {name for name in case_sources if runtime(name)}
    for name in extra:
        if name not in tree:
            raise ValueError('case source is absent from candidate: ' + name)
        if not (Path(root) / name).is_file():
            raise ValueError('case source is absent from worktree: ' + name)
    candidate = ({p for p in tree if _is_product(p)} - harness_paths) | extra
    current = (_current_paths(root, harness_paths) - harness_paths) | extra
    if candidate != current:
        raise ValueError('product closure differs between candidate and worktree: missing=%r added=%r' %
                         (sorted(candidate-current), sorted(current-candidate)))
    for name in candidate:
        if name not in tree or tree[name][0] not in ('100644', '100755') or tree[name][1] != 'blob':
            raise ValueError('product closure path missing or not a regular blob: ' + name)
    return sorted(candidate), tree


def closure_paths(root, candidate_source, case_sources=(), harness_paths=()):
    return _paths(root, candidate_source, case_sources, harness_paths)[0]


def prove(root, candidate_source, case_sources=(), harness_commit=None, harness_paths=()):
    root = Path(root).resolve()
    if not isinstance(harness_commit, str) or not re.fullmatch(r'[0-9a-f]{40}', harness_commit):
        raise ValueError('current harness commit required')
    paths, tree = _paths(root, candidate_source, case_sources, harness_paths)
    current_tree = _tree(root, harness_commit)
    proof = []
    for name in paths:
        current = root / name
        if (current.is_symlink() or any(p.is_symlink() for p in current.parents) or
                not current.is_file() or not current.resolve().is_relative_to(root)):
            raise ValueError('product closure path missing or linked: ' + name)
        if name not in current_tree:
            raise ValueError('product closure path missing from current Git: ' + name)
        mode, unused_kind, oid = tree[name]
        current_mode, current_kind, current_oid = current_tree[name]
        if current_kind != 'blob' or current_mode not in ('100644', '100755'):
            raise ValueError('current product closure object is not a regular blob: ' + name)
        # Mode and content identity are source-level Git facts. The host
        # checkout's umask/mount mode is not product source; it is deliberately
        # not used to erase or invent an execution-bit change.
        if current_oid != oid or current_mode != mode:
            raise ValueError('product closure source differs from candidate: ' + name)
        got, digest = _file_identity(current, 'sha1' if len(oid) == 40 else 'sha256')
        if got != oid:
            raise ValueError('product closure worktree differs from candidate: ' + name)
        proof.append({'path': name, 'sha256': digest, 'mode': mode})
    return {'schema': SCHEMA, 'candidate_source': candidate_source,
            'harness_commit': harness_commit, 'closure': proof,
            'closure_sha256': hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def validate_plan(root, plan, registered, required):
    """Recheck the stored proof against current worktree and harness."""
    if not candidate_enabled(plan.get('candidate')):
        return False
    proof = plan.get('source_reuse')
    if not isinstance(proof, dict) or proof.get('schema') != SCHEMA:
        return False
    if proof.get('candidate_source') != plan.get('source_commit'):
        return False
    if proof.get('harness_commit') != plan.get('harness_commit'):
        return False
    try:
        current = _git(root, 'rev-parse', 'HEAD').decode().strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    if current != plan.get('harness_commit'):
        return False
    case_sources = []
    for case_id in required:
        case_sources.extend(registered[case_id].get('sources') or [])
    try:
        actual = prove(root, plan['source_commit'], case_sources, current,
                       current_harness_paths(root))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return False
    return actual == proof
