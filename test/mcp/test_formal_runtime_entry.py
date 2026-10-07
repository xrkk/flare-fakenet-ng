"""Original offline config planning and separate preparation failure chain."""
import copy
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from test_formal_runtime_context import materials, write_json, record, git
from test_formal_runtime_prepare import prepared, repin, reseal_history
from formal_runtime.context import load_context, MaterialError
from formal_runtime import preparation, runtime_sources, config_ownership, runner

REAL = Path(__file__).resolve().parents[2]


def original_plan(manifest):
    return config_ownership.selection_plan(SimpleNamespace(args=SimpleNamespace(command='run'),
                                                          manifest=lambda: manifest))


@pytest.fixture
def config_prepared(prepared):
    plan = prepared[4]
    value = original_plan(json.loads(Path(plan['original_manifest']['path']).read_bytes()))
    plan['configuration_plan'] = write_json(prepared[1].parent/'config-plan.json', value)
    return repin(prepared)


def test_offline_configuration_plan_has_actual_401_names_without_clients_or_output(config_prepared, monkeypatch):
    repo, path, pin, data, _ = config_prepared
    def deny(*args, **kwargs): raise AssertionError('no Suite/client for original offline config semantics')
    monkeypatch.setattr(runner.suite.Suite, '__init__', deny)
    monkeypatch.setattr(runner.suite.RawMcp, '__init__', deny)
    value = preparation.configuration_plan(load_context(path, pin, repository_root=repo))
    assert len(value['selected']) == 100 and len(value['must_be_absent']) == 401
    assert value['restoration_builtin'] == 'default.ini' and value['no_contract_renaming'] is True
    assert not Path(data['evidence_root']).exists() and not Path(data['audit_root']).exists()


@pytest.mark.parametrize('change', ['omit-name', 'rename-name', 'wrong-default', 'bool-attempt', 'source-sha'])
def test_self_rehashed_config_plan_cannot_change_original_lifecycle(config_prepared, change):
    plan = config_prepared[4]; path = Path(plan['configuration_plan']['path'])
    value = json.loads(path.read_bytes())
    if change == 'omit-name': value['must_be_absent'].pop()
    elif change == 'rename-name': value['must_be_absent'][0] = 'renamed.ini'
    elif change == 'wrong-default': value['restoration_builtin'] = 'other.ini'
    elif change == 'bool-attempt': value['selected'][0]['attempt'] = True
    else: value['selection_source_SHA'] = '0'*64
    plan['configuration_plan'] = write_json(path, value)
    repo, material, pin, _, _ = repin(config_prepared)
    with pytest.raises(MaterialError, match='differs from original full lifecycle'):
        preparation.configuration_plan(load_context(material, pin, repository_root=repo))


@pytest.fixture
def entry_material(config_prepared):
    repo, material, _, data, plan = config_prepared
    nonce = 'a'*32
    data['physical_namespace'] = (r'E:\FakeNet-NG-MCP-test-work\clean-r5-20261005'+'\\'+nonce+'\\'+
                                 hashlib.sha256(data['evidence_root'].encode()).hexdigest()[:12])
    plan.update(physical_namespace=data['physical_namespace'], nonce=nonce, cycles_bound=70)
    entry = REAL/'test/mcp/acceptance/run_formal_completion.py'
    wanted = runtime_sources.expected_sources(REAL, entry)
    for source in wanted:
        target = repo/source.relative_to(REAL); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    git(repo, 'add', 'test/mcp', 'fakenet', 'fnpr_sentinel.py')
    git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'immutable original runtime fixture')
    commit = git(repo, 'rev-parse', 'HEAD')
    identity = data['candidate_identity']; identity['source'] = commit
    data['tool_source'] = {'commit': commit, 'files': [record(repo/p.relative_to(REAL))
        for p in sorted(wanted) if p.is_relative_to(REAL/'test/mcp')]}
    plan['additional_tool_files'] = [record(repo/'fnpr_sentinel.py')]
    config_path = Path(plan['configuration_plan']['path']); config = json.loads(config_path.read_bytes())
    config['selection_source'] = str(repo/'test/mcp/acceptance/scenario_suite.py')
    plan['configuration_plan'] = write_json(config_path, config)
    manifest_path = Path(plan['candidate_files']['manifest']['path'])
    package = json.loads(manifest_path.read_bytes()); package['source_commit'] = commit
    plan['candidate_files']['manifest'] = write_json(manifest_path, package)
    identity['manifest_sha256'] = record(manifest_path)['sha256']
    archive = Path(plan['candidate_files']['archive']['path'])
    with zipfile.ZipFile(archive) as bundle: bodies = {name: bundle.read(name) for name in bundle.namelist()}
    bodies['mcp-candidate-manifest.json'] = manifest_path.read_bytes()
    with zipfile.ZipFile(archive, 'w') as bundle:
        for name, body in bodies.items(): bundle.writestr(name, body)
    plan['candidate_files']['archive'] = record(archive); identity['zip_sha256'] = record(archive)['sha256']
    for key in ('verification', 'deployment'):
        path = Path(plan['candidate_files'][key]['path']); value = json.loads(path.read_bytes())
        value['zip_sha256'] = identity['zip_sha256']
        if key == 'deployment': value['source'] = commit
        plan['candidate_files'][key] = write_json(path, value)
    for row in data['suite_argv'].values():
        path = Path(row['path']); value = json.loads(path.read_bytes())
        for flag, new in (('--source-commit', commit), ('--package-sha256', identity['zip_sha256'])):
            value['argv'][value['argv'].index(flag)+1] = new
        row.update(write_json(path, value))
    history = Path(data['source_indices'][0]['path']).parent
    for path in (history/'results').glob('*.json'):
        value = json.loads(path.read_bytes()); value['identity'].update(source_commit=commit, package_sha256=identity['zip_sha256'])
        write_json(path, value)
    spike_path = Path(data['spike_source']['path']); spike = json.loads(spike_path.read_bytes())
    spike['identity'].update(source_commit=commit, package_sha256=identity['zip_sha256'])
    spike['cases'] = [{'scenario_id': 'sst-005'}]
    data['spike_source'] = write_json(spike_path, spike)
    reseal_history(config_prepared)
    spike_selection = write_json(material.parent/'spike-selection.json', {'sst-005': str(history)})
    jobs = []
    for scope in ('credited-selection', 'spike-only'):
        child = copy.deepcopy(data); child_plan = copy.deepcopy(plan)
        child['evidence_root'] = str(repo/'Logs'/('unused-audit-business-'+scope))
        child['audit_root'] = str(Path(data['audit_root'])/'preparation-audits'/scope)
        child_plan['root'] = child['evidence_root']
        for kind, row in child['suite_argv'].items():
            value = json.loads(Path(row['path']).read_bytes())
            value['argv'][value['argv'].index('--suite-root')+1] = child['evidence_root']
            child['suite_argv'][kind] = write_json(material.parent/(scope+'-'+kind+'.json'), value)
        child['plan'] = write_json(material.parent/(scope+'-plan.json'), child_plan)
        child_record = write_json(material.parent/(scope+'-materials.json'), child)
        jobs.append({'scope': scope, 'materials': child_record,
                     'selection': data['credited_selection'] if scope == 'credited-selection' else spike_selection})
    plan['preparation_audits'] = jobs
    repo, material, pin, data, plan = repin(config_prepared)
    return repo, material, pin, data, plan


def invoke(entry_material, tmp_path, capacity=False):
    repo, material, pin, _, _ = entry_material
    script = repo/'test/mcp/acceptance/run_formal_completion.py'
    argv = [sys.executable, '-B', str(script), '--materials-json', str(material),
            '--materials-sha256', pin, '--repository-root', str(repo), 'prepare']
    if capacity:
        # Only the parent's disk boundary is controlled. The actual independent
        # child rechecks real free space and retains its own failure.
        launcher = tmp_path/'host-capacity-boundary.py'
        launcher.write_text('import runpy,shutil,sys\nfrom types import SimpleNamespace\n'
            'shutil.disk_usage=lambda _:SimpleNamespace(free=100*2**30)\n'
            'script=sys.argv.pop(1)\nsys.path.insert(0,__import__("os").path.dirname(script))\n'
            'runpy.run_path(script,run_name="__main__")\n')
        argv = [argv[0], '-B', str(launcher), *argv[2:]]
    completed = subprocess.run(argv, cwd=repo, capture_output=True, text=True, timeout=240)
    (tmp_path/'entry-stdout.log').write_text(completed.stdout)
    (tmp_path/'entry-stderr.log').write_text(completed.stderr)
    write_json(tmp_path/'entry-command-exit.json', {'argv': argv, 'returncode': completed.returncode,
                                                 'host_child_waited': True, 'VM_calls': 0})
    return completed


def test_entry_rejects_fresh_capacity_without_audit_or_business_output(entry_material, tmp_path):
    result = invoke(entry_material, tmp_path)
    assert result.returncode == 4 and 'fresh offline host/tmp capacity insufficient' in result.stdout
    assert not Path(entry_material[3]['audit_root']).exists()
    assert not Path(entry_material[3]['evidence_root']).exists()


def test_entry_actual_independent_audit_failure_stops_second_audit_and_retains_originals(entry_material, tmp_path):
    result = invoke(entry_material, tmp_path, capacity=True)
    assert result.returncode == 4 and 'original independent preparation audit failed' in result.stdout, result.stderr+result.stdout
    root = Path(entry_material[3]['audit_root'])
    terminal = json.loads((root/'preparation-terminal.json').read_bytes())
    assert terminal['passed'] is False and terminal['VM_calls'] == terminal['new_formal_credit'] == 0
    assert terminal['host_audit_processes_waited'] is True and len(terminal['audits']) == 1
    row = terminal['audits'][0]
    assert row['scope'] == 'credited-selection' and row['exit_code'] != 0
    assert Path(row['stderr']['path']).read_bytes()
    assert not (root/'prepare-spike-only.intent.json').exists()
    assert not (root/'preparation-result.json').exists()
    assert not Path(entry_material[3]['evidence_root']).exists()


@pytest.mark.parametrize('change,reason', [('order','must be ordered'),('missing','two explicit'),
    ('pin','input fingerprint mismatch'),('selection','credited selection differs')])
def test_audit_jobs_are_independently_frozen_before_output(entry_material, change, reason):
    repo, material, _, data, plan = entry_material
    if change == 'order': plan['preparation_audits'].reverse()
    elif change == 'missing': plan['preparation_audits'].pop()
    elif change == 'pin': plan['preparation_audits'][0]['materials']['sha256'] = '0'*64
    else: plan['preparation_audits'][0]['selection'] = plan['preparation_audits'][1]['selection']
    data['plan'] = write_json(Path(data['plan']['path']), plan)
    context = load_context(material, write_json(material,data)['sha256'], repository_root=repo)
    with pytest.raises(MaterialError, match=reason): preparation.audit_jobs(context)
    assert not context.evidence_root.exists() and not context.audit_root.exists()


def test_entry_help_import_do_not_import_runtime_or_create_outputs(tmp_path):
    script = REAL/'test/mcp/acceptance/run_formal_completion.py'
    result = subprocess.run([sys.executable,'-B',str(script),'--help'], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and 'prepare' in result.stdout
    code = 'import runpy,sys;runpy.run_path(sys.argv[1],run_name="import_only");assert "formal_runtime.preparation" not in sys.modules;assert "formal_runtime.audit" not in sys.modules'
    result = subprocess.run([sys.executable,'-B','-c',code,str(script)], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('change,reason', [('candidate','candidate/tool'), ('resource','source/resource'),
    ('protected','omits protected'), ('manifest','original material differs'),
    ('argv','argv differs beyond'), ('output','distinct unused')])
def test_audit_child_cannot_change_parent_contract_or_reuse_output(entry_material, change, reason):
    repo, material, _, data, plan = entry_material
    job = plan['preparation_audits'][0]
    path = Path(job['materials']['path']); child = json.loads(path.read_bytes())
    child_plan_path = Path(child['plan']['path']); child_plan = json.loads(child_plan_path.read_bytes())
    if change == 'candidate':
        child['candidate_identity']['default_sha256'] = '0'*64
        child_plan['identity'] = child['candidate_identity']
    elif change == 'resource': child['resource_plan']['per_scenario_audit_copy_bytes'] += 1
    elif change == 'protected': child['protected_sources'] = []
    elif change == 'manifest': child_plan['original_manifest'] = child_plan['candidate_files']['manifest']
    elif change == 'argv':
        for row in child['suite_argv'].values():
            argv_path = Path(row['path']); invocation = json.loads(argv_path.read_bytes())
            invocation['argv'] += ['--seed', '1']; row.update(write_json(argv_path, invocation))
    else: Path(child['audit_root']).mkdir(parents=True)
    child['plan'] = write_json(child_plan_path, child_plan)
    job['materials'] = write_json(path, child)
    data['plan'] = write_json(Path(data['plan']['path']), plan)
    context = load_context(material, write_json(material,data)['sha256'], repository_root=repo)
    with pytest.raises(MaterialError, match=reason): preparation.audit_jobs(context)


@pytest.mark.parametrize('change,reason', [('namespace','nonce/scope'), ('scope','nonce/scope'),
                                         ('nonce','nonce/scope'), ('cycles','cycle bound')])
def test_preparation_cannot_grant_wrong_producer_namespace_or_cycle_bound(entry_material, change, reason):
    repo, material, _, data, plan = entry_material
    if change == 'namespace': data['physical_namespace'] = r'E:\other-namespace'
    elif change == 'scope': data['physical_namespace'] = data['physical_namespace'][:-12]+'0'*12
    elif change == 'nonce': plan['nonce'] = 'b'*32
    else: plan['cycles_bound'] = True
    plan['physical_namespace'] = data['physical_namespace']
    data['plan'] = write_json(Path(data['plan']['path']), plan)
    context = load_context(material, write_json(material,data)['sha256'], repository_root=repo)
    with pytest.raises(MaterialError, match=reason): preparation.execution_plan(context)
    assert not context.evidence_root.exists() and not context.audit_root.exists()
