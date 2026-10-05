"""Versioned original captures use indexed data and immutable Git tool blobs."""
import hashlib
import json
import re
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, record, write_json, git
from test_formal_runtime_producer import current
from test_formal_runtime_instance import subject, CaptureClient, PROFILE
from formal_runtime.context import load_context, MaterialError
from formal_runtime import instance, producer, producer_source, source
from bounded_mcp import TransportUnknown


def pin_source(current):
    repo = current.repository_root
    data = json.loads(current.materials_path.read_bytes())
    originals = Path(__file__).parent/'acceptance'
    for relative in producer_source.PRODUCER_FILES:
        path = repo/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(originals/Path(relative).relative_to('test/mcp/acceptance'),path)
    git(repo,'add','test/mcp')
    git(repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
        '-c','commit.gpgsign=false','commit','-qm','original producer source bytes')
    data['tool_source']={'commit':git(repo,'rev-parse','HEAD'),
                         'files':[record(repo/p) for p in sorted(producer_source.PRODUCER_FILES)]}
    pin = write_json(current.materials_path,data)['sha256']
    return load_context(current.materials_path,pin,repository_root=repo)


class ExactCaptureClient(CaptureClient):
    def powershell(self, command, timeout):
        raw=super().powershell(command,timeout)
        if 'logman start $s -ets' in command:
            run=re.search(r"\$r='([^']+)'",command)[1]
            raw={'output':json.dumps({'session_name':re.search(r"\$s='([^']+)'",command)[1],
                'guest':run,'metadata':run+r'\kernel-network.metadata.json'}),'exit_code':0}
        return raw


@pytest.fixture
def versioned(current):
    original_context=pin_source(current)
    repo=original_context.repository_root
    root = original_context.evidence_root
    producer.register_execution(original_context)
    r = subject(original_context)
    r.vm = instance.ProtectedVm(ExactCaptureClient(original_context,success=True),original_context,instance.Responsibility())
    instance.bind_namespace(r,original_context)
    guest = r._guest_scenario_root('sst-001',1)
    r.vm.client.client.run = guest+r'\run-01'
    capture = r._start_capture_and_probe(guest,PROFILE,'bound-nonce','run-01')
    write_json(root/'execution-context.json',{'backup_names':['owned-environment.xml']})
    write_json(root/'cycle-1-intent.json',{'receipt':original_context.physical_namespace+r'\scenario-suite-20260912\cycle\receipt.json'})

    inputs = repo/'Logs/consumer-inputs'
    inputs.mkdir()
    consumer_data = json.loads(original_context.materials_path.read_bytes())
    consumer_data.update(evidence_root=str(repo/'Logs/new-reader-output'),audit_root=str(repo/'Logs/new-reader-audit'))
    namespace = (r'E:\FakeNet-NG-MCP-test-work\clean-r61-20261005'+'\\'+'4'*32+'\\'+
        hashlib.sha256(consumer_data['evidence_root'].encode()).hexdigest()[:12])
    consumer_data['physical_namespace'] = namespace
    plan = json.loads(Path(consumer_data['plan']['path']).read_bytes())
    plan.update(root=consumer_data['evidence_root'],physical_namespace=namespace)
    consumer_data['plan'] = write_json(inputs/'plan.json',plan)
    for kind,row in consumer_data['suite_argv'].items():
        argv = json.loads(Path(row['path']).read_bytes())
        argv['argv'][argv['argv'].index('--suite-root')+1]=consumer_data['evidence_root']
        consumer_data['suite_argv'][kind] = write_json(inputs/(kind+'.json'),argv)
    consumer_data['protected_sources'].extend([str(root),str(inputs)])
    material = inputs/'materials.json'

    def freeze_index():
        rows=[]
        for p in sorted(root.rglob('*')):
            if p.is_file() and p.name != 'full-SHA-index.json':
                rows.append(dict(record(p),path=p.relative_to(root).as_posix()))
        consumer_data['source_indices']=[write_json(root/'full-SHA-index.json',{'rows':rows})]
        pin=write_json(material,consumer_data)['sha256']
        return load_context(material,pin,repository_root=repo)
    return freeze_index(),root,original_context,capture,consumer_data,freeze_index,r


def test_original_versioned_binding_reads_actual_short_responses_not_new_consumer_scope(versioned):
    context,root,original,capture,_,_,_ = versioned
    binding=source.resolve_source(context,root)
    assert binding.physical_namespace == original.physical_namespace != context.physical_namespace
    assert binding.values['source_nonce'] == '3'*32
    assert len(binding.values['captures']) == len(binding.values['kernels']) == 1
    assert binding.values['captures'][0]['pid'] == capture['pid']
    assert binding.values['captures'][0]['response'].startswith(str(root/'VM-final-responses'))
    assert not (root/'file-transport').exists()  # The original captured command was short.
    assert binding.values['unresolved_capture_intents'] == ()
    assert original.physical_namespace+r'\scenario-suite-20260912\owned-environment.xml' in binding.values['required_files']


def test_old_tool_identity_is_git_data_after_worktree_and_consumer_commit_change(versioned):
    context,root,original,_,data,freeze,_ = versioned
    helper=context.source_root/'test/mcp/acceptance/formal_runtime/producer.py'
    helper.write_text(helper.read_text()+'\n# later consumer source change\n')
    git(context.source_root,'add','test/mcp')
    git(context.source_root,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
        '-c','commit.gpgsign=false','commit','-qm','later consumer source')
    data['tool_source']={'commit':git(context.source_root,'rev-parse','HEAD'),
                        'files':[record(context.source_root/p) for p in sorted(producer_source.PRODUCER_FILES)]}
    context=freeze()
    assert context.tool_source['commit'] != original.tool_source['commit']
    assert source.resolve_source(context,root).physical_namespace == original.physical_namespace


@pytest.mark.parametrize('change,reason',[
    ('schema','unknown versioned'),('root','root/candidate'),('namespace','material binding'),
    ('terminal','terminal missing'),('response','response fingerprint'),('orphan','orphan'),
    ('intent-hash','actual intent'),('tool','immutable Git'),('missing-tool','closure incomplete'),
    ('backup','backup name escape')])
def test_indexed_contradiction_still_fails_original_producer_binding(versioned,change,reason):
    context,root,original,_,_,freeze,_=versioned
    path=root/'execution-binding.json'
    binding=json.loads(path.read_bytes())
    if change=='schema': binding['schema']='unknown.v2';write_json(path,binding)
    elif change=='root': binding['original_execution_root']=str(root.parent/'wrong');write_json(path,binding)
    elif change=='namespace': binding['physical_namespace']=context.physical_namespace;write_json(path,binding)
    elif change in ('terminal','response'):
        p=next((root/'VM-final-terminals').glob('*.json'));value=json.loads(p.read_bytes())
        if change=='terminal': value['call_id']='0'*32
        else: value['response']['sha256']='0'*64
        write_json(p,value)
    elif change=='orphan':write_json(root/'VM-final-responses'/('0'*32+'.json'),{'output':'{}'})
    elif change=='intent-hash':
        p=next((root/'VM-final-intents').glob('*.json'));value=json.loads(p.read_bytes())
        value['command_sha256']='0'*64;write_json(p,value)
    elif change in ('tool','missing-tool'):
        p=Path(binding['materials']['path']);value=json.loads(p.read_bytes())
        if change=='tool':value['tool_source']['files'][0]['sha256']='0'*64
        else:value['tool_source']['files'].pop()
        binding['materials']=write_json(p,value);write_json(path,binding)
    else:write_json(root/'execution-context.json',{'backup_names':['../foreign']})
    context=freeze()
    with pytest.raises(source.SourceError,match=reason):source.resolve_source(context,root)


def test_changed_source_response_without_new_independent_pin_is_refused(versioned):
    context,root,*_=versioned
    p=next((root/'VM-final-responses').glob('*.json'));p.write_text('changed source')
    with pytest.raises(MaterialError,match='fingerprint mismatch'):source.resolve_source(context,root)


def test_actual_shared_second_probe_borrows_only_first_original_owner(versioned,monkeypatch):
    context,root,original,owner,_,freeze,r=versioned
    owner.update(nonce='bound-nonce',physical_owner_id='bound-nonce:pktmon')
    client=r.vm.client.client
    client.run=owner['guest'].rsplit('\\',1)[0]+r'\run-02'
    original_call=client.powershell
    def environment(command,timeout):
        raw=original_call(command,timeout)
        if 'shared_physical=$true' in command:
            value=json.loads(raw['output'])
            value.update(run_label='run-02',pid=8,probe_creation_ticks=12,
                shared_physical=True,physical_owner_id=owner['physical_owner_id'],
                etl=owner['etl'],pktmon_nic=owner['pktmon_nic'],nonce='bound-nonce',
                capture_run_id='bound-nonce:run-02')
            raw={'output':json.dumps(value),'exit_code':0}
        return raw
    monkeypatch.setattr(client,'powershell',environment)
    second=r._start_probe_on_shared_capture(owner['guest'].rsplit('\\',1)[0],PROFILE,
                                           'bound-nonce','run-02',owner)
    assert second['shared_physical']
    context=freeze();binding=source.resolve_source(context,root)
    assert len(binding.values['captures'])==2 and len(binding.values['kernels'])==2
    assert binding.owner_roots=={source.parts(owner['guest'].rsplit('\\',1)[0])}
    response_path=next(p for p in (root/'VM-final-responses').glob('*.json')
        if '"shared_physical": true' in json.loads(p.read_bytes()).get('output',''))
    response=json.loads(response_path.read_bytes());body=json.loads(response['output'])
    body['physical_owner_id']='wrong:pktmon';response['output']=json.dumps(body)
    write_json(response_path,response)
    terminal_path=root/'VM-final-terminals'/response_path.name
    terminal=json.loads(terminal_path.read_bytes());terminal['response']=record(response_path)
    write_json(terminal_path,terminal);context=freeze()
    with pytest.raises(source.SourceError,match='owner mismatch'):source.resolve_source(context,root)


def test_indexed_actual_etw_body_cannot_disagree_with_original_command(versioned):
    _,root,_,_,_,freeze,_=versioned
    path=next(p for p in (root/'VM-final-responses').glob('*.json')
        if 'session_name' in json.loads(p.read_bytes()).get('output',''))
    response=json.loads(path.read_bytes());body=json.loads(response['output'])
    body['session_name']='SST-Kernel-foreign';response['output']=json.dumps(body)
    write_json(path,response)
    terminal_path=root/'VM-final-terminals'/path.name
    terminal=json.loads(terminal_path.read_bytes());terminal['response']=record(path)
    write_json(terminal_path,terminal);context=freeze()
    with pytest.raises(source.SourceError,match='ETW actual response differs'):source.resolve_source(context,root)


def test_unknown_etw_remains_in_exact_closure_query_and_unknown_capture_withholds_export(versioned):
    context,root,original,_,_,freeze,r=versioned
    def unknown(*_):raise TransportUnknown('environment unknown',{'sent':'possibly-sent'})
    journal=producer.VmJournal(original,instance.Responsibility())
    command="$r='"+original.physical_namespace+r"\scenario-suite-20260912\another\run-01';$s='SST-Kernel-abc-1';logman start $s -ets"
    with pytest.raises(TransportUnknown):journal.dispatch(unknown,command,30)
    context=freeze();binding=source.resolve_source(context,root)
    assert len(binding.values['kernels'])==2 and any(k['response_unknown'] for k in binding.values['kernels'])
    seen=[]
    names=[k['name'] for k in binding.values['kernels']]
    def closed(command,timeout):
        seen.append(command)
        return {'output':json.dumps({'sessions':[{'name':name,'exit':-2144337918,
            'query':'Data Collector Set was not found.'} for name in names],
            'probe':[],'children':[],'pktmon':'Stopped'})}
    out=context.evidence_root/'gate';out.mkdir(parents=True)
    source.source_capture_gate(SimpleNamespace(vm=SimpleNamespace(powershell=closed)),binding,out)
    assert 'SST-Kernel-abc-1' in seen[0] and 'logman stop' not in seen[0]
    command=next(json.loads(p.read_bytes())['command'] for p in (root/'VM-final-intents').glob('*.json')
                 if '$encoded=' in json.loads(p.read_bytes())['command'])
    with pytest.raises(TransportUnknown):journal.dispatch(unknown,command,30)
    context=freeze();binding=source.resolve_source(context,root)
    assert binding.values['unresolved_capture_intents']
    with pytest.raises(source.SourceError,match='accurate original recovery'):
        source.source_capture_gate(SimpleNamespace(vm=SimpleNamespace(powershell=lambda *_:pytest.fail('must refuse'))),binding,out)
