import hashlib
from fakenet.mcp.artifacts import ArtifactRegistry


def test_only_closed_configured_http_post_names_are_published(tmp_path):
    source=tmp_path/'source'; source.mkdir()
    source.joinpath('active-config.ini').write_text('[FakeNet]\nDivertTraffic: No\n[HTTP]\nEnabled: True\nListener: HTTPListener\nDumpHTTPPosts: Yes\nDumpHTTPPostsFilePrefix: post+[safe]\n[Disabled]\nEnabled: False\nListener: HTTPListener\nDumpHTTPPosts: Yes\nDumpHTTPPostsFilePrefix: private\n',encoding='utf-8')
    finished=source/'post+[safe]_20261008_120000.txt'; finished.write_bytes(b'POST / HTTP/1.1\r\n\r\nbenign')
    for name in ('private_20261008_120000.txt','unrelated.txt','post+[safe]_20261008_120000.txt.part','post+[safe]_not-a-date.txt'):
        source.joinpath(name).write_bytes(b'not published')
    registry=ArtifactRegistry(tmp_path/'artifacts')
    registry.register_fakenet_outputs('run',source,prefix='')
    rows=registry.metadata(run_id='run')
    assert next(row for row in rows if row['path'].endswith(finished.name))['sha256']==hashlib.sha256(finished.read_bytes()).hexdigest()
    assert not any(row['path'].endswith('unrelated.txt') or 'private_' in row['path'] or 'not-a-date' in row['path'] or '.part' in row['path'] for row in rows)
    finished.write_bytes(b'changed after publication')
    assert source.joinpath('published.json').exists()


def test_absolute_or_escaping_http_prefix_is_not_read(tmp_path):
    source=tmp_path/'source'; source.mkdir()
    private=tmp_path/'private_20261008_120000.txt'; private.write_bytes(b'keep original')
    source.joinpath('active-config.ini').write_text('[HTTP]\nEnabled: True\nListener: HTTPListener\nDumpHTTPPosts: Yes\nDumpHTTPPostsFilePrefix: ../private\n',encoding='utf-8')
    registry=ArtifactRegistry(tmp_path/'artifacts')
    registry.register_fakenet_outputs('run',source,prefix='')
    assert not any(row['type']=='txt' for row in registry.metadata())
    assert private.read_bytes()==b'keep original'


def test_keep_window_and_changed_registered_bytes(tmp_path):
    source=tmp_path/'source'; source.mkdir()
    source.joinpath('active-config.ini').write_text('[HTTP]\nEnabled: True\nListener: HTTPListener\nDumpHTTPPosts: Yes\n',encoding='utf-8')
    old=source/'http_20261007_120000.txt'; old.write_bytes(b'earlier')
    new=source/'http_20261008_120000.txt'; new.write_bytes(b'current')
    registry=ArtifactRegistry(tmp_path/'artifacts')
    registry.register_fakenet_outputs('run',source,keep=lambda path:path!=old,prefix='')
    assert not (registry.run_dir('run')/old.name).exists()
    copied=registry.run_dir('run')/new.name
    assert next(row for row in registry.metadata() if row['path']==str(copied))['complete'] is True
    copied.write_bytes(b'changed')
    assert next(row for row in registry.metadata() if row['path']==str(copied))['complete'] is False


def test_explicit_compatibility_entry_refuses_active_or_changed_config(tmp_path):
    import importlib.util
    import json
    import uuid
    import pytest
    from pathlib import Path
    spec=importlib.util.spec_from_file_location('closed_publish',Path(__file__).resolve().parents[2]/'tools/publish_closed_run_artifacts.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    root=tmp_path/'artifacts'; run=str(uuid.uuid4()); source=root/'runs'/run;source.mkdir(parents=True)
    config=source/'active-config.ini'; config.write_bytes(b'[HTTP]\nEnabled: True\nListener: HTTPListener\nDumpHTTPPosts: Yes\n')
    post=source/'http_20261008_120000.txt';post.write_bytes(b'closed POST')
    overview={'selected_run_id':run,'consistent':True,'partial':False,'status_after_version':2,
              'service_status':{'state':'healthy','state_version':2,'health':{'process_alive':True},
                                'config_identity':{'sha256':hashlib.sha256(config.read_bytes()).hexdigest()}},
              'artifacts_query':{'query':{'run_id':run},'error':None}}
    with pytest.raises(ValueError):module.publish(overview,root)
    assert not (root/run).exists()
    overview['service_status'].update(state='stopped',health={'process_alive':False})
    result=module.publish(overview,root)
    assert str(root/run/post.name) in result['paths']
    assert (root/run/post.name).read_bytes()==post.read_bytes()
    config.write_bytes(b'changed config')
    with pytest.raises(ValueError,match='config'):module.publish(overview,root)
