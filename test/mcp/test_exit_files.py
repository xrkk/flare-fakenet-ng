import pytest
from fakenet.mcp.exit_files import publish, read, run_directory, digest, validate_target


@pytest.mark.parametrize('run', ['../outside', '/absolute', 'a/b', 'not-a-run'])
def test_notification_cannot_supply_output_path(tmp_path, run):
    with pytest.raises(ValueError):
        run_directory(tmp_path, run)
    assert list(tmp_path.iterdir()) == []


def test_bounded_publication_and_read(tmp_path):
    p = tmp_path / 'record.json'
    with pytest.raises(ValueError):
        publish(p, {'text': 'x' * 20000})
    assert not p.exists()
    publish(p, {'run': 'a'})
    assert read(p) == {'run': 'a'}
    p.write_bytes(b' ' * 20000)
    with pytest.raises(ValueError):
        read(p)


def test_digest_refuses_oversized_file(tmp_path):
    p = tmp_path / 'partial'
    p.write_bytes(b'12345')
    with pytest.raises(ValueError):
        digest(p, limit=4)


def test_only_dedicated_image_can_be_a_target():
    record = dict(schema='fakenet.exit-target.v1',
                  run_id='85fa5b14-fdd5-4867-886a-4ebc5b8e074d',
                  pid=42, supervisor_pid=40, creation_time='1234',
                  supervisor_creation_time='1230', supervisor_instance='current',
                  image=r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe',
                  command_line='managed-child', budget_seconds=60)
    with pytest.raises(ValueError, match='dedicated'):
        validate_target(record, 42)
    record['image'] = r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe'
    assert validate_target(record, 42) is record
    with pytest.raises(ValueError, match='foreign'):
        validate_target(record, 43)
