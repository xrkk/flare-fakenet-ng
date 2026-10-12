import hashlib
import os
from pathlib import Path

from fakenet.mcp.artifacts import ArtifactRegistry


def _build_package(root):
    pcap = root / 'packets_20260903_000000.pcap'
    pcap.write_bytes(b'\xd4\xc3\xb2\xa1raw-pcap')
    converted = root / 'packets_20260903_000000-converted.pcap'
    converted.write_bytes(b'\xd4\xc3\xb2\xa1converted-pcap')
    observations = root / (pcap.name + '.observations.ndjson')
    observations.write_bytes(b'{"ordinal":1}\n')
    nbis = root / (pcap.name + '.nbis.ndjson')
    nbis.write_bytes(b'{"ordinal":1}\n')
    seal = root / (pcap.name + '.capture-originals.json')
    seal.write_bytes(b'{"schema":"fakenet.capture-originals.v1"}\n')
    report = root / 'report_20260903_000000.html'
    report.write_bytes(b'<html></html>')
    extra = root / 'extra.ndjson'
    extra.write_bytes(b'{"not":"a capture original"}\n')
    orphan = root / 'orphan_20260903_000000.pcap'
    orphan.write_bytes(b'orphan-pcap')
    (root / (orphan.name + '.observations.ndjson')).write_bytes(
        b'{"ordinal":1}\n')
    return dict(pcap=pcap, converted=converted, observations=observations,
                nbis=nbis, seal=seal, report=report, extra=extra,
                orphan=orphan)


def test_sealed_pair_sidecars_register_with_matching_metadata(tmp_path):
    package = tmp_path / 'package'
    package.mkdir()
    sources = _build_package(package)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', package,
                                               prefix='fakenet-')
    names = {Path(item).name for item in copied}
    for key in ('pcap', 'observations', 'nbis', 'seal', 'report'):
        assert 'fakenet-' + sources[key].name in names
    # An unsealed sidecar and an arbitrary other *.ndjson never qualify.
    assert 'fakenet-extra.ndjson' not in names
    assert 'fakenet-' + sources['orphan'].name + '.observations.ndjson' \
        not in names
    rows = {Path(item['path']).name: item
            for item in registry.metadata(run_id='run-1')}
    for key in ('observations', 'nbis', 'seal'):
        row = rows['fakenet-' + sources[key].name]
        assert row['complete'] is True
        assert row['sha256'] == hashlib.sha256(
            sources[key].read_bytes()).hexdigest()
        assert row['size'] == sources[key].stat().st_size
    assert rows['fakenet-' + sources['pcap'].name]['complete'] is True
    # The registry walked only this run's subtree; a foreign run is empty.
    assert registry.metadata(run_id='foreign') == []


def test_symlinked_sidecar_is_not_registered(tmp_path):
    package = tmp_path / 'package'
    package.mkdir()
    sources = _build_package(package)
    target = tmp_path / 'real.ndjson'
    target.write_bytes(b'{"ordinal":1}\n')
    os.unlink(sources['observations'])
    os.symlink(target, sources['observations'])
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', package,
                                               prefix='fakenet-')
    names = {Path(item).name for item in copied}
    assert 'fakenet-' + sources['observations'].name not in names
    assert 'fakenet-' + sources['nbis'].name in names


def test_unsealed_pair_never_registers_sidecars(tmp_path):
    package = tmp_path / 'package'
    package.mkdir()
    sources = _build_package(package)
    os.unlink(sources['seal'])
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', package,
                                               prefix='fakenet-')
    names = {Path(item).name for item in copied}
    assert 'fakenet-' + sources['observations'].name not in names
    assert 'fakenet-' + sources['nbis'].name not in names
    assert 'fakenet-extra.ndjson' not in names
