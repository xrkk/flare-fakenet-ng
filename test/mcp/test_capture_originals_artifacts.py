# Copyright 2026 Google LLC
"""Capture-originals artifact registration qualifies real sealed groups.

Fixtures are produced by the verified production interfaces
(``DualPcapWriter`` + ``CaptureOriginalsWriter``, the same callbacks the
diverter drives through ``logNbi``), never by hand-written schema JSON.
Every counterexample mutates exactly one premise of an otherwise valid
sealed capture and asserts the specific rejection reason, the absent
side-original publication and the untouched plain-artifact semantics.
"""

import hashlib
import json
import logging
import os
import shutil
import socket
from pathlib import Path

import dpkt
import pytest

from fakenet.mcp.artifacts import ArtifactRegistry

PREFIX = 'fakenet-'


def _ip_packet(payload=b'sealed-original'):
    tcp = dpkt.tcp.TCP(sport=40000, dport=3585, seq=100, ack=1,
                       flags=dpkt.tcp.TH_ACK, data=payload)
    tcp.off = 5
    packet = dpkt.ip.IP(src=socket.inet_aton('192.0.2.10'),
                        dst=socket.inet_aton('198.51.100.20'),
                        p=dpkt.ip.IP_PROTO_TCP, ttl=64, data=tcp)
    packet.len = len(packet)
    return bytes(packet)


def build_sealed_capture(directory, stem='packets_20260903_000000',
                         converted=True, nbi=True):
    """One real sealed capture from the production writer interfaces."""
    from fakenet.capture_originals import CaptureOriginalsWriter
    from fakenet.diverters.pcapwriter import DualPcapWriter
    directory = Path(directory)
    raw = str(directory / (stem + '.pcap'))
    ethernet = str(directory / (stem + '-converted.pcap'))
    logger = logging.getLogger('capture-originals-artifacts-test')
    writer = DualPcapWriter(raw, ethernet, logger, clock=lambda: 2.0)
    packet = _ip_packet()
    writer.write_ip_packet(packet)
    originals = CaptureOriginalsWriter(raw)
    originals.record_observation({
        'logical_packet_id': 'packet-1', 'observation_role': 'initial',
        'direction': 'outbound', 'length': len(packet),
        'sha256': hashlib.sha256(packet).hexdigest(), 'timestamp': 2.0})
    if nbi:
        originals.record_nbi(session={'pid': 111, 'comm': 'REGISTRY_FIXTURE'},
                             application_layer_proto='HTTP',
                             is_ssl_encrypted='No', network_mode='singlehost',
                             nbi={'Request URI': '/fixture'})
    summary = writer.close()
    originals.seal(summary.raw_filename,
                   summary.ethernet_filename if converted else None)
    originals.close()
    if not converted:
        os.unlink(ethernet)
    return raw


def group_paths(raw):
    stem = Path(raw).name[:-len('.pcap')]
    parent = Path(raw).parent
    return {'raw': Path(raw),
            'observations': parent / (stem + '.pcap.observations.ndjson'),
            'nbis': parent / (stem + '.pcap.nbis.ndjson'),
            'seal': parent / (stem + '.pcap.capture-originals.json'),
            'converted': parent / (stem + '-converted.pcap')}


def rows_by_name(registry, run_id):
    return {Path(row['path']).name: row
            for row in registry.metadata(run_id=run_id)}


def rejections_for(registry, capture_name):
    return [item for item in registry.last_registration_rejections
            if item['capture'] == capture_name]


def no_side_originals(registry, run_id, paths):
    run_dir = registry.run_dir(run_id)
    for role in ('observations', 'nbis', 'seal'):
        assert not (run_dir / (PREFIX + paths[role].name)).exists(), role
    names = {Path(row['path']).name for row in registry.metadata(run_id=run_id)}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role


def write_http_originals(source):
    source.joinpath('active-config.ini').write_text(
        '[HTTP]\nEnabled: True\nListener: HTTPListener\n'
        'DumpHTTPPosts: Yes\n', encoding='utf-8')
    post = source / 'http_20261008_120000.txt'
    post.write_bytes(b'POST / HTTP/1.1\r\n\r\nbenign')
    return post


def test_real_paired_group_publishes_side_originals_with_accurate_mapping(
        tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('raw', 'converted', 'observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name in names, role
    assert registry.last_registration_rejections == []
    mapping = {Path(item).name[len(PREFIX):]: Path(item) for item in copied}
    for role in ('raw', 'converted', 'observations', 'nbis', 'seal'):
        destination = mapping[paths[role].name]
        assert destination.read_bytes() == paths[role].read_bytes(), role
        assert destination.stat().st_size == paths[role].stat().st_size
    rows = rows_by_name(registry, 'run-1')
    for role in ('observations', 'nbis', 'seal'):
        row = rows[PREFIX + paths[role].name]
        assert row['complete'] is True, role
        assert row['sha256'] == hashlib.sha256(
            paths[role].read_bytes()).hexdigest()
        assert row['size'] == paths[role].stat().st_size
    assert rows[PREFIX + paths['raw'].name]['complete'] is True
    assert registry.metadata(run_id='foreign') == []


def test_raw_only_group_publishes_without_converted(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source, converted=False)
    paths = group_paths(raw)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('raw', 'observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name in names, role
    assert not any(name.endswith('-converted.pcap')
                   for name in names)
    assert registry.last_registration_rejections == []
    for role in ('observations', 'nbis', 'seal'):
        assert rows_by_name(registry, 'run-1')[
            PREFIX + paths[role].name]['complete'] is True


def test_invalid_seal_and_changed_journal_are_rejected_not_exported(tmp_path):
    # The two R27 red-start counterexamples: the loader refuses, so the
    # registry must refuse publication instead of exporting complete=true.
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    paths['seal'].write_text('{"schema":"fakenet.capture-originals.v1"}\n')
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role
    assert PREFIX + paths['raw'].name in names  # plain PCAP semantics stay
    no_side_originals(registry, 'run-1', paths)
    reasons = [item['reason'] for item in
               rejections_for(registry, paths['raw'].name)]
    assert any('capture id' in reason for reason in reasons)

    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    paths2['observations'].write_bytes(
        paths2['observations'].read_bytes() + b'{}\n')
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    copied2 = registry2.register_fakenet_outputs('run-1', source2,
                                                 prefix=PREFIX)
    names2 = {Path(item).name for item in copied2}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths2[role].name not in names2, role
    no_side_originals(registry2, 'run-1', paths2)
    assert any('differs from the seal' in item['reason'] for item in
               rejections_for(registry2, paths2['raw'].name))


def test_missing_seal_or_journal_rejects_group(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    os.unlink(paths['seal'])
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    no_side_originals(registry, 'run-1', paths)
    assert any('seal is missing' in item['reason'] for item in
               rejections_for(registry, paths['raw'].name))

    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    os.unlink(paths2['nbis'])
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    registry2.register_fakenet_outputs('run-1', source2, prefix=PREFIX)
    no_side_originals(registry2, 'run-1', paths2)
    assert rejections_for(registry2, paths2['raw'].name)


def test_foreign_seal_journal_and_capture_id_are_rejected(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw_a = build_sealed_capture(source, 'packets_20260903_000000')
    raw_b = build_sealed_capture(source, 'packets_20260904_000000')
    paths_a = group_paths(raw_a)
    paths_b = group_paths(raw_b)

    # A borrowed seal from another capture never qualifies this one: its
    # converted pairing already names another capture's files.
    paths_a['seal'].write_bytes(paths_b['seal'].read_bytes())
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    no_side_originals(registry, 'run-1', paths_a)
    assert any('does not pair' in item['reason'] for item in
               rejections_for(registry, paths_a['raw'].name))
    # The untouched second capture still publishes completely.
    for role in ('observations', 'nbis', 'seal'):
        assert rows_by_name(registry, 'run-1')[
            PREFIX + paths_b[role].name]['complete'] is True

    # A seal whose pair basename names a different capture is foreign.
    source4 = tmp_path / 'package4'
    source4.mkdir()
    raw4 = build_sealed_capture(source4)
    paths4 = group_paths(raw4)
    seal4 = json.loads(paths4['seal'].read_text())
    seal4['pair_basename'] = 'other_20260903_000000.pcap'
    paths4['seal'].write_text(json.dumps(seal4, indent=2) + '\n')
    registry4 = ArtifactRegistry(tmp_path / 'artifacts4')
    registry4.register_fakenet_outputs('run-1', source4, prefix=PREFIX)
    no_side_originals(registry4, 'run-1', paths4)
    assert any('foreign capture' in item['reason'] for item in
               rejections_for(registry4, paths4['raw'].name))

    # A journal borrowed from another capture is refused for both.
    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    paths2['observations'].write_bytes(
        paths_b['observations'].read_bytes())
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    registry2.register_fakenet_outputs('run-1', source2, prefix=PREFIX)
    no_side_originals(registry2, 'run-1', paths2)
    assert rejections_for(registry2, paths2['raw'].name)

    # Wrong header capture id: the seal's id no longer binds the journals.
    source3 = tmp_path / 'package3'
    source3.mkdir()
    raw3 = build_sealed_capture(source3)
    paths3 = group_paths(raw3)
    seal = json.loads(paths3['seal'].read_text())
    seal['capture_id'] = '01234567-89ab-cdef-0123-456789abcdef'
    paths3['seal'].write_text(json.dumps(seal, indent=2) + '\n')
    registry3 = ArtifactRegistry(tmp_path / 'artifacts3')
    registry3.register_fakenet_outputs('run-1', source3, prefix=PREFIX)
    no_side_originals(registry3, 'run-1', paths3)
    assert any('foreign or invalid' in item['reason'] for item in
               rejections_for(registry3, paths3['raw'].name))


def test_wrong_sha_and_same_sha_physical_replacement_are_rejected(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    seal = json.loads(paths['seal'].read_text())
    seal['raw_pcap']['sha256'] = '0' * 64
    paths['seal'].write_text(json.dumps(seal, indent=2) + '\n')
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    no_side_originals(registry, 'run-1', paths)
    assert any('SHA-256 differs' in item['reason'] for item in
               rejections_for(registry, paths['raw'].name))

    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    replacement = Path(raw2).with_name('.replacement')
    replacement.write_bytes(Path(raw2).read_bytes())
    os.replace(replacement, raw2)  # identical bytes, new inode
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    registry2.register_fakenet_outputs('run-1', source2, prefix=PREFIX)
    no_side_originals(registry2, 'run-1', paths2)
    assert any('physical replacement' in item['reason'] for item in
               rejections_for(registry2, paths2['raw'].name))


def test_seal_cannot_select_converted_paths_or_names(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    for name in ('../outside-converted.pcap', '/tmp/escape-converted.pcap',
                 'other_20260903_000000-converted.pcap'):
        seal = json.loads(paths['seal'].read_text())
        seal['converted_pcap']['name'] = name
        paths['seal'].write_text(json.dumps(seal, indent=2) + '\n')
        registry = ArtifactRegistry(
            tmp_path / ('artifacts-%d' % (abs(hash(name)) % 100000)))
        registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
        no_side_originals(registry, 'run-1', paths)
        assert any('does not pair' in item['reason'] for item in
                   rejections_for(registry, paths['raw'].name)), name

    # A converted PCAP the seal names but that is missing rejects the group.
    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    os.unlink(paths2['converted'])
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    registry2.register_fakenet_outputs('run-1', source2, prefix=PREFIX)
    no_side_originals(registry2, 'run-1', paths2)
    assert any('missing or not a plain file' in item['reason'] for item in
               rejections_for(registry2, paths2['raw'].name))

    # Unrelated ndjson and an unsealed orphan's sidecar never register.
    source2.joinpath('extra.ndjson').write_bytes(b'{"not":"an original"}\n')
    orphan = source2 / 'orphan_20260903_000000.pcap'
    orphan.write_bytes(b'orphan-pcap')
    source2.joinpath(orphan.name + '.observations.ndjson').write_bytes(
        b'{"ordinal":1}\n')
    copied2 = registry2.register_fakenet_outputs('run-2', source2,
                                                 prefix=PREFIX)
    names2 = {Path(item).name for item in copied2}
    assert 'fakenet-extra.ndjson' not in names2
    assert PREFIX + orphan.name in names2  # plain PCAP semantics stay
    assert PREFIX + orphan.name + '.observations.ndjson' not in names2


def test_symlinked_originals_are_rejected(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    outside = tmp_path / 'outside-converted.pcap'
    shutil.copyfile(paths['converted'], outside)
    paths['converted'].unlink()
    os.symlink(outside, paths['converted'])
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    no_side_originals(registry, 'run-1', paths)
    assert any('missing or not a plain file' in item['reason'] for item in
               rejections_for(registry, paths['raw'].name))

    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    target = tmp_path / 'real-journal.ndjson'
    target.write_bytes(paths2['observations'].read_bytes())
    paths2['observations'].unlink()
    os.symlink(target, paths2['observations'])
    registry2 = ArtifactRegistry(tmp_path / 'artifacts2')
    registry2.register_fakenet_outputs('run-1', source2, prefix=PREFIX)
    no_side_originals(registry2, 'run-1', paths2)
    assert any('symlink' in item['reason'] or 'plain file' in item['reason']
               for item in rejections_for(registry2, paths2['raw'].name))


def test_keep_covering_only_part_of_the_group_blocks_side_originals(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs(
        'run-1', source, keep=lambda path: path != paths['seal'],
        prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role
    assert PREFIX + paths['raw'].name in names  # plain PCAP semantics stay
    assert any('keep filter excluded group members' in item['reason'] and
               paths['seal'].name in item['reason'] for item in
               rejections_for(registry, paths['raw'].name))


def test_existing_destination_with_different_bytes_rejects_group(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw_first = build_sealed_capture(source, 'packets_20260903_000000')
    paths_first = group_paths(raw_first)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    for role in ('observations', 'nbis', 'seal'):
        assert rows_by_name(registry, 'run-1')[
            PREFIX + paths_first[role].name]['complete'] is True

    # A different capture under the same basename must not overwrite or
    # re-publish over the recorded history.
    source_second = tmp_path / 'package-second'
    source_second.mkdir()
    raw_second = build_sealed_capture(source_second,
                                      'packets_20260903_000000')
    paths_second = group_paths(raw_second)
    assert paths_second['observations'].read_bytes() != \
        paths_first['observations'].read_bytes()
    copied = registry.register_fakenet_outputs('run-1', source_second,
                                               prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths_second[role].name not in names, role
    run_dir = registry.run_dir('run-1')
    assert (run_dir / (PREFIX + paths_first['observations'].name)
            ).read_bytes() == paths_first['observations'].read_bytes()
    assert any('existing destination differs' in item['reason'] for item in
               rejections_for(registry, paths_second['raw'].name))

    # Re-registering the same qualified capture stays complete and never
    # counts an identical destination as a conflict.
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    rows = rows_by_name(registry, 'run-1')
    for role in ('observations', 'nbis', 'seal'):
        row = rows[PREFIX + paths_first[role].name]
        assert row['complete'] is True, role
        assert row['sha256'] == hashlib.sha256(
            paths_first[role].read_bytes()).hexdigest()


def test_source_change_during_copy_rejects_group(monkeypatch, tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    real_copy2 = shutil.copy2

    def poisoned_copy2(source_path, destination_path):
        real_copy2(source_path, destination_path)
        if str(source_path).endswith('.observations.ndjson'):
            with open(source_path, 'ab') as stream:
                stream.write(b'{}\n')

    monkeypatch.setattr(shutil, 'copy2', poisoned_copy2)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role
    no_side_originals(registry, 'run-1', paths)
    assert registry.last_registration_rejections
    assert PREFIX + paths['raw'].name in names  # plain PCAP semantics stay


def test_copy_failure_rejects_group_without_partial_originals(
        monkeypatch, tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)

    real_copy2 = shutil.copy2

    def failing_copy2(source_path, destination_path):
        if str(source_path).endswith('.observations.ndjson'):
            raise OSError('injected copy failure')
        return real_copy2(source_path, destination_path)

    monkeypatch.setattr(shutil, 'copy2', failing_copy2)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role
    no_side_originals(registry, 'run-1', paths)
    assert any('injected copy failure' in item['reason'] for item in
               registry.last_registration_rejections)
    leftovers = [item.name for item in registry.run_dir('run-1').iterdir()
                 if item.name.startswith('.copy-')]
    assert leftovers == []


def test_same_bytes_swap_after_qualification_rejects_publication(
        monkeypatch, tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    real_copy2 = shutil.copy2

    def swapping_copy2(source_path, destination_path):
        result = real_copy2(source_path, destination_path)
        if str(source_path).endswith('.observations.ndjson'):
            replacement = Path(raw).with_name('.swap')
            replacement.write_bytes(Path(raw).read_bytes())
            os.replace(replacement, raw)  # identical bytes, new inode
        return result

    monkeypatch.setattr(shutil, 'copy2', swapping_copy2)
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + paths[role].name not in names, role
    no_side_originals(registry, 'run-1', paths)
    assert any('physical replacement' in item['reason'] for item in
               registry.last_registration_rejections)


def test_bad_group_does_not_block_valid_group_or_http_originals(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    post = write_http_originals(source)
    raw_good = build_sealed_capture(source, 'packets_20260903_000000')
    raw_bad = build_sealed_capture(source, 'packets_20260904_000000')
    good = group_paths(raw_good)
    bad = group_paths(raw_bad)
    bad['observations'].write_bytes(
        bad['observations'].read_bytes()[:-1])  # truncated after sealing
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    copied = registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    names = {Path(item).name for item in copied}
    for role in ('observations', 'nbis', 'seal'):
        assert PREFIX + good[role].name in names, role
        assert PREFIX + bad[role].name not in names, role
    rows = rows_by_name(registry, 'run-1')
    for role in ('observations', 'nbis', 'seal'):
        assert rows[PREFIX + good[role].name]['complete'] is True
    http_row = next(row for row in registry.metadata(run_id='run-1')
                    if row['path'].endswith(post.name))
    assert http_row['complete'] is True
    assert http_row['sha256'] == hashlib.sha256(post.read_bytes()).hexdigest()
    assert any('differs from the seal' in item['reason'] or
               'truncated' in item['reason'] for item in
               rejections_for(registry, bad['raw'].name))


def test_invalid_seal_metadata_is_rejected_clearly_not_a_crash(tmp_path):
    source = tmp_path / 'package'
    source.mkdir()
    raw = build_sealed_capture(source)
    paths = group_paths(raw)
    seal = json.loads(paths['seal'].read_text())
    seal['observations']['records'] = 'many'
    paths['seal'].write_text(json.dumps(seal, indent=2) + '\n')
    registry = ArtifactRegistry(tmp_path / 'artifacts')
    registry.register_fakenet_outputs('run-1', source, prefix=PREFIX)
    no_side_originals(registry, 'run-1', paths)
    assert any('is not an integer' in item['reason'] for item in
               rejections_for(registry, paths['raw'].name))

    # The loader's own guard: a journal ordinal that is not an integer is
    # refused with its reason instead of an unrelated crash.
    from fakenet.payload_report import (PayloadReportError,
                                        load_capture_originals)
    source2 = tmp_path / 'package2'
    source2.mkdir()
    raw2 = build_sealed_capture(source2)
    paths2 = group_paths(raw2)
    journal = paths2['observations']
    lines = journal.read_text().splitlines()
    lines[1] = lines[1].replace('"ordinal":1', '"ordinal":"one"')
    journal.write_text('\n'.join(lines) + '\n')
    seal2 = json.loads(paths2['seal'].read_text())
    data = journal.read_bytes()
    seal2['observations']['bytes'] = len(data)
    seal2['observations']['sha256'] = hashlib.sha256(data).hexdigest()
    paths2['seal'].write_text(json.dumps(seal2, indent=2) + '\n')
    with pytest.raises(PayloadReportError, match='ordinal is not an integer'):
        load_capture_originals(raw2, paths2['converted'])
