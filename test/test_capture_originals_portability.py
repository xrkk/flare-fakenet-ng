"""Exercise real journal creation/sealing on POSIX and Windows Python."""
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest import mock

from fakenet import capture_originals as capture


class CaptureOriginalsPortabilityTests(unittest.TestCase):
    def test_real_writer_seals_utf8_lf_journals_and_pcap_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'benign.pcap'
            raw.write_bytes(b'benign\x00\x0a\x1a\xff')
            with self._writer(raw) as writer:
                writer.record_nbi(session={}, application_layer_proto='test',
                                  is_ssl_encrypted=False, network_mode='fixture',
                                  nbi={'message': '\u539f\u4ef6\nline'})
                seal = writer.seal(str(raw))
                self.assertTrue(writer.sealed)
                self.assertEqual(1, seal['nbis']['records'])
                self.assertEqual(raw.stat().st_ino, seal['raw_pcap']['inode'])
                data = Path(capture.nbis_path(raw)).read_bytes()
                self.assertNotIn(b'\r', data)
                lines = data.decode('utf-8').splitlines()
                self.assertEqual(2, len(lines))
                self.assertEqual('\u539f\u4ef6\nline', json.loads(lines[1])['metrics']['message'])
                self.assertEqual(seal, json.loads(Path(capture.seal_path(raw)).read_bytes()))
                with self.assertRaisesRegex(capture.CaptureOriginalsError, 'refused'):
                    writer.record_observation({})

    @staticmethod
    def _writer(raw):
        # Closing in __exit__ also preserves Windows sharing semantics if
        # a regression raises before the final seal is published.
        from contextlib import contextmanager
        @contextmanager
        def managed():
            writer = capture.CaptureOriginalsWriter(raw)
            try:
                yield writer
            finally:
                writer.close()
        return managed()

    def test_existing_journal_and_exclusive_race_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'benign.pcap'
            existing = Path(capture.nbis_path(raw))
            existing.write_bytes(b'original must survive')
            with self.assertRaises(capture.CaptureOriginalsError):
                capture.CaptureOriginalsWriter(raw)
            self.assertEqual(b'original must survive', existing.read_bytes())
            self.assertFalse(Path(capture.observations_path(raw)).exists())
            path = Path(directory) / 'race'
            barrier = Barrier(2)
            def create(value):
                barrier.wait(timeout=5)
                try:
                    fd = capture._open_exclusive(path)
                except FileExistsError:
                    return False
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(value)
                return True
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(create, (b'one', b'two')))
            self.assertEqual([False, True], sorted(results))
            self.assertIn(path.read_bytes(), (b'one', b'two'))

    def test_regular_file_fsync_failure_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / 'benign.pcap'
            raw.write_bytes(b'benign')
            with self._writer(raw) as writer:
                with mock.patch.object(capture.os, 'fsync', side_effect=OSError('flush failed')):
                    with self.assertRaisesRegex(OSError, 'flush failed'):
                        writer.seal(str(raw))
                self.assertFalse(writer.sealed)
                self.assertFalse(Path(capture.seal_path(raw)).exists())
