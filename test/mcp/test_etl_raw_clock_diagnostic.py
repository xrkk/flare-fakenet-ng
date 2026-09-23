"""Synthetic offline contract checks. These are not Windows ETW acceptance."""
import json
from pathlib import Path
import tempfile
import unittest
import struct
import sys

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))

import etl_raw_clock as e
import tdh_metadata as tdh

class ExportContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = {'timestamp': 111, 'provider': 'abc', 'id': 3, 'version': 1,
                     'opcode': 2, 'task': 4, 'pid': 5, 'tid': 6,
                     'activity': 'def', 'userdata_length': 1,
                     'userdata_sha256': 'payload', 'userdata_base64': 'AA==',
                     'extended_data': []}
    def files(self, raws, utcs):
        raw, utc, paired = (self.root / x for x in ('raw.jsonl','utc.jsonl','paired.jsonl'))
        for path, rows in ((raw, raws), (utc, utcs)):
            path.write_text(''.join(json.dumps(dict(self.base, **row))+'\n' for row in rows), encoding='utf-8')
        return raw, utc, paired
    def test_layout_x64(self):
        found = e.layout_check()
        self.assertEqual(found['EVENT_TRACE_LOGFILEW']['offsets']['EventRecordCallback'], 424)
    def test_pair_and_identity(self):
        args = self.files([{'seq':0,'timestamp':100},{'seq':1,'timestamp':200,'id':4}],
                          [{'seq':0,'timestamp':1000},{'seq':1,'timestamp':2000,'id':4}])
        self.assertEqual(e.pair_streams(*args)['events'],2)
        rows = [json.loads(x) for x in args[2].read_text().splitlines()]
        self.assertEqual([x['raw_timestamp'] for x in rows],[100,200])
        self.assertEqual([x['default_filetime_100ns'] for x in rows],[1000,2000])
        self.assertEqual(e.unique_target(rows,1)['id'],4)
    def test_missing_event_fails(self):
        args = self.files([{'seq':0},{'seq':1,'id':4}], [{'seq':0}])
        with self.assertRaisesRegex(e.DiagnosticError, 'different event counts'):
            e.pair_streams(*args)
    def test_sequence_shift_fails(self):
        args = self.files([{'seq':0}], [{'seq':1}])
        with self.assertRaisesRegex(e.DiagnosticError, 'sequence mismatch'):
            e.pair_streams(*args)
    def test_payload_change_fails(self):
        args = self.files([{'seq':0}], [{'seq':0,'userdata_sha256':'changed'}])
        with self.assertRaisesRegex(e.DiagnosticError, 'identity/payload mismatch'):
            e.pair_streams(*args)
    def test_duplicate_metadata_kept_unique_target_supported(self):
        args = self.files([{'seq':0},{'seq':1,'timestamp':112},{'seq':2,'id':4}],
                          [{'seq':0},{'seq':1,'timestamp':1001},{'seq':2,'timestamp':1002,'id':4}])
        summary=e.pair_streams(*args)
        rows=[json.loads(x) for x in args[2].read_text().splitlines()]
        self.assertEqual(summary['duplicate_identity_groups'],1)
        self.assertEqual([r['binding_status'] for r in rows],['ambiguous','ambiguous','unique'])
        self.assertEqual(e.unique_target(rows,2)['id'],4)
        with self.assertRaisesRegex(e.DiagnosticError,'ambiguous'):
            e.unique_target(rows,0)
    def test_duplicate_target_rejected(self):
        args = self.files([{'seq':0,'id':4},{'seq':1,'timestamp':112,'id':4}],
                          [{'seq':0,'id':4},{'seq':1,'timestamp':1001,'id':4}])
        e.pair_streams(*args)
        rows=[json.loads(x) for x in args[2].read_text().splitlines()]
        with self.assertRaisesRegex(e.DiagnosticError,'ambiguous'):
            e.unique_target(rows,1)
    def test_converted_time_collision_rejected(self):
        args = self.files([{'seq':0},{'seq':1,'id':4}],
                          [{'seq':0,'timestamp':1000},{'seq':1,'timestamp':1000,'id':4}])
        summary=e.pair_streams(*args)
        rows=[json.loads(x) for x in args[2].read_text().splitlines()]
        self.assertEqual(summary['duplicate_converted_time_groups'],1)
        with self.assertRaisesRegex(e.DiagnosticError,'ambiguous'):
            e.unique_target(rows,1)
    def test_non_qpc_unknown_and_lost_fail(self):
        for header, message in [({'ReservedFlags':2,'PerfFreq':10,'EventsLost':0,'BuffersLost':0,'PointerSize':8},'not QPC'),
                                ({'ReservedFlags':0,'PerfFreq':10,'EventsLost':0,'BuffersLost':0,'PointerSize':8},'unknown clock'),
                                ({'ReservedFlags':1,'PerfFreq':10,'EventsLost':1,'BuffersLost':0,'PointerSize':8},'lost events')]:
            with self.subTest(header=header), self.assertRaisesRegex(e.DiagnosticError,message):
                e.clock_check(header)
    def test_callback_exception_captured(self):
        errors=[]
        def emit(_):
            raise RuntimeError('synthetic callback failure')
        callback=e.callback_guard(emit,errors)
        callback(None)
        self.assertEqual(errors[0]['type'],'RuntimeError')
    def test_pktmon_time_integer_conversion(self):
        self.assertEqual(e.pktmon_filetime('2026-09-23T15:23:52.986531300+08:00'),
                         134346218329865313)
        with self.assertRaisesRegex(e.DiagnosticError, 'explicit UTC offset'):
            e.pktmon_filetime('2026-09-23T15:23:52.986531300')
    def test_collision_and_input_unchanged(self):
        inp=self.root/'x.etl'; inp.write_bytes(b'synthetic invalid ETL')
        before=e.sha_file(inp)
        out=self.root/'existing';out.mkdir()
        with self.assertRaises(FileExistsError):
            e.prepare_output(out)
        self.assertEqual(e.sha_file(inp),before)
    def test_input_mutation_rejected(self):
        inp=self.root/'x.etl';inp.write_bytes(b'one')
        before=e.sha_file(inp)
        inp.write_bytes(b'two')
        with self.assertRaisesRegex(e.DiagnosticError,'input changed'):
            e.verify_input_unchanged(before,e.sha_file(inp))
    def test_tdh_metadata_layout_parser_synthetic(self):
        blob=bytearray(200)
        struct.pack_into('<III',blob,100,1,1,0)
        struct.pack_into('<IIHHIHHI',blob,112,0,150,8,8,0,1,8,0)
        blob[150:150+8]='Tcb'.encode('utf-16-le')+b'\0\0'
        result=tdh.parse_tei(bytes(blob))
        self.assertEqual(result['properties'][0]['name'],'Tcb')
        self.assertEqual(result['properties'][0]['metadata_record_offset'],112)
        self.assertEqual(tdh.raw_offsets(b'123123',b'123'),[0,3])
        self.assertEqual(tdh.property_path([{'name':'Outer','flags':1,'in_type_or_struct_start':1,'out_type_or_struct_members':1},{'name':'Tcb','flags':0}],1,1),['Outer','Tcb'])
        with self.assertRaisesRegex(e.DiagnosticError,'outside buffer'):
            bad=bytearray(blob);struct.pack_into('<I',bad,100,999)
            tdh.parse_tei(bytes(bad))
    def test_unsupported_host_records_failure_and_input_unchanged(self):
        inp=self.root/'x.etl';inp.write_bytes(b'synthetic invalid ETL')
        before=e.sha_file(inp)
        out=self.root/'new'
        if e.os.name != 'nt':
            with self.assertRaisesRegex(e.DiagnosticError,'native Windows required'):
                e.export(inp,out)
            manifest=json.loads((out/'manifest.json').read_text())
            self.assertEqual(manifest['status'],'FAILED')
            self.assertEqual(manifest['input_before'],before)
            self.assertEqual(manifest['input_after'],before)
            self.assertEqual(e.sha_file(inp),before)

if __name__ == '__main__':
    unittest.main()
