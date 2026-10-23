#!/usr/bin/env python3
"""Independent oracle for the two real manual product paths."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
IDENTITY=('candidate_id','source_commit','package_sha256','execution_id')
def _read(p): return Path(p).read_text(encoding='utf-8',errors='replace')
def _sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def evaluate(root,original,case,expected_inputs,allow_fixture=False):
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):
        raise NotImplementedError('case is not implemented in this round: '+case)
    if not isinstance(expected_inputs,dict): raise ValueError('expected_inputs object required')
    v=json.loads((Path(original)/'manual-result.json').read_text())
    if v.get('case')!=case or v.get('schema')!='fakenet.manual-result.v1': raise ValueError('case/schema mismatch')
    if v.get('fixture') is True and not allow_fixture: raise ValueError('fixture cannot native credit')
    for key in IDENTITY:
        if v.get('identity',{}).get(key)!=expected_inputs.get(key): raise ValueError('identity mismatch: '+key)
    if case=='GAP-NCSI':
        from dnslib import DNSRecord,QTYPE
        expected_ncsi='131.107.255.225'; expected_other=str(expected_inputs.get('responsea','192.0.2.55'))
        seen=set(); failures=[]
        for row in v.get('queries',[]):
            try:
                q=DNSRecord.parse(Path(row['query']).read_bytes()); r=DNSRecord.parse(Path(row['response']).read_bytes())
                if q.header.id!=r.header.id: raise ValueError('id mismatch')
                if q.header.qr!=0 or r.header.qr!=1: raise ValueError('QR mismatch')
                name=str(q.q.qname).rstrip('.'); want=expected_ncsi if name=='dns.msftncsi.com' else expected_other
                if q.q.qtype!=QTYPE.A: raise ValueError('qtype mismatch')
                answers=[str(a.rdata) for a in r.rr if a.rtype==QTYPE.A]
                if answers!=[want]: raise ValueError('A answer mismatch %r/%r'%(answers,want))
                seen.add(row['transport'])
            except Exception as exc: failures.append('%s: %s'%(row.get('transport'),exc))
        if seen!={'udp','tcp'}: failures.append('UDP/TCP coverage missing')
        rows=[{'id':'ncsi-ipv4','status':'pass' if not failures else 'fail'},{'id':'other-domain','status':'pass' if not failures else 'fail'},{'id':'dns-evidence','status':'pass' if not failures else 'fail'}]
        clean=not failures
        return rows,clean,{'failures':failures}
    if case=='GAP-RAW-DATE':
        template=Path(v['raw_template']).read_bytes(); actual=Path(v['raw_response']).read_bytes(); date=str(v.get('date',''))
        expected=template.replace(b'<RAW-DATE>',date.encode())
        static=Path(v['static_response']).read_bytes(); static_template=_read(v['static_template'])
        failures=[]
        if actual!=expected: failures.append('raw bytes not exact replacement')
        if b'<RAW-DATE>' in actual: failures.append('raw placeholder remains')
        if date.encode() not in static: failures.append('static date missing')
        if b'static-'+date.encode() not in static: failures.append('static body replacement missing')
        if v.get('raw_matched') is not True or v.get('non_match') is not False: failures.append('host/URI matching failed')
        if '<RAW-DATE>' in static_template: pass
        rows=[{'id':'raw-date','status':'pass' if not failures else 'fail'},{'id':'preserved-bytes','status':'pass' if not failures else 'fail'}]
        return rows,not failures,{'failures':failures}
    raise ValueError('unknown case')
