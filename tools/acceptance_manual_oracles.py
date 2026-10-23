#!/usr/bin/env python3
"""Independent manual-feature oracle; rereads emitted bytes, never status only."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
CASES=('GAP-EXECUTECMD','GAP-NCSI','GAP-STANDALONE-LISTENERS','GAP-CTRLC-IPC','GAP-DIVERTER-SWITCH','GAP-SYSLOG-ICMP-LOG','GAP-DUMPPACKETS','GAP-LINUX-FLUSH-INTERFACE','GAP-NETWORK-FIX','GAP-RAW-DATE','GAP-LIST-MUTEX')
def _read(p): return Path(p).read_text(encoding='utf-8',errors='replace')
def evaluate(root,original,case,expected_inputs=None,allow_fixture=False):
    v=json.loads((Path(original)/'manual-result.json').read_text())
    if v.get('case')!=case: raise ValueError('case mismatch')
    if v.get('fixture') is True and not allow_fixture: raise ValueError('fixture cannot native credit')
    rows={}
    def mark(name,ok): rows[name]='pass' if ok else 'fail'
    try:
        if case=='GAP-EXECUTECMD':
            t=_read(v['log']); mark('command',v.get('command')=='/bin/echo'); mark('first-connection',v['connection']['first'] and 'first-connection=true' in t); mark('non-connection',not v['connection']['second'] and 'non-connection=sentinel' in t)
        elif case=='GAP-NCSI':
            lines=[json.loads(x) for x in _read(v['dns']).splitlines()]; mark('ncsi-ipv4',any(x['q']=='dns.msftncsi.com' and '131.107.255.225' in x['a'] for x in lines)); mark('other-domain',any(x['q']=='other.example' and x['a'] and x['a']!=['131.107.255.225'] for x in lines)); mark('dns-evidence',len(lines)==2)
        elif case=='GAP-STANDALONE-LISTENERS':
            raw=bytes.fromhex(v['request'])+bytes.fromhex(v['response']); mark('listener-bytes',b'FNPR/1|manual|' in raw and raw.count(b'FNPR/1')==2); mark('listener-close',v.get('closed') is True)
        elif case=='GAP-CTRLC-IPC':
            t=_read(v['log']); mark('ctrlc','SIGINT' in t); mark('ipc-stop','stop flag' in t and v.get('ipc')=='halt'); mark('owned-exit',v.get('exit')==0 and 'core_exit=0' in t)
        elif case=='GAP-DIVERTER-SWITCH':
            t=_read(v['config']); mark('on','DivertTraffic: Yes' in t); mark('off',v.get('modes')==['on','off']); mark('restore',v['before']==v['after']=={'rules':0})
        elif case=='GAP-SYSLOG-ICMP-LOG':
            t=_read(v['log']); mark('syslog','SYSLOG' in t); mark('icmp',v.get('icmp') is True and 'ICMP' in t); mark('owner',v.get('owner')==4242 and 'pid=4242' in t)
        elif case=='GAP-DUMPPACKETS':
            data=Path(v['pcap']).read_bytes(); mark('enabled',v.get('enabled') is True); mark('disabled',len(data)>24); mark('prefix',v.get('prefix')=='manual'); mark('content',len(data)>24 and data[:4]==b'\xd4\xc3\xb2\xa1')
        elif case=='GAP-LINUX-FLUSH-INTERFACE':
            t=_read(v['config']); mark('flush-iptables','LinuxFlushIptables: Yes' in t); mark('flush-dns','LinuxFlushDNSCommand' in t); mark('restrict-interface','LinuxRestrictInterface: eth0' in t and v.get('rules')=={'iptables':['-F']})
        elif case=='GAP-NETWORK-FIX':
            t=_read(v['config']); mark('fix-gateway','FixGateway: Yes' in t); mark('fix-dns','FixDNS: Yes' in t); mark('modify-local-dns','ModifyLocalDNS: Yes' in t); mark('stop-dns','StopDNSService: No' in t and v['before']==v['after'])
        elif case=='GAP-RAW-DATE':
            t=_read(v['response']); mark('raw-date',v.get('date') in t and 'Date:' in t); mark('preserved-bytes',v.get('preserved') in t)
        elif case=='GAP-LIST-MUTEX':
            d=json.loads(_read(v['lists'])); mark('blacklist','b.example' in d['blacklist']); mark('whitelist','w.example' in d['whitelist']); mark('mutex',d.get('mutex') is False)
    except Exception as exc:
        rows={x:'fail' for x in rows or []}; rows['error']='%s: %s' % (type(exc).__name__,exc)
    out=[{'id':x,'status':rows.get(x,'fail')} for x in expected_inputs or []]
    if not out:
        out=[{'id':x,'status':'pass' if rows.get(x)=='pass' else 'fail'} for x in rows if x in ('command','first-connection','non-connection','ncsi-ipv4','other-domain','dns-evidence','listener-bytes','listener-close','ctrlc','ipc-stop','owned-exit','on','off','restore','syslog','icmp','owner','enabled','disabled','prefix','content','flush-iptables','flush-dns','restrict-interface','fix-gateway','fix-dns','modify-local-dns','stop-dns','raw-date','preserved-bytes','blacklist','whitelist','mutex')]
    clean=all(x['status']=='pass' for x in out) and v.get('cleanup',{}).get('stopped') is True and v.get('cleanup',{}).get('network_restored') is True
    return out,clean,rows
