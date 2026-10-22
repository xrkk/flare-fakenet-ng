"""Re-evaluate original driver artifacts; no native actions or status-only proof."""
import importlib.util
import json
from pathlib import Path


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def load(root, relative):
    spec = importlib.util.spec_from_file_location('acceptance_original_'+Path(relative).stem, Path(root)/relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def upstream(root, directory, checks):
    directory = Path(directory)
    result = read_json(directory/'upstream.json')
    if result.get('schema') != 'fakenet.upstream-result.v1' or result.get('required_checks') != checks:
        raise ValueError('upstream result selection/schema mismatch')
    rows = result.get('checks')
    if not isinstance(rows, list):
        raise ValueError('upstream checks missing')
    converted = [{'id': row['id'], 'status': str(row['status']).lower()} for row in rows]
    expected_suites = list(dict.fromkeys(item.split('::',1)[0] for item in checks))
    lifecycle = read_json(directory/'lifecycle.json')
    if [row.get('suite') for row in lifecycle] != expected_suites:
        raise ValueError('upstream lifecycle does not cover selected suites exactly')
    clean = True
    for index, row in enumerate(lifecycle):
        child = directory/('suite-%02d' % index)
        core = read_json(child/'core-lifecycle.json')
        before, after = read_json(child/'network-before.json'), read_json(child/'network-after.json')
        log = (child/'core.log').read_text(encoding='utf-8',errors='replace')
        if row.get('core') != core:
            raise ValueError('upstream lifecycle differs from original core record')
        good = (core.get('ready') is True and core.get('stopped') is True and
                core.get('forced') is False and core.get('returncode') == 0 and
                before == after and 'FakeNet-NG started successfully' in log and
                (child/'core-console.log').is_file())
        clean = clean and good
    if result.get('failure') or not clean or result.get('cleanup_complete') is not True:
        return converted, False
    return converted, True


def dual_pcap(root, directory, checks, platform):
    directory=Path(directory)
    rows=[]; clean=True
    if platform == 'linux':
        summary=read_json(directory/'summary.json')
        actual=summary.get('results') or []
        required=['Environment','Dependencies']+['Live-'+mode for mode in checks]
        if [row.get('name') for row in actual] != required or any(row.get('status')!='PASS' for row in actual):
            raise ValueError('Linux original result set missing/extra/nonpass')
    else:
        # Original PowerShell result TSV must contain exactly the planned
        # startup/exit/capture/restore rows, plus dependency and normal verifier.
        tsv=(directory/'results.tsv').read_text(encoding='utf-8-sig')
        parsed=[line.split('\t') for line in tsv.splitlines() if line.strip()]
        required=['Dependencies']+[prefix+mode for mode in checks for prefix in ('Start-','Exit-','Capture-','NetworkRestore-')]
        if 'normal' in checks:required.append('LivePcapPair')
        names=[fields[1] for fields in parsed if len(fields)>=2]
        if sorted(names)!=sorted(required) or any(fields[0]!='PASS' for fields in parsed):
            raise ValueError('Windows original result set missing/extra/nonpass')
    for mode in checks:
        child=directory/mode
        evidence=read_json(child/'case-evidence.json')
        before,after=read_json(child/'network-before.json'),read_json(child/'network-after.json')
        if platform=='linux':
            recovered=(evidence.get('network_differences')==[] and evidence.get('resource_residue')==[] and
                       evidence.get('case_error') is None and evidence.get('snapshot_error') is None)
        else:
            recovered=evidence.get('network_restored') is True
        good=(before==after and recovered and evidence.get('process_exited') is True and
              evidence.get('ready') is True and evidence.get('forced') is False)
        clean=clean and good
        code=evidence.get('returncode')
        log=(child/'fakenet.log').read_text(encoding='utf-8',errors='replace')
        fatal=log.count('PCAP_DUAL_WRITE_FAILED')
        if mode=='normal':
            raw=list(p for p in child.glob('*.pcap') if not p.name.endswith('-converted.pcap'))
            eth=list(child.glob('*-converted.pcap'))
            if len(raw)!=1 or len(eth)!=1:raise ValueError('expected exactly one native PCAP pair')
            if platform=='linux':
                original=load(root,'test/dual_pcap_linux/verify_capture.py')
                original.verify_live(str(raw[0]),str(eth[0]),'dual-pcap-linux-v1','198.51.100.77')
            else:
                original=load(root,'test/dual_pcap_vm/verify_dual_pcap.py')
                original.verify(str(raw[0]),str(eth[0]),expected_versions=(4,))
            passed=code==0 and fatal==0 and 'PCAP_DUAL_SUMMARY' in log and 'healthy=True' in log
        else:
            passed=code==1 and fatal==1
            if mode=='close':passed=passed and 'healthy=False' in log
            elif platform=='linux':passed=passed and log.count('PCAP_DUAL_CURRENT_PACKET_DROP')==1
        rows.append({'id':mode,'status':'pass' if passed and good else 'fail'})
    return rows,clean
