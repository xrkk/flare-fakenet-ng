"""Self-contained original-byte regressions; no historical fixture dependency."""
import hashlib
import json
from pathlib import Path
import pytest
import test_scenario_suite as original


@pytest.mark.parametrize('change', ['run', 'pid_creation', 'tuple', 'generation', 'hash'])
def test_sni_original_identity_is_not_replaceable(monkeypatch, change):
    real = original.suite.Suite._traffic_oracle
    class Verified(Exception):
        pass

    def inspect(runner, run, profile, nonce, sentinel):
        baseline = real(runner, run, profile, nonce, sentinel)
        assert baseline['cases'][3]['passed']
        root = runner.root
        if change == 'run':
            run['run_id'] = 'wrong-run'
        elif change == 'pid_creation':
            p = root / 'probe.jsonl'
            rows = [json.loads(x) for x in p.read_text().splitlines()]
            rows[0]['creation_ticks'] += 10**10  # after connection, not native birth
            p.write_text('\n'.join(json.dumps(x) for x in rows) + '\n', encoding='utf-8')
        elif change == 'tuple':
            p = root / 'run.log'
            p.write_text(p.read_text().replace('sport=50161', 'sport=50162'), encoding='utf-8')
        elif change == 'generation':
            p = root / 'pktmon.txt'
            text = p.read_bytes().decode('utf-16-le')
            text = text.replace('connection 0xAAA transition from ClosedState  to SynSentState',
                                'connection 0xAAB transition from ClosedState  to SynSentState')
            p.write_bytes(text.encode('utf-16-le'))
            meta = root / 'pktmon-nic.json'
            m = json.loads(meta.read_text());m['conversion']['text_sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
            meta.write_text(json.dumps(m), encoding='utf-8')
        else:
            (root / 'run.log').write_bytes((root / 'run.log').read_bytes() + b'tampered\n')
        if change != 'hash':
            for record in run['capture']['files'] + run['originals']['files']:
                raw = (root / record['path']).read_bytes()
                record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        rejected = real(runner, run, profile, nonce, sentinel)
        assert not rejected['passed'], (change, rejected)
        if 'cases' in rejected:
            case = rejected['cases'][3]
            assert not case['passed'], (change, case)
            assert case.get('observation_error') or not case.get('sni_binding')
        else:
            assert any(word in str(rejected).lower() for word in ('identity', 'creation', 'hash', 'run', 'original')), rejected
        raise Verified

    monkeypatch.setattr(original.suite.Suite, '_traffic_oracle', inspect)
    with pytest.raises(Verified):
        original.test_sni_mismatch_binding_rebuilds_from_real_originals_online_and_offline()
