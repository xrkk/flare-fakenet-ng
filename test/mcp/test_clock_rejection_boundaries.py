"""Invalid clock provenance must fail before capture conversion is consulted."""
import copy
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "acceptance"))
import scenario_kernel_network as kernel
import scenario_tcpip as tcpip

@pytest.mark.parametrize('entry', ['kernel', 'tcpip'])
@pytest.mark.parametrize('fault', ['unknown_both', 'missing_both', 'bool_version', 'float_frequency', 'backwards'])
def test_invalid_brackets_cannot_fall_back_to_legacy(entry, fault):
    a = dict(schema='sst.clock-sampling.v1', version=1, utc_ticks=100000000,
             q0=100000000, q1=100000000, mono=100000000,
             stopwatch_frequency=10000000, offset_minutes=480)
    b = copy.deepcopy(a)
    for k in ('utc_ticks', 'q0', 'q1', 'mono'):
        b[k] += 10000000
    if fault == 'unknown_both':
        a['schema'] = b['schema'] = 'unsupported'
    elif fault == 'missing_both':
        del a['q1']; del b['q1']
    elif fault == 'bool_version':
        a['version'] = b['version'] = True
    elif fault == 'float_frequency':
        b['stopwatch_frequency'] = 10000000.0
    else:
        a, b = b, a
    m = dict(clock_before=a, clock_after=b)
    with pytest.raises(ValueError, match='clock|frequency|discontinuity'):
        if entry == 'kernel':
            m['capture_mode'] = 'kernel-network-ipv4'
            kernel.validate_capture(b'', b'', b'', b'', m, 'synthetic')
        else:
            m['capture_mode'] = 'all-components-tcpip'
            tcpip.validate_capture(b'', b'', m, 50000000)
