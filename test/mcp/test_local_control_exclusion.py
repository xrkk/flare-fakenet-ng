"""Same-machine management responses must survive multiple TCP segments."""
import pytest
from fakenet.mcp.controlfilter import (apply_local_control_exclusion,
    apply_control_link_exclusion, apply_loopback_exclusion, ControlFilterError)


def filtered():
    value=apply_control_link_exclusion('outbound and (ip or ipv6)', '192.168.204.1','28788,28787,28790')
    value=apply_loopback_exclusion(value)
    return apply_local_control_exclusion(value,'192.168.204.149','28788,28787,28790')


def test_control_exclusion_is_exact_and_idempotent():
    result=filtered()
    assert 'ip.SrcAddr != 192.168.204.149 or ip.DstAddr != 192.168.204.149 or ip.Protocol != 6' in result
    for port in [28787,28788,28790]:
        assert '(tcp.SrcPort != %d and tcp.DstPort != %d)'%(port,port) in result
    assert 'tcp.SrcPort != 80' not in result
    assert result==apply_local_control_exclusion(result,'192.168.204.149','28788,28787,28790')
    assert result.endswith('(outbound and ipv6 and ipv6.DstAddr != ::1)')


def test_process_redirect_inbound_tail_preserved():
    tail=' or (inbound and ip and ip.SrcAddr == 192.168.204.1 and ip.DstAddr == 192.168.204.149 and ip.Protocol == 6)'
    assert apply_local_control_exclusion(filtered()+tail,'192.168.204.149','28788,28787,28790').endswith(tail)


@pytest.mark.parametrize('address,ports',[('0.0.0.0','28788'),('127.0.0.1','28788'),('::1','28788'),('192.168.204.149','0'),('192.168.204.149','65536'),('192.168.204.149','bad')])
def test_invalid_binding_refused(address,ports):
    with pytest.raises(ControlFilterError):apply_local_control_exclusion('outbound and ip',address,ports)


def test_tcp_same_address_management_only_semantics():
    # Evaluate the exact new clause using the production-generated port terms.
    result=filtered();start=result.index('(ip.SrcAddr != 192.168.204.149');end=result.index(' or (outbound and ipv6')
    clause=result[start:end-1]
    for source,target,protocol,sport,dport,expected in [
        ('192.168.204.149','192.168.204.149',6,28788,50000,False),
        ('192.168.204.149','192.168.204.149',6,50000,28788,False),
        ('192.168.204.149','192.168.204.149',6,80,50000,True),
        ('192.168.204.149','192.168.204.1',6,28788,50000,True),
        ('192.168.204.149','45.126.126.198',6,50000,80,True),
        ('192.168.204.149','192.168.204.149',17,28788,50000,True)]:
        # Address literals and substituted addresses are both quoted explicitly.
        expression=clause.replace('ip.SrcAddr', 'src').replace('ip.DstAddr','dst').replace('192.168.204.149',repr('192.168.204.149')).replace('ip.Protocol','proto').replace('tcp.SrcPort','sp').replace('tcp.DstPort','dp')
        assert eval(expression,{'__builtins__':{}},dict(src=source,dst=target,proto=protocol,sp=sport,dp=dport)) is expected
