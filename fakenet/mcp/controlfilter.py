# Copyright 2026 Google LLC
"""Control-link exclusion filter clause (P03 IMP-P03-01, platform-neutral).

The clause excludes MCP control responses (dst = allowed host IPv4,
TCP src = the MCP listen port) from the single main WinDivert filter.
Pure string construction so every platform can unit-test it; the Windows
diverter applies it to the FINAL filter right before the main handle
opens (covering both the base construction and the egress-control
rebuild path) and fails closed on any invalid parameter.
"""

import ipaddress


class ControlFilterError(ValueError):
    pass


def build_control_link_exclusion_clause(exclude_ip, exclude_port):
    """Return the `not (...)` clause, or None when no exclusion is set.

    Raises ControlFilterError (fail closed) on partial/invalid input; the
    clause evaluates false for non-IPv4 packets so IPv6 capture semantics
    are unchanged.
    """
    exclude_ip = str(exclude_ip if exclude_ip is not None else '').strip()
    exclude_port = str(
        exclude_port if exclude_port is not None else '').strip()
    if not exclude_ip and not exclude_port:
        return None
    if not exclude_ip or not exclude_port or not exclude_port.isdigit():
        raise ControlFilterError(
            'ControlLink exclusion requires ControlLinkExcludeIp and a '
            'numeric ControlLinkExcludePort (fail closed)')
    try:
        address = ipaddress.ip_address(exclude_ip)
    except ValueError as exc:
        raise ControlFilterError(
            'ControlLinkExcludeIp is not a valid IP address') from exc
    if address.version != 4 or str(address) != exclude_ip:
        raise ControlFilterError(
            'ControlLinkExcludeIp must be a canonical IPv4 address '
            '(fail closed)')
    return 'not (ip.DstAddr == %s and tcp.SrcPort == %s)' % (
        exclude_ip, exclude_port)
