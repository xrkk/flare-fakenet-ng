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


LEGACY_BASE = 'outbound and ip'
DUAL_BASE = 'outbound and (ip or ipv6)'

# DEC-008: loopback exemption clauses for the main takeover filter.
LOOPBACK_V4_CLAUSE = ('(ip.DstAddr < 127.0.0.0 or ip.DstAddr > '
                      '127.255.255.255)')
LOOPBACK_V6_CLAUSE = 'ipv6.DstAddr != ::1'


def apply_control_link_exclusion(filter_string, exclude_ip, exclude_port):
    """Append the control-link exclusion to a known main-filter shape.

    WinDivert's language has no unary negation, so the exclusion uses the
    De-Morgan form ``ip.DstAddr != H or (tcp.SrcPort != P1 and ...)`` and
    is folded only into the IPv4 arm, leaving IPv6 semantics untouched.

    Recognized shapes (the only ones the diverter produces):
      * ``outbound and ip``                                (legacy)
      * ``outbound and (ip or ipv6)``                      (egress control)
      * ``(...)`` starting with the dual base              (process-redirect
        rebuild, where the base appears as a leading arm)

    Unknown shapes raise ControlFilterError => fail closed.
    """
    clause = build_control_link_exclusion_clause(exclude_ip, exclude_port)
    if clause is None:
        return filter_string
    ports = [item.strip() for item in
             str(exclude_port).strip().split(',') if item.strip()]
    keep_port = ' and '.join('tcp.SrcPort != %s' % port for port in ports)
    negative = '(ip.DstAddr != %s or (%s))' % (
        str(exclude_ip).strip(), keep_port)
    if negative in filter_string:
        return filter_string
    if filter_string == LEGACY_BASE:
        return 'outbound and ip and %s' % negative
    if filter_string == DUAL_BASE:
        return '(outbound and ip and %s) or (outbound and ipv6)' % negative
    for prefix in (DUAL_BASE, '(%s)' % DUAL_BASE):
        if filter_string.startswith(prefix):
            head = '(outbound and ip and %s) or (outbound and ipv6)' % \
                negative
            return head + filter_string[len(prefix):]
    raise ControlFilterError(
        'unrecognized main filter shape for control-link exclusion: %r'
        % filter_string[:120])


def apply_loopback_exclusion(filter_string):
    """Fold the DEC-008 loopback exemption into a known main-filter shape.

    Loopback traffic (IPv4 127.0.0.0/8, IPv6 ::1) never leaves the machine;
    diverting it hijacks local IPC to FakeNet's fake services (r39
    socketpair handshake deadlock, r40 `Diverter python.exe requested TCP
    127.0.0.1:...` redirection logs). The exemption applies to the main
    takeover filter only — the record-only inbound capture handle keeps
    recording loopback packets for analysis.

    WinDivert's language has no unary negation and no masked ``!=``, so the
    IPv4 clause is the range form ``ip.DstAddr < 127.0.0.0 or
    ip.DstAddr > 127.255.255.255`` (parenthesized; it is an OR expression)
    and IPv6 is the plain ``ipv6.DstAddr != ::1``.

    Recognized shapes are the bases the diverter produces plus every form
    :func:`apply_control_link_exclusion` can emit (including the
    process-redirect rebuild tails). Unknown shapes raise
    ControlFilterError => fail closed.
    """
    if filter_string is None:
        return filter_string
    if LOOPBACK_V4_CLAUSE in filter_string:
        return filter_string  # idempotent
    dual = '(outbound and ip and %s) or (outbound and ipv6 and %s)' % (
        LOOPBACK_V4_CLAUSE, LOOPBACK_V6_CLAUSE)
    if filter_string == DUAL_BASE:
        return dual
    wrapped_dual = '(%s)' % DUAL_BASE
    if filter_string.startswith(wrapped_dual):
        return dual + filter_string[len(wrapped_dual):]
    separator = ' or (outbound and ipv6'
    index = filter_string.find(separator)
    if index >= 0:
        head = filter_string[:index]
        rest = filter_string[index + len(' or '):]
        if head.startswith('(') and head.endswith(')'):
            head = '%s and %s)' % (head[:-1], LOOPBACK_V4_CLAUSE)
        else:
            head = '%s and %s' % (head, LOOPBACK_V4_CLAUSE)
        marker = '(outbound and ipv6'
        rest = (rest[:len(marker)] + ' and %s' % LOOPBACK_V6_CLAUSE +
                rest[len(marker):])
        return '%s or %s' % (head, rest)
    if filter_string.startswith(LEGACY_BASE):
        return '%s and %s' % (filter_string, LOOPBACK_V4_CLAUSE)
    raise ControlFilterError(
        'unrecognized main filter shape for loopback exemption: %r'
        % filter_string[:120])


def build_control_link_exclusion_clause(exclude_ip, exclude_port):
    """Return the exclusion clause, or None when no exclusion is set.

    ``exclude_port`` accepts a single port or a comma-separated port list
    (control port plus any host-only observation channels).  Raises
    ControlFilterError (fail closed) on partial/invalid input; the clause
    evaluates false for non-IPv4 packets so IPv6 semantics are unchanged.
    """
    exclude_ip = str(exclude_ip if exclude_ip is not None else '').strip()
    ports = [item.strip() for item in str(
        exclude_port if exclude_port is not None else '').split(',')]
    if not exclude_ip and not any(ports):
        return None
    if not exclude_ip or not any(ports):
        raise ControlFilterError(
            'ControlLink exclusion requires ControlLinkExcludeIp and '
            'numeric ControlLinkExcludePort (fail closed)')
    for port in ports:
        if not port or not port.isdigit():
            raise ControlFilterError(
                'ControlLinkExcludePort entries must be numeric '
                '(fail closed)')
    try:
        address = ipaddress.ip_address(exclude_ip)
    except ValueError as exc:
        raise ControlFilterError(
            'ControlLinkExcludeIp is not a valid IP address') from exc
    if address.version != 4 or str(address) != exclude_ip:
        raise ControlFilterError(
            'ControlLinkExcludeIp must be a canonical IPv4 address '
            '(fail closed)')
    keep_port = ' and '.join('tcp.SrcPort != %s' % port for port in ports)
    # De Morgan over the port list: keep unless (dst==host AND any port hit)
    return '(ip.DstAddr != %s or (%s))' % (exclude_ip, keep_port)


def exclusion_clause(filter_string, exclude_ip, exclude_port):
    """Backward-compatible single-entry alias used by older callers."""
    return build_control_link_exclusion_clause(exclude_ip, exclude_port)
