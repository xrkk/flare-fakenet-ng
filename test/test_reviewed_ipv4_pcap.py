import os
import socket
import tempfile
import unittest

import dpkt

from analyze_reviewed_ipv4_pcap import MATRICES, analyze


def packet_for(protocol, target, port):
    if protocol == "TCP":
        transport = dpkt.tcp.TCP(sport=50000, dport=port, flags=dpkt.tcp.TH_SYN)
        ip_protocol = dpkt.ip.IP_PROTO_TCP
    else:
        transport = dpkt.udp.UDP(sport=50000, dport=port, data=b"v12")
        transport.ulen = len(transport)
        ip_protocol = dpkt.ip.IP_PROTO_UDP
    packet = dpkt.ip.IP(
        src=socket.inet_aton("192.168.204.10"),
        dst=socket.inet_aton(target),
        p=ip_protocol,
        ttl=64,
        data=transport,
    )
    packet.len = len(packet)
    return dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\x00\xaa\xbb\xcc\xdd\xee",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=packet,
    )


class ReviewedIPv4PcapTests(unittest.TestCase):
    def write_capture(self, tuples):
        handle, path = tempfile.mkstemp(suffix=".pcapng")
        os.close(handle)
        with open(path, "wb") as stream:
            writer = dpkt.pcapng.Writer(stream)
            for item in tuples:
                writer.writepkt(bytes(packet_for(*item)))
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_exact_profile_requires_all_allowed_and_zero_denied(self):
        matrix = MATRICES["exact_ports"]
        result = analyze(self.write_capture(matrix["allowed"]), "exact_ports")
        self.assertTrue(result["allowed_ok"])
        self.assertTrue(result["denied_ok"])

        polluted = analyze(
            self.write_capture(matrix["allowed"] + matrix["denied"][:1]),
            "exact_ports",
        )
        self.assertFalse(polluted["denied_ok"])

    def test_all_ports_profile_requires_each_boundary_tuple(self):
        allowed = MATRICES["all_ports"]["allowed"]
        self.assertTrue(analyze(
            self.write_capture(allowed), "all_ports")["allowed_ok"])
        self.assertFalse(analyze(
            self.write_capture(allowed[:-1]), "all_ports")["allowed_ok"])


if __name__ == "__main__":
    unittest.main()
