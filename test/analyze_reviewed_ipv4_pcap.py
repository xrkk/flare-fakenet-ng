"""Verify v13 reviewed-public-IPv4 acceptance tuples in a pktmon PCAPNG."""

import argparse
import json
import socket

import dpkt


MATRICES = {
    "baidu_tcp443": {
        "allowed": (
            ("TCP", "110.242.69.21", 443),
        ),
        "denied": (
            ("TCP", "110.242.69.21", 80),
            ("TCP", "110.242.69.21", 444),
            ("UDP", "110.242.69.21", 443),
            ("TCP", "110.242.70.57", 443),
        ),
    },
}


def _ipv4_packet(raw):
    try:
        frame = dpkt.ethernet.Ethernet(raw)
        if isinstance(frame.data, dpkt.ip.IP):
            return frame.data
    except (dpkt.UnpackError, ValueError):
        pass
    try:
        packet = dpkt.ip.IP(raw)
        return packet if packet.v == 4 else None
    except (dpkt.UnpackError, ValueError):
        return None


def analyze(path, profile):
    matrix = MATRICES[profile]
    observed = matrix["allowed"] + matrix["denied"]
    counts = {item: 0 for item in observed}
    with open(path, "rb") as stream:
        for _, raw in dpkt.pcapng.Reader(stream):
            packet = _ipv4_packet(raw)
            if packet is None:
                continue
            if isinstance(packet.data, dpkt.tcp.TCP):
                protocol = "TCP"
            elif isinstance(packet.data, dpkt.udp.UDP):
                protocol = "UDP"
            else:
                continue
            item = (protocol, socket.inet_ntoa(packet.dst), packet.data.dport)
            if item in counts:
                counts[item] += 1
    return {
        "profile": profile,
        "counts": {"%s/%s/%d" % item: count for item, count in counts.items()},
        "allowed_ok": all(counts[item] > 0 for item in matrix["allowed"]),
        "denied_ok": all(counts[item] == 0 for item in matrix["denied"]),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("profile", choices=tuple(MATRICES))
    parser.add_argument("report")
    args = parser.parse_args()
    result = analyze(args.pcap, args.profile)
    with open(args.report, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0 if result["allowed_ok"] and result["denied_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
