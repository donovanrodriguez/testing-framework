from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    PadN,
)
from scapy.sendrecv import sr1

DESCRIPTION = "Send packets with long chains of extension headers to test parsing limits"


def run(target_ip):
    results = []
    pad = [PadN(optdata=b"\x00\x00")]

    # Increasing chain lengths to find the per-OS parsing cutoff
    for count in [2, 5, 10, 20, 30]:
        pkt = IPv6(dst=target_ip)
        for _ in range(count):
            pkt = pkt / IPv6ExtHdrDestOpt(options=pad)
        pkt = pkt / ICMPv6EchoRequest(id=count, seq=count)
        reply = sr1(pkt, timeout=5, verbose=0)
        results.append((pkt, reply))

    # HBH (valid first) + 30 DestOpt chain — tests absolute limit
    pkt_max = IPv6(dst=target_ip) / IPv6ExtHdrHopByHop(options=pad)
    for _ in range(30):
        pkt_max = pkt_max / IPv6ExtHdrDestOpt(options=pad)
    pkt_max = pkt_max / ICMPv6EchoRequest(id=99, seq=99)
    reply_max = sr1(pkt_max, timeout=5, verbose=0)
    results.append((pkt_max, reply_max))

    return results
