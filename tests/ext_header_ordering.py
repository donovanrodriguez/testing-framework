from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    PadN,
)
from scapy.sendrecv import sr1

DESCRIPTION = "Send packets with extension headers in correct and incorrect RFC 8200 order"


def run(target_ip):
    results = []
    pad = [PadN(optdata=b"\x00\x00")]

    # Correct order: HBH, DestOpt, ICMPv6
    pkt1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / IPv6ExtHdrDestOpt(options=pad)
        / ICMPv6EchoRequest(id=1, seq=1)
    )
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Wrong order: DestOpt BEFORE HBH (HBH must be first after IPv6 header)
    pkt2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrDestOpt(options=pad)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=2, seq=2)
    )
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # Correct order: HBH, Routing, DestOpt, ICMPv6
    pkt3 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / IPv6ExtHdrRouting(type=0, segleft=0, addresses=[])
        / IPv6ExtHdrDestOpt(options=pad)
        / ICMPv6EchoRequest(id=3, seq=3)
    )
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # Wrong order: Routing before HBH
    pkt4 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrRouting(type=0, segleft=0, addresses=[])
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=4, seq=4)
    )
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # HBH only (valid, correct position)
    pkt5 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=5, seq=5)
    )
    reply5 = sr1(pkt5, timeout=5, verbose=0)
    results.append((pkt5, reply5))

    # Duplicate HBH headers (RFC 8200: MUST NOT appear more than once)
    pkt6 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=6, seq=6)
    )
    reply6 = sr1(pkt6, timeout=5, verbose=0)
    results.append((pkt6, reply6))

    return results
