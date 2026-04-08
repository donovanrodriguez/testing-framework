from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    HBHOptUnknown,
)
from scapy.packet import Raw
from scapy.sendrecv import sr1

DESCRIPTION = "Send packets with unknown extension header types and HBH option action bits"


def run(target_ip):
    results = []

    # Build a raw extension header block: nh=58 (ICMPv6), len=0 (8 bytes total)
    unknown_ext_hdr = bytes([58, 0, 0, 0, 0, 0, 0, 0])
    echo_req = bytes(ICMPv6EchoRequest(id=1, seq=1))

    # Unknown next-header type 253 (RFC 3692 experimentation)
    pkt1 = IPv6(dst=target_ip, nh=253) / Raw(load=unknown_ext_hdr + echo_req)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Unknown next-header type 254 (RFC 3692 experimentation)
    pkt2 = IPv6(dst=target_ip, nh=254) / Raw(load=unknown_ext_hdr + echo_req)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # Unassigned next-header type 142
    pkt3 = IPv6(dst=target_ip, nh=142) / Raw(load=unknown_ext_hdr + echo_req)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # HBH option action bits 00 (skip and continue): otype=0x1F
    skip_opt = HBHOptUnknown(otype=0x1F, optdata=b"\x00\x00")
    pkt4 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[skip_opt])
        / ICMPv6EchoRequest(id=4, seq=4)
    )
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # HBH option action bits 01 (discard silently): otype=0x5F
    discard_opt = HBHOptUnknown(otype=0x5F, optdata=b"\x00\x00")
    pkt5 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[discard_opt])
        / ICMPv6EchoRequest(id=5, seq=5)
    )
    reply5 = sr1(pkt5, timeout=5, verbose=0)
    results.append((pkt5, reply5))

    # HBH option action bits 10 (discard + send ICMPv6 Parameter Problem): otype=0x9F
    error_opt = HBHOptUnknown(otype=0x9F, optdata=b"\x00\x00")
    pkt6 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[error_opt])
        / ICMPv6EchoRequest(id=6, seq=6)
    )
    reply6 = sr1(pkt6, timeout=5, verbose=0)
    results.append((pkt6, reply6))

    # HBH option action bits 11 (discard + send ICMP if not multicast dst): otype=0xDF
    error_nonmcast_opt = HBHOptUnknown(otype=0xDF, optdata=b"\x00\x00")
    pkt7 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[error_nonmcast_opt])
        / ICMPv6EchoRequest(id=7, seq=7)
    )
    reply7 = sr1(pkt7, timeout=5, verbose=0)
    results.append((pkt7, reply7))

    return results
