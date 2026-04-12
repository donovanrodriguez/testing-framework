import time
import struct

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ParamProblem,
    IPv6ExtHdrHopByHop,
    HBHOptUnknown,
    in6_chksum,
)
from scapy.packet import Raw
from scapy.sendrecv import send, sr1, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Send packets with unknown extension header types and HBH option action bits"


def _send_and_receive(pkt, target_ip, timeout=5):
    """AsyncSniffer approach for HBH-wrapped packets where sr1 can't match
    echo replies that lack extension headers."""
    iface = conf.route6.route(target_ip)[0]
    sniffer = AsyncSniffer(
        iface=iface,
        filter=f"icmp6 and ip6 src host {target_ip}",
        timeout=timeout,
        count=5,
    )
    sniffer.start()
    time.sleep(0.2)
    send(pkt, verbose=0)
    sniffer.join()
    for p in (sniffer.results or []):
        if not p.haslayer(IPv6):
            continue
        inner = p[IPv6]
        if inner.haslayer(ICMPv6EchoReply) or inner.haslayer(ICMPv6ParamProblem):
            return inner
    return None


def _build_echo_with_checksum(target_ip, echo_id, echo_seq):
    """Build raw ICMPv6 Echo Request bytes with a correct checksum."""
    tmp = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=echo_id, seq=echo_seq)
    chksum = in6_chksum(58, tmp, bytes(tmp.payload))
    body = bytearray(bytes(ICMPv6EchoRequest(id=echo_id, seq=echo_seq)))
    struct.pack_into("!H", body, 2, chksum)
    return bytes(body)


def run(target_ip):
    results = []

    # Build a raw extension header block: nh=58 (ICMPv6), len=0 (8 bytes total)
    unknown_ext_hdr = bytes([58, 0, 0, 0, 0, 0, 0, 0])
    echo_req = _build_echo_with_checksum(target_ip, 1, 1)

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
    reply4 = _send_and_receive(pkt4, target_ip)
    results.append((pkt4, reply4))

    # HBH option action bits 01 (discard silently): otype=0x5F
    discard_opt = HBHOptUnknown(otype=0x5F, optdata=b"\x00\x00")
    pkt5 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[discard_opt])
        / ICMPv6EchoRequest(id=5, seq=5)
    )
    reply5 = _send_and_receive(pkt5, target_ip)
    results.append((pkt5, reply5))

    # HBH option action bits 10 (discard + send ICMPv6 Parameter Problem): otype=0x9F
    error_opt = HBHOptUnknown(otype=0x9F, optdata=b"\x00\x00")
    pkt6 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[error_opt])
        / ICMPv6EchoRequest(id=6, seq=6)
    )
    reply6 = _send_and_receive(pkt6, target_ip)
    results.append((pkt6, reply6))

    # HBH option action bits 11 (discard + send ICMP if not multicast dst): otype=0xDF
    error_nonmcast_opt = HBHOptUnknown(otype=0xDF, optdata=b"\x00\x00")
    pkt7 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=[error_nonmcast_opt])
        / ICMPv6EchoRequest(id=7, seq=7)
    )
    reply7 = _send_and_receive(pkt7, target_ip)
    results.append((pkt7, reply7))

    return results
