import time

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ParamProblem,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    PadN,
)
from scapy.sendrecv import send, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Send packets with extension headers in correct and incorrect RFC 8200 order"


def _send_and_receive(pkt, target_ip, timeout=5):
    """sr1 can't match echo replies to ext-header-wrapped requests because
    the reply lacks extension headers.  Use AsyncSniffer instead."""
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
    reply1 = _send_and_receive(pkt1, target_ip)
    results.append((pkt1, reply1))

    # Wrong order: DestOpt BEFORE HBH (HBH must be first after IPv6 header)
    pkt2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrDestOpt(options=pad)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=2, seq=2)
    )
    reply2 = _send_and_receive(pkt2, target_ip)
    results.append((pkt2, reply2))

    # Correct order: HBH, Routing, DestOpt, ICMPv6
    pkt3 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / IPv6ExtHdrRouting(type=0, segleft=0, addresses=[])
        / IPv6ExtHdrDestOpt(options=pad)
        / ICMPv6EchoRequest(id=3, seq=3)
    )
    reply3 = _send_and_receive(pkt3, target_ip)
    results.append((pkt3, reply3))

    # Wrong order: Routing before HBH
    pkt4 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrRouting(type=0, segleft=0, addresses=[])
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=4, seq=4)
    )
    reply4 = _send_and_receive(pkt4, target_ip)
    results.append((pkt4, reply4))

    # HBH only (valid, correct position)
    pkt5 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=5, seq=5)
    )
    reply5 = _send_and_receive(pkt5, target_ip)
    results.append((pkt5, reply5))

    # Duplicate HBH headers (RFC 8200: MUST NOT appear more than once)
    pkt6 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrHopByHop(options=pad)
        / IPv6ExtHdrHopByHop(options=pad)
        / ICMPv6EchoRequest(id=6, seq=6)
    )
    reply6 = _send_and_receive(pkt6, target_ip)
    results.append((pkt6, reply6))

    return results
