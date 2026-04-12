import time

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ParamProblem,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    PadN,
)
from scapy.sendrecv import send, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Send packets with long chains of extension headers to test parsing limits"


def _send_and_receive(pkt, target_ip, timeout=5):
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

    # Increasing chain lengths to find the per-OS parsing cutoff
    for count in [2, 5, 10, 20, 30]:
        pkt = IPv6(dst=target_ip)
        for _ in range(count):
            pkt = pkt / IPv6ExtHdrDestOpt(options=pad)
        pkt = pkt / ICMPv6EchoRequest(id=count, seq=count)
        reply = _send_and_receive(pkt, target_ip)
        results.append((pkt, reply))

    # HBH (valid first) + 30 DestOpt chain — tests absolute limit
    pkt_max = IPv6(dst=target_ip) / IPv6ExtHdrHopByHop(options=pad)
    for _ in range(30):
        pkt_max = pkt_max / IPv6ExtHdrDestOpt(options=pad)
    pkt_max = pkt_max / ICMPv6EchoRequest(id=99, seq=99)
    reply_max = _send_and_receive(pkt_max, target_ip)
    results.append((pkt_max, reply_max))

    return results
