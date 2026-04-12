import time

from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrFragment,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ICMPv6ParamProblem,
    ICMPv6TimeExceeded,
)
from scapy.packet import Raw
from scapy.sendrecv import send, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Send tiny and atomic IPv6 fragments to test minimum size enforcement"


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
        if (inner.haslayer(ICMPv6EchoReply) or inner.haslayer(ICMPv6ParamProblem)
                or inner.haslayer(ICMPv6TimeExceeded)):
            return inner
    return None


def run(target_ip):
    results = []

    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"X" * 48)
    icmp_data = bytes(full_pkt)[40:]

    # --- Test 1: Atomic fragment (fragment header present, offset=0, M=0) ---
    frag_id = 0x1111
    atomic = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=0, id=frag_id, nh=58)
        / Raw(load=icmp_data)
    )
    reply1 = _send_and_receive(atomic, target_ip)
    results.append((atomic, reply1))

    # --- Test 2: Tiny first fragment (8 bytes — minimum allowed) ---
    frag_id2 = 0x2222
    tiny1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id2, nh=58)
        / Raw(load=icmp_data[:8])
    )
    tiny2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=1, m=0, id=frag_id2, nh=58)
        / Raw(load=icmp_data[8:])
    )

    send(tiny1, verbose=0)
    reply2 = _send_and_receive(tiny2, target_ip)
    results.append((tiny1, None))
    results.append((tiny2, reply2))

    # --- Test 3: 1-byte payload fragment (below 8-byte alignment) ---
    frag_id3 = 0x3333
    micro1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id3, nh=58)
        / Raw(load=icmp_data[:1])
    )
    micro2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=0, id=frag_id3, nh=58)
        / Raw(load=icmp_data[1:])
    )

    send(micro1, verbose=0)
    reply3 = _send_and_receive(micro2, target_ip)
    results.append((micro1, None))
    results.append((micro2, reply3))

    return results
