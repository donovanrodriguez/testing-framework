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

DESCRIPTION = "Send overlapping IPv6 fragments and observe reassembly or rejection"


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

    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"A" * 24)
    icmp_data = bytes(full_pkt)[40:]

    # --- Test 1: Overlapping fragments ---
    frag_id = 0xAAAA

    frag1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id, nh=58)
        / Raw(load=icmp_data[:16])
    )
    frag2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=1, m=0, id=frag_id, nh=58)
        / Raw(load=icmp_data[8:])
    )

    send(frag1, verbose=0)
    reply1 = _send_and_receive(frag2, target_ip)
    results.append((frag1, None))
    results.append((frag2, reply1))

    # --- Test 2: Exact duplicate fragment ---
    frag_id2 = 0xBBBB

    frag1b = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id2, nh=58)
        / Raw(load=icmp_data[:16])
    )
    frag1b_dup = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id2, nh=58)
        / Raw(load=icmp_data[:16])
    )
    frag2b = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=2, m=0, id=frag_id2, nh=58)
        / Raw(load=icmp_data[16:])
    )

    send(frag1b, verbose=0)
    send(frag1b_dup, verbose=0)
    reply2 = _send_and_receive(frag2b, target_ip)
    results.append((frag1b, None))
    results.append((frag1b_dup, None))
    results.append((frag2b, reply2))

    return results
