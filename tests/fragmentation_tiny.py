from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import sr1, send

DESCRIPTION = "Send tiny and atomic IPv6 fragments to test minimum size enforcement"


def run(target_ip):
    results = []

    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"X" * 48)
    icmp_data = bytes(full_pkt)[40:]  # 56 bytes

    # --- Test 1: Atomic fragment (fragment header present, offset=0, M=0) ---
    # RFC 8200 deprecated atomic fragments but stacks must still handle them
    frag_id = 0x1111
    atomic = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=0, id=frag_id, nh=58)
        / Raw(load=icmp_data)
    )
    reply1 = sr1(atomic, timeout=5, verbose=0)
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
    reply2 = sr1(tiny2, timeout=5, verbose=0)
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
    reply3 = sr1(micro2, timeout=5, verbose=0)
    results.append((micro1, None))
    results.append((micro2, reply3))

    return results
