from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import sr1, send

DESCRIPTION = "Send overlapping IPv6 fragments and observe reassembly or rejection"


def run(target_ip):
    results = []

    # Build a valid ICMPv6 echo with correct checksum, then extract the bytes
    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"A" * 24)
    icmp_data = bytes(full_pkt)[40:]  # 32 bytes of ICMPv6

    # --- Test 1: Overlapping fragments ---
    frag_id = 0xAAAA

    # Fragment 1: offset=0, M=1, first 16 bytes
    frag1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id, nh=58)
        / Raw(load=icmp_data[:16])
    )
    # Fragment 2: offset=1 (8 bytes), M=0, bytes 8-31 — overlaps with frag1 bytes 8-15
    frag2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=1, m=0, id=frag_id, nh=58)
        / Raw(load=icmp_data[8:])
    )

    send(frag1, verbose=0)
    reply1 = sr1(frag2, timeout=5, verbose=0)
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
    reply2 = sr1(frag2b, timeout=5, verbose=0)
    results.append((frag1b, None))
    results.append((frag1b_dup, None))
    results.append((frag2b, reply2))

    return results
