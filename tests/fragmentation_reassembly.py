from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.packet import Raw
from scapy.sendrecv import sr1, send

DESCRIPTION = "Test fragment reassembly with out-of-order and missing fragments (slow: ~65s timeout)"

REASSEMBLY_TIMEOUT = 65


def run(target_ip):
    results = []

    # --- Test 1: Out-of-order delivery (frag2 before frag1) ---
    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"R" * 48)
    icmp_data = bytes(full_pkt)[40:]

    frag_id = 0xAA01
    frag1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id, nh=58)
        / Raw(load=icmp_data[:24])
    )
    frag2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=3, m=0, id=frag_id, nh=58)
        / Raw(load=icmp_data[24:])
    )

    send(frag2, verbose=0)
    results.append((frag2, None))
    reply1 = sr1(frag1, timeout=5, verbose=0)
    results.append((frag1, reply1))

    # --- Test 2: Missing middle fragment (send frag1 + frag3, skip frag2) ---
    # After reassembly timeout (~60s), some OSes send ICMPv6 Time Exceeded
    frag_id2 = 0xAA02
    full_pkt2 = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=2, seq=2, data=b"M" * 48)
    icmp_data2 = bytes(full_pkt2)[40:]

    f1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id2, nh=58)
        / Raw(load=icmp_data2[:16])
    )
    f3 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=4, m=0, id=frag_id2, nh=58)
        / Raw(load=icmp_data2[32:])
    )

    send(f1, verbose=0)
    results.append((f1, None))
    reply2 = sr1(f3, timeout=REASSEMBLY_TIMEOUT, verbose=0)
    results.append((f3, reply2))

    # --- Test 3: Three fragments in reverse order (3, 2, 1) ---
    frag_id3 = 0xAA03
    full_pkt3 = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=3, seq=3, data=b"O" * 48)
    icmp_data3 = bytes(full_pkt3)[40:]

    r1 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=1, id=frag_id3, nh=58)
        / Raw(load=icmp_data3[:16])
    )
    r2 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=2, m=1, id=frag_id3, nh=58)
        / Raw(load=icmp_data3[16:32])
    )
    r3 = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=4, m=0, id=frag_id3, nh=58)
        / Raw(load=icmp_data3[32:])
    )

    send(r3, verbose=0)
    results.append((r3, None))
    send(r2, verbose=0)
    results.append((r2, None))
    reply3 = sr1(r1, timeout=5, verbose=0)
    results.append((r1, reply3))

    return results
