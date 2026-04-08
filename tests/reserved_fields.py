from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, IPv6ExtHdrFragment
from scapy.packet import Raw
from scapy.sendrecv import sr1

DESCRIPTION = "Send packets with non-zero reserved bits and deprecated next-header values"


def run(target_ip):
    results = []

    # Non-zero traffic class values
    for tc_val in [0xFF, 0x01]:
        pkt = IPv6(dst=target_ip, tc=tc_val) / ICMPv6EchoRequest(id=1, seq=tc_val)
        reply = sr1(pkt, timeout=5, verbose=0)
        results.append((pkt, reply))

    # Maximum flow label value
    pkt_fl = IPv6(dst=target_ip, fl=0xFFFFF) / ICMPv6EchoRequest(id=2, seq=1)
    reply_fl = sr1(pkt_fl, timeout=5, verbose=0)
    results.append((pkt_fl, reply_fl))

    # Fragment header with non-zero reserved fields (res1=3, res2=1)
    full_pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=3, seq=1, data=b"R" * 8)
    icmp_data = bytes(full_pkt)[40:]
    frag_pkt = (
        IPv6(dst=target_ip)
        / IPv6ExtHdrFragment(offset=0, m=0, id=0x5555, nh=58, res1=3, res2=1)
        / Raw(load=icmp_data)
    )
    reply_frag = sr1(frag_pkt, timeout=5, verbose=0)
    results.append((frag_pkt, reply_frag))

    # Deprecated next-header: nh=1 (IPv4 ICMP, not valid in IPv6)
    pkt_nh1 = IPv6(dst=target_ip, nh=1) / Raw(
        load=b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"Z" * 8
    )
    reply_nh1 = sr1(pkt_nh1, timeout=5, verbose=0)
    results.append((pkt_nh1, reply_nh1))

    # Unassigned next-header: nh=253 (RFC 3692 experimentation)
    pkt_nh253 = IPv6(dst=target_ip, nh=253) / Raw(load=b"\x00" * 16)
    reply_nh253 = sr1(pkt_nh253, timeout=5, verbose=0)
    results.append((pkt_nh253, reply_nh253))

    # nh=59 (No Next Header) with trailing data — must be ignored per RFC 8200
    pkt_nh59 = IPv6(dst=target_ip, nh=59) / Raw(load=b"SHOULD_BE_IGNORED")
    reply_nh59 = sr1(pkt_nh59, timeout=5, verbose=0)
    results.append((pkt_nh59, reply_nh59))

    return results
