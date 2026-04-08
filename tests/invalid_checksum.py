from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, getmacbyip6
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.config import conf

DESCRIPTION = "Send ICMPv6 and UDP packets with corrupted checksums"


def run(target_ip):
    results = []
    target_mac = getmacbyip6(target_ip)
    iface = str(conf.iface)

    # --- ICMPv6 with corrupted checksum ---
    pkt_icmp = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=1, seq=1, data=b"CKSM")
    raw_icmp = bytearray(bytes(pkt_icmp))
    # ICMPv6 checksum at IPv6 header (40 bytes) + offset 2 = bytes 42-43
    raw_icmp[42] = 0xDE
    raw_icmp[43] = 0xAD
    l2_pkt1 = Ether(dst=target_mac, type=0x86DD) / Raw(load=bytes(raw_icmp))
    reply1 = srp1(l2_pkt1, iface=iface, timeout=5, verbose=0)
    results.append((l2_pkt1, reply1))

    # --- ICMPv6 with checksum zeroed ---
    raw_icmp_zero = bytearray(bytes(pkt_icmp))
    raw_icmp_zero[42] = 0x00
    raw_icmp_zero[43] = 0x00
    l2_pkt2 = Ether(dst=target_mac, type=0x86DD) / Raw(load=bytes(raw_icmp_zero))
    reply2 = srp1(l2_pkt2, iface=iface, timeout=5, verbose=0)
    results.append((l2_pkt2, reply2))

    # --- UDP with corrupted checksum ---
    pkt_udp = IPv6(dst=target_ip) / UDP(sport=12345, dport=9999) / Raw(load=b"BADCKSUM")
    raw_udp = bytearray(bytes(pkt_udp))
    # UDP checksum at IPv6 header (40) + UDP offset 6 = bytes 46-47
    raw_udp[46] = 0xBA
    raw_udp[47] = 0xDD
    l2_pkt3 = Ether(dst=target_mac, type=0x86DD) / Raw(load=bytes(raw_udp))
    reply3 = srp1(l2_pkt3, iface=iface, timeout=5, verbose=0)
    results.append((l2_pkt3, reply3))

    # --- UDP with checksum=0 (MUST be dropped in IPv6 per RFC 8200) ---
    raw_udp_zero = bytearray(bytes(pkt_udp))
    raw_udp_zero[46] = 0x00
    raw_udp_zero[47] = 0x00
    l2_pkt4 = Ether(dst=target_mac, type=0x86DD) / Raw(load=bytes(raw_udp_zero))
    reply4 = srp1(l2_pkt4, iface=iface, timeout=5, verbose=0)
    results.append((l2_pkt4, reply4))

    return results
