import socket

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NS,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import sr1
from scapy.config import conf
from scapy.utils6 import in6_getnsma

DESCRIPTION = "Send Neighbor Solicitations and analyze NA responses"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))

    target_packed = socket.inet_pton(socket.AF_INET6, target_ip)
    nsma_packed = in6_getnsma(target_packed)
    nsma = socket.inet_ntop(socket.AF_INET6, nsma_packed)

    # Standard unicast NS with Source Link-Layer Address option
    pkt1 = (
        IPv6(dst=target_ip, hlim=255)
        / ICMPv6ND_NS(tgt=target_ip)
        / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
    )
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Multicast NS to solicited-node multicast address
    pkt2 = (
        IPv6(dst=nsma, hlim=255)
        / ICMPv6ND_NS(tgt=target_ip)
        / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
    )
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # NS without Source Link-Layer Address option
    pkt3 = IPv6(dst=target_ip, hlim=255) / ICMPv6ND_NS(tgt=target_ip)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # NS with hlim != 255 (MUST be silently discarded per RFC 4861)
    pkt4 = (
        IPv6(dst=target_ip, hlim=64)
        / ICMPv6ND_NS(tgt=target_ip)
        / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
    )
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    return results
