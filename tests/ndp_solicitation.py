import socket
import time

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.l2 import get_if_hwaddr, Ether
from scapy.sendrecv import sr1, sendp, AsyncSniffer
from scapy.config import conf
from scapy.route6 import Route6
from scapy.utils6 import in6_getnsma

DESCRIPTION = "Send Neighbor Solicitations and analyze NA responses"


def _resolve_iface(target_ip):
    route = conf.route6.route(target_ip)
    return route[0] if route[0] else conf.iface


def run(target_ip):
    results = []
    iface = str(_resolve_iface(target_ip))
    my_mac = get_if_hwaddr(iface)

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
    sniffer = AsyncSniffer(
        iface=iface,
        filter="icmp6 and ip6[40] == 136",
        timeout=5,
        count=1,
    )
    nsma_bytes = socket.inet_pton(socket.AF_INET6, nsma)
    mcast_mac = "33:33:%02x:%02x:%02x:%02x" % tuple(nsma_bytes[-4:])
    sniffer.start()
    time.sleep(0.5)
    sendp(Ether(dst=mcast_mac) / pkt2, iface=iface, verbose=0)
    sniffer.join()
    reply2 = None
    if sniffer.results:
        for pkt in sniffer.results:
            if pkt.haslayer(ICMPv6ND_NA):
                reply2 = pkt
                break
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
