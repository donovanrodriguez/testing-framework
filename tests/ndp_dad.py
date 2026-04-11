import socket
import time

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import get_if_hwaddr, Ether
from scapy.sendrecv import sendp, AsyncSniffer
from scapy.config import conf
from scapy.utils6 import in6_getnsma

DESCRIPTION = "Send DAD-style Neighbor Solicitations (src=::) to test address defense"


def _resolve_iface(target_ip):
    route = conf.route6.route(target_ip)
    return route[0] if route[0] else conf.iface


def _sniff_and_send(pkt, mcast_dst, iface, timeout=5):
    nsma_bytes = socket.inet_pton(socket.AF_INET6, mcast_dst)
    mcast_mac = "33:33:%02x:%02x:%02x:%02x" % tuple(nsma_bytes[-4:])

    sniffer = AsyncSniffer(
        iface=iface,
        filter="icmp6 and ip6[40] == 136",
        timeout=timeout,
        count=1,
    )
    sniffer.start()
    time.sleep(0.5)
    sendp(Ether(dst=mcast_mac) / pkt, iface=iface, verbose=0)
    sniffer.join()

    for p in sniffer.results:
        if p.haslayer(ICMPv6ND_NA):
            return p
    return None


def run(target_ip):
    results = []
    iface = str(_resolve_iface(target_ip))

    target_packed = socket.inet_pton(socket.AF_INET6, target_ip)
    nsma_packed = in6_getnsma(target_packed)
    nsma = socket.inet_ntop(socket.AF_INET6, nsma_packed)

    # DAD NS: src=::, dst=solicited-node multicast, no SLLA option
    pkt1 = IPv6(src="::", dst=nsma, hlim=255) / ICMPv6ND_NS(tgt=target_ip)
    reply1 = _sniff_and_send(pkt1, nsma, iface)
    results.append((pkt1, reply1))

    # DAD NS to all-nodes multicast instead of solicited-node
    pkt2 = IPv6(src="::", dst="ff02::1", hlim=255) / ICMPv6ND_NS(tgt=target_ip)
    reply2 = _sniff_and_send(pkt2, "ff02::1", iface)
    results.append((pkt2, reply2))

    # DAD NS for an address NOT held by the target (control — expect no reply)
    fake_ip = "2001:db8::dead:beef"
    fake_packed = socket.inet_pton(socket.AF_INET6, fake_ip)
    fake_nsma_packed = in6_getnsma(fake_packed)
    fake_nsma = socket.inet_ntop(socket.AF_INET6, fake_nsma_packed)

    pkt3 = IPv6(src="::", dst=fake_nsma, hlim=255) / ICMPv6ND_NS(tgt=fake_ip)
    reply3 = _sniff_and_send(pkt3, fake_nsma, iface)
    results.append((pkt3, reply3))

    return results
