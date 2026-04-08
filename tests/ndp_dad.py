import socket

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
from scapy.sendrecv import sr1
from scapy.utils6 import in6_getnsma

DESCRIPTION = "Send DAD-style Neighbor Solicitations (src=::) to test address defense"


def run(target_ip):
    results = []

    target_packed = socket.inet_pton(socket.AF_INET6, target_ip)
    nsma_packed = in6_getnsma(target_packed)
    nsma = socket.inet_ntop(socket.AF_INET6, nsma_packed)

    # DAD NS: src=::, dst=solicited-node multicast, no SLLA option
    # Target should respond with NA to ff02::1 if it holds this address
    pkt1 = IPv6(src="::", dst=nsma, hlim=255) / ICMPv6ND_NS(tgt=target_ip)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # DAD NS to all-nodes multicast instead of solicited-node
    pkt2 = IPv6(src="::", dst="ff02::1", hlim=255) / ICMPv6ND_NS(tgt=target_ip)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # DAD NS for an address NOT held by the target (control — expect no reply)
    fake_ip = "2001:db8::dead:beef"
    fake_packed = socket.inet_pton(socket.AF_INET6, fake_ip)
    fake_nsma_packed = in6_getnsma(fake_packed)
    fake_nsma = socket.inet_ntop(socket.AF_INET6, fake_nsma_packed)

    pkt3 = IPv6(src="::", dst=fake_nsma, hlim=255) / ICMPv6ND_NS(tgt=fake_ip)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    return results
