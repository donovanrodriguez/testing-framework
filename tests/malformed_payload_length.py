from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1

DESCRIPTION = "Send IPv6 packets with incorrect payload length values (zero, short, long)"


def run(target_ip):
    results = []

    # plen=0 but actual payload exists
    pkt1 = IPv6(dst=target_ip, plen=0) / ICMPv6EchoRequest(id=1, seq=1)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # plen too short (actual ICMPv6 echo is 8 bytes, claim 2)
    pkt2 = IPv6(dst=target_ip, plen=2) / ICMPv6EchoRequest(id=2, seq=2)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # plen too long (actual payload is 8 bytes, claim 1000)
    pkt3 = IPv6(dst=target_ip, plen=1000) / ICMPv6EchoRequest(id=3, seq=3)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    return results
