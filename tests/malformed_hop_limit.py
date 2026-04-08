from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1

DESCRIPTION = "Send ICMPv6 Echo Requests with edge-case hop limits (0, 1)"


def run(target_ip):
    results = []

    # hlim=0: should be expired on arrival, but since the packet IS at its
    # destination, behavior varies — some stacks accept, others drop
    pkt1 = IPv6(dst=target_ip, hlim=0) / ICMPv6EchoRequest(id=1, seq=1)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # hlim=1: valid for direct link; reply hop limit reveals OS default
    # (Linux/macOS/FreeBSD=64, Windows=128)
    pkt2 = IPv6(dst=target_ip, hlim=1) / ICMPv6EchoRequest(id=2, seq=2)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    return results
