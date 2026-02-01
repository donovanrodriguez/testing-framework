from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1

DESCRIPTION = "Send an ICMPv6 Echo Request and capture the reply"


def run(target_ip):
    pkt = IPv6(dst=target_ip) / ICMPv6EchoRequest()
    reply = sr1(pkt, timeout=5, verbose=0)
    return [(pkt, reply)]
