from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.sendrecv import sr1

DESCRIPTION = "Send multiple Echo Requests and analyze flow label patterns in replies"


def run(target_ip):
    results = []

    # 20 sequential echo requests with fl=0 to observe reply flow label
    # generation patterns (per-OS fingerprint signal)
    for i in range(20):
        pkt = IPv6(dst=target_ip, fl=0) / ICMPv6EchoRequest(id=0x1337, seq=i + 1)
        reply = sr1(pkt, timeout=5, verbose=0)
        results.append((pkt, reply))

    # 5 requests with non-zero flow labels to test whether target echoes them
    for i in range(5):
        fl_val = 0x10000 + i
        pkt = IPv6(dst=target_ip, fl=fl_val) / ICMPv6EchoRequest(id=0x1338, seq=i + 1)
        reply = sr1(pkt, timeout=5, verbose=0)
        results.append((pkt, reply))

    return results
