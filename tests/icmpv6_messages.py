from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6DestUnreach,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
    ICMPv6ParamProblem,
)
from scapy.packet import Raw
from scapy.sendrecv import sr1

DESCRIPTION = "Send valid ICMPv6 error messages and observe target handling"


def run(target_ip):
    results = []

    # Embed a fake "original packet" that the target supposedly sent
    fake_original = bytes(
        IPv6(src=target_ip, dst="2001:db8::dead") / ICMPv6EchoRequest(id=42, seq=42)
    )

    # Destination Unreachable — no route (code=0)
    pkt1 = IPv6(dst=target_ip) / ICMPv6DestUnreach(code=0) / Raw(load=fake_original)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Destination Unreachable — admin prohibited (code=1)
    pkt2 = IPv6(dst=target_ip) / ICMPv6DestUnreach(code=1) / Raw(load=fake_original)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # Destination Unreachable — port unreachable (code=4)
    pkt3 = IPv6(dst=target_ip) / ICMPv6DestUnreach(code=4) / Raw(load=fake_original)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # Packet Too Big — MTU=1280 (minimum valid)
    pkt4 = IPv6(dst=target_ip) / ICMPv6PacketTooBig(mtu=1280) / Raw(load=fake_original)
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # Packet Too Big — MTU=576 (below IPv6 minimum, should be rejected)
    pkt5 = IPv6(dst=target_ip) / ICMPv6PacketTooBig(mtu=576) / Raw(load=fake_original)
    reply5 = sr1(pkt5, timeout=5, verbose=0)
    results.append((pkt5, reply5))

    # Time Exceeded — hop limit exceeded (code=0)
    pkt6 = IPv6(dst=target_ip) / ICMPv6TimeExceeded(code=0) / Raw(load=fake_original)
    reply6 = sr1(pkt6, timeout=5, verbose=0)
    results.append((pkt6, reply6))

    # Time Exceeded — fragment reassembly timeout (code=1)
    pkt7 = IPv6(dst=target_ip) / ICMPv6TimeExceeded(code=1) / Raw(load=fake_original)
    reply7 = sr1(pkt7, timeout=5, verbose=0)
    results.append((pkt7, reply7))

    # Parameter Problem — erroneous header field (code=0, ptr=4)
    pkt8 = (
        IPv6(dst=target_ip)
        / ICMPv6ParamProblem(code=0, ptr=4)
        / Raw(load=fake_original)
    )
    reply8 = sr1(pkt8, timeout=5, verbose=0)
    results.append((pkt8, reply8))

    return results
