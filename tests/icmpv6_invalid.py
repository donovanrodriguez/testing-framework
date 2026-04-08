import struct

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6DestUnreach,
    ICMPv6Unknown,
)
from scapy.packet import Raw
from scapy.sendrecv import sr1

DESCRIPTION = "Send ICMPv6 messages with unknown types, invalid codes, and malformed bodies"


def run(target_ip):
    results = []

    # Unknown informational type (type=200, range 128-255)
    pkt1 = IPv6(dst=target_ip) / ICMPv6Unknown(
        type=200, code=0, msgbody=b"\x00\x00\x00\x00"
    )
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Unknown error type (type=5, range 0-127)
    pkt2 = IPv6(dst=target_ip) / ICMPv6Unknown(
        type=5, code=0, msgbody=b"\x00\x00\x00\x00"
    )
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # Valid type with invalid code (Dest Unreachable code=255)
    fake_orig = bytes(
        IPv6(src=target_ip, dst="::1") / ICMPv6EchoRequest()
    )
    pkt3 = IPv6(dst=target_ip) / ICMPv6DestUnreach(code=255) / Raw(load=fake_orig)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # Echo Request with non-zero code (code should be 0)
    # ICMPv6EchoRequest doesn't expose code, so use ICMPv6Unknown
    echo_body = struct.pack("!HH", 4, 4) + b"\x00" * 4
    pkt4 = IPv6(dst=target_ip) / ICMPv6Unknown(type=128, code=1, msgbody=echo_body)
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # Truncated ICMPv6 (type + code only, no checksum or body)
    pkt5 = IPv6(dst=target_ip, nh=58, plen=2) / Raw(load=b"\x80\x00")
    reply5 = sr1(pkt5, timeout=5, verbose=0)
    results.append((pkt5, reply5))

    # Maximum type/code values (type=255, code=255)
    pkt6 = IPv6(dst=target_ip) / ICMPv6Unknown(
        type=255, code=255, msgbody=b"\x00\x00\x00\x00"
    )
    reply6 = sr1(pkt6, timeout=5, verbose=0)
    results.append((pkt6, reply6))

    return results
