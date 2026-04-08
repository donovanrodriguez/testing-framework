from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_Redirect,
    ICMPv6NDOptDstLLAddr,
    ICMPv6EchoRequest,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import sr1
from scapy.config import conf

DESCRIPTION = "Send NDP Redirect messages to observe acceptance and validation behavior"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))

    fake_router_ll = "fe80::1"
    better_nexthop = "fe80::2"
    some_destination = "2001:db8::100"

    # Valid-looking redirect (from "router" link-local, hlim=255)
    pkt1 = (
        IPv6(src=fake_router_ll, dst=target_ip, hlim=255)
        / ICMPv6ND_Redirect(tgt=better_nexthop, dst=some_destination)
        / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
    )
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # Redirect with hlim != 255 (MUST be discarded per RFC 4861)
    pkt2 = (
        IPv6(src=fake_router_ll, dst=target_ip, hlim=64)
        / ICMPv6ND_Redirect(tgt=better_nexthop, dst=some_destination)
        / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
    )
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # Redirect from non-link-local source (MUST be discarded)
    pkt3 = (
        IPv6(src="2001:db8::1", dst=target_ip, hlim=255)
        / ICMPv6ND_Redirect(tgt=better_nexthop, dst=some_destination)
        / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
    )
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # On-link redirect (target == destination)
    pkt4 = (
        IPv6(src=fake_router_ll, dst=target_ip, hlim=255)
        / ICMPv6ND_Redirect(tgt=some_destination, dst=some_destination)
        / ICMPv6NDOptDstLLAddr(lladdr=my_mac)
    )
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # Verification ping after redirects
    verify = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=99, seq=99)
    reply_verify = sr1(verify, timeout=5, verbose=0)
    results.append((verify, reply_verify))

    return results
