import time

from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6ND_NS,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import send, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Send RA with SLAAC prefix and observe DAD behavior from target"

PREFIX = "fd00:db8:1::"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))
    router_ll = "fe80::bad:cafe"

    def make_ra(prefix, a_flag=1, valid=3600, preferred=1800):
        return (
            IPv6(src=router_ll, dst="ff02::1", hlim=255)
            / ICMPv6ND_RA(M=0, O=0, routerlifetime=1800, chlim=64)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                L=1,
                A=a_flag,
                validlifetime=valid,
                preferredlifetime=preferred,
                prefix=prefix,
            )
            / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )

    # Test 1: RA with A=1 — target should generate a SLAAC address and perform DAD
    # DAD NS packets have src=:: and target=the new address
    ra = make_ra(PREFIX)
    sniffer = AsyncSniffer(
        filter="icmp6 and ip6[40] == 135",
        timeout=10,
    )
    sniffer.start()
    time.sleep(0.5)
    send(ra, verbose=0)
    sniffer.join()

    dad_packets = [p for p in sniffer.results if p.haslayer(ICMPv6ND_NS) and p[IPv6].src == "::"]
    if dad_packets:
        for dad in dad_packets:
            results.append((ra, dad))
    else:
        results.append((ra, None))

    # Test 2: RA with A=0 — target should NOT generate a SLAAC address
    ra_no_auto = make_ra(PREFIX, a_flag=0)
    sniffer2 = AsyncSniffer(
        filter="icmp6 and ip6[40] == 135",
        timeout=10,
    )
    sniffer2.start()
    time.sleep(0.5)
    send(ra_no_auto, verbose=0)
    sniffer2.join()

    dad_packets2 = [p for p in sniffer2.results if p.haslayer(ICMPv6ND_NS) and p[IPv6].src == "::"]
    if dad_packets2:
        for dad in dad_packets2:
            results.append((ra_no_auto, dad))
    else:
        results.append((ra_no_auto, None))

    # Cleanup: withdraw the prefix
    ra_withdraw = make_ra(PREFIX, valid=0, preferred=0)
    send(ra_withdraw, verbose=0)
    results.append((ra_withdraw, None))

    return results
