from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6EchoRequest,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import sr1, send
from scapy.config import conf

DESCRIPTION = "Send competing RAs from multiple simulated routers to observe preference handling"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))

    def make_ra(router_ll, prefix, prf, lifetime=1800):
        return (
            IPv6(src=router_ll, dst="ff02::1", hlim=255)
            / ICMPv6ND_RA(M=0, O=0, prf=prf, routerlifetime=lifetime, chlim=64)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                L=1,
                A=1,
                validlifetime=3600,
                preferredlifetime=1800,
                prefix=prefix,
            )
            / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )

    # Router A: high preference (prf=1)
    ra_a = make_ra("fe80::a", "2001:db8:a::", prf=1)
    send(ra_a, verbose=0)
    results.append((ra_a, None))

    # Router B: low preference (prf=3)
    ra_b = make_ra("fe80::b", "2001:db8:b::", prf=3)
    send(ra_b, verbose=0)
    results.append((ra_b, None))

    # Router C: medium/default preference (prf=0)
    ra_c = make_ra("fe80::c", "2001:db8:c::", prf=0)
    send(ra_c, verbose=0)
    results.append((ra_c, None))

    # Ping to observe which source address / route the target prefers
    verify1 = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=13, seq=1)
    reply1 = sr1(verify1, timeout=5, verbose=0)
    results.append((verify1, reply1))

    # De-register Router A (lifetime=0)
    ra_a_dereg = make_ra("fe80::a", "2001:db8:a::", prf=1, lifetime=0)
    send(ra_a_dereg, verbose=0)
    results.append((ra_a_dereg, None))

    # Verify fallback behavior after preferred router is removed
    verify2 = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=13, seq=2)
    reply2 = sr1(verify2, timeout=5, verbose=0)
    results.append((verify2, reply2))

    # Cleanup: de-register remaining routers
    for router_ll, prefix, prf in [
        ("fe80::b", "2001:db8:b::", 3),
        ("fe80::c", "2001:db8:c::", 0),
    ]:
        cleanup = make_ra(router_ll, prefix, prf, lifetime=0)
        send(cleanup, verbose=0)
        results.append((cleanup, None))

    return results
