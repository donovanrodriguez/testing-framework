from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import sr1
from scapy.config import conf

DESCRIPTION = "Send Router Advertisements with various M/O flag combinations"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))
    router_ll = "fe80::bad:cafe"
    prefix = "2001:db8:face::"

    def make_ra(m_flag, o_flag, a_flag, hlim=255, lifetime=1800):
        return (
            IPv6(src=router_ll, dst=target_ip, hlim=hlim)
            / ICMPv6ND_RA(M=m_flag, O=o_flag, routerlifetime=lifetime, chlim=64)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                L=1,
                A=a_flag,
                validlifetime=3600,
                preferredlifetime=1800,
                prefix=prefix,
            )
            / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )

    # M=0, O=0, A=1: SLAAC only
    pkt1 = make_ra(0, 0, 1)
    reply1 = sr1(pkt1, timeout=5, verbose=0)
    results.append((pkt1, reply1))

    # M=1, O=0, A=0: managed address config via DHCPv6
    pkt2 = make_ra(1, 0, 0)
    reply2 = sr1(pkt2, timeout=5, verbose=0)
    results.append((pkt2, reply2))

    # M=0, O=1, A=1: SLAAC for addresses, DHCPv6 for other info
    pkt3 = make_ra(0, 1, 1)
    reply3 = sr1(pkt3, timeout=5, verbose=0)
    results.append((pkt3, reply3))

    # M=1, O=1, A=0: full DHCPv6
    pkt4 = make_ra(1, 1, 0)
    reply4 = sr1(pkt4, timeout=5, verbose=0)
    results.append((pkt4, reply4))

    # RA with hlim != 255 (MUST be discarded)
    pkt5 = make_ra(0, 0, 1, hlim=64)
    reply5 = sr1(pkt5, timeout=5, verbose=0)
    results.append((pkt5, reply5))

    # RA with routerlifetime=0 (cease being default router)
    pkt6 = make_ra(0, 0, 1, lifetime=0)
    reply6 = sr1(pkt6, timeout=5, verbose=0)
    results.append((pkt6, reply6))

    return results
