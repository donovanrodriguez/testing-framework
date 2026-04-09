import time

from scapy.layers.inet6 import (
    IPv6,
    UDP,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.dhcp6 import (
    DHCP6_Solicit,
    DHCP6_Advertise,
    DHCP6_Request,
    DHCP6_Reply,
    DHCP6_InfoRequest,
    DHCP6OptClientId,
    DHCP6OptServerId,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DUID_LLT,
)
from scapy.layers.l2 import get_if_hwaddr
from scapy.sendrecv import send, AsyncSniffer
from scapy.config import conf

DESCRIPTION = "Test DHCPv6 stateful and stateless client behavior"

PREFIX = "fd00:db8:1::"
OFFERED_ADDR = "fd00:db8:1::ff"


def run(target_ip):
    results = []
    my_mac = get_if_hwaddr(str(conf.iface))
    router_ll = "fe80::bad:cafe"
    server_duid = DUID_LLT(hwtype=1, time=int(time.time()), lladdr=my_mac)

    def make_ra(m_flag, o_flag, a_flag):
        return (
            IPv6(src=router_ll, dst="ff02::1", hlim=255)
            / ICMPv6ND_RA(M=m_flag, O=o_flag, routerlifetime=1800, chlim=64)
            / ICMPv6NDOptPrefixInfo(
                prefixlen=64,
                L=1,
                A=a_flag,
                validlifetime=3600,
                preferredlifetime=1800,
                prefix=PREFIX,
            )
            / ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
        )

    # Test 1: Stateful DHCPv6 — RA with M=1 should trigger a Solicit
    ra_stateful = make_ra(1, 0, 0)
    sniffer = AsyncSniffer(filter="udp port 547", timeout=10, count=1)
    sniffer.start()
    time.sleep(0.5)
    send(ra_stateful, verbose=0)
    sniffer.join()

    solicit = None
    if sniffer.results:
        for pkt in sniffer.results:
            if pkt.haslayer(DHCP6_Solicit):
                solicit = pkt
                break
    results.append((ra_stateful, solicit))

    # Test 2: Full 4-message exchange — respond to Solicit with Advertise,
    # expect Request, then complete with Reply
    if solicit and solicit.haslayer(DHCP6_Solicit):
        client_id = solicit[DHCP6OptClientId]
        trid = solicit[DHCP6_Solicit].trid

        advertise = (
            IPv6(src=router_ll, dst=solicit[IPv6].src)
            / UDP(sport=547, dport=546)
            / DHCP6_Advertise(trid=trid)
            / DHCP6OptServerId(duid=server_duid)
            / client_id
            / DHCP6OptIA_NA(
                iaid=1,
                T1=300,
                T2=480,
                ianaopts=[DHCP6OptIAAddress(
                    addr=OFFERED_ADDR, preflft=1800, validlft=3600,
                )]
            )
        )

        sniffer2 = AsyncSniffer(filter="udp port 547", timeout=10, count=1)
        sniffer2.start()
        time.sleep(0.5)
        send(advertise, verbose=0)
        sniffer2.join()

        request = None
        if sniffer2.results:
            for pkt in sniffer2.results:
                if pkt.haslayer(DHCP6_Request):
                    request = pkt
                    break
        results.append((advertise, request))

        if request and request.haslayer(DHCP6_Request):
            req_trid = request[DHCP6_Request].trid
            reply = (
                IPv6(src=router_ll, dst=request[IPv6].src)
                / UDP(sport=547, dport=546)
                / DHCP6_Reply(trid=req_trid)
                / DHCP6OptServerId(duid=server_duid)
                / request[DHCP6OptClientId]
                / DHCP6OptIA_NA(
                    iaid=1,
                    T1=300,
                    T2=480,
                    ianaopts=[DHCP6OptIAAddress(
                        addr=OFFERED_ADDR, preflft=1800, validlft=3600,
                    )]
                )
            )
            send(reply, verbose=0)
            results.append((reply, None))

    # Test 3: Stateless DHCPv6 — RA with O=1 should trigger Information-Request
    ra_stateless = make_ra(0, 1, 1)
    sniffer3 = AsyncSniffer(filter="udp port 547", timeout=10, count=1)
    sniffer3.start()
    time.sleep(0.5)
    send(ra_stateless, verbose=0)
    sniffer3.join()

    info_req = None
    if sniffer3.results:
        for pkt in sniffer3.results:
            if pkt.haslayer(DHCP6_InfoRequest):
                info_req = pkt
                break
    results.append((ra_stateless, info_req))

    return results
