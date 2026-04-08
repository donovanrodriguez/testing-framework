from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, getmacbyip6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import srp1
from scapy.config import conf

DESCRIPTION = "Send IPv6 packets with invalid version fields (0, 4, 15)"


def run(target_ip):
    results = []
    target_mac = getmacbyip6(target_ip)

    for ver in [0, 4, 15]:
        # Build valid packet first so ICMPv6 checksum is computed correctly
        base = IPv6(dst=target_ip) / ICMPv6EchoRequest(id=ver, seq=ver)
        raw_bytes = bytearray(bytes(base))

        # Byte 0 top nibble is version — replace it
        raw_bytes[0] = (ver << 4) | (raw_bytes[0] & 0x0F)

        # L2 sending bypasses kernel version check on raw sockets
        l2_pkt = Ether(dst=target_mac, type=0x86DD) / Raw(load=bytes(raw_bytes))
        reply = srp1(l2_pkt, iface=str(conf.iface), timeout=5, verbose=0)
        results.append((l2_pkt, reply))

    return results
