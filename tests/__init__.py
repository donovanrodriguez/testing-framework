from tests import icmpv6_echo
from tests import malformed_version
from tests import malformed_payload_length
from tests import malformed_hop_limit
from tests import fragmentation_overlap
from tests import fragmentation_tiny
from tests import fragmentation_reassembly
from tests import invalid_checksum
from tests import reserved_fields
from tests import ndp_solicitation
from tests import ndp_dad
from tests import ndp_redirect
from tests import ra_flags
from tests import ra_competing
from tests import icmpv6_messages
from tests import icmpv6_invalid
from tests import ext_header_ordering
from tests import ext_header_unknown
from tests import ext_header_chain
from tests import flow_label_entropy
from tests import slaac_autoconf
from tests import dhcpv6_exchange

TEST_REGISTRY = {
    "icmpv6_echo": icmpv6_echo,
    "malformed_version": malformed_version,
    "malformed_payload_length": malformed_payload_length,
    "malformed_hop_limit": malformed_hop_limit,
    "fragmentation_overlap": fragmentation_overlap,
    "fragmentation_tiny": fragmentation_tiny,
    "fragmentation_reassembly": fragmentation_reassembly,
    "invalid_checksum": invalid_checksum,
    "reserved_fields": reserved_fields,
    "ndp_solicitation": ndp_solicitation,
    "ndp_dad": ndp_dad,
    "ndp_redirect": ndp_redirect,
    "ra_flags": ra_flags,
    "ra_competing": ra_competing,
    "icmpv6_messages": icmpv6_messages,
    "icmpv6_invalid": icmpv6_invalid,
    "ext_header_ordering": ext_header_ordering,
    "ext_header_unknown": ext_header_unknown,
    "ext_header_chain": ext_header_chain,
    "flow_label_entropy": flow_label_entropy,
    "slaac_autoconf": slaac_autoconf,
    "dhcpv6_exchange": dhcpv6_exchange,
}


def list_tests():
    return sorted(TEST_REGISTRY.keys())


def get_test(name):
    return TEST_REGISTRY.get(name)
