# IPv6 Testing Framework

A CLI tool for testing OS-specific IPv6 implementations using Scapy for packet crafting and pcap generation.

## Project Structure

```
testing-framework/
├── main.py              # CLI entry point
├── tests/
│   ├── __init__.py      # Test registry and discovery
│   └── *.py             # Individual test modules
├── output/              # Per-system pcap output directories
└── requirements.txt     # Python dependencies
```

## Setup

```bash
python -m venv .
source bin/activate
pip install -r requirements.txt
```

## Usage

```
python main.py <target_ip> <test_name>
```

### List available tests

```
python main.py --list
```

### Run a test

```
python main.py ::1 icmpv6_echo
python main.py 2001:db8::1 icmpv6_echo
```

### Specify output directory for pcap files

```
python main.py --output-dir ./pcaps ::1 icmpv6_echo
```

## Pcap Output

Pcap files are written using the naming convention:

```
<target_ip_with_hyphens>_<test_name>.pcap
```

For IPv6 addresses, colons are replaced with hyphens. For example, targeting `2001:db8::1` with `icmpv6_echo` produces:

```
2001-db8--1_icmpv6_echo.pcap
```

## Available Tests

### Malformed Packet Handling

| Test Name | Description |
|---|---|
| malformed_version | Send IPv6 packets with invalid version fields (0, 4, 15) |
| malformed_payload_length | Send IPv6 packets with incorrect payload length values (zero, short, long) |
| malformed_hop_limit | Send ICMPv6 Echo Requests with edge-case hop limits (0, 1) |
| invalid_checksum | Send ICMPv6 and UDP packets with corrupted checksums |
| reserved_fields | Send packets with non-zero reserved bits and deprecated next-header values |
| fragmentation_overlap | Send overlapping IPv6 fragments and observe reassembly or rejection |
| fragmentation_tiny | Send tiny and atomic IPv6 fragments to test minimum size enforcement |
| fragmentation_reassembly | Test fragment reassembly with out-of-order and missing fragments |

### Supporting Protocols

| Test Name | Description |
|---|---|
| icmpv6_echo | Send an ICMPv6 Echo Request and capture the reply |
| icmpv6_messages | Send valid ICMPv6 error messages and observe target handling |
| icmpv6_invalid | Send ICMPv6 messages with unknown types, invalid codes, and malformed bodies |
| ndp_solicitation | Send Neighbor Solicitations and analyze NA responses |
| ndp_dad | Send DAD-style Neighbor Solicitations (src=::) to test address defense |
| ndp_redirect | Send NDP Redirect messages to observe acceptance and validation behavior |
| ra_flags | Send Router Advertisements with various M/O flag combinations |
| dhcpv6_exchange | Test DHCPv6 stateful and stateless client behavior |

### Core Protocol Mechanics

| Test Name | Description |
|---|---|
| ext_header_ordering | Send packets with extension headers in correct and incorrect RFC 8200 order |
| ext_header_unknown | Send packets with unknown extension header types and HBH option action bits |
| ext_header_chain | Send packets with long chains of extension headers to test parsing limits |
| flow_label_entropy | Send multiple Echo Requests and analyze flow label patterns in replies |

## Adding New Tests

1. Create a new module in `tests/` (e.g. `tests/neighbor_discovery.py`)
2. Define a `DESCRIPTION` string and a `run(target_ip)` function
3. `run()` must return a list of `(sent_packet, received_packet_or_None)` tuples
4. Register the module in `tests/__init__.py` by importing it and adding it to `TEST_REGISTRY`

Example skeleton:

```python
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr1

DESCRIPTION = "Short description of this test"


def run(target_ip):
    pkt = IPv6(dst=target_ip) / ...
    reply = sr1(pkt, timeout=5, verbose=0)
    return [(pkt, reply)]
```
