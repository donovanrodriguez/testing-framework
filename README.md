# IPv6 Testing Framework

A CLI tool for testing OS-specific IPv6 implementations using Scapy for packet crafting and pcap generation.

## Project Structure

```
testing-framework/
├── main.py              # CLI entry point
├── tests/
│   ├── __init__.py      # Test registry and discovery
│   └── icmpv6_echo.py   # ICMPv6 Echo Request test
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

| Test Name      | Description                                        |
|----------------|----------------------------------------------------|
| icmpv6_echo    | Send an ICMPv6 Echo Request and capture the reply  |

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
