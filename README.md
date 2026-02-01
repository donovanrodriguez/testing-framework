# testing-framework

A simple Python framework for network testing, including malformed packet testing and deprecated protocol field testing.

## Features

- **Malformed Packet Testing**: Send and test responses to malformed network packets
  - Invalid TCP flags
  - Zero-length payloads
  - Invalid IP versions
  - Invalid checksums
  - Overlapping fragments
  - Tiny TTL values

- **Deprecated Fields Testing**: Test responses to deprecated or obsolete protocol fields
  - IP Loose Source Routing
  - IP Strict Source Routing
  - IP Record Route
  - TCP Echo option (RFC 1072)
  - IP Security option
  - IP Timestamp option
  - IPv4/IPv6 confusion testing

## Installation

1. Clone the repository:
```bash
git clone https://github.com/donovanrodriguez/testing-framework.git
cd testing-framework
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

**Note**: These scripts require root/administrator privileges to send raw packets.

### Quick Start

Run the example test script:
```bash
sudo python example_test.py <target_ip> [target_port]
```

Example:
```bash
sudo python example_test.py 127.0.0.1 80
```

### Individual Test Modules

#### Malformed Packet Tests
```bash
sudo python malformed_packets.py <target_ip> [target_port]
```

Example:
```bash
sudo python malformed_packets.py 192.168.1.1 443
```

#### Deprecated Fields Tests
```bash
sudo python deprecated_fields.py <target_ip> [target_port]
```

Example:
```bash
sudo python deprecated_fields.py 10.0.0.1 8080
```

### Using as a Library

You can also import and use the testing classes in your own scripts:

```python
from malformed_packets import MalformedPacketTester
from deprecated_fields import DeprecatedFieldsTester

# Test malformed packets
tester = MalformedPacketTester("192.168.1.1", 80)
tester.run_all_tests()
results = tester.get_results()

# Test deprecated fields
dep_tester = DeprecatedFieldsTester("192.168.1.1", 80)
dep_tester.run_all_tests()
```

## Project Structure

```
testing-framework/
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── network_tester.py        # Base network testing class
├── malformed_packets.py     # Malformed packet tests
├── deprecated_fields.py     # Deprecated fields tests
└── example_test.py          # Example usage script
```

## Requirements

- Python 3.6+
- Scapy 2.5.0+
- Root/Administrator privileges (for raw packet manipulation)

## Security Notice

⚠️ **Warning**: This framework is designed for testing purposes only. Use it responsibly and only on networks you own or have explicit permission to test. Unauthorized network testing may be illegal.

## License

This project is provided as-is for educational and testing purposes.