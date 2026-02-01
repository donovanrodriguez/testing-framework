# TESTING FRAMEWORK FOR TESTING OS SPECIFIC IMPLEMENTATIONS IN IPV6

The testing environment will consist of an isolated IPv6 lab network using VMware Workstation. The test network will include: IPv6 subnets with configurable routers and various network topologies, target hosts running Windows 11, Windows Server, Fedora 43, macOS Tahoe, and FreeBSD 15.0, a monitoring station (Fedora 43 as well) running Wireshark, tcpdump, and python scripts using scapy to generate test traffic. Physical hosts will be introduced in validation phases to confirm VM-based findings translate to real hardware. 
The variable(s) I’m going to manipulate/modify is/are: 
Malformed Packet Variables:
* Packet structure
* Protocol field values
* Packet fragmentation anomalies
* Checksum validity and corruption scenarios
Supporting Protocol Variables:
* Router Advertisement messages
* Neighbor Discovery message types
* Address autoconfiguration methods
* ICMPv6 message types and parameters
Core Protocol Mechanics Variables:
* Extension headers
* Flow labels
* Hop limit
* Address types
