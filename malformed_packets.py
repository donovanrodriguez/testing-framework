#!/usr/bin/env python3
"""
Malformed Packet Testing
========================

Tests for sending malformed packets and analyzing responses.
"""

from scapy.all import *
from network_tester import NetworkTester
import logging

logger = logging.getLogger(__name__)


class MalformedPacketTester(NetworkTester):
    """Test network behavior with malformed packets."""
    
    def test_invalid_tcp_flags(self):
        """Test with invalid TCP flag combinations."""
        test_name = "Invalid TCP Flags"
        try:
            # Create a packet with all TCP flags set (invalid combination)
            packet = IP(dst=self.target_ip) / TCP(
                dport=self.target_port,
                flags="FSRPAUEC"  # All flags set
            )
            
            response = self.send_packet(packet)
            
            if response:
                if response.haslayer(TCP):
                    self.log_result(test_name, True, 
                                  f"Received response with flags: {response[TCP].flags}")
                else:
                    self.log_result(test_name, True, "Received non-TCP response")
            else:
                self.log_result(test_name, True, "No response (expected for malformed packet)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_zero_length_payload(self):
        """Test packet with zero-length payload."""
        test_name = "Zero Length Payload"
        try:
            packet = IP(dst=self.target_ip) / TCP(
                dport=self.target_port,
                flags="S"
            )
            
            response = self.send_packet(packet)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags & 0x12:  # SYN-ACK
                    self.log_result(test_name, True, "Received SYN-ACK")
                elif response[TCP].flags & 0x04:  # RST
                    self.log_result(test_name, True, "Received RST")
                else:
                    self.log_result(test_name, True, f"Received flags: {response[TCP].flags}")
            else:
                self.log_result(test_name, True, "No response received")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_invalid_ip_version(self):
        """Test with invalid IP version field."""
        test_name = "Invalid IP Version"
        try:
            # Manually craft a packet with wrong IP version
            packet = IP(dst=self.target_ip, version=3) / TCP(
                dport=self.target_port,
                flags="S"
            )
            
            response = self.send_packet(packet, timeout=1)
            
            if response:
                self.log_result(test_name, True, "Received response to invalid IP version")
            else:
                self.log_result(test_name, True, "No response (expected for invalid IP version)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_invalid_checksum(self):
        """Test packet with intentionally invalid checksum."""
        test_name = "Invalid Checksum"
        try:
            packet = IP(dst=self.target_ip) / TCP(
                dport=self.target_port,
                flags="S",
                chksum=0xFFFF  # Invalid checksum
            )
            
            response = self.send_packet(packet, timeout=1)
            
            if response:
                self.log_result(test_name, True, "Received response despite invalid checksum")
            else:
                self.log_result(test_name, True, "No response (checksum rejected)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_overlapping_fragments(self):
        """Test with overlapping IP fragments."""
        test_name = "Overlapping Fragments"
        try:
            # Create overlapping fragments
            packet = IP(dst=self.target_ip, flags="MF", frag=0) / TCP(
                dport=self.target_port,
                flags="S"
            ) / ("X" * 8)
            
            response = self.send_packet(packet, timeout=1)
            
            self.log_result(test_name, True, 
                          "Sent fragmented packet" + 
                          (" - received response" if response else " - no response"))
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_tiny_ttl(self):
        """Test packet with TTL=1 (should not reach remote targets)."""
        test_name = "Tiny TTL"
        try:
            packet = IP(dst=self.target_ip, ttl=1) / ICMP()
            
            response = self.send_packet(packet, timeout=1)
            
            if response and response.haslayer(ICMP):
                if response[ICMP].type == 11:  # Time exceeded
                    self.log_result(test_name, True, "Received Time Exceeded (expected)")
                else:
                    self.log_result(test_name, True, f"Received ICMP type: {response[ICMP].type}")
            else:
                self.log_result(test_name, True, "No response (expected for TTL=1)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def run_all_tests(self):
        """Run all malformed packet tests."""
        logger.info(f"Starting malformed packet tests against {self.target_ip}:{self.target_port}")
        
        self.test_invalid_tcp_flags()
        self.test_zero_length_payload()
        self.test_invalid_ip_version()
        self.test_invalid_checksum()
        self.test_overlapping_fragments()
        self.test_tiny_ttl()
        
        self.print_summary()
        return self.get_results()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python malformed_packets.py <target_ip> [target_port]")
        print("Example: python malformed_packets.py 127.0.0.1 80")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    tester = MalformedPacketTester(target_ip, target_port)
    tester.run_all_tests()
