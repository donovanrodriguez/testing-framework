#!/usr/bin/env python3
"""
Deprecated Fields Testing
=========================

Tests for using deprecated or obsolete protocol fields.
"""

from scapy.all import *
from network_tester import NetworkTester
import logging

logger = logging.getLogger(__name__)


class DeprecatedFieldsTester(NetworkTester):
    """Test network behavior with deprecated protocol fields."""
    
    def test_ip_loose_source_routing(self):
        """Test with IP Loose Source Routing (deprecated/security risk)."""
        test_name = "IP Loose Source Routing"
        try:
            # Loose Source Routing option (Type 131)
            # This is deprecated due to security concerns
            packet = IP(
                dst=self.target_ip,
                options=[IPOption_LSRR(routers=["8.8.8.8", self.target_ip])]
            ) / ICMP()
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                self.log_result(test_name, True, "Accepted packet with LSRR option")
            else:
                self.log_result(test_name, True, "No response (LSRR may be filtered)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_ip_strict_source_routing(self):
        """Test with IP Strict Source Routing (deprecated/security risk)."""
        test_name = "IP Strict Source Routing"
        try:
            # Strict Source Routing option (Type 137)
            packet = IP(
                dst=self.target_ip,
                options=[IPOption_SSRR(routers=["8.8.8.8", self.target_ip])]
            ) / ICMP()
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                self.log_result(test_name, True, "Accepted packet with SSRR option")
            else:
                self.log_result(test_name, True, "No response (SSRR may be filtered)")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_ip_record_route(self):
        """Test with IP Record Route option (rarely used)."""
        test_name = "IP Record Route"
        try:
            # Record Route option (Type 7)
            packet = IP(
                dst=self.target_ip,
                options=[IPOption_RR()]
            ) / ICMP()
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                if response.haslayer(IP) and response[IP].options:
                    self.log_result(test_name, True, 
                                  f"Received response with options: {response[IP].options}")
                else:
                    self.log_result(test_name, True, "Received response (no route recorded)")
            else:
                self.log_result(test_name, True, "No response")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_tcp_echo_option(self):
        """Test with TCP Echo option (obsolete, RFC 1072)."""
        test_name = "TCP Echo Option"
        try:
            # TCP Echo option was defined in RFC 1072 but is now obsolete
            # Option Kind: 6, Option Length: 6
            tcp_options = [('EOL', None)]  # Most implementations ignore unknown options
            
            packet = IP(dst=self.target_ip) / TCP(
                dport=self.target_port,
                flags="S",
                options=tcp_options
            )
            
            response = self.send_packet(packet, timeout=2)
            
            if response and response.haslayer(TCP):
                self.log_result(test_name, True, 
                              f"Received TCP response with flags: {response[TCP].flags}")
            else:
                self.log_result(test_name, True, "No response")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_ip_security_option(self):
        """Test with IP Security option (deprecated)."""
        test_name = "IP Security Option"
        try:
            # IP Security option (Type 130) - from RFC 791, deprecated
            # Most modern systems ignore this
            packet = IP(
                dst=self.target_ip,
                options=[IPOption(copy_flag=1, optclass=0, option=2)]
            ) / ICMP()
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                self.log_result(test_name, True, "Accepted packet with Security option")
            else:
                self.log_result(test_name, True, "No response")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_ip_timestamp_option(self):
        """Test with IP Timestamp option (rarely used today)."""
        test_name = "IP Timestamp Option"
        try:
            # Timestamp option (Type 68)
            packet = IP(
                dst=self.target_ip,
                options=[IPOption_Timestamp()]
            ) / ICMP()
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                self.log_result(test_name, True, "Received response to timestamped packet")
            else:
                self.log_result(test_name, True, "No response")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def test_ipv4_with_ipv6_extension_headers(self):
        """Test mixing IPv4 with concepts from IPv6."""
        test_name = "IPv4/IPv6 Confusion"
        try:
            # Try to send an IPv4 packet but with excessive options
            # to simulate confusion attacks
            packet = IP(
                dst=self.target_ip,
                options=[IPOption_NOP(), IPOption_NOP(), IPOption_NOP()]
            ) / TCP(
                dport=self.target_port,
                flags="S"
            )
            
            response = self.send_packet(packet, timeout=2)
            
            if response:
                self.log_result(test_name, True, "Handled IPv4 with multiple NOPs")
            else:
                self.log_result(test_name, True, "No response")
                
        except Exception as e:
            self.log_result(test_name, False, f"Error: {e}")
            
    def run_all_tests(self):
        """Run all deprecated fields tests."""
        logger.info(f"Starting deprecated fields tests against {self.target_ip}:{self.target_port}")
        
        self.test_ip_loose_source_routing()
        self.test_ip_strict_source_routing()
        self.test_ip_record_route()
        self.test_tcp_echo_option()
        self.test_ip_security_option()
        self.test_ip_timestamp_option()
        self.test_ipv4_with_ipv6_extension_headers()
        
        self.print_summary()
        return self.get_results()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python deprecated_fields.py <target_ip> [target_port]")
        print("Example: python deprecated_fields.py 127.0.0.1 80")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    tester = DeprecatedFieldsTester(target_ip, target_port)
    tester.run_all_tests()
