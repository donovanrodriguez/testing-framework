#!/usr/bin/env python3
"""
Network Testing Framework
=========================

A simple framework for testing network behavior with malformed packets
and deprecated protocol fields.
"""

from scapy.all import *
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkTester:
    """Base class for network testing functionality."""
    
    def __init__(self, target_ip: str, target_port: int = 80):
        """
        Initialize the network tester.
        
        Args:
            target_ip: Target IP address to test
            target_port: Target port number (default: 80)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.results = []
        
    def log_result(self, test_name: str, success: bool, details: str = ""):
        """Log a test result."""
        result = {
            'test_name': test_name,
            'success': success,
            'details': details,
            'target': f"{self.target_ip}:{self.target_port}"
        }
        self.results.append(result)
        logger.info(f"Test: {test_name} - {'PASS' if success else 'FAIL'} - {details}")
        
    def send_packet(self, packet, timeout: int = 2) -> Optional[Any]:
        """
        Send a packet and wait for response.
        
        Args:
            packet: The packet to send
            timeout: Response timeout in seconds
            
        Returns:
            Response packet or None
        """
        try:
            response = sr1(packet, timeout=timeout, verbose=0)
            return response
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
            
    def get_results(self) -> list:
        """Return all test results."""
        return self.results
        
    def print_summary(self):
        """Print a summary of all test results."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r['success'])
        failed = total - passed
        
        print("\n" + "="*50)
        print("TEST SUMMARY")
        print("="*50)
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {(passed/total*100) if total > 0 else 0:.1f}%")
        print("="*50)
