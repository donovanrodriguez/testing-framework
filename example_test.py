#!/usr/bin/env python3
"""
Example Test Script
==================

Demonstrates how to use the network testing framework.
"""

from malformed_packets import MalformedPacketTester
from deprecated_fields import DeprecatedFieldsTester
import sys


def run_example_tests(target_ip: str = "127.0.0.1", target_port: int = 80):
    """
    Run example network tests.
    
    Args:
        target_ip: Target IP address to test
        target_port: Target port number
    """
    print(f"\n{'='*60}")
    print(f"Network Testing Framework - Example Tests")
    print(f"Target: {target_ip}:{target_port}")
    print(f"{'='*60}\n")
    
    # Test 1: Malformed Packets
    print("\n[1/2] Running Malformed Packet Tests...")
    print("-" * 60)
    malformed_tester = MalformedPacketTester(target_ip, target_port)
    malformed_tester.run_all_tests()
    
    # Test 2: Deprecated Fields
    print("\n[2/2] Running Deprecated Fields Tests...")
    print("-" * 60)
    deprecated_tester = DeprecatedFieldsTester(target_ip, target_port)
    deprecated_tester.run_all_tests()
    
    # Combined Summary
    print("\n" + "="*60)
    print("OVERALL SUMMARY")
    print("="*60)
    
    all_results = malformed_tester.get_results() + deprecated_tester.get_results()
    total = len(all_results)
    passed = sum(1 for r in all_results if r['success'])
    failed = total - passed
    
    print(f"Total Tests Run: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/total*100) if total > 0 else 0:.1f}%")
    print("="*60)
    
    return all_results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUsage: python example_test.py <target_ip> [target_port]")
        print("\nExamples:")
        print("  python example_test.py 127.0.0.1")
        print("  python example_test.py 192.168.1.1 8080")
        print("\nNote: This script requires root/administrator privileges to send raw packets.")
        print("      Run with: sudo python example_test.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    try:
        run_example_tests(target_ip, target_port)
    except PermissionError:
        print("\nError: This script requires root/administrator privileges.")
        print("Please run with: sudo python example_test.py <target_ip>")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError running tests: {e}")
        sys.exit(1)
