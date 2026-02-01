#!/usr/bin/env python3
import argparse
import ipaddress
import os
import sys

from scapy.utils import wrpcap

import tests


def sanitize_ip(ip_str):
    return ip_str.replace(":", "-").replace(".", "-")


def build_pcap_path(output_dir, target_ip, test_name):
    filename = f"{sanitize_ip(target_ip)}_{test_name}.pcap"
    return os.path.join(output_dir, filename)


def main():
    parser = argparse.ArgumentParser(
        description="IPv6 Testing Framework — craft and send test packets, capture results to pcap"
    )
    parser.add_argument("target", nargs="?", help="Target IPv6 address")
    parser.add_argument("test", nargs="?", help="Name of the test to run")
    parser.add_argument(
        "--list", action="store_true", help="List available tests and exit"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to write pcap files (default: current directory)",
    )
    args = parser.parse_args()

    if args.list:
        print("Available tests:")
        for name in tests.list_tests():
            module = tests.get_test(name)
            desc = getattr(module, "DESCRIPTION", "")
            print(f"  {name:20s} {desc}")
        return 0

    if not args.target or not args.test:
        parser.error("target and test are required (or use --list)")

    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"Error: '{args.target}' is not a valid IP address", file=sys.stderr)
        return 1

    test_module = tests.get_test(args.test)
    if test_module is None:
        print(f"Error: unknown test '{args.test}'", file=sys.stderr)
        print(f"Run with --list to see available tests", file=sys.stderr)
        return 1

    print(f"Running test '{args.test}' against {args.target} ...")
    results = test_module.run(args.target)

    all_packets = []
    sent_count = 0
    recv_count = 0
    for sent, recv in results:
        if sent is not None:
            all_packets.append(sent)
            sent_count += 1
        if recv is not None:
            all_packets.append(recv)
            recv_count += 1

    pcap_path = build_pcap_path(args.output_dir, args.target, args.test)
    if all_packets:
        wrpcap(pcap_path, all_packets)
        print(f"Packets sent: {sent_count}, received: {recv_count}")
        print(f"Pcap written to: {pcap_path}")
    else:
        print("No packets were captured.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
