#!/usr/bin/env python3
"""Example usage of the network inventory scanner."""

from network_inventory.scanner import NetworkScanner


def main():
    """Demonstrate basic usage of the NetworkScanner."""
    # Create a scanner for a specific network range
    scanner = NetworkScanner(network_range="192.168.1.0/24")
    
    print(f"Scanning network: {scanner.network_range}")
    
    # Perform the scan
    devices = scanner.scan()
    
    if devices:
        print(f"Found {len(devices)} device(s):")
        for device in devices:
            print(f"  {device}")
    else:
        print("No devices found (implementation pending)")


if __name__ == "__main__":
    main()
