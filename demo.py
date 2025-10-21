#!/usr/bin/env python3
"""
Demo script showing example output of the network scanner.
This doesn't require root privileges or actual network scanning.
"""

from tabulate import tabulate


def demo_output():
    """Display example output that the network scanner would produce."""
    
    print("=" * 70)
    print("Network Inventory Scanner - Demo Output")
    print("=" * 70)
    print()
    print("Scanning network: 192.168.1.0/24")
    print("This may take a moment...")
    print()
    
    # Example devices that might be found on a network
    devices = [
        {
            'mac': '00:1a:2b:3c:4d:5e',
            'ip': '192.168.1.1',
            'hostname': 'router.home',
            'vendor': 'Unknown'
        },
        {
            'mac': 'a4:5e:60:c2:8f:3a',
            'ip': '192.168.1.10',
            'hostname': 'laptop-work',
            'vendor': 'Unknown'
        },
        {
            'mac': 'dc:a6:32:12:34:56',
            'ip': '192.168.1.15',
            'hostname': 'smartphone',
            'vendor': 'Unknown'
        },
        {
            'mac': '48:d2:24:aa:bb:cc',
            'ip': '192.168.1.25',
            'hostname': 'smart-tv',
            'vendor': 'Unknown'
        },
        {
            'mac': 'b8:27:eb:dd:ee:ff',
            'ip': '192.168.1.50',
            'hostname': 'raspberry-pi',
            'vendor': 'Unknown'
        },
        {
            'mac': 'f0:18:98:11:22:33',
            'ip': '192.168.1.75',
            'hostname': 'N/A',
            'vendor': 'Unknown'
        },
        {
            'mac': '2c:f0:5d:44:55:66',
            'ip': '192.168.1.100',
            'hostname': 'desktop-gaming',
            'vendor': 'Unknown'
        },
    ]
    
    # Format as table
    table_data = []
    for device in devices:
        table_data.append([
            device['mac'],
            device['ip'],
            device['hostname'],
            device['vendor']
        ])
    
    headers = ['MAC Address', 'IPv4 Address', 'Hostname', 'Vendor']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal devices found: {len(devices)}")
    print()
    print("=" * 70)
    print("Note: This is example output demonstrating the scanner's format.")
    print("Actual results will vary based on devices present on your network.")
    print("Run 'sudo python network_scanner.py' to scan your actual network.")
    print("=" * 70)


if __name__ == "__main__":
    demo_output()
