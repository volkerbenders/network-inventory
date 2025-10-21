#!/usr/bin/env python3
"""
Network Inventory Scanner
Scans the local network and displays device information in a table.
"""

import requests
import sys
import socket
import ipaddress
import argparse
from scapy.all import ARP, Ether, srp, conf
from tabulate import tabulate


def get_mac_details(mac_address):
    """
    Get the vendor name for a MAC address.
    Uses MacVendors API to determine the vendor of a network device.
    
    Args:
        mac_address: MAC address string
        
    Returns:
        Vendor name or 'Invalid MAC {mac_address}' else
    """
    
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"
    print(f"Fetching vendor for MAC: {mac_address}")
    # Use get method to fetch details
    response = requests.get(url+mac_address)
    if response.status_code != 200:
        return f"Invalid MAC {mac_address}"
    return response.content.decode()

def get_hostname(ip_address):
    """
    Try to resolve hostname from IP address.
    
    Args:
        ip_address: IP address string
        
    Returns:
        Hostname or 'N/A' if resolution fails
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A"


def scan_network(network_range):
    """
    Scan the local network for devices using ARP requests.
    
    Args:
        network_range: Network range in CIDR notation (e.g., '192.168.1.0/24')
        
    Returns:
        List of dictionaries containing device information
    """
    print(f"Scanning network: {network_range}")
    print("This may take a moment...\n")
    
    # Create ARP request packet
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet and receive responses
    # timeout=3, verbose=False to suppress output
    answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    
    devices = []
    for sent, received in answered_list:
        device_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc),
            'vendor': get_mac_details(received.hwsrc)
        }
        devices.append(device_info)
    
    return devices


def get_default_network_range():
    """
    Try to determine the default network range based on the local IP address.
    
    Returns:
        Network range in CIDR notation or None if unable to determine
    """
    try:
        # Get local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 subnet
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return None


def print_results(devices):
    """
    Print the scan results in a formatted table.
    
    Args:
        devices: List of device dictionaries
    """
    if not devices:
        print("No devices found on the network.")
        return
    
    # Prepare table data
    table_data = []
    for device in devices:
        table_data.append([
            device['mac'],
            device['ip'],
            device['hostname'],
            device['vendor']
        ])
    
    # Print table
    headers = ['MAC Address', 'IPv4 Address', 'Hostname', 'Vendor']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal devices found: {len(devices)}")


def main():
    """Main function to run the network scanner."""
    parser = argparse.ArgumentParser(
        description='Network Inventory Scanner - Scan local network for devices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py
  python network_scanner.py -n 192.168.1.0/24
  sudo python network_scanner.py -n 10.0.0.0/24

Note: This script may require root/administrator privileges to send ARP packets.
On Linux/Mac, run with 'sudo'. On Windows, run as Administrator.
        """
    )
    
    parser.add_argument(
        '-n', '--network',
        type=str,
        help='Network range in CIDR notation (e.g., 192.168.1.0/24)',
        default=None
    )
    
    args = parser.parse_args()
    
    # Determine network range
    network_range = args.network
    if not network_range:
        network_range = get_default_network_range()
        if not network_range:
            print("Error: Could not determine default network range.")
            print("Please specify the network range using -n option.")
            print("Example: python network_scanner.py -n 192.168.1.0/24")
            sys.exit(1)
    
    # Validate network range
    try:
        ipaddress.IPv4Network(network_range)
    except ValueError as e:
        print(f"Error: Invalid network range '{network_range}': {e}")
        sys.exit(1)
    
    # Check if running with appropriate privileges
    try:
        # Disable verbose output from Scapy
        conf.verb = 0
        
        # Scan the network
        devices = scan_network(network_range)
        
        # Print results
        print_results(devices)
        
    except PermissionError:
        print("Error: Permission denied. This script requires root/administrator privileges.")
        print("On Linux/Mac: Run with 'sudo python network_scanner.py'")
        print("On Windows: Run terminal as Administrator")
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
