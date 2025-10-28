#!/usr/bin/env python3
"""
Network Inventory Scanner
Scans the local network and displays device information in a table.
"""

from asyncio.log import logger
import json
from linecache import cache
import logging
from math import log
import re
import requests
import sys
import socket
import ipaddress
import argparse
from scapy.all import ARP, Ether, srp, conf
from tabulate import tabulate
from time import sleep

# import the caching helpers
from mac_vendor_cache import (
    add_vendor_to_cache,
    get_vendor_from_cache,
    check_vendor_cache,
    initialize_mac_vendor_cache,
    write_vendor_cache_to_file,
)


vendor_cache = {}

def init_logger():
    """Initialize logger for the application."""
    #import logging
    #global logger
    logger = logging.getLogger("network_scanner")
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    fh = logging.FileHandler("network_scanner.log")
    fh.setLevel(logging.DEBUG)  
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

logger = init_logger()

def add_vendor_to_cache(mac_address, vendor_name):
    """Add vendor name to cache for a given MAC address."""
    logger.debug(f"+ + + Caching vendor for {mac_address}: {vendor_name}")    
    vendor_cache[mac_address] = vendor_name
def get_vendor_from_cache(mac_address):
    """Retrieve vendor name from cache for a given MAC address."""
    logger.debug(f"- - - Retrieving vendor from cache for {mac_address}")
    return vendor_cache.get(mac_address)+" (cached)"

def check_vendor_cache(mac_address):
    """Check if vendor name is in cache for a given MAC address."""
    logger.debug(f". . . Checking vendor cache for {mac_address}")
    return mac_address in vendor_cache

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

    if check_vendor_cache(mac_address):
        return get_vendor_from_cache(mac_address)
    logger.debug(f"Vendor not found in cache for {mac_address}, querying API...")

    url = "https://api.macvendors.com/"
    logger.debug(f"Fetching vendor for MAC: {mac_address}")
    # Use get method to fetch details
    response = requests.get(url+mac_address)
    if response.status_code == 404:
        return f"Unknown Vendor {mac_address}"
    elif response.status_code != 200:
        return f"Invalid MAC {mac_address}, Status Code: {response.status_code}"
    vendor = response.content.decode()
    add_vendor_to_cache(mac_address, vendor)
    return vendor

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
    logger.debug(f">>> Received {len(answered_list)} responses")
    devices = []
    for sent, received in answered_list:
        device_info = {
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': get_hostname(received.psrc),
            'vendor': get_mac_details(received.hwsrc)
        }
        devices.append(device_info)
        sleep(1.0)  # Add a small delay to avoid overwhelming the API
    

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
    for i, device in enumerate(devices):
        table_data.append([
            i,
            device['mac'],
            device['ip'],
            device['hostname'],
            device['vendor']
        ])
    
    # Print table
    headers = ['#', 'MAC Address', 'IPv4 Address', 'Hostname', 'Vendor']
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    print(f"\nTotal devices found: {len(devices)}")
cache_path = "mac_vendor_cache.json"

def initialize_mac_vendor_cache():
    """Initialize the MAC vendor cache from local database."""
    try:
        breakpoint()
        with open(cache_path, "r", encoding="utf-8") as f:
            vendor_cache = json.load(f)
    except Exception as e:
        logger.error(f"Could not load MAC vendor cache from file. {e}")
        pass

def write_vendor_cache_to_file():
    """Write the MAC vendor cache to a local file."""
    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(vendor_cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

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
    initialize_mac_vendor_cache()
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
        logger.error(f"Error: Invalid network range '{network_range}': {e}")
        sys.exit(1)
    
    # Check if running with appropriate privileges
    try:
        # Disable verbose output from Scapy
        conf.verb = 0
        
        # Scan the network
        devices = scan_network(network_range)
        write_vendor_cache_to_file()
        # Print results
        print_results(devices)
        
    except PermissionError:
        logger.error("Error: Permission denied. This script requires root/administrator privileges.")
        logger.error("On Linux/Mac: Run with 'sudo python network_scanner.py'")
        logger.error("On Windows: Run terminal as Administrator")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
