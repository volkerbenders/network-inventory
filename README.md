# Network Inventory Scanner

A Python client application that scans your local network and displays detailed information about discovered devices.

## Features

- **Network Scanning**: Automatically scans your local network or a specified network range
- **Device Discovery**: Identifies devices using ARP protocol
- **Detailed Information**: For each device found, displays:
  - MAC Address
  - IPv4 Address
  - Hostname (if resolvable)
  - Vendor (manufacturer of the network interface)
- **Table Output**: Results are displayed in a clean, formatted table

## Requirements

- Python 3.6 or higher
- Root/Administrator privileges (required for sending ARP packets)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/volkerbenders/network-inventory.git
cd network-inventory
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage (Auto-detect network)

The scanner will automatically detect your local network range:

**Linux/Mac:**
```bash
sudo python network_scanner.py
```

**Windows (run as Administrator):**
```bash
python network_scanner.py
```

### Specify Network Range

You can specify a custom network range in CIDR notation:

**Linux/Mac:**
```bash
sudo python network_scanner.py -n 192.168.1.0/24
```

**Windows (run as Administrator):**
```bash
python network_scanner.py -n 192.168.1.0/24
```

### Help

View all available options:
```bash
python network_scanner.py --help
```

## Example Output

```
Scanning network: 192.168.1.0/24
This may take a moment...

+-------------------+----------------+----------------------+------------------+
| MAC Address       | IPv4 Address   | Hostname             | Vendor           |
+===================+================+======================+==================+
| aa:bb:cc:dd:ee:ff | 192.168.1.1    | router.local         | TP-Link          |
+-------------------+----------------+----------------------+------------------+
| 11:22:33:44:55:66 | 192.168.1.100  | desktop-pc           | Intel Corp.      |
+-------------------+----------------+----------------------+------------------+
| 77:88:99:aa:bb:cc | 192.168.1.150  | N/A                  | Apple, Inc.      |
+-------------------+----------------+----------------------+------------------+

Total devices found: 3
```

## How It Works

1. **ARP Scanning**: The application sends ARP (Address Resolution Protocol) requests to all IP addresses in the specified network range
2. **Response Collection**: Devices that are online respond with their MAC address and IP address
3. **Hostname Resolution**: For each responding device, the application attempts to resolve the hostname using reverse DNS lookup
4. **Vendor Lookup**: The MAC address is used to identify the manufacturer using Scapy's built-in MAC vendor database
5. **Display Results**: All collected information is formatted and displayed in a table

## Troubleshooting

### Permission Denied Error

If you get a permission error, make sure you're running the script with appropriate privileges:
- **Linux/Mac**: Use `sudo`
- **Windows**: Run your terminal as Administrator

### No Devices Found

If no devices are found:
- Verify you're connected to the network
- Check if your firewall is blocking ARP packets
- Try specifying the network range manually with the `-n` option
- Ensure the network range is correct for your network

### Import Errors

If you get import errors, make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Dependencies

- `scapy`: For network packet manipulation and ARP scanning
- `tabulate`: For formatted table output

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Note

This tool requires elevated privileges to send raw network packets. Use responsibly and only on networks you own or have permission to scan.
