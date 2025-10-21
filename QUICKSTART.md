# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/volkerbenders/network-inventory.git
cd network-inventory

# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

### Scan your local network (auto-detect)

**Linux/Mac:**
```bash
sudo python network_scanner.py
```

**Windows (as Administrator):**
```bash
python network_scanner.py
```

### Scan a specific network range

**Linux/Mac:**
```bash
sudo python network_scanner.py -n 192.168.1.0/24
```

**Windows (as Administrator):**
```bash
python network_scanner.py -n 192.168.1.0/24
```

## Example Output

```
Scanning network: 192.168.1.0/24
This may take a moment...

+-------------------+----------------+----------------------+------------------+
| MAC Address       | IPv4 Address   | Hostname             | Vendor           |
+===================+================+======================+==================+
| aa:bb:cc:dd:ee:ff | 192.168.1.1    | router.local         | Unknown          |
+-------------------+----------------+----------------------+------------------+
| 11:22:33:44:55:66 | 192.168.1.100  | desktop-pc           | Unknown          |
+-------------------+----------------+----------------------+------------------+
| 77:88:99:aa:bb:cc | 192.168.1.150  | N/A                  | Unknown          |
+-------------------+----------------+----------------------+------------------+

Total devices found: 3
```

## Common Issues

### Permission Denied
- **Linux/Mac:** Use `sudo`
- **Windows:** Run Command Prompt as Administrator

### No Devices Found
- Verify you're connected to the network
- Check firewall settings
- Try specifying network range manually with `-n`

## Help

```bash
python network_scanner.py --help
```
