import argparse
import nmap

def scan_ports(ip, aggressive=False):
    scanner = nmap.PortScanner()
    if aggressive:
        scanner.scan(ip, arguments='-T4 -A')
    else:
        scanner.scan(ip)
    open_ports = []
    for port in scanner[ip]['tcp']:
        if scanner[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    if open_ports:
        print(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {ip}")

# Set up command-line argument parser
parser = argparse.ArgumentParser()
parser.add_argument('file', help='File containing list of IP addresses')
parser.add_argument('-a', '--aggressive', action='store_true',
                    help='Use aggressive scanning')

# Parse command-line arguments
args = parser.parse_args()

# Open the file containing the list of IP addresses
with open(args.file, 'r') as file:
    ip_list = file.readlines()

# Loop through the IP addresses and scan for open ports
for ip in ip_list:
    ip = ip.strip()  # Remove any extra whitespace or newline characters
    if args.aggressive:
        print(f"Scanning {ip} (aggressive mode)...")
    else:
        print(f"Scanning {ip}...")
    scan_ports(ip, aggressive=args.aggressive)
