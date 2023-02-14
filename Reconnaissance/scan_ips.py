import argparse
import csv
import time

# Try to import the nmap module; if it fails, prompt the user to install it
try:
    import nmap
except ImportError:
    print("The 'nmap' module is not installed. Would you like to install it now? (y/n)")
    choice = input().lower()
    if choice == 'y':
        !pip install python-nmap
        import nmap
    else:
        print("Exiting...")
        exit()

def scan_ports(ip, aggressive=False, vulners=False, syn_scan=False):
    scanner = nmap.PortScanner()
    if syn_scan:
        scanner.scan(ip, arguments='-sS -p-')
    elif aggressive:
        scanner.scan(ip, arguments='-T4 -A')
    else:
        scanner.scan(ip, arguments='-p-')
    open_ports = []
    for port in scanner[ip]['tcp']:
        if scanner[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    if open_ports:
        print(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {ip}")
    if vulners:
        print(f"Scanning for vulnerabilities on {ip}...")
        scanner.scan(ip, arguments='-sV --script nmap-vulners')
        for port in scanner[ip]['tcp']:
            if scanner[ip]['tcp'][port]['state'] == 'open':
                for result in scanner[ip]['tcp'][port]['script']['vulners']:
                    results.append([ip, port, result['id'], result['cvss']])

# Set up command-line argument parser
parser = argparse.ArgumentParser()
parser.add_argument('file', help='File containing list of IP addresses')
parser.add_argument('-a', '--aggressive', action='store_true',
                    help='Use aggressive scanning')
parser.add_argument('-v', '--vulners', action='store_true',
                    help='Scan for vulnerabilities')
parser.add_argument('-s', '--syn', action='store_true',
                    help='Use SYN scanning')
parser.add_argument('-t', '--time', type=int, default=0,
                    help='Time to wait (in seconds) between scans')
parser.add_argument('-o', '--output', default='output.csv',
                    help='Output file for results')

# Parse command-line arguments
args = parser.parse_args()

# Open the file containing the list of IP addresses
with open(args.file, 'r') as file:
    ip_list = file.readlines()

# Set up a list to store the results
results = []

# Loop through the IP addresses and scan for open ports and vulnerabilities
for ip in ip_list:
    ip = ip.strip()  # Remove any extra whitespace or newline characters
    if args.syn:
        print(f"Scanning {ip} (SYN scan mode)...")
    elif args.aggressive:
        print(f"Scanning {ip} (aggressive mode)...")
    else:
        print(f"Scanning {ip}...")
    scan_ports(ip, aggressive=args.aggressive, vulners=args.vulners, syn_scan=args.syn)
    time.sleep(args.time)  # Pause the script for the specified amount of time

# Export results to a CSV file
with open(args.output, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['IP Address', 'Port', 'Vulnerability ID', 'CVSS'])
    for result in results:
        writer.writerow(result)
        print(f"Exported result for {result[0]} to {args.output}")
