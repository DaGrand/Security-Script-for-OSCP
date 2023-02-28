import argparse
import nmap

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
        output = f"Open ports on {ip}: {', '.join(map(str, open_ports))}\n"
    else:
        output = f"No open ports found on {ip}\n"
    if vulners:
        output += f"Scanning for vulnerabilities on {ip}...\n"
        scanner.scan(ip, arguments='-sV --script nmap-vulners')
        for port in scanner[ip]['tcp']:
            if scanner[ip]['tcp'][port]['state'] == 'open':
                output += f"Vulnerabilities found on port {port}:\n"
                for result in scanner[ip]['tcp'][port]['script']['vulners']:
                    output += f" - {result['id']} ({result['cvss']})\n"
    return output

# Set up command-line argument parser
parser = argparse.ArgumentParser()
parser.add_argument('file', help='File containing list of IP addresses')
parser.add_argument('-a', '--aggressive', action='store_true',
                    help='Use aggressive scanning')
parser.add_argument('-v', '--vulners', action='store_true',
                    help='Scan for vulnerabilities')
parser.add_argument('-s', '--syn', action='store_true',
                    help='Use SYN scanning')
parser.add_argument('-o', '--output', default='output.txt',
                    help='Output file name')

# Parse command-line arguments
args = parser.parse_args()

# Open the file containing the list of IP addresses
with open(args.file, 'r') as file:
    ip_list = file.readlines()

# Loop through the IP addresses and scan for open ports and vulnerabilities
output = ''
for ip in ip_list:
    ip = ip.strip()  # Remove any extra whitespace or newline characters
    if args.syn:
        output += f"Scanning {ip} (SYN scan mode)...\n"
    elif args.aggressive:
        output += f"Scanning {ip} (aggressive mode)...\n"
    else:
        output += f"Scanning {ip}...\n"
    output += scan_ports(ip, aggressive=args.aggressive, vulners=args.vulners, syn_scan=args.syn)

# Write the output to a file
with open(args.output, 'w') as file:
    file.write(output)

print(f"Results saved to {args.output}")
