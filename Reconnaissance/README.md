In this script, I define a function called scan_ports that takes an IP address and an optional aggressive argument. The aggressive argument is a boolean flag that indicates whether to use aggressive scanning mode or not. If aggressive is True, we pass the -T4 -A arguments to the PortScanner object to enable more aggressive scanning. Otherwise, we use the default scanning settings.

We also define a command-line argument parser using the argparse module. The parser takes a required file argument, which is the name of the file containing the list of IP addresses. It also takes an optional -a or --aggressive flag, which sets the aggressive argument to True.

In the main part of the script, we open the file containing the list of IP addresses and loop through each IP. For each IP, we print a message indicating that we are scanning that IP, and then call the scan_ports function with the IP and the aggressive flag that was set on the command line.

#### Normal scan
To run the script, save it to a file (e.g. scan_ips.py) and then run it from the command line like this:

`python scan_ips.py ip_addresses.txt`

This will scan each IP address in ip_addresses.txt using the default scanning settings. 

#### Aggressive scan
To enable aggressive scanning mode, use the -a or --aggressive flag:

`python scan_ips.py ip_addresses.txt -a`

#### Syn Ack scan
A new argument called -s or --syn that indicates whether to use SYN scanning or not. If this argument is provided on the command line, we call the PortScanner object again with the -sS -p- arguments to enable SYN scanning and scan all ports using the -p- option.

We modify the scan_ports function to include the syn_scan parameter, which is False by default. If syn_scan is True, we call the PortScanner object with the -sS -p- arguments to enable SYN scanning and scan all ports. Otherwise, we use the -p- argument to scan all ports without using SYN scanning.

To run the script with SYN scanning enabled and scan all ports, use the -s or --syn flag:

`python scan_ips.py ip_addresses.txt -s`

#### Full scan with delay
A new argument called -t or --time that specifies the amount of time to wait between scans, in seconds. We use the time.sleep() function to pause the script for this amount of time between each scan.

To run the script and wait 5 seconds between each scan, use the -t or --time flag:

`python scan_ips.py ip_addresses.txt -t 5`

#### Output file
A new argument called -o or --output that specifies the output file for the results. We also set up a list called results to store the results for each IP address scanned, including any vulnerabilities found.
