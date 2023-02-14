In this script, I define a function called scan_ports that takes an IP address and an optional aggressive argument. The aggressive argument is a boolean flag that indicates whether to use aggressive scanning mode or not. If aggressive is True, we pass the -T4 -A arguments to the PortScanner object to enable more aggressive scanning. Otherwise, we use the default scanning settings.

We also define a command-line argument parser using the argparse module. The parser takes a required file argument, which is the name of the file containing the list of IP addresses. It also takes an optional -a or --aggressive flag, which sets the aggressive argument to True.

In the main part of the script, we open the file containing the list of IP addresses and loop through each IP. For each IP, we print a message indicating that we are scanning that IP, and then call the scan_ports function with the IP and the aggressive flag that was set on the command line.

To run the script, save it to a file (e.g. scan_ips.py) and then run it from the command line like this:

`python scan_ips.py ip_addresses.txt`

This will scan each IP address in ip_addresses.txt using the default scanning settings. 

To enable aggressive scanning mode, use the -a or --aggressive flag:

`python scan_ips.py ip_addresses.txt -a`
