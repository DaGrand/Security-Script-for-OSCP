Nmap Reconnaissance Script
===========================

📌 Description
--------------
This Python script automates a series of Nmap scans against a list of IP addresses. Results are stored in a single `.nmap` file and a `.csv` file summarizing open ports and scan types. 

It’s designed to:
- Run **fast scans first** (for quick insights)
- Follow up with **more extensive scans**
- Save all results in a timestamped output folder (format: `output_MM-DD_HH-MM`)

⚙️ Features
-----------
- Scan Types:
  - `-sC` (default scripts)
  - `-sV` (service version detection)
  - `--version-light` (lightweight version detection)
  - `-p-` (full port scan)
  - `-T0` (slow timing for stealth)
  - Random web scan on port 80 with scripts (`banner,http-title`)

- Output:
  - All `.nmap` results are appended into a single file
  - A `.csv` file listing all open ports and scan types
  - Organized output directory with current date and time (no year or seconds)

▶️ Usage
--------
1. Prepare a file containing one IP address per line:

Example: `ips.txt`
```
192.168.1.1
10.10.10.10
```

2. Run the script:
```
python FirstRecon.py ips.txt -o output.csv -t 2
```

- `ips.txt`: your input list of IP addresses
- `-o output.csv`: optional output filename for the CSV (default: `output.csv`)
- `-t 2`: optional time delay in seconds between each scan

⚠️ Warning
----------
Do **not** scan systems you do not own or have explicit permission to scan. This tool is for **authorized and ethical use only**.

🛠️ Requirements
----------------
- Python 3.x
- Nmap installed and available in your system path (`nmap` command)