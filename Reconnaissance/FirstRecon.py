"""
Nmap Reconnaissance Script

Description:
Ce script permet d'exécuter une série de scans Nmap sur une liste d'adresses IP, en enregistrant les résultats
au format .nmap uniquement, en appendant chaque résultat à un seul fichier global.
Un fichier CSV est aussi généré pour répertorier les ports ouverts et le type de scan.

Fonctionnalités :
- Exécute plusieurs types de scans sur chaque IP :
  - Scan avec scripts par défaut (-sC)
  - Détection des versions des services (-sV)
  - Scan de version allégé (--version-light)
  - Scan de tous les ports (-p-)
  - Scan lent (-T0)
  - Scan aléatoire de sites web (-n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000)
- Affiche l'état d'avancement des scans en temps réel
- Enregistre tous les résultats dans un seul fichier .nmap
- Un fichier CSV récapitulatif des ports ouverts

Utilisation :
1. Préparer un fichier contenant une liste d'adresses IP (une IP par ligne)
2. Exécuter le script avec la commande :
   ```
   python script.py <fichier_ip> -o <output.csv> -t <temps_pause>
   ```
   - `<fichier_ip>` : fichier contenant les adresses IP à scanner
   - `-o <output.csv>` : (optionnel) fichier CSV pour sauvegarder les résultats (défaut : output.csv)
   - `-t <temps_pause>` : (optionnel) temps d'attente entre les scans (en secondes)

Exemple d'exécution :
```sh
python script.py ip_list.txt -o results.csv -t 2
```

Attention :
- L'exécution de ce script peut générer beaucoup de trafic réseau.
- Veillez à obtenir une autorisation avant de scanner des cibles qui ne vous appartiennent pas.

"""

import argparse
import csv
import time
import os
import subprocess
from datetime import datetime

def run_scan(ip, scan_type, scan_command, results, output_file):
    print(f"\n[+] Running: nmap {ip} {scan_command}")
    temp_file = f"{output_file}_tmp.nmap"
    full_command = f"nmap {ip} {scan_command} -oN {temp_file}"
    subprocess.run(full_command, shell=True)
    print(f"[+] Temporary results saved: {temp_file}")

    # Append the temporary file to the main .nmap file
    with open(temp_file, 'r') as tmp, open(f"{output_file}.nmap", 'a') as final:
        final.write(f"\n# Scan Type: {scan_type}\n")
        final.writelines(tmp.readlines())
    os.remove(temp_file)

    # Optional: parse ports from output
    try:
        with open(f"{output_file}.nmap", 'r') as file:
            capture = False
            for line in file:
                if line.startswith("Nmap scan report for"):
                    current_ip = line.split()[-1]
                if line.startswith("PORT"):
                    capture = True
                    continue
                if capture and line.strip() == '':
                    capture = False
                elif capture:
                    parts = line.split()
                    if len(parts) > 1 and "/" in parts[0]:
                        port = parts[0].split("/")[0]
                        results.append([current_ip, port, scan_type])
    except Exception as e:
        print(f"[-] Failed to parse .nmap file: {e}")

def scan_target(ip, results, output_file):
    fast_scans = {
        "default_scripts": "-sC",
        "service_version": "-sV",
        "light_version": "-sV --version-light",
        "ping scan": "-sP -p",
        "quick scan": "-PN -sV --top-ports 50 --open",
        "search smb vuln": "-PN --script smb-vuln* -p139,445",
        "UDP scan": "-sU -sC -sV"
    }
    long_scans = {
        "all_ports": "-p-",
        "slow_scan": "-T0",
        "random_web": "-n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000"
    }

    print("[+] Starting fast scans")
    for scan_type, scan_command in fast_scans.items():
        run_scan(ip, scan_type, scan_command, results, output_file)

    print("[+] Starting longer scans")
    for scan_type, scan_command in long_scans.items():
        run_scan(ip, scan_type, scan_command, results, output_file)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File containing list of IP addresses')
    parser.add_argument('-t', '--time', type=int, default=0, help='Time to wait (in seconds) between scans')
    parser.add_argument('-o', '--output', default='output.csv', help='Output file for results')
    args = parser.parse_args()

    timestamp = datetime.now().strftime('%m-%d_%H-%M')
    output_dir = f"output_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    output_file_base = os.path.join(output_dir, "scan_results")

    with open(args.file, 'r') as file:
        ip_list = file.readlines()

    results = []
    for ip in ip_list:
        ip = ip.strip()
        print(f"\n[+] Scanning target: {ip}")
        scan_target(ip, results, output_file_base)
        time.sleep(args.time)

    output_csv_path = os.path.join(output_dir, args.output)
    with open(output_csv_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Port', 'Scan Type'])
        for result in results:
            writer.writerow(result)
            print(f"Exported result for {result[0]} to {output_csv_path}")

if __name__ == "__main__":
    main()