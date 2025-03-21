"""
Nmap Reconnaissance Script

Description:
Ce script permet d'exécuter une série de scans Nmap sur une liste d'adresses IP, en enregistrant les résultats
au format .nmap uniquement, en appendant chaque résultat à un seul fichier global.
Un fichier CSV est aussi généré pour répertorier les ports ouverts et le type de scan.

Une fois les scans terminés, un `searchsploit` est exécuté pour chaque port ouvert identifié :
- Une recherche basée sur le nom du service (ex: "Microsoft IIS httpd 10.0")
- Une recherche basée sur le numéro de port uniquement (avec `-p`)

Les résultats sont exportés dans le même dossier sous forme de fichier `searchsploit.csv`.

Fonctionnalités :
- Exécute plusieurs types de scans sur chaque IP
- Option pour n'exécuter que les scans rapides (`--fast-only`)
- Affiche l'état d'avancement des scans en temps réel
- Enregistre tous les résultats dans un seul fichier .nmap
- Génère deux fichiers CSV :
  - Résumé des ports ouverts (avec nettoyage des doublons)
  - Résultat des recherches d'exploits

Utilisation :
1. Préparer un fichier contenant une liste d'adresses IP (une IP par ligne)
2. Exécuter le script avec la commande :
   ```
   python script.py <fichier_ip> -o <output.csv> -t <temps_pause> [--fast-only]
   ```

Exemple :
```sh
python script.py ip_list.txt -o results.csv -t 2 --fast-only
```

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

    with open(temp_file, 'r') as tmp, open(f"{output_file}.nmap", 'a') as final:
        final.write(f"\n# Scan Type: {scan_type}\n")
        final.writelines(tmp.readlines())
    os.remove(temp_file)

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
                    if len(parts) > 2 and "/" in parts[0]:
                        port = parts[0].split("/")[0]
                        service = " ".join(parts[2:])
                        results.append([current_ip, port, scan_type, service])
    except Exception as e:
        print(f"[-] Failed to parse .nmap file: {e}")

def scan_target(ip, results, output_file, fast_only):
    fast_scans = {
        "default_scripts": "-sC",
        "service_version": "-sV",
        "light_version": "-sV --version-light",
        "quick scan": "-Pn -sV --top-ports 50 --open",
        "search smb vuln": "-Pn --script smb-vuln* -p139,445"
    }
    long_scans = {
        "all_ports": "-p-",
        "UDP scan": "-sU -sC -sV",
        "slow_scan": "-T0",
        "random_web": "-n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000"
    }

    print("[+] Starting fast scans")
    for scan_type, scan_command in fast_scans.items():
        run_scan(ip, scan_type, scan_command, results, output_file)

    if not fast_only:
        print("[+] Starting longer scans")
        for scan_type, scan_command in long_scans.items():
            run_scan(ip, scan_type, scan_command, results, output_file)

def clean_csv_duplicates(csv_path):
    print("[+] Cleaning duplicates in output CSV...")
    seen = set()
    unique_rows = []
    with open(csv_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            key = tuple(row)
            if key not in seen:
                seen.add(key)
                unique_rows.append(row)

    with open(csv_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(unique_rows)
    print("[+] Duplicate entries removed.")

def run_searchsploit(results, output_dir):
    output_path = os.path.join(output_dir, "searchsploit.csv")
    with open(output_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["IP", "Port", "Search Type", "Query", "Result"])

        for row in results:
            ip, port, _, service = row
            queries = [("service", service), ("port", f"-p {port}")]

            for search_type, query in queries:
                try:
                    cmd = f"searchsploit {query}"
                    print(f"[+] Running: {cmd}")
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    output = result.stdout.strip().replace('\n', ' | ')
                    writer.writerow([ip, port, search_type, query, output])
                except Exception as e:
                    writer.writerow([ip, port, search_type, query, f"Error: {e}"])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File containing list of IP addresses')
    parser.add_argument('-t', '--time', type=int, default=0, help='Time to wait (in seconds) between scans')
    parser.add_argument('-o', '--output', default='output.csv', help='Output file for results')
    parser.add_argument('--fast-only', action='store_true', help='Run only fast scans')
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
        scan_target(ip, results, output_file_base, args.fast_only)
        time.sleep(args.time)

    output_csv_path = os.path.join(output_dir, args.output)
    with open(output_csv_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Port', 'Scan Type', 'Service'])
        for result in results:
            writer.writerow(result)
            print(f"Exported result for {result[0]} to {output_csv_path}")

    # Nettoyage des doublons
    clean_csv_duplicates(output_csv_path)

    print("\n[+] Running SearchSploit lookups...")
    run_searchsploit(results, output_dir)
    print("[+] SearchSploit results saved to searchsploit.csv")

if __name__ == "__main__":
    main()