"""
Nmap Reconnaissance Script

Description:
Ce script permet d'exécuter une série de scans Nmap sur une liste d'adresses IP, en enregistrant les résultats
au format standard Nmap (-oA) et en générant un fichier CSV contenant les ports ouverts et les types de scan utilisés.

Fonctionnalités :
- Exécute plusieurs types de scans sur chaque IP :
  - Scan de tous les ports (-p-)
  - Détection des versions des services (-sV)
  - Scan de version allégé (--version-light)
  - Scan lent (-T0)
  - Scan avec scripts par défaut (-sC)
  - Scan aléatoire de sites web (-n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000)
- Affiche l'état d'avancement des scans en temps réel
- Enregistre les résultats en sortie dans plusieurs formats :
  - Fichiers Nmap (.nmap, .xml, .gnmap)
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

def run_scan(ip, scan_type, scan_command, results):
    print(f"\n[+] Running: nmap {ip} {scan_command}")
    export_name = f"{ip.replace('.', '_')}_{scan_type}"
    full_command = f"nmap {ip} {scan_command} -oA {export_name}"
    subprocess.run(full_command, shell=True)
    print(f"[+] Results saved: {export_name}.nmap, {export_name}.xml, {export_name}.gnmap\n")

    # Parse the .gnmap file for open ports
    try:
        with open(f"{export_name}.gnmap", 'r') as file:
            for line in file:
                if "/open/" in line:
                    parts = line.split()
                    for part in parts:
                        if "/open/" in part:
                            port = part.split('/')[0]
                            results.append([ip, port, scan_type])
    except FileNotFoundError:
        print(f"[-] .gnmap file not found for {ip} ({scan_type})")

def scan_target(ip, results):
    scans = {
        "all_ports": "-p-",
        "service_version": "-sV",
        "light_version": "-sV --version-light",
        "slow_scan": "-T0",
        "default_scripts": "-sC",
        "random_web": "-n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000"
    }
    
    for scan_type, scan_command in scans.items():
        run_scan(ip, scan_type, scan_command, results)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='File containing list of IP addresses')
    parser.add_argument('-t', '--time', type=int, default=0, help='Time to wait (in seconds) between scans')
    parser.add_argument('-o', '--output', default='output.csv', help='Output file for results')
    args = parser.parse_args()
    
    with open(args.file, 'r') as file:
        ip_list = file.readlines()
    
    results = []
    for ip in ip_list:
        ip = ip.strip()
        print(f"\n[+] Scanning target: {ip}")
        scan_target(ip, results)
        time.sleep(args.time)  # Pause entre les scans
    
    with open(args.output, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Port', 'Scan Type'])
        for result in results:
            writer.writerow(result)
            print(f"Exported result for {result[0]} to {args.output}")

if __name__ == "__main__":
    main()
