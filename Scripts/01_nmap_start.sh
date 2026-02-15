#!/bin/bash

# ============================================================
# RECON V3 - Smart Enumeration Script
# Usage: ./recon_v3.sh <IP> [-f|--fast] [-u|--udp] [--vuln]
# ============================================================

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 1. Root Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This script must be run as root (for SYN/UDP scanning).${NC}" 
   exit 1
fi

# --- 2. Variables & Arguments ---
fast=false
udp=false
vuln_scan=false
target=""

function usage() {
    echo -e "${YELLOW}Usage: $0 <target_ip> [options]${NC}"
    echo -e "Options:"
    echo -e "  -f, --fast    Use aggressive timing (-T4, min-rate 5000)"
    echo -e "  -u, --udp     Enable UDP scanning (Top 100 ports if fast, Top 1000 default)"
    echo -e "      --vuln    Run Nmap 'vuln' category scripts (Intrusive!)"
    exit 1
}

# Parse Args
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -f|--fast)
            fast=true
            shift
            ;;
        -u|--udp)
            udp=true
            shift
            ;;
        -v|--vuln)
            vuln_scan=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            if [[ -z "$target" ]]; then
                target="$1"
            else
                echo -e "${RED}[!] Unknown argument: $1${NC}"
                usage
            fi
            shift
            ;;
    esac
done

if [[ -z "$target" ]]; then
    echo -e "${RED}[!] No target specified.${NC}"
    usage
fi

# --- 3. Setup Workspace ---
scan_dir="nmap_${target}"
mkdir -p "$scan_dir"
echo -e "${BLUE}[*] Workspace: $scan_dir${NC}"

# Define Timing
# Default: Safe but efficient
nmap_timing="-T4 --min-rate 1000"

if [[ $fast == true ]]; then
    # Fast: Aggressive, good for CTFs or non-sensitive internal networks
    nmap_timing="-T4 --min-rate 5000 --max-retries 1"
    echo -e "${YELLOW}[!] FAST MODE: Aggressive timing enabled.${NC}"
fi

# ==========================================
# PHASE 1: TCP Discovery (All Ports)
# ==========================================
echo -e "${GREEN}[+] [1/5] Starting TCP All-Port Scan...${NC}"

# -v is reduced to keep terminal clean; detailed output goes to files
nmap -Pn -p- $nmap_timing -oA "$scan_dir/all_ports" "$target" -v > /dev/null

if [[ $? -ne 0 ]]; then
    echo -e "${RED}[!] Nmap scan failed or was interrupted.${NC}"
    exit 1
fi

# ==========================================
# PHASE 2: Port Extraction
# ==========================================
# Extracting directly from .gnmap for reliability
ports=$(grep "Status: Up" "$scan_dir/all_ports.gnmap" | cut -d " " -f2 > /dev/null) 
open_ports=$(grep -oP '\d+/open/tcp' "$scan_dir/all_ports.gnmap" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

if [[ -z "$open_ports" ]]; then
    echo -e "${RED}[!] No open TCP ports found on $target. Exiting.${NC}"
    exit 0
else
    echo -e "${GREEN}[+] Open Ports: ${YELLOW}$open_ports${NC}"
fi

# ==========================================
# PHASE 3: Service & Version Scan
# ==========================================
echo -e "${GREEN}[+] [2/5] Enumerating Services on Open Ports...${NC}"
nmap -Pn -p"$open_ports" -sC -sV $nmap_timing -oA "$scan_dir/services" "$target" -v > /dev/null

# ==========================================
# PHASE 4: Smart Enumeration Triggers
# ==========================================
echo -e "${GREEN}[+] [3/5] Running Targeted Scripts...${NC}"

# -- HTTP/HTTPS (80, 443, 8080, 8443) --
if echo "$open_ports" | grep -qE "(^|,)(80|443|8080|8443)($|,)"; then
    echo -e "${YELLOW}    [*] HTTP(s) Detected -> Running Enum Scripts${NC}"
    nmap -Pn -p80,443,8080,8443 --script http-enum,http-headers,http-methods,http-title -oN "$scan_dir/web_enum.txt" "$target" > /dev/null
    
    # Optional: GoWitness for Screenshots (if installed)
    if command -v gowitness &> /dev/null; then
        echo -e "${YELLOW}    [*] Taking Screenshots (GoWitness)${NC}"
        mkdir -p "$scan_dir/screens"
        gowitness single --url "http://$target" --destination "$scan_dir/screens/" > /dev/null 2>&1
        gowitness single --url "https://$target" --destination "$scan_dir/screens/" > /dev/null 2>&1
    fi
fi

# -- SMB (445) --
if echo "$open_ports" | grep -qE "(^|,)445($|,)"; then
    echo -e "${YELLOW}    [*] SMB Detected -> Enumerating Shares/Users/Vulns${NC}"
    # Using 'unsafe=1' allows for more aggressive scripts that might crash a fragile service (use with caution)
    nmap -Pn -p445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln* --script-args=unsafe=1 -oN "$scan_dir/smb_enum.txt" "$target" > /dev/null
fi

# -- RDP (3389) --
if echo "$open_ports" | grep -qE "(^|,)3389($|,)"; then
    echo -e "${YELLOW}    [*] RDP Detected -> Checking Encryption/Vulns${NC}"
    nmap -Pn -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 -oN "$scan_dir/rdp_enum.txt" "$target" > /dev/null
fi

# ==========================================
# PHASE 5: UDP Scan (Optional)
# ==========================================
if [[ $udp == true ]]; then
    echo -e "${GREEN}[+] [4/5] Starting UDP Scan...${NC}"
    if [[ $fast == true ]]; then
        echo -e "${YELLOW}    [*] Fast Mode: Top 100 UDP Ports only${NC}"
        nmap -sU --top-ports 100 -oA "$scan_dir/udp_scan" "$target" -v > /dev/null
    else
        echo -e "${YELLOW}    [*] Default Mode: Top 1000 UDP Ports (Slow)${NC}"
        nmap -sU $nmap_timing -oA "$scan_dir/udp_scan" "$target" -v > /dev/null
    fi
fi

# ==========================================
# PHASE 6: Vulnerability Scan (Optional)
# ==========================================
if [[ $vuln_scan == true ]]; then
    echo -e "${GREEN}[+] [5/5] Running Full Vulnerability Scan (--script vuln)...${NC}"
    echo -e "${RED}    [!] Warning: This is noisy and can crash services.${NC}"
    nmap -Pn -p"$open_ports" --script vuln $nmap_timing -oN "$scan_dir/vulns_full.txt" "$target" > /dev/null
fi

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}[OK] Recon Completed for $target${NC}"
echo -e "${BLUE}Results saved in: $scan_dir/${NC}"
echo -e "${BLUE}=========================================${NC}"
