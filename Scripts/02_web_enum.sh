#!/bin/bash

# ============================================================
# WEB RECON V2 - Enumeration & Fuzzing
# Usage: ./web_recon_v2.sh <URL>
# Example: ./web_recon_v2.sh https://example.com
# ============================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 1. Input Validation
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <URL>${NC}"
    exit 1
fi

URL="$1"
# Extract domain for filename (e.g., https://example.com -> example.com)
DOMAIN=$(echo "$URL" | awk -F/ '{print $3}')
DATE=$(date +%Y%m%d)
OUT_DIR="web_${DOMAIN}_${DATE}"

# 2. Wordlist Setup (Adjustable)
# Using variables allows you to change lists easily in one place
WL_DIRS="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
WL_FILES="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

# Check if wordlists exist
if [ ! -f "$WL_DIRS" ] || [ ! -f "$WL_FILES" ]; then
    echo -e "${RED}[!] Error: SecLists wordlists not found at configured paths.${NC}"
    echo -e "${YELLOW}[i] Please install SecLists or update variables in the script.${NC}"
    exit 1
fi

mkdir -p "$OUT_DIR"
echo -e "${BLUE}[*] Target: $URL${NC}"
echo -e "${BLUE}[*] Output Directory: $OUT_DIR${NC}"

# ==========================================
# STEP 1: WAF Detection (Crucial)
# ==========================================
echo -e "${GREEN}[+] [1/5] Checking for WAF (wafw00f)...${NC}"
if command -v wafw00f &> /dev/null; then
    wafw00f -a "$URL" > "$OUT_DIR/waf.log"
    # Check log for detection
    if grep -q "No WAF detected" "$OUT_DIR/waf.log"; then
        echo -e "${GREEN}    [*] No WAF detected.${NC}"
    else
        echo -e "${RED}    [!] WAF DETECTED! Check $OUT_DIR/waf.log before proceeding aggressively.${NC}"
        # Optional: Ask user to continue?
        # read -p "Continue? (y/n) " -n 1 -r; echo; if [[ ! $REPLY =~ ^[Yy]$ ]]; then exit 1; fi
    fi
else
    echo -e "${YELLOW}    [!] wafw00f not installed. Skipping.${NC}"
fi

# ==========================================
# STEP 2: Fingerprinting
# ==========================================
echo -e "${GREEN}[+] [2/5] Fingerprinting (WhatWeb)...${NC}"
# -a 3 is aggressive, might need reduction if WAF is present
whatweb -a 3 --color=never --log-verbose="$OUT_DIR/whatweb.log" "$URL" > /dev/null
echo -e "${YELLOW}    [*] Results saved to whatweb.log${NC}"

# ==========================================
# STEP 3: Directory & File Fuzzing
# ==========================================
echo -e "${GREEN}[+] [3/5] Directory Fuzzing (Feroxbuster)...${NC}"

# Common flags for feroxbuster
# -k: Insecure (skip SSL)
# -d: Depth (prevent infinite loops)
# --rate-limit: prevent DOS
FEROX_FLAGS="-t 20 --rate-limit 100 -k -d 2 --no-state"

# Run Directory Scan
echo -e "${YELLOW}    [*] Scanning for Directories...${NC}"
feroxbuster -u "$URL" $FEROX_FLAGS -w "$WL_DIRS" -o "$OUT_DIR/ferox_dirs.txt" > /dev/null 2>&1

# Run File Scan (Extensions)
# Note: Scanning for files with extensions is slower, so we do it separately or combined
echo -e "${YELLOW}    [*] Scanning for Files (php,txt,bak,zip,html,json)...${NC}"
feroxbuster -u "$URL" $FEROX_FLAGS -w "$WL_FILES" -x php,txt,bak,zip,html,json -o "$OUT_DIR/ferox_files.txt" > /dev/null 2>&1

echo -e "${YELLOW}    [*] Fuzzing complete.${NC}"

# ==========================================
# STEP 4: Vulnerability Scanning (Nuclei)
# ==========================================
echo -e "${GREEN}[+] [4/5] Vulnerability Scan (Nuclei)...${NC}"
# -as: Automatic scan (uses technology detection to select templates)
# -s: Severity (Critical, High, Medium, Low)
nuclei -u "$URL" -as -s critical,high,medium,low -o "$OUT_DIR/nuclei.txt"

# ==========================================
# STEP 5: Web Server Scan (Nikto)
# ==========================================
echo -e "${GREEN}[+] [5/5] Legacy Scan (Nikto)...${NC}"
# Nikto is slow. We set a max time of 20 minutes (1200 seconds)
# -Tuning 123bde = limit scan types to interesting ones to save time
nikto -h "$URL" -maxtime 20m -o "$OUT_DIR/nikto.txt" > /dev/null

echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}[OK] Web Recon Completed for $DOMAIN${NC}"
echo -e "${BLUE}Results saved in: $OUT_DIR/${NC}"
echo -e "${BLUE}=========================================${NC}"
