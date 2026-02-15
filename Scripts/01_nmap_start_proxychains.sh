#! /bin/bash

# Parse command-line arguments
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        -f|--fast)
            fast=true
            shift
            ;;
        *)
            target="$1"
            shift
            ;;
    esac
done

# Create nmap directory
mkdir -p nmap

# Perform Nmap scan to identify all open ports
nmap_cmd="proxychains -q nmap -sT -Pn --top-ports=100 -oN nmap/all_ports $target -vvv"
if [[ $fast == true ]]; then
    nmap_cmd+=" --max-rtt-timeout 100ms --max-retries 1"
fi
$nmap_cmd

# Extract list of open ports from all_ports file
ports=$(cat nmap/all_ports | grep "open" |grep -v "Warning" | cut -d "/" -f1 | tr "\n" "," | sed 's/.$//')
echo "Open ports: $ports"

# Perform Nmap scan on open ports to identify services and vulnerabilities
nmap_cmd="proxychains -q nmap -sT -Pn -p$ports -sC -sV $target -oN nmap/services -vvv"
if [[ $fast == true ]]; then
    nmap_cmd+=" --max-rtt-timeout 100ms --max-retries 1"
fi
$nmap_cmd
