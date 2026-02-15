#!/bin/bash

# Enumerate SMB shares
mkdir smb 
echo "Enumerating SMB shares..."
smbclient -L $1 -U ''

# Check for null sessions
echo "Checking for null sessions..."
rpcclient -U "" -N $1 -c enumdomusers
rpcclient -U "" -N $1 -c srvinfo
rpcclient -U "" -N $1 -c querydominfo
rpcclient -U "" -N $1 -c enumdomgroups

# Enumerate users and groups
echo "Enumerating users and groups..."
enum4linux -a $1 |tee "smb/enum4linux_$2.log"

# Check for SMB signing vulnerabilities
echo "Checking for SMB signing vulnerabilities..."
nmap -Pn -p 445 --script smb-security-mode.nse $1 -oN "smb/nmap_smb_2"


# Check for SMB vulnerabilities using Nmap
echo "Checking for SMB vulnerabilities using Nmap..."
nmap -Pn -p 445 --script smb-vuln* $1 -oN "smb/nmap_smbvulns_$2.txt"


# Check for SMB vulnerabilities using Metasploit
echo "Checking for SMB vulnerabilities using Metasploit..."
msfconsole -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $1; run; exit" |tee "smb/msfresult_$2.txt"

echo "checking eternal blue"

msfconsole -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS $1; run; exit" |tee "smb/eternalblue_$2.txt"


