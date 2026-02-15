#!/bin/bash
mkdir web 
dir=$(pwd)
wordlist="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
echo "=======start whatweb====="
proxychains -q whatweb -a 3 $1 |tee web/whatweb.log
echo "=======start nikto ====="
proxychains -q nikto -h $1 |tee web/nikto.log
echo "=======start dirsearch====="
proxychains -q dirsearch.py -u $1 -w $wordlist -x 403 -o web/dirsearch.log
