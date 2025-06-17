#!/bin/bash
echo "[*] Lancement de Metasploit avec un scan TCP sur scanme.nmap.org..."
msfconsole -q -x "
use auxiliary/scanner/portscan/tcp;
set RHOSTS scanme.nmap.org;
set THREADS 10;
run;
exit;"
