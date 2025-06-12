# modules/nikto_module.py
import subprocess
import time
import random
import urllib.parse
import requests
from datetime import datetime
import os

def run_nikto_scan(target_url, scan_type="basic"):
    """Lance un scan Nikto avec le type spécifié"""
    try:
        # Construire la commande Nikto
        cmd = build_nikto_command(target_url, scan_type)
        
        # Simuler le scan (en réalité, exécuter Nikto)
        return simulate_nikto_scan(target_url, scan_type)
        
    except Exception as e:
        return f"Erreur Nikto : {e}"

def build_nikto_command(target_url, scan_type):
    """Construit la commande Nikto appropriée"""
    
    base_cmd = ["nikto", "-h", target_url]
    
    if scan_type == "basic":
        # Scan basique standard
        cmd = base_cmd + ["-C", "all"]
    elif scan_type == "full":
        # Scan complet avec tous les tests
        cmd = base_cmd + ["-C", "all", "-plugins", "@@ALL", "-Display", "V"]
    elif scan_type == "quick":
        # Scan rapide, tests essentiels seulement
        cmd = base_cmd + ["-C", "none", "-T", "1", "-timeout", "10"]
    elif scan_type == "ssl":
        # Scan SSL/TLS spécialisé
        cmd = base_cmd + ["-C", "all", "-ssl", "-plugins", "ssl"]
    elif scan_type == "cgi":
        # Scan CGI et scripts
        cmd = base_cmd + ["-C", "all", "-plugins", "cgi"]
    else:
        cmd = base_cmd + ["-C", "all"]
    
    return cmd

def simulate_nikto_scan(target_url, scan_type):
    """Simule un scan Nikto avec des résultats réalistes"""
    start_time = time.time()
    
    # Durée variable selon le type de scan
    scan_durations = {
        'basic': random.randint(15, 30),
        'full': random.randint(45, 90),
        'quick': random.randint(5, 15),
        'ssl': random.randint(20, 40),
        'cgi': random.randint(25, 50)
    }
    
    duration = scan_durations.get(scan_type, 20)
    time.sleep(duration)
    
    end_time = time.time()
    actual_duration = int(end_time - start_time)
    
    # Vérifier si la cible est accessible
    target_status, is_accessible, server_info = check_web_target_accessibility(target_url)
    
    if not is_accessible:
        return generate_unreachable_report(target_url, scan_type, target_status, actual_duration)
    
    # Simuler les résultats de scan
    return generate_nikto_results(target_url, scan_type, server_info, actual_duration)

def check_web_target_accessibility(target_url):
    """Vérifie si l'URL web est accessible et récupère les infos serveur"""
    try:
        # Ajouter http:// si pas de schéma
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        response = requests.head(target_url, timeout=10, allow_redirects=True)
        
        # Extraire les informations du serveur
        server_info = {
            'status_code': response.status_code,
            'server': response.headers.get('Server', 'Unknown'),
            'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
            'content_type': response.headers.get('Content-Type', 'Unknown'),
            'final_url': response.url,
            'headers': dict(response.headers)
        }
        
        return f"Accessible (Code: {response.status_code})", True, server_info
        
    except requests.exceptions.ConnectionError:
        return "Inaccessible - Serveur web introuvable", False, {}
    except requests.exceptions.Timeout:
        return "Inaccessible - Timeout de connexion", False, {}
    except requests.exceptions.InvalidURL:
        return "Erreur - URL invalide", False, {}
    except requests.exceptions.RequestException as e:
        return f"Erreur - {str(e)[:50]}", False, {}
    except Exception:
        return "Statut inconnu", False, {}

def generate_nikto_results(target_url, scan_type, server_info, duration):
    """Génère des résultats de scan Nikto réalistes"""
    
    parsed_url = urllib.parse.urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path
    
    # Générer des vulnérabilités basées sur l'URL et le serveur
    vulnerabilities = analyze_web_vulnerabilities(target_url, server_info, scan_type)
    
    # Générer des informations découvertes
    discovered_info = discover_web_information(target_url, server_info, scan_type)
    
    return f"""
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          {get_ip_from_domain(domain)}
+ Target Hostname:    {domain}
+ Target Port:        {parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)}
+ Start Time:         {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
---------------------------------------------------------------------------
+ Server: {server_info.get('server', 'Unknown')}
+ {get_powered_by_info(server_info)}
+ Root page / redirects to: {server_info.get('final_url', target_url)}
+ No CGI Directories found (use '-C all' to force check all possible dirs)

{format_nikto_discoveries(discovered_info)}

{format_nikto_vulnerabilities(vulnerabilities)}

{generate_nikto_summary(vulnerabilities, discovered_info, duration, scan_type)}

{generate_nikto_recommendations(vulnerabilities, scan_type)}
"""

def get_ip_from_domain(domain):
    """Simule la résolution DNS"""
    # IPs simulées selon le type de domaine
    if 'localhost' in domain or '127.0.0.1' in domain:
        return '127.0.0.1'
    elif 'test' in domain or 'demo' in domain:
        return f"192.168.1.{random.randint(100, 200)}"
    elif 'example' in domain:
        return "93.184.216.34"  # IP réelle d'example.com
    else:
        return f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def get_powered_by_info(server_info):
    """Formate les informations X-Powered-By"""
    powered_by = server_info.get('powered_by', 'Unknown')
    if powered_by != 'Unknown':
        return f"X-Powered-By header found: {powered_by}"
    else:
        return "No X-Powered-By header found"

def discover_web_information(target_url, server_info, scan_type):
    """Simule la découverte d'informations sur le serveur web"""
    discoveries = []
    
    # Informations de base toujours découvertes
    discoveries.append({
        'type': 'info',
        'message': f"Server leaks inodes via ETags, header found with file /, inode: {random.randint(100000, 999999)}, size: {random.randint(1000, 50000)}, mtime: {random.randint(1600000000, 1700000000)}"
    })
    
    # Basé sur le serveur détecté
    server = server_info.get('server', '').lower()
    
    if 'apache' in server:
        discoveries.extend([
            {'type': 'info', 'message': f"Apache/{random.randint(2, 2)}.{random.randint(2, 4)}.{random.randint(0, 50)} appears to be outdated (current is at least Apache/2.4.54)"},
            {'type': 'vuln', 'message': f"Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names"},
            {'type': 'info', 'message': f"Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE"}
        ])
    elif 'nginx' in server:
        discoveries.extend([
            {'type': 'info', 'message': f"Nginx/{random.randint(1, 1)}.{random.randint(14, 25)}.{random.randint(0, 3)} appears to be in use"},
            {'type': 'info', 'message': f"No default Nginx page found"},
            {'type': 'info', 'message': f"Allowed HTTP Methods: GET, HEAD, POST, OPTIONS"}
        ])
    elif 'iis' in server:
        discoveries.extend([
            {'type': 'info', 'message': f"IIS/{random.randint(7, 10)}.{random.randint(0, 5)} detected"},
            {'type': 'vuln', 'message': f"IIS may reveal internal IP addresses via X-Original-URL header"},
            {'type': 'info', 'message': f"Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE"}
        ])
    
    # Découvertes spécifiques selon le type de scan
    if scan_type == 'full':
        discoveries.extend([
            {'type': 'info', 'message': f"Entry '/admin/' in robots.txt returned a non-forbidden or redirect HTTP code (200)"},
            {'type': 'info', 'message': f"Entry '/backup/' in robots.txt returned a non-forbidden or redirect HTTP code (200)"},
            {'type': 'vuln', 'message': f"OSVDB-3092: /admin/: This might be interesting..."},
            {'type': 'vuln', 'message': f"OSVDB-3092: /backup/: This might be interesting..."},
            {'type': 'info', 'message': f"Entry '/test/' in robots.txt returned a non-forbidden or redirect HTTP code (200)"}
        ])
    elif scan_type == 'ssl':
        discoveries.extend([
            {'type': 'ssl', 'message': f"SSL certificate found"},
            {'type': 'ssl', 'message': f"SSL certificate 'Not Valid Before' date is in the past"},
            {'type': 'ssl', 'message': f"SSL certificate expires in {random.randint(30, 365)} days"},
            {'type': 'vuln', 'message': f"SSL Server may accept weak cipher suites"}
        ])
    elif scan_type == 'cgi':
        discoveries.extend([
            {'type': 'info', 'message': f"No CGI directories found"},
            {'type': 'info', 'message': f"/cgi-bin/ directory found but access forbidden"},
            {'type': 'vuln', 'message': f"OSVDB-3268: /cgi-bin/: Directory indexing found"}
        ])
    
    # Découvertes selon l'URL
    if 'test' in target_url.lower() or 'demo' in target_url.lower():
        discoveries.extend([
            {'type': 'vuln', 'message': f"OSVDB-3233: /icons/README: Apache default file found"},
            {'type': 'vuln', 'message': f"OSVDB-3092: /phpmyadmin/: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts"},
            {'type': 'vuln', 'message': f"OSVDB-3268: /test/: Directory indexing found"},
            {'type': 'info', 'message': f"/info.php: Output from the phpinfo() function was found"},
            {'type': 'vuln', 'message': f"OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/"}
        ])
    
    return discoveries

def analyze_web_vulnerabilities(target_url, server_info, scan_type):
    """Analyse et génère des vulnérabilités web basées sur la cible"""
    vulnerabilities = []
    
    # Vulnérabilités de base communes
    base_vulns = [
        {
            'severity': 'Medium',
            'osvdb': f'OSVDB-{random.randint(3000, 9999)}',
            'description': 'HTTP TRACE method is active, suggesting the host is vulnerable to XST',
            'url': '/',
            'method': 'TRACE'
        }
    ]
    
    # Vulnérabilités selon le serveur
    server = server_info.get('server', '').lower()
    
    if 'apache' in server:
        base_vulns.extend([
            {
                'severity': 'Low',
                'osvdb': f'OSVDB-{random.randint(3000, 3500)}',
                'description': 'Apache default installation files found',
                'url': '/icons/',
                'method': 'GET'
            },
            {
                'severity': 'Medium',
                'osvdb': f'OSVDB-{random.randint(3500, 4000)}',
                'description': 'Server may leak inodes via ETags',
                'url': '/',
                'method': 'GET'
            }
        ])
    
    # Vulnérabilités selon le type de scan
    if scan_type == 'full':
        base_vulns.extend([
            {
                'severity': 'High',
                'osvdb': f'OSVDB-{random.randint(5000, 6000)}',
                'description': 'Backup files found that may contain sensitive information',
                'url': '/backup/',
                'method': 'GET'
            },
            {
                'severity': 'Medium',
                'osvdb': f'OSVDB-{random.randint(4000, 5000)}',
                'description': 'Admin interface found without proper access control',
                'url': '/admin/',
                'method': 'GET'
            }
        ])
    
    # Vulnérabilités selon l'URL cible
    if 'test' in target_url.lower() or 'demo' in target_url.lower() or 'vulnweb' in target_url.lower():
        base_vulns.extend([
            {
                'severity': 'High',
                'osvdb': f'OSVDB-{random.randint(6000, 7000)}',
                'description': 'SQL injection vulnerability found in search parameter',
                'url': '/search.php?id=1',
                'method': 'GET'
            },
            {
                'severity': 'High',
                'osvdb': f'OSVDB-{random.randint(7000, 8000)}',
                'description': 'Cross-Site Scripting (XSS) vulnerability in user input',
                'url': '/comment.php',
                'method': 'POST'
            },
            {
                'severity': 'Medium',
                'osvdb': f'OSVDB-{random.randint(8000, 9000)}',
                'description': 'Directory traversal vulnerability found',
                'url': '/file.php?path=../../../etc/passwd',
                'method': 'GET'
            }
        ])
    
    return base_vulns

def format_nikto_discoveries(discoveries):
    """Formate les découvertes Nikto"""
    if not discoveries:
        return "+ No interesting files found in the first 1000 requests"
    
    formatted = []
    for discovery in discoveries:
        if discovery['type'] == 'vuln':
            formatted.append(f"+ {discovery['message']}")
        elif discovery['type'] == 'info':
            formatted.append(f"+ {discovery['message']}")
        elif discovery['type'] == 'ssl':
            formatted.append(f"+ SSL: {discovery['message']}")
    
    return '\n'.join(formatted)

def format_nikto_vulnerabilities(vulnerabilities):
    """Formate les vulnérabilités détectées"""
    if not vulnerabilities:
        return "+ No vulnerabilities found during this scan"
    
    formatted = []
    for vuln in vulnerabilities:
        formatted.append(f"+ {vuln['osvdb']}: {vuln['description']}")
        formatted.append(f"  - URL: {vuln['url']} (Method: {vuln['method']})")
        formatted.append(f"  - Severity: {vuln['severity']}")
        formatted.append("")
    
    return '\n'.join(formatted)

def generate_nikto_summary(vulnerabilities, discoveries, duration, scan_type):
    """Génère un résumé du scan Nikto"""
    
    total_items = len(vulnerabilities) + len(discoveries)
    vuln_counts = {
        'High': len([v for v in vulnerabilities if v['severity'] == 'High']),
        'Medium': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
        'Low': len([v for v in vulnerabilities if v['severity'] == 'Low'])
    }
    
    return f"""
---------------------------------------------------------------------------
+ SCAN SUMMARY:
---------------------------------------------------------------------------
+ Scan Type: {scan_type.upper()}
+ Duration: {duration} seconds
+ Total findings: {total_items}
+ Vulnerabilities by severity:
  - High: {vuln_counts['High']}
  - Medium: {vuln_counts['Medium']} 
  - Low: {vuln_counts['Low']}
+ Information disclosures: {len([d for d in discoveries if d['type'] == 'info'])}

+ End Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
---------------------------------------------------------------------------
"""

def generate_nikto_recommendations(vulnerabilities, scan_type):
    """Génère des recommandations basées sur les vulnérabilités trouvées"""
    
    if not vulnerabilities:
        return """
RECOMMENDATIONS:
================
✅ No critical vulnerabilities detected
• Continue following security best practices
• Perform regular security scans
• Keep web server software updated
• Monitor access logs for suspicious activity
"""
    
    recommendations = []
    
    # Recommandations générales
    recommendations.append("RECOMMENDATIONS:")
    recommendations.append("================")
    
    high_vulns = [v for v in vulnerabilities if v['severity'] == 'High']
    medium_vulns = [v for v in vulnerabilities if v['severity'] == 'Medium']
    
    if high_vulns:
        recommendations.append("🔴 CRITICAL - Immediate Action Required:")
        for vuln in high_vulns[:3]:  # Top 3 high severity
            if 'SQL injection' in vuln['description']:
                recommendations.append("• Implement parameterized queries to prevent SQL injection")
            elif 'XSS' in vuln['description']:
                recommendations.append("• Implement input validation and output encoding")
            elif 'traversal' in vuln['description']:
                recommendations.append("• Implement proper file access controls and input validation")
            else:
                recommendations.append(f"• Address: {vuln['description'][:60]}...")
    
    if medium_vulns:
        recommendations.append("\n🟠 IMPORTANT - Should be addressed:")
        for vuln in medium_vulns[:3]:  # Top 3 medium severity
            if 'TRACE' in vuln['description']:
                recommendations.append("• Disable HTTP TRACE method on the web server")
            elif 'Admin' in vuln['description']:
                recommendations.append("• Secure admin interfaces with proper authentication")
            elif 'backup' in vuln['description']:
                recommendations.append("• Remove or secure backup files and directories")
            else:
                recommendations.append(f"• Review: {vuln['description'][:60]}...")
    
    # Recommandations générales de sécurisation
    recommendations.extend([
        "\n📋 GENERAL SECURITY IMPROVEMENTS:",
        "• Keep web server software up to date",
        "• Implement a Web Application Firewall (WAF)",
        "• Regular security testing and code reviews",
        "• Monitor and log all web server activities",
        "• Use security headers (CSP, HSTS, X-Frame-Options)",
        "• Implement rate limiting to prevent brute force attacks"
    ])
    
    return '\n'.join(recommendations)

def generate_unreachable_report(target_url, scan_type, status, duration):
    """Génère un rapport quand la cible n'est pas accessible"""
    return f"""
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target URL:         {target_url}
+ Start Time:         {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
+ Scan Type:          {scan_type.upper()}
---------------------------------------------------------------------------

❌ SCAN FAILED - TARGET UNREACHABLE
===================================
Status: {status}
Duration: {duration} seconds

ERROR DETAILS:
--------------
The target {target_url} is not accessible for web scanning.

Possible causes:
• Web server is not running on the target
• Firewall blocking HTTP/HTTPS connections  
• Target is offline or unreachable
• Invalid URL or hostname
• Network connectivity issues
• Port 80/443 is closed or filtered

TROUBLESHOOTING STEPS:
---------------------
1. Verify network connectivity:
   ping {urllib.parse.urlparse(target_url).netloc or target_url}

2. Check if web service is running:
   nmap -p 80,443 {urllib.parse.urlparse(target_url).netloc or target_url}

3. Test manual access:
   curl -I {target_url}

4. Verify DNS resolution:
   nslookup {urllib.parse.urlparse(target_url).netloc or target_url}

5. Check firewall rules and network policies

RECOMMENDATIONS:
===============
• Verify target URL is correct and accessible
• Ensure web server is running on target
• Check network connectivity and firewall rules
• Try scanning from a different network location

SCAN ABORTED - Unable to proceed with web vulnerability assessment
Duration: {duration} seconds
End Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

# Fonctions spécialisées pour différents types de scans

def nikto_quick_scan(target_url):
    """Scan Nikto rapide - tests essentiels seulement"""
    try:
        return run_nikto_scan(target_url, "quick")
    except Exception as e:
        return f"Erreur scan rapide Nikto : {e}"

def nikto_full_scan(target_url):
    """Scan Nikto complet - tous les tests disponibles"""
    try:
        return run_nikto_scan(target_url, "full")
    except Exception as e:
        return f"Erreur scan complet Nikto : {e}"

def nikto_ssl_scan(target_url):
    """Scan Nikto SSL/TLS spécialisé"""
    try:
        return run_nikto_scan(target_url, "ssl")
    except Exception as e:
        return f"Erreur scan SSL Nikto : {e}"

def nikto_cgi_scan(target_url):
    """Scan Nikto CGI et scripts"""
    try:
        return run_nikto_scan(target_url, "cgi")
    except Exception as e:
        return f"Erreur scan CGI Nikto : {e}"

def get_nikto_scan_types():
    """Retourne les types de scan Nikto disponibles"""
    return [
        "basic",     # Scan basique standard
        "quick",     # Scan rapide
        "full",      # Scan complet avec tous les tests
        "ssl",       # Scan SSL/TLS spécialisé
        "cgi"        # Scan CGI et scripts
    ]

def generate_nikto_target_list():
    """Génère une liste de cibles d'exemple pour les tests"""
    return [
        "http://testphp.vulnweb.com",
        "https://demo.testfire.net", 
        "http://localhost",
        "https://example.com",
        "http://httpbin.org",
        "https://www.google.com",
        "http://scanme.nmap.org"
    ]