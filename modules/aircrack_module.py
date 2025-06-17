# modules/aircrack_module.py
import subprocess
import os

def scan_wifi_networks(interface="wlan0"):
    """Scanne les réseaux WiFi avec airodump-ng"""
    try:
        # Vérifier si l'interface existe
        if not check_interface_exists(interface):
            return f"Erreur : L'interface {interface} n'existe pas ou n'est pas disponible"
        
        # Créer le dossier temp s'il n'existe pas
        os.makedirs('temp', exist_ok=True)
        
        # Nom du fichier de sortie
        output_file = f"temp/wifi_scan_{interface}"
        
        # Commande airodump-ng
        cmd = [
            "airodump-ng", 
            interface, 
            "--write", output_file, 
            "--output-format", "csv",
            "--write-interval", "10"
        ]
        
        # Lancer airodump-ng pendant 15 secondes
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait()
        
        # Lire le fichier CSV généré
        csv_file = f"{output_file}-01.csv"
        if os.path.exists(csv_file):
            with open(csv_file, "r") as f:
                csv_content = f.read()
            
            # Nettoyer le fichier temporaire
            try:
                os.remove(csv_file)
            except:
                pass
            
            return parse_airodump_csv(csv_content)
        else:
            return f"Erreur : Aucun fichier de résultats généré. Vérifiez que l'interface {interface} est en mode monitor."
            
    except FileNotFoundError:
        return "Erreur : airodump-ng non trouvé. Veuillez installer aircrack-ng:\nsudo apt-get install aircrack-ng"
    except PermissionError:
        return "Erreur : Privilèges insuffisants. Exécutez le programme en tant qu'administrateur."
    except Exception as e:
        return f"Erreur lors du scan WiFi : {e}"

def parse_airodump_csv(csv_content):
    """Parse le contenu CSV d'airodump-ng et formate les résultats"""
    try:
        lines = csv_content.split('\n')
        
        # Trouver la section des réseaux (APs)
        ap_section_start = -1
        station_section_start = -1
        
        for i, line in enumerate(lines):
            if line.strip().startswith('BSSID'):
                ap_section_start = i
            elif line.strip().startswith('Station MAC'):
                station_section_start = i
                break
        
        if ap_section_start == -1:
            return "Aucun réseau WiFi détecté"
        
        # Parser les points d'accès
        networks = []
        end_line = station_section_start if station_section_start != -1 else len(lines)
        
        for i in range(ap_section_start + 1, end_line):
            line = lines[i].strip()
            if not line or line.startswith(','):
                continue
            
            parts = [part.strip() for part in line.split(',')]
            if len(parts) >= 14:
                bssid = parts[0]
                power = parts[8] if parts[8] else "N/A"
                channel = parts[3] if parts[3] else "N/A"
                encryption = parts[5] if parts[5] else "Open"
                essid = parts[13] if parts[13] else "<Hidden>"
                
                if bssid and bssid != "BSSID":
                    networks.append({
                        'bssid': bssid,
                        'essid': essid,
                        'power': power,
                        'channel': channel,
                        'encryption': encryption
                    })
        
        # Formater les résultats
        if not networks:
            return "Aucun réseau WiFi détecté pendant la durée du scan"
        
        result = f"Scan WiFi terminé - {len(networks)} réseaux détectés\n"
        result += "=" * 60 + "\n\n"
        result += f"{'ESSID':<20} {'BSSID':<18} {'PWR':<6} {'CH':<4} {'Encryption':<15}\n"
        result += "-" * 60 + "\n"
        
        # Trier par puissance du signal (décroissant)
        networks.sort(key=lambda x: int(x['power']) if x['power'].isdigit() or (x['power'].startswith('-') and x['power'][1:].isdigit()) else -100, reverse=True)
        
        for network in networks:
            essid = network['essid'][:19] if len(network['essid']) > 19 else network['essid']
            result += f"{essid:<20} {network['bssid']:<18} {network['power']:<6} {network['channel']:<4} {network['encryption']:<15}\n"
        
        # Analyse de sécurité
        result += "\n" + "=" * 60 + "\n"
        result += "ANALYSE DE SÉCURITÉ:\n"
        result += "-" * 20 + "\n"
        
        open_networks = [n for n in networks if 'Open' in n['encryption'] or not n['encryption']]
        wep_networks = [n for n in networks if 'WEP' in n['encryption']]
        wps_networks = [n for n in networks if 'WPS' in n['encryption']]
        
        if open_networks:
            result += f"⚠️  RÉSEAUX OUVERTS DÉTECTÉS ({len(open_networks)}):\n"
            for net in open_networks:
                result += f"   - {net['essid']} ({net['bssid']}) - RISQUE ÉLEVÉ\n"
            result += "\n"
        
        if wep_networks:
            result += f"⚠️  RÉSEAUX WEP DÉTECTÉS ({len(wep_networks)}):\n"
            for net in wep_networks:
                result += f"   - {net['essid']} ({net['bssid']}) - CHIFFREMENT OBSOLÈTE\n"
            result += "\n"
        
        if wps_networks:
            result += f"⚠️  RÉSEAUX WPS ACTIVÉ ({len(wps_networks)}):\n"
            for net in wps_networks:
                result += f"   - {net['essid']} ({net['bssid']}) - VULNÉRABLE AUX ATTAQUES WPS\n"
            result += "\n"
        
        secure_networks = len(networks) - len(open_networks) - len(wep_networks)
        if secure_networks > 0:
            result += f"✅ RÉSEAUX SÉCURISÉS: {secure_networks} (WPA2/WPA3)\n"
        
        return result
        
    except Exception as e:
        return f"Erreur lors de l'analyse des résultats : {e}"

def check_interface_exists(interface):
    """Vérifie si l'interface réseau existe"""
    try:
        # Utiliser iwconfig pour vérifier les interfaces WiFi
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        return interface in result.stdout
    except:
        # Fallback: vérifier dans /sys/class/net/
        return os.path.exists(f'/sys/class/net/{interface}')

def monitor_mode_start(interface="wlan0"):
    """Active le mode monitor sur l'interface"""
    try:
        if not check_interface_exists(interface):
            return f"Erreur : L'interface {interface} n'existe pas"
        
        # Arrêter l'interface
        subprocess.run(['sudo', 'ifconfig', interface, 'down'], 
                      capture_output=True, text=True, check=True)
        
        # Activer le mode monitor avec airmon-ng
        result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                              capture_output=True, text=True, check=True)
        
        return f"Mode monitor activé sur {interface}\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'activation du mode monitor : {e.stderr}"
    except FileNotFoundError:
        return "Erreur : airmon-ng non trouvé. Installez aircrack-ng."
    except Exception as e:
        return f"Erreur : {e}"

def monitor_mode_stop(interface="wlan0mon"):
    """Désactive le mode monitor"""
    try:
        # Désactiver le mode monitor avec airmon-ng
        result = subprocess.run(['sudo', 'airmon-ng', 'stop', interface], 
                              capture_output=True, text=True, check=True)
        
        # Redémarrer NetworkManager si disponible
        try:
            subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], 
                         capture_output=True, text=True)
        except:
            pass  # Ignorer si NetworkManager n'est pas disponible
        
        return f"Mode monitor désactivé sur {interface}\n{result.stdout}"
        
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de la désactivation du mode monitor : {e.stderr}"
    except FileNotFoundError:
        return "Erreur : airmon-ng non trouvé. Installez aircrack-ng."
    except Exception as e:
        return f"Erreur : {e}"

def crack_wep_network(bssid, pcap_file):
    """Tente de cracker une clé WEP"""
    try:
        if not os.path.exists(pcap_file):
            return f"Erreur : Le fichier {pcap_file} n'existe pas"
        
        cmd = ["aircrack-ng", "-b", bssid, pcap_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            return f"Crack WEP réussi :\n{result.stdout}"
        else:
            return f"Crack WEP échoué :\n{result.stderr}"
            
    except subprocess.TimeoutExpired:
        return "Timeout : Le crack WEP a pris trop de temps"
    except FileNotFoundError:
        return "Erreur : aircrack-ng non trouvé"
    except Exception as e:
        return f"Erreur crack WEP : {e}"

def capture_handshake(interface, bssid, channel, output_file):
    """Capture un handshake WPA/WPA2"""
    try:
        # Changer de canal
        subprocess.run(['sudo', 'iwconfig', interface, 'channel', str(channel)], 
                      capture_output=True, text=True)
        
        # Lancer airodump-ng pour capturer le handshake
        cmd = [
            'airodump-ng', 
            '-c', str(channel),
            '--bssid', bssid,
            '-w', output_file,
            interface
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Capturer pendant 60 secondes
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait()
        
        # Vérifier si un handshake a été capturé
        cap_file = f"{output_file}-01.cap"
        if os.path.exists(cap_file):
            return f"Capture terminée. Fichier sauvegardé : {cap_file}"
        else:
            return "Aucun handshake capturé pendant la durée spécifiée"
            
    except Exception as e:
        return f"Erreur lors de la capture : {e}"

def get_wifi_interfaces():
    """Liste les interfaces WiFi disponibles"""
    try:
        result = subprocess.run(['iwconfig'], capture_output=True, text=True)
        interfaces = []
        
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
        
        if interfaces:
            return f"Interfaces WiFi disponibles : {', '.join(interfaces)}"
        else:
            return "Aucune interface WiFi détectée"
            
    except FileNotFoundError:
        return "Erreur : iwconfig non trouvé. Installez wireless-tools."
    except Exception as e:
        return f"Erreur : {e}"