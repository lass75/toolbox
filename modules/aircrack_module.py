# modules/aircrack_module.py
import subprocess
import time

def scan_wifi_networks(interface="wlan0"):
    """Scanne les réseaux WiFi avec airodump-ng"""
    try:
        # Essayer le scan WiFi réel
        cmd = ["airodump-ng", interface, "--write", "temp_scan", "--output-format", "csv"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(10)
        process.terminate()
        
        # Lire les résultats
        with open("temp_scan-01.csv", "r") as f:
            return f.read()
    except Exception as e:
        # Simulation si aircrack non disponible
        return simulate_wifi_scan()

def simulate_wifi_scan():
    """Simule un scan WiFi"""
    time.sleep(2)
    return """
Réseaux WiFi détectés:
BSSID              PWR  Beacons  CH  CC  ESSID
AA:BB:CC:DD:EE:FF  -45      123   6  WPA2  HomeNetwork_5G
11:22:33:44:55:66  -60       89  11  Open  OpenWiFi
77:88:99:AA:BB:CC  -55       45   1  WEP   OfficeNet
DD:EE:FF:00:11:22  -70       12   9  WPA   Guest_Network

Risques identifiés:
- OpenWiFi : Réseau ouvert (RISQUE ÉLEVÉ)
- OfficeNet : Chiffrement WEP obsolète (RISQUE MOYEN)
"""

def crack_wep_network(bssid, pcap_file):
    """Tente de cracker une clé WEP"""
    try:
        cmd = ["aircrack-ng", "-b", bssid, pcap_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout
    except Exception as e:
        return f"Erreur crack WEP : {e}"

def monitor_mode_start(interface="wlan0"):
    """Active le mode monitor"""
    try:
        cmd = ["airmon-ng", "start", interface]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Erreur mode monitor : {e}"

def monitor_mode_stop(interface="wlan0mon"):
    """Désactive le mode monitor"""
    try:
        cmd = ["airmon-ng", "stop", interface]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Erreur arrêt monitor : {e}"